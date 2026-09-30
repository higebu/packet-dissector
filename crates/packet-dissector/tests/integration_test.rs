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
//! | Ethernet → LLDP (IEEE 802.1 Port VLAN ID TLV)   | integration_ethernet_lldp_org_port_vlan_id    |
//! | Ethernet → IPv4 → ICMP Echo             | integration_ethernet_ipv4_icmp_echo           |
//! | Ethernet → IPv4 → IGMPv2 Report         | integration_ethernet_ipv4_igmp_v2_report      |
//! | Ethernet → IPv4 → IGMPv3 Report         | integration_ethernet_ipv4_igmp_v3_report      |
//! | Ethernet → IPv4 → IGMP MRD Solicitation | integration_ethernet_ipv4_igmp_mrd_solicitation |
//! | Ethernet → IPv6 → ICMPv6 Echo           | integration_ethernet_ipv6_icmpv6_echo         |
//! | Ethernet → IPv6 → TCP                    | integration_ethernet_ipv6_tcp                 |
//! | Ethernet → IPv6 → UDP → DNS             | integration_ethernet_ipv6_udp_dns             |
//! | Ethernet → IPv4 → SCTP                   | integration_ethernet_ipv4_sctp                |
//! | Ethernet → IPv4 → SCTP → Diameter (CER)  | integration_ethernet_ipv4_sctp_diameter       |
//! | Ethernet → IPv4 → SCTP (2 bundled DATA) → Diameter ×2 | integration_ethernet_ipv4_sctp_bundled_data_chunks |
//! | Ethernet → IPv4 → SCTP (DATA fragment, not dispatched) | integration_ethernet_ipv4_sctp_fragment_not_dispatched |
//! | Ethernet → IPv4 → SCTP (bundled, 2nd malformed) → Diameter ×2 + Err | integration_ethernet_ipv4_sctp_bundled_error_keeps_other_chunks |
//! | Ethernet → IPv4 → SCTP (bundled) summary stops at SCTP | integration_ethernet_ipv4_sctp_bundled_summary |
//! | Ethernet → IPv4 → SCTP(40000→40001, PPID 46) → Diameter | integration_ethernet_ipv4_sctp_ppid_diameter_nondefault_port |
//! | Ethernet → IPv4 → SCTP(port 38412, PPID 46) → Diameter (PPID wins) | integration_ethernet_ipv4_sctp_ppid_wins_over_port |
//! | Ethernet → IPv4 → SCTP(port 3868, PPID 0 / unknown) → Diameter by port | integration_ethernet_ipv4_sctp_ppid_falls_back_to_port |
//! | Ethernet → IPv4 → SCTP(unknown PPID and ports) → no upper layer | integration_ethernet_ipv4_sctp_unknown_ppid_and_port |
//! | Ethernet → IPv4 → SCTP(unknown PPID, then PPID 46) summary names Diameter | integration_ethernet_ipv4_sctp_summary_uses_first_resolvable_chunk |
//! | Ethernet → IPv4 → SCTP(9487→40001, PPID 60) → NGAP | integration_ethernet_ipv4_sctp_ppid_ngap_nondefault_port |
//! | Ethernet → IPv4 → SCTP(port 29118, PPID 0) → SGsAP | integration_ethernet_ipv4_sctp_sgsap_paging_request |
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
//! | Ethernet → IPv6 → UDP → DHCPv6 DHCPV4-QUERY → DHCP Discover | integration_ethernet_ipv6_udp_dhcpv4_query_dhcp_discover |
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
//! | Ethernet → IPv4 → UDP → SIP INVITE → SDP      | integration_ethernet_ipv4_udp_sip_invite_with_sdp   |
//! | Ethernet → IPv4 → TCP → HTTP 200 → SDP        | integration_ethernet_ipv4_tcp_http_response_sdp_body |
//! | Ethernet → IPv4 → TCP → SIP (invalid SDP body) | integration_ethernet_ipv4_tcp_sip_invalid_sdp_body  |
//! | Ethernet → IPv4 → UDP → GTPv2-C (Create Session) | integration_ethernet_ipv4_udp_gtpv2c_create_session |
//! | Ethernet → IPv4 → UDP → GTPv2-C (Echo Request)   | integration_ethernet_ipv4_udp_gtpv2c_echo_request   |
//! | Ethernet → IPv4 → UDP → GTPv2-C + piggyback      | integration_ethernet_ipv4_udp_gtpv2c_piggyback      |
//! | Ethernet → IPv4 → UDP → PFCP (Heartbeat)          | integration_ethernet_ipv4_udp_pfcp_heartbeat        |
//! | Ethernet → IPv4 → UDP → PFCP (Session Est.)       | integration_ethernet_ipv4_udp_pfcp_session_establishment |
//! | SLL2 → IPv4 → UDP                                 | integration_sll2_ipv4_udp                           |
//! | SLL → IPv4 → UDP                                  | integration_sll_ipv4_udp                            |
//! | SLL2 → IPv6 → TCP (SYN)                           | integration_sll2_ipv6_tcp_syn                       |
//! | Ethernet → IPv4 → GRE → IPv4 → UDP                | integration_ethernet_ipv4_gre_ipv4                   |
//! | Ethernet → IPv4 → GRE → IPv6 → UDP                | integration_ethernet_ipv4_gre_ipv6                   |
//! | Ethernet → IPv4 → TCP → TLS ClientHello            | ethernet_ipv4_tcp_tls_client_hello                   |
//! | Ethernet → IPv4 → TCP → TLS Alert                  | ethernet_ipv4_tcp_tls_alert                          |
//! | Ethernet → IPv4 → TCP → TLS coalesced handshakes   | ethernet_ipv4_tcp_tls_coalesced_server_flight        |
//! | Ethernet → IPv4 → TCP → TLS 1.3 CH extensions      | ethernet_ipv4_tcp_tls13_client_hello_extensions      |
//! | Ethernet → IPv4 → TCP (443) → non-TLS rejected     | ethernet_ipv4_tcp_non_tls_on_port_443                |
//! | Ethernet → IPv4 → UDP → STUN Binding Request       | integration_ethernet_ipv4_udp_stun_binding_request   |
//! | Ethernet → IPv4 → UDP → STUN XOR-MAPPED-ADDRESS    | integration_ethernet_ipv4_udp_stun_xor_mapped_address |
//! | Ethernet → IPv4 → UDP → TURN ChannelData           | integration_ethernet_ipv4_udp_turn_channeldata       |
//! | Ethernet → IPv4 → TCP → TURN ChannelData ×2        | integration_ethernet_ipv4_tcp_turn_channeldata_pipelined |
//! | Ethernet → IPv4 → UDP → classic STUN (RFC 3489)    | integration_ethernet_ipv4_udp_classic_stun           |
//! | Ethernet → IPv4 → TCP → ChannelData split in padding | integration_ethernet_ipv4_tcp_turn_channeldata_split_padding |
//! | Ethernet → IPv4 → TCP → classic STUN rejected      | integration_ethernet_ipv4_tcp_classic_stun_rejected  |
//! | Ethernet → IPv4 → GRE (Key) → IPv4 → UDP          | integration_ethernet_ipv4_gre_key_ipv4               |
//! | Ethernet → IPv4 → Enhanced GRE (v1) → PPP → IPv4 → UDP | integration_ethernet_ipv4_gre_v1_ppp_ipv4       |
//! | Ethernet → IPv4 → Enhanced GRE (v1, ack only)     | integration_ethernet_ipv4_gre_v1_ack_only            |
//! | link_type=1 (Ethernet) via dissect_with_link_type  | integration_dissect_with_link_type_ethernet          |
//! | link_type=0 (NULL, LE/BE) → IPv4/IPv6 → UDP         | integration_link_type_null_ipv4_le, integration_link_type_null_ipv4_be, integration_link_type_null_ipv6 |
//! | link_type=108 (LOOP) → IPv4 → UDP                   | integration_link_type_loop_ipv4                      |
//! | link_type=101 (RAW) → IPv4/IPv6 → UDP               | integration_link_type_raw_ipv4, integration_link_type_raw_ipv6 |
//! | link_type=228 (IPV4) → IPv4 → UDP                   | integration_link_type_ipv4                           |
//! | link_type=229 (IPV6) → IPv6 → UDP                   | integration_link_type_ipv6                           |
//! | link_type=228/229 with the other IP version         | integration_link_type_ipv4_ipv6_reject_other_version |
//! | Unregistered link type is an error, not Ethernet    | integration_unregistered_link_type_is_error          |
//! | Ethernet → LACP                                     | integration_ethernet_lacp                            |
//! | Ethernet → Slow Protocols Marker                    | integration_ethernet_slow_protocols_marker           |
//! | Ethernet → Slow Protocols OAM (Information)         | integration_ethernet_slow_protocols_oam              |
//! | Ethernet → Slow Protocols OSSP → ESMC               | integration_ethernet_slow_protocols_esmc             |
//! | Ethernet → Slow Protocols (unknown subtype)         | integration_ethernet_slow_protocols_unknown_subtype  |
//! | Ethernet → LLC → STP Config BPDU                    | integration_ethernet_llc_stp_config                  |
//! | Ethernet → LLC → STP TCN BPDU                       | integration_ethernet_llc_stp_tcn                     |
//! | Ethernet → LLC → RST BPDU                           | integration_ethernet_llc_rstp                        |
//! | Ethernet → LLC → MST BPDU with an MSTI message      | integration_ethernet_llc_mstp                        |
//! | Ethernet → LLC → SNAP (RFC 1042) → IPv4 → ICMP      | integration_ethernet_llc_snap_ipv4_icmp              |
//! | Ethernet → LLC → SNAP (non-zero OUI) ends the chain | integration_ethernet_llc_snap_other_oui              |
//! | SLL (protocol 0x0004) → LLC → STP                   | integration_sll_llc_stp                              |
//! | SLL2 (protocol 0x0004) → LLC → SNAP → IPv4          | integration_sll2_llc_snap_ipv4                       |
//! | Ethernet → MPLS → IPv4 → UDP                         | integration_ethernet_mpls_ipv4_udp                   |
//! | Ethernet → MPLS (2 labels) → IPv4 → UDP              | integration_ethernet_mpls_two_labels_ipv4_udp        |
//! | Ethernet → MPLS (GAL) → ACH → BFD                    | integration_ethernet_mpls_gal_ach_bfd                |
//! | Ethernet → MPLS → PW-ACH → IPv4 → UDP                | integration_ethernet_mpls_pw_ach_ipv4                |
//! | Ethernet → MPLS → PW-CW → Ethernet → IPv4 → UDP      | integration_ethernet_mpls_pw_control_word_ethernet   |
//! | Ethernet → MPLS → Ethernet PW without CW (DA 00:..)  | integration_ethernet_mpls_pw_without_control_word_does_not_fail |
//! | Ethernet → IPv4 → UDP → NTP (Client)                 | integration_ethernet_ipv4_udp_ntp_client             |
//! | Ethernet → IPv4 → UDP → NTP (Control, mode 6)        | integration_ethernet_ipv4_udp_ntp_control_request    |
//! | Ethernet → IPv4 → UDP → BFD (Up)                     | integration_ethernet_ipv4_udp_bfd_up                 |
//! | Ethernet → IPv4 → UDP → BFD Echo (opaque payload)    | integration_ethernet_ipv4_udp_bfd_echo_opaque        |
//! | Ethernet → IPv4 → UDP → BFD Echo (Control format)    | integration_ethernet_ipv4_udp_bfd_echo_control       |
//! | Ethernet → IPv4 → UDP → S-BFD / Micro-BFD            | integration_ethernet_ipv4_udp_sbfd_and_micro_bfd     |
//! | PPP (HDLC) → IPv4 → UDP                               | integration_ppp_ipv4_udp                              |
//! | PPP (HDLC, link type 50) → LCP (inline)                | integration_ppp_lcp_inline                            |
//! | Ethernet → IPv4 → UDP → GENEVE → Ethernet → IPv4 → UDP | integration_ethernet_ipv4_udp_geneve_ipv4        |
//! | Ethernet → IPv4 → UDP → GENEVE (opts) → Ethernet → IPv4 | integration_ethernet_ipv4_udp_geneve_with_options |
//! | Ethernet → IPv4 → UDP(4790) → VXLAN-GPE → IPv4 → UDP | integration_ethernet_ipv4_udp_vxlan_gpe_ipv4      |
//! | Ethernet → IPv4 → UDP(4790) → VXLAN-GPE → Ethernet → IPv4 → UDP | integration_ethernet_ipv4_udp_vxlan_gpe_ethernet |
//! | Ethernet → IPv4 → UDP → VXLAN-GBP → Ethernet → IPv4 → UDP | integration_ethernet_ipv4_udp_vxlan_gbp      |
//! | Ethernet → IPv4 → UDP → VXLAN (I=0) → Ethernet → IPv4 → UDP | integration_ethernet_ipv4_udp_vxlan_i_flag_clear |
//! | Ethernet → IPv4 → UDP → L2TP → PPP → IPv4 → UDP          | ethernet_ipv4_udp_l2tp_ppp_ipv4_udp              |
//! | Ethernet → IPv4 → UDP → L2TP(L) → PPP → IPv4 → UDP      | ethernet_ipv4_udp_l2tp_length_ppp_ipv4_udp       |
//! | Ethernet → IPv4 → UDP → L2TP (control)                   | ethernet_ipv4_udp_l2tp_control                   |
//! | Ethernet → IPv4 → L2TPv3 (IP, data)                       | integration_ethernet_ipv4_l2tpv3_ip_data             |
//! | Ethernet → IPv4 → L2TPv3 (IP, data) → Ethernet → IPv4     | integration_ethernet_ipv4_l2tpv3_ethernet_pw         |
//! | Ethernet → IPv4 → L2TPv3 (IP, control SCCRQ)              | integration_ethernet_ipv4_l2tpv3_ip_control          |
//! | Ethernet → IPv4 → UDP → L2TPv3-UDP (control SCCRP)        | integration_ethernet_ipv4_udp_l2tpv3_control         |
//! | Ethernet → IPv4 → UDP → L2TPv3-UDP (data)                 | integration_ethernet_ipv4_udp_l2tpv3_data            |
//! | Ethernet → IPv4 → AH → TCP                                 | integration_ethernet_ipv4_ah_tcp                     |
//! | Ethernet → IPv4 → ESP                                       | integration_ethernet_ipv4_esp                        |
//! | Ethernet → IPv4 → ESP (NULL tunnel) → IPv4 → UDP             | integration_ethernet_ipv4_esp_null_ipv4_udp          |
//! | Ethernet → IPv4 → ESP (NULL transport) → UDP                  | integration_ethernet_ipv4_esp_null_transport_udp     |
//! | Ethernet → IPv4 → UDP(500) → IKEv2 IKE_SA_INIT              | integration_ethernet_ipv4_udp_ike_sa_init            |
//! | Ethernet → IPv4 → UDP(4500) → ESP (NULL) → IPv4 → UDP       | integration_ethernet_ipv4_udp4500_esp_null_ipv4_udp  |
//! | Ethernet → IPv4 → UDP(4500) → Non-ESP marker → IKEv2        | integration_ethernet_ipv4_udp4500_non_esp_marker_ike |
//! | Ethernet → IPv4 → UDP(4500) → NAT-keepalive                 | integration_ethernet_ipv4_udp4500_nat_keepalive      |
//! | Ethernet → IPv4 → UDP → RTP                                  | integration_ethernet_ipv4_udp_rtp                    |
//! | Ethernet → IPv4 → UDP → QUIC Initial                          | integration_ethernet_ipv4_udp_quic_initial            |
//! | Ethernet → IPv4 → UDP → QUIC Short Header                     | integration_ethernet_ipv4_udp_quic_short              |
//! | Ethernet → IPv4 → UDP → QUIC Initial + Handshake (coalesced)  | integration_ethernet_ipv4_udp_quic_coalesced          |
//! | Ethernet → IPv4 → UDP → QUIC Initial (decrypted, RFC 9001 A.2) | integration_ethernet_ipv4_udp_quic_initial_decrypted  |
//! | Ethernet → IPv4 → TCP → HTTP/2 (h2c)                        | integration_ethernet_ipv4_tcp_http2_settings         |
//! | Ethernet → IPv4 → TCP → HTTP/1.1 (via HttpDispatcher)       | integration_ethernet_ipv4_tcp_http_dispatcher_http11 |
//! | Ethernet → IPv4 → TCP → HTTP 301 (Content-Type dispatch)   | integration_ethernet_ipv4_tcp_http_response_content_type |
//! | Ethernet → IPv4 → SCTP COOKIE ACK + Ethernet pad            | integration_ethernet_ipv4_sctp_padded                |
//! | Ethernet → IPv6 → SCTP COOKIE ACK + trailer                  | integration_ethernet_ipv6_sctp_trailer               |
//! | Ethernet → IPv4 → ICMP Echo (no data) + Ethernet pad         | integration_ethernet_ipv4_icmp_echo_padded           |
//! | Ethernet → IPv4 → ESP (NULL transport) → UDP + Ethernet pad  | integration_ethernet_ipv4_esp_null_transport_udp_padded |
//! | Ethernet → IPv4 → UDP (surplus area, RFC 9868 §7) → probe    | integration_ethernet_ipv4_udp_surplus_area_not_passed_to_application |
//! | Ethernet → IPv4 → IPv4 → probe (inner Total Length bound)    | integration_ethernet_ipv4_in_ipv4_payload_bounded_by_inner_total_length |
//! | Ethernet → IPv6 → probe (Payload Length bound)               | integration_ethernet_ipv6_payload_bounded_by_payload_length |
//! | Ethernet → IPv6 (Payload Length 0) → HBH Jumbo → probe       | integration_ethernet_ipv6_zero_payload_length_hop_by_hop_not_bounded |
//! | Ethernet (802.3 Length) → LLC → probe + Ethernet pad         | integration_ethernet_802_3_llc_payload_bounded_by_length |
//! | Ethernet → IPv4 → TCP SYN + Ethernet pad + trailer           | integration_ethernet_ipv4_tcp_syn_padded             |
//! | Ethernet → IPv4 (snaplen-truncated) → TCP                    | integration_ethernet_ipv4_tcp_snaplen_truncated      |
//! | Ethernet → IPv6 (snaplen-truncated) → TCP                    | integration_ethernet_ipv6_tcp_snaplen_truncated      |
//! | Ethernet → IPv4 → UDP → DNS (cut by snaplen)                 | integration_ethernet_ipv4_udp_dns_snaplen_truncated  |
//! | Ethernet → IPv4 (snaplen-truncated) → probe                  | integration_ethernet_ipv4_snaplen_payload_ends_at_capture |
//! | Ethernet → IPv4 → TCP (snaplen) then next segment → HTTP     | integration_ethernet_ipv4_tcp_snaplen_segment_does_not_stall_reassembly |
//! | Ethernet → IPv6 (Payload Length 0, no HBH) → TCP              | integration_ethernet_ipv6_zero_payload_length_tcp_not_bounded |

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

/// 20-byte Diameter CER header without AVPs.
///
/// RFC 6733, Section 3 — <https://www.rfc-editor.org/rfc/rfc6733#section-3>
fn diameter_cer_header(hop_by_hop: u32) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 1; // Version
    h[1..4].copy_from_slice(&[0x00, 0x00, 0x14]); // Message Length = 20
    h[4] = 0x80; // R flag
    h[5..8].copy_from_slice(&[0x00, 0x01, 0x01]); // Command Code 257 (CER)
    h[12..16].copy_from_slice(&hop_by_hop.to_be_bytes());
    h[16..20].copy_from_slice(&hop_by_hop.to_be_bytes());
    h
}

/// Ethernet → IPv4 → SCTP(49152 → 3868) with the given DATA chunks
/// (`flags`, user data).
fn build_eth_ipv4_sctp_data_chunks(chunks: &[(u8, &[u8])]) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 49152, 3868);
    for (i, (flags, user_data)) in chunks.iter().enumerate() {
        push_sctp_data_chunk(&mut pkt, *flags, i as u32 + 1, 46, user_data);
    }
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

fn diameter_hop_by_hop_ids(buf: &DissectBuffer<'_>) -> Vec<u32> {
    buf.layers()
        .iter()
        .filter(|l| l.name == "Diameter")
        .map(
            |l| match buf.field_by_name(l, "hop_by_hop_id").unwrap().value {
                FieldValue::U32(v) => v,
                ref other => panic!("expected U32, got {other:?}"),
            },
        )
        .collect()
}

/// Two bundled unfragmented DATA chunks each carry a Diameter message, and
/// both are dissected.
///
/// RFC 9260, Section 6.10 — <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>
#[test]
fn integration_ethernet_ipv4_sctp_bundled_data_chunks() {
    let reg = DissectorRegistry::default();
    let first = diameter_cer_header(1);
    let second = diameter_cer_header(2);
    let data = build_eth_ipv4_sctp_data_chunks(&[(0x03, &first), (0x03, &second)]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP", "Diameter", "Diameter"]);
    assert_eq!(diameter_hop_by_hop_ids(&buf), [1, 2]);

    // Each Diameter layer covers its own DATA chunk's user data:
    // Ethernet(14) + IPv4(20) + SCTP common header(12) + DATA header(16).
    let sctp = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(sctp.range, 34..data.len());
    assert_eq!(buf.layers()[3].range, 62..82);
    assert_eq!(buf.layers()[4].range, 98..118);
}

/// A DATA chunk with only the B bit set holds the first fragment of a user
/// message. It is shown in the SCTP layer but not handed to Diameter, and
/// the packet is not an error.
///
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
/// RFC 9260, Section 6.9 — <https://www.rfc-editor.org/rfc/rfc9260#section-6.9>
#[test]
fn integration_ethernet_ipv4_sctp_fragment_not_dispatched() {
    let reg = DissectorRegistry::default();
    let cer = diameter_cer_header(1);
    let data = build_eth_ipv4_sctp_data_chunks(&[(0x02, &cer[..12])]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP"]);
}

/// A malformed user message in one bundled DATA chunk does not stop the
/// other chunks from being dissected. The error is still reported, and the
/// SCTP layer plus the well-formed Diameter messages are kept.
#[test]
fn integration_ethernet_ipv4_sctp_bundled_error_keeps_other_chunks() {
    let reg = DissectorRegistry::default();
    let first = diameter_cer_header(1);
    let malformed = [0x01, 0x00, 0x00, 0x14, 0x80, 0x00, 0x01, 0x01]; // 8 of 20 bytes
    let third = diameter_cer_header(3);
    let data =
        build_eth_ipv4_sctp_data_chunks(&[(0x03, &first), (0x03, &malformed), (0x03, &third)]);
    let mut buf = DissectBuffer::new();
    let err = reg.dissect(&data, &mut buf).unwrap_err();
    assert!(
        matches!(err, PacketError::Truncated { .. }),
        "unexpected error {err:?}"
    );

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP", "Diameter", "Diameter"]);
    assert_eq!(diameter_hop_by_hop_ids(&buf), [1, 3]);
}

/// `dissect_summary` stops at the SCTP layer for bundled DATA chunks and
/// reports the upper protocol.
#[test]
fn integration_ethernet_ipv4_sctp_bundled_summary() {
    let reg = DissectorRegistry::default();
    let first = diameter_cer_header(1);
    let second = diameter_cer_header(2);
    let data = build_eth_ipv4_sctp_data_chunks(&[(0x03, &first), (0x03, &second)]);
    let mut buf = DissectBuffer::new();
    let summary = reg.dissect_summary(&data, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP"]);
    assert_eq!(summary.next_protocol, Some("Diameter"));
    assert!(buf.embedded_payloads().is_empty());
}

/// Ethernet → IPv4 → SCTP with one unfragmented DATA chunk carrying `ppid`.
fn build_eth_ipv4_sctp_ppid(src_port: u16, dst_port: u16, ppid: u32, user_data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, src_port, dst_port);
    push_sctp_data_chunk(&mut pkt, 0x03, 1, ppid, user_data);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt
}

/// The summary names the first bundled user message whose protocol is
/// known, even when an earlier chunk's PPID is not registered.
#[test]
fn integration_ethernet_ipv4_sctp_summary_uses_first_resolvable_chunk() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 40000, 40001);
    push_sctp_data_chunk(&mut pkt, 0x03, 1, 9999, b"opaque");
    push_sctp_data_chunk(&mut pkt, 0x03, 2, 46, &diameter_cer_header(1));
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    let summary = reg.dissect_summary(&pkt, &mut buf).unwrap();
    assert_eq!(summary.next_protocol, Some("Diameter"));
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "SCTP"]);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "SCTP", "Diameter"]);
}

/// Diameter on ports registered for nothing is found by PPID 46.
///
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
/// IANA "SCTP Payload Protocol Identifiers" — <https://www.iana.org/assignments/sctp-parameters/>
#[test]
fn integration_ethernet_ipv4_sctp_ppid_diameter_nondefault_port() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_sctp_ppid(40000, 40001, 46, &diameter_cer_header(1));
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "SCTP", "Diameter"]);
    assert_eq!(diameter_hop_by_hop_ids(&buf), [1]);

    // The summary names the protocol selected by PPID.
    let mut buf = DissectBuffer::new();
    let summary = reg.dissect_summary(&data, &mut buf).unwrap();
    assert_eq!(summary.next_protocol, Some("Diameter"));
}

/// The PPID is tried before the ports: PPID 46 on the NGAP port is Diameter.
#[test]
fn integration_ethernet_ipv4_sctp_ppid_wins_over_port() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_sctp_ppid(40000, 38412, 46, &diameter_cer_header(7));
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "SCTP", "Diameter"]);
}

/// PPID 0 ("unspecified") and unregistered PPIDs fall back to the SCTP port.
///
/// RFC 9260, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
#[test]
fn integration_ethernet_ipv4_sctp_ppid_falls_back_to_port() {
    let reg = DissectorRegistry::default();
    for ppid in [0, 9999] {
        let data = build_eth_ipv4_sctp_ppid(49152, 3868, ppid, &diameter_cer_header(2));
        let mut buf = DissectBuffer::new();
        reg.dissect(&data, &mut buf).unwrap();
        assert_eq!(
            layer_names(&buf),
            ["Ethernet", "IPv4", "SCTP", "Diameter"],
            "ppid {ppid}"
        );
    }
}

/// With neither the PPID nor a port registered, the user data stays in the
/// SCTP layer.
#[test]
fn integration_ethernet_ipv4_sctp_unknown_ppid_and_port() {
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_sctp_ppid(40000, 40001, 9999, &diameter_cer_header(2));
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "SCTP"]);
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

/// RFC 7341, Sections 6 and 7.1 — a DHCPv4-query carries a DHCPDISCOVER in
/// its DHCPv4 Message option (87); the DHCPv4 message is dissected by the
/// DHCP dissector as the next layer.
#[test]
fn integration_ethernet_ipv6_udp_dhcpv4_query_dhcp_discover() {
    let reg = DissectorRegistry::default();

    let mut dhcp_opts = Vec::new();
    dhcp_opts.extend_from_slice(&dhcp_option(53, &[1])); // DHCPDISCOVER
    dhcp_opts.push(255);
    let dhcpv4 = build_dhcp_message(1, 0x0102_0304, MAC_DHCP_CLIENT, [0; 4], &dhcp_opts);

    // msg-type DHCPV4-QUERY (20), flags with the U bit clear.
    let mut dhcpv6_msg = vec![20, 0, 0, 0];
    dhcpv6_msg.extend_from_slice(&dhcpv6_option(87, &dhcpv4));
    let data = build_eth_ipv6_udp_dhcpv6(546, 547, &dhcpv6_msg);

    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv6", "UDP", "DHCPv6", "DHCP"]);

    let dhcpv6 = &buf.layers()[3];
    assert_eq!(
        buf.resolve_display_name(dhcpv6, "msg_type_name"),
        Some("DHCPV4_QUERY")
    );
    assert_eq!(buf.field_u32(dhcpv6, "flags"), Some(0));
    assert_eq!(buf.field_u8(dhcpv6, "unicast"), Some(0));

    // The DHCP layer covers exactly the DHCPv4 Message option data, which
    // follows the DHCPv6 header (4) and the option header (4).
    let dhcp = &buf.layers()[4];
    let dhcpv4_start = dhcpv6.range.start + 8;
    assert_eq!(dhcp.range, dhcpv4_start..dhcpv4_start + dhcpv4.len());
    assert_eq!(dhcp.range.end, dhcpv6.range.end);
    assert_eq!(buf.field_u32(dhcp, "xid"), Some(0x0102_0304));
    assert_eq!(
        buf.resolve_display_name(dhcp, "dhcp_message_type_name"),
        Some("DISCOVER")
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
    pkt.extend_from_slice(&[0x00, 0x09]); // DL PDU SESSION INFORMATION, QFI 9
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
    // 3GPP TS 38.415, Section 5.5.2.1 — QFI decoded from the container
    let FieldValue::Array(ref ext_range) = ext.value else {
        panic!("expected Array")
    };
    let FieldValue::Object(ref obj) = direct_children(&buf, ext_range)[0].value else {
        panic!("expected Object")
    };
    let qfi = buf
        .nested_fields(obj)
        .iter()
        .find(|f| f.name() == "qfi")
        .unwrap();
    assert_eq!(qfi.value, FieldValue::U8(9));
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

/// Ethernet → IPv4 → UDP → SIP INVITE → SDP body.
///
/// The SIP dissector returns `DispatchHint::ByContentType("application/sdp")`
/// (RFC 3261, Section 7.4) and the registry dispatches the body to the SDP
/// dissector (RFC 8866).
#[test]
fn integration_ethernet_ipv4_udp_sip_invite_with_sdp() {
    let registry = DissectorRegistry::default();

    let sdp_body = b"v=0\r\n\
                     o=alice 2890844526 2890844527 IN IP4 host.example.com\r\n\
                     s=Call to Bob\r\n\
                     c=IN IP4 198.51.100.1\r\n\
                     t=0 0\r\n\
                     m=audio 49170 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n";
    let sip_header = format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
         To: Bob <sip:bob@example.net>\r\n\
         From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
         Call-ID: a84b4c76e66710@pc33.example.com\r\n\
         CSeq: 314159 INVITE\r\n\
         Contact: <sip:alice@pc33.example.com>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        sdp_body.len()
    );

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 5060, 5060);
    pkt.extend_from_slice(sip_header.as_bytes());
    pkt.extend_from_slice(sdp_body);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "SIP");
    assert_eq!(buf.layers()[4].name, "SDP");
    assert_layers_contiguous(&buf);

    let sdp = buf.layer_by_name("SDP").unwrap();
    assert_eq!(
        buf.field_by_name(sdp, "version").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(sdp, "session_name").unwrap().value,
        FieldValue::Str("Call to Bob")
    );
    let media = buf.field_by_name(sdp, "media_descriptions").unwrap();
    let media_range = match &media.value {
        FieldValue::Array(r) => r,
        other => panic!("expected Array, got {other:?}"),
    };
    let media_obj = buf
        .nested_fields(media_range)
        .iter()
        .find(|f| f.name() == "media_description")
        .cloned()
        .unwrap();
    if let FieldValue::Object(ref r) = media_obj.value {
        let fields = buf.nested_fields(r);
        let port = fields.iter().find(|f| f.name() == "port").unwrap();
        assert_eq!(port.value, FieldValue::U16(49170));
    } else {
        panic!("expected Object");
    }
}

/// Ethernet → IPv4 → TCP → SIP with an invalid SDP body.
///
/// A body that fails to parse as SDP must not fail the whole packet: the
/// TCP fast path counts the body as consumed and terminates the chain, so
/// the already-dissected layers survive and no SDP layer is emitted.
#[test]
fn integration_ethernet_ipv4_tcp_sip_invalid_sdp_body() {
    let registry = DissectorRegistry::default();

    let body = b"this is not an sdp session description\r\n";
    let sip_header = format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 12345, 5060, 0x18); // PSH+ACK
    pkt.extend_from_slice(sip_header.as_bytes());
    pkt.extend_from_slice(body);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_eq!(buf.layers()[3].name, "SIP");
    assert!(buf.layer_by_name("SDP").is_none());
}

/// Ethernet → IPv4 → TCP → HTTP 200 → SDP body.
///
/// The HTTP dissector emits the same `ByContentType` dispatch hint as SIP,
/// so an SDP body in an HTTP response is dissected without extra wiring.
#[test]
fn integration_ethernet_ipv4_tcp_http_response_sdp_body() {
    let registry = DissectorRegistry::default();

    let sdp_body = b"v=0\r\n\
                     o=- 3724394400 3724394405 IN IP4 198.51.100.1\r\n\
                     s=RTSP-style session\r\n\
                     t=0 0\r\n\
                     m=video 51372 RTP/AVP 99\r\n";
    let http_header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n",
        sdp_body.len()
    );

    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 80, 12345, 0x18); // PSH+ACK
    pkt.extend_from_slice(http_header.as_bytes());
    pkt.extend_from_slice(sdp_body);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[3].name, "HTTP");
    assert_eq!(buf.layers()[4].name, "SDP");
    assert_layers_contiguous(&buf);

    let sdp = buf.layer_by_name("SDP").unwrap();
    assert_eq!(
        buf.field_by_name(sdp, "session_name").unwrap().value,
        FieldValue::Str("RTSP-style session")
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

/// Ethernet → IPv4 → UDP → GTPv2-C Create Session Response with a
/// piggybacked Create Bearer Request (3GPP TS 29.274, Section 5.5.1)
#[test]
fn integration_ethernet_ipv4_udp_gtpv2c_piggyback() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0xAA; 6], [0xBB; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 2123, 2123);
    let first = push_gtpv2c_with_teid(&mut pkt, 33, 0x11, 1, &[3, 0, 1, 0, 5]);
    pkt[first] |= 0x10; // P flag
    push_gtpv2c_with_teid(&mut pkt, 95, 0x22, 2, &[]);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 5);
    assert_eq!(buf.layers()[3].name, "GTPv2-C");
    assert_eq!(buf.layers()[4].name, "GTPv2-C");
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[4].range.end, pkt.len());
    let piggybacked = &buf.layers()[4];
    assert_eq!(
        display_name_for(&buf, piggybacked, "message_type"),
        Some("Create Bearer Request")
    );
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

/// dissect_with_link_type with link_type=1 (LINKTYPE_ETHERNET).
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

    // LINKTYPE_ETHERNET = 1
    let mut buf = DissectBuffer::new();
    registry.dissect_with_link_type(&pkt, 1, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_layers_contiguous(&buf);
}

// ---------------------------------------------------------------------------
// Link types without an Ethernet header
// https://www.tcpdump.org/linktypes.html
// ---------------------------------------------------------------------------

/// IPv4 → UDP packet with no link-layer header.
fn build_ipv4_udp() -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ipv4(&mut pkt, 17, [127, 0, 0, 1], [127, 0, 0, 1]);
    let udp_start = push_udp(&mut pkt, 12345, 9999);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, 0);
    pkt
}

/// IPv6 → UDP packet with no link-layer header.
fn build_ipv6_udp() -> Vec<u8> {
    let mut loopback = [0u8; 16];
    loopback[15] = 1;
    let mut pkt = Vec::new();
    push_ipv6(&mut pkt, 17, loopback, loopback);
    let udp_start = push_udp(&mut pkt, 12345, 9999);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv6_payload_length(&mut pkt, 0);
    pkt
}

fn layer_names<'a>(buf: &'a DissectBuffer<'_>) -> Vec<&'a str> {
    buf.layers().iter().map(|l| l.name).collect()
}

/// LINKTYPE_NULL (0) with AF_INET (2) in little-endian host order (e.g. a
/// macOS `lo0` capture).
#[test]
fn integration_link_type_null_ipv4_le() {
    let registry = DissectorRegistry::default();
    let mut pkt = vec![0x02, 0x00, 0x00, 0x00];
    pkt.extend_from_slice(&build_ipv4_udp());

    let mut buf = DissectBuffer::new();
    registry.dissect_with_link_type(&pkt, 0, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Null", "IPv4", "UDP"]);
    assert_layers_contiguous(&buf);
    let null = buf.layer_by_name("Null").unwrap();
    assert_eq!(
        buf.field_by_name(null, "family").unwrap().value,
        FieldValue::U32(2)
    );
}

/// LINKTYPE_NULL (0) with AF_INET (2) in big-endian host order.
#[test]
fn integration_link_type_null_ipv4_be() {
    let registry = DissectorRegistry::default();
    let mut pkt = vec![0x00, 0x00, 0x00, 0x02];
    pkt.extend_from_slice(&build_ipv4_udp());

    let mut buf = DissectBuffer::new();
    registry.dissect_with_link_type(&pkt, 0, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Null", "IPv4", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// LINKTYPE_NULL (0): 24, 28 and 30 all indicate IPv6.
#[test]
fn integration_link_type_null_ipv6() {
    let registry = DissectorRegistry::default();
    for af in [24u32, 28, 30] {
        let mut pkt = af.to_le_bytes().to_vec();
        pkt.extend_from_slice(&build_ipv6_udp());

        let mut buf = DissectBuffer::new();
        registry.dissect_with_link_type(&pkt, 0, &mut buf).unwrap();
        assert_eq!(layer_names(&buf), ["Null", "IPv6", "UDP"], "AF {af}");
        assert_layers_contiguous(&buf);
    }
}

/// LINKTYPE_LOOP (108): protocol type in big-endian order.
#[test]
fn integration_link_type_loop_ipv4() {
    let registry = DissectorRegistry::default();
    let mut pkt = vec![0x00, 0x00, 0x00, 0x02];
    pkt.extend_from_slice(&build_ipv4_udp());

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 108, &mut buf)
        .unwrap();
    assert_eq!(layer_names(&buf), ["Loop", "IPv4", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// LINKTYPE_RAW (101) carrying IPv4.
#[test]
fn integration_link_type_raw_ipv4() {
    let registry = DissectorRegistry::default();
    let pkt = build_ipv4_udp();

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 101, &mut buf)
        .unwrap();
    assert_eq!(layer_names(&buf), ["IPv4", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// LINKTYPE_RAW (101) carrying IPv6.
#[test]
fn integration_link_type_raw_ipv6() {
    let registry = DissectorRegistry::default();
    let pkt = build_ipv6_udp();

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 101, &mut buf)
        .unwrap();
    assert_eq!(layer_names(&buf), ["IPv6", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// LINKTYPE_IPV4 (228).
#[test]
fn integration_link_type_ipv4() {
    let registry = DissectorRegistry::default();
    let pkt = build_ipv4_udp();

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 228, &mut buf)
        .unwrap();
    assert_eq!(layer_names(&buf), ["IPv4", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// LINKTYPE_IPV6 (229).
#[test]
fn integration_link_type_ipv6() {
    let registry = DissectorRegistry::default();
    let pkt = build_ipv6_udp();

    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 229, &mut buf)
        .unwrap();
    assert_eq!(layer_names(&buf), ["IPv6", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// LINKTYPE_IPV4 / LINKTYPE_IPV6: a packet of the other IP version is an
/// error ("... should be considered errors").
#[test]
fn integration_link_type_ipv4_ipv6_reject_other_version() {
    let registry = DissectorRegistry::default();
    let v4 = build_ipv4_udp();
    let v6 = build_ipv6_udp();

    let mut buf = DissectBuffer::new();
    let err = registry
        .dissect_with_link_type(&v6, 228, &mut buf)
        .unwrap_err();
    assert_eq!(
        err,
        PacketError::InvalidFieldValue {
            field: "version",
            value: 6
        }
    );

    let mut buf = DissectBuffer::new();
    let err = registry
        .dissect_with_link_type(&v4, 229, &mut buf)
        .unwrap_err();
    assert_eq!(
        err,
        PacketError::InvalidFieldValue {
            field: "version",
            value: 4
        }
    );
}

/// A link type with no registered dissector must be reported, not parsed
/// as Ethernet. 147 is LINKTYPE_USER0.
#[test]
fn integration_unregistered_link_type_is_error() {
    let registry = DissectorRegistry::default();
    // A valid Ethernet frame: before the fix this was silently dissected
    // as Ethernet regardless of the link type.
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);
    pkt.extend_from_slice(&build_ipv4_udp());

    let mut buf = DissectBuffer::new();
    let err = registry
        .dissect_with_link_type(&pkt, 147, &mut buf)
        .unwrap_err();
    assert_eq!(err, PacketError::UnsupportedLinkType(147));
    assert!(buf.layers().is_empty());

    let mut buf = DissectBuffer::new();
    let err = registry
        .dissect_summary_with_link_type(&pkt, 147, &mut buf)
        .unwrap_err();
    assert_eq!(err, PacketError::UnsupportedLinkType(147));

    // dissect() without a link type keeps using the entry dissector.
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(layer_names(&buf), ["Ethernet", "IPv4", "UDP"]);
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

/// Ethernet header addressed to the Slow Protocols multicast address
/// (IEEE 802.3-2022, Annex 57A) with EtherType 0x8809.
fn slow_protocols_frame(pdu: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x01, 0x80, 0xC2, 0x00, 0x00, 0x02],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        0x8809,
    );
    pkt.extend_from_slice(pdu);
    pkt
}

/// Ethernet (EtherType 0x8809) → Marker PDU (subtype 0x02, IEEE 802.1AX-2020
/// Section 6.5.3.3).
#[test]
fn integration_ethernet_slow_protocols_marker() {
    let registry = DissectorRegistry::default();
    let mut pdu = vec![0u8; 110];
    pdu[..20].copy_from_slice(&[
        0x02, 0x01, // Marker, version 1
        0x01, 0x10, // Marker Information TLV, length 16
        0x00, 0x01, // Requester Port
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Requester System
        0x00, 0x00, 0x00, 0x01, // Requester Transaction ID
        0x00, 0x00, // Pad
        0x00, 0x00, // Terminator
    ]);
    let pkt = slow_protocols_frame(&pdu);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[1].name, "Marker");
    assert_layers_contiguous(&buf);
    let marker = buf.layer_by_name("Marker").unwrap();
    assert_eq!(
        buf.field_by_name(marker, "requester_transaction_id")
            .unwrap()
            .value,
        FieldValue::U32(1)
    );
}

/// Ethernet (EtherType 0x8809) → OAM Information OAMPDU (subtype 0x03,
/// IEEE 802.3-2022 Clause 57).
#[test]
fn integration_ethernet_slow_protocols_oam() {
    let registry = DissectorRegistry::default();
    let mut pdu = vec![0x03, 0x00, 0x08, 0x00]; // OAM, Local Evaluating, Information
    pdu.extend_from_slice(&[
        0x01, 0x10, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0xEE, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]);
    pdu.resize(46, 0);
    let pkt = slow_protocols_frame(&pdu);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[1].name, "OAM");
    assert_layers_contiguous(&buf);
    let oam = buf.layer_by_name("OAM").unwrap();
    assert_eq!(buf.field_u8(oam, "flags_local_evaluating"), Some(1));
    assert_eq!(buf.field_u8(oam, "code"), Some(0));
}

/// Ethernet (EtherType 0x8809) → OSSP with ITU-T OUI → ESMC (ITU-T G.8264
/// Section 11.3.1.1).
#[test]
fn integration_ethernet_slow_protocols_esmc() {
    let registry = DissectorRegistry::default();
    let mut pdu = vec![0x0A, 0x00, 0x19, 0xA7, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00];
    pdu.extend_from_slice(&[0x01, 0x00, 0x04, 0x02]); // QL TLV, SSM code 0x2
    pdu.resize(46, 0);
    let pkt = slow_protocols_frame(&pdu);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[1].name, "ESMC");
    assert_layers_contiguous(&buf);
    let esmc = buf.layer_by_name("ESMC").unwrap();
    assert_eq!(buf.field_u16(esmc, "itu_subtype"), Some(1));
}

/// Ethernet (EtherType 0x8809) with a subtype that has no dissector yields a
/// generic Slow Protocols layer instead of an error.
#[test]
fn integration_ethernet_slow_protocols_unknown_subtype() {
    let registry = DissectorRegistry::default();
    let mut pdu = vec![0x0B, 0x01];
    pdu.resize(46, 0);
    let pkt = slow_protocols_frame(&pdu);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 2);
    assert_eq!(buf.layers()[1].name, "SlowProtocols");
    assert_layers_contiguous(&buf);
    let slow = buf.layer_by_name("SlowProtocols").unwrap();
    assert_eq!(buf.field_u8(slow, "subtype"), Some(0x0B));
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

/// Ethernet → IPv4 → Enhanced GRE (PPTP, RFC 2637 §4.1) → PPP → IPv4 → UDP
/// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
#[test]
fn integration_ethernet_ipv4_gre_v1_ppp_ipv4() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);
    let outer_ipv4_start = push_ipv4(&mut pkt, 47, [10, 0, 0, 1], [10, 0, 0, 2]);

    // Enhanced GRE: K=1 S=1 A=1, ver=1, Protocol Type 0x880B (PPP)
    pkt.extend_from_slice(&[0x30, 0x81, 0x88, 0x0B]);
    let payload_length_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]); // Payload Length (placeholder)
    pkt.extend_from_slice(&42u16.to_be_bytes()); // Call ID
    pkt.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Acknowledgment Number
    let gre_payload_start = pkt.len();

    // PPP without HDLC framing, Protocol 0x0021 (IPv4)
    pkt.extend_from_slice(&[0x00, 0x21]);
    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);
    let payload_length = (pkt.len() - gre_payload_start) as u16;
    pkt[payload_length_offset..payload_length_offset + 2]
        .copy_from_slice(&payload_length.to_be_bytes());
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "GRE", "PPP", "IPv4", "UDP"]);
    assert_layers_contiguous(&buf);

    let gre = buf.layer_by_name("GRE").unwrap();
    assert_eq!(gre.range.len(), 16);
    assert_eq!(buf.field_u8(gre, "version"), Some(1));
    assert_eq!(buf.field_u16(gre, "payload_length"), Some(payload_length));
    assert_eq!(buf.field_u16(gre, "call_id"), Some(42));
    assert_eq!(buf.field_u32(gre, "sequence_number"), Some(1));
    assert_eq!(buf.field_u32(gre, "acknowledgment_number"), Some(0));
}

/// Ethernet → IPv4 → Enhanced GRE acknowledgment-only packet (RFC 2637 §4.1)
/// <https://www.rfc-editor.org/rfc/rfc2637#section-4.1>
#[test]
fn integration_ethernet_ipv4_gre_v1_ack_only() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);
    let outer_ipv4_start = push_ipv4(&mut pkt, 47, [10, 0, 0, 1], [10, 0, 0, 2]);
    // K=1 A=1, ver=1, PPP, Payload Length 0, Call ID 42, Ack 5
    pkt.extend_from_slice(&[
        0x20, 0x81, 0x88, 0x0B, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x05,
    ]);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "GRE"]);
    assert_layers_contiguous(&buf);
    let gre = buf.layer_by_name("GRE").unwrap();
    assert_eq!(buf.field_u32(gre, "acknowledgment_number"), Some(5));
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

/// Ethernet → LLC → MST BPDU (IEEE 802.1Q-2022, Clause 14.4) with one MSTI.
#[test]
fn integration_ethernet_llc_mstp() {
    let mut pkt = Vec::new();
    let len_offset = push_ethernet_llc(&mut pkt, STP_DST, MAC_SRC_STP);
    push_rstp_bpdu(&mut pkt);
    let bpdu_start = pkt.len() - 36;
    pkt[bpdu_start + 2] = 0x03; // Version 3
    pkt.extend_from_slice(&80u16.to_be_bytes()); // Version 3 Length
    pkt.push(0x00); // Format Selector
    pkt.extend_from_slice(&[0u8; 32]); // Configuration Name
    pkt.extend_from_slice(&[0u8; 2 + 16]); // Revision Level, Digest
    pkt.extend_from_slice(&[0u8; 4]); // CIST Internal Root Path Cost
    pkt.extend_from_slice(&[0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // CIST Bridge ID
    pkt.push(20); // CIST Remaining Hops
    let mut msti = [0u8; 16];
    msti[1..3].copy_from_slice(&0x8001u16.to_be_bytes());
    pkt.extend_from_slice(&msti);
    fixup_802_3_length(&mut pkt, len_offset);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 2);
    assert_layers_contiguous(&buf);
    let stp = &buf.layers()[1];
    assert_eq!(stp.range.len(), 118);
    assert_eq!(display_name_for(&buf, stp, "bpdu_type"), Some("MST"));
    assert_eq!(
        buf.field_by_name(stp, "cist_remaining_hops").unwrap().value,
        FieldValue::U8(20)
    );
    assert!(buf.field_by_name(stp, "mstis").unwrap().value.is_array());
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

/// Ethernet → LLDP with an IEEE 802.1 Port VLAN ID TLV decoded into `org`
/// (IEEE 802.1AB-2005 Annex F.2).
#[test]
fn integration_ethernet_lldp_org_port_vlan_id() {
    let reg = DissectorRegistry::default();
    let mut data = build_eth_lldp();
    data.truncate(data.len() - 2); // drop End Of LLDPDU
    data.extend_from_slice(&[0xFE, 0x06, 0x00, 0x80, 0xC2, 0x01, 0x00, 0x64]);
    data.extend_from_slice(&[0x00, 0x00]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();
    assert_layers_contiguous(&buf);

    // tlvs[4] (after Chassis ID, Port ID, TTL, System Name) → org → pvid.
    let lldp = buf.layer_by_name("LLDP").unwrap();
    let FieldValue::Array(tlvs) = &buf.field_by_name(lldp, "tlvs").unwrap().value else {
        panic!("tlvs")
    };
    let org_tlv = buf
        .nested_fields(tlvs)
        .iter()
        .filter_map(|f| match &f.value {
            FieldValue::Object(r) => Some(buf.nested_fields(r)),
            _ => None,
        })
        .nth(4)
        .unwrap();
    let FieldValue::Object(org) = &org_tlv.iter().find(|f| f.name() == "org").unwrap().value else {
        panic!("org")
    };
    let pvid = buf
        .nested_fields(org)
        .iter()
        .find(|f| f.name() == "pvid")
        .unwrap();
    assert_eq!(pvid.value, FieldValue::U16(100));
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

/// Minimal BFD Control packet (24 bytes, RFC 5880 §4.1, state Up).
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.1>
fn push_bfd_control(pkt: &mut Vec<u8>) {
    pkt.extend_from_slice(&[0x20, 0xC0, 0x03, 0x18]); // v1, Up, detect mult 3, len 24
    pkt.extend_from_slice(&1u32.to_be_bytes()); // my discriminator
    pkt.extend_from_slice(&2u32.to_be_bytes()); // your discriminator
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // desired min tx
    pkt.extend_from_slice(&1_000_000u32.to_be_bytes()); // required min rx
    pkt.extend_from_slice(&0u32.to_be_bytes()); // required min echo rx
}

/// Ethernet → MPLS (GAL) → ACH (0x0007) → BFD — VCCV BFD without IP/UDP
/// (RFC 5586 §4 — <https://www.rfc-editor.org/rfc/rfc5586#section-4>, RFC 5885 §3.2 —
/// <https://www.rfc-editor.org/rfc/rfc5885#section-3.2>)
#[test]
fn integration_ethernet_mpls_gal_ach_bfd() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x00; 6], 0x8847);
    push_mpls(&mut pkt, 13, 0, 1, 1);
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x07]);
    push_bfd_control(&mut pkt);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "MPLS", "ACH", "BFD"]);
    assert_layers_contiguous(&buf);
}

/// Ethernet → MPLS → PW-ACH (0x0021) → IPv4 → UDP (RFC 4385 §5 —
/// <https://www.rfc-editor.org/rfc/rfc4385#section-5>)
#[test]
fn integration_ethernet_mpls_pw_ach_ipv4() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x00; 6], 0x8847);
    push_mpls(&mut pkt, 100, 0, 1, 64);
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x21]);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "MPLS", "ACH", "IPv4", "UDP"]);
    assert_layers_contiguous(&buf);
}

/// Ethernet → MPLS → Ethernet PW *without* a control word whose destination
/// MAC starts with nibble 0. The first nibble cannot tell this apart from a
/// control word (RFC 4928 §3 — <https://www.rfc-editor.org/rfc/rfc4928#section-3>),
/// but the Length bits the MAC lands on are reserved for an Ethernet PW
/// (RFC 4448 §4.6 — <https://www.rfc-editor.org/rfc/rfc4448#section-4.6>), so
/// they must not cut the payload short and fail the whole packet.
#[test]
fn integration_ethernet_mpls_pw_without_control_word_does_not_fail() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x00; 6], 0x8847);
    push_mpls(&mut pkt, 16, 0, 1, 64);
    // Tagged inner Ethernet: DA 00:1b:21:3a:4b:5c, VLAN 100, IPv4
    pkt.extend_from_slice(&[0x00, 0x1B, 0x21, 0x3A, 0x4B, 0x5C]);
    pkt.extend_from_slice(&[0x66; 6]);
    pkt.extend_from_slice(&[0x81, 0x00, 0x00, 0x64, 0x08, 0x00]);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[1].name, "MPLS");
}

/// Ethernet → MPLS → PW control word → Ethernet → IPv4 → UDP (RFC 4385 §3 —
/// <https://www.rfc-editor.org/rfc/rfc4385#section-3>, RFC 4448 §4.6 — <https://www.rfc-editor.org/rfc/rfc4448#section-4.6>)
#[test]
fn integration_ethernet_mpls_pw_control_word_ethernet() {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x00; 6], 0x8847);
    push_mpls(&mut pkt, 16, 0, 1, 64);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // control word, sequence 1
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0x66; 6],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let udp_start = push_udp(&mut pkt, 12345, 80);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let reg = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(
        names,
        ["Ethernet", "MPLS", "PW-CW", "Ethernet", "IPv4", "UDP"]
    );
    assert_layers_contiguous(&buf);
    let cw = buf.layer_by_name("PW-CW").unwrap();
    assert_eq!(
        buf.field_by_name(cw, "payload_heuristic").unwrap().value,
        FieldValue::Str("ethernet")
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

/// Build an Ethernet → IPv4 → UDP(`dst_port`) packet carrying the `tunnel`
/// header followed by whatever `inner` appends.
fn build_udp_tunnel_packet(
    dst_port: u16,
    tunnel: &[u8],
    inner: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0xff; 6], [0x11; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 50000, dst_port);
    pkt.extend_from_slice(tunnel);
    inner(&mut pkt);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);
    pkt
}

/// Inner IPv4 → UDP.
fn push_inner_ipv4_udp(pkt: &mut Vec<u8>) {
    let start = push_ipv4(pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let udp_start = push_udp(pkt, 12345, 80);
    fixup_udp_length(pkt, udp_start);
    fixup_ipv4_length(pkt, start);
}

/// Ethernet → IPv4 → UDP(4790) → VXLAN-GPE (Next Protocol IPv4) → IPv4 → UDP
/// (draft-ietf-nvo3-vxlan-gpe-13 §3.2 —
/// <https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-3.2>)
#[test]
fn integration_ethernet_ipv4_udp_vxlan_gpe_ipv4() {
    let reg = DissectorRegistry::default();
    // Ver 0, I=1, P=1; Next Protocol 0x01 (IPv4); VNI 100
    let gpe = [0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0x64, 0x00];
    let pkt = build_udp_tunnel_packet(4790, &gpe, push_inner_ipv4_udp);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(
        names,
        ["Ethernet", "IPv4", "UDP", "VXLAN-GPE", "IPv4", "UDP"]
    );
    assert_layers_contiguous(&buf);
    let layer = buf.layer_by_name("VXLAN-GPE").unwrap();
    assert_eq!(buf.field_u32(layer, "vni"), Some(100));
    assert_eq!(buf.field_u8(layer, "next_protocol"), Some(1));
}

/// Ethernet → IPv4 → UDP(4790) → VXLAN-GPE (Next Protocol Ethernet) →
/// Ethernet → IPv4 → UDP
#[test]
fn integration_ethernet_ipv4_udp_vxlan_gpe_ethernet() {
    let reg = DissectorRegistry::default();
    let gpe = [0x0C, 0x00, 0x00, 0x03, 0x00, 0x00, 0x64, 0x00];
    let pkt = build_udp_tunnel_packet(4790, &gpe, |pkt| {
        push_ethernet(pkt, [0xaa; 6], [0xbb; 6], 0x0800);
        push_inner_ipv4_udp(pkt);
    });

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(
        names,
        [
            "Ethernet",
            "IPv4",
            "UDP",
            "VXLAN-GPE",
            "Ethernet",
            "IPv4",
            "UDP"
        ]
    );
    assert_layers_contiguous(&buf);
}

/// Ethernet → IPv4 → UDP(4789) → VXLAN-GBP → Ethernet → IPv4 → UDP
#[test]
fn integration_ethernet_ipv4_udp_vxlan_gbp() {
    let reg = DissectorRegistry::default();
    // G=1 I=1, Group Policy ID 0x1234, VNI 100
    let vxlan = [0x88, 0x00, 0x12, 0x34, 0x00, 0x00, 0x64, 0x00];
    let pkt = build_udp_tunnel_packet(4789, &vxlan, |pkt| {
        push_ethernet(pkt, [0xaa; 6], [0xbb; 6], 0x0800);
        push_inner_ipv4_udp(pkt);
    });

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(
        names,
        [
            "Ethernet", "IPv4", "UDP", "VXLAN", "Ethernet", "IPv4", "UDP"
        ]
    );
    assert_layers_contiguous(&buf);
    let layer = buf.layer_by_name("VXLAN").unwrap();
    assert_eq!(buf.field_u16(layer, "group_policy_id"), Some(0x1234));
}

/// Ethernet → IPv4 → UDP(4789) → VXLAN (I=0) → Ethernet → IPv4 → UDP
///
/// RFC 7348, Section 5 gives receivers no instruction to discard I=0
/// packets, so the payload is still decoded.
/// <https://www.rfc-editor.org/rfc/rfc7348#section-5>
#[test]
fn integration_ethernet_ipv4_udp_vxlan_i_flag_clear() {
    let reg = DissectorRegistry::default();
    let vxlan = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00];
    let pkt = build_udp_tunnel_packet(4789, &vxlan, |pkt| {
        push_ethernet(pkt, [0xaa; 6], [0xbb; 6], 0x0800);
        push_inner_ipv4_udp(pkt);
    });

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 7);
    assert_layers_contiguous(&buf);
    let layer = buf.layer_by_name("VXLAN").unwrap();
    assert_eq!(buf.field_u8(layer, "vni_valid"), Some(0));
}

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

#[test]
fn integration_ethernet_ipv4_udp_ntp_control_request() {
    // RFC 9327, Section 2 — a 12-octet `ntpq -c rv` request (mode 6).
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 50000, 123);
    pkt.extend_from_slice(&[0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();

    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    let ntp = &buf.layers()[3];
    assert_eq!(ntp.name, "NTP");
    assert_eq!(
        buf.field_by_name(ntp, "mode").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(ntp, "opcode").unwrap().value,
        FieldValue::U8(2)
    );
    assert!(buf.field_by_name(ntp, "stratum").is_none());
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

/// Build Ethernet/IPv4/UDP to `dst_port` carrying `payload`.
fn build_eth_ipv4_udp_payload(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, src_port, dst_port);
    pkt.extend_from_slice(payload);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);
    pkt
}

/// Minimal BFD Control packet (RFC 5880, Section 4.1) in the Down state.
///   <https://www.rfc-editor.org/rfc/rfc5880#section-4.1>
fn bfd_control_down(my_disc: u32) -> Vec<u8> {
    let mut p = vec![1u8 << 5, 1u8 << 6, 3, 24];
    p.extend_from_slice(&my_disc.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&1_000_000u32.to_be_bytes());
    p.extend_from_slice(&1_000_000u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

#[test]
fn integration_ethernet_ipv4_udp_bfd_echo_opaque() {
    // RFC 5880, Section 5 — the Echo payload is a local matter and must not
    // make the frame fail.
    //   <https://www.rfc-editor.org/rfc/rfc5880#section-5>
    let payloads: [&[u8]; 2] = [
        &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a],
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ],
    ];
    let registry = DissectorRegistry::default();
    for payload in payloads {
        let pkt = build_eth_ipv4_udp_payload(3785, 3785, payload);
        let mut buf = DissectBuffer::new();
        registry.dissect(&pkt, &mut buf).unwrap();
        assert_eq!(buf.layers().len(), 4);
        assert_layers_contiguous(&buf);
        let echo = &buf.layers()[3];
        assert_eq!(echo.name, "BFD-Echo");
        assert_eq!(
            buf.field_by_name(echo, "payload").unwrap().value,
            FieldValue::Bytes(payload)
        );
    }
}

#[test]
fn integration_ethernet_ipv4_udp_bfd_echo_control() {
    // RFC 9747, Section 2 — Unaffiliated BFD Echo uses the Control format on
    // UDP 3785.
    //   <https://www.rfc-editor.org/rfc/rfc9747#section-2>
    let pkt = build_eth_ipv4_udp_payload(49152, 3785, &bfd_control_down(0x55));
    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    let bfd = &buf.layers()[3];
    assert_eq!(bfd.name, "BFD-Echo");
    assert_eq!(bfd.display_name, None);
    assert_eq!(
        buf.field_by_name(bfd, "my_discriminator").unwrap().value,
        FieldValue::U32(0x55)
    );
}

#[test]
fn integration_ethernet_ipv4_udp_sbfd_and_micro_bfd() {
    // RFC 7881, Section 2 (S-BFD, UDP 7784) and RFC 7130, Section 2.2
    // (Micro-BFD, UDP 6784) both carry BFD Control packets.
    //   <https://www.rfc-editor.org/rfc/rfc7881#section-2>
    //   <https://www.rfc-editor.org/rfc/rfc7130#section-2.2>
    let registry = DissectorRegistry::default();
    for (src, dst) in [(49152, 7784), (7784, 49152), (49152, 6784)] {
        let pkt = build_eth_ipv4_udp_payload(src, dst, &bfd_control_down(7));
        let mut buf = DissectBuffer::new();
        registry.dissect(&pkt, &mut buf).unwrap();
        assert_eq!(buf.layers().len(), 4, "ports {src} -> {dst}");
        assert_layers_contiguous(&buf);
        let bfd = &buf.layers()[3];
        assert_eq!(bfd.name, "BFD");
        assert_eq!(bfd.display_name, None);
    }
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
    // RFC 8926 §3.5 — the option TLV is decoded too.
    // https://www.rfc-editor.org/rfc/rfc8926#section-3.5
    let list = buf.field_by_name(geneve, "tunnel_options").unwrap();
    let objects: Vec<_> = buf
        .nested_fields(list.value.as_container_range().unwrap())
        .iter()
        .filter_map(|f| f.value.as_container_range())
        .collect();
    assert_eq!(objects.len(), 1);
    assert_eq!(
        buf.resolve_nested_display_name(objects[0], "class_name"),
        Some("Open Virtual Networking (OVN)")
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
// Ethernet → IPv4 → OSPFv2 LSU (Router-LSA) with cryptographic authentication
// ---------------------------------------------------------------------------

/// The OSPFv2 layer covers the message digest that follows `packet_length`
/// (RFC 2328, Appendix D.3), and the LSA body is decoded (RFC 2328,
/// Appendix A.4.2).
#[test]
fn integration_ethernet_ipv4_ospfv2_lsu_with_digest() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05],
        [0xaa; 6],
        0x0800,
    );
    let ipv4_start = push_ipv4(&mut pkt, 89, [10, 0, 0, 1], [224, 0, 0, 5]);

    let ospf_start = pkt.len();
    pkt.extend_from_slice(&[2, 4, 0, 64]); // v2, LSU, length 64
    pkt.extend_from_slice(&[1, 1, 1, 1, 0, 0, 0, 0]); // Router ID, Area ID
    pkt.extend_from_slice(&[0, 0, 0, 2]); // Checksum, AuType 2
    pkt.extend_from_slice(&[0, 0, 1, 16, 0, 0, 0, 5]); // Key ID 1, len 16, seq 5
    pkt.extend_from_slice(&[0, 0, 0, 1]); // # LSAs
    pkt.extend_from_slice(&[0, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1]); // Router-LSA header
    pkt.extend_from_slice(&[0x80, 0, 0, 1, 0, 0, 0, 36]);
    pkt.extend_from_slice(&[0, 0, 0, 1]); // flags, #links = 1
    pkt.extend_from_slice(&[192, 0, 2, 0, 255, 255, 255, 0, 3, 0, 0, 10]);
    assert_eq!(pkt.len() - ospf_start, 64);
    pkt.extend_from_slice(&[0x5a; 16]); // MD5 digest
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    let ospf = buf.layer_by_name("OSPFv2").unwrap();
    assert_eq!(ospf.range, ospf_start..pkt.len());
    assert_eq!(
        buf.field_by_name(ospf, "auth_digest").unwrap().value,
        FieldValue::Bytes(&[0x5a; 16])
    );
    assert_eq!(
        buf.field_by_name(ospf, "link_id").unwrap().value,
        FieldValue::Ipv4Addr([192, 0, 2, 0])
    );
    assert_eq!(
        buf.field_by_name(ospf, "num_links").unwrap().value,
        FieldValue::U16(1)
    );
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
    // Labelled from the ClientHello legacy_version, not the 0x0301 record.
    assert_eq!(tls.display_name, Some("TLSv1.2"));
    let msgs = tls_handshake_messages(&buf, tls);
    assert_eq!(msgs.len(), 1);
    let FieldValue::Object(ref ch_range) = msgs[0].value else {
        panic!("expected Object")
    };
    let ch = buf.nested_fields(ch_range);
    assert_eq!(ch[0].name(), "type");
    assert_eq!(ch[0].value, FieldValue::U8(1));
    assert_eq!(
        buf.resolve_nested_display_name(ch_range, "type_name"),
        Some("Client Hello")
    );
    // ClientHello body fields
    let field = |name: &str| ch.iter().find(|f| f.name() == name).unwrap();
    assert_eq!(field("version").value, FieldValue::U16(0x0303));
    let FieldValue::Array(ref suites_range) = field("cipher_suites").value else {
        panic!("expected Array")
    };
    let suites = buf.nested_fields(suites_range);
    assert_eq!(suites.len(), 2);
    assert_eq!(suites[0].value, FieldValue::U16(0x1301));
    assert_eq!(suites[1].value, FieldValue::U16(0xc02f));
    // SNI extension
    let FieldValue::Array(ref exts_range) = field("extensions").value else {
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
    let msgs = tls_handshake_messages(&buf, tls);
    assert_eq!(msgs.len(), 1);
    let FieldValue::Object(ref sh_range) = msgs[0].value else {
        panic!("expected Object")
    };
    let sh = buf.nested_fields(sh_range);
    assert_eq!(sh[0].value, FieldValue::U8(2));
    assert_eq!(
        buf.resolve_nested_display_name(sh_range, "type_name"),
        Some("Server Hello")
    );
    assert_eq!(
        sh.iter()
            .find(|f| f.name() == "cipher_suite")
            .unwrap()
            .value,
        FieldValue::U16(0x1301)
    );
    assert_eq!(
        buf.resolve_nested_display_name(sh_range, "cipher_suite_name"),
        Some("TLS_AES_128_GCM_SHA256")
    );
}

/// Direct children of the TLS layer's `handshake_messages` array.
fn tls_handshake_messages<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    tls: &packet_dissector::packet::Layer,
) -> Vec<&'a packet_dissector::field::Field<'pkt>> {
    let FieldValue::Array(ref range) = buf.field_by_name(tls, "handshake_messages").unwrap().value
    else {
        panic!("expected Array")
    };
    direct_children(buf, range)
}

#[test]
fn ethernet_ipv4_tcp_tls_coalesced_server_flight() {
    // RFC 9846, Section 5.1 — https://www.rfc-editor.org/rfc/rfc9846#section-5.1
    // ServerHello, Certificate and ServerHelloDone in one record.
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 2], [10, 0, 0, 1]);
    push_tcp(&mut pkt, 443, 50000, 0x18);

    let mut hs = vec![0x02, 0x00, 0x00, 0x26, 0x03, 0x03];
    hs.extend_from_slice(&[0x11; 32]);
    hs.extend_from_slice(&[0x00, 0xc0, 0x2f, 0x00]);
    hs.extend_from_slice(&[0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
    hs.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]);
    push_tls_record(&mut pkt, 0x16, 0x0303, &hs);

    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);

    let tls = buf.layer_by_name("TLS").unwrap();
    assert_eq!(tls.display_name, Some("TLSv1.2"));
    let types: Vec<FieldValue> = tls_handshake_messages(&buf, tls)
        .iter()
        .map(|m| {
            let FieldValue::Object(ref r) = m.value else {
                panic!("expected Object")
            };
            buf.nested_fields(r)[0].value.clone()
        })
        .collect();
    assert_eq!(
        types,
        vec![FieldValue::U8(2), FieldValue::U8(11), FieldValue::U8(14)]
    );
}

#[test]
fn ethernet_ipv4_tcp_tls13_client_hello_extensions() {
    // RFC 7301, Section 3.1 (ALPN) and RFC 9846, Section 4.3.8 (key_share).
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 50000, 443, 0x18);

    let mut exts = Vec::new();
    // application_layer_protocol_negotiation: ["h2"]
    exts.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
    // key_share: x25519 with a 4-byte key
    exts.extend_from_slice(&[
        0x00, 0x33, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x04, 1, 2, 3, 4,
    ]);
    let mut ch = vec![0x03, 0x03];
    ch.extend_from_slice(&[0xaa; 32]);
    ch.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);
    let mut hs = vec![0x01, 0x00];
    hs.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ch);
    push_tls_record(&mut pkt, 0x16, 0x0301, &hs);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);

    let names: Vec<&str> = buf.fields().iter().map(|f| f.name()).collect();
    let alpn = buf
        .fields()
        .iter()
        .find(|f| f.name() == "protocol_name")
        .unwrap();
    assert_eq!(alpn.value, FieldValue::Bytes(b"h2"));
    let key = buf
        .fields()
        .iter()
        .find(|f| f.name() == "key_exchange")
        .unwrap();
    assert_eq!(key.value, FieldValue::Bytes(&[1, 2, 3, 4]));
    assert!(names.contains(&"client_shares"));
}

#[test]
fn ethernet_ipv4_tcp_non_tls_on_port_443() {
    // A payload that is not a TLS record is not reported as TLS.
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 50000, 443, 0x18);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    let err = registry.dissect(&pkt, &mut buf).unwrap_err();
    assert_eq!(
        err,
        PacketError::InvalidFieldValue {
            field: "content_type",
            value: 0
        }
    );
    assert!(buf.layer_by_name("TLS").is_none());
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

/// Ethernet → IPv4 → L2TPv3 (IP, data) → Ethernet → IPv4 (RFC 4719
/// Ethernet pseudowire, no cookie, no L2-Specific Sublayer).
/// <https://www.rfc-editor.org/rfc/rfc4719>
#[test]
fn integration_ethernet_ipv4_l2tpv3_ethernet_pw() {
    let registry = DissectorRegistry::default();

    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ip_start = pkt.len();
    push_ipv4(&mut pkt, 115, [10, 0, 0, 1], [10, 0, 0, 2]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x12, 0x34]);
    push_ethernet(&mut pkt, [0x02; 6], [0x03; 6], 0x0800);
    let inner_ip = pkt.len();
    push_ipv4(&mut pkt, 17, [192, 168, 0, 1], [192, 168, 0, 2]);
    fixup_ipv4_length(&mut pkt, inner_ip);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    registry.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(
        names[..5],
        ["Ethernet", "IPv4", "L2TPv3", "Ethernet", "IPv4"]
    );
    assert_layers_contiguous(&buf);
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
// PPP → LCP (via link_type=50, LINKTYPE_PPP_HDLC, control protocol inline)
// ---------------------------------------------------------------------------

#[test]
fn integration_ppp_lcp_inline() {
    let registry = DissectorRegistry::default();
    let mut pkt = Vec::new();

    // LINKTYPE_PPP_HDLC frames carry the RFC 1662, Section 3.1 Address and
    // Control fields (no flag octets) —
    // https://www.tcpdump.org/linktypes/LINKTYPE_PPP_HDLC.html
    // https://www.rfc-editor.org/rfc/rfc1662#section-3.1
    // Address=0xFF, Control=0x03, Protocol=0xC021 (LCP)
    pkt.extend_from_slice(&[0xFF, 0x03, 0xC0, 0x21]);

    // LCP Configure-Request with MRU option
    #[rustfmt::skip]
    pkt.extend_from_slice(&[
        0x01, 0x01, 0x00, 0x08, // Code=1 (Configure-Request), Id=1, Len=8
        1, 4, 0x05, 0xDC,       // MRU=1500
    ]);

    // LINKTYPE_PPP_HDLC = 50
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

/// Ethernet → IPv4 → UDP(4500) → ESP (NULL, tunnel mode) → IPv4 → UDP
///
/// RFC 3948, Section 2.1 — UDP-encapsulated ESP for NAT traversal. The SPI
/// field is non-zero, which distinguishes ESP from the Non-ESP marker that
/// prefixes IKE on the same port.
/// <https://www.rfc-editor.org/rfc/rfc3948#section-2.1>
#[test]
#[cfg(all(feature = "esp", feature = "udp", feature = "ipv4"))]
fn integration_ethernet_ipv4_udp4500_esp_null_ipv4_udp() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let outer_ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 4500, 4500);

    // ESP header — SPI MUST NOT be zero (RFC 3948, Section 2.1).
    pkt.extend_from_slice(&0x0000_5005u32.to_be_bytes());
    pkt.extend_from_slice(&9u32.to_be_bytes());

    let inner_ipv4_start = push_ipv4(&mut pkt, 17, [192, 168, 1, 1], [192, 168, 1, 2]);
    let inner_udp_start = push_udp(&mut pkt, 12345, 54321);
    pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    fixup_udp_length(&mut pkt, inner_udp_start);
    fixup_ipv4_length(&mut pkt, inner_ipv4_start);

    // ESP trailer: pad_length=0, next_header=4 (IPv4-in-IPv4)
    pkt.push(0x00);
    pkt.push(0x04);

    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, outer_ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet, outer IPv4, UDP, ESP, inner IPv4, inner UDP
    assert_eq!(buf.layers().len(), 6);
    assert_eq!(buf.layers()[2].name, "UDP");
    assert_eq!(buf.layers()[3].name, "ESP");
    assert_eq!(buf.layers()[4].name, "IPv4");
    assert_eq!(buf.layers()[5].name, "UDP");

    let esp = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(esp, "spi").unwrap().value,
        FieldValue::U32(0x0000_5005)
    );
    assert_eq!(
        buf.field_by_name(esp, "next_header").unwrap().value,
        FieldValue::U8(4)
    );

    let inner_udp = &buf.layers()[5];
    assert_eq!(
        buf.field_by_name(inner_udp, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
}

/// Ethernet → IPv4 → UDP(4500) → Non-ESP marker → IKEv2 IKE_SA_INIT
///
/// RFC 3948, Section 2.2 — "A Non-ESP Marker is 4 zero-valued bytes aligning
/// with the SPI field of an ESP packet."
/// <https://www.rfc-editor.org/rfc/rfc3948#section-2.2>
#[test]
#[cfg(all(feature = "ike", feature = "udp", feature = "ipv4"))]
fn integration_ethernet_ipv4_udp4500_non_esp_marker_ike() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 4500, 4500);

    pkt.extend_from_slice(&[0x00; 4]); // Non-ESP marker

    // IKE header (28 bytes) + one SA payload (8 bytes)
    pkt.extend_from_slice(&[0x01; 8]); // Initiator SPI
    pkt.extend_from_slice(&[0x00; 8]); // Responder SPI
    pkt.push(33); // Next Payload: SA
    pkt.push(0x20); // Version 2.0
    pkt.push(34); // IKE_SA_INIT
    pkt.push(0x08); // Flags: Initiator
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&36u32.to_be_bytes());
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
}

/// Ethernet → IPv4 → UDP(4500) → NAT-keepalive
///
/// RFC 3948, Section 2.3 — "The sender MUST use a one-octet-long payload with
/// the value 0xFF." It is neither ESP nor IKE, so no further layer appears.
/// <https://www.rfc-editor.org/rfc/rfc3948#section-2.3>
#[test]
#[cfg(all(feature = "esp", feature = "udp", feature = "ipv4"))]
fn integration_ethernet_ipv4_udp4500_nat_keepalive() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();

    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 4500, 4500);
    pkt.push(0xFF);
    fixup_udp_length(&mut pkt, udp_start);
    fixup_ipv4_length(&mut pkt, ipv4_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Ethernet, IPv4, UDP only — a keepalive carries no protocol payload.
    assert_eq!(buf.layers().len(), 3);
    assert_eq!(buf.layers()[2].name, "UDP");
    assert!(buf.layer_by_name("ESP").is_none());
    assert!(buf.layer_by_name("IKE").is_none());
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

/// NGAP on a non-default port is found by PPID 60 (IANA "SCTP Payload
/// Protocol Identifiers" — <https://www.iana.org/assignments/sctp-parameters/>).
#[cfg(all(feature = "sctp", feature = "ngap"))]
#[test]
fn integration_ethernet_ipv4_sctp_ppid_ngap_nondefault_port() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
    push_sctp(&mut pkt, 9487, 40001);
    push_sctp_data_chunk(&mut pkt, 0x03, 1, 60, NGAP_NG_SETUP_REQUEST);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP", "NGAP"]);
}

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

// ---------------------------------------------------------------------------
// SCTP → SGsAP (SGsAP-PAGING-REQUEST)
// ---------------------------------------------------------------------------

/// SGsAP-PAGING-REQUEST: IMSI, VLR name and service indicator "CS call
/// indicator" (3GPP TS 29.118, Section 8.14).
#[cfg(all(feature = "sctp", feature = "sgsap"))]
const SGSAP_PAGING_REQUEST: &[u8] = &[
    0x01, 0x01, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x02, 0x04, 0x03, b'v', b'l',
    b'r', 0x20, 0x01, 0x01,
];

/// SGsAP is found by its registered SCTP port 29118; its payload protocol
/// identifier 0 is "unspecified" and does not select it on another port
/// (3GPP TS 29.118, Section 6.3).
#[cfg(all(feature = "sctp", feature = "sgsap"))]
#[test]
fn integration_ethernet_ipv4_sctp_sgsap_paging_request() {
    let reg = DissectorRegistry::default();
    for (dst_port, expected) in [(29118, Some("SGsAP")), (40000, None)] {
        let mut pkt = Vec::new();
        push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
        let ip_start = push_ipv4(&mut pkt, 132, IPV4_SRC, IPV4_DST);
        push_sctp(&mut pkt, 9487, dst_port);
        push_sctp_data_chunk(&mut pkt, 0x03, 1, 0, SGSAP_PAGING_REQUEST);
        fixup_ipv4_length(&mut pkt, ip_start);

        let mut buf = DissectBuffer::new();
        reg.dissect(&pkt, &mut buf).unwrap();
        assert_eq!(buf.layers().get(3).map(|l| l.name), expected, "{dst_port}");
        if expected.is_none() {
            continue;
        }
        let sgsap = &buf.layers()[3];
        assert_eq!(
            display_name_for(&buf, sgsap, "message_type"),
            Some("SGsAP-PAGING-REQUEST")
        );
        let ies = buf.field_by_name(sgsap, "ies").unwrap();
        let FieldValue::Array(ref arr) = ies.value else {
            panic!("expected ies to be Array");
        };
        assert_eq!(direct_children(&buf, arr).len(), 3);
    }
}

/// NGAP InitialUEMessage with parsed IE values: RAN-UE-NGAP-ID, NAS-PDU
/// with plain 5GMM Registration Request, UEContextRequest and
/// RRCEstablishmentCause, all APER-encoded (3GPP TS 38.413, Section 9.5).
///
/// Values match an independent APER encoder (pycrate `NGAP_IEs`).
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
    container.push(0x02); // length = 2
    // 2-bit octet count - 1 (0), padding, value 42 — ITU-T X.691, 11.5.7.4.
    container.extend_from_slice(&[0x00, 0x2A]);

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
    // Extension bit 0, 4-bit index 3 (mo-Signalling), padding — ITU-T X.691, 14.
    container.push(0x18);

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

    // QUIC Short Header: header_form=0, fixed_bit=1, spin_bit=1
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
    // Key Phase is header-protected (RFC 9001, Section 5.4.1) and not shown.
    // https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
    assert!(buf.field_by_name(quic, "key_phase").is_none());
}

/// RFC 9000, Section 12.2 — Initial and Handshake packets coalesced into one
/// UDP datagram become two QUIC layers split at the Length field.
/// <https://www.rfc-editor.org/rfc/rfc9000#section-12.2>
#[test]
fn integration_ethernet_ipv4_udp_quic_coalesced() {
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 2], [10, 0, 0, 1]);
    let udp_start = push_udp(&mut pkt, 443, 50000);

    let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    // Initial (v1): Length = 20
    pkt.push(0xc0);
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);
    pkt.push(0); // SCID length
    pkt.extend_from_slice(&encode_quic_varint(0)); // token length
    pkt.extend_from_slice(&encode_quic_varint(20));
    pkt.extend_from_slice(&[0xAA; 20]);
    // Handshake (v1): Length = 16
    pkt.push(0xe0);
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);
    pkt.push(0); // SCID length
    pkt.extend_from_slice(&encode_quic_varint(16));
    pkt.extend_from_slice(&[0xBB; 16]);

    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 5);
    assert_layers_contiguous(&buf);
    assert_eq!(buf.layers()[3].name, "QUIC");
    assert_eq!(buf.layers()[3].display_name, Some("QUIC Initial"));
    assert_eq!(buf.layers()[3].range, 42..79);
    assert_eq!(buf.layers()[4].name, "QUIC");
    assert_eq!(buf.layers()[4].display_name, Some("QUIC Handshake"));
    assert_eq!(buf.layers()[4].range, 79..111);
    assert_eq!(pkt.len(), 111);
}

/// RFC 9001, Section 5 — with `quic-decrypt`, the client Initial from RFC 9001
/// Appendix A.2 is decrypted and its CRYPTO frame is shown.
/// <https://www.rfc-editor.org/rfc/rfc9001#appendix-A.2>
#[cfg(feature = "quic-decrypt")]
#[test]
fn integration_ethernet_ipv4_udp_quic_initial_decrypted() {
    let text = include_str!("data/rfc9001_a2_client_initial.hex");
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let initial: Vec<u8> = digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();

    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 50000, 443);
    pkt.extend_from_slice(&initial);
    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    let quic = &buf.layers()[3];
    assert_eq!(quic.display_name, Some("QUIC Initial"));
    assert_eq!(
        buf.field_by_name(quic, "packet_number").unwrap().value,
        FieldValue::U64(2)
    );
    let frames = buf.field_by_name(quic, "frames").unwrap();
    assert_eq!(frames.range, 42 + 22..42 + 1200 - 16);
    let FieldValue::Array(ref range) = frames.value else {
        panic!("expected Array");
    };
    let FieldValue::Object(ref crypto) = buf.nested_fields(range)[0].value else {
        panic!("expected Object");
    };
    let crypto = buf.nested_fields(crypto);
    assert_eq!(crypto[0].name(), "frame_type");
    assert_eq!(crypto[0].value, FieldValue::U64(0x06));
    assert_eq!(crypto[2].name(), "length");
    assert_eq!(crypto[2].value, FieldValue::U64(241));
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

#[test]
fn integration_ethernet_ipv4_udp_stun_xor_mapped_address() {
    // RFC 5769, Section 2.2 — Binding response with XOR-MAPPED-ADDRESS
    // 192.0.2.1:32853. https://www.rfc-editor.org/rfc/rfc5769#section-2.2
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 3478, 50000);
    pkt.extend_from_slice(&[
        0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6,
        0x86, 0xfa, 0x87, 0xdf, 0xae, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12,
        0xa6, 0x43,
    ]);
    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_layers_contiguous(&buf);
    let stun = buf.layer_by_name("STUN").unwrap();
    let fields = buf.layer_fields(stun);
    let find = |name: &str| fields.iter().find(|f| f.name() == name).unwrap();
    assert_eq!(find("port").value, FieldValue::U16(32853));
    assert_eq!(find("address").value, FieldValue::Ipv4Addr([192, 0, 2, 1]));
}

#[test]
fn integration_ethernet_ipv4_udp_turn_channeldata() {
    // RFC 8656, Section 12.4 — ChannelData on the TURN server port.
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.4
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 3478, 50000);
    pkt.extend_from_slice(&[0x40, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    let cd = &buf.layers()[3];
    assert_eq!(cd.name, "TURN-ChannelData");
    assert_eq!(
        buf.field_by_name(cd, "channel_number").unwrap().value,
        FieldValue::U16(0x4000)
    );
    assert_eq!(
        buf.field_by_name(cd, "data").unwrap().value,
        FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
    );
}

#[test]
fn integration_ethernet_ipv4_tcp_turn_channeldata_pipelined() {
    // RFC 8656, Section 12.5 — over TCP each ChannelData message is padded to
    // a multiple of four bytes; two messages share one segment.
    // https://www.rfc-editor.org/rfc/rfc8656#section-12.5
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 3478, 50000, 0x18);
    pkt.extend_from_slice(&[
        0x40, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // channel 0x4000
        0x40, 0x01, 0x00, 0x02, 0x11, 0x22, 0x00, 0x00, // channel 0x4001 + pad
    ]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(
        names,
        [
            "Ethernet",
            "IPv4",
            "TCP",
            "TURN-ChannelData",
            "TURN-ChannelData"
        ]
    );
    assert_layers_contiguous(&buf);
    let second = &buf.layers()[4];
    assert_eq!(
        buf.field_by_name(second, "channel_number").unwrap().value,
        FieldValue::U16(0x4001)
    );
    assert_eq!(
        buf.field_by_name(second, "padding").unwrap().value,
        FieldValue::Bytes(&[0x00, 0x00])
    );
    assert!(
        buf.layer_fields(second)
            .iter()
            .all(|f| f.name() != "reassembly_in_progress")
    );
}

#[test]
fn integration_ethernet_ipv4_tcp_turn_channeldata_split_padding() {
    // RFC 8656, Section 12.5 — the padding of a ChannelData message over TCP
    // is part of the message; a segment boundary inside it must not shift
    // the stream. https://www.rfc-editor.org/rfc/rfc8656#section-12.5
    let reg = DissectorRegistry::default();
    let segment = |seq: u32, payload: &[u8]| {
        let mut pkt: Vec<u8> = Vec::new();
        push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
        let ip_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
        let tcp_start = pkt.len();
        push_tcp(&mut pkt, 3478, 50000, 0x18);
        pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(payload);
        fixup_ipv4_length(&mut pkt, ip_start);
        pkt
    };

    // Segment 1: channel 0x4001, length 2, data, but no padding yet.
    let first = segment(1, &[0x40, 0x01, 0x00, 0x02, 0x11, 0x22]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&first, &mut buf).unwrap();
    assert!(buf.layer_by_name("TURN-ChannelData").is_none());

    // Segment 2: the two padding bytes, then channel 0x4000 with 4 bytes.
    let second = segment(
        7,
        &[0x00, 0x00, 0x40, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&second, &mut buf).unwrap();
    let channels: Vec<_> = buf
        .layers()
        .iter()
        .filter(|l| l.name == "TURN-ChannelData")
        .map(|l| {
            buf.field_by_name(l, "channel_number")
                .unwrap()
                .value
                .clone()
        })
        .collect();
    assert_eq!(channels, [FieldValue::U16(0x4001), FieldValue::U16(0x4000)]);
}

#[test]
fn integration_ethernet_ipv4_tcp_classic_stun_rejected() {
    // RFC 5389, Section 12 — "UDP was the only supported transport."
    // https://www.rfc-editor.org/rfc/rfc5389#section-12
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 6, [10, 0, 0, 1], [10, 0, 0, 2]);
    push_tcp(&mut pkt, 50000, 3478, 0x18);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x5A; 16]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    let err = reg.dissect(&pkt, &mut buf).unwrap_err();
    assert!(matches!(
        err,
        PacketError::InvalidFieldValue {
            field: "magic_cookie",
            ..
        }
    ));
}

#[test]
fn integration_ethernet_ipv4_udp_classic_stun() {
    // RFC 5389, Section 12 — RFC 3489 Binding Request without magic cookie.
    // https://www.rfc-editor.org/rfc/rfc5389#section-12
    let reg = DissectorRegistry::default();
    let mut pkt: Vec<u8> = Vec::new();
    push_ethernet(&mut pkt, [0; 6], [0; 6], 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, [10, 0, 0, 1], [10, 0, 0, 2]);
    let udp_start = push_udp(&mut pkt, 50000, 3478);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x5A; 16]);
    fixup_ipv4_length(&mut pkt, ip_start);
    fixup_udp_length(&mut pkt, udp_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 4);
    assert_layers_contiguous(&buf);
    let stun = &buf.layers()[3];
    assert_eq!(stun.name, "STUN");
    assert_eq!(stun.display_name, Some("Classic STUN (RFC 3489)"));
    assert!(buf.field_by_name(stun, "magic_cookie").is_none());
    assert_eq!(
        buf.field_by_name(stun, "transaction_id").unwrap().value,
        FieldValue::Bytes(&[0x5A; 16])
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
fn integration_ethernet_ipv4_igmp_mrd_solicitation() {
    // RFC 4286, Section 4.1 — a 4-octet Solicitation to All-Routers.
    //   <https://www.rfc-editor.org/rfc/rfc4286#section-4.1>
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(
        &mut pkt,
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0x02],
        MAC_SRC,
        0x0800,
    );
    let ip_start = push_ipv4(&mut pkt, 2, IPV4_SRC, [224, 0, 0, 2]);
    pkt.extend_from_slice(&[0x31, 0x00, 0xce, 0xff]);
    fixup_ipv4_length(&mut pkt, ip_start);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);
    assert_layers_contiguous(&buf);

    let igmp = &buf.layers()[2];
    assert_eq!(igmp.name, "IGMP");
    assert_eq!(
        display_name_for(&buf, igmp, "type"),
        Some("Multicast Router Solicitation")
    );
    assert!(buf.field_by_name(igmp, "group_address").is_none());
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

// ---------------------------------------------------------------------------
// Payload bounds: IPv4 Total Length / IPv6 Payload Length / UDP Length /
// IEEE 802.3 Length end the payload handed to upper layers.
//
// RFC 791, Section 3.1 — https://www.rfc-editor.org/rfc/rfc791#section-3.1
// RFC 8200, Section 3 — https://www.rfc-editor.org/rfc/rfc8200#section-3
// RFC 9868, Section 7 — https://www.rfc-editor.org/rfc/rfc9868#section-7
// IEEE 802.3-2022, clause 3.2.6 (Length/Type) and clause 3.2.8 (Pad).
// ---------------------------------------------------------------------------

/// Minimum Ethernet frame length without FCS (IEEE 802.3-2022, clause 3.2.8:
/// frames shorter than the minimum are padded after the client data).
const MIN_ETHERNET_FRAME_LEN_NO_FCS: usize = 60;

/// Append zero padding until the frame reaches the Ethernet minimum size.
fn pad_ethernet_frame(pkt: &mut Vec<u8>) {
    if pkt.len() < MIN_ETHERNET_FRAME_LEN_NO_FCS {
        pkt.resize(MIN_ETHERNET_FRAME_LEN_NO_FCS, 0x00);
    }
}

/// Test dissector that claims every byte it is given, so its layer range
/// shows exactly which slice the dispatch loop handed to it.
struct PayloadProbe;

impl Dissector for PayloadProbe {
    fn name(&self) -> &'static str {
        "Payload Probe"
    }
    fn short_name(&self) -> &'static str {
        "Probe"
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
        buf.begin_layer("Probe", None, &[], offset..offset + data.len());
        buf.end_layer();
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

/// Assert that no layer extends past `end` (the end of the enclosing
/// datagram / LLC PDU).
fn assert_layers_end_within(buf: &DissectBuffer<'_>, end: usize) {
    for layer in buf.layers() {
        assert!(
            layer.range.end <= end,
            "Layer '{}' ends at {} past the datagram end {}",
            layer.name,
            layer.range.end,
            end
        );
    }
}

/// Ethernet → IPv4 → SCTP COOKIE ACK with Ethernet padding.
///
/// The 10 pad octets must not be walked as another SCTP chunk.
#[test]
fn integration_ethernet_ipv4_sctp_padded() {
    let reg = DissectorRegistry::default();
    #[rustfmt::skip]
    let pkt: [u8; 60] = [
        // Ethernet, EtherType IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
        // IPv4, total_length 36, proto 132 (SCTP)
        0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
        // SCTP 5000 -> 5000, vtag 1, checksum 0
        0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // COOKIE ACK chunk (type 11, flags 0, length 4)
        0x0b, 0x00, 0x00, 0x04,
        // Ethernet pad (10 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "SCTP"]);
    assert_layers_contiguous(&buf);
    assert_layers_end_within(&buf, 14 + 36);
    let sctp = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(sctp.range, 34..50);
}

/// Ethernet → IPv6 → SCTP COOKIE ACK followed by a 4-byte trailer
/// (e.g. a captured FCS). The trailer is outside the IPv6 payload.
#[test]
fn integration_ethernet_ipv6_sctp_trailer() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 132, IPV6_SRC, IPV6_DST);
    push_sctp(&mut pkt, 5000, 5000);
    pkt.extend_from_slice(&[0x0b, 0x00, 0x00, 0x04]); // COOKIE ACK
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    let datagram_end = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // trailer

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv6", "SCTP"]);
    assert_layers_contiguous(&buf);
    assert_layers_end_within(&buf, datagram_end);
}

/// Ethernet → IPv4 → ICMP Echo Request without data, padded to 60 bytes.
///
/// The pad must not show up as ICMP echo `data`.
#[test]
fn integration_ethernet_ipv4_icmp_echo_padded() {
    let reg = DissectorRegistry::default();
    let mut pkt = build_eth_ipv4_icmp_echo();
    let datagram_end = pkt.len();
    pad_ethernet_frame(&mut pkt);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let icmp = buf.layer_by_name("ICMP").unwrap();
    assert_eq!(icmp.range, 34..datagram_end);
    assert!(buf.field_by_name(icmp, "data").is_none());
    assert_layers_end_within(&buf, datagram_end);
}

/// Ethernet → IPv4 → ESP (NULL, transport mode) → UDP with Ethernet padding.
///
/// ESP locates its trailer from the end of its input, so the pad must be
/// excluded for the NULL-encryption heuristic to find `next_header = 17`.
#[test]
fn integration_ethernet_ipv4_esp_null_transport_udp_padded() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, [0x00; 6], [0x01; 6], 0x0800);
    let ipv4_start = push_ipv4(&mut pkt, 50, [10, 0, 0, 1], [10, 0, 0, 2]);
    pkt.extend_from_slice(&0x0000_3003u32.to_be_bytes()); // SPI
    pkt.extend_from_slice(&7u32.to_be_bytes()); // Sequence Number
    let udp_start = push_udp(&mut pkt, 10000, 20000);
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // UDP payload
    fixup_udp_length(&mut pkt, udp_start);
    pkt.push(0x00); // pad_length
    pkt.push(17); // next_header = UDP
    fixup_ipv4_length(&mut pkt, ipv4_start);
    let datagram_end = pkt.len();
    pad_ethernet_frame(&mut pkt);
    assert!(pkt.len() > datagram_end);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "ESP", "UDP"]);
    let esp = buf.layer_by_name("ESP").unwrap();
    assert_eq!(
        buf.field_by_name(esp, "next_header").unwrap().value,
        FieldValue::U8(17)
    );
    // ESP covers exactly the IP payload. Decrypted inner layers are placed
    // after it in virtual offsets, so only ESP is checked against the datagram.
    assert_eq!(esp.range, 34..datagram_end);
}

/// Ethernet → IPv4 → UDP → probe: UDP user data ends at the UDP Length.
///
/// RFC 9868, Section 7 — bytes past the UDP Length but within the IP
/// payload are the surplus area, not UDP user data.
/// <https://www.rfc-editor.org/rfc/rfc9868#section-7>
#[test]
fn integration_ethernet_ipv4_udp_surplus_area_not_passed_to_application() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_udp_port_or_replace(9999, Box::new(PayloadProbe));
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 17, IPV4_SRC, IPV4_DST);
    let udp_start = push_udp(&mut pkt, 9999, 9999);
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // UDP user data
    fixup_udp_length(&mut pkt, udp_start);
    let user_data_end = pkt.len();
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // surplus area
    fixup_ipv4_length(&mut pkt, ip_start);
    pad_ethernet_frame(&mut pkt);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let probe = buf.layer_by_name("Probe").unwrap();
    assert_eq!(probe.range, udp_start + 8..user_data_end);
}

/// Ethernet → IPv4 → IPv4 → probe: the inner datagram is bounded by its
/// own Total Length, and the outer bound still applies.
#[test]
fn integration_ethernet_ipv4_in_ipv4_payload_bounded_by_inner_total_length() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_ip_protocol_or_replace(253, Box::new(PayloadProbe));
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let outer_start = push_ipv4(&mut pkt, 4, IPV4_SRC, IPV4_DST);
    let inner_start = push_ipv4(&mut pkt, 253, [192, 168, 0, 1], [192, 168, 0, 2]);
    pkt.extend_from_slice(&[0xAA, 0xBB]); // inner payload
    fixup_ipv4_length(&mut pkt, inner_start);
    let inner_end = pkt.len();
    pkt.extend_from_slice(&[0xCC; 3]); // outer payload bytes past the inner datagram
    fixup_ipv4_length(&mut pkt, outer_start);
    pad_ethernet_frame(&mut pkt);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let probe = buf.layer_by_name("Probe").unwrap();
    assert_eq!(probe.range, inner_start + 20..inner_end);
}

/// Ethernet → IPv6 (Payload Length) → probe: the IPv6 payload ends at
/// `40 + payload_length`.
#[test]
fn integration_ethernet_ipv6_payload_bounded_by_payload_length() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_ip_protocol_or_replace(253, Box::new(PayloadProbe));
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    let ip_start = push_ipv6(&mut pkt, 253, IPV6_SRC, IPV6_DST);
    pkt.extend_from_slice(&[0xAA; 6]);
    fixup_ipv6_payload_length(&mut pkt, ip_start);
    let datagram_end = pkt.len();
    pkt.extend_from_slice(&[0x00; 4]); // trailer

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let probe = buf.layer_by_name("Probe").unwrap();
    assert_eq!(probe.range, ip_start + 40..datagram_end);
}

/// Ethernet → IPv6 with Payload Length 0 and a Hop-by-Hop header: a
/// possible Jumbo Payload, so the payload is not bounded by the IPv6
/// header.
///
/// RFC 2675, Section 3 — https://www.rfc-editor.org/rfc/rfc2675#section-3
#[test]
fn integration_ethernet_ipv6_zero_payload_length_hop_by_hop_not_bounded() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_ip_protocol_or_replace(253, Box::new(PayloadProbe));
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    push_ipv6(&mut pkt, 0, IPV6_SRC, IPV6_DST); // Payload Length stays 0
    // Hop-by-Hop header with a Jumbo Payload option (type 0xC2, len 4).
    let hbh_start = pkt.len();
    pkt.extend_from_slice(&[253, 0, 0xC2, 4]);
    let jumbo_len = 8u32 + 4;
    pkt.extend_from_slice(&jumbo_len.to_be_bytes());
    pkt.extend_from_slice(&[0xAA; 4]);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let probe = buf.layer_by_name("Probe").unwrap();
    assert_eq!(probe.range, hbh_start + 8..pkt.len());
}

/// Ethernet (IEEE 802.3 Length) → LLC → probe: the LLC PDU ends at the
/// Length field, and the pad after it is not LLC data.
///
/// IEEE 802.3-2022, clause 3.2.6 (Length/Type) and clause 3.2.8 (Pad).
#[test]
fn integration_ethernet_802_3_llc_payload_bounded_by_length() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_llc_sap_or_replace(0x42, Box::new(PayloadProbe));
    let mut pkt = Vec::new();
    let length_offset = push_ethernet_llc(&mut pkt, [0x01, 0x80, 0xC2, 0, 0, 0], MAC_SRC);
    push_stp_tcn_bpdu(&mut pkt);
    fixup_802_3_length(&mut pkt, length_offset);
    let llc_pdu_end = pkt.len();
    pad_ethernet_frame(&mut pkt);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let probe = buf.layer_by_name("Probe").unwrap();
    assert_eq!(probe.range, 17..llc_pdu_end);
}

/// IPv4 (total length 28, ICMP) + ICMP Echo Request (8 octets).
fn ipv4_icmp_echo_bytes() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

/// Ethernet (802.3 Length) → LLC (0xAA, UI) → SNAP OUI 00-00-00 → IPv4 → ICMP.
///
/// RFC 1042, "Frame Format and MAC Level Issues".
#[test]
fn integration_ethernet_llc_snap_ipv4_icmp() {
    let reg = DissectorRegistry::default();
    let mut pkt = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let mut llc = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
    llc.extend_from_slice(&ipv4_icmp_echo_bytes());
    pkt.extend_from_slice(&(llc.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&llc);
    pad_ethernet_frame(&mut pkt);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "SNAP", "IPv4", "ICMP"]);
    assert_layers_contiguous(&buf);
    let snap = buf.layer_by_name("SNAP").unwrap();
    assert_eq!(snap.range, 17..22);
    assert_eq!(buf.field_u16(snap, "pid"), Some(0x0800));
}

/// Ethernet → LLC → SNAP with Cisco OUI 00-00-0C (CDP): the SNAP layer is
/// shown and the chain ends.
#[test]
fn integration_ethernet_llc_snap_other_oui() {
    let reg = DissectorRegistry::default();
    let mut pkt = vec![
        0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let llc = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00, 0x02, 0xB4];
    pkt.extend_from_slice(&(llc.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&llc);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "SNAP"]);
}

/// SLL header (LINKTYPE_LINUX_SLL) with the given protocol type.
fn sll_header(protocol_type: u16) -> Vec<u8> {
    let mut pkt = vec![0x00, 0x02, 0x00, 0x01, 0x00, 0x06];
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]);
    pkt.extend_from_slice(&protocol_type.to_be_bytes());
    pkt
}

/// SLL with protocol type 0x0004 → LLC (0x42) → STP Configuration BPDU.
///
/// LINKTYPE_LINUX_SLL: 0x0004 "if the payload begins with an 802.2 LLC header".
#[test]
fn integration_sll_llc_stp() {
    let reg = DissectorRegistry::default();
    let mut pkt = sll_header(0x0004);
    pkt.extend_from_slice(&[0x42, 0x42, 0x03]);
    push_stp_config_bpdu(&mut pkt);

    let mut buf = DissectBuffer::new();
    reg.dissect_with_link_type(&pkt, 113, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["SLL", "STP"]);
    assert_layers_contiguous(&buf);
    let sll = buf.layer_by_name("SLL").unwrap();
    assert_eq!(sll.range, 0..19);
    assert_eq!(buf.field_u8(sll, "llc_dsap"), Some(0x42));
}

/// SLL2 with protocol type 0x0004 → LLC (0xAA) → SNAP → IPv4 → ICMP.
#[test]
fn integration_sll2_llc_snap_ipv4() {
    let reg = DissectorRegistry::default();
    let mut pkt = vec![
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x06,
    ];
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00]);
    pkt.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
    pkt.extend_from_slice(&ipv4_icmp_echo_bytes());

    let mut buf = DissectBuffer::new();
    reg.dissect_with_link_type(&pkt, 276, &mut buf).unwrap();
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["SLL2", "SNAP", "IPv4", "ICMP"]);
    assert_layers_contiguous(&buf);
}

/// Ethernet → IPv4 → TCP SYN with Ethernet padding and a trailer: the TCP payload
/// is already derived from the IP layer and must stay unchanged.
#[test]
fn integration_ethernet_ipv4_tcp_syn_padded() {
    let reg = DissectorRegistry::default();
    let mut pkt = build_eth_ipv4_tcp_syn();
    let datagram_end = pkt.len();
    pad_ethernet_frame(&mut pkt);
    pkt.extend_from_slice(&[0xFF; 6]); // extra trailer beyond the minimum frame

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "TCP"]);
    assert_layers_end_within(&buf, datagram_end);
}

// ---------------------------------------------------------------------------
// Snaplen truncation: a capture that holds fewer bytes than the IPv4 Total
// Length / UDP Length is valid capture data, not a malformed datagram.
//
// RFC 791, Section 3.1 — https://www.rfc-editor.org/rfc/rfc791#section-3.1
// pcap savefile caplen vs len — https://www.tcpdump.org/manpages/pcap-savefile.5.html
// ---------------------------------------------------------------------------

/// Ethernet → IPv4 (Total Length 1500) → TCP header only, as written by
/// `tcpdump -s 54`.
#[test]
fn integration_ethernet_ipv4_tcp_snaplen_truncated() {
    let reg = DissectorRegistry::default();
    #[rustfmt::skip]
    let pkt: [u8; 54] = [
        // Ethernet, IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        // IPv4, total length 1500, TCP
        0x45, 0x00, 0x05, 0xdc, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
        // TCP 12345 -> 80, ACK
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    ];

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "TCP"]);
    assert_layers_contiguous(&buf);
    let ipv4 = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(
        buf.field_by_name(ipv4, "total_length").unwrap().value,
        FieldValue::U16(1500)
    );
}

/// Ethernet → IPv6 (Payload Length 1480) → TCP header only: the same
/// snaplen-truncated capture over IPv6 dissects identically.
#[test]
fn integration_ethernet_ipv6_tcp_snaplen_truncated() {
    let reg = DissectorRegistry::default();
    let mut pkt = build_eth_ipv6_tcp();
    pkt[14 + 4..14 + 6].copy_from_slice(&1480u16.to_be_bytes());

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv6", "TCP"]);
}

/// Ethernet → IPv4 → UDP → DNS cut mid-record by the snap length.
///
/// The IPv4 and UDP layers survive; only the innermost layer that needs
/// the missing bytes reports the truncation.
#[test]
fn integration_ethernet_ipv4_udp_dns_snaplen_truncated() {
    let reg = DissectorRegistry::default();
    let full = build_eth_ipv4_udp_dns_query();
    // Keep the DNS header and part of the question name.
    let snaplen = 14 + 20 + 8 + 12 + 4;
    assert!(snaplen < full.len());
    let pkt = &full[..snaplen];

    let mut buf = DissectBuffer::new();
    let err = reg.dissect(pkt, &mut buf).unwrap_err();

    assert!(matches!(err, PacketError::Truncated { .. }), "{err:?}");
    // DNS may keep the part of its layer it parsed before the error.
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).take(3).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "UDP"]);
    let udp = buf.layer_by_name("UDP").unwrap();
    assert_eq!(
        buf.field_by_name(udp, "length").unwrap().value,
        FieldValue::U16((full.len() - 34) as u16)
    );
}

/// Ethernet → IPv4 → probe cut by the snap length: the payload handed
/// upward ends at the captured bytes, not at Total Length.
#[test]
fn integration_ethernet_ipv4_snaplen_payload_ends_at_capture() {
    let mut reg = DissectorRegistry::default();
    reg.register_by_ip_protocol_or_replace(253, Box::new(PayloadProbe));
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 253, IPV4_SRC, IPV4_DST);
    pkt.extend_from_slice(&[0xAA; 100]);
    fixup_ipv4_length(&mut pkt, ip_start);
    pkt.truncate(64);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let probe = buf.layer_by_name("Probe").unwrap();
    assert_eq!(probe.range, 34..64);
}

/// Build Ethernet → IPv4 → TCP (12345 → 80) with the given sequence number,
/// declared TCP payload length and captured payload bytes.
fn build_eth_ipv4_tcp_segment(seq: u32, declared_payload_len: usize, captured: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x0800);
    let ip_start = push_ipv4(&mut pkt, 6, IPV4_SRC, IPV4_DST);
    let tcp_start = pkt.len();
    push_tcp(&mut pkt, 12345, 80, 0x18); // PSH+ACK
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(captured);
    let total_length = (20 + 20 + declared_payload_len) as u16;
    pkt[ip_start + 2..ip_start + 4].copy_from_slice(&total_length.to_be_bytes());
    pkt
}

/// A snaplen-truncated TCP segment must not be buffered for reassembly:
/// its captured bytes are shorter than the sequence space it occupies, so
/// buffering them would leave a gap before the next segment and stall the
/// stream.
#[test]
fn integration_ethernet_ipv4_tcp_snaplen_segment_does_not_stall_reassembly() {
    let reg = DissectorRegistry::default();

    // Segment 1: 1000 payload bytes on the wire, only 24 captured.
    let first = build_eth_ipv4_tcp_segment(1, 1000, b"GET / HTTP/1.1\r\nHost: ex");
    let mut buf = DissectBuffer::new();
    let _ = reg.dissect(&first, &mut buf);
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).take(3).collect();
    assert_eq!(names, ["Ethernet", "IPv4", "TCP"]);

    // Segment 2: the next segment in sequence space, fully captured.
    let request = b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let second = build_eth_ipv4_tcp_segment(1 + 1000, request.len(), request);
    let mut buf = DissectBuffer::new();
    reg.dissect(&second, &mut buf).unwrap();

    let http = buf
        .layer_by_name("HTTP")
        .expect("HTTP must be dissected after a snaplen-truncated segment");
    assert_eq!(
        buf.field_by_name(http, "method").unwrap().value,
        FieldValue::Str("GET")
    );
}

/// Ethernet → IPv6 (Payload Length 0, Next Header TCP) → TCP: host-side
/// captures of large segmentation-offloaded packets carry Payload Length 0
/// without a Jumbo Payload option. The payload is left unbounded so TCP is
/// still dissected.
#[test]
fn integration_ethernet_ipv6_zero_payload_length_tcp_not_bounded() {
    let reg = DissectorRegistry::default();
    let mut pkt = Vec::new();
    push_ethernet(&mut pkt, MAC_DST, MAC_SRC, 0x86DD);
    push_ipv6(&mut pkt, 6, IPV6_SRC, IPV6_DST); // Payload Length stays 0
    push_tcp(&mut pkt, 12345, 443, 0x10);

    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["Ethernet", "IPv6", "TCP"]);
}
