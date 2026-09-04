//! BGP-4 (Border Gateway Protocol version 4) dissector.
//!
//! ## References
//! - RFC 4271 (BGP-4): <https://www.rfc-editor.org/rfc/rfc4271>
//! - RFC 1997 (Communities): <https://www.rfc-editor.org/rfc/rfc1997>
//! - RFC 2918 (Route Refresh): <https://www.rfc-editor.org/rfc/rfc2918>
//! - RFC 4360 (Extended Communities): <https://www.rfc-editor.org/rfc/rfc4360>
//! - RFC 4456 (Route Reflection): <https://www.rfc-editor.org/rfc/rfc4456>
//! - RFC 4486 (Cease NOTIFICATION subcodes): <https://www.rfc-editor.org/rfc/rfc4486>
//! - RFC 4724 (Graceful Restart Capability): <https://www.rfc-editor.org/rfc/rfc4724>
//! - RFC 4760 (Multiprotocol Extensions): <https://www.rfc-editor.org/rfc/rfc4760>
//! - RFC 5492 (Capabilities Advertisement with BGP-4): <https://www.rfc-editor.org/rfc/rfc5492>
//! - RFC 6793 (4-octet AS Numbers): <https://www.rfc-editor.org/rfc/rfc6793>
//! - RFC 7313 (Enhanced Route Refresh): <https://www.rfc-editor.org/rfc/rfc7313>
//! - RFC 7911 (ADD-PATH Capability): <https://www.rfc-editor.org/rfc/rfc7911>
//! - RFC 8092 (Large Communities): <https://www.rfc-editor.org/rfc/rfc8092>
//! - RFC 7911 (ADD-PATH / Path Identifier): <https://www.rfc-editor.org/rfc/rfc7911>
//! - RFC 8203 (Hard Reset Cease subcode): <https://www.rfc-editor.org/rfc/rfc8203>
//! - RFC 8654 (Extended Message): <https://www.rfc-editor.org/rfc/rfc8654>
//! - RFC 8669 (BGP Prefix-SID): <https://www.rfc-editor.org/rfc/rfc8669>
//! - RFC 8950 (Extended Next Hop Encoding Capability): <https://www.rfc-editor.org/rfc/rfc8950>
//! - RFC 9012 (Tunnel Encapsulation / Color): <https://www.rfc-editor.org/rfc/rfc9012>
//! - RFC 9072 (Extended Optional Parameters Length): <https://www.rfc-editor.org/rfc/rfc9072>
//! - RFC 9234 (BGP Role Capability): <https://www.rfc-editor.org/rfc/rfc9234>
//! - RFC 9252 (SRv6 BGP Services): <https://www.rfc-editor.org/rfc/rfc9252>
//! - RFC 9494 (Long-Lived Graceful Restart Capability): <https://www.rfc-editor.org/rfc/rfc9494>
//! - IANA Capability Codes: <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>
//! - draft-abraitis-idr-addpath-paths-limit-04 (PATHS-LIMIT Capability): <https://datatracker.ietf.org/doc/draft-abraitis-idr-addpath-paths-limit/>
//! - draft-ietf-bess-mup-safi-01 (MUP SAFI): <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
//! - draft-walton-bgp-hostname-capability-02 (FQDN Capability): <https://datatracker.ietf.org/doc/draft-walton-bgp-hostname-capability/>
//!
//! # RFC 4271 (BGP-4) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 4.1 | Message Header | `parse_bgp_keepalive` |
//! | 4.1 | Marker validation | `parse_bgp_invalid_marker` |
//! | 4.1 | Truncated header | `parse_bgp_truncated_header` |
//! | 4.2 | OPEN Message | `parse_bgp_open_basic` |
//! | 4.2 | OPEN with Capabilities | `parse_bgp_open_with_capabilities` |
//! | 4.2 | Truncated OPEN | `parse_bgp_truncated_open` |
//! | 4.3 | UPDATE Withdrawn Routes | `parse_bgp_update_withdraw` |
//! | 4.3 | UPDATE Path Attributes + NLRI | `parse_bgp_update_announce` |
//! | 4.3 | NLRI prefix CIDR formatting | `format_nlri_ipv4_prefix_cidr` |
//! | 4.5 | NOTIFICATION | `parse_bgp_notification` |
//! | 5.1.1 | ORIGIN | `parse_bgp_update_origin` |
//! | 5.1.2 | AS_PATH | `parse_bgp_update_as_path` |
//! | 5.1.3 | NEXT_HOP | `parse_bgp_update_next_hop` |
//! | 5.1.4 | MULTI_EXIT_DISC | `parse_bgp_update_multi_exit_disc` |
//! | 5.1.5 | LOCAL_PREF | `parse_bgp_update_local_pref` |
//! | 5.1.6 | ATOMIC_AGGREGATE | `parse_bgp_update_atomic_aggregate` |
//! | 5.1.7 | AGGREGATOR (2-byte AS) | `parse_bgp_update_aggregator_2byte_as` |
//! | 4.1 | Multiple messages per segment | `parse_bgp_multiple_messages` |
//! | 4.2+4.4 | OPEN followed by KEEPALIVE | `parse_bgp_open_followed_by_keepalive` |
//! | 4.3 | Unknown attribute (raw bytes) | `parse_bgp_update_unknown_attribute` |
//! | 4.3 | Malformed NLRI handling | `parse_bgp_update_malformed_nlri_is_dropped` |
//! | 4.1/5.1 | Message type, AFI/SAFI, attribute, ORIGIN, AS_PATH segment and community name tables | `name_lookup_tables` |
//!
//! # RFC 6793 (4-octet AS Numbers) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 3 | AGGREGATOR (4-byte AS) | `parse_bgp_update_aggregator_4byte_as` |
//! | 3 | AS4_PATH | `parse_bgp_update_as4_path` |
//! | 3 | AS4_AGGREGATOR | `parse_bgp_update_as4_aggregator` |
//! | 3 | 4-octet AS Number Capability (asn) | `parse_bgp_open_capability_as4` |
//!
//! # RFC 1997 Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 3 | COMMUNITIES | `parse_bgp_update_communities` |
//!
//! # RFC 2918 Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 3 | ROUTE-REFRESH | `parse_bgp_route_refresh` |
//!
//! # RFC 7313 (Enhanced Route Refresh) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 4 | Message Subtype (BoRR) | `parse_bgp_route_refresh_subtype_borr` |
//!
//! # RFC 9072 (Extended Optional Parameters Length) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 2 | Extended OPEN encoding + 2-octet param length | `parse_bgp_open_extended_optional_parameters` |
//!
//! # RFC 4486 / RFC 8203 (Cease NOTIFICATION subcodes) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 4486 §4 | Cease subcodes 1–8 + RFC 8203 §4 subcode 9 | `parse_bgp_notification_cease_subcode_name` |
//!
//! # RFC 4360 / RFC 9012 Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 2 | Extended Communities + Color | `parse_bgp_update_extended_communities` |
//! | 2 | IPv4 Address Specific Route Target | `parse_bgp_update_extended_communities_ipv4_route_target` |
//! | 2 | Route Origin (Two-Octet AS) | `parse_bgp_update_extended_communities_route_origin` |
//! | 2 | IPv4 Address Specific Route Origin | `parse_bgp_update_extended_communities_ipv4_route_origin` |
//! | 2 | EVPN Extended Community | `parse_bgp_update_extended_communities_evpn` |
//! | 2 | Unknown Extended Community | `parse_bgp_update_extended_communities_unknown` |
//!
//! # RFC 4456 (Route Reflection) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 8 | ORIGINATOR_ID | `parse_bgp_update_originator_id` |
//! | 8 | CLUSTER_LIST | `parse_bgp_update_cluster_list` |
//!
//! # RFC 4760 Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 3 | MP_REACH_NLRI (IPv6) | `parse_bgp_update_mp_reach_ipv6` |
//! | 3 | MP_REACH_NLRI (IPv6 link-local NH) | `parse_bgp_update_mp_reach_ipv6_link_local` |
//! | 4 | MP_UNREACH_NLRI (IPv6) | `parse_bgp_update_mp_unreach_ipv6` |
//! | 4 | MP_UNREACH_NLRI (IPv4) | `parse_bgp_update_mp_unreach_ipv4` |
//! | 3 | IPv6 NLRI prefix CIDR formatting | `format_nlri_ipv6_prefix_cidr` |
//! | 8 | Multiprotocol Extensions Capability (afi/safi) | `parse_bgp_open_capability_multiprotocol` |
//!
//! # BGP OPEN Capability Decoding Coverage
//!
//! | RFC / Draft Section | Description | Test |
//! |----------------------|-------------|------|
//! | RFC 7911 §4 | ADD-PATH Capability (afi_safis, send_receive) | `parse_bgp_open_capability_add_path` |
//! | RFC 7911 §4 | ADD-PATH truncated value (raw kept, not decoded) | `parse_bgp_open_capability_add_path_truncated` |
//! | draft-abraitis-idr-addpath-paths-limit-04 §3 | PATHS-LIMIT Capability (afi_safis, paths_limit) | `parse_bgp_open_capability_paths_limit` |
//! | RFC 4724 §3 | Graceful Restart Capability with AFI/SAFI list | `parse_bgp_open_capability_graceful_restart_with_afi_safi` |
//! | RFC 4724 §3 | Graceful Restart Capability without AFI/SAFI list | `parse_bgp_open_capability_graceful_restart_without_afi_safi` |
//! | RFC 9494 §3.1 | Long-Lived Graceful Restart Capability (afi_safis, stale_time) | `parse_bgp_open_capability_llgr` |
//! | RFC 8950 §4 | Extended Next Hop Encoding Capability (2-octet safi) | `parse_bgp_open_capability_extended_next_hop` |
//! | RFC 9234 §4.1 | BGP Role Capability (role_name) | `parse_bgp_open_capability_role` |
//! | draft-walton-bgp-hostname-capability-02 §3 | FQDN Capability (hostname, domain_name) | `parse_bgp_open_capability_fqdn` |
//! | IANA Capability Codes | Unknown capability code (no code_name / decoded fields) | `parse_bgp_open_capability_unknown_code` |
//! | IANA Capability Codes | Zero-length capabilities (Route Refresh, Extended Message, Enhanced RR, deprecated RR) | `parse_bgp_open_capability_zero_length_code_names` |
//! | RFC 5492 | `optional_parameters` / `afi_safis` schema union | `bgp_optional_parameters_schema_has_afi_safis_send_receive` |
//!
//! # draft-ietf-bess-mup-safi-01 Coverage
//!
//! | Section | Description | Test |
//! |---------|-------------|------|
//! | 3 | MUP NLRI (Interwork Segment Discovery) | `parse_bgp_update_mup_interwork_segment_discovery` |
//! | 3.3 | Type 1 ST (3GPP 5G) | `parse_bgp_update_mup_type1_st` |
//! | 3.1.4/3.3 | Type 2 ST (3GPP 5G) | `parse_bgp_update_mup_type2_st` |
//! | 3.1.5 | ST Route TLVs (3gpp-5g Session Parameters, Interwork Endpoint, Source Address) | `parse_bgp_update_mup_type1_st`, `parse_bgp_update_mup_type2_st` |
//! | 3.2 | MUP Extended Community sub-types (2-Octet AS / IPv4 / 4-Octet AS, Direct/Interwork Segment) | `mup_extended_community_type_names`, `format_ext_community_mup_values` |
//! | 3 | Route Type / Architecture Type name tables | `name_lookup_tables` |
//! | 3 | Truncated MUP entry handling | `parse_bgp_update_mup_truncated_entry_is_dropped` |
//!
//! # RFC 7911 (ADD-PATH) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 3 | ADD-PATH detection heuristic (IPv4) | `detect_add_path_prefixes_ipv4` |
//! | 3 | ADD-PATH detection heuristic (IPv6) | `detect_add_path_prefixes_ipv6` |
//! | 3 | ADD-PATH detection heuristic (MUP SAFI) | `detect_add_path_mup_blocks` |
//! | 3 | Path Identifier in NLRI + withdrawn routes | `parse_bgp_update_add_path_nlri_and_withdrawn` |
//! | 3 | Path Identifier in MP_REACH_NLRI (IPv6) | `parse_bgp_update_mp_reach_ipv6_add_path` |
//! | 3 | Path Identifier in MP_REACH_NLRI (MUP) | `parse_bgp_update_mp_reach_mup_add_path` |
//! | 3 | Plain encoding preferred when unambiguous | `parse_bgp_update_mup_without_add_path_stays_plain` |
//! | 3 | Schema exposes `path_id` / polymorphic `value` | `field_schema_exposes_nlri_and_path_attribute_value_children` |
//!
//! # RFC 8092 Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 2 | LARGE_COMMUNITY | `parse_bgp_update_large_community` |
//!
//! # RFC 8669 (BGP Prefix-SID) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 3.1 | Label-Index TLV | `parse_bgp_prefix_sid_label_index` |
//! | 3.2 | Originator SRGB TLV | `parse_bgp_prefix_sid_originator_srgb` |
//! | 3 | Multiple TLVs | `parse_bgp_prefix_sid_multiple_tlvs` |
//! | 3 | Unknown TLV | `parse_bgp_prefix_sid_unknown_tlv` |
//! | 6 | Truncated TLV handling | `parse_bgp_prefix_sid_truncated` |
//!
//! # RFC 9252 (SRv6 BGP Services) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 2 | SRv6 L3 Service TLV | `parse_bgp_prefix_sid_srv6_l3_service` |
//! | 2 | SRv6 L2 Service TLV | `parse_bgp_prefix_sid_srv6_l2_service` |
//! | 3.1 | SRv6 SID Information Sub-TLV | `parse_bgp_prefix_sid_srv6_l3_service` |
//! | 3.2.1 | SRv6 SID Structure Sub-Sub-TLV | `parse_bgp_prefix_sid_srv6_sid_structure` |

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u24, read_be_u32, read_ipv4_addr, read_ipv6_addr,
};

/// BGP message header size in bytes (RFC 4271, Section 4.1).
/// 16-byte marker + 2-byte length + 1-byte type.
const HEADER_SIZE: usize = 19;

/// BGP marker: 16 bytes of 0xFF (RFC 4271, Section 4.1).
const MARKER: [u8; 16] = [0xFF; 16];

/// Minimum OPEN message size: 19-byte header + 10-byte body (RFC 4271, Section 4.2).
const MIN_OPEN_SIZE: usize = 29;

/// Minimum NOTIFICATION message size: 19-byte header + 2-byte body (RFC 4271, Section 4.5).
const MIN_NOTIFICATION_SIZE: usize = 21;

/// Minimum UPDATE message size: 19-byte header + 4-byte body (RFC 4271, Section 4.3).
const MIN_UPDATE_SIZE: usize = 23;

/// ROUTE-REFRESH message size: 19-byte header + 4-byte body (RFC 2918).
const ROUTE_REFRESH_SIZE: usize = 23;

/// Size of the RFC 7911 ADD-PATH Path Identifier prepended to an NLRI entry.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
const PATH_ID_SIZE: usize = 4;

/// MUP NLRI fixed header size: Architecture Type (1) + Route Type (2) + Length (1).
///
/// draft-ietf-bess-mup-safi-01, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
const MUP_NLRI_HEADER_SIZE: usize = 4;

/// The only MUP Architecture Type defined by draft-ietf-bess-mup-safi-01: 3gpp-5g.
const MUP_ARCHITECTURE_TYPE_3GPP_5G: u8 = 1;

/// Lowest MUP Route Type defined by draft-ietf-bess-mup-safi-01, Section 3.
const MUP_ROUTE_TYPE_MIN: u16 = 1;

/// Highest MUP Route Type defined by draft-ietf-bess-mup-safi-01, Section 3.
const MUP_ROUTE_TYPE_MAX: u16 = 4;

/// SAFI value for BGP-MUP (draft-ietf-bess-mup-safi-01).
const SAFI_MUP: u8 = 85;

/// BGP message type: OPEN (RFC 4271, Section 4.1).
const MSG_OPEN: u8 = 1;
/// BGP message type: UPDATE (RFC 4271, Section 4.1).
const MSG_UPDATE: u8 = 2;
/// BGP message type: NOTIFICATION (RFC 4271, Section 4.1).
const MSG_NOTIFICATION: u8 = 3;
/// BGP message type: KEEPALIVE (RFC 4271, Section 4.1).
const MSG_KEEPALIVE: u8 = 4;
/// BGP message type: ROUTE-REFRESH (RFC 2918).
const MSG_ROUTE_REFRESH: u8 = 5;

/// BGP OPEN Capability Code: Multiprotocol Extensions (RFC 4760, Section 8).
const CAP_MULTIPROTOCOL: u8 = 1;
/// BGP OPEN Capability Code: Route Refresh Capability for BGP-4 (RFC 2918).
const CAP_ROUTE_REFRESH: u8 = 2;
/// BGP OPEN Capability Code: Extended Next Hop Encoding (RFC 8950, Section 4).
const CAP_EXTENDED_NEXT_HOP: u8 = 5;
/// BGP OPEN Capability Code: BGP Extended Message (RFC 8654).
const CAP_EXTENDED_MESSAGE: u8 = 6;
/// BGP OPEN Capability Code: BGP Role (RFC 9234, Section 4.1).
const CAP_ROLE: u8 = 9;
/// BGP OPEN Capability Code: Graceful Restart Capability (RFC 4724, Section 3).
const CAP_GRACEFUL_RESTART: u8 = 64;
/// BGP OPEN Capability Code: Support for 4-octet AS number capability
/// (RFC 6793, Section 3).
const CAP_AS4: u8 = 65;
/// BGP OPEN Capability Code: ADD-PATH Capability (RFC 7911, Section 4).
const CAP_ADD_PATH: u8 = 69;
/// BGP OPEN Capability Code: Enhanced Route Refresh Capability (RFC 7313).
const CAP_ENHANCED_ROUTE_REFRESH: u8 = 70;
/// BGP OPEN Capability Code: Long-Lived Graceful Restart (LLGR) Capability
/// (RFC 9494, Section 3.1).
const CAP_LLGR: u8 = 71;
/// BGP OPEN Capability Code: FQDN Capability
/// (draft-walton-bgp-hostname-capability-02, Section 3).
const CAP_FQDN: u8 = 73;
/// BGP OPEN Capability Code: PATHS-LIMIT Capability
/// (draft-abraitis-idr-addpath-paths-limit-04, Section 3).
const CAP_PATHS_LIMIT: u8 = 76;
/// BGP OPEN Capability Code: Route Refresh Capability (deprecated, pre-RFC 2918).
const CAP_ROUTE_REFRESH_DEPRECATED: u8 = 128;

/// Returns a human-readable name for BGP message types.
///
/// RFC 4271, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.1>
/// RFC 2918 — <https://www.rfc-editor.org/rfc/rfc2918>
fn msg_type_name(v: u8) -> Option<&'static str> {
    match v {
        MSG_OPEN => Some("OPEN"),
        MSG_UPDATE => Some("UPDATE"),
        MSG_NOTIFICATION => Some("NOTIFICATION"),
        MSG_KEEPALIVE => Some("KEEPALIVE"),
        MSG_ROUTE_REFRESH => Some("ROUTE-REFRESH"),
        _ => None,
    }
}

/// Returns a human-readable name for AFI values.
///
/// IANA Address Family Numbers — <https://www.iana.org/assignments/address-family-numbers>
fn afi_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("IPv4"),
        2 => Some("IPv6"),
        25 => Some("L2VPN"),
        _ => None,
    }
}

/// Returns a human-readable name for SAFI values.
///
/// IANA SAFI Namespace — <https://www.iana.org/assignments/safi-namespace>
fn safi_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Unicast"),
        2 => Some("Multicast"),
        4 => Some("MPLS Labels"),
        65 => Some("VPLS"),
        70 => Some("EVPN"),
        71 => Some("BGP-LS"),
        73 => Some("SR Policy"),
        85 => Some("BGP-MUP"),
        128 => Some("MPLS-labeled VPN"),
        129 => Some("Multicast VPN"),
        132 => Some("Route Target Constraints"),
        133 => Some("FlowSpec"),
        134 => Some("L3VPN FlowSpec"),
        _ => None,
    }
}

/// Returns a human-readable name for BGP OPEN Capability Codes.
///
/// IANA "Capability Codes" registry —
/// <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>
fn capability_code_name(v: u8) -> Option<&'static str> {
    match v {
        CAP_MULTIPROTOCOL => Some("Multiprotocol Extensions for BGP-4"),
        CAP_ROUTE_REFRESH => Some("Route Refresh Capability for BGP-4"),
        3 => Some("Outbound Route Filtering Capability"),
        CAP_EXTENDED_NEXT_HOP => Some("Extended Next Hop Encoding"),
        CAP_EXTENDED_MESSAGE => Some("BGP Extended Message"),
        7 => Some("BGPsec Capability"),
        8 => Some("Multiple Labels Capability"),
        CAP_ROLE => Some("BGP Role"),
        CAP_GRACEFUL_RESTART => Some("Graceful Restart Capability"),
        CAP_AS4 => Some("Support for 4-octet AS number capability"),
        67 => Some("Support for Dynamic Capability (capability specific)"),
        68 => Some("Multisession BGP Capability"),
        CAP_ADD_PATH => Some("ADD-PATH Capability"),
        CAP_ENHANCED_ROUTE_REFRESH => Some("Enhanced Route Refresh Capability"),
        CAP_LLGR => Some("Long-Lived Graceful Restart (LLGR) Capability"),
        CAP_FQDN => Some("FQDN Capability"),
        74 => Some("BFD Strict-Mode Capability"),
        75 => Some("Software Version Capability"),
        CAP_PATHS_LIMIT => Some("PATHS-LIMIT Capability"),
        CAP_ROUTE_REFRESH_DEPRECATED => Some("Prestandard Route Refresh (deprecated)"),
        _ => None,
    }
}

/// Returns a human-readable name for the BGP Role Capability's Role value.
///
/// RFC 9234, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9234#section-4.1>
fn role_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Provider"),
        1 => Some("RS"),
        2 => Some("RS-Client"),
        3 => Some("Customer"),
        4 => Some("Peer"),
        _ => None,
    }
}

/// Returns a human-readable name for the ADD-PATH / PATHS-LIMIT Send/Receive value.
///
/// RFC 7911, Section 4 — <https://www.rfc-editor.org/rfc/rfc7911#section-4>
fn add_path_send_receive_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("receive"),
        2 => Some("send"),
        3 => Some("send-receive"),
        _ => None,
    }
}

/// Parses OPEN message optional parameters, extracting capabilities.
///
/// `param_len_size` selects the parameter Length encoding width: 1 octet for the
/// classic encoding (RFC 4271) or 2 octets for the extended encoding
/// (RFC 9072, Section 3 — <https://www.rfc-editor.org/rfc/rfc9072#section-3>).
///
/// RFC 4271, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.2>
/// RFC 5492 — <https://www.rfc-editor.org/rfc/rfc5492>
fn parse_optional_parameters<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    params_data: &'pkt [u8],
    base_offset: usize,
    param_len_size: usize,
) {
    let mut pos = 0;
    let hdr_size = 1 + param_len_size;

    while pos + hdr_size <= params_data.len() {
        let param_type = params_data[pos];
        let param_len = if param_len_size == 1 {
            params_data[pos + 1] as usize
        } else {
            // RFC 9072 Figure 2 — 2-octet parameter length field.
            ((params_data[pos + 1] as usize) << 8) | (params_data[pos + 2] as usize)
        };
        let param_start = base_offset + pos;

        if pos + hdr_size + param_len > params_data.len() {
            break;
        }

        // RFC 5492: Capability Optional Parameter (type=2)
        if param_type == 2 {
            let cap_data = &params_data[pos + hdr_size..pos + hdr_size + param_len];
            let mut cap_pos = 0;
            while cap_pos + 2 <= cap_data.len() {
                let cap_code = cap_data[cap_pos];
                let cap_len = cap_data[cap_pos + 1] as usize;
                let cap_abs = base_offset + pos + hdr_size + cap_pos;

                if cap_pos + 2 + cap_len > cap_data.len() {
                    break;
                }

                let obj_idx = buf.begin_container(
                    &OPT_PARAM_OBJECT_DESCRIPTOR,
                    FieldValue::Object(0..0),
                    cap_abs..cap_abs + 2 + cap_len,
                );
                buf.push_field(
                    &OPT_PARAM_CHILDREN[FD_OPT_CODE],
                    FieldValue::U8(cap_code),
                    cap_abs..cap_abs + 1,
                );
                buf.push_field(
                    &OPT_PARAM_CHILDREN[FD_OPT_LENGTH],
                    FieldValue::U8(cap_data[cap_pos + 1]),
                    cap_abs + 1..cap_abs + 2,
                );

                if cap_len > 0 {
                    let cap_value = &cap_data[cap_pos + 2..cap_pos + 2 + cap_len];
                    buf.push_field(
                        &OPT_PARAM_CHILDREN[FD_OPT_VALUE],
                        FieldValue::Bytes(cap_value),
                        cap_abs + 2..cap_abs + 2 + cap_len,
                    );
                    parse_capability_value(buf, cap_code, cap_value, cap_abs + 2);
                }

                buf.end_container(obj_idx);
                cap_pos += 2 + cap_len;
            }
        } else {
            // Non-capability parameter: store raw
            let val = &params_data[pos + hdr_size..pos + hdr_size + param_len];
            let obj_idx = buf.begin_container(
                &OPT_PARAM_OBJECT_DESCRIPTOR,
                FieldValue::Object(0..0),
                param_start..param_start + hdr_size + param_len,
            );
            buf.push_field(
                &NON_CAP_PARAM_CHILDREN[FD_NCP_PARAM_TYPE],
                FieldValue::U8(param_type),
                param_start..param_start + 1,
            );
            buf.push_field(
                &NON_CAP_PARAM_CHILDREN[FD_NCP_VALUE],
                FieldValue::Bytes(val),
                param_start + hdr_size..param_start + hdr_size + param_len,
            );
            buf.end_container(obj_idx);
        }

        pos += hdr_size + param_len;
    }
}

/// Dispatches to a per-capability decoder that pushes structured child
/// fields (siblings of `code`/`length`/`value`) inside the current
/// capability object, based on the IANA Capability Code.
///
/// `value` is the capability's raw Capability Value field; `offset` is its
/// absolute byte offset within the packet. Unknown codes and malformed /
/// truncated values are silently skipped — the raw `value` field pushed by
/// the caller remains the only representation in that case.
fn parse_capability_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u8,
    value: &'pkt [u8],
    offset: usize,
) {
    match code {
        CAP_MULTIPROTOCOL => parse_cap_multiprotocol(buf, value, offset),
        CAP_EXTENDED_NEXT_HOP => parse_cap_extended_next_hop(buf, value, offset),
        CAP_ROLE => parse_cap_role(buf, value, offset),
        CAP_GRACEFUL_RESTART => parse_cap_graceful_restart(buf, value, offset),
        CAP_AS4 => parse_cap_as4(buf, value, offset),
        CAP_ADD_PATH => parse_cap_add_path(buf, value, offset),
        CAP_LLGR => parse_cap_llgr(buf, value, offset),
        CAP_FQDN => parse_cap_fqdn(buf, value, offset),
        CAP_PATHS_LIMIT => parse_cap_paths_limit(buf, value, offset),
        // Route Refresh / Enhanced Route Refresh / Extended Message /
        // deprecated Route Refresh carry no Capability Value beyond
        // `code_name`; other/unknown codes are left as raw `value` only.
        _ => {}
    }
}

/// Parses the Multiprotocol Extensions Capability Value (`afi`, `safi`).
///
/// RFC 4760, Section 8 — <https://www.rfc-editor.org/rfc/rfc4760#section-8>
///
///   AFI (2 octets) + Reserved (1 octet) + SAFI (1 octet).
fn parse_cap_multiprotocol<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.len() < 4 {
        return;
    }
    let afi = read_be_u16(value, 0).unwrap_or_default();
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI],
        FieldValue::U16(afi),
        offset..offset + 2,
    );
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_SAFI],
        FieldValue::U8(value[3]),
        offset + 3..offset + 4,
    );
}

/// Parses the Support for 4-octet AS Number Capability Value (`asn`).
///
/// RFC 6793, Section 3 — <https://www.rfc-editor.org/rfc/rfc6793#section-3>
fn parse_cap_as4<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.len() < 4 {
        return;
    }
    let asn = read_be_u32(value, 0).unwrap_or_default();
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_ASN],
        FieldValue::U32(asn),
        offset..offset + 4,
    );
}

/// Parses the BGP Role Capability Value (`role`).
///
/// RFC 9234, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9234#section-4.1>
fn parse_cap_role<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    let Some(&role) = value.first() else {
        return;
    };
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_ROLE],
        FieldValue::U8(role),
        offset..offset + 1,
    );
}

/// Parses the ADD-PATH Capability Value into `afi_safis`.
///
/// RFC 7911, Section 4 — <https://www.rfc-editor.org/rfc/rfc7911#section-4>
///
///   Zero or more 4-byte tuples: AFI (2) + SAFI (1) + Send/Receive (1).
/// A `value` whose length is not a positive multiple of 4 (e.g. truncated)
/// is left undecoded.
fn parse_cap_add_path<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.is_empty() || value.len() % 4 != 0 {
        return;
    }
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut pos = 0;
    while pos + 4 <= value.len() {
        let abs = offset + pos;
        let afi = read_be_u16(value, pos).unwrap_or_default();
        let safi = value[pos + 2];
        let send_receive = value[pos + 3];

        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 4,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(afi),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(u16::from(safi)),
            abs + 2..abs + 3,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SEND_RECEIVE],
            FieldValue::U8(send_receive),
            abs + 3..abs + 4,
        );
        buf.end_container(obj_idx);

        pos += 4;
    }
    buf.end_container(array_idx);
}

/// Parses the PATHS-LIMIT Capability Value into `afi_safis`.
///
/// draft-abraitis-idr-addpath-paths-limit-04, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-abraitis-idr-addpath-paths-limit/>
///
///   Zero or more 5-byte tuples: AFI (2) + SAFI (1) + Paths Limit (2).
fn parse_cap_paths_limit<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.is_empty() || value.len() % 5 != 0 {
        return;
    }
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut pos = 0;
    while pos + 5 <= value.len() {
        let abs = offset + pos;
        let afi = read_be_u16(value, pos).unwrap_or_default();
        let safi = value[pos + 2];
        let paths_limit = read_be_u16(value, pos + 3).unwrap_or_default();

        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 5,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(afi),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(u16::from(safi)),
            abs + 2..abs + 3,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_PATHS_LIMIT],
            FieldValue::U16(paths_limit),
            abs + 3..abs + 5,
        );
        buf.end_container(obj_idx);

        pos += 5;
    }
    buf.end_container(array_idx);
}

/// Parses the Graceful Restart Capability Value (`restart_flags`,
/// `restart_time`, and an optional `afi_safis` list).
///
/// RFC 4724, Section 3 — <https://www.rfc-editor.org/rfc/rfc4724#section-3>
///
///   Restart Flags (4 bits) + Restart Time (12 bits), then zero or more
/// 4-byte tuples: AFI (2) + SAFI (1) + Flags (1).
fn parse_cap_graceful_restart<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) {
    if value.len() < 2 {
        return;
    }
    let restart_flags = value[0] >> 4;
    let restart_time = (u16::from(value[0] & 0x0F) << 8) | u16::from(value[1]);
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_RESTART_FLAGS],
        FieldValue::U8(restart_flags),
        offset..offset + 1,
    );
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_RESTART_TIME],
        FieldValue::U16(restart_time),
        offset..offset + 2,
    );

    let tuples = &value[2..];
    if tuples.is_empty() || tuples.len() % 4 != 0 {
        return;
    }
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset + 2..offset + value.len(),
    );
    let mut pos = 0;
    while pos + 4 <= tuples.len() {
        let abs = offset + 2 + pos;
        let afi = read_be_u16(tuples, pos).unwrap_or_default();
        let safi = tuples[pos + 2];
        let flags = tuples[pos + 3];

        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 4,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(afi),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(u16::from(safi)),
            abs + 2..abs + 3,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_FLAGS],
            FieldValue::U8(flags),
            abs + 3..abs + 4,
        );
        buf.end_container(obj_idx);

        pos += 4;
    }
    buf.end_container(array_idx);
}

/// Parses the Long-Lived Graceful Restart (LLGR) Capability Value into
/// `afi_safis`.
///
/// RFC 9494, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9494#section-3.1>
///
///   Zero or more 7-byte tuples: AFI (2) + SAFI (1) + Flags (1) +
/// Long-Lived Stale Time (3, u24).
fn parse_cap_llgr<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.is_empty() || value.len() % 7 != 0 {
        return;
    }
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut pos = 0;
    while pos + 7 <= value.len() {
        let abs = offset + pos;
        let afi = read_be_u16(value, pos).unwrap_or_default();
        let safi = value[pos + 2];
        let flags = value[pos + 3];
        let stale_time = read_be_u24(value, pos + 4).unwrap_or_default();

        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 7,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(afi),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(u16::from(safi)),
            abs + 2..abs + 3,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_FLAGS],
            FieldValue::U8(flags),
            abs + 3..abs + 4,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_STALE_TIME],
            FieldValue::U32(stale_time),
            abs + 4..abs + 7,
        );
        buf.end_container(obj_idx);

        pos += 7;
    }
    buf.end_container(array_idx);
}

/// Parses the Extended Next Hop Encoding Capability Value into `afi_safis`.
///
/// RFC 8950, Section 4 — <https://www.rfc-editor.org/rfc/rfc8950#section-4>
///
///   Zero or more 6-byte tuples: NLRI AFI (2) + NLRI SAFI (2) +
/// Nexthop AFI (2). Unlike the other capabilities sharing `afi_safis`, the
/// SAFI here is a 2-octet field.
fn parse_cap_extended_next_hop<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) {
    if value.is_empty() || value.len() % 6 != 0 {
        return;
    }
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut pos = 0;
    while pos + 6 <= value.len() {
        let abs = offset + pos;
        let afi = read_be_u16(value, pos).unwrap_or_default();
        let safi = read_be_u16(value, pos + 2).unwrap_or_default();
        let next_hop_afi = read_be_u16(value, pos + 4).unwrap_or_default();

        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 6,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(afi),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(safi),
            abs + 2..abs + 4,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_NEXT_HOP_AFI],
            FieldValue::U16(next_hop_afi),
            abs + 4..abs + 6,
        );
        buf.end_container(obj_idx);

        pos += 6;
    }
    buf.end_container(array_idx);
}

/// Parses the FQDN Capability Value (`hostname`, `domain_name`).
///
/// draft-walton-bgp-hostname-capability-02, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-walton-bgp-hostname-capability/>
///
///   Hostname Length (1) + Hostname (variable, UTF-8) +
/// Domain Name Length (1) + Domain Name (variable, UTF-8).
///
/// Each string is emitted only when it decodes as valid UTF-8; a
/// zero-length Domain Name is simply omitted.
fn parse_cap_fqdn<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    let Some(&hostname_len) = value.first() else {
        return;
    };
    let hostname_len = hostname_len as usize;
    if 1 + hostname_len > value.len() {
        return;
    }
    if let Ok(hostname) = core::str::from_utf8(&value[1..1 + hostname_len]) {
        buf.push_field(
            &OPT_PARAM_CHILDREN[FD_OPT_HOSTNAME],
            FieldValue::Str(hostname),
            offset + 1..offset + 1 + hostname_len,
        );
    }

    let dn_len_pos = 1 + hostname_len;
    let Some(&domain_len) = value.get(dn_len_pos) else {
        return;
    };
    let domain_len = domain_len as usize;
    if domain_len == 0 || dn_len_pos + 1 + domain_len > value.len() {
        return;
    }
    if let Ok(domain_name) =
        core::str::from_utf8(&value[dn_len_pos + 1..dn_len_pos + 1 + domain_len])
    {
        buf.push_field(
            &OPT_PARAM_CHILDREN[FD_OPT_DOMAIN_NAME],
            FieldValue::Str(domain_name),
            offset + dn_len_pos + 1..offset + dn_len_pos + 1 + domain_len,
        );
    }
}

/// Parses OPEN message body and appends fields.
///
/// RFC 4271, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.2>
/// RFC 9072 (Extended Optional Parameters Length) —
/// <https://www.rfc-editor.org/rfc/rfc9072>
fn parse_open<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> Result<(), PacketError> {
    if data.len() < MIN_OPEN_SIZE {
        return Err(PacketError::Truncated {
            expected: MIN_OPEN_SIZE,
            actual: data.len(),
        });
    }

    let version = data[19];
    let my_as = read_be_u16(data, 20)?;
    let hold_time = read_be_u16(data, 22)?;
    let bgp_id = [data[24], data[25], data[26], data[27]];
    let opt_params_len_byte = data[28];

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION],
        FieldValue::U8(version),
        offset + 19..offset + 20,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MY_AS],
        FieldValue::U16(my_as),
        offset + 20..offset + 22,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HOLD_TIME],
        FieldValue::U16(hold_time),
        offset + 22..offset + 24,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_BGP_IDENTIFIER],
        FieldValue::Ipv4Addr(bgp_id),
        offset + 24..offset + 28,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_OPT_PARAMS_LENGTH],
        FieldValue::U8(opt_params_len_byte),
        offset + 28..offset + 29,
    );

    // RFC 9072, Section 2 — <https://www.rfc-editor.org/rfc/rfc9072#section-2>
    // Extended encoding is signalled by the byte at offset 29 (Non-Ext OP Type)
    // having value 255. The Extended Opt. Parm. Length is then encoded as a
    // 2-octet unsigned integer at bytes 30..32 and each parameter uses a
    // 2-octet length field.
    let extended = data.len() >= 32 && data[29] == 255;

    let (params_offset, params_len, param_len_size) = if extended {
        let ext_len = read_be_u16(data, 30)? as usize;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_EXT_OPT_PARAMS_LENGTH],
            FieldValue::U16(ext_len as u16),
            offset + 30..offset + 32,
        );
        (32usize, ext_len, 2usize)
    } else {
        (29usize, opt_params_len_byte as usize, 1usize)
    };

    if params_len > 0 {
        let params_end = params_offset + params_len;
        if data.len() < params_end {
            return Err(PacketError::Truncated {
                expected: params_end,
                actual: data.len(),
            });
        }

        let params_data = &data[params_offset..params_end];
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_OPTIONAL_PARAMETERS],
            FieldValue::Array(0..0),
            offset + params_offset..offset + params_end,
        );
        parse_optional_parameters(buf, params_data, offset + params_offset, param_len_size);
        buf.end_container(array_idx);
    }

    Ok(())
}

/// Returns a human-readable name for BGP error codes.
///
/// RFC 4271, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.5>
fn error_code_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Message Header Error"),
        2 => Some("OPEN Message Error"),
        3 => Some("UPDATE Message Error"),
        4 => Some("Hold Timer Expired"),
        5 => Some("Finite State Machine Error"),
        6 => Some("Cease"),
        7 => Some("ROUTE-REFRESH Message Error"),
        8 => Some("Send Hold Timer Expired"),
        _ => None,
    }
}

/// Returns a human-readable name for Cease NOTIFICATION subcodes.
///
/// RFC 4486, Section 4 — <https://www.rfc-editor.org/rfc/rfc4486#section-4>
/// RFC 8203, Section 4 — <https://www.rfc-editor.org/rfc/rfc8203#section-4>
fn cease_subcode_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Maximum Number of Prefixes Reached"),
        2 => Some("Administrative Shutdown"),
        3 => Some("Peer De-configured"),
        4 => Some("Administrative Reset"),
        5 => Some("Connection Rejected"),
        6 => Some("Other Configuration Change"),
        7 => Some("Connection Collision Resolution"),
        8 => Some("Out of Resources"),
        9 => Some("Hard Reset"),
        _ => None,
    }
}

/// Parses NOTIFICATION message body and appends fields.
///
/// RFC 4271, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.5>
fn parse_notification<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> Result<(), PacketError> {
    if data.len() < MIN_NOTIFICATION_SIZE {
        return Err(PacketError::Truncated {
            expected: MIN_NOTIFICATION_SIZE,
            actual: data.len(),
        });
    }

    let error_code = data[19];
    let error_subcode = data[20];

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_ERROR_CODE],
        FieldValue::U8(error_code),
        offset + 19..offset + 20,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_ERROR_SUBCODE],
        FieldValue::U8(error_subcode),
        offset + 20..offset + 21,
    );

    if data.len() > MIN_NOTIFICATION_SIZE {
        let data_bytes = &data[21..];
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA],
            FieldValue::Bytes(data_bytes),
            offset + 21..offset + data.len(),
        );
    }

    Ok(())
}

/// Returns a human-readable name for ROUTE-REFRESH Message Subtypes.
///
/// RFC 7313, Section 4 — <https://www.rfc-editor.org/rfc/rfc7313#section-4>
fn route_refresh_subtype_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Route Refresh"),
        1 => Some("BoRR"),
        2 => Some("EoRR"),
        _ => None,
    }
}

/// Parses ROUTE-REFRESH message body and appends fields.
///
/// RFC 2918 — <https://www.rfc-editor.org/rfc/rfc2918>
/// RFC 7313 (Enhanced Route Refresh) — <https://www.rfc-editor.org/rfc/rfc7313>
fn parse_route_refresh<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> Result<(), PacketError> {
    if data.len() < ROUTE_REFRESH_SIZE {
        return Err(PacketError::Truncated {
            expected: ROUTE_REFRESH_SIZE,
            actual: data.len(),
        });
    }

    let afi = read_be_u16(data, 19)?;
    // RFC 7313, Section 4 — <https://www.rfc-editor.org/rfc/rfc7313#section-4>
    // redefined byte 21 from "Reserved" to "Message Subtype".
    let message_subtype = data[21];
    let safi = data[22];

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_AFI],
        FieldValue::U16(afi),
        offset + 19..offset + 21,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MESSAGE_SUBTYPE],
        FieldValue::U8(message_subtype),
        offset + 21..offset + 22,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SAFI],
        FieldValue::U8(safi),
        offset + 22..offset + 23,
    );

    Ok(())
}

/// Returns `true` when an IPv4/IPv6 NLRI block carries RFC 7911 ADD-PATH
/// Path Identifiers.
///
/// BGP dissection here is stateless: the ADD-PATH capability is negotiated in
/// OPEN messages (RFC 7911, Section 4) and this dissector does not track session
/// state across messages, so the encoding must be inferred from the NLRI block
/// itself.
///
/// The heuristic mirrors Wireshark's `detect_add_path_prefix46()` in
/// `epan/dissectors/packet-bgp.c`. The block is treated as ADD-PATH iff:
///
/// 1. it parses exactly as a sequence of
///    `[Path Identifier (4)][Length (1)][Prefix (ceil(Length/8))]` entries, and
/// 2. it does *not* also parse exactly as a sequence of plain
///    `[Length (1)][Prefix (ceil(Length/8))]` entries, or a plain parse yields a
///    zero-length prefix (`0/0`) that is not the sole entry of the block — in
///    practice the leading octets are then really a Path Identifier.
///
/// Plain encoding wins when both readings are valid.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_prefixes(data: &[u8], max_bits: usize) -> bool {
    // (1) Must parse completely and validly as ADD-PATH prefixes.
    let mut pos = 0;
    while pos < data.len() {
        // Both the 4-octet Path Identifier and the Length octet must be present.
        let Some(&prefix_bits) = data.get(pos + PATH_ID_SIZE) else {
            return false;
        };
        if prefix_bits as usize > max_bits {
            return false;
        }
        pos += PATH_ID_SIZE + 1 + (prefix_bits as usize).div_ceil(8);
        if pos > data.len() {
            return false;
        }
    }

    // (2) Must not parse completely and validly as plain prefixes.
    let mut pos = 0;
    while pos < data.len() {
        let prefix_bits = data[pos] as usize;
        if prefix_bits > max_bits {
            return true;
        }
        pos += 1 + prefix_bits.div_ceil(8);
        if pos > data.len() {
            return true;
        }
        // A zero-length prefix sharing the block with other data is much more
        // likely to be the tail of a Path Identifier than a real default route.
        if prefix_bits == 0 && data.len() > 1 {
            return true;
        }
    }

    false
}

/// Returns `true` when a MUP (SAFI 85) NLRI block carries RFC 7911 ADD-PATH
/// Path Identifiers.
///
/// The MUP analogue of [`detect_add_path_prefixes`]: the block is ADD-PATH iff
/// it parses exactly as MUP entries each preceded by a 4-octet Path Identifier,
/// and does not parse exactly as plain MUP entries. Plain wins when both are
/// valid.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
/// draft-ietf-bess-mup-safi-01, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
fn detect_add_path_mup(data: &[u8]) -> bool {
    mup_block_parses(data, PATH_ID_SIZE) && !mup_block_parses(data, 0)
}

/// Returns `true` when `data` parses exactly as a sequence of MUP NLRI entries,
/// each preceded by `path_id_len` octets of Path Identifier.
///
/// An entry is considered valid when it declares the only defined Architecture
/// Type (1, 3gpp-5g), a defined Route Type (1-4), and a Length that keeps the
/// walk inside the block. The block is valid when the entries consume it exactly.
///
/// draft-ietf-bess-mup-safi-01, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
fn mup_block_parses(data: &[u8], path_id_len: usize) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let entry = pos + path_id_len;
        if entry + MUP_NLRI_HEADER_SIZE > data.len() {
            return false;
        }
        if data[entry] != MUP_ARCHITECTURE_TYPE_3GPP_5G {
            return false;
        }
        let route_type = read_be_u16(data, entry + 1).unwrap_or_default();
        if !(MUP_ROUTE_TYPE_MIN..=MUP_ROUTE_TYPE_MAX).contains(&route_type) {
            return false;
        }
        pos = entry + MUP_NLRI_HEADER_SIZE + data[entry + 3] as usize;
        if pos > data.len() {
            return false;
        }
    }
    true
}

/// Parses a sequence of BGP prefixes into one Object per entry.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// Each prefix: 1-byte length (in bits) + ceil(length/8) bytes of prefix, pushed
/// as `{ "prefix": "10.0.0.0/24" }`.
///
/// When the block is detected as RFC 7911 ADD-PATH (see
/// [`detect_add_path_prefixes`]) each entry is preceded by a 4-octet Path
/// Identifier and is pushed as `{ "path_id": 5, "prefix": "10.0.0.0/24" }`.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
///
/// When `ipv6` is true, formats as IPv6; otherwise as IPv4.
fn parse_prefixes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ipv6: bool,
) {
    let mut pos = 0;

    let max_bits: usize = if ipv6 { 128 } else { 32 };
    let descriptor = if ipv6 {
        &PREFIX_ENTRY_IPV6_DESCRIPTOR
    } else {
        &PREFIX_ENTRY_IPV4_DESCRIPTOR
    };
    let id_len = if detect_add_path_prefixes(data, max_bits) {
        PATH_ID_SIZE
    } else {
        0
    };

    // The Length octet sits right after the (optional) Path Identifier, so an
    // entry needs at least `id_len + 1` octets to exist at all.
    while pos + id_len < data.len() {
        let prefix_bits = data[pos + id_len] as usize;

        // Validate prefix length against address family maximum.
        if prefix_bits > max_bits {
            break;
        }

        let prefix_bytes = prefix_bits.div_ceil(8);
        let entry_len = id_len + 1 + prefix_bytes;

        if pos + entry_len > data.len() {
            break;
        }

        let abs = base_offset + pos;
        let obj_idx = buf.begin_container(
            &NLRI_ENTRY_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + entry_len,
        );

        if id_len != 0 {
            buf.push_field(
                &IP_NLRI_ENTRY_CHILDREN[FD_NLRI_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }

        buf.push_field(
            descriptor,
            FieldValue::Bytes(&data[pos + id_len..pos + entry_len]),
            abs + id_len..abs + entry_len,
        );

        buf.end_container(obj_idx);

        pos += entry_len;
    }
}

/// Returns a human-readable name for path attribute type codes.
///
/// IANA BGP Path Attributes — <https://www.iana.org/assignments/bgp-parameters>
fn path_attr_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("ORIGIN"),
        2 => Some("AS_PATH"),
        3 => Some("NEXT_HOP"),
        4 => Some("MULTI_EXIT_DISC"),
        5 => Some("LOCAL_PREF"),
        6 => Some("ATOMIC_AGGREGATE"),
        7 => Some("AGGREGATOR"),
        8 => Some("COMMUNITIES"),
        9 => Some("ORIGINATOR_ID"),
        10 => Some("CLUSTER_LIST"),
        14 => Some("MP_REACH_NLRI"),
        15 => Some("MP_UNREACH_NLRI"),
        16 => Some("EXTENDED COMMUNITIES"),
        17 => Some("AS4_PATH"),
        18 => Some("AS4_AGGREGATOR"),
        22 => Some("PMSI_TUNNEL"),
        23 => Some("Tunnel Encapsulation"),
        26 => Some("AIGP"),
        29 => Some("BGP-LS Attribute"),
        32 => Some("LARGE_COMMUNITY"),
        33 => Some("BGPsec_Path"),
        35 => Some("Only to Customer (OTC)"),
        40 => Some("BGP Prefix-SID"),
        _ => None,
    }
}

/// Parses a single path attribute and pushes it as an Object into the buffer.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// Returns the number of bytes consumed, or `None` if parsing fails.
fn parse_path_attribute<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
) -> Option<usize> {
    if data.len() < 3 {
        return None;
    }

    let flags = data[0];
    let type_code = data[1];
    let extended_length = flags & 0x10 != 0;

    let (attr_len, header_len) = if extended_length {
        if data.len() < 4 {
            return None;
        }
        (read_be_u16(data, 2).unwrap_or_default() as usize, 4usize)
    } else {
        (data[2] as usize, 3usize)
    };

    let total_len = header_len + attr_len;
    if data.len() < total_len {
        return None;
    }

    let value_data = &data[header_len..total_len];

    let obj_idx = buf.begin_container(
        &PATH_ATTR_OBJECT_DESCRIPTOR,
        FieldValue::Object(0..0),
        base_offset..base_offset + total_len,
    );

    buf.push_field(
        &PATH_ATTR_CHILDREN[FD_PA_FLAGS],
        FieldValue::U8(flags),
        base_offset..base_offset + 1,
    );
    buf.push_field(
        &PATH_ATTR_CHILDREN[FD_PA_TYPE_CODE],
        FieldValue::U8(type_code),
        base_offset + 1..base_offset + 2,
    );
    buf.push_field(
        &PATH_ATTR_CHILDREN[FD_PA_ATTR_LENGTH],
        FieldValue::U16(attr_len as u16),
        base_offset + 2..base_offset + header_len,
    );

    let val_offset = base_offset + header_len;
    parse_attr_value(buf, type_code, value_data, val_offset);

    buf.end_container(obj_idx);

    Some(total_len)
}

/// Returns a human-readable name for ORIGIN values.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
fn origin_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("IGP"),
        1 => Some("EGP"),
        2 => Some("INCOMPLETE"),
        _ => None,
    }
}

/// Formats a well-known community value using IANA registry names.
///
/// IANA BGP Well-known Communities —
/// <https://www.iana.org/assignments/bgp-well-known-communities/bgp-well-known-communities.xhtml>
fn well_known_community_name(v: u32) -> Option<&'static str> {
    match v {
        0xFFFF_0000 => Some("GRACEFUL_SHUTDOWN"),
        0xFFFF_0001 => Some("ACCEPT_OWN"),
        0xFFFF_0002 => Some("ROUTE_FILTER_TRANSLATED_v4"),
        0xFFFF_0003 => Some("ROUTE_FILTER_v4"),
        0xFFFF_0004 => Some("ROUTE_FILTER_TRANSLATED_v6"),
        0xFFFF_0005 => Some("ROUTE_FILTER_v6"),
        0xFFFF_0006 => Some("LLGR_STALE"),
        0xFFFF_0007 => Some("NO_LLGR"),
        0xFFFF_029A => Some("BLACKHOLE"),
        0xFFFF_FF01 => Some("NO_EXPORT"),
        0xFFFF_FF02 => Some("NO_ADVERTISE"),
        0xFFFF_FF03 => Some("NO_EXPORT_SUBCONFED"),
        0xFFFF_FF04 => Some("NOPEER"),
        _ => None,
    }
}

/// Returns a human-readable name for Extended Community types.
///
/// RFC 4360 — <https://www.rfc-editor.org/rfc/rfc4360>
/// RFC 9012 — <https://www.rfc-editor.org/rfc/rfc9012>
/// draft-ietf-bess-mup-safi-01, Section 3.2 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
fn extended_community_type_name(type_high: u8, sub_type: u8) -> Option<&'static str> {
    let base_type = type_high & 0x3F;
    match (base_type, sub_type) {
        (0x00, 0x02) | (0x02, 0x02) => Some("Route Target"),
        (0x01, 0x02) => Some("Route Target (IPv4)"),
        (0x00, 0x03) | (0x02, 0x03) => Some("Route Origin"),
        (0x01, 0x03) => Some("Route Origin (IPv4)"),
        (0x03, 0x0B) => Some("Color"),
        (0x06, _) => Some("EVPN"),
        (0x0C, 0x00) => Some("MUP Direct Segment (2-Octet AS)"),
        (0x0C, 0x01) => Some("MUP Direct Segment (IPv4 Address)"),
        (0x0C, 0x02) => Some("MUP Direct Segment (4-Octet AS)"),
        (0x0C, 0x03) => Some("MUP Interwork Segment (2-Octet AS)"),
        (0x0C, 0x04) => Some("MUP Interwork Segment (IPv4 Address)"),
        (0x0C, 0x05) => Some("MUP Interwork Segment (4-Octet AS)"),
        _ => None,
    }
}

/// Returns a human-readable name for AS_PATH segment types.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// RFC 5065 — <https://www.rfc-editor.org/rfc/rfc5065>
fn as_path_segment_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("AS_SET"),
        2 => Some("AS_SEQUENCE"),
        3 => Some("AS_CONFED_SEQUENCE"),
        4 => Some("AS_CONFED_SET"),
        _ => None,
    }
}

/// Parses BGP Prefix-SID attribute value as a sequence of TLVs.
///
/// RFC 8669, Section 3 — <https://www.rfc-editor.org/rfc/rfc8669#section-3>
///
/// Each TLV: 1-byte Type + 2-byte Length + variable Value.
fn parse_prefix_sid<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let array_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    let mut count = 0;

    while pos + 3 <= data.len() {
        let tlv_type = data[pos];
        let tlv_len = read_be_u16(data, pos + 1).unwrap_or_default() as usize;
        let abs = offset + pos;

        if pos + 3 + tlv_len > data.len() {
            break;
        }

        let total = 3 + tlv_len;
        let obj_idx = buf.begin_container(
            &PREFIX_SID_TLV_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + total,
        );

        buf.push_field(
            &PREFIX_SID_TLV_CHILDREN[FD_PSID_TYPE],
            FieldValue::U8(tlv_type),
            abs..abs + 1,
        );
        buf.push_field(
            &PREFIX_SID_TLV_CHILDREN[FD_PSID_LENGTH],
            FieldValue::U16(tlv_len as u16),
            abs + 1..abs + 3,
        );

        let val_data = &data[pos + 3..pos + 3 + tlv_len];
        let val_offset = abs + 3;

        match tlv_type {
            // Label-Index TLV (RFC 8669, Section 3.1)
            1 => parse_label_index_tlv(buf, val_data, val_offset),
            // Originator SRGB TLV (RFC 8669, Section 3.2)
            3 => parse_originator_srgb_tlv(buf, val_data, val_offset),
            // SRv6 L3 Service TLV (RFC 9252, Section 2) /
            // SRv6 L2 Service TLV (RFC 9252, Section 2)
            5 | 6 => parse_srv6_service_tlv(buf, val_data, val_offset),
            _ => {
                if !val_data.is_empty() {
                    buf.push_field(
                        &PREFIX_SID_TLV_CHILDREN[FD_PSID_VALUE],
                        FieldValue::Bytes(val_data),
                        val_offset..val_offset + val_data.len(),
                    );
                }
            }
        }

        buf.end_container(obj_idx);
        count += 1;
        pos += total;
    }

    if count == 0 {
        // Remove the empty array placeholder
        buf.pop_field();
    } else {
        buf.end_container(array_idx);
    }
}

/// Parses a Label-Index TLV value.
///
/// RFC 8669, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc8669#section-3.1>
///
///   Reserved (1 byte) + Flags (2 bytes) + Label Index (4 bytes) = 7 bytes.
fn parse_label_index_tlv<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data.len() < 7 {
        if !data.is_empty() {
            buf.push_field(
                &PREFIX_SID_TLV_CHILDREN[FD_PSID_VALUE],
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        return;
    }
    // Skip Reserved (1 byte)
    let flags = read_be_u16(data, 1).unwrap_or_default();
    let label_index = read_be_u32(data, 3).unwrap_or_default();

    buf.push_field(
        &PREFIX_SID_TLV_CHILDREN[FD_PSID_FLAGS],
        FieldValue::U16(flags),
        offset + 1..offset + 3,
    );
    buf.push_field(
        &PREFIX_SID_TLV_CHILDREN[FD_PSID_LABEL_INDEX],
        FieldValue::U32(label_index),
        offset + 3..offset + 7,
    );
}

/// Parses an Originator SRGB TLV value.
///
/// RFC 8669, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8669#section-3.2>
///
///   Flags (2 bytes) + SRGB entries (6 bytes each: 3-byte base + 3-byte range).
fn parse_originator_srgb_tlv<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data.len() < 2 {
        if !data.is_empty() {
            buf.push_field(
                &PREFIX_SID_TLV_CHILDREN[FD_PSID_VALUE],
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        return;
    }

    let flags = read_be_u16(data, 0).unwrap_or_default();
    buf.push_field(
        &PREFIX_SID_TLV_CHILDREN[FD_PSID_FLAGS],
        FieldValue::U16(flags),
        offset..offset + 2,
    );

    let array_idx = buf.begin_container(
        &PREFIX_SID_TLV_CHILDREN[FD_PSID_SRGB_ENTRIES],
        FieldValue::Array(0..0),
        offset + 2..offset + data.len(),
    );
    let mut count = 0;
    let mut pos = 2;
    while pos + 6 <= data.len() {
        let abs = offset + pos;
        let base = read_be_u24(data, pos).unwrap_or_default();
        let range = read_be_u24(data, pos + 3).unwrap_or_default();

        let obj_idx = buf.begin_container(
            &SRGB_ENTRY_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 6,
        );
        buf.push_field(
            &SRGB_ENTRY_CHILDREN[FD_SRGB_BASE],
            FieldValue::U32(base),
            abs..abs + 3,
        );
        buf.push_field(
            &SRGB_ENTRY_CHILDREN[FD_SRGB_RANGE],
            FieldValue::U32(range),
            abs + 3..abs + 6,
        );
        buf.end_container(obj_idx);

        count += 1;
        pos += 6;
    }

    if count == 0 {
        buf.pop_field();
    } else {
        buf.end_container(array_idx);
    }
}

/// Parses an SRv6 L3/L2 Service TLV value.
///
/// RFC 9252, Section 2 — <https://www.rfc-editor.org/rfc/rfc9252#section-2>
///
///   Reserved (1 byte) + Sub-TLVs (each: 1-byte Type + 2-byte Length + variable Value).
fn parse_srv6_service_tlv<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data.is_empty() {
        return;
    }

    // Skip Reserved (1 byte)
    let array_idx = buf.begin_container(
        &PREFIX_SID_TLV_CHILDREN[FD_PSID_SUB_TLVS],
        FieldValue::Array(0..0),
        offset + 1..offset + data.len(),
    );
    let mut count = 0;
    let mut pos = 1;

    while pos + 3 <= data.len() {
        let sub_type = data[pos];
        let sub_len = read_be_u16(data, pos + 1).unwrap_or_default() as usize;
        let abs = offset + pos;

        if pos + 3 + sub_len > data.len() {
            break;
        }

        let total = 3 + sub_len;
        let obj_idx = buf.begin_container(
            &SRV6_SID_INFO_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + total,
        );

        buf.push_field(
            &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_TYPE],
            FieldValue::U8(sub_type),
            abs..abs + 1,
        );
        buf.push_field(
            &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_LENGTH],
            FieldValue::U16(sub_len as u16),
            abs + 1..abs + 3,
        );

        let val_data = &data[pos + 3..pos + 3 + sub_len];
        let val_offset = abs + 3;

        match sub_type {
            // SRv6 SID Information Sub-TLV (RFC 9252, Section 3.1)
            1 => parse_srv6_sid_info_sub_tlv(buf, val_data, val_offset),
            _ => {
                if !val_data.is_empty() {
                    buf.push_field(
                        &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_VALUE],
                        FieldValue::Bytes(val_data),
                        val_offset..val_offset + val_data.len(),
                    );
                }
            }
        }

        buf.end_container(obj_idx);
        count += 1;
        pos += total;
    }

    if count == 0 {
        buf.pop_field();
    } else {
        buf.end_container(array_idx);
    }
}

/// Parses an SRv6 SID Information Sub-TLV value.
///
/// RFC 9252, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9252#section-3.1>
///
///   Reserved1 (1) + SRv6 SID (16) + Service SID Flags (1) + Endpoint Behavior (2)
///   + Reserved2 (1) = 21 bytes minimum, followed by optional Sub-Sub-TLVs.
fn parse_srv6_sid_info_sub_tlv<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) {
    if data.len() < 21 {
        if !data.is_empty() {
            buf.push_field(
                &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_VALUE],
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        return;
    }

    // Skip Reserved1 (1 byte)
    let sid = read_ipv6_addr(data, 1).unwrap_or_default();
    let sid_flags = data[17];
    let endpoint_behavior = read_be_u16(data, 18).unwrap_or_default();
    // Skip Reserved2 at data[20]

    buf.push_field(
        &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_SID],
        FieldValue::Ipv6Addr(sid),
        offset + 1..offset + 17,
    );
    buf.push_field(
        &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_FLAGS],
        FieldValue::U8(sid_flags),
        offset + 17..offset + 18,
    );
    buf.push_field(
        &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_ENDPOINT_BEHAVIOR],
        FieldValue::U16(endpoint_behavior),
        offset + 18..offset + 20,
    );

    // Parse Sub-Sub-TLVs (RFC 9252, Section 3.2)
    let mut pos = 21;
    while pos + 3 <= data.len() {
        let ss_type = data[pos];
        let ss_len = read_be_u16(data, pos + 1).unwrap_or_default() as usize;

        if pos + 3 + ss_len > data.len() {
            break;
        }

        // SRv6 SID Structure Sub-Sub-TLV (RFC 9252, Section 3.2.1)
        if ss_type == 1 && ss_len == 6 {
            let ss_val = &data[pos + 3..pos + 3 + ss_len];
            let abs = offset + pos + 3;
            let obj_idx = buf.begin_container(
                &SRV6_SID_INFO_CHILDREN[FD_SRV6_SI_SID_STRUCTURE],
                FieldValue::Object(0..0),
                offset + pos..offset + pos + 3 + ss_len,
            );
            buf.push_field(
                &SRV6_SID_STRUCTURE_CHILDREN[FD_SRV6_SS_LBL],
                FieldValue::U8(ss_val[0]),
                abs..abs + 1,
            );
            buf.push_field(
                &SRV6_SID_STRUCTURE_CHILDREN[FD_SRV6_SS_LNL],
                FieldValue::U8(ss_val[1]),
                abs + 1..abs + 2,
            );
            buf.push_field(
                &SRV6_SID_STRUCTURE_CHILDREN[FD_SRV6_SS_FL],
                FieldValue::U8(ss_val[2]),
                abs + 2..abs + 3,
            );
            buf.push_field(
                &SRV6_SID_STRUCTURE_CHILDREN[FD_SRV6_SS_AL],
                FieldValue::U8(ss_val[3]),
                abs + 3..abs + 4,
            );
            buf.push_field(
                &SRV6_SID_STRUCTURE_CHILDREN[FD_SRV6_SS_TL],
                FieldValue::U8(ss_val[4]),
                abs + 4..abs + 5,
            );
            buf.push_field(
                &SRV6_SID_STRUCTURE_CHILDREN[FD_SRV6_SS_TO],
                FieldValue::U8(ss_val[5]),
                abs + 5..abs + 6,
            );
            buf.end_container(obj_idx);
        }

        pos += 3 + ss_len;
    }
}

/// Parses an AS_PATH or AS4_PATH attribute value into the buffer.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// RFC 6793 — <https://www.rfc-editor.org/rfc/rfc6793>
fn parse_as_path<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    as_size: usize,
) {
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let seg_type = data[pos];
        let seg_len = data[pos + 1] as usize;
        let seg_abs = offset + pos;

        let seg_data_len = seg_len * as_size;
        if pos + 2 + seg_data_len > data.len() {
            break;
        }

        let seg_obj_idx = buf.begin_container(
            &AS_PATH_SEG_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            seg_abs..seg_abs + 2 + seg_data_len,
        );

        buf.push_field(
            &AS_PATH_SEG_CHILDREN[FD_APS_SEGMENT_TYPE],
            FieldValue::U8(seg_type),
            seg_abs..seg_abs + 1,
        );

        let as_array_idx = buf.begin_container(
            &AS_PATH_SEG_CHILDREN[FD_APS_AS_NUMBERS],
            FieldValue::Array(0..0),
            seg_abs + 2..seg_abs + 2 + seg_data_len,
        );
        for i in 0..seg_len {
            let as_offset = pos + 2 + i * as_size;
            let as_abs = offset + as_offset;
            let asn = if as_size == 4 {
                read_be_u32(data, as_offset).unwrap_or_default()
            } else {
                read_be_u16(data, as_offset).unwrap_or_default() as u32
            };
            buf.push_field(
                &AS_NUMBER_DESCRIPTOR,
                FieldValue::U32(asn),
                as_abs..as_abs + as_size,
            );
        }
        buf.end_container(as_array_idx);

        buf.end_container(seg_obj_idx);

        pos += 2 + seg_data_len;
    }
}

/// Parses the value of a path attribute based on its type code.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
fn parse_attr_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    type_code: u8,
    data: &'pkt [u8],
    offset: usize,
) {
    match type_code {
        // ORIGIN (RFC 4271, Section 5.1.1)
        1 if data.len() == 1 => {
            buf.push_field(
                &FD_ORIGIN_VALUE,
                FieldValue::U8(data[0]),
                offset..offset + 1,
            );
        }
        // AS_PATH (RFC 4271, Section 5.1.2) — 2-byte AS numbers
        2 => {
            let array_idx = buf.begin_container(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Array(0..0),
                offset..offset + data.len(),
            );
            parse_as_path(buf, data, offset, 2);
            buf.end_container(array_idx);
        }
        // NEXT_HOP (RFC 4271, Section 5.1.3) — 4-byte IPv4 address
        3 if data.len() == 4 => {
            buf.push_field(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
                offset..offset + 4,
            );
        }
        // MULTI_EXIT_DISC (RFC 4271, Section 5.1.4) — 4-byte unsigned integer
        4 if data.len() == 4 => {
            let med = read_be_u32(data, 0).unwrap_or_default();
            buf.push_field(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::U32(med),
                offset..offset + 4,
            );
        }
        // LOCAL_PREF (RFC 4271, Section 5.1.5) — 4-byte unsigned integer
        5 if data.len() == 4 => {
            let lp = read_be_u32(data, 0).unwrap_or_default();
            buf.push_field(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::U32(lp),
                offset..offset + 4,
            );
        }
        // ATOMIC_AGGREGATE (RFC 4271, Section 5.1.6) — 0 bytes
        6 => {}
        // AGGREGATOR (RFC 4271, Section 5.1.7) — 2-byte AS + 4-byte IP = 6 bytes
        // or 4-byte AS + 4-byte IP = 8 bytes (RFC 6793)
        7 if data.len() == 6 || data.len() == 8 => {
            buf.push_field(
                &FD_AGGREGATOR_VALUE,
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        // COMMUNITIES (RFC 1997) — sequence of 4-byte values
        8 if data.len() % 4 == 0 => {
            let array_idx = buf.begin_container(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Array(0..0),
                offset..offset + data.len(),
            );
            let mut pos = 0;
            while pos + 4 <= data.len() {
                let val = read_be_u32(data, pos).unwrap_or_default();
                buf.push_field(
                    &COMMUNITY_ENTRY_DESCRIPTOR,
                    FieldValue::U32(val),
                    offset + pos..offset + pos + 4,
                );
                pos += 4;
            }
            buf.end_container(array_idx);
        }
        // ORIGINATOR_ID (RFC 4456) — 4-byte IPv4 address
        9 if data.len() == 4 => {
            buf.push_field(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
                offset..offset + 4,
            );
        }
        // CLUSTER_LIST (RFC 4456) — sequence of 4-byte cluster IDs
        10 if data.len() % 4 == 0 => {
            let array_idx = buf.begin_container(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Array(0..0),
                offset..offset + data.len(),
            );
            let mut pos = 0;
            while pos + 4 <= data.len() {
                buf.push_field(
                    &CLUSTER_ID_DESCRIPTOR,
                    FieldValue::Ipv4Addr([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]),
                    offset + pos..offset + pos + 4,
                );
                pos += 4;
            }
            buf.end_container(array_idx);
        }
        // MP_REACH_NLRI (RFC 4760, Section 3)
        14 if data.len() >= 5 => {
            parse_mp_reach_nlri(buf, data, offset);
        }
        // MP_UNREACH_NLRI (RFC 4760, Section 4)
        15 if data.len() >= 3 => {
            parse_mp_unreach_nlri(buf, data, offset);
        }
        // EXTENDED_COMMUNITIES (RFC 4360) — sequence of 8-byte values
        16 if data.len() % 8 == 0 => {
            let array_idx = buf.begin_container(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Array(0..0),
                offset..offset + data.len(),
            );
            let mut pos = 0;
            while pos + 8 <= data.len() {
                let abs = offset + pos;
                buf.push_field(
                    &EXT_COMMUNITY_ENTRY_DESCRIPTOR,
                    FieldValue::Bytes(&data[pos..pos + 8]),
                    abs..abs + 8,
                );
                pos += 8;
            }
            buf.end_container(array_idx);
        }
        // AS4_PATH (RFC 6793) — same format as AS_PATH but with 4-byte AS numbers
        17 => {
            let array_idx = buf.begin_container(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Array(0..0),
                offset..offset + data.len(),
            );
            parse_as_path(buf, data, offset, 4);
            buf.end_container(array_idx);
        }
        // AS4_AGGREGATOR (RFC 6793) — 4-byte AS + 4-byte IP = 8 bytes
        18 if data.len() == 8 => {
            buf.push_field(
                &FD_AS4_AGGREGATOR_VALUE,
                FieldValue::Bytes(data),
                offset..offset + 8,
            );
        }
        // LARGE_COMMUNITY (RFC 8092) — sequence of 12-byte values
        32 if data.len() % 12 == 0 => {
            let array_idx = buf.begin_container(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::Array(0..0),
                offset..offset + data.len(),
            );
            let mut pos = 0;
            while pos + 12 <= data.len() {
                buf.push_field(
                    &LARGE_COMMUNITY_ENTRY_DESCRIPTOR,
                    FieldValue::Bytes(&data[pos..pos + 12]),
                    offset + pos..offset + pos + 12,
                );
                pos += 12;
            }
            buf.end_container(array_idx);
        }
        // BGP Prefix-SID (RFC 8669, RFC 9252)
        40 => {
            parse_prefix_sid(buf, data, offset);
        }
        _ => {
            // Unknown/unhandled attribute: store raw bytes
            if !data.is_empty() {
                buf.push_field(
                    &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                    FieldValue::Bytes(data),
                    offset..offset + data.len(),
                );
            }
        }
    }
}

/// Returns a human-readable name for MUP route types.
///
/// draft-ietf-bess-mup-safi-01, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
fn mup_route_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Interwork Segment Discovery"),
        2 => Some("Direct Segment Discovery"),
        3 => Some("Type 1 Session Transformed"),
        4 => Some("Type 2 Session Transformed"),
        _ => None,
    }
}

/// Returns a human-readable name for MUP architecture types.
///
/// draft-ietf-bess-mup-safi-01, Section 3
fn mup_architecture_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("3gpp-5g"),
        _ => None,
    }
}

/// Returns a human-readable name for MUP ST Route TLV types.
///
/// draft-ietf-bess-mup-safi-01, Section 3.1.5 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
fn mup_st_tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("3gpp-5g Session Parameters"),
        2 => Some("Interwork Endpoint"),
        3 => Some("Source Address"),
        _ => None,
    }
}

/// Parses a sequence of MUP NLRI entries into the buffer.
///
/// draft-ietf-bess-mup-safi-01, Section 3 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
///
/// Each MUP NLRI: Architecture Type (1) + Route Type (2) + Length (1) + Route Type specific data.
///
/// When the block is detected as RFC 7911 ADD-PATH (see [`detect_add_path_mup`])
/// every entry is preceded by a 4-octet Path Identifier, emitted as a leading
/// `path_id` field.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn parse_mup_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ipv6: bool,
) {
    let mut pos = 0;
    let id_len = if detect_add_path_mup(data) {
        PATH_ID_SIZE
    } else {
        0
    };

    while pos + id_len + MUP_NLRI_HEADER_SIZE <= data.len() {
        let entry = pos + id_len;
        let arch_type = data[entry];
        let route_type = read_be_u16(data, entry + 1).unwrap_or_default();
        let rt_len = data[entry + 3] as usize;

        if entry + MUP_NLRI_HEADER_SIZE + rt_len > data.len() {
            break;
        }

        let abs = base_offset + pos;
        let entry_abs = base_offset + entry;
        let rt_data = &data[entry + MUP_NLRI_HEADER_SIZE..entry + MUP_NLRI_HEADER_SIZE + rt_len];
        let total = id_len + MUP_NLRI_HEADER_SIZE + rt_len;

        let obj_idx = buf.begin_container(
            &MUP_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + total,
        );

        if id_len != 0 {
            buf.push_field(
                &MUP_NLRI_CHILDREN[FD_MUP_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }

        buf.push_field(
            &MUP_NLRI_CHILDREN[FD_MUP_ARCH_TYPE],
            FieldValue::U8(arch_type),
            entry_abs..entry_abs + 1,
        );
        buf.push_field(
            &MUP_NLRI_CHILDREN[FD_MUP_ROUTE_TYPE],
            FieldValue::U16(route_type),
            entry_abs + 1..entry_abs + 3,
        );

        let rt_offset = entry_abs + MUP_NLRI_HEADER_SIZE;
        parse_mup_route_type_data(buf, route_type, rt_data, rt_offset, ipv6);

        buf.end_container(obj_idx);

        pos += total;
    }
}

/// Parses route-type-specific data for MUP NLRI entries.
///
/// draft-ietf-bess-mup-safi-01, Sections 3.1–3.5
fn parse_mup_route_type_data<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    route_type: u16,
    data: &'pkt [u8],
    offset: usize,
    ipv6: bool,
) {
    // All route types start with an 8-byte RD (RFC 4364).
    if data.len() < 8 {
        if !data.is_empty() {
            buf.push_field(
                &MUP_NLRI_CHILDREN[FD_MUP_VALUE],
                FieldValue::Bytes(data),
                offset..offset + data.len(),
            );
        }
        return;
    }

    buf.push_field(
        &MUP_NLRI_CHILDREN[FD_MUP_RD],
        FieldValue::Bytes(&data[..8]),
        offset..offset + 8,
    );

    let rest = &data[8..];
    let rest_offset = offset + 8;

    match route_type {
        // Route Type 1: Interwork Segment Discovery
        1 => {
            if rest.is_empty() {
                return;
            }
            let prefix_len = rest[0] as usize;
            let prefix_bytes = prefix_len.div_ceil(8);
            if 1 + prefix_bytes > rest.len() {
                return;
            }
            let prefix_descriptor = if ipv6 {
                &PREFIX_ENTRY_IPV6_DESCRIPTOR
            } else {
                &PREFIX_ENTRY_IPV4_DESCRIPTOR
            };
            buf.push_field(
                prefix_descriptor,
                FieldValue::Bytes(&rest[..1 + prefix_bytes]),
                rest_offset..rest_offset + 1 + prefix_bytes,
            );
        }
        // Route Type 2: Direct Segment Discovery
        2 => {
            let addr_len = if ipv6 { 16 } else { 4 };
            if rest.len() < addr_len {
                return;
            }
            if ipv6 {
                let addr = read_ipv6_addr(rest, 0).unwrap_or_default();
                buf.push_field(
                    &MUP_NLRI_CHILDREN[FD_MUP_ADDRESS],
                    FieldValue::Ipv6Addr(addr),
                    rest_offset..rest_offset + 16,
                );
            } else {
                buf.push_field(
                    &MUP_NLRI_CHILDREN[FD_MUP_ADDRESS],
                    FieldValue::Ipv4Addr([rest[0], rest[1], rest[2], rest[3]]),
                    rest_offset..rest_offset + 4,
                );
            }
        }
        // Route Type 3: Type 1 Session Transformed (ST) — 3GPP 5G
        3 => {
            if rest.is_empty() {
                return;
            }
            let prefix_len = rest[0] as usize;
            let prefix_bytes = prefix_len.div_ceil(8);
            if 1 + prefix_bytes > rest.len() {
                return;
            }
            let prefix_descriptor = if ipv6 {
                &PREFIX_ENTRY_IPV6_DESCRIPTOR
            } else {
                &PREFIX_ENTRY_IPV4_DESCRIPTOR
            };
            buf.push_field(
                prefix_descriptor,
                FieldValue::Bytes(&rest[..1 + prefix_bytes]),
                rest_offset..rest_offset + 1 + prefix_bytes,
            );

            // 3GPP 5G architecture-specific fields
            let arch_start = 1 + prefix_bytes;
            let arch_data = &rest[arch_start..];
            let arch_offset = rest_offset + arch_start;
            // TEID (4) + QFI (1) + Endpoint Address Length (1) = minimum 6
            if arch_data.len() >= 6 {
                buf.push_field(
                    &MUP_NLRI_CHILDREN[FD_MUP_TEID],
                    FieldValue::Bytes(&arch_data[..4]),
                    arch_offset..arch_offset + 4,
                );
                buf.push_field(
                    &MUP_NLRI_CHILDREN[FD_MUP_QFI],
                    FieldValue::U8(arch_data[4]),
                    arch_offset + 4..arch_offset + 5,
                );

                let ep_addr_bits = arch_data[5] as usize;
                let ep_addr_bytes = ep_addr_bits / 8;
                let ep_start = 6;
                if ep_start + ep_addr_bytes <= arch_data.len() {
                    let ep_val = format_address(
                        &arch_data[ep_start..ep_start + ep_addr_bytes],
                        ep_addr_bits == 128,
                    );
                    buf.push_field(
                        &MUP_NLRI_CHILDREN[FD_MUP_ENDPOINT_ADDRESS],
                        ep_val,
                        arch_offset + ep_start..arch_offset + ep_start + ep_addr_bytes,
                    );

                    // Optional Source Address, followed by optional TLVs (Section 3.1.5)
                    let src_start = ep_start + ep_addr_bytes;
                    let mut tlv_start = src_start;
                    if src_start < arch_data.len() {
                        let src_addr_bits = arch_data[src_start] as usize;
                        tlv_start = src_start + 1;
                        if src_addr_bits > 0 {
                            let src_addr_bytes = src_addr_bits / 8;
                            let src_data_start = src_start + 1;
                            if src_data_start + src_addr_bytes <= arch_data.len() {
                                let src_val = format_address(
                                    &arch_data[src_data_start..src_data_start + src_addr_bytes],
                                    src_addr_bits == 128,
                                );
                                buf.push_field(
                                    &MUP_NLRI_CHILDREN[FD_MUP_SOURCE_ADDRESS],
                                    src_val,
                                    arch_offset + src_data_start
                                        ..arch_offset + src_data_start + src_addr_bytes,
                                );
                                tlv_start = src_data_start + src_addr_bytes;
                            }
                        }
                    }
                    if tlv_start < arch_data.len() {
                        parse_mup_st_tlvs(buf, &arch_data[tlv_start..], arch_offset + tlv_start);
                    }
                }
            }
        }
        // Route Type 4: Type 2 Session Transformed (ST)
        4 => {
            if rest.is_empty() {
                return;
            }
            let ep_len_bits = rest[0] as usize;
            // Endpoint Length covers the fixed-size Endpoint Address (32 bits for IPv4,
            // 128 for IPv6) plus the variable-length (0-4 octet) architecture-specific
            // TEID that follows it.
            let ep_total_bytes = ep_len_bits.div_ceil(8);
            if 1 + ep_total_bytes > rest.len() {
                return;
            }
            let addr_bits = if ipv6 { 128 } else { 32 };
            let addr_bytes = addr_bits / 8;
            if addr_bytes <= rest.len().saturating_sub(1) {
                let addr_val = format_address(&rest[1..1 + addr_bytes], ipv6);
                buf.push_field(
                    &MUP_NLRI_CHILDREN[FD_MUP_ENDPOINT_ADDRESS],
                    addr_val,
                    rest_offset + 1..rest_offset + 1 + addr_bytes,
                );

                let teid_start = 1 + addr_bytes;
                let teid_bits = ep_len_bits.saturating_sub(addr_bits);
                let teid_bytes = teid_bits.div_ceil(8).min(4);
                if teid_bytes > 0 && teid_start + teid_bytes <= rest.len() {
                    buf.push_field(
                        &MUP_NLRI_CHILDREN[FD_MUP_TEID],
                        FieldValue::Bytes(&rest[teid_start..teid_start + teid_bytes]),
                        rest_offset + teid_start..rest_offset + teid_start + teid_bytes,
                    );
                }
            }
            // Optional TLVs follow the full endpoint block (Section 3.1.5). Use
            // ep_total_bytes (derived directly from the wire Endpoint Length field,
            // and already bounds-checked above) as the authoritative boundary so a
            // malformed/oversized declared TEID length can't cause TLV parsing to
            // start inside the endpoint blob.
            let ep_end = 1 + ep_total_bytes;
            if ep_end < rest.len() {
                parse_mup_st_tlvs(buf, &rest[ep_end..], rest_offset + ep_end);
            }
        }
        _ => {
            if !rest.is_empty() {
                buf.push_field(
                    &MUP_NLRI_CHILDREN[FD_MUP_VALUE],
                    FieldValue::Bytes(rest),
                    rest_offset..rest_offset + rest.len(),
                );
            }
        }
    }
}

/// Parses trailing TLVs on ST routes into the `tlvs` array.
///
/// draft-ietf-bess-mup-safi-01, Section 3.1.5 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
///
/// Each TLV: 1-byte Type + 1-byte Length + variable Value. Unknown types (or a value that
/// doesn't match the type's expected length) are stored as raw bytes rather than rejected.
fn parse_mup_st_tlvs<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], base_offset: usize) {
    let array_idx = buf.begin_container(
        &MUP_NLRI_CHILDREN[FD_MUP_TLVS],
        FieldValue::Array(0..0),
        base_offset..base_offset + data.len(),
    );
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let tlv_type = data[pos];
        let tlv_len = data[pos + 1] as usize;
        let abs = base_offset + pos;

        if pos + 2 + tlv_len > data.len() {
            break;
        }

        let value = &data[pos + 2..pos + 2 + tlv_len];
        let total = 2 + tlv_len;
        let obj_idx = buf.begin_container(
            &MUP_ST_TLV_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + total,
        );

        buf.push_field(
            &MUP_ST_TLV_CHILDREN[FD_MUP_TLV_TYPE],
            FieldValue::U8(tlv_type),
            abs..abs + 1,
        );
        buf.push_field(
            &MUP_ST_TLV_CHILDREN[FD_MUP_TLV_LENGTH],
            FieldValue::U8(tlv_len as u8),
            abs + 1..abs + 2,
        );

        let value_offset = abs + 2;
        match (tlv_type, value.len()) {
            // 3gpp-5g Session Parameters TLV: TEID (4) + QFI (1)
            (1, 5) => {
                buf.push_field(
                    &MUP_ST_TLV_CHILDREN[FD_MUP_TLV_TEID],
                    FieldValue::Bytes(&value[..4]),
                    value_offset..value_offset + 4,
                );
                buf.push_field(
                    &MUP_ST_TLV_CHILDREN[FD_MUP_TLV_QFI],
                    FieldValue::U8(value[4]),
                    value_offset + 4..value_offset + 5,
                );
            }
            // Interwork Endpoint TLV / Source Address TLV: IPv4 or IPv6 address
            (2 | 3, 4 | 16) => {
                let addr_val = format_address(value, value.len() == 16);
                buf.push_field(
                    &MUP_ST_TLV_CHILDREN[FD_MUP_TLV_ADDRESS],
                    addr_val,
                    value_offset..value_offset + value.len(),
                );
            }
            _ => {
                if !value.is_empty() {
                    buf.push_field(
                        &MUP_ST_TLV_CHILDREN[FD_MUP_TLV_VALUE],
                        FieldValue::Bytes(value),
                        value_offset..value_offset + value.len(),
                    );
                }
            }
        }

        buf.end_container(obj_idx);
        pos += total;
    }

    buf.end_container(array_idx);
}

/// Writes a BGP IPv4 NLRI prefix as a JSON-quoted CIDR string (e.g., `"192.168.1.0/24"`).
///
/// The raw bytes are `[prefix_len_bits, prefix_octets...]` per RFC 4271, Section 4.3.
/// Missing octets are zero-filled to produce a full dotted-quad address.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
fn format_nlri_ipv4_prefix(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) => *b,
        _ => return w.write_all(b"\"\""),
    };
    if bytes.is_empty() {
        return w.write_all(b"\"\"");
    }
    let prefix_len = bytes[0];
    let mut octets = [0u8; 4];
    let available = (bytes.len() - 1).min(4);
    octets[..available].copy_from_slice(&bytes[1..1 + available]);
    write!(
        w,
        "\"{}.{}.{}.{}/{}\"",
        octets[0], octets[1], octets[2], octets[3], prefix_len
    )
}

/// Writes a BGP IPv6 NLRI prefix as a JSON-quoted CIDR string (e.g., `"2001:db8::/32"`).
///
/// The raw bytes are `[prefix_len_bits, prefix_octets...]` per RFC 4760, Section 3.
/// Missing octets are zero-filled and the address is formatted per RFC 5952.
///
/// RFC 4760, Section 3 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
fn format_nlri_ipv6_prefix(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) => *b,
        _ => return w.write_all(b"\"\""),
    };
    if bytes.is_empty() {
        return w.write_all(b"\"\"");
    }
    let prefix_len = bytes[0];
    let mut addr = [0u8; 16];
    let available = (bytes.len() - 1).min(16);
    addr[..available].copy_from_slice(&bytes[1..1 + available]);
    // Use FieldValue::Ipv6Addr Display which formats per RFC 5952.
    write!(w, "\"{}/{}\"", FieldValue::Ipv6Addr(addr), prefix_len)
}

/// Formats an address as IPv4 or IPv6 FieldValue.
fn format_address(data: &[u8], ipv6: bool) -> FieldValue<'_> {
    if ipv6 && data.len() == 16 {
        FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default())
    } else if !ipv6 && data.len() == 4 {
        FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default())
    } else {
        FieldValue::Bytes(data)
    }
}

/// Writes a BGP AGGREGATOR / AS4_AGGREGATOR value as `"<AS> <IPv4>"`.
///
/// Accepts 6 bytes (2-byte AS + 4-byte IPv4) or 8 bytes (4-byte AS + 4-byte IPv4).
///
/// RFC 4271, Section 5.1.7 — <https://www.rfc-editor.org/rfc/rfc4271#section-5.1.7>
/// RFC 6793, Section 7 — <https://www.rfc-editor.org/rfc/rfc6793#section-7>
fn format_aggregator(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) => *b,
        _ => return w.write_all(b"\"\""),
    };
    match bytes.len() {
        6 => {
            let asn = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
            write!(
                w,
                "\"{} {}.{}.{}.{}\"",
                asn, bytes[2], bytes[3], bytes[4], bytes[5]
            )
        }
        8 => {
            let asn = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            write!(
                w,
                "\"{} {}.{}.{}.{}\"",
                asn, bytes[4], bytes[5], bytes[6], bytes[7]
            )
        }
        _ => w.write_all(b"\"\""),
    }
}

/// Writes the Global Administrator : Local Administrator portion (bytes 2..8) of an
/// RFC 4360/RFC 5668-style Extended Community.
///
/// `kind`: 0 = 2-Octet AS Specific, 1 = IPv4 Address Specific, 2 = 4-Octet AS Specific.
fn write_ext_community_admin_value(
    kind: u8,
    bytes: &[u8],
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match kind {
        // 2-Octet AS Specific
        0 => {
            let asn = u16::from_be_bytes([bytes[2], bytes[3]]) as u32;
            let val = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            write!(w, "\"{}:{}\"", asn, val)
        }
        // IPv4 Address Specific
        1 => {
            let val = u16::from_be_bytes([bytes[6], bytes[7]]);
            write!(
                w,
                "\"{}.{}.{}.{}:{}\"",
                bytes[2], bytes[3], bytes[4], bytes[5], val
            )
        }
        // 4-Octet AS Specific
        _ => {
            let asn = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            let val = u16::from_be_bytes([bytes[6], bytes[7]]);
            write!(w, "\"{}:{}\"", asn, val)
        }
    }
}

/// Writes an Extended Community's raw bytes as a `"0x..."` hex string.
fn write_ext_community_hex(bytes: &[u8], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    write!(w, "\"0x")?;
    for b in bytes {
        write!(w, "{b:02x}")?;
    }
    write!(w, "\"")
}

/// Writes a BGP Extended Community as a human-readable string.
///
/// 8-byte value: Type (1) + Sub-Type (1) + Value (6).
/// - Type 0x00/0x40: 2-Octet AS — `"<AS>:<value>"`
/// - Type 0x01/0x41: IPv4 Address — `"<IPv4>:<value>"`
/// - Type 0x02/0x42: 4-Octet AS — `"<AS>:<value>"`
/// - Type 0x0C (MUP): Sub-Type selects 2-Octet AS / IPv4 Address / 4-Octet AS Specific
///   formatting for both Direct Segment (0x00-0x02) and Interwork Segment (0x03-0x05).
/// - Other types: hex representation.
///
/// RFC 4360, Section 3 — <https://www.rfc-editor.org/rfc/rfc4360#section-3>
/// draft-ietf-bess-mup-safi-01, Section 3.2 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
fn format_ext_community(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) if b.len() == 8 => *b,
        _ => return w.write_all(b"\"\""),
    };
    let type_high = bytes[0];
    match type_high {
        0x00 | 0x40 => write_ext_community_admin_value(0, bytes, w),
        0x01 | 0x41 => write_ext_community_admin_value(1, bytes, w),
        0x02 | 0x42 => write_ext_community_admin_value(2, bytes, w),
        0x0C => match bytes[1] {
            0x00 | 0x03 => write_ext_community_admin_value(0, bytes, w),
            0x01 | 0x04 => write_ext_community_admin_value(1, bytes, w),
            0x02 | 0x05 => write_ext_community_admin_value(2, bytes, w),
            _ => write_ext_community_hex(bytes, w),
        },
        _ => write_ext_community_hex(bytes, w),
    }
}

/// Writes a BGP Large Community as `"<global>:<local1>:<local2>"`.
///
/// 12-byte value: Global Administrator (u32) : Local Data 1 (u32) : Local Data 2 (u32).
///
/// RFC 8092, Section 2 — <https://www.rfc-editor.org/rfc/rfc8092#section-2>
fn format_large_community(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) if b.len() == 12 => *b,
        _ => return w.write_all(b"\"\""),
    };
    let global = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let local1 = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let local2 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    write!(w, "\"{}:{}:{}\"", global, local1, local2)
}

/// Writes a Route Distinguisher as `"<type>:<admin>:<assigned>"`.
///
/// 8-byte value: Type (u16 BE) + admin/assigned fields.
/// - Type 0: 2-byte ASN + 4-byte assigned → `"0:<ASN>:<assigned>"`
/// - Type 1: 4-byte IPv4 + 2-byte assigned → `"1:<IPv4>:<assigned>"`
/// - Type 2: 4-byte ASN + 2-byte assigned → `"2:<ASN>:<assigned>"`
///
/// RFC 4364, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc4364#section-4.2>
fn format_route_distinguisher(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) if b.len() == 8 => *b,
        _ => return w.write_all(b"\"\""),
    };
    let rd_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    match rd_type {
        0 => {
            let asn = u16::from_be_bytes([bytes[2], bytes[3]]) as u32;
            let val = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            write!(w, "\"0:{}:{}\"", asn, val)
        }
        1 => {
            let val = u16::from_be_bytes([bytes[6], bytes[7]]);
            write!(
                w,
                "\"1:{}.{}.{}.{}:{}\"",
                bytes[2], bytes[3], bytes[4], bytes[5], val
            )
        }
        2 => {
            let asn = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            let val = u16::from_be_bytes([bytes[6], bytes[7]]);
            write!(w, "\"2:{}:{}\"", asn, val)
        }
        _ => {
            write!(w, "\"{rd_type}:0x")?;
            for b in &bytes[2..] {
                write!(w, "{b:02x}")?;
            }
            write!(w, "\"")
        }
    }
}

/// Writes a GTP TEID as a hex string (e.g., `"0x12345678"`).
///
/// 4-byte big-endian unsigned integer.
fn format_teid(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) if b.len() == 4 => *b,
        _ => return w.write_all(b"\"\""),
    };
    let val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    write!(w, "\"0x{val:08x}\"")
}

/// Parses MP_REACH_NLRI attribute value.
///
/// RFC 4760, Section 3 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
fn parse_mp_reach_nlri<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let afi = read_be_u16(data, 0).unwrap_or_default();
    let safi = data[2];
    let nh_len = data[3] as usize;

    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(
        &MP_CHILDREN[FD_MP_AFI],
        FieldValue::U16(afi),
        offset..offset + 2,
    );
    buf.push_field(
        &MP_CHILDREN[FD_MP_SAFI],
        FieldValue::U8(safi),
        offset + 2..offset + 3,
    );

    let nh_start = 4;
    let nh_end = nh_start + nh_len;
    if nh_end > data.len() {
        buf.end_container(obj_idx);
        return;
    }

    // Parse Next Hop based on AFI
    let nh_data = &data[nh_start..nh_end];
    if afi == 1 && nh_len == 4 {
        // IPv4 Next Hop
        buf.push_field(
            &MP_CHILDREN[FD_MP_NEXT_HOP],
            FieldValue::Ipv4Addr([nh_data[0], nh_data[1], nh_data[2], nh_data[3]]),
            offset + nh_start..offset + nh_end,
        );
    } else if afi == 2 && (nh_len == 16 || nh_len == 32) {
        // IPv6 Next Hop (16 bytes global, or 32 bytes global + link-local)
        let addr = read_ipv6_addr(nh_data, 0).unwrap_or_default();
        buf.push_field(
            &MP_CHILDREN[FD_MP_NEXT_HOP],
            FieldValue::Ipv6Addr(addr),
            offset + nh_start..offset + nh_start + 16,
        );
        if nh_len == 32 {
            let ll_addr = read_ipv6_addr(nh_data, 16).unwrap_or_default();
            buf.push_field(
                &MP_CHILDREN[FD_MP_NEXT_HOP_LINK_LOCAL],
                FieldValue::Ipv6Addr(ll_addr),
                offset + nh_start + 16..offset + nh_end,
            );
        }
    } else {
        buf.push_field(
            &MP_CHILDREN[FD_MP_NEXT_HOP],
            FieldValue::Bytes(nh_data),
            offset + nh_start..offset + nh_end,
        );
    }

    // Skip Reserved byte
    let nlri_start = nh_end + 1;
    if nlri_start < data.len() {
        let nlri_data = &data[nlri_start..];
        let is_mup = safi == SAFI_MUP;
        let is_ip = afi == 1 || afi == 2;
        if is_mup || is_ip {
            let array_idx = buf.begin_container(
                &MP_CHILDREN[FD_MP_NLRI],
                FieldValue::Array(0..0),
                offset + nlri_start..offset + data.len(),
            );
            let before = buf.field_count();
            if is_mup {
                parse_mup_nlri(buf, nlri_data, offset + nlri_start, afi == 2);
            } else {
                parse_prefixes(buf, nlri_data, offset + nlri_start, afi == 2);
            }
            if buf.field_count() == before {
                buf.pop_field(); // remove empty array placeholder
            } else {
                buf.end_container(array_idx);
            }
        }
    }

    buf.end_container(obj_idx);
}

/// Parses MP_UNREACH_NLRI attribute value.
///
/// RFC 4760, Section 4 — <https://www.rfc-editor.org/rfc/rfc4760#section-4>
fn parse_mp_unreach_nlri<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let afi = read_be_u16(data, 0).unwrap_or_default();
    let safi = data[2];

    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );

    buf.push_field(
        &MP_CHILDREN[FD_MP_AFI],
        FieldValue::U16(afi),
        offset..offset + 2,
    );
    buf.push_field(
        &MP_CHILDREN[FD_MP_SAFI],
        FieldValue::U8(safi),
        offset + 2..offset + 3,
    );

    let wr_start = 3;
    if wr_start < data.len() {
        let wr_data = &data[wr_start..];
        let is_mup = safi == SAFI_MUP;
        let is_ip = afi == 1 || afi == 2;
        if is_mup || is_ip {
            let array_idx = buf.begin_container(
                &MP_CHILDREN[FD_MP_WITHDRAWN_ROUTES],
                FieldValue::Array(0..0),
                offset + wr_start..offset + data.len(),
            );
            let before = buf.field_count();
            if is_mup {
                parse_mup_nlri(buf, wr_data, offset + wr_start, afi == 2);
            } else {
                parse_prefixes(buf, wr_data, offset + wr_start, afi == 2);
            }
            if buf.field_count() == before {
                buf.pop_field(); // remove empty array placeholder
            } else {
                buf.end_container(array_idx);
            }
        }
    }

    buf.end_container(obj_idx);
}

/// Parses UPDATE message body and appends fields.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
fn parse_update<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> Result<(), PacketError> {
    if data.len() < MIN_UPDATE_SIZE {
        return Err(PacketError::Truncated {
            expected: MIN_UPDATE_SIZE,
            actual: data.len(),
        });
    }

    let withdrawn_len = read_be_u16(data, 19)? as usize;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_WITHDRAWN_ROUTES_LENGTH],
        FieldValue::U16(withdrawn_len as u16),
        offset + 19..offset + 21,
    );

    let wr_start = 21;
    let wr_end = wr_start + withdrawn_len;

    if data.len() < wr_end + 2 {
        return Err(PacketError::Truncated {
            expected: wr_end + 2,
            actual: data.len(),
        });
    }

    // Parse withdrawn routes
    if withdrawn_len > 0 {
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_WITHDRAWN_ROUTES],
            FieldValue::Array(0..0),
            offset + wr_start..offset + wr_end,
        );
        let before = buf.field_count();
        parse_prefixes(buf, &data[wr_start..wr_end], offset + wr_start, false);
        if buf.field_count() == before {
            buf.pop_field();
        } else {
            buf.end_container(array_idx);
        }
    }

    let path_attr_len = read_be_u16(data, wr_end)? as usize;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TOTAL_PATH_ATTRIBUTE_LENGTH],
        FieldValue::U16(path_attr_len as u16),
        offset + wr_end..offset + wr_end + 2,
    );

    let pa_start = wr_end + 2;
    let pa_end = pa_start + path_attr_len;

    if data.len() < pa_end {
        return Err(PacketError::Truncated {
            expected: pa_end,
            actual: data.len(),
        });
    }

    // Parse path attributes
    if path_attr_len > 0 {
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_PATH_ATTRIBUTES],
            FieldValue::Array(0..0),
            offset + pa_start..offset + pa_end,
        );
        let before = buf.field_count();
        let mut pos = 0;
        let attr_data = &data[pa_start..pa_end];
        while pos < attr_data.len() {
            if let Some(consumed) =
                parse_path_attribute(buf, &attr_data[pos..], offset + pa_start + pos)
            {
                pos += consumed;
            } else {
                break;
            }
        }
        if buf.field_count() == before {
            buf.pop_field();
        } else {
            buf.end_container(array_idx);
        }
    }

    // Parse NLRI (remaining bytes after path attributes)
    let nlri_start = pa_end;
    let nlri_end = data.len();
    if nlri_start < nlri_end {
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_NLRI],
            FieldValue::Array(0..0),
            offset + nlri_start..offset + nlri_end,
        );
        let before = buf.field_count();
        parse_prefixes(buf, &data[nlri_start..nlri_end], offset + nlri_start, false);
        if buf.field_count() == before {
            buf.pop_field();
        } else {
            buf.end_container(array_idx);
        }
    }

    Ok(())
}

/// Object descriptor for capability entries inside `optional_parameters`.
static OPT_PARAM_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("capability", "Capability", FieldType::Object)
        .with_children(OPT_PARAM_CHILDREN);

/// Object descriptor for path attribute entries inside `path_attributes`.
static PATH_ATTR_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("path_attribute", "Path Attribute", FieldType::Object)
        .with_children(PATH_ATTR_CHILDREN);

/// Descriptor for IPv4 prefix entries with CIDR format (e.g., `"192.168.1.0/24"`).
///
/// Raw bytes: `[prefix_len_bits, prefix_octets...]` per RFC 4271, Section 4.3.
static PREFIX_ENTRY_IPV4_DESCRIPTOR: FieldDescriptor = PREFIX_ENTRY_IPV4_FIELD;

/// Const form of [`PREFIX_ENTRY_IPV4_DESCRIPTOR`], for use in child descriptor lists.
const PREFIX_ENTRY_IPV4_FIELD: FieldDescriptor =
    FieldDescriptor::new("prefix", "Prefix", FieldType::Bytes)
        .with_format_fn(format_nlri_ipv4_prefix);

/// Descriptor for IPv6 prefix entries with CIDR format (e.g., `"2001:db8::/32"`).
///
/// Raw bytes: `[prefix_len_bits, prefix_octets...]` per RFC 4760, Section 3.
static PREFIX_ENTRY_IPV6_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("prefix", "Prefix", FieldType::Bytes)
        .with_format_fn(format_nlri_ipv6_prefix);

/// Schema entry for the RFC 7911 ADD-PATH Path Identifier of an NLRI entry.
///
/// Present only when the NLRI block was detected as ADD-PATH encoded, hence
/// optional.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
const PATH_ID_FIELD: FieldDescriptor =
    FieldDescriptor::new("path_id", "Path Identifier", FieldType::U32).optional();

/// Schema entry for the prefix inside an NLRI entry object.
///
/// The `format_fn` renders the CIDR string. The address-family specific runtime
/// descriptors ([`PREFIX_ENTRY_IPV4_DESCRIPTOR`] / [`PREFIX_ENTRY_IPV6_DESCRIPTOR`])
/// are what actually serialise a value; this entry only advertises the field in
/// the schema, so the IPv4 formatter stands in for both families.
const NLRI_PREFIX_FIELD: FieldDescriptor = PREFIX_ENTRY_IPV4_FIELD.optional();

/// Field descriptor index for [`IP_NLRI_ENTRY_CHILDREN`] (index 1 is `prefix`,
/// pushed through the address-family specific `PREFIX_ENTRY_*` descriptors).
const FD_NLRI_PATH_ID: usize = 0;

/// Child field descriptors for plain IPv4/IPv6 NLRI entry objects.
///
/// Each entry of a `nlri` / `withdrawn_routes` array is an object
/// `{ "prefix": "10.0.0.0/24" }`, gaining a leading `path_id` when the block is
/// ADD-PATH encoded.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
const IP_NLRI_ENTRY_FIELDS: [FieldDescriptor; 2] = [PATH_ID_FIELD, NLRI_PREFIX_FIELD];

/// Slice form of [`IP_NLRI_ENTRY_FIELDS`].
static IP_NLRI_ENTRY_CHILDREN: &[FieldDescriptor] = &IP_NLRI_ENTRY_FIELDS;

/// Object descriptor for NLRI / withdrawn route entries.
static NLRI_ENTRY_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("nlri_entry", "NLRI Entry", FieldType::Object)
        .with_children(IP_NLRI_ENTRY_CHILDREN);

/// Union of every field that can appear in an NLRI entry object inside an
/// MP_REACH_NLRI / MP_UNREACH_NLRI attribute value.
///
/// The element shape depends on the SAFI: SAFI 85 (BGP-MUP) yields MUP entries,
/// every other supported SAFI yields plain prefix entries. All fields are
/// therefore optional.
///
/// RFC 4760 — <https://www.rfc-editor.org/rfc/rfc4760>
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
/// draft-ietf-bess-mup-safi-01 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
const NLRI_ENTRY_FIELDS: [FieldDescriptor; 12] = [
    PATH_ID_FIELD,
    NLRI_PREFIX_FIELD,
    // MUP NLRI entry fields (`path_id` and `prefix` are already listed above).
    MUP_NLRI_FIELDS[FD_MUP_ARCH_TYPE].optional(),
    MUP_NLRI_FIELDS[FD_MUP_ROUTE_TYPE].optional(),
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
    MUP_NLRI_FIELDS[FD_MUP_RD],
    MUP_NLRI_FIELDS[FD_MUP_ADDRESS],
    MUP_NLRI_FIELDS[FD_MUP_TEID],
    MUP_NLRI_FIELDS[FD_MUP_QFI],
    MUP_NLRI_FIELDS[FD_MUP_ENDPOINT_ADDRESS],
    MUP_NLRI_FIELDS[FD_MUP_SOURCE_ADDRESS],
    MUP_NLRI_FIELDS[FD_MUP_TLVS],
];

/// Object descriptor for AS_PATH segment entries.
static AS_PATH_SEG_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("segment", "Segment", FieldType::Object)
        .with_children(AS_PATH_SEG_CHILDREN);

/// Descriptor for AS number entries inside AS_PATH segments.
static AS_NUMBER_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("asn", "AS Number", FieldType::U32);

/// Descriptor for community entries (U32 raw value).
static COMMUNITY_ENTRY_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("community", "Community", FieldType::U32).with_display_fn(
        |v, _| match v {
            FieldValue::U32(c) => well_known_community_name(*c),
            _ => None,
        },
    );

/// Descriptor for cluster ID entries.
static CLUSTER_ID_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("cluster_id", "Cluster ID", FieldType::Ipv4Addr);

/// Descriptor for extended community entries (raw 8 bytes).
static EXT_COMMUNITY_ENTRY_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("ext_community", "Extended Community", FieldType::Bytes)
        .with_display_fn(|v, _| match v {
            FieldValue::Bytes(b) if b.len() >= 2 => extended_community_type_name(b[0], b[1]),
            _ => None,
        })
        .with_format_fn(format_ext_community);

/// Descriptor for large community entries (raw 12 bytes).
static LARGE_COMMUNITY_ENTRY_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("large_community", "Large Community", FieldType::Bytes)
        .with_format_fn(format_large_community);

/// Object descriptor for MUP NLRI entries.
static MUP_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("mup_entry", "MUP Entry", FieldType::Object)
        .with_children(MUP_NLRI_CHILDREN);

/// Object descriptor for Prefix-SID TLV entries.
static PREFIX_SID_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(PREFIX_SID_TLV_CHILDREN);

/// Object descriptor for SRGB entries.
static SRGB_ENTRY_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("srgb_entry", "SRGB Entry", FieldType::Object)
        .with_children(SRGB_ENTRY_CHILDREN);

/// Object descriptor for SRv6 SID Information Sub-TLV entries.
static SRV6_SID_INFO_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("sub_tlv", "Sub-TLV", FieldType::Object)
        .with_children(SRV6_SID_INFO_CHILDREN);

/// Field descriptor indices for [`NON_CAP_PARAM_CHILDREN`].
const FD_NCP_PARAM_TYPE: usize = 0;
const FD_NCP_VALUE: usize = 1;

/// Child field descriptors for non-capability optional parameter objects.
static NON_CAP_PARAM_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("param_type", "Parameter Type", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Field descriptor indices for [`AS_PATH_SEG_CHILDREN`].
const FD_APS_SEGMENT_TYPE: usize = 0;
const FD_APS_AS_NUMBERS: usize = 1;

/// Child field descriptors for AS_PATH segment objects.
const AS_PATH_SEG_FIELDS: [FieldDescriptor; 2] = [
    FieldDescriptor {
        name: "segment_type",
        display_name: "Segment Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => as_path_segment_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("as_numbers", "AS Numbers", FieldType::Array),
];

/// Slice form of [`AS_PATH_SEG_FIELDS`].
static AS_PATH_SEG_CHILDREN: &[FieldDescriptor] = &AS_PATH_SEG_FIELDS;

/// Field descriptor indices for [`MUP_NLRI_CHILDREN`].
const FD_MUP_PATH_ID: usize = 0;
const FD_MUP_ARCH_TYPE: usize = 1;
const FD_MUP_ROUTE_TYPE: usize = 2;
const FD_MUP_VALUE: usize = 3;
const FD_MUP_RD: usize = 4;
// Index 5 is `prefix`, pushed through the address-family specific
// `PREFIX_ENTRY_*` descriptors.
const FD_MUP_ADDRESS: usize = 6;
const FD_MUP_TEID: usize = 7;
const FD_MUP_QFI: usize = 8;
const FD_MUP_ENDPOINT_ADDRESS: usize = 9;
const FD_MUP_SOURCE_ADDRESS: usize = 10;
const FD_MUP_TLVS: usize = 11;

/// Child field descriptors for MUP NLRI entry objects.
///
/// The leading `path_id` is only emitted when the enclosing NLRI block is
/// RFC 7911 ADD-PATH encoded (RFC 7911, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc7911#section-3>).
const MUP_NLRI_FIELDS: [FieldDescriptor; 12] = [
    PATH_ID_FIELD,
    FieldDescriptor {
        name: "architecture_type",
        display_name: "Architecture Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(a) => mup_architecture_type_name(*a),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "route_type",
        display_name: "Route Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(r) => mup_route_type_name(*r),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("rd", "Route Distinguisher", FieldType::Bytes)
        .optional()
        .with_format_fn(format_route_distinguisher),
    NLRI_PREFIX_FIELD,
    FieldDescriptor::new("address", "Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("teid", "TEID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_teid),
    FieldDescriptor::new("qfi", "QFI", FieldType::U8).optional(),
    FieldDescriptor::new("endpoint_address", "Endpoint Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("source_address", "Source Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(&MUP_ST_TLV_FIELDS),
];

/// Slice form of [`MUP_NLRI_FIELDS`].
static MUP_NLRI_CHILDREN: &[FieldDescriptor] = &MUP_NLRI_FIELDS;

/// Field descriptor indices for [`MUP_ST_TLV_CHILDREN`].
const FD_MUP_TLV_TYPE: usize = 0;
const FD_MUP_TLV_LENGTH: usize = 1;
const FD_MUP_TLV_TEID: usize = 2;
const FD_MUP_TLV_QFI: usize = 3;
const FD_MUP_TLV_ADDRESS: usize = 4;
const FD_MUP_TLV_VALUE: usize = 5;

/// Child field descriptors for MUP ST Route TLV entries.
///
/// draft-ietf-bess-mup-safi-01, Section 3.1.5 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
const MUP_ST_TLV_FIELDS: [FieldDescriptor; 6] = [
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => mup_st_tlv_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("teid", "TEID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_teid),
    FieldDescriptor::new("qfi", "QFI", FieldType::U8).optional(),
    FieldDescriptor::new("address", "Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`MUP_ST_TLV_FIELDS`].
static MUP_ST_TLV_CHILDREN: &[FieldDescriptor] = &MUP_ST_TLV_FIELDS;

/// Object descriptor for MUP ST Route TLV entries.
static MUP_ST_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(MUP_ST_TLV_CHILDREN);

/// Field descriptor indices for [`PREFIX_SID_TLV_CHILDREN`].
const FD_PSID_TYPE: usize = 0;
const FD_PSID_LENGTH: usize = 1;
const FD_PSID_FLAGS: usize = 2;
const FD_PSID_LABEL_INDEX: usize = 3;
const FD_PSID_SRGB_ENTRIES: usize = 4;
const FD_PSID_SUB_TLVS: usize = 5;
const FD_PSID_VALUE: usize = 6;

/// Child field descriptors for TLVs inside BGP Prefix-SID attribute.
///
/// RFC 8669 — <https://www.rfc-editor.org/rfc/rfc8669>
/// RFC 9252 — <https://www.rfc-editor.org/rfc/rfc9252>
const PREFIX_SID_TLV_FIELDS: [FieldDescriptor; 7] = [
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("flags", "Flags", FieldType::U16).optional(),
    FieldDescriptor::new("label_index", "Label Index", FieldType::U32).optional(),
    FieldDescriptor::new("srgb_entries", "SRGB Entries", FieldType::Array)
        .optional()
        .with_children(&SRGB_ENTRY_FIELDS),
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&SRV6_SID_INFO_FIELDS),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`PREFIX_SID_TLV_FIELDS`].
static PREFIX_SID_TLV_CHILDREN: &[FieldDescriptor] = &PREFIX_SID_TLV_FIELDS;

/// Field descriptor indices for [`SRGB_ENTRY_CHILDREN`].
const FD_SRGB_BASE: usize = 0;
const FD_SRGB_RANGE: usize = 1;

/// Child field descriptors for SRGB entries in Originator SRGB TLV.
///
/// RFC 8669, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8669#section-3.2>
const SRGB_ENTRY_FIELDS: [FieldDescriptor; 2] = [
    FieldDescriptor::new("base", "SRGB Base", FieldType::U32),
    FieldDescriptor::new("range", "SRGB Range", FieldType::U32),
];

/// Slice form of [`SRGB_ENTRY_FIELDS`].
static SRGB_ENTRY_CHILDREN: &[FieldDescriptor] = &SRGB_ENTRY_FIELDS;

/// Field descriptor indices for [`SRV6_SID_INFO_CHILDREN`].
const FD_SRV6_SI_TYPE: usize = 0;
const FD_SRV6_SI_LENGTH: usize = 1;
const FD_SRV6_SI_SID: usize = 2;
const FD_SRV6_SI_FLAGS: usize = 3;
const FD_SRV6_SI_ENDPOINT_BEHAVIOR: usize = 4;
const FD_SRV6_SI_SID_STRUCTURE: usize = 5;
const FD_SRV6_SI_VALUE: usize = 6;

/// Child field descriptors for SRv6 SID Information Sub-TLV.
///
/// RFC 9252, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9252#section-3.1>
const SRV6_SID_INFO_FIELDS: [FieldDescriptor; 7] = [
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("srv6_sid", "SRv6 SID", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("sid_flags", "Service SID Flags", FieldType::U8).optional(),
    FieldDescriptor::new("endpoint_behavior", "Endpoint Behavior", FieldType::U16).optional(),
    FieldDescriptor::new("sid_structure", "SID Structure", FieldType::Object)
        .optional()
        .with_children(&SRV6_SID_STRUCTURE_FIELDS),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`SRV6_SID_INFO_FIELDS`].
static SRV6_SID_INFO_CHILDREN: &[FieldDescriptor] = &SRV6_SID_INFO_FIELDS;

/// Field descriptor indices for [`SRV6_SID_STRUCTURE_CHILDREN`].
const FD_SRV6_SS_LBL: usize = 0;
const FD_SRV6_SS_LNL: usize = 1;
const FD_SRV6_SS_FL: usize = 2;
const FD_SRV6_SS_AL: usize = 3;
const FD_SRV6_SS_TL: usize = 4;
const FD_SRV6_SS_TO: usize = 5;

/// Child field descriptors for SRv6 SID Structure Sub-Sub-TLV.
///
/// RFC 9252, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9252#section-3.2.1>
const SRV6_SID_STRUCTURE_FIELDS: [FieldDescriptor; 6] = [
    FieldDescriptor::new(
        "locator_block_length",
        "Locator Block Length",
        FieldType::U8,
    ),
    FieldDescriptor::new("locator_node_length", "Locator Node Length", FieldType::U8),
    FieldDescriptor::new("function_length", "Function Length", FieldType::U8),
    FieldDescriptor::new("argument_length", "Argument Length", FieldType::U8),
    FieldDescriptor::new(
        "transposition_length",
        "Transposition Length",
        FieldType::U8,
    ),
    FieldDescriptor::new(
        "transposition_offset",
        "Transposition Offset",
        FieldType::U8,
    ),
];

/// Slice form of [`SRV6_SID_STRUCTURE_FIELDS`].
static SRV6_SID_STRUCTURE_CHILDREN: &[FieldDescriptor] = &SRV6_SID_STRUCTURE_FIELDS;

/// Field descriptor indices for [`MP_CHILDREN`].
const FD_MP_AFI: usize = 0;
const FD_MP_SAFI: usize = 1;
const FD_MP_NEXT_HOP: usize = 2;
const FD_MP_NEXT_HOP_LINK_LOCAL: usize = 3;
const FD_MP_NLRI: usize = 4;
const FD_MP_WITHDRAWN_ROUTES: usize = 5;

/// Child field descriptors for MP_REACH_NLRI / MP_UNREACH_NLRI objects.
///
/// RFC 4760, Sections 3-4 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
const MP_FIELDS: [FieldDescriptor; 6] = [
    FieldDescriptor::new("afi", "AFI", FieldType::U16).with_display_fn(|v, _siblings| match v {
        FieldValue::U16(a) => afi_name(*a),
        _ => None,
    }),
    FieldDescriptor::new("safi", "SAFI", FieldType::U8).with_display_fn(|v, _siblings| match v {
        FieldValue::U8(s) => safi_name(*s),
        _ => None,
    }),
    FieldDescriptor::new("next_hop", "Next Hop", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "next_hop_link_local",
        "Next Hop Link-Local",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("nlri", "NLRI", FieldType::Array)
        .optional()
        .with_children(&NLRI_ENTRY_FIELDS),
    FieldDescriptor::new("withdrawn_routes", "Withdrawn Routes", FieldType::Array)
        .optional()
        .with_children(&NLRI_ENTRY_FIELDS),
];

/// Slice form of [`MP_FIELDS`].
static MP_CHILDREN: &[FieldDescriptor] = &MP_FIELDS;

/// Field descriptor indices for [`AFI_SAFI_CHILDREN`].
const FD_AS_AFI: usize = 0;
const FD_AS_SAFI: usize = 1;
const FD_AS_SEND_RECEIVE: usize = 2;
const FD_AS_PATHS_LIMIT: usize = 3;
const FD_AS_FLAGS: usize = 4;
const FD_AS_STALE_TIME: usize = 5;
const FD_AS_NEXT_HOP_AFI: usize = 6;

/// Shared child field descriptors for the elements of every `afi_safis`
/// array (ADD-PATH, PATHS-LIMIT, Graceful Restart, LLGR, Extended Next Hop
/// Encoding). `afi`/`safi` are common to all five; the rest are specific to
/// one or two of them and therefore optional, so `list_fields` sees a
/// single union of the possible shapes.
///
/// `safi` is always stored as [`FieldType::U16`] here — RFC 8950's Extended
/// Next Hop Encoding uses a genuine 2-octet SAFI, while the other four
/// capabilities use a 1-octet SAFI widened to `u16` for a uniform shape.
static AFI_SAFI_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("afi", "AFI", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(a) => afi_name(*a),
        _ => None,
    }),
    FieldDescriptor::new("safi", "SAFI", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(s) => u8::try_from(*s).ok().and_then(safi_name),
        _ => None,
    }),
    FieldDescriptor::new("send_receive", "Send/Receive", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(sr) => add_path_send_receive_name(*sr),
            _ => None,
        }),
    FieldDescriptor::new("paths_limit", "Paths Limit", FieldType::U16).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("stale_time", "Long-Lived Stale Time", FieldType::U32).optional(),
    FieldDescriptor::new("next_hop_afi", "Next Hop AFI", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(a) => afi_name(*a),
            _ => None,
        }),
];

/// Object descriptor for `afi_safis` array elements shared across the
/// capabilities listed on [`AFI_SAFI_CHILDREN`].
static AFI_SAFI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("afi_safi", "AFI/SAFI", FieldType::Object)
        .with_children(AFI_SAFI_CHILDREN);

/// Field descriptor indices for [`OPT_PARAM_CHILDREN`].
const FD_OPT_CODE: usize = 0;
const FD_OPT_LENGTH: usize = 1;
const FD_OPT_VALUE: usize = 2;
const FD_OPT_AFI: usize = 3;
const FD_OPT_SAFI: usize = 4;
const FD_OPT_ASN: usize = 5;
const FD_OPT_AFI_SAFIS: usize = 6;
const FD_OPT_RESTART_FLAGS: usize = 7;
const FD_OPT_RESTART_TIME: usize = 8;
const FD_OPT_ROLE: usize = 9;
const FD_OPT_HOSTNAME: usize = 10;
const FD_OPT_DOMAIN_NAME: usize = 11;
// Index 12 ("param_type") has no dedicated constant: it is only ever
// looked up by name (schema union member for non-capability optional
// parameters — see NON_CAP_PARAM_CHILDREN), never pushed through
// OPT_PARAM_CHILDREN at runtime.

/// Child field descriptors for objects inside `optional_parameters`.
///
/// This is a union of two element shapes: a capability object (`code`,
/// `length`, `value`, plus the well-known capabilities' decoded fields) and
/// a non-capability optional parameter (`param_type`, `value`) — see
/// [`NON_CAP_PARAM_CHILDREN`] for the descriptors actually pushed at
/// runtime for the latter. All fields beyond `code`/`length`/`param_type`
/// are optional since only one capability's decoded shape (if any) applies
/// to a given element.
static OPT_PARAM_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "Code", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(c) => capability_code_name(*c),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    // Multiprotocol Extensions (RFC 4760, Section 8).
    FieldDescriptor::new("afi", "AFI", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(a) => afi_name(*a),
            _ => None,
        }),
    FieldDescriptor::new("safi", "SAFI", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(s) => safi_name(*s),
            _ => None,
        }),
    // Support for 4-octet AS number capability (RFC 6793, Section 3).
    FieldDescriptor::new("asn", "AS Number", FieldType::U32).optional(),
    // ADD-PATH / PATHS-LIMIT / Graceful Restart / LLGR / Extended Next Hop
    // Encoding (see AFI_SAFI_CHILDREN doc comment).
    FieldDescriptor::new("afi_safis", "AFI/SAFIs", FieldType::Array)
        .optional()
        .with_children(AFI_SAFI_CHILDREN),
    // Graceful Restart (RFC 4724, Section 3).
    FieldDescriptor::new("restart_flags", "Restart Flags", FieldType::U8).optional(),
    FieldDescriptor::new("restart_time", "Restart Time", FieldType::U16).optional(),
    // BGP Role (RFC 9234, Section 4.1).
    FieldDescriptor::new("role", "Role", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(r) => role_name(*r),
            _ => None,
        }),
    // FQDN (draft-walton-bgp-hostname-capability-02, Section 3).
    FieldDescriptor::new("hostname", "Hostname", FieldType::Str).optional(),
    FieldDescriptor::new("domain_name", "Domain Name", FieldType::Str).optional(),
    // Non-capability optional parameter union member — see
    // NON_CAP_PARAM_CHILDREN.
    FieldDescriptor::new("param_type", "Parameter Type", FieldType::U8).optional(),
];

/// Field descriptor indices for [`PATH_ATTR_CHILDREN`].
const FD_PA_FLAGS: usize = 0;
const FD_PA_TYPE_CODE: usize = 1;
const FD_PA_ATTR_LENGTH: usize = 2;
const FD_PA_VALUE: usize = 3;

/// ORIGIN "value" field descriptor with display_fn for IGP/EGP/INCOMPLETE.
static FD_ORIGIN_VALUE: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(o) => origin_name(*o),
        _ => None,
    });

/// AGGREGATOR "value" field descriptor with format_fn for `"<AS> <IPv4>"`.
///
/// RFC 4271, Section 5.1.7 — <https://www.rfc-editor.org/rfc/rfc4271#section-5.1.7>
static FD_AGGREGATOR_VALUE: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes)
        .optional()
        .with_format_fn(format_aggregator);

/// AS4_AGGREGATOR "value" field descriptor with format_fn for `"<AS> <IPv4>"`.
///
/// RFC 6793, Section 7 — <https://www.rfc-editor.org/rfc/rfc6793#section-7>
static FD_AS4_AGGREGATOR_VALUE: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes)
        .optional()
        .with_format_fn(format_aggregator);

/// Child field descriptors for objects inside `path_attributes`.
static PATH_ATTR_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor {
        name: "type_code",
        display_name: "Type Code",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => path_attr_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("attr_length", "Attribute Length", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Any)
        .optional()
        .with_children(PATH_ATTR_VALUE_CHILDREN),
];

/// Union of every field that can appear inside a structured path attribute
/// `value`.
///
/// A path attribute `value` is [`FieldType::Any`]: its runtime shape is selected
/// by the sibling `type_code`. It is an Object for MP_REACH_NLRI /
/// MP_UNREACH_NLRI (RFC 4760), an Array of TLV objects for BGP Prefix-SID
/// (RFC 8669 / RFC 9252), an Array of segment objects for AS_PATH / AS4_PATH
/// (RFC 4271, Section 5.1.2), an Array of scalars for COMMUNITIES /
/// CLUSTER_LIST / EXTENDED COMMUNITIES / LARGE_COMMUNITY, a scalar for ORIGIN /
/// MULTI_EXIT_DISC / LOCAL_PREF, an IPv4 address for NEXT_HOP / ORIGINATOR_ID,
/// and raw bytes for unknown attributes.
///
/// This list is the union of the sub-fields of every *object* shape, so that a
/// schema walker can discover them. Every entry is optional because none of them
/// is present for all `type_code` values.
static PATH_ATTR_VALUE_CHILDREN: &[FieldDescriptor] = &[
    // MP_REACH_NLRI / MP_UNREACH_NLRI object fields (RFC 4760).
    MP_FIELDS[FD_MP_AFI].optional(),
    MP_FIELDS[FD_MP_SAFI].optional(),
    MP_FIELDS[FD_MP_NEXT_HOP],
    MP_FIELDS[FD_MP_NEXT_HOP_LINK_LOCAL],
    MP_FIELDS[FD_MP_NLRI],
    MP_FIELDS[FD_MP_WITHDRAWN_ROUTES],
    // BGP Prefix-SID TLV element fields (RFC 8669, RFC 9252).
    PREFIX_SID_TLV_FIELDS[FD_PSID_TYPE].optional(),
    PREFIX_SID_TLV_FIELDS[FD_PSID_LENGTH].optional(),
    PREFIX_SID_TLV_FIELDS[FD_PSID_FLAGS],
    PREFIX_SID_TLV_FIELDS[FD_PSID_LABEL_INDEX],
    PREFIX_SID_TLV_FIELDS[FD_PSID_SRGB_ENTRIES],
    PREFIX_SID_TLV_FIELDS[FD_PSID_SUB_TLVS],
    PREFIX_SID_TLV_FIELDS[FD_PSID_VALUE],
    // AS_PATH / AS4_PATH segment fields (RFC 4271, Section 5.1.2; RFC 6793).
    AS_PATH_SEG_FIELDS[FD_APS_SEGMENT_TYPE].optional(),
    AS_PATH_SEG_FIELDS[FD_APS_AS_NUMBERS].optional(),
];

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_MARKER: usize = 0;
const FD_LENGTH: usize = 1;
const FD_TYPE: usize = 2;
// OPEN fields (RFC 4271, Section 4.2; RFC 9072)
const FD_VERSION: usize = 3;
const FD_MY_AS: usize = 4;
const FD_HOLD_TIME: usize = 5;
const FD_BGP_IDENTIFIER: usize = 6;
const FD_OPT_PARAMS_LENGTH: usize = 7;
const FD_EXT_OPT_PARAMS_LENGTH: usize = 8;
const FD_OPTIONAL_PARAMETERS: usize = 9;
// NOTIFICATION fields (RFC 4271, Section 4.5)
const FD_ERROR_CODE: usize = 10;
const FD_ERROR_SUBCODE: usize = 11;
const FD_DATA: usize = 12;
// ROUTE-REFRESH fields (RFC 2918, RFC 7313)
const FD_AFI: usize = 13;
const FD_SAFI: usize = 14;
const FD_MESSAGE_SUBTYPE: usize = 15;
// UPDATE fields (RFC 4271, Section 4.3)
const FD_WITHDRAWN_ROUTES_LENGTH: usize = 16;
const FD_WITHDRAWN_ROUTES: usize = 17;
const FD_TOTAL_PATH_ATTRIBUTE_LENGTH: usize = 18;
const FD_PATH_ATTRIBUTES: usize = 19;
const FD_NLRI: usize = 20;

/// Field descriptors for the BGP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // Header fields (RFC 4271, Section 4.1)
    FieldDescriptor::new("marker", "Marker", FieldType::Bytes),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => msg_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    // OPEN fields (RFC 4271, Section 4.2)
    FieldDescriptor::new("version", "Version", FieldType::U8).optional(),
    FieldDescriptor::new("my_as", "My AS", FieldType::U16).optional(),
    FieldDescriptor::new("hold_time", "Hold Time", FieldType::U16).optional(),
    FieldDescriptor::new("bgp_identifier", "BGP Identifier", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new(
        "opt_params_length",
        "Optional Parameters Length",
        FieldType::U8,
    )
    .optional(),
    // RFC 9072 — Extended Optional Parameters Length (2 octets, only when
    // byte 29 of the OPEN message equals the 0xFF sentinel).
    FieldDescriptor::new(
        "ext_opt_params_length",
        "Extended Optional Parameters Length",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "optional_parameters",
        "Optional Parameters",
        FieldType::Array,
    )
    .optional()
    .with_children(OPT_PARAM_CHILDREN),
    // NOTIFICATION fields (RFC 4271, Section 4.5)
    FieldDescriptor {
        name: "error_code",
        display_name: "Error Code",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(c) => error_code_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 4486 / RFC 8203 — Cease subcode names. The lookup is conditional on
    // the sibling `error_code` being 6 (Cease); other error codes have their
    // own subcode tables that are not currently decoded.
    FieldDescriptor {
        name: "error_subcode",
        display_name: "Error Subcode",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, siblings| {
            let FieldValue::U8(subcode) = v else {
                return None;
            };
            let error_code = siblings
                .iter()
                .find(|f| f.name() == "error_code")
                .and_then(|f| f.value.as_u8())?;
            if error_code == 6 {
                cease_subcode_name(*subcode)
            } else {
                None
            }
        }),
        format_fn: None,
    },
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    // ROUTE-REFRESH fields (RFC 2918)
    FieldDescriptor {
        name: "afi",
        display_name: "AFI",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(a) => afi_name(*a),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "safi",
        display_name: "SAFI",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => safi_name(*s),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 7313, Section 4 — Enhanced Route Refresh Message Subtype
    FieldDescriptor {
        name: "message_subtype",
        display_name: "Message Subtype",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => route_refresh_subtype_name(*s),
            _ => None,
        }),
        format_fn: None,
    },
    // UPDATE fields (RFC 4271, Section 4.3)
    FieldDescriptor::new(
        "withdrawn_routes_length",
        "Withdrawn Routes Length",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("withdrawn_routes", "Withdrawn Routes", FieldType::Array)
        .optional()
        .with_children(IP_NLRI_ENTRY_CHILDREN),
    FieldDescriptor::new(
        "total_path_attribute_length",
        "Total Path Attribute Length",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("path_attributes", "Path Attributes", FieldType::Array)
        .optional()
        .with_children(PATH_ATTR_CHILDREN),
    FieldDescriptor::new("nlri", "NLRI", FieldType::Array)
        .optional()
        .with_children(IP_NLRI_ENTRY_CHILDREN),
];

/// Parses a single BGP message from the start of `data` and appends one layer.
/// Returns the number of bytes consumed.
///
/// RFC 4271, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.1>
fn dissect_one_message<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<usize, PacketError> {
    if data.len() < HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Validate marker (RFC 4271, Section 4.1).
    if data[..16] != MARKER {
        return Err(PacketError::InvalidHeader("BGP marker must be all 0xFF"));
    }

    let length = read_be_u16(data, 16)?;

    // RFC 4271, Section 4.1: Length must be >= 19 (header size) and <= 4096
    // (or 65535 with Extended Message, RFC 8654).
    if (length as usize) < HEADER_SIZE {
        return Err(PacketError::InvalidFieldValue {
            field: "length",
            value: length as u32,
        });
    }
    if length as usize > data.len() {
        return Err(PacketError::Truncated {
            expected: length as usize,
            actual: data.len(),
        });
    }

    let msg_type = data[18];
    let msg_len = length as usize;
    let msg_data = &data[..msg_len];
    let consumed = msg_data.len();

    buf.begin_layer("BGP", None, FIELD_DESCRIPTORS, offset..offset + consumed);

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MARKER],
        FieldValue::Bytes(&data[..16]),
        offset..offset + 16,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LENGTH],
        FieldValue::U16(length),
        offset + 16..offset + 18,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TYPE],
        FieldValue::U8(msg_type),
        offset + 18..offset + 19,
    );

    match msg_type {
        MSG_OPEN => parse_open(buf, msg_data, offset)?,
        MSG_UPDATE => parse_update(buf, msg_data, offset)?,
        MSG_NOTIFICATION => parse_notification(buf, msg_data, offset)?,
        MSG_ROUTE_REFRESH => parse_route_refresh(buf, msg_data, offset)?,
        _ => {}
    }

    buf.end_layer();

    Ok(consumed)
}

/// BGP-4 dissector.
pub struct BgpDissector;

impl Dissector for BgpDissector {
    fn name(&self) -> &'static str {
        "Border Gateway Protocol"
    }

    fn short_name(&self) -> &'static str {
        "BGP"
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
        let mut pos = 0;

        // A single TCP segment may carry multiple BGP messages back-to-back.
        // Parse each one as a separate BGP layer.
        while pos + HEADER_SIZE <= data.len() {
            let consumed = dissect_one_message(&data[pos..], buf, offset + pos)?;
            pos += consumed;
        }

        if pos == 0 {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        Ok(DissectResult::new(pos, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    fn nested_field_by_name<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a Field<'pkt> {
        buf.nested_fields(range)
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field '{}' not found", name))
    }

    /// Helper: collect only the *direct* children of an Array/Object
    /// container range, skipping over each child container's own
    /// descendants.
    ///
    /// `DissectBuffer::nested_fields` returns every field in the flat
    /// buffer within `range`, which — for a container whose children are
    /// themselves containers (e.g. an array of objects with their own
    /// nested array) — includes grandchildren too. This walks `range`
    /// one direct sibling at a time, jumping past a child's own range
    /// when it is itself an Array/Object.
    fn direct_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &core::ops::Range<u32>,
    ) -> Vec<&'a Field<'pkt>> {
        let mut out = Vec::new();
        let mut pos = range.start;
        while pos < range.end {
            let field = &buf.fields()[pos as usize];
            out.push(field);
            pos = match &field.value {
                FieldValue::Array(r) | FieldValue::Object(r) => r.end.max(pos + 1),
                _ => pos + 1,
            };
        }
        out
    }

    /// Build a minimal BGP KEEPALIVE message (19 bytes).
    fn build_keepalive() -> Vec<u8> {
        let mut raw = vec![0xFF; 16]; // Marker
        raw.extend_from_slice(&19u16.to_be_bytes()); // Length
        raw.push(4); // Type = KEEPALIVE
        raw
    }

    #[test]
    fn parse_bgp_keepalive() {
        let data = build_keepalive();
        let mut buf = DissectBuffer::new();
        let result = BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 19);
        assert!(matches!(result.next, DispatchHint::End));
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "BGP");
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U16(19)
        );
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("KEEPALIVE")
        );
    }

    /// Build a BGP OPEN message with no optional parameters.
    fn build_open_basic() -> Vec<u8> {
        let mut raw = vec![0xFF; 16]; // Marker
        raw.extend_from_slice(&29u16.to_be_bytes()); // Length = 29 (minimum OPEN)
        raw.push(1); // Type = OPEN
        raw.push(4); // Version = 4
        raw.extend_from_slice(&65001u16.to_be_bytes()); // My AS = 65001
        raw.extend_from_slice(&180u16.to_be_bytes()); // Hold Time = 180
        raw.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier = 10.0.0.1
        raw.push(0); // Opt Params Len = 0
        raw
    }

    /// Build a BGP OPEN message with capabilities.
    fn build_open_with_capabilities() -> Vec<u8> {
        // Capabilities: Multiprotocol Extensions (IPv4 Unicast) + 4-octet AS (65550)
        let cap_mp = [1, 4, 0, 1, 0, 1]; // code=1, len=4, AFI=1, res=0, SAFI=1
        let as4_bytes = 65582u32.to_be_bytes();
        let cap_as4 = [
            65,
            4,
            as4_bytes[0],
            as4_bytes[1],
            as4_bytes[2],
            as4_bytes[3],
        ];

        // Capability parameter: type=2, length=sum of capabilities
        let cap_param_len = cap_mp.len() + cap_as4.len();
        let opt_params_len = 2 + cap_param_len; // type(1) + len(1) + caps

        let total_len = 29 + opt_params_len;
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(1); // Type = OPEN
        raw.push(4); // Version
        raw.extend_from_slice(&65001u16.to_be_bytes()); // My AS
        raw.extend_from_slice(&180u16.to_be_bytes()); // Hold Time
        raw.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier
        raw.push(opt_params_len as u8); // Opt Params Len
        raw.push(2); // Param Type = Capability
        raw.push(cap_param_len as u8);
        raw.extend_from_slice(&cap_mp);
        raw.extend_from_slice(&cap_as4);
        raw
    }

    #[test]
    fn parse_bgp_open_basic() {
        let data = build_open_basic();
        let mut buf = DissectBuffer::new();
        let result = BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 29);
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "type_name"), Some("OPEN"));
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "my_as").unwrap().value,
            FieldValue::U16(65001)
        );
        assert_eq!(
            buf.field_by_name(layer, "hold_time").unwrap().value,
            FieldValue::U16(180)
        );
        assert_eq!(
            buf.field_by_name(layer, "bgp_identifier").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(
            buf.field_by_name(layer, "opt_params_length").unwrap().value,
            FieldValue::U8(0)
        );
        assert!(buf.field_by_name(layer, "optional_parameters").is_none());
    }

    #[test]
    fn parse_bgp_open_with_capabilities() {
        let data = build_open_with_capabilities();
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let params = buf.field_by_name(layer, "optional_parameters").unwrap();
        let FieldValue::Array(ref arr_range) = params.value else {
            panic!("expected Array");
        };
        // Collect top-level Object children
        let objects: Vec<_> = buf
            .nested_fields(arr_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(objects.len(), 2);
        // First: Multiprotocol Extensions
        let cap1_range = objects[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, cap1_range, "code"),
            FieldValue::U8(1)
        );
        // value now stores raw capability bytes (AFI/SAFI)
        let val = nested_field_value(&buf, cap1_range, "value");
        assert_eq!(*val, FieldValue::Bytes(&[0, 1, 0, 1]));
        // Second: 4-octet AS
        let cap2_range = objects[1].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, cap2_range, "code"),
            FieldValue::U8(65)
        );
        // 4-byte AS number stored as raw bytes
        let as4_val = nested_field_value(&buf, cap2_range, "value");
        assert_eq!(*as4_val, FieldValue::Bytes(&65582u32.to_be_bytes()));
    }

    #[test]
    fn parse_bgp_open_extended_optional_parameters() {
        // RFC 9072 Section 2 — Extended OPEN encoding.
        // - byte 28: Non-Ext OP Len  = 255
        // - byte 29: Non-Ext OP Type = 255 (sentinel)
        // - bytes 30-31: Extended Opt. Parm. Length (u16)
        // - bytes 32+: parameters with 2-octet length per parameter (RFC 9072 Figure 2)
        //
        // Build a single Capability parameter (type=2) containing one
        // Multiprotocol Extensions capability (code=1, len=4, AFI=1, res=0, SAFI=1).
        let cap_mp = [1u8, 4, 0, 1, 0, 1]; // capability code=1, len=4, AFI/res/SAFI
        let cap_param_value = cap_mp;
        let ext_param_hdr_len = 1 /* type */ + 2 /* len */;
        let ext_param_total_len = ext_param_hdr_len + cap_param_value.len();
        let ext_opt_params_len = ext_param_total_len; // single param
        let total_len = 29 /* OPEN body offsets up to byte 28 */
            + 1 /* Non-Ext OP Type */
            + 2 /* Extended Opt. Parm. Length */
            + ext_opt_params_len;

        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(1); // Type = OPEN
        raw.push(4); // Version
        raw.extend_from_slice(&65001u16.to_be_bytes()); // My AS
        raw.extend_from_slice(&180u16.to_be_bytes()); // Hold Time
        raw.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier
        raw.push(255); // byte 28: Non-Ext OP Len = 255
        raw.push(255); // byte 29: Non-Ext OP Type = 255 (sentinel)
        raw.extend_from_slice(&(ext_opt_params_len as u16).to_be_bytes()); // bytes 30-31
        // Extended Optional Parameter (type=2 Capability, 2-byte length)
        raw.push(2); // Param Type = Capability
        raw.extend_from_slice(&(cap_param_value.len() as u16).to_be_bytes());
        raw.extend_from_slice(&cap_param_value);

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "type_name"), Some("OPEN"));
        // Original 1-byte length field reflects the 0xFF sentinel byte at offset 28.
        assert_eq!(
            buf.field_by_name(layer, "opt_params_length").unwrap().value,
            FieldValue::U8(255)
        );
        // Extended length field is present only when extended encoding is used.
        assert_eq!(
            buf.field_by_name(layer, "ext_opt_params_length")
                .unwrap()
                .value,
            FieldValue::U16(ext_opt_params_len as u16)
        );
        // Capability is parsed using the 2-byte parameter length.
        let params = buf.field_by_name(layer, "optional_parameters").unwrap();
        let FieldValue::Array(ref arr_range) = params.value else {
            panic!("expected Array");
        };
        let objects: Vec<_> = buf
            .nested_fields(arr_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(objects.len(), 1);
        let cap_range = objects[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, cap_range, "code"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *nested_field_value(&buf, cap_range, "value"),
            FieldValue::Bytes(&[0, 1, 0, 1])
        );
    }

    #[test]
    fn parse_bgp_notification() {
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&23u16.to_be_bytes()); // Length = 23
        raw.push(3); // Type = NOTIFICATION
        raw.push(6); // Error Code = Cease
        raw.push(2); // Error Subcode = Administrative Shutdown
        raw.extend_from_slice(&[0xDE, 0xAD]); // Data

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("NOTIFICATION")
        );
        assert_eq!(
            buf.field_by_name(layer, "error_code").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "error_code_name"),
            Some("Cease")
        );
        assert_eq!(
            buf.field_by_name(layer, "error_subcode").unwrap().value,
            FieldValue::U8(2)
        );
        // error_subcode_name requires both code and subcode for lookup,
        // so it cannot be a simple display_fn on a single field.
        assert_eq!(
            buf.field_by_name(layer, "data").unwrap().value,
            FieldValue::Bytes(&[0xDE, 0xAD])
        );
    }

    #[test]
    fn parse_bgp_notification_cease_subcode_name() {
        // RFC 4486, Section 4 — Cease NOTIFICATION subcode 2 = "Administrative Shutdown".
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&21u16.to_be_bytes()); // Length = 21 (no data)
        raw.push(3); // Type = NOTIFICATION
        raw.push(6); // Error Code = Cease
        raw.push(2); // Error Subcode = Administrative Shutdown

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "error_subcode_name"),
            Some("Administrative Shutdown")
        );

        // RFC 8203, Section 4 — Cease subcode 9 = "Hard Reset".
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&21u16.to_be_bytes());
        raw.push(3); // Type = NOTIFICATION
        raw.push(6); // Cease
        raw.push(9); // Hard Reset (RFC 8203)

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "error_subcode_name"),
            Some("Hard Reset")
        );

        // For non-Cease error codes, error_subcode_name must NOT decode as a
        // Cease subcode (the lookup table is error-code specific).
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&21u16.to_be_bytes());
        raw.push(3); // Type = NOTIFICATION
        raw.push(1); // Error Code = Message Header Error
        raw.push(2); // Subcode (not Cease subcode)

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "error_subcode_name"), None);
    }

    #[test]
    fn parse_bgp_route_refresh() {
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&23u16.to_be_bytes()); // Length = 23
        raw.push(5); // Type = ROUTE-REFRESH
        raw.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        raw.push(0); // Reserved
        raw.push(1); // SAFI = Unicast

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("ROUTE-REFRESH")
        );
        assert_eq!(
            buf.field_by_name(layer, "afi").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(buf.resolve_display_name(layer, "afi_name"), Some("IPv4"));
        assert_eq!(
            buf.field_by_name(layer, "safi").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "safi_name"),
            Some("Unicast")
        );
    }

    #[test]
    fn parse_bgp_route_refresh_subtype_borr() {
        // RFC 7313 redefines byte 21 of ROUTE-REFRESH from Reserved to Message Subtype.
        // Subtype 1 = Beginning of RIB (BoRR).
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&23u16.to_be_bytes()); // Length = 23
        raw.push(5); // Type = ROUTE-REFRESH
        raw.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        raw.push(1); // Message Subtype = BoRR (RFC 7313)
        raw.push(1); // SAFI = Unicast

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "message_subtype").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_subtype_name"),
            Some("BoRR")
        );
        assert_eq!(
            buf.field_by_name(layer, "safi").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_bgp_update_withdraw() {
        // UPDATE with 1 withdrawn route: 10.0.0.0/8
        let mut raw = vec![0xFF; 16];
        let withdrawn = [8, 10]; // prefix_len=8, prefix=10 (10.0.0.0/8)
        let total_len = 19 + 2 + withdrawn.len() + 2; // header + wr_len + wr + pa_len
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(2); // Type = UPDATE
        raw.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes()); // Withdrawn Routes Length
        raw.extend_from_slice(&withdrawn);
        raw.extend_from_slice(&0u16.to_be_bytes()); // Total Path Attribute Length = 0

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "withdrawn_routes_length")
                .unwrap()
                .value,
            FieldValue::U16(2)
        );
        let wr = buf.field_by_name(layer, "withdrawn_routes").unwrap();
        let FieldValue::Array(ref arr_range) = wr.value else {
            panic!("expected Array");
        };
        let entries = nlri_entry_ranges(&buf, arr_range);
        assert_eq!(entries.len(), 1);
        // Each entry is an object; the prefix is raw bytes [prefix_len, octets...]
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "prefix"),
            FieldValue::Bytes(&[8, 10])
        );
        assert!(nested_field_by_name_opt(&buf, &entries[0], "path_id").is_none());
        assert!(buf.field_by_name(layer, "nlri").is_none());
    }

    #[test]
    fn parse_bgp_update_announce() {
        // UPDATE with no withdrawn, a raw path attribute, and NLRI 192.168.1.0/24
        let mut raw = vec![0xFF; 16];

        // Path attribute: ORIGIN = IGP (type=1, flags=0x40, len=1, value=0)
        let attr = [0x40, 0x01, 0x01, 0x00]; // well-known transitive, ORIGIN, len=1, IGP

        // NLRI: 192.168.1.0/24
        let nlri = [24, 192, 168, 1]; // prefix_len=24, prefix=192.168.1

        let total_len = 19 + 2 + 2 + attr.len() + nlri.len();
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(2); // Type = UPDATE
        raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
        raw.extend_from_slice(&(attr.len() as u16).to_be_bytes()); // Path Attr Length
        raw.extend_from_slice(&attr);
        raw.extend_from_slice(&nlri);

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "total_path_attribute_length")
                .unwrap()
                .value,
            FieldValue::U16(attr.len() as u16)
        );

        // Check path attributes
        let pa = buf.field_by_name(layer, "path_attributes").unwrap();
        let FieldValue::Array(ref arr_range) = pa.value else {
            panic!("expected Array");
        };
        let pa_objects: Vec<_> = buf
            .nested_fields(arr_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(pa_objects.len(), 1);

        // Check NLRI
        let nlri_field = buf.field_by_name(layer, "nlri").unwrap();
        let FieldValue::Array(ref nlri_range) = nlri_field.value else {
            panic!("expected Array");
        };
        let nlri_entries = nlri_entry_ranges(&buf, nlri_range);
        assert_eq!(nlri_entries.len(), 1);
        // Prefix stored as raw bytes: [prefix_len=24, 192, 168, 1]
        assert_eq!(
            *nested_field_value(&buf, &nlri_entries[0], "prefix"),
            FieldValue::Bytes(&[24, 192, 168, 1])
        );
    }

    /// Helper: extract the first path attribute's child range from a dissected UPDATE.
    fn first_pa_obj_range(buf: &DissectBuffer<'_>) -> core::ops::Range<u32> {
        let layer = &buf.layers()[0];
        let pa = buf.field_by_name(layer, "path_attributes").unwrap();
        let FieldValue::Array(ref arr_range) = pa.value else {
            panic!("expected Array for path_attributes")
        };
        let nested = buf.nested_fields(arr_range);
        let FieldValue::Object(ref obj_range) = nested[0].value else {
            panic!("expected Object for first path_attribute")
        };
        obj_range.clone()
    }

    /// Helper: look up a named field's value from a range.
    fn nested_field_value<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'pkt> {
        &nested_field_by_name(buf, range, name).value
    }

    /// Helper: build an UPDATE with specific path attributes and optional NLRI.
    fn build_update(attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
        let total_len = 19 + 2 + 2 + attrs.len() + nlri.len();
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(2); // Type = UPDATE
        raw.extend_from_slice(&0u16.to_be_bytes()); // Withdrawn Routes Length = 0
        raw.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        raw.extend_from_slice(attrs);
        raw.extend_from_slice(nlri);
        raw
    }

    /// Helper: build a path attribute header + value.
    fn build_attr(flags: u8, type_code: u8, value: &[u8]) -> Vec<u8> {
        let mut raw = vec![flags, type_code];
        if flags & 0x10 != 0 {
            raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            raw.push(value.len() as u8);
        }
        raw.extend_from_slice(value);
        raw
    }

    #[test]
    fn parse_bgp_update_origin() {
        let attr = build_attr(0x40, 1, &[0]); // ORIGIN = IGP
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        // ORIGIN stored as raw U8 value; display deferred to format_fn
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_bgp_update_as_path() {
        let mut as_path_value = vec![2, 2]; // AS_SEQUENCE, 2 ASNs
        as_path_value.extend_from_slice(&65001u16.to_be_bytes());
        as_path_value.extend_from_slice(&65002u16.to_be_bytes());
        let attr = build_attr(0x40, 2, &as_path_value);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref segs_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for AS_PATH");
        };
        // First Object in the Array is a segment
        let segs: Vec<_> = buf
            .nested_fields(segs_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(segs.len(), 1);
        let seg_range = segs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, seg_range, "segment_type"),
            FieldValue::U8(2)
        ); // AS_SEQUENCE
        let asns_field = nested_field_by_name(&buf, seg_range, "as_numbers");
        let asns_range = asns_field.value.as_container_range().unwrap();
        let asns = buf.nested_fields(asns_range);
        assert_eq!(asns.len(), 2);
        assert_eq!(asns[0].value, FieldValue::U32(65001));
        assert_eq!(asns[1].value, FieldValue::U32(65002));
    }

    #[test]
    fn parse_bgp_update_next_hop() {
        let attr = build_attr(0x40, 3, &[10, 0, 0, 1]);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_bgp_update_communities() {
        let mut val = Vec::new();
        val.extend_from_slice(&((65001u32 << 16) | 100).to_be_bytes());
        val.extend_from_slice(&0xFFFFFF01u32.to_be_bytes()); // NO_EXPORT
        let attr = build_attr(0xC0, 8, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for communities");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 2);
        assert_eq!(comms[0].value, FieldValue::U32((65001 << 16) | 100));
        assert_eq!(comms[1].value, FieldValue::U32(0xFFFFFF01));
    }

    #[test]
    fn parse_bgp_update_extended_communities() {
        let mut val = vec![0x00, 0x02];
        val.extend_from_slice(&65001u16.to_be_bytes());
        val.extend_from_slice(&100u32.to_be_bytes());
        val.extend_from_slice(&[0x03, 0x0B, 0x00, 0x00]);
        val.extend_from_slice(&1000u32.to_be_bytes());
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for extended communities");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 2);
        // Extended communities stored as raw 8-byte slices
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[0..8]));
        assert_eq!(comms[1].value, FieldValue::Bytes(&val[8..16]));
    }

    #[test]
    fn parse_bgp_update_large_community() {
        let mut val = Vec::new();
        val.extend_from_slice(&64496u32.to_be_bytes());
        val.extend_from_slice(&100u32.to_be_bytes());
        val.extend_from_slice(&200u32.to_be_bytes());
        let attr = build_attr(0xC0, 32, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for large communities");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    #[test]
    fn parse_bgp_update_mp_reach_ipv6() {
        let mut val = Vec::new();
        val.extend_from_slice(&2u16.to_be_bytes());
        val.push(1);
        val.push(16);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(0);
        val.push(48);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        assert_eq!(
            *nested_field_value(&buf, mp_range, "afi"),
            FieldValue::U16(2)
        );
        let expected_nh = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            *nested_field_value(&buf, mp_range, "next_hop"),
            FieldValue::Ipv6Addr(expected_nh)
        );
        let FieldValue::Array(ref prefixes_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for NLRI");
        };
        let prefixes = nlri_entry_ranges(&buf, prefixes_range);
        assert_eq!(prefixes.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &prefixes[0], "prefix"),
            FieldValue::Bytes(&[48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01])
        );
    }

    // ---------------------------------------------------------------------
    // RFC 7911 (ADD-PATH) — https://www.rfc-editor.org/rfc/rfc7911#section-3
    // ---------------------------------------------------------------------

    /// Helper: look up a named field inside a range, returning `None` if absent.
    fn nested_field_by_name_opt<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    /// Helper: collect the child ranges of the entry objects in an NLRI array.
    fn nlri_entry_ranges(
        buf: &DissectBuffer<'_>,
        range: &core::ops::Range<u32>,
    ) -> Vec<core::ops::Range<u32>> {
        buf.nested_fields(range)
            .iter()
            .filter_map(|f| f.value.as_container_range().cloned())
            .collect()
    }

    /// Helper: the `nlri` array range of the first path attribute's MP value.
    fn mp_nlri_range(buf: &DissectBuffer<'_>, name: &str) -> core::ops::Range<u32> {
        let obj_range = first_pa_obj_range(buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(buf, &obj_range, "value") else {
            panic!("expected Object for MP_REACH/MP_UNREACH value");
        };
        let FieldValue::Array(ref arr) = *nested_field_value(buf, mp_range, name) else {
            panic!("expected Array for {name}");
        };
        arr.clone()
    }

    #[test]
    fn detect_add_path_prefixes_ipv4() {
        // Plain: 24/192.168.1 — parses as plain, so not ADD-PATH.
        assert!(!detect_add_path_prefixes(&[24, 192, 168, 1], 32));
        // ADD-PATH: path_id=1, 24/10.0.0 — a plain read would see prefix_len=0
        // followed by more data, which flags ADD-PATH.
        assert!(detect_add_path_prefixes(&[0, 0, 0, 1, 24, 10, 0, 0], 32));
        // Two ADD-PATH entries for the same prefix.
        let two = [0, 0, 0, 1, 24, 10, 0, 0, 0, 0, 0, 2, 24, 10, 0, 0];
        assert!(detect_add_path_prefixes(&two, 32));
        // Empty block: nothing to decide, treat as plain.
        assert!(!detect_add_path_prefixes(&[], 32));
        // Truncated Path Identifier cannot be ADD-PATH.
        assert!(!detect_add_path_prefixes(&[0, 0, 0], 32));
        // Prefix length beyond the address family maximum in both readings.
        assert!(!detect_add_path_prefixes(&[200, 1, 2, 3, 4], 32));
        // Ambiguous: a single default route (0/0) stays plain.
        assert!(!detect_add_path_prefixes(&[0], 32));
        // Path Identifier 0x10000001 + 10.0.0.0/8: the plain reading runs past
        // the end of the block, so only the ADD-PATH reading is complete.
        assert!(detect_add_path_prefixes(&[0x10, 0, 0, 1, 8, 10], 32));
        // Path Identifier 0xFF000001 + 192.168.1.0/24: the plain reading hits a
        // prefix length above the IPv4 maximum.
        assert!(detect_add_path_prefixes(
            &[0xFF, 0, 0, 1, 24, 192, 168, 1],
            32
        ));
        // Declared prefix longer than the remaining data: only the ADD-PATH
        // reading is complete, so it wins.
        assert!(detect_add_path_prefixes(&[0, 0, 0, 7, 8, 10], 32));
    }

    #[test]
    fn detect_add_path_prefixes_ipv6() {
        // 2001:db8::/32 as a plain prefix.
        assert!(!detect_add_path_prefixes(
            &[32, 0x20, 0x01, 0x0d, 0xb8],
            128
        ));
        // Same prefix with path_id 7 prepended.
        assert!(detect_add_path_prefixes(
            &[0, 0, 0, 7, 32, 0x20, 0x01, 0x0d, 0xb8],
            128
        ));
    }

    #[test]
    fn detect_add_path_mup_blocks() {
        // Plain MUP entry: arch=1, route_type=1, len=1, one octet of data.
        let plain = [1, 0, 1, 1, 0xAA];
        assert!(!detect_add_path_mup(&plain));
        // Same entry with a 4-octet Path Identifier prepended.
        let mut add_path = vec![0, 0, 0, 5];
        add_path.extend_from_slice(&plain);
        assert!(detect_add_path_mup(&add_path));
        // Empty block: treat as plain.
        assert!(!detect_add_path_mup(&[]));
        // Unknown architecture type in both readings.
        assert!(!detect_add_path_mup(&[9, 0, 1, 0]));
        // Route type out of range in both readings.
        assert!(!detect_add_path_mup(&[1, 0, 9, 0]));
        // Truncated: neither reading consumes the block exactly.
        assert!(!detect_add_path_mup(&[1, 0, 1]));
        // Declared length overruns the block in both readings.
        assert!(!detect_add_path_mup(&[1, 0, 1, 200, 0]));
        // Path Identifier 0x01000000: the ADD-PATH reading is exact while the
        // plain reading sees Route Type 0, which is undefined.
        assert!(detect_add_path_mup(&[1, 0, 0, 0, 1, 0, 1, 1, 0xAA]));
        // Path Identifier 0x010100C8: the plain reading has a valid header but
        // its declared Length runs past the end of the block.
        assert!(detect_add_path_mup(&[1, 0, 1, 200, 1, 0, 1, 1, 0xAA]));
    }

    #[test]
    fn parse_bgp_update_add_path_nlri_and_withdrawn() {
        // RFC 7911, Section 3 — Path Identifier prepended to each NLRI entry.
        // Withdrawn: path_id 1 and 2 for 10.0.0.0/8.
        // NLRI: path_id 1 and 2 for 192.168.1.0/24.
        let withdrawn = [0, 0, 0, 1, 8, 10, 0, 0, 0, 2, 8, 10];
        let nlri = [0, 0, 0, 1, 24, 192, 168, 1, 0, 0, 0, 2, 24, 192, 168, 1];

        let mut raw = vec![0xFF; 16];
        let total_len = 19 + 2 + withdrawn.len() + 2 + nlri.len();
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(2); // Type = UPDATE
        raw.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
        raw.extend_from_slice(&withdrawn);
        raw.extend_from_slice(&0u16.to_be_bytes()); // Total Path Attribute Length = 0
        raw.extend_from_slice(&nlri);

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];

        let wr = buf.field_by_name(layer, "withdrawn_routes").unwrap();
        let FieldValue::Array(ref wr_range) = wr.value else {
            panic!("expected Array for withdrawn_routes");
        };
        let wr_entries = nlri_entry_ranges(&buf, wr_range);
        assert_eq!(wr_entries.len(), 2);
        for (i, expected_id) in [1u32, 2u32].iter().enumerate() {
            assert_eq!(
                *nested_field_value(&buf, &wr_entries[i], "path_id"),
                FieldValue::U32(*expected_id)
            );
            assert_eq!(
                *nested_field_value(&buf, &wr_entries[i], "prefix"),
                FieldValue::Bytes(&[8, 10])
            );
        }

        let nlri_field = buf.field_by_name(layer, "nlri").unwrap();
        let FieldValue::Array(ref nlri_range) = nlri_field.value else {
            panic!("expected Array for nlri");
        };
        let nlri_entries = nlri_entry_ranges(&buf, nlri_range);
        assert_eq!(nlri_entries.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &nlri_entries[0], "path_id"),
            FieldValue::U32(1)
        );
        assert_eq!(
            *nested_field_value(&buf, &nlri_entries[1], "path_id"),
            FieldValue::U32(2)
        );
        assert_eq!(
            *nested_field_value(&buf, &nlri_entries[1], "prefix"),
            FieldValue::Bytes(&[24, 192, 168, 1])
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_ipv6_add_path() {
        // RFC 4760 MP_REACH_NLRI carrying RFC 7911 ADD-PATH NLRI.
        let mut val = Vec::new();
        val.extend_from_slice(&2u16.to_be_bytes()); // AFI = IPv6
        val.push(1); // SAFI = Unicast
        val.push(16); // Next Hop length
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(0); // Reserved
        // path_id 1, 2001:db8:1::/48
        val.extend_from_slice(&1u32.to_be_bytes());
        val.push(48);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        // path_id 2, same prefix
        val.extend_from_slice(&2u32.to_be_bytes());
        val.push(48);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let nlri_range = mp_nlri_range(&buf, "nlri");
        let entries = nlri_entry_ranges(&buf, &nlri_range);
        assert_eq!(entries.len(), 2);
        for (i, expected_id) in [1u32, 2u32].iter().enumerate() {
            assert_eq!(
                *nested_field_value(&buf, &entries[i], "path_id"),
                FieldValue::U32(*expected_id)
            );
            assert_eq!(
                *nested_field_value(&buf, &entries[i], "prefix"),
                FieldValue::Bytes(&[48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01])
            );
        }
    }

    #[test]
    fn parse_bgp_update_mp_reach_mup_add_path() {
        // MUP (SAFI 85) Interwork Segment Discovery entries with ADD-PATH
        // Path Identifiers (RFC 7911, Section 3).
        let mut entry = Vec::new();
        entry.push(1); // Architecture Type = 3gpp-5g
        entry.extend_from_slice(&1u16.to_be_bytes()); // Route Type = 1
        entry.push(12); // Length: RD(8) + prefix_len(1) + prefix(3)
        entry.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // RD
        entry.push(24);
        entry.extend_from_slice(&[192, 168, 1]);

        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        val.push(85); // SAFI = BGP-MUP
        val.push(4); // Next Hop length
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0); // Reserved
        val.extend_from_slice(&7u32.to_be_bytes());
        val.extend_from_slice(&entry);
        val.extend_from_slice(&8u32.to_be_bytes());
        val.extend_from_slice(&entry);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let nlri_range = mp_nlri_range(&buf, "nlri");
        let entries = nlri_entry_ranges(&buf, &nlri_range);
        assert_eq!(entries.len(), 2);
        for (i, expected_id) in [7u32, 8u32].iter().enumerate() {
            assert_eq!(
                *nested_field_value(&buf, &entries[i], "path_id"),
                FieldValue::U32(*expected_id)
            );
            assert_eq!(
                *nested_field_value(&buf, &entries[i], "architecture_type"),
                FieldValue::U8(1)
            );
            assert_eq!(
                *nested_field_value(&buf, &entries[i], "route_type"),
                FieldValue::U16(1)
            );
            assert_eq!(
                *nested_field_value(&buf, &entries[i], "prefix"),
                FieldValue::Bytes(&[24, 192, 168, 1])
            );
        }
    }

    #[test]
    fn parse_bgp_update_mup_without_add_path_stays_plain() {
        // The same MUP entry without Path Identifiers must not be misread as
        // ADD-PATH (plain wins when both readings are valid).
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(12);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(24);
        val.extend_from_slice(&[192, 168, 1]);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let nlri_range = mp_nlri_range(&buf, "nlri");
        let entries = nlri_entry_ranges(&buf, &nlri_range);
        assert_eq!(entries.len(), 1);
        assert!(nested_field_by_name_opt(&buf, &entries[0], "path_id").is_none());
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "prefix"),
            FieldValue::Bytes(&[24, 192, 168, 1])
        );
    }

    #[test]
    fn name_lookup_tables() {
        // The `display_fn` name tables are only reached through serialization,
        // so exercise every arm (and the unknown fallback) directly.

        // RFC 4271, Section 4.1 / RFC 2918.
        assert_eq!(msg_type_name(MSG_OPEN), Some("OPEN"));
        assert_eq!(msg_type_name(MSG_UPDATE), Some("UPDATE"));
        assert_eq!(msg_type_name(MSG_NOTIFICATION), Some("NOTIFICATION"));
        assert_eq!(msg_type_name(MSG_KEEPALIVE), Some("KEEPALIVE"));
        assert_eq!(msg_type_name(MSG_ROUTE_REFRESH), Some("ROUTE-REFRESH"));
        assert_eq!(msg_type_name(0), None);

        // IANA Address Family Numbers.
        assert_eq!(afi_name(1), Some("IPv4"));
        assert_eq!(afi_name(2), Some("IPv6"));
        assert_eq!(afi_name(25), Some("L2VPN"));
        assert_eq!(afi_name(0), None);

        // IANA SAFI Namespace.
        for (v, expected) in [
            (1u8, "Unicast"),
            (2, "Multicast"),
            (4, "MPLS Labels"),
            (65, "VPLS"),
            (70, "EVPN"),
            (71, "BGP-LS"),
            (73, "SR Policy"),
            (SAFI_MUP, "BGP-MUP"),
            (128, "MPLS-labeled VPN"),
            (129, "Multicast VPN"),
            (132, "Route Target Constraints"),
            (133, "FlowSpec"),
            (134, "L3VPN FlowSpec"),
        ] {
            assert_eq!(safi_name(v), Some(expected), "SAFI {v}");
        }
        assert_eq!(safi_name(0), None);

        // IANA BGP Path Attributes.
        for (v, expected) in [
            (1u8, "ORIGIN"),
            (2, "AS_PATH"),
            (3, "NEXT_HOP"),
            (4, "MULTI_EXIT_DISC"),
            (5, "LOCAL_PREF"),
            (6, "ATOMIC_AGGREGATE"),
            (7, "AGGREGATOR"),
            (8, "COMMUNITIES"),
            (9, "ORIGINATOR_ID"),
            (10, "CLUSTER_LIST"),
            (14, "MP_REACH_NLRI"),
            (15, "MP_UNREACH_NLRI"),
            (16, "EXTENDED COMMUNITIES"),
            (17, "AS4_PATH"),
            (18, "AS4_AGGREGATOR"),
            (22, "PMSI_TUNNEL"),
            (23, "Tunnel Encapsulation"),
            (26, "AIGP"),
            (29, "BGP-LS Attribute"),
            (32, "LARGE_COMMUNITY"),
            (33, "BGPsec_Path"),
            (35, "Only to Customer (OTC)"),
            (40, "BGP Prefix-SID"),
        ] {
            assert_eq!(path_attr_type_name(v), Some(expected), "attribute {v}");
        }
        assert_eq!(path_attr_type_name(0), None);

        // RFC 4271, Section 5.1.1.
        assert_eq!(origin_name(0), Some("IGP"));
        assert_eq!(origin_name(1), Some("EGP"));
        assert_eq!(origin_name(2), Some("INCOMPLETE"));
        assert_eq!(origin_name(3), None);

        // RFC 4271, Section 5.1.2 / RFC 5065.
        assert_eq!(as_path_segment_type_name(1), Some("AS_SET"));
        assert_eq!(as_path_segment_type_name(2), Some("AS_SEQUENCE"));
        assert_eq!(as_path_segment_type_name(3), Some("AS_CONFED_SEQUENCE"));
        assert_eq!(as_path_segment_type_name(4), Some("AS_CONFED_SET"));
        assert_eq!(as_path_segment_type_name(0), None);

        // IANA BGP Well-known Communities (RFC 1997 and successors).
        for (v, expected) in [
            (0xFFFF_0000u32, "GRACEFUL_SHUTDOWN"),
            (0xFFFF_0001, "ACCEPT_OWN"),
            (0xFFFF_0002, "ROUTE_FILTER_TRANSLATED_v4"),
            (0xFFFF_0003, "ROUTE_FILTER_v4"),
            (0xFFFF_0004, "ROUTE_FILTER_TRANSLATED_v6"),
            (0xFFFF_0005, "ROUTE_FILTER_v6"),
            (0xFFFF_0006, "LLGR_STALE"),
            (0xFFFF_0007, "NO_LLGR"),
            (0xFFFF_029A, "BLACKHOLE"),
            (0xFFFF_FF01, "NO_EXPORT"),
            (0xFFFF_FF02, "NO_ADVERTISE"),
            (0xFFFF_FF03, "NO_EXPORT_SUBCONFED"),
            (0xFFFF_FF04, "NOPEER"),
        ] {
            assert_eq!(
                well_known_community_name(v),
                Some(expected),
                "community {v}"
            );
        }
        assert_eq!(well_known_community_name(0), None);

        // draft-ietf-bess-mup-safi-01, Section 3.
        assert_eq!(mup_route_type_name(1), Some("Interwork Segment Discovery"));
        assert_eq!(mup_route_type_name(2), Some("Direct Segment Discovery"));
        assert_eq!(mup_route_type_name(3), Some("Type 1 Session Transformed"));
        assert_eq!(mup_route_type_name(4), Some("Type 2 Session Transformed"));
        assert_eq!(mup_route_type_name(0), None);
        assert_eq!(
            mup_architecture_type_name(MUP_ARCHITECTURE_TYPE_3GPP_5G),
            Some("3gpp-5g")
        );
        assert_eq!(mup_architecture_type_name(0), None);
        assert_eq!(mup_st_tlv_type_name(0), None);
    }

    #[test]
    fn parse_bgp_update_malformed_nlri_is_dropped() {
        // Postel's law: malformed NLRI blocks stop the walk without panicking
        // and, when no entry could be decoded, no `nlri` field is emitted.

        // Prefix length above the IPv4 maximum (RFC 4271, Section 4.3).
        let data = build_update(&[], &[200, 1, 2, 3, 4]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.field_by_name(&buf.layers()[0], "nlri").is_none());

        // Prefix declared longer than the remaining data.
        let data = build_update(&[], &[24, 192, 168]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert!(buf.field_by_name(&buf.layers()[0], "nlri").is_none());

        // A valid prefix followed by a truncated one: the first is kept.
        let data = build_update(&[], &[8, 10, 24, 192, 168]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let nlri = buf.field_by_name(&buf.layers()[0], "nlri").unwrap();
        let FieldValue::Array(ref range) = nlri.value else {
            panic!("expected Array for nlri");
        };
        let entries = nlri_entry_ranges(&buf, range);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "prefix"),
            FieldValue::Bytes(&[8, 10])
        );
    }

    #[test]
    fn parse_bgp_update_mup_truncated_entry_is_dropped() {
        // MUP entry whose declared Route Type Length runs past the end of the
        // NLRI block: the walk stops and the empty array placeholder is removed.
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        val.push(85); // SAFI = BGP-MUP
        val.push(4); // Next Hop length
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0); // Reserved
        val.push(1); // Architecture Type
        val.extend_from_slice(&1u16.to_be_bytes()); // Route Type
        val.push(200); // Length, far beyond the remaining data
        val.push(0xAA);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        assert!(nested_field_by_name_opt(&buf, mp_range, "nlri").is_none());
    }

    #[test]
    fn field_schema_exposes_nlri_and_path_attribute_value_children() {
        /// Recursively look up a descriptor by name.
        fn find<'a>(descs: &'a [FieldDescriptor], name: &str) -> Option<&'a FieldDescriptor> {
            descs.iter().find(|d| d.name == name)
        }

        let descs = BgpDissector.field_descriptors();

        // Top-level `nlri` / `withdrawn_routes` expose `path_id` and `prefix`.
        for name in ["nlri", "withdrawn_routes"] {
            let d = find(descs, name).unwrap_or_else(|| panic!("{name} descriptor missing"));
            assert_eq!(d.field_type, FieldType::Array);
            let children = d
                .children
                .unwrap_or_else(|| panic!("{name} has no children"));
            let path_id = find(children, "path_id").expect("path_id missing");
            assert_eq!(path_id.field_type, FieldType::U32);
            assert!(path_id.optional);
            assert!(find(children, "prefix").is_some());
        }

        // `path_attributes.value` is polymorphic and lists the union of every
        // structured shape it can take.
        let pa = find(descs, "path_attributes").expect("path_attributes missing");
        let pa_children = pa.children.expect("path_attributes has no children");
        let value = find(pa_children, "value").expect("value missing");
        assert_eq!(value.field_type, FieldType::Any);
        assert!(value.optional);
        let value_children = value.children.expect("value has no children");
        for name in [
            "afi",
            "safi",
            "next_hop",
            "next_hop_link_local",
            "nlri",
            "withdrawn_routes",
            "label_index",
            "srgb_entries",
            "sub_tlvs",
            "segment_type",
            "as_numbers",
        ] {
            let child =
                find(value_children, name).unwrap_or_else(|| panic!("{name} missing from union"));
            assert!(child.optional, "{name} in a union must be optional");
        }

        // `value.nlri` reaches the MUP entry fields, including `route_type`.
        let mp_nlri = find(value_children, "nlri").expect("nlri missing");
        let entry_children = mp_nlri.children.expect("nlri has no children");
        for name in [
            "path_id",
            "prefix",
            "route_type",
            "architecture_type",
            "rd",
            "teid",
            "qfi",
            "endpoint_address",
            "source_address",
            "address",
        ] {
            let child = find(entry_children, name)
                .unwrap_or_else(|| panic!("{name} missing from NLRI entry union"));
            assert!(child.optional, "{name} in a union must be optional");
        }
    }

    #[test]
    fn parse_bgp_truncated_open() {
        let mut data = vec![0xFF; 16];
        data.extend_from_slice(&29u16.to_be_bytes());
        data.push(1);
        data.extend_from_slice(&[4, 0, 1]);
        let mut buf = DissectBuffer::new();
        let err = BgpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_bgp_truncated_header() {
        let data = vec![0xFF; 10];
        let mut buf = DissectBuffer::new();
        let err = BgpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 19,
                actual: 10
            }
        ));
    }

    #[test]
    fn parse_bgp_invalid_marker() {
        let mut data = build_keepalive();
        data[0] = 0x00;
        let mut buf = DissectBuffer::new();
        let err = BgpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_bgp_multiple_messages() {
        let mut data = build_keepalive();
        data.extend_from_slice(&build_keepalive());

        let mut buf = DissectBuffer::new();
        let result = BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 38);
        assert_eq!(buf.layers().len(), 2);
        assert_eq!(buf.layers()[0].name, "BGP");
        assert_eq!(buf.layers()[1].name, "BGP");
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "type_name"),
            Some("KEEPALIVE")
        );
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[1], "type_name"),
            Some("KEEPALIVE")
        );
        assert_eq!(buf.layers()[0].range, 0..19);
        assert_eq!(buf.layers()[1].range, 19..38);
    }

    #[test]
    fn parse_bgp_open_followed_by_keepalive() {
        let mut data = build_open_basic();
        data.extend_from_slice(&build_keepalive());

        let mut buf = DissectBuffer::new();
        let result = BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 48);
        assert_eq!(buf.layers().len(), 2);
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "type_name"),
            Some("OPEN")
        );
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[1], "type_name"),
            Some("KEEPALIVE")
        );
    }

    #[test]
    fn parse_bgp_update_mup_interwork_segment_discovery() {
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(12);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(24);
        val.extend_from_slice(&[192, 168, 1]);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        assert_eq!(
            *nested_field_value(&buf, mp_range, "safi"),
            FieldValue::U8(85)
        );
        let FieldValue::Array(ref entries_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for MUP NLRI");
        };
        let entries: Vec<_> = buf
            .nested_fields(entries_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(entries.len(), 1);
        let entry_range = entries[0].value.as_container_range().unwrap();
        // Prefix stored as raw bytes [prefix_len, prefix_data...]
        assert_eq!(
            *nested_field_value(&buf, entry_range, "prefix"),
            FieldValue::Bytes(&[24, 192, 168, 1])
        );
    }

    #[test]
    fn parse_bgp_update_mup_type1_st() {
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&3u16.to_be_bytes());
        let rt_len = 8 + 1 + 4 + 4 + 1 + 1 + 4;
        val.push(rt_len as u8);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(32);
        val.extend_from_slice(&[10, 1, 1, 1]);
        val.extend_from_slice(&0x12345678u32.to_be_bytes());
        val.push(9);
        val.push(32);
        val.extend_from_slice(&[10, 0, 0, 2]);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        let FieldValue::Array(ref entries_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for MUP NLRI");
        };
        let entry_objs: Vec<_> = buf
            .nested_fields(entries_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        let entry_range = entry_objs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, entry_range, "prefix"),
            FieldValue::Bytes(&[32, 10, 1, 1, 1])
        );
        // TEID stored as raw 4 bytes
        assert_eq!(
            *nested_field_value(&buf, entry_range, "teid"),
            FieldValue::Bytes(&0x12345678u32.to_be_bytes())
        );
        assert_eq!(
            *nested_field_value(&buf, entry_range, "qfi"),
            FieldValue::U8(9)
        );
        assert_eq!(
            *nested_field_value(&buf, entry_range, "endpoint_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
    }

    #[test]
    fn parse_bgp_update_mup_type1_st_tlvs() {
        // Same Type 1 ST fields as `parse_bgp_update_mup_type1_st`, plus a Source Address
        // Length of 0 (no inline source address) followed by a trailing Source Address TLV.
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&3u16.to_be_bytes());
        let tlv = [3u8, 4, 10, 0, 0, 9]; // Type 3: Source Address TLV, IPv4
        let rt_len = 8 + 1 + 4 + 4 + 1 + 1 + 4 + 1 + tlv.len();
        val.push(rt_len as u8);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(32);
        val.extend_from_slice(&[10, 1, 1, 1]);
        val.extend_from_slice(&0x12345678u32.to_be_bytes());
        val.push(9);
        val.push(32);
        val.extend_from_slice(&[10, 0, 0, 2]);
        val.push(0); // Source Address Length = 0 (not carried)
        val.extend_from_slice(&tlv);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        let FieldValue::Array(ref entries_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for MUP NLRI");
        };
        let entry_objs: Vec<_> = buf
            .nested_fields(entries_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        let entry_range = entry_objs[0].value.as_container_range().unwrap();

        let FieldValue::Array(ref tlvs_range) = *nested_field_value(&buf, entry_range, "tlvs")
        else {
            panic!("expected Array for tlvs");
        };
        let tlvs: Vec<_> = buf
            .nested_fields(tlvs_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(tlvs.len(), 1);
        let tlv_range = tlvs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, tlv_range, "type"),
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.resolve_nested_display_name(tlv_range, "type_name"),
            Some("Source Address")
        );
        assert_eq!(
            *nested_field_value(&buf, tlv_range, "address"),
            FieldValue::Ipv4Addr([10, 0, 0, 9])
        );
    }

    #[test]
    fn parse_bgp_update_mup_type2_st() {
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&4u16.to_be_bytes());
        let tlv1 = [1u8, 5, 0x11, 0x22, 0x33, 0x44, 7]; // Type 1: 3gpp-5g Session Parameters
        let tlv2 = [2u8, 4, 10, 0, 0, 6]; // Type 2: Interwork Endpoint, IPv4
        let rt_len = 8 + 1 + 4 + 4 + tlv1.len() + tlv2.len();
        val.push(rt_len as u8);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // RD
        val.push(64); // Endpoint Length: 32 (address) + 32 (TEID) bits
        val.extend_from_slice(&[10, 0, 0, 5]); // Endpoint Address
        val.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // TEID
        val.extend_from_slice(&tlv1);
        val.extend_from_slice(&tlv2);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        let FieldValue::Array(ref entries_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for MUP NLRI");
        };
        let entry_objs: Vec<_> = buf
            .nested_fields(entries_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        let entry_range = entry_objs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, entry_range, "endpoint_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 5])
        );
        assert_eq!(
            *nested_field_value(&buf, entry_range, "teid"),
            FieldValue::Bytes(&0xAABBCCDDu32.to_be_bytes())
        );

        let FieldValue::Array(ref tlvs_range) = *nested_field_value(&buf, entry_range, "tlvs")
        else {
            panic!("expected Array for tlvs");
        };
        let tlvs: Vec<_> = buf
            .nested_fields(tlvs_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(tlvs.len(), 2);

        let tlv0_range = tlvs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, tlv0_range, "type"),
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_nested_display_name(tlv0_range, "type_name"),
            Some("3gpp-5g Session Parameters")
        );
        assert_eq!(
            *nested_field_value(&buf, tlv0_range, "teid"),
            FieldValue::Bytes(&[0x11, 0x22, 0x33, 0x44])
        );
        assert_eq!(
            *nested_field_value(&buf, tlv0_range, "qfi"),
            FieldValue::U8(7)
        );

        let tlv1_range = tlvs[1].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, tlv1_range, "type"),
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_nested_display_name(tlv1_range, "type_name"),
            Some("Interwork Endpoint")
        );
        assert_eq!(
            *nested_field_value(&buf, tlv1_range, "address"),
            FieldValue::Ipv4Addr([10, 0, 0, 6])
        );
    }

    #[test]
    fn parse_bgp_update_mup_type2_st_zero_length_teid() {
        // Endpoint Length of 32 (IPv4 AFI length only) means a zero-length TEID: the
        // Endpoint Address is still fixed-size at the AFI length and a TLV can follow
        // directly, with no TEID field in between.
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&4u16.to_be_bytes());
        let tlv = [2u8, 4, 10, 0, 0, 8]; // Type 2: Interwork Endpoint, IPv4
        let rt_len = 8 + 1 + 4 + tlv.len();
        val.push(rt_len as u8);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // RD
        val.push(32); // Endpoint Length: 32 (address) + 0 (TEID) bits
        val.extend_from_slice(&[10, 0, 0, 7]); // Endpoint Address
        val.extend_from_slice(&tlv);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        let FieldValue::Array(ref entries_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for MUP NLRI");
        };
        let entry_objs: Vec<_> = buf
            .nested_fields(entries_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        let entry_range = entry_objs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, entry_range, "endpoint_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 7])
        );
        assert!(
            !buf.nested_fields(entry_range)
                .iter()
                .any(|f| f.name() == "teid")
        );

        let FieldValue::Array(ref tlvs_range) = *nested_field_value(&buf, entry_range, "tlvs")
        else {
            panic!("expected Array for tlvs");
        };
        let tlvs: Vec<_> = buf
            .nested_fields(tlvs_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(tlvs.len(), 1);
        let tlv_range = tlvs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, tlv_range, "address"),
            FieldValue::Ipv4Addr([10, 0, 0, 8])
        );
    }

    #[test]
    fn parse_bgp_update_mup_type2_st_oversized_teid_length() {
        // Endpoint Length declares 72 bits: 32 (IPv4 address) + 40 (a malformed,
        // oversized TEID — the max is 4 octets / 32 bits). The TLV boundary must be
        // derived from the full declared Endpoint Length (9 octets after the length
        // byte), not from the accumulated address + capped-TEID bytes, otherwise the
        // trailing TLV gets parsed starting one byte early, inside the endpoint blob.
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(85);
        val.push(4);
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.push(0);
        val.push(1);
        val.extend_from_slice(&4u16.to_be_bytes());
        let tlv = [2u8, 4, 10, 0, 0, 10]; // Type 2: Interwork Endpoint, IPv4
        let rt_len = 8 + 1 + 4 + 5 + tlv.len();
        val.push(rt_len as u8);
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // RD
        val.push(72); // Endpoint Length: 32 (address) + 40 (oversized TEID) bits
        val.extend_from_slice(&[10, 0, 0, 9]); // Endpoint Address
        val.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]); // 5-octet declared TEID area
        val.extend_from_slice(&tlv);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        let FieldValue::Array(ref entries_range) = *nested_field_value(&buf, mp_range, "nlri")
        else {
            panic!("expected Array for MUP NLRI");
        };
        let entry_objs: Vec<_> = buf
            .nested_fields(entries_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        let entry_range = entry_objs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, entry_range, "endpoint_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 9])
        );
        // TEID is capped to the first 4 octets of the declared (oversized) TEID area.
        assert_eq!(
            *nested_field_value(&buf, entry_range, "teid"),
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04])
        );

        let FieldValue::Array(ref tlvs_range) = *nested_field_value(&buf, entry_range, "tlvs")
        else {
            panic!("expected Array for tlvs");
        };
        let tlvs: Vec<_> = buf
            .nested_fields(tlvs_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(tlvs.len(), 1);
        let tlv_range = tlvs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, tlv_range, "type"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *nested_field_value(&buf, tlv_range, "address"),
            FieldValue::Ipv4Addr([10, 0, 0, 10])
        );
    }

    #[test]
    fn parse_bgp_update_mup_extended_community() {
        let mut val = vec![0x0C, 0x00];
        val.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for extended communities");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    // --- BGP Prefix-SID tests ---

    fn build_psid_tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
        let mut raw = vec![tlv_type];
        raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
        raw.extend_from_slice(value);
        raw
    }

    /// Helper: extract the first path attribute's "value" field.
    fn extract_pa_value<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> &'a FieldValue<'pkt> {
        let obj_range = first_pa_obj_range(buf);
        nested_field_value(buf, &obj_range, "value")
    }

    #[test]
    fn parse_bgp_prefix_sid_label_index() {
        let mut val = vec![0x00];
        val.extend_from_slice(&0u16.to_be_bytes());
        val.extend_from_slice(&100u32.to_be_bytes());
        let tlv = build_psid_tlv(1, &val);
        let attr = build_attr(0xC0, 40, &tlv);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, obj_range, "type"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *nested_field_value(&buf, obj_range, "label_index"),
            FieldValue::U32(100)
        );
        assert_eq!(
            *nested_field_value(&buf, obj_range, "flags"),
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_bgp_prefix_sid_originator_srgb() {
        let mut val = vec![0x00, 0x00];
        val.push(0x00);
        val.push(0x3E);
        val.push(0x80);
        val.push(0x00);
        val.push(0x1F);
        val.push(0x40);
        let tlv = build_psid_tlv(3, &val);
        let attr = build_attr(0xC0, 40, &tlv);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, obj_range, "type"),
            FieldValue::U8(3)
        );
        let entries_field = nested_field_by_name(&buf, obj_range, "srgb_entries");
        let FieldValue::Array(ref srgbs_range) = entries_field.value else {
            panic!("expected Array");
        };
        let srgbs = buf.nested_fields(srgbs_range);
        assert!(srgbs[0].value.is_object());
        let FieldValue::Object(ref entry_range) = srgbs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, entry_range, "base"),
            FieldValue::U32(16000)
        );
        assert_eq!(
            *nested_field_value(&buf, entry_range, "range"),
            FieldValue::U32(8000)
        );
    }

    #[test]
    fn parse_bgp_prefix_sid_srv6_l3_service() {
        let mut sid_info_val = vec![0x00];
        sid_info_val
            .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        sid_info_val.push(0x00);
        sid_info_val.extend_from_slice(&0x0029u16.to_be_bytes());
        sid_info_val.push(0x00);
        let sub_tlv = build_psid_tlv(1, &sid_info_val);
        let mut service_val = vec![0x00];
        service_val.extend_from_slice(&sub_tlv);
        let tlv = build_psid_tlv(5, &service_val);
        let attr = build_attr(0xC0 | 0x10, 40, &tlv);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        let sub_tlvs_field = nested_field_by_name(&buf, obj_range, "sub_tlvs");
        let FieldValue::Array(ref subs_range) = sub_tlvs_field.value else {
            panic!("expected Array");
        };
        let subs = buf.nested_fields(subs_range);
        assert!(subs[0].value.is_object());
        let FieldValue::Object(ref si_range) = subs[0].value else {
            panic!("expected Object");
        };
        let expected_sid = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            *nested_field_value(&buf, si_range, "srv6_sid"),
            FieldValue::Ipv6Addr(expected_sid)
        );
        assert_eq!(
            *nested_field_value(&buf, si_range, "endpoint_behavior"),
            FieldValue::U16(0x0029)
        );
    }

    #[test]
    fn parse_bgp_prefix_sid_srv6_sid_structure() {
        let mut sid_info_val = vec![0x00];
        sid_info_val.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        sid_info_val.push(0x00);
        sid_info_val.extend_from_slice(&0x003Eu16.to_be_bytes());
        sid_info_val.push(0x00);
        sid_info_val.push(0x01);
        sid_info_val.extend_from_slice(&6u16.to_be_bytes());
        sid_info_val.push(40);
        sid_info_val.push(24);
        sid_info_val.push(16);
        sid_info_val.push(0);
        sid_info_val.push(0);
        sid_info_val.push(0);
        let sub_tlv = build_psid_tlv(1, &sid_info_val);
        let mut service_val = vec![0x00];
        service_val.extend_from_slice(&sub_tlv);
        let tlv = build_psid_tlv(5, &service_val);
        let attr = build_attr(0xC0 | 0x10, 40, &tlv);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        let sub_tlvs_field = nested_field_by_name(&buf, obj_range, "sub_tlvs");
        let FieldValue::Array(ref subs_range) = sub_tlvs_field.value else {
            panic!("expected Array");
        };
        let subs = buf.nested_fields(subs_range);
        let FieldValue::Object(ref si_range) = subs[0].value else {
            panic!("expected Object");
        };
        let ss_field = nested_field_by_name(&buf, si_range, "sid_structure");
        let FieldValue::Object(ref ss_range) = ss_field.value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, ss_range, "locator_block_length"),
            FieldValue::U8(40)
        );
        assert_eq!(
            *nested_field_value(&buf, ss_range, "locator_node_length"),
            FieldValue::U8(24)
        );
        assert_eq!(
            *nested_field_value(&buf, ss_range, "function_length"),
            FieldValue::U8(16)
        );
        assert_eq!(
            *nested_field_value(&buf, ss_range, "argument_length"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *nested_field_value(&buf, ss_range, "transposition_length"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *nested_field_value(&buf, ss_range, "transposition_offset"),
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_bgp_prefix_sid_multiple_tlvs() {
        let mut label_val = vec![0x00];
        label_val.extend_from_slice(&0u16.to_be_bytes());
        label_val.extend_from_slice(&200u32.to_be_bytes());
        let tlv1 = build_psid_tlv(1, &label_val);
        let mut srgb_val = vec![0x00, 0x00];
        srgb_val.extend_from_slice(&[0x00, 0x3E, 0x80]);
        srgb_val.extend_from_slice(&[0x00, 0x1F, 0x40]);
        let tlv2 = build_psid_tlv(3, &srgb_val);
        let mut attr_val = Vec::new();
        attr_val.extend_from_slice(&tlv1);
        attr_val.extend_from_slice(&tlv2);
        let attr = build_attr(0xC0, 40, &attr_val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj0) = tlvs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(*nested_field_value(&buf, obj0, "type"), FieldValue::U8(1));
        assert_eq!(
            *nested_field_value(&buf, obj0, "label_index"),
            FieldValue::U32(200)
        );
        // Second TLV Object starts after the first Object's children
        let second_start = (obj0.end - tlvs_range.start) as usize;
        let FieldValue::Object(ref obj1) = tlvs[second_start].value else {
            panic!("expected Object");
        };
        assert_eq!(*nested_field_value(&buf, obj1, "type"), FieldValue::U8(3));
    }

    #[test]
    fn parse_bgp_prefix_sid_unknown_tlv() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let tlv = build_psid_tlv(99, &payload);
        let attr = build_attr(0xC0, 40, &tlv);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, obj_range, "type"),
            FieldValue::U8(99)
        );
        assert_eq!(
            *nested_field_value(&buf, obj_range, "value"),
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn parse_bgp_prefix_sid_truncated() {
        let mut label_val = vec![0x00];
        label_val.extend_from_slice(&0u16.to_be_bytes());
        label_val.extend_from_slice(&50u32.to_be_bytes());
        let tlv1 = build_psid_tlv(1, &label_val);
        let mut truncated = vec![0x01];
        truncated.extend_from_slice(&10u16.to_be_bytes());
        truncated.extend_from_slice(&[0xAA, 0xBB]);
        let mut attr_val = Vec::new();
        attr_val.extend_from_slice(&tlv1);
        attr_val.extend_from_slice(&truncated);
        let attr = build_attr(0xC0, 40, &attr_val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, obj_range, "label_index"),
            FieldValue::U32(50)
        );
    }

    #[test]
    fn parse_bgp_update_mp_unreach_ipv6() {
        let mut val = Vec::new();
        val.extend_from_slice(&2u16.to_be_bytes());
        val.push(1);
        val.push(32);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let attr = build_attr(0x80 | 0x10, 15, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_UNREACH");
        };
        assert_eq!(
            *nested_field_value(&buf, mp_range, "afi"),
            FieldValue::U16(2)
        );
        assert_eq!(
            *nested_field_value(&buf, mp_range, "safi"),
            FieldValue::U8(1)
        );
        let wr_field = nested_field_by_name(&buf, mp_range, "withdrawn_routes");
        let FieldValue::Array(ref wr_range) = wr_field.value else {
            panic!("expected Array");
        };
        let prefixes = nlri_entry_ranges(&buf, wr_range);
        assert_eq!(prefixes.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &prefixes[0], "prefix"),
            FieldValue::Bytes(&[32, 0x20, 0x01, 0x0d, 0xb8])
        );
    }

    #[test]
    fn parse_bgp_update_mp_unreach_ipv4() {
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes());
        val.push(1);
        val.push(8);
        val.push(10);
        let attr = build_attr(0x80 | 0x10, 15, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_UNREACH");
        };
        assert_eq!(
            *nested_field_value(&buf, mp_range, "afi"),
            FieldValue::U16(1)
        );
        let wr_field = nested_field_by_name(&buf, mp_range, "withdrawn_routes");
        let FieldValue::Array(ref wr_range) = wr_field.value else {
            panic!("expected Array");
        };
        let prefixes = nlri_entry_ranges(&buf, wr_range);
        assert_eq!(prefixes.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &prefixes[0], "prefix"),
            FieldValue::Bytes(&[8, 10])
        );
    }

    #[test]
    fn parse_bgp_update_aggregator_2byte_as() {
        let mut val = Vec::new();
        val.extend_from_slice(&65001u16.to_be_bytes());
        val.extend_from_slice(&[10, 0, 0, 1]);
        let attr = build_attr(0xC0, 7, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&val[..])
        );
    }

    #[test]
    fn parse_bgp_update_aggregator_4byte_as() {
        let mut val = Vec::new();
        val.extend_from_slice(&131072u32.to_be_bytes());
        val.extend_from_slice(&[192, 168, 1, 1]);
        let attr = build_attr(0xC0 | 0x10, 7, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&val[..])
        );
    }

    #[test]
    fn parse_bgp_update_as4_path() {
        let mut as4_path_value = vec![2, 2];
        as4_path_value.extend_from_slice(&200000u32.to_be_bytes());
        as4_path_value.extend_from_slice(&300000u32.to_be_bytes());
        let attr = build_attr(0xC0 | 0x10, 17, &as4_path_value);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref segs_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for AS4_PATH");
        };
        let segs: Vec<_> = buf
            .nested_fields(segs_range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(segs.len(), 1);
        let seg_range = segs[0].value.as_container_range().unwrap();
        assert_eq!(
            *nested_field_value(&buf, seg_range, "segment_type"),
            FieldValue::U8(2)
        );
        let asns_field = nested_field_by_name(&buf, seg_range, "as_numbers");
        let asns_range = asns_field.value.as_container_range().unwrap();
        let asns = buf.nested_fields(asns_range);
        assert_eq!(asns.len(), 2);
        assert_eq!(asns[0].value, FieldValue::U32(200000));
        assert_eq!(asns[1].value, FieldValue::U32(300000));
    }

    #[test]
    fn parse_bgp_update_as4_aggregator() {
        let mut val = Vec::new();
        val.extend_from_slice(&200000u32.to_be_bytes());
        val.extend_from_slice(&[172, 16, 0, 1]);
        let attr = build_attr(0xC0 | 0x10, 18, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&val[..])
        );
    }

    #[test]
    fn parse_bgp_update_cluster_list() {
        let mut val = Vec::new();
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.extend_from_slice(&[10, 0, 0, 2]);
        let attr = build_attr(0x80, 10, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref clusters_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array for CLUSTER_LIST");
        };
        let clusters = buf.nested_fields(clusters_range);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(clusters[1].value, FieldValue::Ipv4Addr([10, 0, 0, 2]));
    }

    #[test]
    fn parse_bgp_update_originator_id() {
        let attr = build_attr(0x80, 9, &[10, 0, 0, 1]);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_bgp_update_multi_exit_disc() {
        let attr = build_attr(0x80, 4, &100u32.to_be_bytes());
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::U32(100)
        );
    }

    #[test]
    fn parse_bgp_update_local_pref() {
        let attr = build_attr(0x40, 5, &200u32.to_be_bytes());
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::U32(200)
        );
    }

    #[test]
    fn parse_bgp_update_atomic_aggregate() {
        let attr = build_attr(0x40, 6, &[]);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let fields = buf.nested_fields(&obj_range);
        assert!(!fields.iter().any(|f| f.name() == "value"));
    }

    #[test]
    fn parse_bgp_update_extended_communities_ipv4_route_target() {
        let mut val = vec![0x01, 0x02];
        val.extend_from_slice(&[192, 168, 1, 1]);
        val.extend_from_slice(&100u16.to_be_bytes());
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    #[test]
    fn parse_bgp_update_extended_communities_route_origin() {
        let mut val = vec![0x00, 0x03];
        val.extend_from_slice(&65001u16.to_be_bytes());
        val.extend_from_slice(&500u32.to_be_bytes());
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    #[test]
    fn parse_bgp_update_extended_communities_evpn() {
        let mut val = vec![0x06, 0x00];
        val.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    #[test]
    fn parse_bgp_update_extended_communities_unknown() {
        let val = vec![0x99, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    #[test]
    fn parse_bgp_update_unknown_attribute() {
        let attr = build_attr(0xC0, 99, &[0xDE, 0xAD]);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let fields = buf.nested_fields(&obj_range);
        assert!(!fields.iter().any(|f| f.name() == "type_name"));
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&[0xDE, 0xAD])
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_ipv6_link_local() {
        let mut val = Vec::new();
        val.extend_from_slice(&2u16.to_be_bytes());
        val.push(1);
        val.push(32);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        val.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(0);
        val.push(48);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Object for MP_REACH");
        };
        assert_eq!(
            *nested_field_value(&buf, mp_range, "next_hop"),
            FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            *nested_field_value(&buf, mp_range, "next_hop_link_local"),
            FieldValue::Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn parse_bgp_update_extended_communities_ipv4_route_origin() {
        let mut val = vec![0x01, 0x03];
        val.extend_from_slice(&[10, 0, 0, 1]);
        val.extend_from_slice(&200u16.to_be_bytes());
        let attr = build_attr(0xC0, 16, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        let FieldValue::Array(ref comms_range) = *nested_field_value(&buf, &obj_range, "value")
        else {
            panic!("expected Array");
        };
        let comms = buf.nested_fields(comms_range);
        assert_eq!(comms.len(), 1);
        assert_eq!(comms[0].value, FieldValue::Bytes(&val[..]));
    }

    #[test]
    fn parse_bgp_prefix_sid_srv6_l2_service() {
        let mut sid_info_val = vec![0x00];
        sid_info_val.extend_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        sid_info_val.push(0x00);
        sid_info_val.extend_from_slice(&0x0014u16.to_be_bytes());
        sid_info_val.push(0x00);
        let sub_tlv = build_psid_tlv(1, &sid_info_val);
        let mut service_val = vec![0x00];
        service_val.extend_from_slice(&sub_tlv);
        let tlv = build_psid_tlv(6, &service_val);
        let attr = build_attr(0xC0 | 0x10, 40, &tlv);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let pa_value = extract_pa_value(&buf);
        let FieldValue::Array(tlvs_range) = pa_value else {
            panic!("expected Array");
        };
        let tlvs = buf.nested_fields(tlvs_range);
        assert!(tlvs[0].value.is_object());
        let FieldValue::Object(ref obj_range) = tlvs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, obj_range, "type"),
            FieldValue::U8(6)
        );
        let sub_tlvs_field = nested_field_by_name(&buf, obj_range, "sub_tlvs");
        let FieldValue::Array(ref subs_range) = sub_tlvs_field.value else {
            panic!("expected Array");
        };
        let subs = buf.nested_fields(subs_range);
        assert!(subs[0].value.is_object());
        let FieldValue::Object(ref si_range) = subs[0].value else {
            panic!("expected Object");
        };
        assert_eq!(
            *nested_field_value(&buf, si_range, "endpoint_behavior"),
            FieldValue::U16(0x0014)
        );
    }

    /// Helper: invoke a format_fn and return the output bytes as a String.
    fn call_format_fn(
        f: fn(&FieldValue<'_>, &FormatContext<'_>, &mut dyn std::io::Write) -> std::io::Result<()>,
        value: &FieldValue<'_>,
    ) -> String {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        f(value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn format_nlri_ipv4_prefix_cidr() {
        // /24 prefix: 192.168.1.0/24
        assert_eq!(
            call_format_fn(
                format_nlri_ipv4_prefix,
                &FieldValue::Bytes(&[24, 192, 168, 1])
            ),
            "\"192.168.1.0/24\""
        );
        // /32 host route: 10.0.0.1/32
        assert_eq!(
            call_format_fn(
                format_nlri_ipv4_prefix,
                &FieldValue::Bytes(&[32, 10, 0, 0, 1])
            ),
            "\"10.0.0.1/32\""
        );
        // /0 default route: 0.0.0.0/0
        assert_eq!(
            call_format_fn(format_nlri_ipv4_prefix, &FieldValue::Bytes(&[0])),
            "\"0.0.0.0/0\""
        );
        // /8 prefix: 10.0.0.0/8
        assert_eq!(
            call_format_fn(format_nlri_ipv4_prefix, &FieldValue::Bytes(&[8, 10])),
            "\"10.0.0.0/8\""
        );
        // Empty bytes → empty string
        assert_eq!(
            call_format_fn(format_nlri_ipv4_prefix, &FieldValue::Bytes(&[])),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(
            call_format_fn(format_nlri_ipv4_prefix, &FieldValue::U8(0)),
            "\"\""
        );
    }

    #[test]
    fn format_nlri_ipv6_prefix_cidr() {
        // /48 prefix: 2001:db8:1::/48
        assert_eq!(
            call_format_fn(
                format_nlri_ipv6_prefix,
                &FieldValue::Bytes(&[48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01])
            ),
            "\"2001:db8:1::/48\""
        );
        // /128 host route: 2001:db8::1/128
        let mut full = vec![128];
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 0x01;
        full.extend_from_slice(&addr);
        assert_eq!(
            call_format_fn(format_nlri_ipv6_prefix, &FieldValue::Bytes(&full)),
            "\"2001:db8::1/128\""
        );
        // /0 default route: ::/0
        assert_eq!(
            call_format_fn(format_nlri_ipv6_prefix, &FieldValue::Bytes(&[0])),
            "\"::/0\""
        );
        // Empty bytes → empty string
        assert_eq!(
            call_format_fn(format_nlri_ipv6_prefix, &FieldValue::Bytes(&[])),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(
            call_format_fn(format_nlri_ipv6_prefix, &FieldValue::U8(0)),
            "\"\""
        );
    }

    #[test]
    fn format_aggregator_values() {
        // 6-byte: 2-byte AS 65001 + IPv4 10.0.0.1
        assert_eq!(
            call_format_fn(
                format_aggregator,
                &FieldValue::Bytes(&[0xFD, 0xE9, 10, 0, 0, 1])
            ),
            "\"65001 10.0.0.1\""
        );
        // 8-byte: 4-byte AS 65001 + IPv4 10.0.0.1
        assert_eq!(
            call_format_fn(
                format_aggregator,
                &FieldValue::Bytes(&[0, 0, 0xFD, 0xE9, 10, 0, 0, 1])
            ),
            "\"65001 10.0.0.1\""
        );
        // Empty bytes → empty string
        assert_eq!(
            call_format_fn(format_aggregator, &FieldValue::Bytes(&[])),
            "\"\""
        );
        // Wrong size (7 bytes) → empty string
        assert_eq!(
            call_format_fn(
                format_aggregator,
                &FieldValue::Bytes(&[0, 0, 0, 0, 0, 0, 0])
            ),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(
            call_format_fn(format_aggregator, &FieldValue::U8(0)),
            "\"\""
        );
    }

    #[test]
    fn format_ext_community_values() {
        // Type 0x00: 2-Octet AS — AS 65001, value 100
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x00, 0x02, 0xFD, 0xE9, 0, 0, 0, 100])
            ),
            "\"65001:100\""
        );
        // Type 0x40: transitive 2-Octet AS — same format
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x40, 0x02, 0xFD, 0xE9, 0, 0, 0, 100])
            ),
            "\"65001:100\""
        );
        // Type 0x01: IPv4 Address — 10.0.0.1:100
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x01, 0x02, 10, 0, 0, 1, 0, 100])
            ),
            "\"10.0.0.1:100\""
        );
        // Type 0x41: transitive IPv4 Address
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x41, 0x02, 10, 0, 0, 1, 0, 100])
            ),
            "\"10.0.0.1:100\""
        );
        // Type 0x02: 4-Octet AS — AS 65001, value 100
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x02, 0x02, 0, 0, 0xFD, 0xE9, 0, 100])
            ),
            "\"65001:100\""
        );
        // Type 0x42: transitive 4-Octet AS
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x42, 0x02, 0, 0, 0xFD, 0xE9, 0, 100])
            ),
            "\"65001:100\""
        );
        // Unknown type → hex fallback
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            ),
            "\"0x0300010203040506\""
        );
        // Empty bytes → empty string
        assert_eq!(
            call_format_fn(format_ext_community, &FieldValue::Bytes(&[])),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(
            call_format_fn(format_ext_community, &FieldValue::U8(0)),
            "\"\""
        );
    }

    #[test]
    fn mup_extended_community_type_names() {
        assert_eq!(
            extended_community_type_name(0x0C, 0x00),
            Some("MUP Direct Segment (2-Octet AS)")
        );
        assert_eq!(
            extended_community_type_name(0x0C, 0x01),
            Some("MUP Direct Segment (IPv4 Address)")
        );
        assert_eq!(
            extended_community_type_name(0x0C, 0x02),
            Some("MUP Direct Segment (4-Octet AS)")
        );
        assert_eq!(
            extended_community_type_name(0x0C, 0x03),
            Some("MUP Interwork Segment (2-Octet AS)")
        );
        assert_eq!(
            extended_community_type_name(0x0C, 0x04),
            Some("MUP Interwork Segment (IPv4 Address)")
        );
        assert_eq!(
            extended_community_type_name(0x0C, 0x05),
            Some("MUP Interwork Segment (4-Octet AS)")
        );
        // Unknown sub-type → None
        assert_eq!(extended_community_type_name(0x0C, 0x06), None);
    }

    #[test]
    fn format_ext_community_mup_values() {
        // Sub-Type 0x00: 2-Octet AS Specific, Direct Segment — AS 65001, value 100
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x00, 0xFD, 0xE9, 0, 0, 0, 100])
            ),
            "\"65001:100\""
        );
        // Sub-Type 0x01: IPv4 Address Specific, Direct Segment — 10.0.0.1:100
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x01, 10, 0, 0, 1, 0, 100])
            ),
            "\"10.0.0.1:100\""
        );
        // Sub-Type 0x02: 4-Octet AS Specific, Direct Segment — AS 65001, value 100
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x02, 0, 0, 0xFD, 0xE9, 0, 100])
            ),
            "\"65001:100\""
        );
        // Sub-Type 0x03: 2-Octet AS Specific, Interwork Segment — AS 65002, value 200
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x03, 0xFD, 0xEA, 0, 0, 0, 200])
            ),
            "\"65002:200\""
        );
        // Sub-Type 0x04: IPv4 Address Specific, Interwork Segment — 10.0.0.2:200
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x04, 10, 0, 0, 2, 0, 200])
            ),
            "\"10.0.0.2:200\""
        );
        // Sub-Type 0x05: 4-Octet AS Specific, Interwork Segment — AS 65002, value 200
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x05, 0, 0, 0xFD, 0xEA, 0, 200])
            ),
            "\"65002:200\""
        );
        // Unknown sub-type → hex fallback
        assert_eq!(
            call_format_fn(
                format_ext_community,
                &FieldValue::Bytes(&[0x0C, 0x99, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            ),
            "\"0x0c99010203040506\""
        );
    }

    #[test]
    fn format_large_community_values() {
        // 65001:100:200
        assert_eq!(
            call_format_fn(
                format_large_community,
                &FieldValue::Bytes(&[0, 0, 0xFD, 0xE9, 0, 0, 0, 100, 0, 0, 0, 200])
            ),
            "\"65001:100:200\""
        );
        // 0:0:0
        assert_eq!(
            call_format_fn(
                format_large_community,
                &FieldValue::Bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            ),
            "\"0:0:0\""
        );
        // Empty bytes → empty string
        assert_eq!(
            call_format_fn(format_large_community, &FieldValue::Bytes(&[])),
            "\"\""
        );
        // Wrong size (8 bytes) → empty string
        assert_eq!(
            call_format_fn(
                format_large_community,
                &FieldValue::Bytes(&[0, 0, 0, 0, 0, 0, 0, 0])
            ),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(
            call_format_fn(format_large_community, &FieldValue::U8(0)),
            "\"\""
        );
    }

    #[test]
    fn format_route_distinguisher_values() {
        // Type 0: 2-byte ASN 65001 + 4-byte assigned 100
        assert_eq!(
            call_format_fn(
                format_route_distinguisher,
                &FieldValue::Bytes(&[0, 0, 0xFD, 0xE9, 0, 0, 0, 100])
            ),
            "\"0:65001:100\""
        );
        // Type 1: IPv4 10.0.0.1 + 2-byte assigned 100
        assert_eq!(
            call_format_fn(
                format_route_distinguisher,
                &FieldValue::Bytes(&[0, 1, 10, 0, 0, 1, 0, 100])
            ),
            "\"1:10.0.0.1:100\""
        );
        // Type 2: 4-byte ASN 65001 + 2-byte assigned 100
        assert_eq!(
            call_format_fn(
                format_route_distinguisher,
                &FieldValue::Bytes(&[0, 2, 0, 0, 0xFD, 0xE9, 0, 100])
            ),
            "\"2:65001:100\""
        );
        // Unknown type → hex fallback
        assert_eq!(
            call_format_fn(
                format_route_distinguisher,
                &FieldValue::Bytes(&[0, 3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            ),
            "\"3:0x010203040506\""
        );
        // Empty bytes → empty string
        assert_eq!(
            call_format_fn(format_route_distinguisher, &FieldValue::Bytes(&[])),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(
            call_format_fn(format_route_distinguisher, &FieldValue::U8(0)),
            "\"\""
        );
    }

    #[test]
    fn format_teid_values() {
        // 0x12345678
        assert_eq!(
            call_format_fn(format_teid, &FieldValue::Bytes(&[0x12, 0x34, 0x56, 0x78])),
            "\"0x12345678\""
        );
        // Zero
        assert_eq!(
            call_format_fn(format_teid, &FieldValue::Bytes(&[0, 0, 0, 0])),
            "\"0x00000000\""
        );
        // Empty bytes → empty string
        assert_eq!(call_format_fn(format_teid, &FieldValue::Bytes(&[])), "\"\"");
        // Wrong size (3 bytes) → empty string
        assert_eq!(
            call_format_fn(format_teid, &FieldValue::Bytes(&[1, 2, 3])),
            "\"\""
        );
        // Non-Bytes variant → empty string
        assert_eq!(call_format_fn(format_teid, &FieldValue::U8(0)), "\"\"");
    }

    // -- OPEN Capability decoding ------------------------------------------

    /// Helper: encode one Capability TLV as `[code, len, value...]`.
    fn cap_tlv(code: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![code, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// Helper: build a BGP OPEN message with a single Capability optional
    /// parameter (type=2) whose value is the concatenation of `caps`
    /// (already-encoded `[code, len, value...]` TLVs, see [`cap_tlv`]).
    fn build_open_with_caps(caps: &[u8]) -> Vec<u8> {
        let opt_params_len = 2 + caps.len(); // param header (type+len) + cap TLVs
        let total_len = 19 + 10 + opt_params_len;
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&(total_len as u16).to_be_bytes());
        raw.push(1); // Type = OPEN
        raw.push(4); // Version
        raw.extend_from_slice(&65001u16.to_be_bytes()); // My AS
        raw.extend_from_slice(&180u16.to_be_bytes()); // Hold Time
        raw.extend_from_slice(&[10, 0, 0, 1]); // BGP Identifier
        raw.push(opt_params_len as u8);
        raw.push(2); // Param Type = Capability
        raw.push(caps.len() as u8);
        raw.extend_from_slice(caps);
        raw
    }

    /// Helper: given a buffer dissected from [`build_open_with_caps`],
    /// return the child range of its single `optional_parameters`
    /// capability object. Returns an owned `Range<u32>` (not borrowed from
    /// `buf`), so callers keep using `buf` and this range side by side.
    fn single_capability_range(buf: &DissectBuffer<'_>) -> core::ops::Range<u32> {
        let layer = &buf.layers()[0];
        let params = buf.field_by_name(layer, "optional_parameters").unwrap();
        let FieldValue::Array(ref arr_range) = params.value else {
            panic!("expected Array");
        };
        // `build_open_with_caps` always encodes exactly one capability TLV,
        // so the array's first direct child is that capability object.
        // (Filtering `nested_fields` by `is_object()` would also match
        // nested `afi_safis` entry objects further down the flat buffer.)
        let first = buf
            .nested_fields(arr_range)
            .first()
            .expect("expected at least one field in optional_parameters");
        assert!(
            first.value.is_object(),
            "expected the capability object as the array's first child"
        );
        first.value.as_container_range().unwrap().clone()
    }

    /// Helper: look up an optional nested field by name; `None` if absent.
    fn nested_field_opt<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    #[test]
    fn parse_bgp_open_capability_multiprotocol() {
        // Code=1, AFI=1 (IPv4), Reserved=0, SAFI=85 (BGP-MUP).
        let caps = cap_tlv(1, &[0, 1, 0, 85]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(*nested_field_value(&buf, &range, "code"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("Multiprotocol Extensions for BGP-4")
        );
        assert_eq!(*nested_field_value(&buf, &range, "afi"), FieldValue::U16(1));
        assert_eq!(
            buf.resolve_nested_display_name(&range, "afi_name"),
            Some("IPv4")
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "safi"),
            FieldValue::U8(85)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&range, "safi_name"),
            Some("BGP-MUP")
        );
    }

    #[test]
    fn parse_bgp_open_capability_as4() {
        // Code=65, synthetic 4-octet ASN.
        let asn: u32 = 0x1234_5678;
        let caps = cap_tlv(65, &asn.to_be_bytes());
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("Support for 4-octet AS number capability")
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "asn"),
            FieldValue::U32(asn)
        );
    }

    #[test]
    fn parse_bgp_open_capability_add_path() {
        // Code=69, two tuples: (AFI=1,SAFI=85,SR=3) and (AFI=1,SAFI=128,SR=3).
        let mut value = Vec::new();
        value.extend_from_slice(&[0, 1, 85, 3]);
        value.extend_from_slice(&[0, 1, 128, 3]);
        let caps = cap_tlv(69, &value);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("ADD-PATH Capability")
        );
        let afi_safis = nested_field_by_name(&buf, &range, "afi_safis");
        let FieldValue::Array(ref arr_range) = afi_safis.value else {
            panic!("expected Array for afi_safis");
        };
        let entries = direct_children(&buf, arr_range);
        assert_eq!(entries.len(), 2);

        let e0 = entries[0].value.as_container_range().unwrap();
        assert_eq!(*nested_field_value(&buf, e0, "afi"), FieldValue::U16(1));
        assert_eq!(*nested_field_value(&buf, e0, "safi"), FieldValue::U16(85));
        assert_eq!(
            buf.resolve_nested_display_name(e0, "safi_name"),
            Some("BGP-MUP")
        );
        assert_eq!(
            *nested_field_value(&buf, e0, "send_receive"),
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.resolve_nested_display_name(e0, "send_receive_name"),
            Some("send-receive")
        );

        let e1 = entries[1].value.as_container_range().unwrap();
        assert_eq!(*nested_field_value(&buf, e1, "afi"), FieldValue::U16(1));
        assert_eq!(*nested_field_value(&buf, e1, "safi"), FieldValue::U16(128));
        assert_eq!(
            buf.resolve_nested_display_name(e1, "safi_name"),
            Some("MPLS-labeled VPN")
        );
        assert_eq!(
            *nested_field_value(&buf, e1, "send_receive"),
            FieldValue::U8(3)
        );
    }

    #[test]
    fn parse_bgp_open_capability_add_path_truncated() {
        // Code=69, length=3: not a multiple of 4, so the tuple is malformed
        // and must be left undecoded (raw `value` kept, no `afi_safis`).
        let caps = cap_tlv(69, &[0, 1, 85]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            *nested_field_value(&buf, &range, "value"),
            FieldValue::Bytes(&[0, 1, 85])
        );
        assert!(nested_field_opt(&buf, &range, "afi_safis").is_none());
    }

    #[test]
    fn parse_bgp_open_capability_paths_limit() {
        // Code=76, one tuple: AFI=1, SAFI=85, Paths Limit=100.
        let caps = cap_tlv(76, &[0, 1, 85, 0, 100]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("PATHS-LIMIT Capability")
        );
        let afi_safis = nested_field_by_name(&buf, &range, "afi_safis");
        let FieldValue::Array(ref arr_range) = afi_safis.value else {
            panic!("expected Array for afi_safis");
        };
        let entries = direct_children(&buf, arr_range);
        assert_eq!(entries.len(), 1);
        let e0 = entries[0].value.as_container_range().unwrap();
        assert_eq!(*nested_field_value(&buf, e0, "afi"), FieldValue::U16(1));
        assert_eq!(*nested_field_value(&buf, e0, "safi"), FieldValue::U16(85));
        assert_eq!(
            *nested_field_value(&buf, e0, "paths_limit"),
            FieldValue::U16(100)
        );
    }

    #[test]
    fn parse_bgp_open_capability_graceful_restart_with_afi_safi() {
        // Code=64. Restart Flags=0b1000 (R bit set), Restart Time=120,
        // one tuple: AFI=1, SAFI=85, Flags=0x80 (F bit set).
        let caps = cap_tlv(64, &[0x80, 120, 0, 1, 85, 0x80]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("Graceful Restart Capability")
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "restart_flags"),
            FieldValue::U8(8)
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "restart_time"),
            FieldValue::U16(120)
        );
        let afi_safis = nested_field_by_name(&buf, &range, "afi_safis");
        let FieldValue::Array(ref arr_range) = afi_safis.value else {
            panic!("expected Array for afi_safis");
        };
        let entries = direct_children(&buf, arr_range);
        assert_eq!(entries.len(), 1);
        let e0 = entries[0].value.as_container_range().unwrap();
        assert_eq!(*nested_field_value(&buf, e0, "afi"), FieldValue::U16(1));
        assert_eq!(*nested_field_value(&buf, e0, "safi"), FieldValue::U16(85));
        assert_eq!(*nested_field_value(&buf, e0, "flags"), FieldValue::U8(0x80));
    }

    #[test]
    fn parse_bgp_open_capability_graceful_restart_without_afi_safi() {
        // Code=64, 2-byte value: Restart Flags=0, Restart Time=0. No
        // AFI/SAFI list, so `afi_safis` must be absent entirely.
        let caps = cap_tlv(64, &[0, 0]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            *nested_field_value(&buf, &range, "restart_flags"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "restart_time"),
            FieldValue::U16(0)
        );
        assert!(nested_field_opt(&buf, &range, "afi_safis").is_none());
    }

    #[test]
    fn parse_bgp_open_capability_llgr() {
        // Code=71, one tuple: AFI=1, SAFI=85, Flags=0x80, Stale Time=300.
        let mut value = vec![0, 1, 85, 0x80];
        value.extend_from_slice(&300u32.to_be_bytes()[1..]); // u24
        let caps = cap_tlv(71, &value);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("Long-Lived Graceful Restart (LLGR) Capability")
        );
        let afi_safis = nested_field_by_name(&buf, &range, "afi_safis");
        let FieldValue::Array(ref arr_range) = afi_safis.value else {
            panic!("expected Array for afi_safis");
        };
        let entries = direct_children(&buf, arr_range);
        assert_eq!(entries.len(), 1);
        let e0 = entries[0].value.as_container_range().unwrap();
        assert_eq!(*nested_field_value(&buf, e0, "afi"), FieldValue::U16(1));
        assert_eq!(*nested_field_value(&buf, e0, "safi"), FieldValue::U16(85));
        assert_eq!(*nested_field_value(&buf, e0, "flags"), FieldValue::U8(0x80));
        assert_eq!(
            *nested_field_value(&buf, e0, "stale_time"),
            FieldValue::U32(300)
        );
    }

    #[test]
    fn parse_bgp_open_capability_extended_next_hop() {
        // Code=5, one tuple: NLRI AFI=1, NLRI SAFI=1, Nexthop AFI=2.
        let caps = cap_tlv(5, &[0, 1, 0, 1, 0, 2]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("Extended Next Hop Encoding")
        );
        let afi_safis = nested_field_by_name(&buf, &range, "afi_safis");
        let FieldValue::Array(ref arr_range) = afi_safis.value else {
            panic!("expected Array for afi_safis");
        };
        let entries = direct_children(&buf, arr_range);
        assert_eq!(entries.len(), 1);
        let e0 = entries[0].value.as_container_range().unwrap();
        assert_eq!(*nested_field_value(&buf, e0, "afi"), FieldValue::U16(1));
        // safi is 2 octets for this capability (unlike the others).
        assert_eq!(*nested_field_value(&buf, e0, "safi"), FieldValue::U16(1));
        assert_eq!(
            buf.resolve_nested_display_name(e0, "safi_name"),
            Some("Unicast")
        );
        assert_eq!(
            *nested_field_value(&buf, e0, "next_hop_afi"),
            FieldValue::U16(2)
        );
        assert_eq!(
            buf.resolve_nested_display_name(e0, "next_hop_afi_name"),
            Some("IPv6")
        );
    }

    #[test]
    fn parse_bgp_open_capability_role() {
        // Code=9, Role=2 (RS-Client).
        let caps = cap_tlv(9, &[2]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("BGP Role")
        );
        assert_eq!(*nested_field_value(&buf, &range, "role"), FieldValue::U8(2));
        assert_eq!(
            buf.resolve_nested_display_name(&range, "role_name"),
            Some("RS-Client")
        );
    }

    #[test]
    fn parse_bgp_open_capability_fqdn() {
        // Code=73: Hostname="rtr1", Domain Name="lab.example".
        let hostname = b"rtr1";
        let domain = b"lab.example";
        let mut value = vec![hostname.len() as u8];
        value.extend_from_slice(hostname);
        value.push(domain.len() as u8);
        value.extend_from_slice(domain);
        let caps = cap_tlv(73, &value);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("FQDN Capability")
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "hostname"),
            FieldValue::Str("rtr1")
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "domain_name"),
            FieldValue::Str("lab.example")
        );
    }

    #[test]
    fn parse_bgp_open_capability_fqdn_zero_length_domain_omitted() {
        // Hostname="rtr1", Domain Name Length=0 → domain_name omitted.
        let hostname = b"rtr1";
        let mut value = vec![hostname.len() as u8];
        value.extend_from_slice(hostname);
        value.push(0);
        let caps = cap_tlv(73, &value);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            *nested_field_value(&buf, &range, "hostname"),
            FieldValue::Str("rtr1")
        );
        assert!(nested_field_opt(&buf, &range, "domain_name").is_none());
    }

    #[test]
    fn parse_bgp_open_capability_unknown_code() {
        // Code=200 is unassigned in the IANA Capability Codes registry.
        let caps = cap_tlv(200, &[1, 2, 3]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);

        assert_eq!(
            *nested_field_value(&buf, &range, "code"),
            FieldValue::U8(200)
        );
        assert_eq!(buf.resolve_nested_display_name(&range, "code_name"), None);
        assert_eq!(
            *nested_field_value(&buf, &range, "value"),
            FieldValue::Bytes(&[1, 2, 3])
        );
        assert!(nested_field_opt(&buf, &range, "afi").is_none());
        assert!(nested_field_opt(&buf, &range, "afi_safis").is_none());
    }

    #[test]
    fn parse_bgp_open_capability_zero_length_code_names() {
        // Route Refresh (2) / BGP Extended Message (6) / Enhanced Route
        // Refresh (70) / deprecated Route Refresh (128) carry no Capability
        // Value: only `code`/`length` plus the resolved `code_name`.
        let cases: [(u8, &str); 4] = [
            (2, "Route Refresh Capability for BGP-4"),
            (6, "BGP Extended Message"),
            (70, "Enhanced Route Refresh Capability"),
            (128, "Prestandard Route Refresh (deprecated)"),
        ];
        for (code, name) in cases {
            let caps = cap_tlv(code, &[]);
            let data = build_open_with_caps(&caps);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            let range = single_capability_range(&buf);

            assert_eq!(
                *nested_field_value(&buf, &range, "length"),
                FieldValue::U8(0)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&range, "code_name"),
                Some(name),
                "code {code}"
            );
            assert!(nested_field_opt(&buf, &range, "value").is_none());
        }
    }

    #[test]
    fn bgp_optional_parameters_schema_has_afi_safis_send_receive() {
        // `optional_parameters`'s declared children must include `afi_safis`,
        // whose own children must include `send_receive` — the shape an LLM
        // client needs to discover without dissecting a live packet.
        let afi_safis = OPT_PARAM_CHILDREN
            .iter()
            .find(|f| f.name == "afi_safis")
            .expect("optional_parameters children must include afi_safis");
        let afi_safi_children = afi_safis
            .children
            .expect("afi_safis descriptor must declare children");
        assert!(
            afi_safi_children.iter().any(|f| f.name == "send_receive"),
            "afi_safis children must include send_receive"
        );
        assert!(afi_safi_children.iter().any(|f| f.name == "paths_limit"));
        assert!(afi_safi_children.iter().any(|f| f.name == "stale_time"));
        assert!(afi_safi_children.iter().any(|f| f.name == "next_hop_afi"));

        // The union also covers non-capability optional parameters.
        let param_type = OPT_PARAM_CHILDREN
            .iter()
            .find(|f| f.name == "param_type")
            .expect("optional_parameters children must include param_type");
        assert_eq!(
            param_type.name,
            NON_CAP_PARAM_CHILDREN[FD_NCP_PARAM_TYPE].name
        );
    }
}
