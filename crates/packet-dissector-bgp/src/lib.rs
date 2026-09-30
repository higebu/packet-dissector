//! BGP-4 (Border Gateway Protocol version 4) dissector.
//!
//! ## References
//! - RFC 4271 (BGP-4): <https://www.rfc-editor.org/rfc/rfc4271>
//! - RFC 1997 (Communities): <https://www.rfc-editor.org/rfc/rfc1997>
//! - RFC 2918 (Route Refresh): <https://www.rfc-editor.org/rfc/rfc2918>
//! - RFC 2545 (BGP-4 Multiprotocol Extensions for IPv6): <https://www.rfc-editor.org/rfc/rfc2545>
//! - RFC 4360 (Extended Communities): <https://www.rfc-editor.org/rfc/rfc4360>
//! - RFC 4577 (OSPF as the PE/CE Protocol / OSPF Extended Communities): <https://www.rfc-editor.org/rfc/rfc4577>
//! - RFC 5668 (4-Octet AS Specific Extended Community): <https://www.rfc-editor.org/rfc/rfc5668>
//! - RFC 5701 (IPv6 Address Specific Extended Community): <https://www.rfc-editor.org/rfc/rfc5701>
//! - RFC 7153 (IANA Registries for BGP Extended Communities): <https://www.rfc-editor.org/rfc/rfc7153>
//! - RFC 7432 (BGP MPLS-Based Ethernet VPN): <https://www.rfc-editor.org/rfc/rfc7432>
//! - RFC 8097 (BGP Prefix Origin Validation State Extended Community): <https://www.rfc-editor.org/rfc/rfc8097>
//! - RFC 8955 (Dissemination of Flow Specification Rules): <https://www.rfc-editor.org/rfc/rfc8955>
//! - RFC 9135 (Integrated Routing and Bridging in EVPN): <https://www.rfc-editor.org/rfc/rfc9135>
//! - RFC 10005 (BGP Link Bandwidth Extended Community): <https://www.rfc-editor.org/rfc/rfc10005>
//! - IANA BGP Extended Communities: <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml>
//! - RFC 4364 (BGP/MPLS IP VPNs): <https://www.rfc-editor.org/rfc/rfc4364>
//! - RFC 4456 (Route Reflection): <https://www.rfc-editor.org/rfc/rfc4456>
//! - RFC 4486 (Cease NOTIFICATION subcodes): <https://www.rfc-editor.org/rfc/rfc4486>
//! - RFC 4659 (BGP-MPLS IP VPN Extension for IPv6 VPN): <https://www.rfc-editor.org/rfc/rfc4659>
//! - RFC 4684 (Constrained Route Distribution for BGP/MPLS IP VPNs): <https://www.rfc-editor.org/rfc/rfc4684>
//! - RFC 4724 (Graceful Restart Capability): <https://www.rfc-editor.org/rfc/rfc4724>
//! - RFC 4761 (VPLS Using BGP for Auto-Discovery and Signaling): <https://www.rfc-editor.org/rfc/rfc4761>
//! - RFC 6074 (Provisioning, Auto-Discovery, and Signaling in L2VPNs): <https://www.rfc-editor.org/rfc/rfc6074>
//! - RFC 6368 (Internal BGP as PE-CE Protocol / ATTR_SET): <https://www.rfc-editor.org/rfc/rfc6368>
//! - RFC 6514 (BGP Encodings for Multicast in MPLS/BGP IP VPNs / PMSI Tunnel): <https://www.rfc-editor.org/rfc/rfc6514>
//! - RFC 6515 (IPv4 and IPv6 Infrastructure Addresses in BGP Updates for Multicast VPN): <https://www.rfc-editor.org/rfc/rfc6515>
//! - RFC 6625 (Wildcards in Multicast VPN Auto-Discovery Routes): <https://www.rfc-editor.org/rfc/rfc6625>
//! - RFC 7441 (Encoding mLDP FECs in the NLRI of BGP MCAST-VPN Routes): <https://www.rfc-editor.org/rfc/rfc7441>
//! - RFC 7524 (Inter-Area P2MP Segmented LSPs / Global Table Multicast Leaf A-D routes): <https://www.rfc-editor.org/rfc/rfc7524>
//! - RFC 7311 (Accumulated IGP Metric Attribute): <https://www.rfc-editor.org/rfc/rfc7311>
//! - RFC 8205 (BGPsec Protocol Specification): <https://www.rfc-editor.org/rfc/rfc8205>
//! - RFC 8365 (Network Virtualization Overlay Solution Using EVPN): <https://www.rfc-editor.org/rfc/rfc8365>
//! - RFC 7432 (BGP MPLS-Based Ethernet VPN): <https://www.rfc-editor.org/rfc/rfc7432>
//! - RFC 9136 (IP Prefix Advertisement in EVPN): <https://www.rfc-editor.org/rfc/rfc9136>
//! - RFC 9135 (Integrated Routing and Bridging in EVPN): <https://www.rfc-editor.org/rfc/rfc9135>
//! - RFC 9251 (IGMP and MLD Proxies for EVPN): <https://www.rfc-editor.org/rfc/rfc9251>
//! - RFC 9572 (Updates to EVPN Broadcast, Unknown Unicast, or Multicast (BUM) Procedures): <https://www.rfc-editor.org/rfc/rfc9572>
//! - IANA EVPN Route Types: <https://www.iana.org/assignments/evpn/evpn.xhtml>
//! - RFC 8955 (Dissemination of Flow Specification Rules): <https://www.rfc-editor.org/rfc/rfc8955>
//! - RFC 8956 (Dissemination of Flow Specification Rules for IPv6): <https://www.rfc-editor.org/rfc/rfc8956>
//! - IANA Flow Spec Component Types: <https://www.iana.org/assignments/flow-spec/flow-spec.xhtml>
//! - RFC 9514 (BGP-LS Extensions for SRv6): <https://www.rfc-editor.org/rfc/rfc9514>
//! - RFC 9857 (Advertisement of SR Policies Using BGP-LS): <https://www.rfc-editor.org/rfc/rfc9857>
//! - RFC 9086 (BGP-LS Extensions for Segment Routing BGP Egress Peer Engineering): <https://www.rfc-editor.org/rfc/rfc9086>
//! - RFC 9015 (BGP Control Plane for the Network Service Header / SFP attribute): <https://www.rfc-editor.org/rfc/rfc9015>
//! - RFC 9026 (Multicast VPN Fast Upstream Failover / BFD Discriminator): <https://www.rfc-editor.org/rfc/rfc9026>
//! - RFC 9552 (BGP-LS): <https://www.rfc-editor.org/rfc/rfc9552>
//! - RFC 9830 (Advertising Segment Routing Policies in BGP): <https://www.rfc-editor.org/rfc/rfc9830>
//! - RFC 4760 (Multiprotocol Extensions): <https://www.rfc-editor.org/rfc/rfc4760>
//! - RFC 5492 (Capabilities Advertisement with BGP-4): <https://www.rfc-editor.org/rfc/rfc5492>
//! - RFC 5065 (AS Confederations): <https://www.rfc-editor.org/rfc/rfc5065>
//! - RFC 6793 (4-octet AS Numbers): <https://www.rfc-editor.org/rfc/rfc6793>
//! - RFC 7606 (Revised Error Handling for BGP UPDATE Messages): <https://www.rfc-editor.org/rfc/rfc7606>
//! - RFC 7313 (Enhanced Route Refresh): <https://www.rfc-editor.org/rfc/rfc7313>
//! - RFC 7911 (ADD-PATH Capability): <https://www.rfc-editor.org/rfc/rfc7911>
//! - RFC 8092 (Large Communities): <https://www.rfc-editor.org/rfc/rfc8092>
//! - RFC 9003 (Extended BGP Administrative Shutdown Communication, obsoletes RFC 8203): <https://www.rfc-editor.org/rfc/rfc9003>
//! - RFC 8538 (Notification Message Support for BGP Graceful Restart / Hard Reset): <https://www.rfc-editor.org/rfc/rfc8538>
//! - RFC 9384 (BFD Down Cease NOTIFICATION subcode): <https://www.rfc-editor.org/rfc/rfc9384>
//! - RFC 6608 (Subcodes for BGP Finite State Machine Error): <https://www.rfc-editor.org/rfc/rfc6608>
//! - RFC 5291 (Outbound Route Filtering Capability): <https://www.rfc-editor.org/rfc/rfc5291>
//! - RFC 5292 (Address-Prefix-Based Outbound Route Filter): <https://www.rfc-editor.org/rfc/rfc5292>
//! - RFC 8205 (BGPsec Protocol Specification / BGPsec Capability): <https://www.rfc-editor.org/rfc/rfc8205>
//! - IANA BGP Parameters (Error Subcodes, ORF Types): <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml>
//! - RFC 8277 (Using BGP to Bind MPLS Labels to Address Prefixes): <https://www.rfc-editor.org/rfc/rfc8277>
//! - RFC 8654 (Extended Message): <https://www.rfc-editor.org/rfc/rfc8654>
//! - RFC 8669 (BGP Prefix-SID): <https://www.rfc-editor.org/rfc/rfc8669>
//! - RFC 8950 (Extended Next Hop Encoding Capability): <https://www.rfc-editor.org/rfc/rfc8950>
//! - RFC 9012 (Tunnel Encapsulation / Color): <https://www.rfc-editor.org/rfc/rfc9012>
//! - RFC 9072 (Extended Optional Parameters Length): <https://www.rfc-editor.org/rfc/rfc9072>
//! - RFC 9234 (BGP Role Capability / OTC attribute): <https://www.rfc-editor.org/rfc/rfc9234>
//! - RFC 9252 (SRv6 BGP Services): <https://www.rfc-editor.org/rfc/rfc9252>
//! - RFC 9494 (Long-Lived Graceful Restart Capability): <https://www.rfc-editor.org/rfc/rfc9494>
//! - IANA Capability Codes: <https://www.iana.org/assignments/capability-codes/capability-codes.xhtml>
//! - IANA BGP Parameters: <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml>
//! - IANA BGP Tunnel Encapsulation: <https://www.iana.org/assignments/bgp-tunnel-encapsulation/bgp-tunnel-encapsulation.xhtml>
//! - IANA BGP-LS Parameters: <https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml>
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
//! | 4.1 | AS_PATH with 4-octet AS numbers | `parse_bgp_update_as_path_four_octet`, `parse_bgp_update_as_path_four_octet_multi_segment` |
//! | 4.1 | AS_PATH with 2-octet AS numbers (not valid as 4-octet) | `parse_bgp_update_as_path_two_octet_size`, `parse_bgp_update_as_path_two_octet_multi_segment` |
//! | 4.1 | AS_PATH valid for both sizes decodes as 4-octet | `parse_bgp_update_as_path_ambiguous_prefers_four_octet` |
//! | 4.1 | Empty AS_PATH has no inferred AS number size | `parse_bgp_update_as_path_empty` |
//! | 4.2.2 | AS4_PATH in the UPDATE selects 2-octet AS_PATH | `parse_bgp_update_as_path_two_octet_hint_from_as4_path` |
//! | 4.2.2 | AS4_AGGREGATOR in the UPDATE selects 2-octet AS_PATH | `parse_bgp_update_as_path_two_octet_hint_from_as4_aggregator` |
//! | 4.1 | AGGREGATOR length (6 / 8) selects the AS_PATH AS number size | `parse_bgp_update_as_path_size_hint_from_aggregator_length` |
//! | 4.1 | A hint that does not fit the AS_PATH is ignored | `parse_bgp_update_as_path_hint_ignored_when_it_does_not_fit` |
//! | 4.1 | AS number size known from the encapsulating protocol (e.g. BMP) | `dissect_message_known_two_octet_as_size`, `dissect_message_known_four_octet_as_size_overrides_inference`, `dissect_message_known_size_that_does_not_fit_falls_back` |
//! | 3 | Malformed AS4_PATH kept as raw bytes | `parse_bgp_update_as4_path_malformed_is_raw` |
//!
//! # RFC 7606 (Revised Error Handling) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 7.2 | AS_PATH segment validation (type, zero length, overrun, underrun) | `as_path_fits_checks_structure` |
//! | 7.2 | AS_PATH malformed for both AS sizes kept as raw bytes | `parse_bgp_update_as_path_malformed_is_raw` |
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
//! # NOTIFICATION Coverage (RFC 4486 / RFC 9003 / RFC 8538 / RFC 9384 / RFC 6608 / RFC 7313)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 4486 §4; RFC 8538 §3 | Cease subcodes 1–9; subcodes of other codes not read as Cease | `parse_bgp_notification_cease_subcode_name` |
//! | RFC 4271 §6.1-6.3; RFC 6608 §4; RFC 7313 §5; RFC 9384 §3 | Error Subcode names for every Error Code | `notification_subcode_names` |
//! | RFC 9003 §2 | Shutdown Communication (UTF-8, zero length, invalid UTF-8, overrun) | `parse_bgp_notification_shutdown_communication` |
//! | RFC 8538 §3.1 | Hard Reset encapsulated Error Code / Subcode / Data | `parse_bgp_notification_hard_reset` |
//!
//! # RFC 5291 / RFC 5292 (ORF) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 5291 §5 | Outbound Route Filtering Capability | `parse_bgp_open_capability_orf` |
//! | RFC 5291 §5 | Malformed ORF Capability left undecoded | `parse_bgp_open_capability_orf_malformed_is_raw` |
//! | RFC 5291 §4; RFC 5292 §3 | ROUTE-REFRESH When-to-refresh and Address Prefix ORF entries (ADD, REMOVE-ALL) | `parse_bgp_route_refresh_address_prefix_orf` |
//! | RFC 5291 §4; RFC 5292 §3 | IPv6 Address Prefix ORF entry and undecoded ORF type | `parse_bgp_route_refresh_orf_other_types` |
//! | RFC 5291 §4; RFC 7313 §4 | Malformed ORFs and BoRR trailing octets kept as `data` | `parse_bgp_route_refresh_malformed_orf_is_raw` |
//! | RFC 5291 §4-5 | ORF, When-to-refresh, Action, Match and BGPsec Direction name tables | `open_notification_refresh_name_tables` |
//!
//! # Message Type Coverage (RFC 4271 §4.4, §6.1)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 4.4, 6.1 | Unknown message type / long KEEPALIVE body kept as `data` | `parse_bgp_unknown_message_type_keeps_body` |
//!
//! # Extended Communities Coverage (RFC 4360 / RFC 7153 / RFC 5701 / RFC 9012 / RFC 7432 / RFC 9135 / RFC 8955 / RFC 4577 / RFC 10005 / RFC 8097)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 4360 §2, §3.1; RFC 9012 §4.3 | Type / Sub-Type objects: Route Target, Color | `parse_bgp_update_extended_communities` |
//! | RFC 4360 §3.1-3.2; RFC 5668 §2; RFC 8955 §7.4; RFC 4577 §4.2.6 | Global / Local Administrator layouts (RT, RO, OSPF Router ID, rt-redirect) | `parse_bgp_update_extended_communities_admin_layouts` |
//! | RFC 10005 §2 | Link Bandwidth (IEEE 754 bytes per second) | `parse_bgp_update_extended_communities_link_bandwidth` |
//! | RFC 7432 §7.5-7.7; RFC 9135 §8.1 | EVPN MAC Mobility, ESI Label, ES-Import RT, Router's MAC | `parse_bgp_update_extended_communities_evpn` |
//! | RFC 9012 §4.1; RFC 7432 §7.8; RFC 4577 §4.2.6; RFC 8097 §2 | Encapsulation, Default Gateway, OSPF Route Type / Domain ID, Origin Validation State | `parse_bgp_update_extended_communities_opaque_and_ospf` |
//! | RFC 8955 §7.1-7.5 | Flow spec traffic-rate, traffic-action, traffic-marking | `parse_bgp_update_extended_communities_flowspec_actions` |
//! | RFC 4360 §2 | Unknown type; length not a multiple of 8 kept raw | `parse_bgp_update_extended_communities_unknown` |
//! | RFC 5701 §2 | IPv6 Address Specific Extended Community | `parse_bgp_update_ipv6_address_specific_extended_community` |
//! | RFC 7153 §5 | Type / Sub-Type name tables, IEEE 754 formatting | `extended_community_name_tables` |
//!
//! # RFC 4456 (Route Reflection) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | 8 | ORIGINATOR_ID | `parse_bgp_update_originator_id` |
//! | 8 | CLUSTER_LIST | `parse_bgp_update_cluster_list` |
//!
//! # Path Attribute Value Coverage (RFC 9234 / RFC 7311 / RFC 6514 / RFC 8365 / RFC 9012 / RFC 9552 / RFC 8205 / RFC 6368 / RFC 9015 / RFC 9026)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 9234 §5 | OTC (AS number) | `parse_bgp_update_otc` |
//! | RFC 9234 §5 | OTC with a length other than 4 kept as raw bytes | `parse_bgp_update_otc_bad_length_is_raw` |
//! | RFC 7311 §3 | AIGP TLV (u64 metric) and unknown TLV | `parse_bgp_update_aigp` |
//! | RFC 7311 §3.2 | Malformed AIGP TLVs kept as raw bytes | `parse_bgp_update_aigp_malformed_is_raw` |
//! | RFC 6514 §5 | PMSI Tunnel, Ingress Replication endpoint (IPv4 / IPv6) | `parse_bgp_update_pmsi_tunnel_ingress_replication`, `parse_bgp_update_pmsi_tunnel_ingress_replication_ipv6` |
//! | RFC 6514 §5 | Other Tunnel Identifiers kept as bytes | `parse_bgp_update_pmsi_tunnel_other_type_keeps_identifier_bytes` |
//! | RFC 6514 §5 | No tunnel information; truncated attribute kept raw | `parse_bgp_update_pmsi_tunnel_no_identifier_and_truncated` |
//! | RFC 8365 §5.1.3 | PMSI MPLS Label field as a 24-bit VNI with VXLAN / NVGRE / VXLAN GPE | `parse_bgp_update_pmsi_tunnel_vni_with_vxlan_encapsulation` |
//! | RFC 9012 §4.1 | Encapsulation Extended Community scan | `attr_context_scans_encapsulation_community` |
//! | RFC 9012 §2, §3.1, §3.2, §3.3.2, §3.4.1, §3.4.2 | Tunnel TLVs and sub-TLVs (1- and 2-octet lengths) | `parse_bgp_update_tunnel_encapsulation` |
//! | RFC 9012 §3.1, §3.4.2 | Egress Endpoint AF 0 / IPv6 / malformed, unrecognized Color | `parse_bgp_update_tunnel_encapsulation_sub_tlv_variants` |
//! | RFC 9012 §13 | Overrunning TLVs / sub-TLVs kept as raw bytes | `parse_bgp_update_tunnel_encapsulation_malformed_is_raw` |
//! | RFC 9552 §5.1, §5.3 | BGP-LS Attribute TLVs | `parse_bgp_update_bgp_ls_attribute` |
//! | RFC 9552 §5.1 | Malformed BGP-LS Attribute kept as raw bytes | `parse_bgp_update_bgp_ls_attribute_malformed_is_raw` |
//! | RFC 8205 §3.1, §3.2 | BGPsec_Path Secure_Path and Signature_Block | `parse_bgp_update_bgpsec_path` |
//! | RFC 8205 §3 | Malformed BGPsec_Path kept as raw bytes | `parse_bgp_update_bgpsec_path_malformed_is_raw` |
//! | RFC 6368 §5 | ATTR_SET Origin AS + nested attributes (4-octet AS_PATH) | `parse_bgp_update_attr_set` |
//! | RFC 6368 §5 | ATTR_SET carrying MP_REACH_NLRI / MP_UNREACH_NLRI kept raw | `parse_bgp_update_attr_set_with_mp_reach_is_raw` |
//! | RFC 6368 §5 | Nested ATTR_SET, 2-octet AS_PATH / AGGREGATOR inside ATTR_SET kept raw | `parse_bgp_update_attr_set_nested_attributes_constrained` |
//! | RFC 6368 §5 | ATTR_SET shorter than 4 octets / bad nested attribute kept raw | `parse_bgp_update_attr_set_malformed_is_raw` |
//! | RFC 9015 §3.2.1 | SFP attribute TLVs; overrunning TLV kept raw | `parse_bgp_update_sfp_attribute` |
//! | RFC 9026 §3.1.6 | BFD Discriminator with Source IP Address TLV | `parse_bgp_update_bfd_discriminator` |
//! | RFC 9026 §3.1.6 | Malformed BFD Discriminator (including a Source IP Address TLV Length other than 4 / 16) kept as raw bytes | `parse_bgp_update_bfd_discriminator_malformed_is_raw` |
//! | IANA BGP Parameters | Path attribute, PMSI, tunnel, BGP-LS, AIGP, SFP, BFD name tables | `path_attribute_value_name_tables` |
//! | RFC 4271 §4.3 | Schema of the new `value` union members | `field_schema_exposes_new_path_attribute_value_children` |
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
//! | 3 | UPDATE top-level afi/safi mirrors first MP_REACH_NLRI | `parse_bgp_update_top_level_afi_safi_from_mp_reach` |
//! | 4 | UPDATE top-level afi/safi mirrors MP_UNREACH_NLRI when it is the only MP attribute | `parse_bgp_update_top_level_afi_safi_from_mp_unreach_only` |
//! | 3/4 | UPDATE top-level afi/safi: first MP attribute in attribute order wins | `parse_bgp_update_top_level_afi_safi_first_attribute_wins` |
//! | 3/4 | Plain IPv4 unicast UPDATE (no MP attribute) has no top-level afi/safi | `parse_bgp_update_plain_ipv4_unicast_has_no_top_level_afi_safi` |
//! | 5 | Plain prefix NLRI for SAFI 2 (multicast) | `parse_bgp_update_mp_reach_ipv4_multicast_prefixes` |
//! | 3 | Non-prefix SAFI of AFI 1 (MDT) NLRI kept as raw bytes | `parse_bgp_update_mp_reach_unsupported_ip_safi_is_raw` |
//! | 4 | Non-prefix SAFI of AFI 1 (MDT) withdrawn routes kept as raw bytes | `parse_bgp_update_mp_unreach_unsupported_ip_safi_is_raw` |
//! | 5 | Malformed tail of a prefix NLRI block kept as raw bytes | `parse_bgp_update_mp_reach_prefix_tail_is_raw` |
//! | 5 | Prefix withdrawn routes that do not decode kept as raw bytes | `parse_bgp_update_mp_unreach_invalid_prefixes_are_raw` |
//!
//! # EVPN NLRI Coverage (RFC 7432 / RFC 9136 / RFC 8365)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 7432 §7, §7.3 | Inclusive Multicast Ethernet Tag route | `parse_bgp_update_mp_reach_evpn_imet` |
//! | RFC 7432 §9.2.1 | IPv4 / IPv6 MP_REACH_NLRI next hop for AFI 25 | `parse_bgp_update_mp_reach_evpn_next_hop` |
//! | RFC 7432 §7.2; RFC 9135 | MAC/IP Advertisement (IPv4, IPv6 with Label2, MAC only) | `parse_bgp_update_mp_reach_evpn_mac_ip` |
//! | RFC 7432 §7.1, §7.4; RFC 9136 §3.1 | Ethernet A-D, Ethernet Segment, IPv4 / IPv6 IP Prefix routes | `parse_bgp_update_mp_reach_evpn_ead_es_ip_prefix` |
//! | RFC 8365 §5.1.3 | MPLS Label fields as VNIs with a VXLAN Encapsulation Extended Community | `parse_bgp_update_mp_reach_evpn_vni_with_vxlan_encapsulation` |
//! | RFC 7432 §7 | Undecoded Route Type / layout mismatch kept as `value` | `parse_bgp_update_mp_reach_evpn_undecoded_routes_keep_value`, `parse_bgp_update_mp_reach_evpn_layout_mismatches_keep_value` |
//! | RFC 7432 §9.2.1 | VPN-shaped next hop for AFI 25 kept raw | `parse_bgp_update_mp_reach_l2vpn_vpn_safi_next_hop_is_raw` |
//! | RFC 7432 §7 | NLRI union `route_type` names MUP or EVPN routes | `nlri_union_route_type_name_follows_the_entry_kind` |
//! | RFC 7432 §7 | EVPN routes in MP_UNREACH_NLRI | `parse_bgp_update_mp_unreach_evpn_withdrawn` |
//! | RFC 7911 §3 | ADD-PATH EVPN block; truncated tail kept as `nlri_raw` | `parse_bgp_update_mp_reach_evpn_add_path_and_truncated_tail`, `detect_add_path_evpn_prefers_plain_encoding` |
//! | IANA EVPN Route Types | Route Type names, ESI formatting | `evpn_name_tables` |
//!
//! # Flow Specification NLRI Coverage (RFC 8955 / RFC 8956)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 8955 §4.2, §4.2.1, §4.3.1-4.3.3 | IPv4 rules: prefixes, numeric and bitmask operators (examples 1-3) | `parse_bgp_update_mp_reach_flowspec_ipv4_examples` |
//! | RFC 8956 §3.1, §3.7, §3.8.2 | IPv6 prefixes with and without offset, TCP Flags, Flow Label | `parse_bgp_update_mp_reach_flowspec_ipv6_examples` |
//! | RFC 8955 §4.1, §8 | SAFI 134 RD; extended 2-octet length | `parse_bgp_update_mp_reach_flowspec_vpn_and_extended_length` |
//! | RFC 8955 §4.2 | Malformed rules (unknown type, order, no end-of-list, prefix length) kept as `value`; overrun kept raw | `parse_bgp_update_mp_reach_flowspec_malformed_rules_keep_value` |
//! | RFC 8955 §4 | Rules in MP_UNREACH_NLRI | `parse_bgp_update_mp_unreach_flowspec_withdrawn` |
//! | RFC 8955 §4.2, §4.2.1.1 | Rule without components malformed; first operator AND bit unset | `parse_bgp_update_mp_reach_flowspec_empty_rules_and_first_and_bit` |
//! | RFC 7911 §3 | ADD-PATH Flow Specification block | `parse_bgp_update_mp_reach_flowspec_add_path` |
//! | IANA Flow Spec Component Types | Component and comparison names | `flowspec_name_tables` |
//!
//! # BGP-LS NLRI Coverage (RFC 9552)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | §5.2, §5.2.1-5.2.3 | Node, Link and IPv4 Prefix NLRI: Protocol-ID, Identifier, descriptor TLVs, Node Descriptor sub-TLVs | `parse_bgp_update_mp_reach_bgp_ls_node_link_prefix` |
//! | §5.2 | SAFI 72 RD; unknown NLRI type, overrunning descriptors and truncated body kept as `value` | `parse_bgp_update_mp_reach_bgp_ls_vpn_unknown_and_malformed` |
//! | §5.2; RFC 7911 §3 | Withdrawn NLRI, ADD-PATH block, truncated tail kept raw | `parse_bgp_update_bgp_ls_withdrawn_add_path_and_tail` |
//! | §5.5 | IPv4 next hop (SAFI 71) and RD + IPv6 next hop (SAFI 72) | `parse_bgp_update_mp_reach_bgp_ls_next_hop` |
//! | §5.5 | RD + IPv6 global + link-local next hop (SAFI 72, 40 octets) | `parse_bgp_update_mp_reach_bgp_ls_vpn_next_hop_link_local` |
//! | IANA BGP-LS | NLRI Type and Protocol-ID names | `bgp_ls_nlri_name_tables` |
//!
//! # Route Target Membership NLRI Coverage (RFC 4684)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | §4 | Default route target, origin AS, partial and full Route Target; IPv4 and IPv6 next hops; AFI 2 kept raw | `parse_bgp_update_mp_reach_rt_constraint` |
//! | §4; RFC 7911 §3 | Lengths of 1-31 or over 96 bits and truncated prefixes kept raw; withdrawn NLRI; ADD-PATH block, including a zero Path Identifier | `parse_bgp_update_rt_constraint_malformed_withdrawn_add_path` |
//!
//! # SR Policy NLRI Coverage (RFC 9830)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | §2.1 | Distinguisher, Color, IPv4 / IPv6 Endpoint; IPv4 and IPv6 + link-local next hops independent of the NLRI AFI | `parse_bgp_update_mp_reach_sr_policy` |
//! | §2.1; RFC 7911 §3 | NLRI Length other than 96 (AFI 1) / 192 (AFI 2) and truncated NLRI kept raw; withdrawn NLRI; ADD-PATH blocks (including Path Identifiers starting with 96 / 192); malformed tail kept plain | `parse_bgp_update_sr_policy_malformed_withdrawn_add_path` |
//!
//! # MCAST-VPN NLRI Coverage (RFC 6514 / RFC 6515 / RFC 6625 / RFC 7441)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 6514 §4.1-4.6 | Route Types 1-7: RD, Originating Router's IP Address, Source AS, Multicast Source / Group, Route Key | `parse_bgp_update_mp_reach_mcast_vpn_route_types` |
//! | RFC 6514 §4; RFC 6515 §2; RFC 6625 §2 | AFI 2 C-S / C-G, IPv6 Originating Router's IP Address under AFI 1, wildcards | `parse_bgp_update_mcast_vpn_ipv6_and_wildcards` |
//! | RFC 6515 §2 | IPv4 / IPv6 next hop independent of the AFI; other lengths kept raw | `parse_bgp_update_mp_reach_mcast_vpn_next_hop` |
//! | RFC 6515 §2; RFC 7441 §3; RFC 7524 §6.2.2; RFC 7911 §3 | Malformed bodies (including Leaf A-D Route Keys and Global Table Multicast Route Keys), mLDP and unassigned Route Types kept as `value`; overrun kept raw; withdrawn routes; ADD-PATH block | `parse_bgp_update_mcast_vpn_malformed_withdrawn_add_path` |
//! | RFC 6514 §10; RFC 7911 §3 | SAFI 129 RD + prefix NLRI, ADD-PATH, IPv6 withdrawal, overlong prefix kept raw | `parse_bgp_update_multicast_vpn_safi_129` |
//! | IANA BGP MCAST-VPN Route Types | Route Type names | `mcast_vpn_route_type_name_table` |
//!
//! # VPLS NLRI Coverage (RFC 4761 / RFC 6074)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 4761 §3.2.2; RFC 6074 §3.2.2.1 | VPLS NLRI (RD, VE ID, VE Block Offset / Size, Label Base) and BGP-AD NLRI (RD, PE_addr); IPv4 next hop | `parse_bgp_update_mp_reach_vpls` |
//! | RFC 6074 §7; RFC 7911 §3 | Other lengths kept as `value`; overrun and Lengths shorter than an RD kept raw; withdrawn NLRI; ADD-PATH blocks, including a malformed tail | `parse_bgp_update_vpls_malformed_withdrawn_add_path` |
//!
//! # RFC 8277 (Labeled NLRI) / RFC 4364 / RFC 4659 (VPN NLRI) Coverage
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 8277 §2.2 | Labeled IPv4 unicast (SAFI 4), single label | `parse_bgp_update_mp_reach_labeled_ipv4_nlri` |
//! | RFC 8277 §2.2 | Labeled IPv6 unicast (AFI 2, SAFI 4) | `parse_bgp_update_mp_reach_labeled_ipv6_nlri` |
//! | RFC 8277 §2.2 | Single label: S bit ignored on reception | `parse_bgp_update_mp_reach_labeled_single_label_s_bit_ignored` |
//! | RFC 8277 §2.3 | Multiple labels terminated by the S bit | `parse_bgp_update_mp_reach_labeled_multiple_labels` |
//! | RFC 8277 §2.4 | Withdrawal with Compatibility 0x800000 (VPN-IPv4) | `parse_bgp_update_mp_unreach_vpn_ipv4_withdraw` |
//! | RFC 8277 §2.4 | Withdrawal with Compatibility 0x000000 | `parse_bgp_update_mp_unreach_labeled_withdraw_zero_compatibility` |
//! | RFC 8277 §2.2 | ADD-PATH Path Identifier before the Length field | `parse_bgp_update_mp_reach_labeled_add_path` |
//! | RFC 8277 §2.2 | Malformed labeled / VPN NLRI kept as raw bytes | `parse_bgp_update_mp_labeled_malformed_is_raw` |
//! | RFC 4364 §4.3.4 | VPN-IPv4 NLRI (label, RD, prefix) | `parse_bgp_update_mp_reach_vpn_ipv4_nlri` |
//! | RFC 4659 §3.2 | VPN-IPv6 NLRI (label, RD, prefix) | `parse_bgp_update_mp_reach_vpn_ipv6_nlri` |
//! | RFC 4271 §4.3 | CIDR formatting of prefixes held in the scratch buffer | `format_nlri_prefix_from_scratch` |
//!
//! # MP_REACH_NLRI Next Hop Coverage (RFC 4364 / RFC 4659 / RFC 8950)
//!
//! | RFC Section | Description | Test |
//! |-------------|-------------|------|
//! | RFC 4364 §4.3.2 | VPN-IPv4 next hop (RD + IPv4) | `parse_bgp_update_mp_reach_vpn_ipv4_next_hop` |
//! | RFC 4659 §3.2.1.1 | VPN-IPv6 next hop (RD + IPv6) | `parse_bgp_update_mp_reach_vpn_ipv6_next_hop` |
//! | RFC 4659 §3.2.1.1 | VPN-IPv6 next hop with link-local | `parse_bgp_update_mp_reach_vpn_ipv6_next_hop_link_local` |
//! | RFC 8950 §3 | IPv6 next hop for IPv4 NLRI (SAFI 1, 4) | `parse_bgp_update_mp_reach_ipv4_nlri_ipv6_next_hop` |
//! | RFC 8950 §3 | VPN-IPv6 next hop for VPN-IPv4 NLRI | `parse_bgp_update_mp_reach_vpn_ipv4_nlri_ipv6_next_hop` |
//! | RFC 4760 §3 | Unexpected next hop length kept as raw bytes | `parse_bgp_update_mp_reach_unexpected_next_hop_length_is_raw` |
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
//! | RFC 8277 §2.1 | Multiple Labels Capability (afi_safis, label_count) | `parse_bgp_open_capability_multiple_labels` |
//! | RFC 8205 §2.1 | BGPsec Capability (bgpsec_version, bgpsec_direction, afi) | `parse_bgp_open_capability_bgpsec` |
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
//! | 3.2 | MUP Extended Community sub-types (2-Octet AS / IPv4 / 4-Octet AS, Direct/Interwork Segment) | `parse_bgp_update_extended_communities_mup` |
//! | 3 | Route Type / Architecture Type name tables | `name_lookup_tables` |
//! | 3 | Truncated MUP entry handling | `parse_bgp_update_mup_truncated_entry_is_raw` |
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

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, MacAddr,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u24, read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr,
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

/// AFI for L2VPN (IANA Address Family Numbers; RFC 7432, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc7432#section-7>).
const AFI_L2VPN: u16 = 25;
/// SAFI for VPLS (RFC 4761, Section 3.2.2 —
/// <https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2>).
const SAFI_VPLS: u8 = 65;
/// SAFI for EVPN (RFC 7432, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc7432#section-7>).
const SAFI_EVPN: u8 = 70;

/// AFI for IPv4 (IANA Address Family Numbers).
const AFI_IPV4: u16 = 1;
/// AFI for IPv6 (IANA Address Family Numbers).
const AFI_IPV6: u16 = 2;
/// SAFI for unicast forwarding (RFC 4760, Section 6 —
/// <https://www.rfc-editor.org/rfc/rfc4760#section-6>).
const SAFI_UNICAST: u8 = 1;
/// SAFI for multicast forwarding (RFC 4760, Section 6 —
/// <https://www.rfc-editor.org/rfc/rfc4760#section-6>).
const SAFI_MULTICAST: u8 = 2;
/// SAFI for NLRI with MPLS labels (RFC 8277, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc8277#section-2>).
const SAFI_MPLS_LABEL: u8 = 4;
/// SAFI for MPLS-labeled VPN address (RFC 4364, Section 4.3.4 —
/// <https://www.rfc-editor.org/rfc/rfc4364#section-4.3.4>).
const SAFI_MPLS_VPN: u8 = 128;
/// SAFI for Multicast for BGP/MPLS IP VPNs, whose next hop is a VPN address
/// (RFC 8950, Section 3 — <https://www.rfc-editor.org/rfc/rfc8950#section-3>).
/// Its NLRI is an RD and a prefix, without a label (RFC 6514, Section 10 —
/// <https://www.rfc-editor.org/rfc/rfc6514#section-10>).
const SAFI_MULTICAST_VPN: u8 = 129;
/// SAFI for MCAST-VPN (RFC 6514, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc6514#section-4>).
const SAFI_MCAST_VPN: u8 = 5;
/// AFI and SAFIs of BGP-LS (RFC 9552, Section 5.2 —
/// <https://www.rfc-editor.org/rfc/rfc9552#section-5.2>).
const AFI_BGP_LS: u16 = 16388;
const SAFI_BGP_LS: u8 = 71;
const SAFI_BGP_LS_VPN: u8 = 72;
/// SAFI for Route Target membership NLRI (RFC 4684, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc4684#section-4>).
const SAFI_RT_CONSTRAINT: u8 = 132;
/// SAFI for SR Policy (RFC 9830, Section 2.1 —
/// <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>).
const SAFI_SR_POLICY: u8 = 73;
/// Size of a Route Distinguisher (RFC 4364, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc4364#section-4.2>).
const RD_SIZE: usize = 8;
/// Size of one Label / Rsrv / S entry, and of the Compatibility field, in a
/// labeled NLRI (RFC 8277, Sections 2.2-2.4 —
/// <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>).
const LABEL_ENTRY_SIZE: usize = 3;

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
/// Outbound Route Filtering Capability (RFC 5291, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc5291#section-5>).
const CAP_ORF: u8 = 3;
/// BGPsec Capability (RFC 8205, Section 2.1 —
/// <https://www.rfc-editor.org/rfc/rfc8205#section-2.1>).
const CAP_BGPSEC: u8 = 7;
/// Multiple Labels Capability (RFC 8277, Section 2.1 —
/// <https://www.rfc-editor.org/rfc/rfc8277#section-2.1>).
const CAP_MULTIPLE_LABELS: u8 = 8;
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
        16388 => Some("BGP-LS"),
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
        5 => Some("MCAST-VPN"),
        65 => Some("VPLS"),
        70 => Some("EVPN"),
        71 => Some("BGP-LS"),
        72 => Some("BGP-LS-VPN"),
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
        CAP_ORF => Some("Outbound Route Filtering Capability"),
        CAP_EXTENDED_NEXT_HOP => Some("Extended Next Hop Encoding"),
        CAP_EXTENDED_MESSAGE => Some("BGP Extended Message"),
        CAP_BGPSEC => Some("BGPsec Capability"),
        CAP_MULTIPLE_LABELS => Some("Multiple Labels Capability"),
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
        CAP_ORF => parse_cap_orf(buf, value, offset),
        CAP_BGPSEC => parse_cap_bgpsec(buf, value, offset),
        CAP_MULTIPLE_LABELS => parse_cap_multiple_labels(buf, value, offset),
        // Route Refresh / Enhanced Route Refresh / Extended Message /
        // deprecated Route Refresh carry no Capability Value beyond
        // `code_name`; other/unknown codes are left as raw `value` only.
        _ => {}
    }
}

/// Returns a human-readable name for ORF Types.
///
/// IANA BGP Outbound Route Filtering (ORF) Types —
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-10>
fn orf_type_name(v: u8) -> Option<&'static str> {
    match v {
        // RFC 5292, Section 3 — https://www.rfc-editor.org/rfc/rfc5292#section-3
        ORF_TYPE_ADDRESS_PREFIX => Some("Address Prefix ORF"),
        // RFC 7543 — https://www.rfc-editor.org/rfc/rfc7543
        65 => Some("CP-ORF"),
        _ => None,
    }
}

/// Returns a human-readable name for the ORF Capability Send/Receive value.
///
/// RFC 5291, Section 5 — <https://www.rfc-editor.org/rfc/rfc5291#section-5>
fn orf_send_receive_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("receive"),
        2 => Some("send"),
        3 => Some("both"),
        _ => None,
    }
}

/// Returns a human-readable name for the BGPsec Capability Direction bit.
///
/// RFC 8205, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8205#section-2.1>
fn bgpsec_direction_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("receive"),
        1 => Some("send"),
        _ => None,
    }
}

/// Parses the Outbound Route Filtering Capability Value into `afi_safis`
/// entries, each with its `orfs` (ORF Type, Send/Receive) list.
///
/// RFC 5291, Section 5 — <https://www.rfc-editor.org/rfc/rfc5291#section-5>
///
///   One or more entries: AFI (2) + Reserved (1) + SAFI (1) + Number of
///   ORFs (1) + Number × (ORF Type (1) + Send/Receive (1)).
///
/// A value that is not exactly a sequence of such entries is left undecoded.
fn parse_cap_orf<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.is_empty() {
        return;
    }
    let mark = buf.fields().len();
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut pos = 0;
    while pos < value.len() {
        let Some(entry_len) = value
            .get(pos + 4)
            .map(|&n| 5 + 2 * usize::from(n))
            .filter(|len| pos + len <= value.len())
        else {
            buf.truncate_fields(mark);
            return;
        };
        let abs = offset + pos;
        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + entry_len,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(read_be_u16(value, pos).unwrap_or_default()),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(u16::from(value[pos + 3])),
            abs + 3..abs + 4,
        );
        let orfs_idx = buf.begin_container(
            &AFI_SAFI_CHILDREN[FD_AS_ORFS],
            FieldValue::Array(0..0),
            abs + 5..abs + entry_len,
        );
        for p in (pos + 5..pos + entry_len).step_by(2) {
            let a = offset + p;
            let orf_idx = buf.begin_container(
                &ORF_CAP_OBJECT_DESCRIPTOR,
                FieldValue::Object(0..0),
                a..a + 2,
            );
            buf.push_field(&ORF_CAP_FIELDS[0], FieldValue::U8(value[p]), a..a + 1);
            buf.push_field(
                &ORF_CAP_FIELDS[1],
                FieldValue::U8(value[p + 1]),
                a + 1..a + 2,
            );
            buf.end_container(orf_idx);
        }
        buf.end_container(orfs_idx);
        buf.end_container(obj_idx);
        pos += entry_len;
    }
    buf.end_container(array_idx);
}

/// Parses the Multiple Labels Capability Value into `afi_safis`.
///
/// RFC 8277, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.1>
///
///   One or more triples: AFI (2) + SAFI (1) + Count (1). A value whose
///   length is not a positive multiple of 4 is left undecoded.
fn parse_cap_multiple_labels<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) {
    parse_cap_afi_safi_quads(buf, value, offset, &AFI_SAFI_CHILDREN[FD_AS_LABEL_COUNT]);
}

/// Parses the BGPsec Capability Value (`bgpsec_version`,
/// `bgpsec_direction`, `afi`).
///
/// RFC 8205, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8205#section-2.1>
///
///   Version (4 bits) + Dir (1 bit) + Unassigned (3 bits) + AFI (2 octets).
///   "The capability length for this capability MUST be set to 3."
fn parse_cap_bgpsec<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    if value.len() != 3 {
        return;
    }
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_BGPSEC_VERSION],
        FieldValue::U8(value[0] >> 4),
        offset..offset + 1,
    );
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_BGPSEC_DIRECTION],
        FieldValue::U8((value[0] >> 3) & 1),
        offset..offset + 1,
    );
    buf.push_field(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI],
        FieldValue::U16(u16::from_be_bytes([value[1], value[2]])),
        offset + 1..offset + 3,
    );
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
    parse_cap_afi_safi_quads(buf, value, offset, &AFI_SAFI_CHILDREN[FD_AS_SEND_RECEIVE]);
}

/// Parses a Capability Value made of `<AFI (2), SAFI (1), X (1)>` tuples into
/// `afi_safis`, with the fourth octet pushed as `fourth` (ADD-PATH
/// Send/Receive, RFC 7911, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc7911#section-4>; Multiple Labels
/// Count, RFC 8277, Section 2.1 —
/// <https://www.rfc-editor.org/rfc/rfc8277#section-2.1>).
///
/// A `value` whose length is not a positive multiple of 4 (e.g. truncated)
/// is left undecoded.
fn parse_cap_afi_safi_quads<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
    fourth: &'static FieldDescriptor,
) {
    if value.is_empty() || value.len() % 4 != 0 {
        return;
    }
    let array_idx = buf.begin_container(
        &OPT_PARAM_CHILDREN[FD_OPT_AFI_SAFIS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    for (i, t) in value.chunks_exact(4).enumerate() {
        let abs = offset + 4 * i;
        let obj_idx = buf.begin_container(
            &AFI_SAFI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 4,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_AFI],
            FieldValue::U16(u16::from_be_bytes([t[0], t[1]])),
            abs..abs + 2,
        );
        buf.push_field(
            &AFI_SAFI_CHILDREN[FD_AS_SAFI],
            FieldValue::U16(u16::from(t[2])),
            abs + 2..abs + 3,
        );
        buf.push_field(fourth, FieldValue::U8(t[3]), abs + 3..abs + 4);
        buf.end_container(obj_idx);
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
        // RFC 9687 — https://www.rfc-editor.org/rfc/rfc9687
        8 => Some("Send Hold Timer Expired"),
        // RFC 9815 — https://www.rfc-editor.org/rfc/rfc9815
        9 => Some("Loss of LSDB Synchronization"),
        _ => None,
    }
}

/// Returns a human-readable name for Cease NOTIFICATION subcodes.
///
/// RFC 4486, Section 4 — <https://www.rfc-editor.org/rfc/rfc4486#section-4>
/// RFC 9003, Section 2 — <https://www.rfc-editor.org/rfc/rfc9003#section-2>
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
        // RFC 8538, Section 3 — https://www.rfc-editor.org/rfc/rfc8538#section-3
        9 => Some("Hard Reset"),
        // RFC 9384, Section 3 — https://www.rfc-editor.org/rfc/rfc9384#section-3
        10 => Some("BFD Down"),
        _ => None,
    }
}

/// Returns a human-readable name for a BGP Error Subcode of `error_code`.
///
/// IANA BGP Error Subcodes —
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-5>
fn error_subcode_name(error_code: u8, subcode: u8) -> Option<&'static str> {
    match (error_code, subcode) {
        // "Unspecific" (RFC 4271 Errata ID 4493 —
        // https://www.rfc-editor.org/errata/eid4493).
        (1..=3, 0) => Some("Unspecific"),
        // Message Header Error subcodes (RFC 4271, Section 6.1 —
        // https://www.rfc-editor.org/rfc/rfc4271#section-6.1).
        (1, 1) => Some("Connection Not Synchronized"),
        (1, 2) => Some("Bad Message Length"),
        (1, 3) => Some("Bad Message Type"),
        // OPEN Message Error subcodes (RFC 4271, Section 6.2 —
        // https://www.rfc-editor.org/rfc/rfc4271#section-6.2; RFC 5492,
        // Section 5 — https://www.rfc-editor.org/rfc/rfc5492#section-5;
        // RFC 9234, Section 4.2 — https://www.rfc-editor.org/rfc/rfc9234#section-4.2).
        (2, 1) => Some("Unsupported Version Number"),
        (2, 2) => Some("Bad Peer AS"),
        (2, 3) => Some("Bad BGP Identifier"),
        (2, 4) => Some("Unsupported Optional Parameter"),
        (2, 6) => Some("Unacceptable Hold Time"),
        (2, 7) => Some("Unsupported Capability"),
        (2, 11) => Some("Role Mismatch"),
        // UPDATE Message Error subcodes (RFC 4271, Section 6.3 —
        // https://www.rfc-editor.org/rfc/rfc4271#section-6.3).
        (3, 1) => Some("Malformed Attribute List"),
        (3, 2) => Some("Unrecognized Well-known Attribute"),
        (3, 3) => Some("Missing Well-known Attribute"),
        (3, 4) => Some("Attribute Flags Error"),
        (3, 5) => Some("Attribute Length Error"),
        (3, 6) => Some("Invalid ORIGIN Attribute"),
        (3, 8) => Some("Invalid NEXT_HOP Attribute"),
        (3, 9) => Some("Optional Attribute Error"),
        (3, 10) => Some("Invalid Network Field"),
        (3, 11) => Some("Malformed AS_PATH"),
        // Finite State Machine Error subcodes (RFC 6608, Section 4 —
        // https://www.rfc-editor.org/rfc/rfc6608#section-4).
        (5, 0) => Some("Unspecified Error"),
        (5, 1) => Some("Receive Unexpected Message in OpenSent State"),
        (5, 2) => Some("Receive Unexpected Message in OpenConfirm State"),
        (5, 3) => Some("Receive Unexpected Message in Established State"),
        (6, _) => cease_subcode_name(subcode),
        // ROUTE-REFRESH Message Error subcodes (RFC 7313, Section 5 —
        // https://www.rfc-editor.org/rfc/rfc7313#section-5).
        (7, 1) => Some("Invalid Message Length"),
        _ => None,
    }
}

/// Cease subcodes whose data may carry a Shutdown Communication (RFC 9003,
/// Section 2 — <https://www.rfc-editor.org/rfc/rfc9003#section-2>).
const CEASE_ADMINISTRATIVE_SHUTDOWN: u8 = 2;
const CEASE_ADMINISTRATIVE_RESET: u8 = 4;
/// Cease subcode "Hard Reset" (RFC 8538, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc8538#section-3>).
const CEASE_HARD_RESET: u8 = 9;
/// Error Code "Cease" (RFC 4271, Section 4.5 —
/// <https://www.rfc-editor.org/rfc/rfc4271#section-4.5>).
const ERROR_CODE_CEASE: u8 = 6;

/// Pushes the Shutdown Communication of a Cease / Administrative Shutdown or
/// Administrative Reset NOTIFICATION `data` with the `length_fd` / `text_fd`
/// descriptors.
///
/// RFC 9003, Section 2 — <https://www.rfc-editor.org/rfc/rfc9003#section-2>:
/// "When the length value is zero, no Shutdown Communication field follows",
/// and "A receiving BGP speaker MUST NOT interpret invalid UTF-8 sequences":
/// nothing is pushed when the Length does not cover exactly the rest of
/// `data` or the text is not UTF-8 (the raw `data` still holds it).
fn push_shutdown_communication<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    length_fd: &'static FieldDescriptor,
    text_fd: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
) {
    let Some((&len, text)) = data.split_first() else {
        return;
    };
    // The Length covers the rest of the data exactly.
    if text.len() != usize::from(len) {
        return;
    }
    let Ok(text) = core::str::from_utf8(text) else {
        return;
    };
    buf.push_field(length_fd, FieldValue::U8(len), offset..offset + 1);
    if !text.is_empty() {
        buf.push_field(
            text_fd,
            FieldValue::Str(text),
            offset + 1..offset + 1 + text.len(),
        );
    }
}

/// Parses NOTIFICATION message body and appends fields.
///
/// RFC 4271, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.5>
///
/// The raw `data` is always kept. Cease / Administrative Shutdown and
/// Administrative Reset data is also decoded as a Shutdown Communication
/// (RFC 9003, Section 2), and Cease / Hard Reset data as the encapsulated
/// `hard_reset` Error Code, Subcode and Data (RFC 8538, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc8538#section-3.1>).
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
        let data_offset = offset + 21;
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA],
            FieldValue::Bytes(data_bytes),
            data_offset..offset + data.len(),
        );
        match (error_code, error_subcode) {
            (ERROR_CODE_CEASE, CEASE_ADMINISTRATIVE_SHUTDOWN | CEASE_ADMINISTRATIVE_RESET) => {
                push_shutdown_communication(
                    buf,
                    &FIELD_DESCRIPTORS[FD_SHUTDOWN_COMMUNICATION_LENGTH],
                    &FIELD_DESCRIPTORS[FD_SHUTDOWN_COMMUNICATION],
                    data_bytes,
                    data_offset,
                );
            }
            // "the Hard Reset encapsulates another NOTIFICATION message in
            // its data portion" (RFC 8538, Section 3.1 —
            // https://www.rfc-editor.org/rfc/rfc8538#section-3.1).
            (ERROR_CODE_CEASE, CEASE_HARD_RESET) if data_bytes.len() >= 2 => {
                let obj_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_HARD_RESET],
                    FieldValue::Object(0..0),
                    data_offset..data_offset + data_bytes.len(),
                );
                let (code, subcode) = (data_bytes[0], data_bytes[1]);
                buf.push_field(
                    &HARD_RESET_FIELDS[0],
                    FieldValue::U8(code),
                    data_offset..data_offset + 1,
                );
                buf.push_field(
                    &HARD_RESET_FIELDS[1],
                    FieldValue::U8(subcode),
                    data_offset + 1..data_offset + 2,
                );
                let inner = &data_bytes[2..];
                if !inner.is_empty() {
                    let inner_offset = data_offset + 2;
                    buf.push_field(
                        &HARD_RESET_FIELDS[2],
                        FieldValue::Bytes(inner),
                        inner_offset..inner_offset + inner.len(),
                    );
                    if code == ERROR_CODE_CEASE
                        && matches!(
                            subcode,
                            CEASE_ADMINISTRATIVE_SHUTDOWN | CEASE_ADMINISTRATIVE_RESET
                        )
                    {
                        push_shutdown_communication(
                            buf,
                            &HARD_RESET_FIELDS[3],
                            &HARD_RESET_FIELDS[4],
                            inner,
                            inner_offset,
                        );
                    }
                }
                buf.end_container(obj_idx);
            }
            _ => {}
        }
    }

    Ok(())
}

/// ORF Type "Address Prefix ORF" (RFC 5292, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc5292#section-3>).
const ORF_TYPE_ADDRESS_PREFIX: u8 = 64;
/// ORF entry Action "REMOVE-ALL" (RFC 5291, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc5291#section-4>).
const ORF_ACTION_REMOVE_ALL: u8 = 2;

/// Returns a human-readable name for the ROUTE-REFRESH When-to-refresh field.
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>
fn when_to_refresh_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IMMEDIATE"),
        2 => Some("DEFER"),
        _ => None,
    }
}

/// Returns a human-readable name for an ORF entry Action.
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>
fn orf_action_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("ADD"),
        1 => Some("REMOVE"),
        ORF_ACTION_REMOVE_ALL => Some("REMOVE-ALL"),
        _ => None,
    }
}

/// Returns a human-readable name for an ORF entry Match.
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>
fn orf_match_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("PERMIT"),
        1 => Some("DENY"),
        _ => None,
    }
}

/// Parses the ORFs following the fixed part of a ROUTE-REFRESH message:
/// When-to-refresh, then one or more (ORF Type, Length of ORF entries, ORF
/// entries).
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>
///
/// Address Prefix ORF entries are decoded (RFC 5292, Section 3); the entries
/// of other ORF types are kept as the ORF's `value`. Returns `false` (nothing
/// left pushed) when the ORFs or Address Prefix ORF entries do not exactly
/// fill their enclosing field.
fn parse_route_refresh_orfs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    afi: u16,
) -> bool {
    // "a collection of one or more ORFs".
    if body.len() < 4 {
        return false;
    }
    let mark = buf.fields().len();
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_WHEN_TO_REFRESH],
        FieldValue::U8(body[0]),
        offset..offset + 1,
    );
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_ORFS],
        FieldValue::Array(0..0),
        offset + 1..offset + body.len(),
    );
    let mut pos = 1;
    while pos < body.len() {
        let Some(len) = read_be_u16(body, pos + 1)
            .ok()
            .map(usize::from)
            .filter(|len| pos + 3 + len <= body.len())
        else {
            buf.truncate_fields(mark);
            return false;
        };
        let orf_type = body[pos];
        let abs = offset + pos;
        let entries = &body[pos + 3..pos + 3 + len];
        let obj_idx = buf.begin_container(
            &ORF_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 3 + len,
        );
        buf.push_field(
            &ORF_FIELDS[FD_ORF_TYPE],
            FieldValue::U8(orf_type),
            abs..abs + 1,
        );
        buf.push_field(
            &ORF_FIELDS[FD_ORF_LENGTH],
            FieldValue::U16(len as u16),
            abs + 1..abs + 3,
        );
        if orf_type == ORF_TYPE_ADDRESS_PREFIX {
            if !parse_address_prefix_orf_entries(buf, entries, abs + 3, afi) {
                buf.truncate_fields(mark);
                return false;
            }
        } else if !entries.is_empty() {
            buf.push_field(
                &ORF_FIELDS[FD_ORF_VALUE],
                FieldValue::Bytes(entries),
                abs + 3..abs + 3 + len,
            );
        }
        buf.end_container(obj_idx);
        pos += 3 + len;
    }
    buf.end_container(array_idx);
    true
}

/// Parses Address Prefix ORF entries into `entries`. Returns `false` when
/// they do not exactly fill `data` (the caller discards what was pushed).
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>:
/// the first octet carries Action (2 bits) and Match (1 bit); "When the
/// Action component of an ORF entry specifies REMOVE-ALL, the entry consists
/// of only the common part."
/// RFC 5292, Section 3 — <https://www.rfc-editor.org/rfc/rfc5292#section-3>:
/// Sequence (4), Minlen (1), Maxlen (1), Length (1), Prefix (variable).
fn parse_address_prefix_orf_entries<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    afi: u16,
) -> bool {
    let array_idx = buf.begin_container(
        &ORF_FIELDS[FD_ORF_ENTRIES],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    // The Prefix is formatted as a CIDR string for IPv4 / IPv6, whose Length
    // cannot exceed the address size (RFC 5292, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc5292#section-2).
    let (prefix_fd, max_bits): (&'static FieldDescriptor, usize) = match afi {
        AFI_IPV4 => (&PREFIX_ENTRY_IPV4_DESCRIPTOR, 32),
        AFI_IPV6 => (&PREFIX_ENTRY_IPV6_DESCRIPTOR, 128),
        _ => (&ORF_ENTRY_FIELDS[FD_ORFE_PREFIX_RAW], usize::from(u8::MAX)),
    };
    let mut pos = 0;
    while pos < data.len() {
        let common = data[pos];
        let action = common >> 6;
        let entry_len = if action == ORF_ACTION_REMOVE_ALL {
            1
        } else {
            match data.get(pos + 7).map(|&bits| usize::from(bits)) {
                Some(bits) if bits <= max_bits => 8 + bits.div_ceil(8),
                _ => return false,
            }
        };
        if pos + entry_len > data.len() {
            return false;
        }
        let abs = offset + pos;
        let e = &ORF_ENTRY_FIELDS;
        let obj_idx = buf.begin_container(
            &ORF_ENTRY_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + entry_len,
        );
        buf.push_field(&e[FD_ORFE_ACTION], FieldValue::U8(action), abs..abs + 1);
        if action != ORF_ACTION_REMOVE_ALL {
            // Match "is significant only when the value of the Action field
            // is either ADD or REMOVE".
            buf.push_field(
                &e[FD_ORFE_MATCH],
                FieldValue::U8((common >> 5) & 1),
                abs..abs + 1,
            );
            buf.push_field(
                &e[FD_ORFE_SEQUENCE],
                FieldValue::U32(read_be_u32(data, pos + 1).unwrap_or_default()),
                abs + 1..abs + 5,
            );
            buf.push_field(
                &e[FD_ORFE_MINLEN],
                FieldValue::U8(data[pos + 5]),
                abs + 5..abs + 6,
            );
            buf.push_field(
                &e[FD_ORFE_MAXLEN],
                FieldValue::U8(data[pos + 6]),
                abs + 6..abs + 7,
            );
            // Length (1) + Prefix: the `[len, octets...]` prefix encoding.
            buf.push_field(
                prefix_fd,
                FieldValue::Bytes(&data[pos + 7..pos + entry_len]),
                abs + 7..abs + entry_len,
            );
        }
        buf.end_container(obj_idx);
        pos += entry_len;
    }
    buf.end_container(array_idx);
    true
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
/// RFC 5291 (ORF) — <https://www.rfc-editor.org/rfc/rfc5291>
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

    // Octets after the fixed part: ORFs of a plain Route-Refresh (RFC 5291,
    // Section 4 — https://www.rfc-editor.org/rfc/rfc5291#section-4), kept as
    // `data` when they do not parse or for a BoRR / EoRR.
    let body = &data[ROUTE_REFRESH_SIZE..];
    if !body.is_empty() {
        let body_offset = offset + ROUTE_REFRESH_SIZE;
        let decoded = message_subtype == 0 && parse_route_refresh_orfs(buf, body, body_offset, afi);
        if !decoded {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_DATA],
                FieldValue::Bytes(body),
                body_offset..body_offset + body.len(),
            );
        }
    }

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
///
/// Returns the number of octets decoded; decoding stops at the first entry
/// that is malformed.
fn parse_prefixes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ipv6: bool,
) -> usize {
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
                &NLRI_ENTRY_CHILDREN[FD_NLRI_PATH_ID],
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
    pos
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
        // RFC 5543 — https://www.rfc-editor.org/rfc/rfc5543
        24 => Some("Traffic Engineering"),
        // RFC 5701 — https://www.rfc-editor.org/rfc/rfc5701
        25 => Some("IPv6 Address Specific Extended Community"),
        26 => Some("AIGP"),
        // RFC 6514 — https://www.rfc-editor.org/rfc/rfc6514
        27 => Some("PE Distinguisher Labels"),
        29 => Some("BGP-LS Attribute"),
        32 => Some("LARGE_COMMUNITY"),
        33 => Some("BGPsec_Path"),
        35 => Some("Only to Customer (OTC)"),
        // RFC 10039 — https://www.rfc-editor.org/rfc/rfc10039
        36 => Some("BGP Domain Path (D-PATH)"),
        // RFC 9015 — https://www.rfc-editor.org/rfc/rfc9015
        37 => Some("SFP attribute"),
        // RFC 9026 — https://www.rfc-editor.org/rfc/rfc9026
        38 => Some("BFD Discriminator"),
        40 => Some("BGP Prefix-SID"),
        // RFC 9793 — https://www.rfc-editor.org/rfc/rfc9793
        41 => Some("BIER"),
        // RFC 6368 — https://www.rfc-editor.org/rfc/rfc6368
        128 => Some("ATTR_SET"),
        _ => None,
    }
}

/// Returns a human-readable name for PMSI Tunnel Types.
///
/// RFC 6514, Section 5 — <https://www.rfc-editor.org/rfc/rfc6514#section-5>
/// IANA P-Multicast Service Interface Tunnel (PMSI Tunnel) Tunnel Types —
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#pmsi-tunnel-types>
fn pmsi_tunnel_type_name(v: u8) -> Option<&'static str> {
    match v {
        0x00 => Some("No tunnel information present"),
        0x01 => Some("RSVP-TE P2MP LSP"),
        0x02 => Some("mLDP P2MP LSP"),
        0x03 => Some("PIM-SSM Tree"),
        0x04 => Some("PIM-SM Tree"),
        0x05 => Some("BIDIR-PIM Tree"),
        0x06 => Some("Ingress Replication"),
        0x07 => Some("mLDP MP2MP LSP"),
        // RFC 7524 — https://www.rfc-editor.org/rfc/rfc7524
        0x08 => Some("Transport Tunnel"),
        // RFC 9574 — https://www.rfc-editor.org/rfc/rfc9574
        0x0A => Some("Assisted Replication Tunnel"),
        // RFC 8556 — https://www.rfc-editor.org/rfc/rfc8556
        0x0B => Some("BIER"),
        // RFC 10018 — https://www.rfc-editor.org/rfc/rfc10018
        0x0C => Some("SR-MPLS P2MP Tree"),
        0x0D => Some("SRv6 P2MP Tree"),
        // RFC 8338 — https://www.rfc-editor.org/rfc/rfc8338
        0xFF => Some("Wildcard Transport Tunnel Type"),
        _ => None,
    }
}

/// Returns a human-readable name for Tunnel Encapsulation Attribute Tunnel
/// Types.
///
/// IANA BGP Tunnel Encapsulation Attribute Tunnel Types —
/// <https://www.iana.org/assignments/bgp-tunnel-encapsulation/bgp-tunnel-encapsulation.xhtml#tunnel-types>
fn tunnel_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("L2TPv3 over IP"),
        2 => Some("GRE"),
        7 => Some("IP in IP"),
        8 => Some("VXLAN Encapsulation"),
        9 => Some("NVGRE Encapsulation"),
        10 => Some("MPLS Encapsulation"),
        11 => Some("MPLS in GRE Encapsulation"),
        12 => Some("VXLAN GPE Encapsulation"),
        13 => Some("MPLS in UDP Encapsulation"),
        14 => Some("IPv6 Tunnel"),
        15 => Some("SR Policy"),
        16 => Some("Bare"),
        19 => Some("Geneve Encapsulation"),
        _ => None,
    }
}

/// Returns a human-readable name for Tunnel Encapsulation Attribute Sub-TLV
/// types.
///
/// IANA BGP Tunnel Encapsulation Attribute Sub-TLVs —
/// <https://www.iana.org/assignments/bgp-tunnel-encapsulation/bgp-tunnel-encapsulation.xhtml#tunnel-sub-tlvs>
fn tunnel_sub_tlv_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Encapsulation"),
        2 => Some("Protocol Type"),
        4 => Some("Color"),
        5 => Some("Load-Balancing Block"),
        6 => Some("Tunnel Egress Endpoint"),
        7 => Some("DS Field"),
        8 => Some("UDP Destination Port"),
        9 => Some("Embedded Label Handling"),
        10 => Some("MPLS Label Stack"),
        11 => Some("Prefix-SID"),
        // RFC 9830 — https://www.rfc-editor.org/rfc/rfc9830
        12 => Some("Preference"),
        13 => Some("Binding SID"),
        14 => Some("ENLP"),
        15 => Some("Priority"),
        // RFC 9015 — https://www.rfc-editor.org/rfc/rfc9015
        16 => Some("SPI/SI Representation"),
        // RFC 9830 — https://www.rfc-editor.org/rfc/rfc9830
        20 => Some("SRv6 Binding SID"),
        128 => Some("Segment List"),
        129 => Some("SR Policy Candidate Path Name"),
        130 => Some("SR Policy Name"),
        _ => None,
    }
}

/// Returns a human-readable name for BGP-LS Node / Link / Prefix Descriptor
/// and Attribute TLV code points.
///
/// Only the code points assigned by RFCs are listed.
///
/// RFC 9552, Section 5 — <https://www.rfc-editor.org/rfc/rfc9552#section-5>
/// IANA BGP-LS Node Descriptor, Link Descriptor, Prefix Descriptor, and
/// Attribute TLVs —
/// <https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv>
fn bgp_ls_tlv_name(v: u16) -> Option<&'static str> {
    match v {
        256 => Some("Local Node Descriptors"),
        257 => Some("Remote Node Descriptors"),
        258 => Some("Link Local/Remote Identifiers"),
        259 => Some("IPv4 interface address"),
        260 => Some("IPv4 neighbor address"),
        261 => Some("IPv6 interface address"),
        262 => Some("IPv6 neighbor address"),
        263 => Some("Multi-Topology Identifier"),
        264 => Some("OSPF Route Type"),
        265 => Some("IP Reachability Information"),
        266 => Some("Node MSD"),
        267 => Some("Link MSD"),
        512 => Some("Autonomous System"),
        513 => Some("BGP-LS Identifier (deprecated)"),
        514 => Some("OSPF Area-ID"),
        515 => Some("IGP Router-ID"),
        516 => Some("BGP Router-ID"),
        517 => Some("BGP Confederation Member"),
        518 => Some("SRv6 SID Information"),
        554 => Some("SR Policy Candidate Path Descriptor"),
        1024 => Some("Node Flag Bits"),
        1025 => Some("Opaque Node Attribute"),
        1026 => Some("Node Name"),
        1027 => Some("IS-IS Area Identifier"),
        1028 => Some("IPv4 Router-ID of Local Node"),
        1029 => Some("IPv6 Router-ID of Local Node"),
        1030 => Some("IPv4 Router-ID of Remote Node"),
        1031 => Some("IPv6 Router-ID of Remote Node"),
        1032 => Some("S-BFD Discriminators"),
        1034 => Some("SR Capabilities"),
        1035 => Some("SR Algorithm"),
        1036 => Some("SR Local Block"),
        1037 => Some("SRMS Preference"),
        1038 => Some("SRv6 Capabilities"),
        1039 => Some("Flexible Algorithm Definition"),
        1040 => Some("Flexible Algorithm Exclude-Any Affinity"),
        1041 => Some("Flexible Algorithm Include-Any Affinity"),
        1042 => Some("Flexible Algorithm Include-All Affinity"),
        1043 => Some("Flexible Algorithm Definition Flags"),
        1044 => Some("Flexible Algorithm Prefix Metric"),
        1045 => Some("Flexible Algorithm Exclude SRLG"),
        1046 => Some("Flexible Algorithm Unsupported"),
        1088 => Some("Administrative group (color)"),
        1089 => Some("Maximum link bandwidth"),
        1090 => Some("Max. reservable link bandwidth"),
        1091 => Some("Unreserved bandwidth"),
        1092 => Some("TE Default Metric"),
        1093 => Some("Link Protection Type"),
        1094 => Some("MPLS Protocol Mask"),
        1095 => Some("IGP Metric"),
        1096 => Some("Shared Risk Link Group"),
        1097 => Some("Opaque Link Attribute"),
        1098 => Some("Link Name"),
        1099 => Some("Adjacency SID"),
        1100 => Some("LAN Adjacency SID"),
        1101 => Some("PeerNode SID"),
        1102 => Some("PeerAdj SID"),
        1103 => Some("PeerSet SID"),
        1105 => Some("RTM Capability"),
        1106 => Some("SRv6 End.X SID"),
        1107 => Some("IS-IS SRv6 LAN End.X SID"),
        1108 => Some("OSPFv3 SRv6 LAN End.X SID"),
        1114 => Some("Unidirectional Link Delay"),
        1115 => Some("Min/Max Unidirectional Link Delay"),
        1116 => Some("Unidirectional Delay Variation"),
        1117 => Some("Unidirectional Link Loss"),
        1118 => Some("Unidirectional Residual Bandwidth"),
        1119 => Some("Unidirectional Available Bandwidth"),
        1120 => Some("Unidirectional Utilized Bandwidth"),
        1121 => Some("Graceful-Link-Shutdown TLV"),
        1122 => Some("Application-Specific Link Attributes"),
        1152 => Some("IGP Flags"),
        1153 => Some("IGP Route Tag"),
        1154 => Some("IGP Extended Route Tag"),
        1155 => Some("Prefix Metric"),
        1156 => Some("OSPF Forwarding Address"),
        1157 => Some("Opaque Prefix Attribute"),
        1158 => Some("Prefix-SID"),
        1159 => Some("Range"),
        1161 => Some("SID/Label"),
        1162 => Some("SRv6 Locator"),
        1170 => Some("Prefix Attributes Flags"),
        1171 => Some("Source Router Identifier"),
        1172 => Some("L2 Bundle Member Attributes"),
        1173 => Some("Extended Administrative Group"),
        1174 => Some("Source OSPF Router-ID"),
        1181 => Some("Sequence Number"),
        1184 => Some("SPF Status"),
        1185 => Some("Address Family Link Descriptor"),
        1201 => Some("SR Binding SID"),
        1202 => Some("SR Candidate Path State"),
        1203 => Some("SR Candidate Path Name"),
        1204 => Some("SR Candidate Path Constraints"),
        1205 => Some("SR Segment List"),
        1206 => Some("SR Segment"),
        1207 => Some("SR Segment List Metric"),
        1208 => Some("SR Affinity Constraint"),
        1209 => Some("SR SRLG Constraint"),
        1210 => Some("SR Bandwidth Constraint"),
        1211 => Some("SR Disjoint Group Constraint"),
        1212 => Some("SRv6 Binding SID"),
        1213 => Some("SR Policy Name"),
        1214 => Some("SR Bidirectional Group Constraint"),
        1215 => Some("SR Metric Constraint"),
        1216 => Some("SR Segment List Bandwidth"),
        1217 => Some("SR Segment List Identifier"),
        1250 => Some("SRv6 Endpoint Behavior"),
        1251 => Some("SRv6 BGP PeerNode SID"),
        1252 => Some("SRv6 SID Structure"),
        _ => None,
    }
}

/// Returns a human-readable name for AIGP attribute TLV types.
///
/// RFC 7311, Section 3 — <https://www.rfc-editor.org/rfc/rfc7311#section-3>
fn aigp_tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("AIGP"),
        _ => None,
    }
}

/// Returns a human-readable name for SFP attribute TLV types.
///
/// RFC 9015, Section 10.3 — <https://www.rfc-editor.org/rfc/rfc9015#section-10.3>
fn sfp_tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Association TLV"),
        2 => Some("Hop TLV"),
        3 => Some("SFT TLV"),
        4 => Some("MPLS Swapping/Stacking"),
        5 => Some("SFP Traversal With MPLS"),
        _ => None,
    }
}

/// Returns a human-readable name for BFD Mode values of the BFD Discriminator
/// attribute.
///
/// RFC 9026, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc9026#section-7.2>
fn bfd_mode_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("P2MP BFD Session"),
        _ => None,
    }
}

/// Returns a human-readable name for BFD Discriminator Optional TLV types.
///
/// RFC 9026, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc9026#section-7.3>
fn bfd_optional_tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Source IP Address"),
        _ => None,
    }
}

/// Context shared by the path attributes of one UPDATE (or of one ATTR_SET).
#[derive(Clone, Copy)]
struct AttrContext {
    /// AS number size inferred from the other attributes (see
    /// [`AttrContext::for_update`]), used for AS_PATH.
    as_size_hint: Option<usize>,
    /// Whether an Encapsulation Extended Community selects a tunnel type
    /// whose MPLS Label fields carry a VNI (see [`carries_vni_encapsulation`]).
    vni_label: bool,
    /// Whether the attributes are nested in an ATTR_SET value (RFC 6368,
    /// Section 5 — <https://www.rfc-editor.org/rfc/rfc6368#section-5>).
    in_attr_set: bool,
}

impl AttrContext {
    /// Context for the top-level Path Attributes field `attrs` of an UPDATE
    /// (RFC 4271, Section 4.3 —
    /// <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>), gathered in one
    /// walk over the attribute headers.
    ///
    /// The AS number size of the AS_PATH is inferred from the other
    /// attributes, or `None` when they give no evidence:
    ///
    /// - AS4_PATH / AS4_AGGREGATOR are only sent towards OLD BGP speakers:
    ///   "When communicating with an OLD BGP speaker, a NEW BGP speaker MUST
    ///   send the AS path information in the AS_PATH attribute encoded with
    ///   two-octet AS numbers.  The NEW BGP speaker MUST also send the AS path
    ///   information in the AS4_PATH attribute" (RFC 6793, Section 4.2.2 —
    ///   <https://www.rfc-editor.org/rfc/rfc6793#section-4.2.2>), and they
    ///   "MUST NOT be carried in an UPDATE message between NEW BGP speakers"
    ///   (RFC 6793, Section 4.1 —
    ///   <https://www.rfc-editor.org/rfc/rfc6793#section-4.1>). Their presence
    ///   means 2-octet.
    /// - AGGREGATOR uses the same AS number size as AS_PATH (RFC 6793,
    ///   Section 4.1): a 6-octet value means 2-octet, an 8-octet value
    ///   4-octet.
    ///
    /// [`AttrContext::vni_label`] is set by an Encapsulation Extended
    /// Community for a VNI-carrying tunnel type (see
    /// [`carries_vni_encapsulation`]).
    fn for_update(attrs: &[u8]) -> Self {
        let mut as4_seen = false;
        let mut aggregator_hint = None;
        let mut vni_label = false;
        for (type_code, value) in path_attr_values(attrs) {
            match (type_code, value.len()) {
                // AS4_PATH / AS4_AGGREGATOR: the strongest evidence.
                (17 | 18, _) => as4_seen = true,
                // AGGREGATOR with a 2-octet or 4-octet AS number.
                (7, 6) => aggregator_hint = Some(2),
                (7, 8) => aggregator_hint = Some(4),
                // EXTENDED COMMUNITIES (RFC 4360, Section 2 —
                // https://www.rfc-editor.org/rfc/rfc4360#section-2).
                (16, _) => vni_label |= carries_vni_encapsulation(value),
                _ => {}
            }
        }
        Self {
            as_size_hint: if as4_seen { Some(2) } else { aggregator_hint },
            vni_label,
            in_attr_set: false,
        }
    }
}

/// Iterates over the `(type code, value)` of the path attributes in `attrs`,
/// stopping at the first attribute whose header or value is truncated.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>:
/// Attribute Flags, Attribute Type Code, and a one- or two-octet (Extended
/// Length bit) Attribute Length.
fn path_attr_values(attrs: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut pos = 0;
    core::iter::from_fn(move || {
        let flags = *attrs.get(pos)?;
        let shape = TlvShape::new(1, if flags & 0x10 != 0 { 2 } else { 1 });
        let (type_code, value_len) = tlv_at(attrs, pos + 1, shape)?;
        let start = pos + 1 + shape.header_len();
        pos = start + value_len;
        Some((type_code as u8, &attrs[start..pos]))
    })
}

/// Returns `true` when the EXTENDED COMMUNITIES value `communities` carries
/// an Encapsulation Extended Community for VXLAN (8), NVGRE (9) or VXLAN GPE
/// (12).
///
/// With those encapsulations the MPLS Label field of the PMSI Tunnel
/// attribute (and of the EVPN routes) carries a VNI: "the entire 24-bit field
/// is used to encode the VNI value" (RFC 8365, Section 5.1.3 —
/// <https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3>). The Encapsulation
/// Extended Community is type 0x03, sub-type 0x0c, with the tunnel type in its
/// last two octets (RFC 9012, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc9012#section-4.1>).
fn carries_vni_encapsulation(communities: &[u8]) -> bool {
    communities
        .chunks_exact(8)
        .any(|c| c[..2] == [0x03, 0x0c] && matches!(u16::from_be_bytes([c[6], c[7]]), 8 | 9 | 12))
}

/// Parses a single path attribute and pushes it as an Object into the buffer.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// Returns the number of bytes consumed, or `None` if parsing fails.
fn parse_path_attribute<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ctx: AttrContext,
) -> Option<(usize, Option<MpAfiSafi>)> {
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
    let mp_afi_safi = parse_attr_value(buf, type_code, value_data, val_offset, ctx);

    buf.end_container(obj_idx);

    Some((total_len, mp_afi_safi))
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

/// Returns a human-readable name for an Extended Community Type (high-order
/// octet).
///
/// IANA BGP Transitive / Non-Transitive Extended Community Types —
/// <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml>
/// RFC 7153, Section 5 — <https://www.rfc-editor.org/rfc/rfc7153#section-5>
fn ext_community_type_name(type_high: u8) -> Option<&'static str> {
    match type_high {
        0x00 => Some("Transitive Two-Octet AS-Specific"),
        0x01 => Some("Transitive IPv4-Address-Specific"),
        0x02 => Some("Transitive Four-Octet AS-Specific"),
        0x03 => Some("Transitive Opaque"),
        0x06 => Some("EVPN"),
        // RFC 9832 — https://www.rfc-editor.org/rfc/rfc9832
        0x0a => Some("Transport Class"),
        // RFC 9015 — https://www.rfc-editor.org/rfc/rfc9015
        0x0b => Some("SFC"),
        // draft-ietf-bess-mup-safi-01, Section 3.2 —
        // https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/
        0x0c => Some("SRv6 MUP"),
        0x40 => Some("Non-Transitive Two-Octet AS-Specific"),
        0x41 => Some("Non-Transitive IPv4-Address-Specific"),
        0x42 => Some("Non-Transitive Four-Octet AS-Specific"),
        0x43 => Some("Non-Transitive Opaque"),
        0x4a => Some("Non-Transitive Transport Class"),
        0x80 => Some("Generic Transitive"),
        0x81 => Some("Generic Transitive Part 2"),
        0x82 => Some("Generic Transitive Part 3"),
        _ => None,
    }
}

/// Returns a human-readable name for an Extended Community (Type, Sub-Type)
/// pair (see [`ext_community_sub_type`]).
fn ext_community_sub_type_name(type_high: u8, sub_type: u8) -> Option<&'static str> {
    ext_community_sub_type(type_high, sub_type).0
}

/// Returns the name and the Value layout of an Extended Community (Type,
/// Sub-Type) pair.
///
/// Only the sub-types assigned by RFCs are named, plus the BGP-MUP ones
/// decoded by this dissector. An unnamed sub-type of an AS- or
/// IPv4-Address-Specific type still uses that type's Global / Local
/// Administrator layout (RFC 4360, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc4360#section-3>).
///
/// IANA BGP Extended Communities —
/// <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml>
fn ext_community_sub_type(
    type_high: u8,
    sub_type: u8,
) -> (Option<&'static str>, ExtCommunityValue) {
    use ExtCommunityValue as V;
    let (name, layout) = match (type_high, sub_type) {
        // Route Target / Route Origin (RFC 4360, Section 4 —
        // https://www.rfc-editor.org/rfc/rfc4360#section-4; RFC 5668,
        // Section 2 — https://www.rfc-editor.org/rfc/rfc5668#section-2).
        (0x00..=0x02, 0x02) => ("Route Target", V::Generic),
        (0x00..=0x02, 0x03) => ("Route Origin", V::Generic),
        // Link Bandwidth (RFC 10005, Section 2 —
        // https://www.rfc-editor.org/rfc/rfc10005#section-2).
        (0x00 | 0x40, 0x04) => ("Link Bandwidth", V::LinkBandwidth),
        // OSPF Domain Identifier / Router ID / Route Type and their
        // backward-compatible 0x80xx forms (RFC 4577, Section 4.2.6 —
        // https://www.rfc-editor.org/rfc/rfc4577#section-4.2.6).
        (0x00..=0x02, 0x05) => ("OSPF Domain Identifier", V::Generic),
        (0x01, 0x07) => ("OSPF Router ID", V::Generic),
        (0x03, 0x06) => ("OSPF Route Type", V::OspfRouteType),
        (0x80, 0x00) => ("OSPF Route Type (deprecated)", V::OspfRouteType),
        (0x80, 0x01) => ("OSPF Router ID (deprecated)", V::Ipv4Address),
        (0x80, 0x05) => ("OSPF Domain Identifier (deprecated)", V::TwoOctetAs),
        // BGP Data Collection (RFC 4384 — https://www.rfc-editor.org/rfc/rfc4384).
        (0x00 | 0x02, 0x08) => ("BGP Data Collection", V::Generic),
        // Source AS and VRF Route Import (RFC 6514, Section 4 —
        // https://www.rfc-editor.org/rfc/rfc6514#section-4).
        (0x00 | 0x02, 0x09) => ("Source AS", V::Generic),
        (0x01, 0x0b) => ("VRF Route Import", V::Generic),
        // L2VPN Identifier (RFC 6074 — https://www.rfc-editor.org/rfc/rfc6074).
        (0x00 | 0x01, 0x0a) => ("L2VPN Identifier", V::Generic),
        // RFC 7524 — https://www.rfc-editor.org/rfc/rfc7524
        (0x01, 0x12) => ("Inter-Area P2MP Segmented Next-Hop", V::Generic),
        // RFC 9081 — https://www.rfc-editor.org/rfc/rfc9081
        (0x01, 0x20) => ("MVPN SA RP-address", V::Generic),
        // Transitive Opaque: CP-ORF (RFC 7543 —
        // https://www.rfc-editor.org/rfc/rfc7543), Extranet (RFC 7900 —
        // https://www.rfc-editor.org/rfc/rfc7900), Additional PMSI Tunnel
        // Attribute Flags (RFC 7902 — https://www.rfc-editor.org/rfc/rfc7902),
        // Context-Specific Label Space ID (RFC 9573 —
        // https://www.rfc-editor.org/rfc/rfc9573), Local Color Mapping
        // (RFC 9871 — https://www.rfc-editor.org/rfc/rfc9871).
        (0x03, 0x03) => ("CP-ORF", V::Raw),
        (0x03, 0x04) => ("Extranet Source", V::Raw),
        (0x03, 0x05) => ("Extranet Separation", V::Raw),
        (0x03, 0x07) => ("Additional PMSI Tunnel Attribute Flags", V::Raw),
        (0x03, 0x08) => ("Context-Specific Label Space ID", V::Raw),
        (0x03, 0x1b) => ("Local Color Mapping", V::Raw),
        // Color and Encapsulation (RFC 9012, Sections 4.3 and 4.1 —
        // https://www.rfc-editor.org/rfc/rfc9012#section-4).
        (0x03, 0x0b) => ("Color", V::Color),
        (0x03, 0x0c) => ("Encapsulation", V::Encapsulation),
        // Default Gateway (RFC 7432, Section 7.8 —
        // https://www.rfc-editor.org/rfc/rfc7432#section-7.8): the Value is
        // reserved and kept as bytes.
        (0x03, 0x0d) => ("Default Gateway", V::Raw),
        // BGP Origin Validation State (RFC 8097, Section 2 —
        // https://www.rfc-editor.org/rfc/rfc8097#section-2).
        (0x43, 0x00) => ("BGP Origin Validation State", V::OriginValidation),
        // EVPN (RFC 7432, Sections 7.5-7.7 —
        // https://www.rfc-editor.org/rfc/rfc7432#section-7.5; RFC 9135,
        // Section 8.1 — https://www.rfc-editor.org/rfc/rfc9135#section-8.1).
        (0x06, 0x00) => ("MAC Mobility", V::MacMobility),
        (0x06, 0x01) => ("ESI Label", V::EsiLabel),
        (0x06, 0x02) => ("ES-Import Route Target", V::Mac),
        (0x06, 0x03) => ("EVPN Router's MAC", V::Mac),
        // EVPN sub-types kept as bytes: RFC 8214
        // (https://www.rfc-editor.org/rfc/rfc8214), RFC 8317
        // (https://www.rfc-editor.org/rfc/rfc8317), RFC 8584
        // (https://www.rfc-editor.org/rfc/rfc8584), RFC 9047
        // (https://www.rfc-editor.org/rfc/rfc9047), RFC 9251
        // (https://www.rfc-editor.org/rfc/rfc9251), RFC 9722
        // (https://www.rfc-editor.org/rfc/rfc9722).
        (0x06, 0x04) => ("EVPN Layer 2 Attributes", V::Raw),
        (0x06, 0x05) => ("E-Tree", V::Raw),
        (0x06, 0x06) => ("DF Election", V::Raw),
        (0x06, 0x08) => ("ARP/ND", V::Raw),
        (0x06, 0x09) => ("Multicast Flags", V::Raw),
        (0x06, 0x0a) => ("EVI-RT Type 0", V::Raw),
        (0x06, 0x0b) => ("EVI-RT Type 1", V::Raw),
        (0x06, 0x0c) => ("EVI-RT Type 2", V::Raw),
        (0x06, 0x0d) => ("EVI-RT Type 3", V::Raw),
        (0x06, 0x0f) => ("Service Carving Time", V::Raw),
        // Flow Specification actions (RFC 8955, Section 7 —
        // https://www.rfc-editor.org/rfc/rfc8955#section-7).
        (0x80, 0x06) => ("Flow spec traffic-rate-bytes", V::TrafficRate),
        (0x80, 0x07) => ("Flow spec traffic-action", V::TrafficAction),
        (0x80, 0x08) => ("Flow spec rt-redirect AS-2octet", V::TwoOctetAs),
        (0x80, 0x09) => ("Flow spec traffic-remarking", V::TrafficMarking),
        (0x80, 0x0c) => ("Flow spec traffic-rate-packets", V::TrafficRate),
        (0x81, 0x08) => ("Flow spec rt-redirect IPv4", V::Ipv4Address),
        (0x82, 0x08) => ("Flow spec rt-redirect AS-4octet", V::FourOctetAs),
        // Layer2 Info (RFC 4761 — https://www.rfc-editor.org/rfc/rfc4761),
        // E-Tree Info (RFC 7796 — https://www.rfc-editor.org/rfc/rfc7796),
        // SFC Classifiers (RFC 9015 — https://www.rfc-editor.org/rfc/rfc9015).
        (0x80, 0x0a) => ("Layer2 Info", V::Raw),
        (0x80, 0x0b) => ("E-Tree Info", V::Raw),
        (0x80, 0x0d) => ("Flow Specification for SFC Classifiers", V::Raw),
        // BGP-MUP Direct / Interwork Segment (draft-ietf-bess-mup-safi-01,
        // Section 3.2 — https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/).
        (0x0C, 0x00) => ("MUP Direct Segment (2-Octet AS)", V::TwoOctetAs),
        (0x0C, 0x01) => ("MUP Direct Segment (IPv4 Address)", V::Ipv4Address),
        (0x0C, 0x02) => ("MUP Direct Segment (4-Octet AS)", V::FourOctetAs),
        (0x0C, 0x03) => ("MUP Interwork Segment (2-Octet AS)", V::TwoOctetAs),
        (0x0C, 0x04) => ("MUP Interwork Segment (IPv4 Address)", V::Ipv4Address),
        (0x0C, 0x05) => ("MUP Interwork Segment (4-Octet AS)", V::FourOctetAs),
        _ => return (None, ext_community_type_layout(type_high)),
    };
    let layout = match layout {
        V::Generic => ext_community_type_layout(type_high),
        other => other,
    };
    (Some(name), layout)
}

/// Returns the Global / Local Administrator layout of an AS- or
/// IPv4-Address-Specific Extended Community Type, or [`ExtCommunityValue::Raw`].
///
/// RFC 4360, Section 3 — <https://www.rfc-editor.org/rfc/rfc4360#section-3>
/// RFC 5668, Section 2 — <https://www.rfc-editor.org/rfc/rfc5668#section-2>
fn ext_community_type_layout(type_high: u8) -> ExtCommunityValue {
    match type_high {
        0x00 | 0x40 => ExtCommunityValue::TwoOctetAs,
        0x01 | 0x41 => ExtCommunityValue::Ipv4Address,
        0x02 | 0x42 => ExtCommunityValue::FourOctetAs,
        _ => ExtCommunityValue::Raw,
    }
}

/// Returns a human-readable name for an IPv6 Address Specific Extended
/// Community Type.
///
/// RFC 5701, Section 2 — <https://www.rfc-editor.org/rfc/rfc5701#section-2>
fn ipv6_ext_community_type_name(type_high: u8) -> Option<&'static str> {
    match type_high {
        0x00 => Some("Transitive IPv6-Address-Specific"),
        0x40 => Some("Non-Transitive IPv6-Address-Specific"),
        _ => None,
    }
}

/// Returns a human-readable name for an IPv6 Address Specific Extended
/// Community (Type, Sub-Type) pair.
///
/// IANA Transitive IPv6-Address-Specific Extended Community Types —
/// <https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#trans-ipv6>
fn ipv6_ext_community_sub_type_name(type_high: u8, sub_type: u8) -> Option<&'static str> {
    match (type_high, sub_type) {
        // RFC 5701, Section 2 — https://www.rfc-editor.org/rfc/rfc5701#section-2
        (0x00, 0x02) => Some("Route Target"),
        (0x00, 0x03) => Some("Route Origin"),
        // RFC 6515 — https://www.rfc-editor.org/rfc/rfc6515
        (0x00, 0x0b) => Some("VRF Route Import"),
        // RFC 8956, Section 6.1 — https://www.rfc-editor.org/rfc/rfc8956#section-6.1
        (0x00, 0x0d) => Some("Flow spec rt-redirect-ipv6"),
        // RFC 7524 — https://www.rfc-editor.org/rfc/rfc7524
        (0x00, 0x12) => Some("Inter-Area P2MP Segmented Next-Hop"),
        _ => None,
    }
}

/// Returns a human-readable name for a BGP Origin Validation State.
///
/// RFC 8097, Section 2 — <https://www.rfc-editor.org/rfc/rfc8097#section-2>
fn origin_validation_state_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Valid"),
        1 => Some("NotFound"),
        2 => Some("Invalid"),
        _ => None,
    }
}

/// Returns the `type` sibling of an extended community object.
fn sibling_ext_type(siblings: &[packet_dissector_core::field::Field<'_>]) -> Option<u8> {
    siblings
        .iter()
        .find(|f| f.name() == "type")
        .and_then(|f| f.value.as_u8())
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

/// AS_PATH segment types defined by RFC 4271 (AS_SET = 1, AS_SEQUENCE = 2) and
/// RFC 5065 (AS_CONFED_SEQUENCE = 3, AS_CONFED_SET = 4).
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// RFC 5065, Section 3 — <https://www.rfc-editor.org/rfc/rfc5065#section-3>
const AS_PATH_SEGMENT_TYPES: core::ops::RangeInclusive<u8> = 1..=4;

/// Returns `true` when `data` is a well-formed AS_PATH / AS4_PATH value whose
/// AS numbers are `as_size` octets wide.
///
/// Every segment must have a recognized segment type (1-4), a non-zero Path
/// Segment Length, and the segments must consume `data` exactly. These are the
/// RFC 7606 malformation rules:
///
/// > An AS_PATH is considered malformed if an unrecognized segment type is
/// > encountered or if it contains a malformed segment.  A segment is
/// > considered malformed if any of the following are true:
/// >
/// > o  There is an overrun where the Path Segment Length field of the
/// >    last segment encountered would cause the Attribute Length to be
/// >    exceeded.
/// >
/// > o  There is an underrun where after the last successfully parsed
/// >    segment there is only a single octet remaining (that is, there is
/// >    not enough unconsumed data to provide even an empty segment
/// >    header).
/// >
/// > o  It has a Path Segment Length field of zero.
///
/// RFC 7606, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc7606#section-7.2>
fn as_path_fits(data: &[u8], as_size: usize) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let Some(&seg_len) = data.get(pos + 1) else {
            return false;
        };
        if !AS_PATH_SEGMENT_TYPES.contains(&data[pos]) || seg_len == 0 {
            return false;
        }
        pos += 2 + seg_len as usize * as_size;
    }
    pos == data.len()
}

/// Selects the AS number size (4 or 2 octets) of an AS_PATH attribute value.
///
/// The size is negotiated per session: "A BGP speaker that advertises such a
/// capability to a particular peer, and receives from that peer the
/// advertisement of such a capability, MUST encode AS numbers as four-octet
/// entities in both the AS_PATH attribute and the AGGREGATOR attribute"
/// (RFC 6793, Section 4.1). This dissector is stateless and cannot see the
/// OPEN exchange, so the size is inferred from the structure of the value with
/// [`as_path_fits`]:
///
/// 1. `hint`, derived from the other attributes of the same UPDATE by
///    [`AttrContext::for_update`], wins when the value fits it;
/// 2. otherwise four-octet is tried first because RFC 6793 sessions are the
///    common case, so a value that is valid for both sizes is decoded with
///    four-octet AS numbers.
///
/// Returns `None` when neither size fits.
///
/// RFC 6793, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6793#section-4.1>
fn detect_as_path_as_size(data: &[u8], hint: Option<usize>) -> Option<usize> {
    hint.into_iter()
        .chain([4, 2])
        .find(|&size| as_path_fits(data, size))
}

/// Pushes an AS_PATH or AS4_PATH attribute value as the attribute `value`
/// Array of segment objects.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
/// RFC 6793 — <https://www.rfc-editor.org/rfc/rfc6793>
///
/// Callers validate `data` with [`as_path_fits`] first, so every segment is
/// complete.
fn parse_as_path<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    as_size: usize,
) {
    let array_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
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
    buf.end_container(array_idx);
}

/// Parses the value of a path attribute based on its type code.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
///
/// Inside an ATTR_SET ([`AttrContext::in_attr_set`]) a further ATTR_SET is
/// not decoded (its value is kept as raw bytes), and AS_PATH / AGGREGATOR are
/// decoded only with 4-octet AS numbers (RFC 6368, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc6368#section-5>). MP_REACH_NLRI /
/// MP_UNREACH_NLRI never get here: they make the ATTR_SET malformed (see
/// [`parse_attr_set`]).
fn parse_attr_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    type_code: u8,
    data: &'pkt [u8],
    offset: usize,
    ctx: AttrContext,
) -> Option<MpAfiSafi> {
    let as_size_hint = ctx.as_size_hint;
    match type_code {
        128 if ctx.in_attr_set => push_raw_attr_value(buf, data, offset),
        // ORIGIN (RFC 4271, Section 5.1.1)
        1 if data.len() == 1 => {
            buf.push_field(
                &FD_ORIGIN_VALUE,
                FieldValue::U8(data[0]),
                offset..offset + 1,
            );
        }
        // AS_PATH (RFC 4271, Section 5.1.2) — 2-octet AS numbers, or 4-octet
        // AS numbers between NEW BGP speakers (RFC 6793, Section 4.1 —
        // https://www.rfc-editor.org/rfc/rfc6793#section-4.1).
        2 if data.is_empty() => {
            // No segments: nothing to infer the AS number size from.
            parse_as_path(buf, data, offset, 2);
        }
        // Inside an ATTR_SET only 4-octet AS numbers are valid.
        2 if ctx.in_attr_set && !as_path_fits(data, 4) => push_raw_attr_value(buf, data, offset),
        2 => match detect_as_path_as_size(data, as_size_hint) {
            Some(as_size) => {
                parse_as_path(buf, data, offset, as_size);
                buf.push_field(
                    &PATH_ATTR_CHILDREN[FD_PA_AS_NUMBER_SIZE],
                    FieldValue::U8(as_size as u8),
                    offset..offset + data.len(),
                );
            }
            // Malformed for both sizes (RFC 7606, Section 7.2 —
            // https://www.rfc-editor.org/rfc/rfc7606#section-7.2): keep the raw
            // octets rather than a partial decode.
            None => {
                buf.push_field(
                    &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                    FieldValue::Bytes(data),
                    offset..offset + data.len(),
                );
            }
        },
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
        7 if data.len() == 8 || (data.len() == 6 && !ctx.in_attr_set) => {
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
            return Some(parse_mp_reach_nlri(buf, data, offset, ctx.vni_label));
        }
        // MP_UNREACH_NLRI (RFC 4760, Section 4)
        15 if data.len() >= 3 => {
            return Some(parse_mp_unreach_nlri(buf, data, offset, ctx.vni_label));
        }
        // EXTENDED COMMUNITIES (RFC 4360, Section 2 —
        // https://www.rfc-editor.org/rfc/rfc4360#section-2) — 8-octet
        // communities.
        16 if data.len() % EXT_COMMUNITY_SIZE == 0 => parse_ext_communities(buf, data, offset),
        // IPv6 Address Specific Extended Community (RFC 5701, Section 2 —
        // https://www.rfc-editor.org/rfc/rfc5701#section-2) — 20-octet
        // communities.
        25 if data.len() % IPV6_EXT_COMMUNITY_SIZE == 0 => {
            parse_ipv6_ext_communities(buf, data, offset)
        }
        // AS4_PATH (RFC 6793) — same format as AS_PATH but with 4-byte AS numbers
        17 if as_path_fits(data, 4) => {
            parse_as_path(buf, data, offset, 4);
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
        // Only to Customer (OTC) (RFC 9234, Section 5 —
        // https://www.rfc-editor.org/rfc/rfc9234#section-5): "Attribute Type
        // Code 35 and a length of 4 octets. ... The attribute value is an AS
        // number (ASN)".
        35 if data.len() == 4 => {
            buf.push_field(
                &PATH_ATTR_CHILDREN[FD_PA_VALUE],
                FieldValue::U32(read_be_u32(data, 0).unwrap_or_default()),
                offset..offset + 4,
            );
        }
        // Structured attributes whose decoder keeps the value raw when it
        // does not parse exactly.
        22 | 23 | 26 | 29 | 33 | 37 | 38 | 128 => {
            let decoded = match type_code {
                // PMSI_TUNNEL (RFC 6514, Section 5 —
                // https://www.rfc-editor.org/rfc/rfc6514#section-5)
                22 => parse_pmsi_tunnel(buf, data, offset, ctx.vni_label),
                // Tunnel Encapsulation (RFC 9012, Section 2 —
                // https://www.rfc-editor.org/rfc/rfc9012#section-2)
                23 => parse_tunnel_encapsulation(buf, data, offset),
                // AIGP (RFC 7311, Section 3 —
                // https://www.rfc-editor.org/rfc/rfc7311#section-3)
                26 => parse_aigp(buf, data, offset),
                // BGP-LS Attribute (RFC 9552, Section 5.3 —
                // https://www.rfc-editor.org/rfc/rfc9552#section-5.3)
                29 => parse_bgp_ls_attribute(buf, data, offset),
                // BGPsec_Path (RFC 8205, Section 3 —
                // https://www.rfc-editor.org/rfc/rfc8205#section-3)
                33 => parse_bgpsec_path(buf, data, offset),
                // SFP attribute (RFC 9015, Section 3.2.1 —
                // https://www.rfc-editor.org/rfc/rfc9015#section-3.2.1)
                37 => parse_sfp_attribute(buf, data, offset),
                // BFD Discriminator (RFC 9026, Section 3.1.6 —
                // https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6)
                38 => parse_bfd_discriminator(buf, data, offset),
                // ATTR_SET (RFC 6368, Section 5 —
                // https://www.rfc-editor.org/rfc/rfc6368#section-5)
                128 => parse_attr_set(buf, data, offset),
                _ => false,
            };
            if !decoded {
                push_raw_attr_value(buf, data, offset);
            }
        }
        // Unknown/unhandled attribute: store raw bytes
        _ => push_raw_attr_value(buf, data, offset),
    }
    None
}

/// Layout of a Type-Length-Value header.
#[derive(Clone, Copy)]
struct TlvShape {
    /// Size of the Type field (1 or 2 octets).
    type_len: usize,
    /// Size of the Length field (1 or 2 octets).
    len_len: usize,
    /// Whether the Length counts the Type and Length fields too (RFC 7311,
    /// Section 3 — <https://www.rfc-editor.org/rfc/rfc7311#section-3>) rather
    /// than only the Value.
    len_includes_header: bool,
}

impl TlvShape {
    /// A TLV whose Length counts only the Value.
    const fn new(type_len: usize, len_len: usize) -> Self {
        Self {
            type_len,
            len_len,
            len_includes_header: false,
        }
    }

    /// Size of the Type and Length fields.
    const fn header_len(self) -> usize {
        self.type_len + self.len_len
    }
}

/// AIGP TLV: 1-octet Type, 2-octet Length including the Type and Length
/// fields (RFC 7311, Section 3 — <https://www.rfc-editor.org/rfc/rfc7311#section-3>).
const AIGP_TLV_SHAPE: TlvShape = TlvShape {
    type_len: 1,
    len_len: 2,
    len_includes_header: true,
};
/// Tunnel TLV: 2-octet Tunnel Type, 2-octet Length (RFC 9012, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc9012#section-2>).
const TUNNEL_TLV_SHAPE: TlvShape = TlvShape::new(2, 2);
/// BGP-LS TLV: 2-octet Type, 2-octet Length (RFC 9552, Section 5.1 —
/// <https://www.rfc-editor.org/rfc/rfc9552#section-5.1>).
const BGP_LS_TLV_SHAPE: TlvShape = TlvShape::new(2, 2);
/// SFP attribute TLV: 1-octet Type, 2-octet Length (RFC 9015,
/// Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9015#section-3.2.1>).
const SFP_TLV_SHAPE: TlvShape = TlvShape::new(1, 2);
/// BFD Discriminator Optional TLV: 1-octet Type, 1-octet Length (RFC 9026,
/// Section 3.1.6 — <https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6>).
const BFD_TLV_SHAPE: TlvShape = TlvShape::new(1, 1);

/// Returns `(type, value_len)` for the TLV of the given shape at `pos`, or
/// `None` when its header or value does not fit in `data`.
fn tlv_at(data: &[u8], pos: usize, shape: TlvShape) -> Option<(u16, usize)> {
    let header_len = shape.header_len();
    let header = data.get(pos..pos.checked_add(header_len)?)?;
    let tlv_type = match shape.type_len {
        1 => u16::from(header[0]),
        _ => read_be_u16(header, 0).ok()?,
    };
    let length = match shape.len_len {
        1 => usize::from(header[shape.type_len]),
        _ => usize::from(read_be_u16(header, shape.type_len).ok()?),
    };
    let value_len = if shape.len_includes_header {
        length.checked_sub(header_len)?
    } else {
        length
    };
    (pos + header_len + value_len <= data.len()).then_some((tlv_type, value_len))
}

/// Returns `value` as a [`FieldValue`] of the descriptor's type (U8 or U16).
fn u8_or_u16(descriptor: &FieldDescriptor, value: u16) -> FieldValue<'static> {
    match descriptor.field_type {
        FieldType::U8 => FieldValue::U8(value as u8),
        _ => FieldValue::U16(value),
    }
}

/// One TLV opened by [`begin_tlv_object`].
struct OpenTlv<'pkt> {
    /// Placeholder index of the TLV Object, to pass to `end_container`.
    idx: u32,
    /// The Type field.
    tlv_type: u16,
    /// The Value field.
    value: &'pkt [u8],
    /// Absolute offset of the Value field.
    value_offset: usize,
    /// Offset of the next TLV, relative to the TLV sequence.
    next: usize,
}

/// Opens the Object of the TLV of the given shape at `pos` of `data` (which
/// starts at absolute `offset`) and pushes its Type (`fields[0]`) and Length
/// (`fields[1]`), each as a U8 or a U16 following its descriptor.
///
/// Returns `None` (nothing pushed) when the TLV does not fit.
fn begin_tlv_object<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    object: &'static FieldDescriptor,
    fields: &'static [FieldDescriptor],
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
    shape: TlvShape,
) -> Option<OpenTlv<'pkt>> {
    let (tlv_type, value_len) = tlv_at(data, pos, shape)?;
    let header_len = shape.header_len();
    let next = pos + header_len + value_len;
    let abs = offset + pos;
    let idx = buf.begin_container(object, FieldValue::Object(0..0), abs..offset + next);
    buf.push_field(
        &fields[0],
        u8_or_u16(&fields[0], tlv_type),
        abs..abs + shape.type_len,
    );
    let length = if shape.len_includes_header {
        value_len + header_len
    } else {
        value_len
    };
    buf.push_field(
        &fields[1],
        u8_or_u16(&fields[1], length as u16),
        abs + shape.type_len..abs + header_len,
    );
    Some(OpenTlv {
        idx,
        tlv_type,
        value: &data[pos + header_len..next],
        value_offset: abs + header_len,
        next,
    })
}

/// Pushes `value` with `descriptor` as Bytes (unless empty).
fn push_bytes_nonempty<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    value: &'pkt [u8],
    offset: usize,
) {
    if !value.is_empty() {
        buf.push_field(
            descriptor,
            FieldValue::Bytes(value),
            offset..offset + value.len(),
        );
    }
}

/// Pushes `data` as the raw `value` of a path attribute (unless empty).
fn push_raw_attr_value<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    push_bytes_nonempty(buf, &PATH_ATTR_CHILDREN[FD_PA_VALUE], data, offset);
}

/// AIGP TLV type "AIGP" (RFC 7311, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc7311#section-3>).
const AIGP_TLV_TYPE_AIGP: u16 = 1;

/// Parses the AIGP attribute value (type code 26) as a sequence of TLVs.
///
/// RFC 7311, Section 3 — <https://www.rfc-editor.org/rfc/rfc7311#section-3>
///
/// The AIGP TLV (Type 1, Length 11) carries an 8-octet Accumulated IGP
/// Metric; TLVs of other types keep their value as bytes. Returns `false`
/// (nothing left pushed) when the TLVs do not exactly fill the attribute or
/// an AIGP TLV does not have Length 11.
fn parse_aigp<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }
    let mark = buf.fields().len();
    let array_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let Some(tlv) = begin_tlv_object(
            buf,
            &AIGP_TLV_OBJECT_DESCRIPTOR,
            AIGP_TLV_CHILDREN,
            data,
            pos,
            offset,
            AIGP_TLV_SHAPE,
        ) else {
            buf.truncate_fields(mark);
            return false;
        };
        if tlv.tlv_type == AIGP_TLV_TYPE_AIGP {
            // "The value field of the AIGP TLV is always 8 octets long, and
            // its value is interpreted as an unsigned 64-bit integer."
            let metric = match read_be_u64(tlv.value, 0) {
                Ok(metric) if tlv.value.len() == 8 => metric,
                _ => {
                    buf.truncate_fields(mark);
                    return false;
                }
            };
            buf.push_field(
                &AIGP_TLV_CHILDREN[FD_AIGP_METRIC],
                FieldValue::U64(metric),
                tlv.value_offset..tlv.value_offset + 8,
            );
        } else {
            push_bytes_nonempty(
                buf,
                &AIGP_TLV_CHILDREN[FD_AIGP_VALUE],
                tlv.value,
                tlv.value_offset,
            );
        }
        buf.end_container(tlv.idx);
        pos = tlv.next;
    }
    buf.end_container(array_idx);
    true
}

/// PMSI Tunnel Type "Ingress Replication" (RFC 6514, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc6514#section-5>).
const PMSI_TUNNEL_INGRESS_REPLICATION: u8 = 6;
/// Size of the PMSI Tunnel attribute fixed part: Flags (1), Tunnel Type (1)
/// and MPLS Label (3) (RFC 6514, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc6514#section-5>).
const PMSI_TUNNEL_FIXED_SIZE: usize = 5;

/// Parses the PMSI_TUNNEL attribute value (type code 22).
///
/// RFC 6514, Section 5 — <https://www.rfc-editor.org/rfc/rfc6514#section-5>
///
/// Flags, Tunnel Type, MPLS Label and a Tunnel Identifier whose syntax depends
/// on the Tunnel Type. The Ingress Replication identifier — "the unicast
/// tunnel endpoint IP address" — is decoded as an address; the others stay
/// bytes.
///
/// The MPLS Label field is exposed as `mpls_label` ("the high-order 20 bits
/// contain the label value"), or as `vni` when `vni_label` is set: with a
/// VXLAN / NVGRE / VXLAN-GPE encapsulation "the entire 24-bit field is used to
/// encode the VNI value" (RFC 8365, Section 5.1.3 —
/// <https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3>).
///
/// Returns `false` (nothing pushed) when the fixed part is truncated.
fn parse_pmsi_tunnel<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    vni_label: bool,
) -> bool {
    if data.len() < PMSI_TUNNEL_FIXED_SIZE {
        return false;
    }
    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_PMSI_FLAGS],
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    let tunnel_type = data[1];
    buf.push_field(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_TUNNEL_TYPE],
        FieldValue::U8(tunnel_type),
        offset + 1..offset + 2,
    );
    let label_field = read_be_u24(data, 2).unwrap_or_default();
    let (label_fd, label) = if vni_label {
        (FD_PAV_VNI, label_field)
    } else {
        (FD_PAV_MPLS_LABEL, label_field >> 4)
    };
    buf.push_field(
        &PATH_ATTR_VALUE_BASE_FIELDS[label_fd],
        FieldValue::U32(label),
        offset + 2..offset + PMSI_TUNNEL_FIXED_SIZE,
    );
    let identifier = &data[PMSI_TUNNEL_FIXED_SIZE..];
    let id_offset = offset + PMSI_TUNNEL_FIXED_SIZE;
    if tunnel_type == PMSI_TUNNEL_INGRESS_REPLICATION
        && (identifier.len() == 4 || identifier.len() == 16)
    {
        buf.push_field(
            &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_TUNNEL_ENDPOINT],
            format_address(identifier, identifier.len() == 16),
            id_offset..id_offset + identifier.len(),
        );
    } else {
        push_bytes_nonempty(
            buf,
            &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_TUNNEL_IDENTIFIER],
            identifier,
            id_offset,
        );
    }
    buf.end_container(obj_idx);
    true
}

/// Returns the shape of the Tunnel Encapsulation sub-TLV of type `sub_type`.
///
/// RFC 9012, Section 2 — <https://www.rfc-editor.org/rfc/rfc9012#section-2>:
/// "The Sub-TLV Length field contains 1 octet if the Sub-TLV Type field
/// contains a value in the range from 0-127. The Sub-TLV Length field contains
/// two octets if the Sub-TLV Type field contains a value in the range from
/// 128-255."
fn tunnel_sub_tlv_shape(sub_type: u8) -> TlvShape {
    TlvShape::new(1, if sub_type < 128 { 1 } else { 2 })
}

/// Parses the Tunnel Encapsulation attribute value (type code 23).
///
/// RFC 9012, Section 2 — <https://www.rfc-editor.org/rfc/rfc9012#section-2>
///
/// The value is a set of Tunnel TLVs, each carrying sub-TLVs, exposed as
/// `tunnels`. Returns `false` (nothing left pushed) when the TLVs or sub-TLVs
/// do not exactly fill their enclosing field.
fn parse_tunnel_encapsulation<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }
    let mark = buf.fields().len();
    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    let array_idx = buf.begin_container(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_TUNNELS],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let Some(tlv) = begin_tlv_object(
            buf,
            &TUNNEL_TLV_OBJECT_DESCRIPTOR,
            TUNNEL_TLV_CHILDREN,
            data,
            pos,
            offset,
            TUNNEL_TLV_SHAPE,
        ) else {
            buf.truncate_fields(mark);
            return false;
        };
        let subs_idx = buf.begin_container(
            &TUNNEL_TLV_CHILDREN[FD_TUN_SUB_TLVS],
            FieldValue::Array(0..0),
            tlv.value_offset..tlv.value_offset + tlv.value.len(),
        );
        if !parse_tunnel_sub_tlvs(buf, tlv.value, tlv.value_offset) {
            buf.truncate_fields(mark);
            return false;
        }
        buf.end_container(subs_idx);
        buf.end_container(tlv.idx);
        pos = tlv.next;
    }
    buf.end_container(array_idx);
    buf.end_container(obj_idx);
    true
}

/// Tunnel Encapsulation sub-TLV types decoded beyond raw bytes (RFC 9012,
/// Sections 3.1, 3.3.2, 3.4.1 and 3.4.2 —
/// <https://www.rfc-editor.org/rfc/rfc9012#section-3>).
const TUNNEL_SUB_TLV_PROTOCOL_TYPE: u8 = 2;
const TUNNEL_SUB_TLV_COLOR: u8 = 4;
const TUNNEL_SUB_TLV_EGRESS_ENDPOINT: u8 = 6;
const TUNNEL_SUB_TLV_UDP_PORT: u8 = 8;

/// Parses the sub-TLVs of one Tunnel TLV. Returns `false` when they do not
/// exactly fill `data` (the caller discards what was pushed).
///
/// RFC 9012, Section 3 — <https://www.rfc-editor.org/rfc/rfc9012#section-3>
fn parse_tunnel_sub_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let fields = TUNNEL_SUB_TLV_CHILDREN;
    let mut pos = 0;
    while pos < data.len() {
        let sub_type = data[pos];
        let Some(tlv) = begin_tlv_object(
            buf,
            &TUNNEL_SUB_TLV_OBJECT_DESCRIPTOR,
            fields,
            data,
            pos,
            offset,
            tunnel_sub_tlv_shape(sub_type),
        ) else {
            return false;
        };
        let (value, vo) = (tlv.value, tlv.value_offset);
        match (sub_type, read_be_u16(value, 4).ok(), value.len()) {
            // Tunnel Egress Endpoint (RFC 9012, Section 3.1 —
            // https://www.rfc-editor.org/rfc/rfc9012#section-3.1): Reserved
            // (4), Address Family (2) and an Address of 0 (Address Family 0),
            // 4 (IPv4) or 16 (IPv6) octets.
            (TUNNEL_SUB_TLV_EGRESS_ENDPOINT, Some(afi @ (0 | AFI_IPV4 | AFI_IPV6)), len)
                if len == 6 + address_len(afi) =>
            {
                buf.push_field(
                    &fields[FD_TSUB_ADDRESS_FAMILY],
                    FieldValue::U16(afi),
                    vo + 4..vo + 6,
                );
                if len > 6 {
                    buf.push_field(
                        &fields[FD_TSUB_ADDRESS],
                        format_address(&value[6..], afi == AFI_IPV6),
                        vo + 6..vo + len,
                    );
                }
            }
            // Color (RFC 9012, Section 3.4.2 —
            // https://www.rfc-editor.org/rfc/rfc9012#section-3.4.2): a Color
            // Extended Community (Section 4.3). "If the Length field of a
            // Color sub-TLV has a value other than 8, or the first two octets
            // of its Value field are not 0x030b, the sub-TLV MUST be treated
            // as if it were an unrecognized sub-TLV".
            (TUNNEL_SUB_TLV_COLOR, _, 8) if value[..2] == [0x03, 0x0b] => {
                buf.push_field(
                    &fields[FD_TSUB_FLAGS],
                    FieldValue::U16(read_be_u16(value, 2).unwrap_or_default()),
                    vo + 2..vo + 4,
                );
                buf.push_field(
                    &fields[FD_TSUB_COLOR],
                    FieldValue::U32(read_be_u32(value, 4).unwrap_or_default()),
                    vo + 4..vo + 8,
                );
            }
            // UDP Destination Port (RFC 9012, Section 3.3.2 —
            // https://www.rfc-editor.org/rfc/rfc9012#section-3.3.2).
            (TUNNEL_SUB_TLV_UDP_PORT, _, 2) => buf.push_field(
                &fields[FD_TSUB_UDP_PORT],
                FieldValue::U16(read_be_u16(value, 0).unwrap_or_default()),
                vo..vo + 2,
            ),
            // Protocol Type (RFC 9012, Section 3.4.1 —
            // https://www.rfc-editor.org/rfc/rfc9012#section-3.4.1): an
            // EtherType.
            (TUNNEL_SUB_TLV_PROTOCOL_TYPE, _, 2) => buf.push_field(
                &fields[FD_TSUB_PROTOCOL_TYPE],
                FieldValue::U16(read_be_u16(value, 0).unwrap_or_default()),
                vo..vo + 2,
            ),
            _ => push_bytes_nonempty(buf, &fields[FD_TSUB_VALUE], value, vo),
        }
        buf.end_container(tlv.idx);
        pos = tlv.next;
    }
    true
}

/// Returns the address length for an IANA Address Family Number (IPv4: 4,
/// IPv6: 16, anything else: 0).
fn address_len(afi: u16) -> usize {
    match afi {
        AFI_IPV4 => 4,
        AFI_IPV6 => 16,
        _ => 0,
    }
}

/// Pushes `data` as an Array of TLV objects whose `fields` are
/// `[type, length, value]`. Returns `false` (nothing left pushed) when the
/// TLVs do not exactly fill `data`.
fn push_generic_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array: &'static FieldDescriptor,
    object: &'static FieldDescriptor,
    fields: &'static [FieldDescriptor],
    data: &'pkt [u8],
    offset: usize,
    shape: TlvShape,
) -> bool {
    let mark = buf.fields().len();
    let array_idx =
        buf.begin_container(array, FieldValue::Array(0..0), offset..offset + data.len());
    let mut pos = 0;
    while pos < data.len() {
        let Some(tlv) = begin_tlv_object(buf, object, fields, data, pos, offset, shape) else {
            buf.truncate_fields(mark);
            return false;
        };
        push_bytes_nonempty(buf, &fields[2], tlv.value, tlv.value_offset);
        buf.end_container(tlv.idx);
        pos = tlv.next;
    }
    buf.end_container(array_idx);
    true
}

/// Parses the BGP-LS Attribute value (type code 29).
///
/// RFC 9552, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.3>
///
/// A set of TLVs exposed as `tlvs`, whose values are kept as bytes. Returns
/// `false` (nothing left pushed) when the TLVs do not exactly fill the
/// attribute.
fn parse_bgp_ls_attribute<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.is_empty() {
        return false;
    }
    let mark = buf.fields().len();
    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    if !push_generic_tlvs(
        buf,
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_TLVS],
        &BGP_LS_TLV_OBJECT_DESCRIPTOR,
        BGP_LS_TLV_CHILDREN,
        data,
        offset,
        BGP_LS_TLV_SHAPE,
    ) {
        buf.truncate_fields(mark);
        return false;
    }
    buf.end_container(obj_idx);
    true
}

/// Parses the SFP attribute value (type code 37) as a sequence of TLVs.
///
/// RFC 9015, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9015#section-3.2.1>
///
/// Returns `false` (nothing left pushed) when the TLVs do not exactly fill
/// the attribute ("TLV length that suggests the TLV extends beyond the end of
/// the SFP attribute" is an error).
fn parse_sfp_attribute<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    !data.is_empty()
        && push_generic_tlvs(
            buf,
            &PATH_ATTR_CHILDREN[FD_PA_VALUE],
            &SFP_TLV_OBJECT_DESCRIPTOR,
            SFP_TLV_CHILDREN,
            data,
            offset,
            SFP_TLV_SHAPE,
        )
}

/// Size of a BGPsec Secure_Path Segment (RFC 8205, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc8205#section-3.1>).
const BGPSEC_SEGMENT_SIZE: usize = 6;
/// Size of the Subject Key Identifier of a Signature Segment (RFC 8205,
/// Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8205#section-3.2>).
const BGPSEC_SKI_SIZE: usize = 20;
/// Signature_Block Length (2) and Algorithm Suite Identifier (1) (RFC 8205,
/// Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8205#section-3.2>).
const BGPSEC_BLOCK_HEADER_SIZE: usize = 3;

/// Parses the BGPsec_Path attribute value (type code 33).
///
/// RFC 8205, Section 3 — <https://www.rfc-editor.org/rfc/rfc8205#section-3>
///
/// A Secure_Path of one or more 6-octet segments followed by one or two
/// Signature_Blocks. Returns `false` (nothing left pushed) when the value is
/// not well formed: a Secure_Path Length other than 2 + 6n (n >= 1), a number
/// of Signature_Blocks other than one or two, a Signature_Block without
/// exactly n Signature Segments, or Signature_Blocks / Signature Segments that
/// do not exactly fill their enclosing field.
fn parse_bgpsec_path<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let Ok(sp_len) = read_be_u16(data, 0).map(usize::from) else {
        return false;
    };
    // "the Secure_Path Length is two greater than six times the number of
    // Secure_Path Segments" (RFC 8205, Section 3.1 —
    // https://www.rfc-editor.org/rfc/rfc8205#section-3.1).
    if sp_len < 2 + BGPSEC_SEGMENT_SIZE
        || (sp_len - 2) % BGPSEC_SEGMENT_SIZE != 0
        || sp_len >= data.len()
    {
        return false;
    }
    let mark = buf.fields().len();
    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_SECURE_PATH_LENGTH],
        FieldValue::U16(sp_len as u16),
        offset..offset + 2,
    );
    let sp_idx = buf.begin_container(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_SECURE_PATH],
        FieldValue::Array(0..0),
        offset + 2..offset + sp_len,
    );
    for pos in (2..sp_len).step_by(BGPSEC_SEGMENT_SIZE) {
        let abs = offset + pos;
        let seg_idx = buf.begin_container(
            &BGPSEC_SEGMENT_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + BGPSEC_SEGMENT_SIZE,
        );
        buf.push_field(
            &BGPSEC_SEGMENT_CHILDREN[FD_BSEG_PCOUNT],
            FieldValue::U8(data[pos]),
            abs..abs + 1,
        );
        buf.push_field(
            &BGPSEC_SEGMENT_CHILDREN[FD_BSEG_FLAGS],
            FieldValue::U8(data[pos + 1]),
            abs + 1..abs + 2,
        );
        buf.push_field(
            &BGPSEC_SEGMENT_CHILDREN[FD_BSEG_ASN],
            FieldValue::U32(read_be_u32(data, pos + 2).unwrap_or_default()),
            abs + 2..abs + BGPSEC_SEGMENT_SIZE,
        );
        buf.end_container(seg_idx);
    }
    buf.end_container(sp_idx);

    let blocks_idx = buf.begin_container(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_SIGNATURE_BLOCKS],
        FieldValue::Array(0..0),
        offset + sp_len..offset + data.len(),
    );
    let segments = (sp_len - 2) / BGPSEC_SEGMENT_SIZE;
    let mut pos = sp_len;
    let mut blocks = 0;
    while pos < data.len() {
        blocks += 1;
        match parse_bgpsec_signature_block(buf, data, pos, offset, segments) {
            // "The BGPsec_PATH attribute will contain one or two
            // Signature_Blocks" (RFC 8205, Section 3).
            Some(end) if blocks <= 2 => pos = end,
            _ => {
                buf.truncate_fields(mark);
                return false;
            }
        }
    }
    buf.end_container(blocks_idx);
    buf.end_container(obj_idx);
    true
}

/// Parses the Signature_Block at `pos` of a BGPsec_Path value and returns the
/// offset just past it, or `None` when it is not well formed (the caller
/// discards what was pushed).
///
/// RFC 8205, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8205#section-3.2>:
/// "The Signature_Block Length in Figure 6 is the total number of octets in
/// the Signature_Block (including the 2 octets used to express this length
/// field)", and "A Signature_Block in Figure 6 has exactly one Signature
/// Segment (see Figure 7) for each Secure_Path Segment" — `segments` of them.
fn parse_bgpsec_signature_block<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
    segments: usize,
) -> Option<usize> {
    let block_len = usize::from(read_be_u16(data, pos).ok()?);
    let end = pos + block_len;
    if block_len < BGPSEC_BLOCK_HEADER_SIZE || end > data.len() {
        return None;
    }
    let abs = offset + pos;
    let block_idx = buf.begin_container(
        &BGPSEC_BLOCK_OBJECT_DESCRIPTOR,
        FieldValue::Object(0..0),
        abs..abs + block_len,
    );
    buf.push_field(
        &BGPSEC_BLOCK_CHILDREN[FD_BBLK_LENGTH],
        FieldValue::U16(block_len as u16),
        abs..abs + 2,
    );
    buf.push_field(
        &BGPSEC_BLOCK_CHILDREN[FD_BBLK_ALGORITHM_SUITE],
        FieldValue::U8(data[pos + 2]),
        abs + 2..abs + BGPSEC_BLOCK_HEADER_SIZE,
    );
    let segs_idx = buf.begin_container(
        &BGPSEC_BLOCK_CHILDREN[FD_BBLK_SIGNATURE_SEGMENTS],
        FieldValue::Array(0..0),
        abs + BGPSEC_BLOCK_HEADER_SIZE..abs + block_len,
    );
    let mut spos = pos + BGPSEC_BLOCK_HEADER_SIZE;
    let mut count = 0;
    while spos < end {
        count += 1;
        // Signature Segment: SKI (20), Signature Length (2), Signature.
        let sig_start = spos + BGPSEC_SKI_SIZE + 2;
        let sig_len = usize::from(read_be_u16(&data[..end], spos + BGPSEC_SKI_SIZE).ok()?);
        let seg_end = sig_start + sig_len;
        if seg_end > end {
            return None;
        }
        let sabs = offset + spos;
        let seg_idx = buf.begin_container(
            &BGPSEC_SIGNATURE_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            sabs..offset + seg_end,
        );
        buf.push_field(
            &BGPSEC_SIGNATURE_CHILDREN[FD_BSIG_SKI],
            FieldValue::Bytes(&data[spos..spos + BGPSEC_SKI_SIZE]),
            sabs..sabs + BGPSEC_SKI_SIZE,
        );
        buf.push_field(
            &BGPSEC_SIGNATURE_CHILDREN[FD_BSIG_SIGNATURE_LENGTH],
            FieldValue::U16(sig_len as u16),
            sabs + BGPSEC_SKI_SIZE..offset + sig_start,
        );
        push_bytes_nonempty(
            buf,
            &BGPSEC_SIGNATURE_CHILDREN[FD_BSIG_SIGNATURE],
            &data[sig_start..seg_end],
            offset + sig_start,
        );
        buf.end_container(seg_idx);
        spos = seg_end;
    }
    if count != segments {
        return None;
    }
    buf.end_container(segs_idx);
    buf.end_container(block_idx);
    Some(end)
}

/// ATTR_SET Origin AS size (RFC 6368, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc6368#section-5>).
const ATTR_SET_ORIGIN_AS_SIZE: usize = 4;

/// Parses the ATTR_SET attribute value (type code 128).
///
/// RFC 6368, Section 5 — <https://www.rfc-editor.org/rfc/rfc6368#section-5>
///
/// A 4-octet Origin AS followed by path attributes, parsed with
/// [`AttrContext::in_attr_set`]. Returns `false` (nothing left pushed) when
/// the ATTR_SET is malformed — "Its length is less than 4 octets", or "The
/// original path attributes carried in the variable-length attribute data
/// include the MP_REACH or MP_UNREACH attribute" — or when the nested
/// attributes do not exactly fill it. A nested attribute whose own value is
/// malformed keeps its raw bytes, like a top-level one, so that the other
/// nested attributes stay decoded.
///
/// MP_REACH_NLRI / MP_UNREACH_NLRI are rejected before they are parsed:
/// [`DissectBuffer::truncate_fields`] does not roll back the scratch buffer
/// that the labeled NLRI decoder writes to.
fn parse_attr_set<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() < ATTR_SET_ORIGIN_AS_SIZE {
        return false;
    }
    let attrs = &data[ATTR_SET_ORIGIN_AS_SIZE..];
    let ctx = AttrContext {
        // "The AS_PATH and AGGREGATOR attributes contained within an ATTR_SET
        // attribute MUST be encoded using 4-octet AS numbers".
        as_size_hint: Some(4),
        in_attr_set: true,
        ..AttrContext::for_update(attrs)
    };
    let mark = buf.fields().len();
    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &PATH_ATTR_VALUE_CHILDREN[FD_PAV_ORIGIN_AS],
        FieldValue::U32(read_be_u32(data, 0).unwrap_or_default()),
        offset..offset + ATTR_SET_ORIGIN_AS_SIZE,
    );
    let array_idx = buf.begin_container(
        &PATH_ATTR_VALUE_CHILDREN[FD_PAV_PATH_ATTRIBUTES],
        FieldValue::Array(0..0),
        offset + ATTR_SET_ORIGIN_AS_SIZE..offset + data.len(),
    );
    let mut pos = 0;
    while pos < attrs.len() {
        let forbidden = matches!(attrs.get(pos + 1), Some(14 | 15));
        let parsed = if forbidden {
            None
        } else {
            parse_path_attribute(
                buf,
                &attrs[pos..],
                offset + ATTR_SET_ORIGIN_AS_SIZE + pos,
                ctx,
            )
        };
        match parsed {
            Some((consumed, _)) => pos += consumed,
            None => {
                buf.truncate_fields(mark);
                return false;
            }
        }
    }
    buf.end_container(array_idx);
    buf.end_container(obj_idx);
    true
}

/// Fixed part of the BFD Discriminator attribute: BFD Mode (1) and BFD
/// Discriminator (4) (RFC 9026, Section 3.1.6 —
/// <https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6>).
const BFD_DISCRIMINATOR_FIXED_SIZE: usize = 5;
/// "The BFD Discriminator attribute MUST be considered malformed if its length
/// is smaller than 11 octets" (RFC 9026, Section 3.1.6 —
/// <https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6>).
const BFD_DISCRIMINATOR_MIN_SIZE: usize = 11;
/// BFD Discriminator Optional TLV type "Source IP Address" (RFC 9026,
/// Section 3.1.6 — <https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6>).
const BFD_TLV_SOURCE_IP_ADDRESS: u16 = 1;

/// Parses the BFD Discriminator attribute value (type code 38).
///
/// RFC 9026, Section 3.1.6 — <https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6>
///
/// BFD Mode, BFD Discriminator and Optional TLVs. Returns `false` (nothing
/// left pushed) when the value is shorter than 11 octets or the Optional TLVs
/// are "not well formed" — including a Source IP Address TLV whose Length is
/// not 4 or 16, which "is considered malformed".
fn parse_bfd_discriminator<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    if data.len() < BFD_DISCRIMINATOR_MIN_SIZE {
        return false;
    }
    let mark = buf.fields().len();
    let obj_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    buf.push_field(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_BFD_MODE],
        FieldValue::U8(data[0]),
        offset..offset + 1,
    );
    buf.push_field(
        &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_BFD_DISCRIMINATOR],
        FieldValue::U32(read_be_u32(data, 1).unwrap_or_default()),
        offset + 1..offset + BFD_DISCRIMINATOR_FIXED_SIZE,
    );
    let tlvs = &data[BFD_DISCRIMINATOR_FIXED_SIZE..];
    let tlvs_offset = offset + BFD_DISCRIMINATOR_FIXED_SIZE;
    if !tlvs.is_empty() {
        let array_idx = buf.begin_container(
            &PATH_ATTR_VALUE_BASE_FIELDS[FD_PAV_OPTIONAL_TLVS],
            FieldValue::Array(0..0),
            tlvs_offset..tlvs_offset + tlvs.len(),
        );
        let mut pos = 0;
        while pos < tlvs.len() {
            let Some(tlv) = begin_tlv_object(
                buf,
                &BFD_TLV_OBJECT_DESCRIPTOR,
                BFD_TLV_CHILDREN,
                tlvs,
                pos,
                tlvs_offset,
                BFD_TLV_SHAPE,
            ) else {
                buf.truncate_fields(mark);
                return false;
            };
            let len = tlv.value.len();
            // Source IP Address TLV: "The Length field is 4 for the IPv4
            // address family and 16 for the IPv6 address family.  The TLV is
            // considered malformed if the field is set to any other value."
            if tlv.tlv_type == BFD_TLV_SOURCE_IP_ADDRESS {
                if len != 4 && len != 16 {
                    buf.truncate_fields(mark);
                    return false;
                }
                buf.push_field(
                    &BFD_TLV_CHILDREN[FD_BFDT_SOURCE_ADDRESS],
                    format_address(tlv.value, len == 16),
                    tlv.value_offset..tlv.value_offset + len,
                );
            } else {
                push_bytes_nonempty(
                    buf,
                    &BFD_TLV_CHILDREN[FD_BFDT_VALUE],
                    tlv.value,
                    tlv.value_offset,
                );
            }
            buf.end_container(tlv.idx);
            pos = tlv.next;
        }
        buf.end_container(array_idx);
    }
    buf.end_container(obj_idx);
    true
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
/// Returns the number of octets decoded; decoding stops at the first entry
/// that overruns the block.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn parse_mup_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ipv6: bool,
) -> usize {
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
    pos
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

/// Returns the `[prefix_len_bits, prefix_octets...]` bytes of an NLRI prefix
/// value: borrowed from the packet for plain prefixes, or from the scratch
/// buffer for labeled / VPN prefixes (see [`parse_labeled_nlri`]).
fn nlri_prefix_bytes<'a>(value: &'a FieldValue<'_>, ctx: &FormatContext<'a>) -> Option<&'a [u8]> {
    match value {
        FieldValue::Bytes(b) => Some(b),
        FieldValue::Scratch(r) => ctx.scratch.get(r.start as usize..r.end as usize),
        _ => None,
    }
}

/// Writes a BGP IPv4 NLRI prefix as a JSON-quoted CIDR string (e.g., `"192.168.1.0/24"`).
///
/// The raw bytes are `[prefix_len_bits, prefix_octets...]` per RFC 4271, Section 4.3,
/// held in the packet or, for labeled / VPN prefixes, in the scratch buffer.
/// Missing octets are zero-filled to produce a full dotted-quad address.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
fn format_nlri_ipv4_prefix(
    value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let Some(bytes) = nlri_prefix_bytes(value, ctx) else {
        return w.write_all(b"\"\"");
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
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let Some(bytes) = nlri_prefix_bytes(value, ctx) else {
        return w.write_all(b"\"\"");
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

/// Size of an Extended Community (RFC 4360, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc4360#section-2>).
const EXT_COMMUNITY_SIZE: usize = 8;
/// Size of an IPv6 Address Specific Extended Community (RFC 5701, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc5701#section-2>).
const IPV6_EXT_COMMUNITY_SIZE: usize = 20;

/// Layout of the 6-octet Value of an Extended Community.
enum ExtCommunityValue {
    /// The Global / Local Administrator layout of the Type (see
    /// [`ext_community_type_layout`]).
    Generic,
    /// 2-octet Global Administrator (AS) and 4-octet Local Administrator
    /// (RFC 4360, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4360#section-3.1>).
    TwoOctetAs,
    /// IPv4 address Global Administrator and 2-octet Local Administrator
    /// (RFC 4360, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4360#section-3.2>).
    Ipv4Address,
    /// 4-octet Global Administrator (AS) and 2-octet Local Administrator
    /// (RFC 5668, Section 2 — <https://www.rfc-editor.org/rfc/rfc5668#section-2>).
    FourOctetAs,
    /// 2-octet Global Administrator and a 4-octet IEEE 754 bandwidth in bytes
    /// per second (RFC 10005, Section 2 —
    /// <https://www.rfc-editor.org/rfc/rfc10005#section-2>).
    LinkBandwidth,
    /// 2-octet id and a 4-octet IEEE 754 rate (RFC 8955, Sections 7.1-7.2 —
    /// <https://www.rfc-editor.org/rfc/rfc8955#section-7.1>).
    TrafficRate,
    /// Flags (2) and Color Value (4) (RFC 9012, Section 4.3 —
    /// <https://www.rfc-editor.org/rfc/rfc9012#section-4.3>).
    Color,
    /// Reserved (4) and Tunnel Type (2) (RFC 9012, Section 4.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9012#section-4.1>).
    Encapsulation,
    /// Area Number (4), Route Type (1), Options (1) (RFC 4577,
    /// Section 4.2.6 — <https://www.rfc-editor.org/rfc/rfc4577#section-4.2.6>).
    OspfRouteType,
    /// Flags (1), Reserved (1), Sequence Number (4) (RFC 7432, Section 7.7 —
    /// <https://www.rfc-editor.org/rfc/rfc7432#section-7.7>).
    MacMobility,
    /// Flags (1), Reserved (2), ESI Label (3) (RFC 7432, Section 7.5 —
    /// <https://www.rfc-editor.org/rfc/rfc7432#section-7.5>).
    EsiLabel,
    /// A 6-octet MAC address (RFC 7432, Section 7.6 —
    /// <https://www.rfc-editor.org/rfc/rfc7432#section-7.6>; RFC 9135,
    /// Section 8.1 — <https://www.rfc-editor.org/rfc/rfc9135#section-8.1>).
    Mac,
    /// Traffic Action Field with the S and T bits (RFC 8955, Section 7.3 —
    /// <https://www.rfc-editor.org/rfc/rfc8955#section-7.3>).
    TrafficAction,
    /// DSCP in the 6 least significant bits (RFC 8955, Section 7.5 —
    /// <https://www.rfc-editor.org/rfc/rfc8955#section-7.5>).
    TrafficMarking,
    /// Validation State in the last octet (RFC 8097, Section 2 —
    /// <https://www.rfc-editor.org/rfc/rfc8097#section-2>).
    OriginValidation,
    /// Not decoded: the 6 octets as `value`.
    Raw,
}

/// Parses an EXTENDED COMMUNITIES value (type code 16) into an Array of
/// Extended Community objects.
///
/// RFC 4360, Section 2 — <https://www.rfc-editor.org/rfc/rfc4360#section-2>
///
/// Callers check that `data` is a multiple of 8 octets.
fn parse_ext_communities<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let array_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    for (i, c) in data.chunks_exact(EXT_COMMUNITY_SIZE).enumerate() {
        parse_ext_community(buf, c, offset + i * EXT_COMMUNITY_SIZE);
    }
    buf.end_container(array_idx);
}

/// Parses one 8-octet Extended Community: Type (1), Sub-Type (1) and a
/// 6-octet Value laid out per [`ext_community_sub_type`].
///
/// RFC 4360, Section 2 — <https://www.rfc-editor.org/rfc/rfc4360#section-2>
fn parse_ext_community<'pkt>(buf: &mut DissectBuffer<'pkt>, c: &'pkt [u8], offset: usize) {
    use ExtCommunityValue as V;
    let f = EXT_COMMUNITY_CHILDREN;
    let o = offset;
    let obj_idx = buf.begin_container(
        &EXT_COMMUNITY_OBJECT_DESCRIPTOR,
        FieldValue::Object(0..0),
        o..o + EXT_COMMUNITY_SIZE,
    );
    let (type_high, sub_type) = (c[0], c[1]);
    buf.push_field(&f[FD_EC_TYPE], FieldValue::U8(type_high), o..o + 1);
    buf.push_field(&f[FD_EC_SUB_TYPE], FieldValue::U8(sub_type), o + 1..o + 2);
    let u16_at = |i: usize| read_be_u16(c, i).unwrap_or_default();
    let u32_at = |i: usize| read_be_u32(c, i).unwrap_or_default();
    // Value octet `i` (2..8) as the field `fd` of `len` octets.
    let mut push = |fd: usize, value: FieldValue<'pkt>, i: usize, len: usize| {
        buf.push_field(&f[fd], value, o + i..o + i + len);
    };
    match ext_community_sub_type(type_high, sub_type).1 {
        V::TwoOctetAs => {
            push(
                FD_EC_GLOBAL_ADMIN,
                FieldValue::U32(u32::from(u16_at(2))),
                2,
                2,
            );
            push(FD_EC_LOCAL_ADMIN, FieldValue::U32(u32_at(4)), 4, 4);
        }
        V::Ipv4Address => {
            let addr = read_ipv4_addr(c, 2).unwrap_or_default();
            push(FD_EC_GLOBAL_ADMIN, FieldValue::Ipv4Addr(addr), 2, 4);
            push(
                FD_EC_LOCAL_ADMIN,
                FieldValue::U32(u32::from(u16_at(6))),
                6,
                2,
            );
        }
        V::FourOctetAs => {
            push(FD_EC_GLOBAL_ADMIN, FieldValue::U32(u32_at(2)), 2, 4);
            push(
                FD_EC_LOCAL_ADMIN,
                FieldValue::U32(u32::from(u16_at(6))),
                6,
                2,
            );
        }
        V::LinkBandwidth => {
            push(
                FD_EC_GLOBAL_ADMIN,
                FieldValue::U32(u32::from(u16_at(2))),
                2,
                2,
            );
            push(FD_EC_BANDWIDTH, FieldValue::Bytes(&c[4..]), 4, 4);
        }
        V::TrafficRate => {
            push(
                FD_EC_GLOBAL_ADMIN,
                FieldValue::U32(u32::from(u16_at(2))),
                2,
                2,
            );
            push(FD_EC_RATE, FieldValue::Bytes(&c[4..]), 4, 4);
        }
        V::Color => {
            push(FD_EC_COLOR_FLAGS, FieldValue::U16(u16_at(2)), 2, 2);
            push(FD_EC_COLOR, FieldValue::U32(u32_at(4)), 4, 4);
        }
        V::Encapsulation => push(FD_EC_ENCAP_TUNNEL_TYPE, FieldValue::U16(u16_at(6)), 6, 2),
        V::OspfRouteType => {
            push(FD_EC_OSPF_AREA, FieldValue::U32(u32_at(2)), 2, 4);
            push(FD_EC_OSPF_ROUTE_TYPE, FieldValue::U8(c[6]), 6, 1);
            push(FD_EC_OSPF_OPTIONS, FieldValue::U8(c[7]), 7, 1);
        }
        V::MacMobility => {
            push(FD_EC_EVPN_FLAGS, FieldValue::U8(c[2]), 2, 1);
            push(FD_EC_SEQUENCE_NUMBER, FieldValue::U32(u32_at(4)), 4, 4);
        }
        V::EsiLabel => {
            push(FD_EC_EVPN_FLAGS, FieldValue::U8(c[2]), 2, 1);
            // An MPLS label, encoded like the other EVPN label fields: "The
            // MPLS Label1 field is encoded as 3 octets, where the high-order
            // 20 bits contain the label value" (RFC 7432, Section 9.2.1 —
            // https://www.rfc-editor.org/rfc/rfc7432#section-9.2.1).
            let label = read_be_u24(c, 5).unwrap_or_default() >> 4;
            push(FD_EC_ESI_LABEL, FieldValue::U32(label), 5, 3);
        }
        V::Mac => {
            let mac = MacAddr([c[2], c[3], c[4], c[5], c[6], c[7]]);
            push(FD_EC_MAC, FieldValue::MacAddr(mac), 2, 6);
        }
        V::TrafficAction => {
            // Sample is bit 46 and Terminal Action bit 47 of the community;
            // the other Traffic Action Field bits stay visible in `value`
            // (RFC 8955, Section 7.3 —
            // https://www.rfc-editor.org/rfc/rfc8955#section-7.3).
            push(FD_EC_VALUE, FieldValue::Bytes(&c[2..]), 2, 6);
            push(FD_EC_SAMPLE, FieldValue::U8((c[7] >> 1) & 1), 7, 1);
            push(FD_EC_TERMINAL_ACTION, FieldValue::U8(c[7] & 1), 7, 1);
        }
        V::TrafficMarking => push(FD_EC_DSCP, FieldValue::U8(c[7] & 0x3f), 7, 1),
        V::OriginValidation => push(FD_EC_VALIDATION_STATE, FieldValue::U8(c[7]), 7, 1),
        V::Generic | V::Raw => push(FD_EC_VALUE, FieldValue::Bytes(&c[2..]), 2, 6),
    }
    buf.end_container(obj_idx);
}

/// Parses an IPv6 Address Specific Extended Community value (type code 25)
/// into an Array of objects: Type (1), Sub-Type (1), Global Administrator
/// (IPv6 address, 16) and Local Administrator (2).
///
/// RFC 5701, Section 2 — <https://www.rfc-editor.org/rfc/rfc5701#section-2>
///
/// Callers check that `data` is a multiple of 20 octets.
fn parse_ipv6_ext_communities<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) {
    // The IPv6 object reuses the FD_EC_TYPE .. FD_EC_LOCAL_ADMIN indices.
    let f = IPV6_EXT_COMMUNITY_CHILDREN;
    let array_idx = buf.begin_container(
        &PATH_ATTR_CHILDREN[FD_PA_VALUE],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    for (i, c) in data.chunks_exact(IPV6_EXT_COMMUNITY_SIZE).enumerate() {
        let o = offset + i * IPV6_EXT_COMMUNITY_SIZE;
        let obj_idx = buf.begin_container(
            &IPV6_EXT_COMMUNITY_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            o..o + IPV6_EXT_COMMUNITY_SIZE,
        );
        buf.push_field(&f[FD_EC_TYPE], FieldValue::U8(c[0]), o..o + 1);
        buf.push_field(&f[FD_EC_SUB_TYPE], FieldValue::U8(c[1]), o + 1..o + 2);
        buf.push_field(
            &f[FD_EC_GLOBAL_ADMIN],
            FieldValue::Ipv6Addr(read_ipv6_addr(c, 2).unwrap_or_default()),
            o + 2..o + 18,
        );
        buf.push_field(
            &f[FD_EC_LOCAL_ADMIN],
            FieldValue::U32(u32::from(read_be_u16(c, 18).unwrap_or_default())),
            o + 18..o + 20,
        );
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
}

/// Writes a 4-octet IEEE 754 single-precision value (big-endian bytes) as a
/// JSON number, or as a string when it is not finite.
///
/// Used for the Link Bandwidth (RFC 10005, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc10005#section-2>) and traffic-rate
/// (RFC 8955, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc8955#section-7.1>)
/// Extended Communities.
fn format_ieee754_f32(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match value {
        &FieldValue::Bytes(&[a, b, c, d]) => {
            let v = f32::from_be_bytes([a, b, c, d]);
            if v.is_finite() {
                write!(w, "{v}")
            } else {
                write!(w, "\"{v}\"")
            }
        }
        _ => w.write_all(b"null"),
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

/// The (AFI, SAFI) decoded from a single MP_REACH_NLRI / MP_UNREACH_NLRI path
/// attribute value, with the absolute offset of the 2-octet AFI field (the
/// 1-octet SAFI immediately follows it).
///
/// Used by [`parse_update`] to mirror the *first* MP_REACH_NLRI / MP_UNREACH_NLRI
/// attribute's address family as top-level `afi`/`safi` layer fields, so a
/// consumer can filter on the address family of an UPDATE without reaching
/// into `path_attributes`.
///
/// RFC 4760, Section 3 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
/// RFC 4760, Section 4 — <https://www.rfc-editor.org/rfc/rfc4760#section-4>
#[derive(Clone, Copy)]
struct MpAfiSafi {
    afi: u16,
    safi: u8,
    /// Absolute offset of the 2-octet AFI field within the packet.
    offset: usize,
}

/// How the NLRI of an MP_REACH_NLRI / MP_UNREACH_NLRI attribute is encoded,
/// selected by its (AFI, SAFI).
///
/// RFC 4760, Section 5 — <https://www.rfc-editor.org/rfc/rfc4760#section-5>
#[derive(Clone, Copy)]
enum MpNlriEncoding {
    /// `<length, prefix>` tuples for IPv4/IPv6 unicast and multicast
    /// (RFC 4760, Section 5 — <https://www.rfc-editor.org/rfc/rfc4760#section-5>).
    Prefixes { ipv6: bool },
    /// BGP-MUP NLRI (draft-ietf-bess-mup-safi-01, Section 3).
    Mup { ipv6: bool },
    /// Labeled NLRI: label(s) or a Compatibility field, an 8-octet Route
    /// Distinguisher when `vpn`, then the prefix.
    ///
    /// RFC 8277, Sections 2.2-2.4 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>
    /// RFC 4364, Section 4.3.4 — <https://www.rfc-editor.org/rfc/rfc4364#section-4.3.4>
    /// RFC 4659, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4659#section-3.2>
    Labeled { ipv6: bool, vpn: bool },
    /// EVPN NLRI (RFC 7432, Section 7 —
    /// <https://www.rfc-editor.org/rfc/rfc7432#section-7>).
    Evpn,
    /// Flow Specification NLRI, with an RD when `vpn` (RFC 8955, Sections 4
    /// and 8 — <https://www.rfc-editor.org/rfc/rfc8955#section-4>; RFC 8956 —
    /// <https://www.rfc-editor.org/rfc/rfc8956>).
    FlowSpec { ipv6: bool, vpn: bool },
    /// Link-State NLRI, with an RD when `vpn` (RFC 9552, Section 5.2 —
    /// <https://www.rfc-editor.org/rfc/rfc9552#section-5.2>).
    BgpLs { vpn: bool },
    /// Route Target membership NLRI (RFC 4684, Section 4 —
    /// <https://www.rfc-editor.org/rfc/rfc4684#section-4>).
    RtConstraint,
    /// SR Policy NLRI (RFC 9830, Section 2.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>).
    SrPolicy { ipv6: bool },
    /// MCAST-VPN NLRI (RFC 6514, Section 4 —
    /// <https://www.rfc-editor.org/rfc/rfc6514#section-4>).
    McastVpn,
    /// SAFI 129 NLRI: an RD and a prefix, without a label (RFC 6514,
    /// Section 10 — <https://www.rfc-editor.org/rfc/rfc6514#section-10>).
    MulticastVpnPrefixes { ipv6: bool },
    /// VPLS and BGP-AD NLRI (RFC 4761, Section 3.2.2 —
    /// <https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2>; RFC 6074,
    /// Section 3.2.2.1 — <https://www.rfc-editor.org/rfc/rfc6074#section-3.2.2.1>).
    Vpls,
}

/// Shape of a labeled NLRI block.
///
/// RFC 8277, Sections 2.2-2.4 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>
struct LabeledNlri {
    /// Maximum prefix length in bits, excluding the labels and the RD: "In an
    /// MP_REACH_NLRI attribute whose AFI/SAFI is 1/4, the prefix length will be
    /// 32 bits or less.  In an MP_REACH_NLRI attribute whose AFI/SAFI is 2/4,
    /// the prefix length will be 128 bits or less.  In an MP_REACH_NLRI
    /// attribute whose SAFI is 128, the prefix will be 96 bits or less if the
    /// AFI is 1 and will be 192 bits or less if the AFI is 2." (RFC 8277,
    /// Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>; the
    /// SAFI 128 limits include the 64-bit RD).
    max_prefix_bits: usize,
    /// Octets of Route Distinguisher preceding the prefix (8 for VPN NLRI).
    rd_len: usize,
    /// MP_UNREACH_NLRI withdrawal: a single 3-octet Compatibility field
    /// replaces the label(s) (RFC 8277, Section 2.4 —
    /// <https://www.rfc-editor.org/rfc/rfc8277#section-2.4>).
    withdraw: bool,
    /// Whether the prefix is IPv6.
    ipv6: bool,
    /// Whether the entries carry labels (or a Compatibility field); SAFI 129
    /// NLRI are an RD and a prefix only (RFC 6514, Section 10 —
    /// <https://www.rfc-editor.org/rfc/rfc6514#section-10>).
    labels: bool,
}

impl LabeledNlri {
    fn new(ipv6: bool, vpn: bool, withdraw: bool) -> Self {
        Self {
            max_prefix_bits: if ipv6 { 128 } else { 32 },
            rd_len: if vpn { RD_SIZE } else { 0 },
            withdraw,
            ipv6,
            labels: true,
        }
    }

    /// Shape of SAFI 129 NLRI: "a Route Distinguisher as defined in
    /// [RFC4364] prepended to an IPv4 or IPv6 address prefix", without a
    /// label (RFC 6514, Section 10 —
    /// <https://www.rfc-editor.org/rfc/rfc6514#section-10>).
    fn unlabeled_vpn(ipv6: bool) -> Self {
        Self {
            labels: false,
            ..Self::new(ipv6, true, false)
        }
    }
}

/// Layout of one labeled NLRI entry, starting at its Length octet.
struct LabeledEntryLayout {
    /// Total octets of the entry including the Length octet.
    len: usize,
    /// Number of 3-octet Label or Compatibility entries.
    label_count: usize,
    /// Prefix length in bits.
    prefix_bits: usize,
}

/// Returns the layout of the labeled NLRI entry at the start of `data`, or
/// `None` if it is malformed.
///
/// The Length octet "specifies the length in bits of the remainder of the
/// NLRI field" (RFC 8277, Section 2.2), i.e. labels + RD + prefix.
///
/// - In a withdrawal the remainder starts with one 3-octet Compatibility field
///   (RFC 8277, Section 2.4).
/// - Otherwise labels are read until one has the S bit set, which is the
///   encoding when the Multiple Labels Capability is used (RFC 8277,
///   Section 2.3). That capability is exchanged in OPEN and is not visible to
///   a stateless dissector, and without it the S bit "MUST be ignored on
///   reception" (RFC 8277, Section 2.2), so an entry that does not parse as an
///   S-terminated label stack is read with a single label.
///
/// A first label with S=0 is therefore read as the start of a label stack
/// whenever the remaining octets allow it: a sender that does not use the
/// Multiple Labels Capability "MUST" set the S bit (RFC 8277, Section 2.2),
/// so S=0 on the first label is only valid with the Section 2.3 encoding.
///
/// RFC 8277, Section 2 — <https://www.rfc-editor.org/rfc/rfc8277#section-2>
fn labeled_entry_layout(data: &[u8], shape: &LabeledNlri) -> Option<LabeledEntryLayout> {
    let length_bits = *data.first()? as usize;
    let len = 1 + length_bits.div_ceil(8);
    if len > data.len() {
        return None;
    }

    let layout = |label_count: usize| {
        let prefix_bits =
            length_bits.checked_sub((label_count * LABEL_ENTRY_SIZE + shape.rd_len) * 8)?;
        (prefix_bits <= shape.max_prefix_bits).then_some(LabeledEntryLayout {
            len,
            label_count,
            prefix_bits,
        })
    };

    if !shape.labels {
        return layout(0);
    }
    if !shape.withdraw {
        // Label stack terminated by the S bit (RFC 8277, Section 2.3 —
        // https://www.rfc-editor.org/rfc/rfc8277#section-2.3).
        let mut label_count = 0;
        while (label_count + 1) * LABEL_ENTRY_SIZE * 8 <= length_bits {
            let s_bit = data[label_count * LABEL_ENTRY_SIZE + LABEL_ENTRY_SIZE] & 0x01;
            label_count += 1;
            if s_bit == 1 {
                if let Some(layout) = layout(label_count) {
                    return Some(layout);
                }
                break;
            }
        }
    }
    // Single label (RFC 8277, Section 2.2 —
    // https://www.rfc-editor.org/rfc/rfc8277#section-2.2) or Compatibility
    // field (RFC 8277, Section 2.4 —
    // https://www.rfc-editor.org/rfc/rfc8277#section-2.4).
    layout(1)
}

/// Returns `true` when `data` parses exactly as labeled NLRI entries, each
/// preceded by `path_id_len` octets of ADD-PATH Path Identifier.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
/// RFC 8277, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>
fn labeled_block_parses(data: &[u8], shape: &LabeledNlri, path_id_len: usize) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let Some(layout) = data
            .get(pos + path_id_len..)
            .and_then(|entry| labeled_entry_layout(entry, shape))
        else {
            return false;
        };
        pos += path_id_len + layout.len;
    }
    true
}

/// Returns the ADD-PATH Path Identifier length (0 or 4) of a labeled NLRI
/// block, or `None` if it parses neither way.
///
/// "If the procedures of [RFC7911] are being used, a four-octet "path
/// identifier" (as defined in Section 3 of [RFC7911]) is part of the NLRI and
/// precedes the Length field." (RFC 8277, Section 2.2). As for plain prefixes
/// (see [`detect_add_path_prefixes`]), the plain encoding wins when both
/// readings are valid.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn labeled_path_id_len(data: &[u8], shape: &LabeledNlri) -> Option<usize> {
    [0, PATH_ID_SIZE]
        .into_iter()
        .find(|&path_id_len| labeled_block_parses(data, shape, path_id_len))
}

/// Parses a labeled NLRI block (RFC 8277) into one Object per entry:
/// `{ path_id?, label_stack | compatibility, rd?, prefix }`.
///
/// A block that does not parse exactly with [`labeled_path_id_len`] is not
/// decoded at all rather than partially. The prefix is not contiguous with its
/// Length octet, so its `[prefix_len_bits, prefix_octets...]` value is
/// assembled in the scratch buffer and rendered by the same CIDR formatters as
/// plain prefixes.
///
/// Returns the number of octets decoded: `data.len()`, or 0 when the block is
/// malformed.
///
/// RFC 8277, Sections 2.2-2.4 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>
/// RFC 4364, Section 4.3.4 — <https://www.rfc-editor.org/rfc/rfc4364#section-4.3.4>
/// RFC 4659, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc4659#section-3.2>
fn parse_labeled_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    shape: &LabeledNlri,
) -> usize {
    let Some(path_id_len) = labeled_path_id_len(data, shape) else {
        return 0;
    };
    let prefix_descriptor = if shape.ipv6 {
        &PREFIX_ENTRY_IPV6_DESCRIPTOR
    } else {
        &PREFIX_ENTRY_IPV4_DESCRIPTOR
    };
    let mut pos = 0;
    while pos < data.len() {
        let entry_start = pos + path_id_len;
        let Some(layout) = data
            .get(entry_start..)
            .and_then(|entry| labeled_entry_layout(entry, shape))
        else {
            break;
        };
        let entry_end = entry_start + layout.len;
        let abs = base_offset + pos;
        let obj_idx = buf.begin_container(
            &NLRI_ENTRY_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + entry_end,
        );

        if path_id_len != 0 {
            buf.push_field(
                &NLRI_ENTRY_CHILDREN[FD_NLRI_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }

        let labels_start = entry_start + 1;
        let labels_end = labels_start + layout.label_count * LABEL_ENTRY_SIZE;
        if shape.labels && shape.withdraw {
            // RFC 8277, Section 2.4 — https://www.rfc-editor.org/rfc/rfc8277#section-2.4:
            // "Upon reception, the value of the Compatibility field MUST be
            // ignored." It is shown as is.
            buf.push_field(
                &NLRI_ENTRY_CHILDREN[FD_NLRI_COMPATIBILITY],
                FieldValue::U32(read_be_u24(data, labels_start).unwrap_or_default()),
                base_offset + labels_start..base_offset + labels_end,
            );
        } else if shape.labels {
            let stack_idx = buf.begin_container(
                &NLRI_ENTRY_CHILDREN[FD_NLRI_LABEL_STACK],
                FieldValue::Array(0..0),
                base_offset + labels_start..base_offset + labels_end,
            );
            for label_pos in (labels_start..labels_end).step_by(LABEL_ENTRY_SIZE) {
                let raw = read_be_u24(data, label_pos).unwrap_or_default();
                let label_abs = base_offset + label_pos;
                let label_idx = buf.begin_container(
                    &LABEL_ENTRY_OBJECT_DESCRIPTOR,
                    FieldValue::Object(0..0),
                    label_abs..label_abs + LABEL_ENTRY_SIZE,
                );
                // 20-bit Label, 3-bit Rsrv, 1-bit S (RFC 8277, Section 2.2 —
                // https://www.rfc-editor.org/rfc/rfc8277#section-2.2).
                buf.push_field(
                    &LABEL_ENTRY_CHILDREN[FD_LABEL_LABEL],
                    FieldValue::U32(raw >> 4),
                    label_abs..label_abs + LABEL_ENTRY_SIZE,
                );
                buf.push_field(
                    &LABEL_ENTRY_CHILDREN[FD_LABEL_RSRV],
                    FieldValue::U8(((raw >> 1) & 0x07) as u8),
                    label_abs + 2..label_abs + 3,
                );
                buf.push_field(
                    &LABEL_ENTRY_CHILDREN[FD_LABEL_S],
                    FieldValue::U8((raw & 0x01) as u8),
                    label_abs + 2..label_abs + 3,
                );
                buf.end_container(label_idx);
            }
            buf.end_container(stack_idx);
        }

        let prefix_start = labels_end + shape.rd_len;
        if shape.rd_len != 0 {
            buf.push_field(
                &MUP_NLRI_CHILDREN[FD_MUP_RD],
                FieldValue::Bytes(&data[labels_end..prefix_start]),
                base_offset + labels_end..base_offset + prefix_start,
            );
        }

        let scratch = buf.push_scratch(&[layout.prefix_bits as u8]);
        buf.extend_scratch(&data[prefix_start..entry_end]);
        buf.push_field(
            prefix_descriptor,
            FieldValue::Scratch(scratch.start..buf.scratch_len()),
            base_offset + prefix_start..base_offset + entry_end,
        );

        buf.end_container(obj_idx);
        pos = entry_end;
    }
    pos
}

/// Returns a human-readable name for EVPN Route Types.
///
/// IANA EVPN Route Types —
/// <https://www.iana.org/assignments/evpn/evpn.xhtml#route-types>
fn evpn_route_type_name(v: u8) -> Option<&'static str> {
    match v {
        // RFC 7432, Section 7 — https://www.rfc-editor.org/rfc/rfc7432#section-7
        EVPN_ROUTE_ETHERNET_AD => Some("Ethernet Auto-discovery"),
        EVPN_ROUTE_MAC_IP => Some("MAC/IP Advertisement"),
        EVPN_ROUTE_IMET => Some("Inclusive Multicast Ethernet Tag"),
        EVPN_ROUTE_ETHERNET_SEGMENT => Some("Ethernet Segment"),
        // RFC 9136, Section 3 — https://www.rfc-editor.org/rfc/rfc9136#section-3
        EVPN_ROUTE_IP_PREFIX => Some("IP Prefix"),
        // RFC 9251, Section 9 — https://www.rfc-editor.org/rfc/rfc9251#section-9
        6 => Some("Selective Multicast Ethernet Tag Route"),
        7 => Some("Multicast Membership Report Synch Route"),
        8 => Some("Multicast Leave Synch Route"),
        // RFC 9572, Section 3 — https://www.rfc-editor.org/rfc/rfc9572#section-3
        9 => Some("Per-Region I-PMSI A-D route"),
        10 => Some("S-PMSI A-D route"),
        11 => Some("Leaf A-D route"),
        _ => None,
    }
}

/// EVPN Route Types decoded by [`parse_evpn_route_body`] (RFC 7432,
/// Section 7 — <https://www.rfc-editor.org/rfc/rfc7432#section-7>; RFC 9136,
/// Section 3 — <https://www.rfc-editor.org/rfc/rfc9136#section-3>).
const EVPN_ROUTE_ETHERNET_AD: u8 = 1;
const EVPN_ROUTE_MAC_IP: u8 = 2;
const EVPN_ROUTE_IMET: u8 = 3;
const EVPN_ROUTE_ETHERNET_SEGMENT: u8 = 4;
const EVPN_ROUTE_IP_PREFIX: u8 = 5;
/// Highest EVPN Route Type assigned by IANA (RFC 9572, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc9572#section-3>).
const EVPN_ROUTE_TYPE_MAX: u8 = 11;
/// EVPN NLRI Route Type (1) + Length (1) (RFC 7432, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc7432#section-7>).
const EVPN_NLRI_HEADER_SIZE: usize = 2;
/// Ethernet Segment Identifier size (RFC 7432, Section 5 —
/// <https://www.rfc-editor.org/rfc/rfc7432#section-5>).
const ESI_SIZE: usize = 10;

/// Returns `true` when an EVPN route of `route_type` may have a
/// Route Type specific field of `len` octets.
///
/// Route Types 1-5 have the fixed lengths of their figures (RFC 7432,
/// Sections 7.1-7.4 — <https://www.rfc-editor.org/rfc/rfc7432#section-7.1>;
/// RFC 9136, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9136#section-3.1>),
/// the other assigned types any length.
fn evpn_route_length_plausible(route_type: u8, len: usize) -> bool {
    match route_type {
        EVPN_ROUTE_ETHERNET_AD => len == 25,
        // IP Address of 0, 4 or 16 octets, with or without MPLS Label2.
        EVPN_ROUTE_MAC_IP => matches!(len, 33 | 36 | 37 | 40 | 49 | 52),
        EVPN_ROUTE_IMET => matches!(len, 17 | 29),
        EVPN_ROUTE_ETHERNET_SEGMENT => matches!(len, 23 | 35),
        EVPN_ROUTE_IP_PREFIX => matches!(len, 34 | 58),
        6..=EVPN_ROUTE_TYPE_MAX => true,
        _ => false,
    }
}

/// Returns `true` when `data` parses exactly as a sequence of EVPN NLRI
/// entries, each preceded by `path_id_len` octets of Path Identifier, whose
/// Route Type and Length pass `entry_ok`.
fn evpn_block_parses(data: &[u8], path_id_len: usize, entry_ok: fn(u8, usize) -> bool) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let entry = pos + path_id_len;
        let (Some(&route_type), Some(&len)) = (data.get(entry), data.get(entry + 1)) else {
            return false;
        };
        if !entry_ok(route_type, usize::from(len)) {
            return false;
        }
        pos = entry + EVPN_NLRI_HEADER_SIZE + usize::from(len);
        if pos > data.len() {
            return false;
        }
    }
    true
}

/// Returns `true` when an EVPN block carries RFC 7911 ADD-PATH Path
/// Identifiers.
///
/// The plain encoding wins whenever it frames the block exactly without a
/// Reserved Route Type 0 — a Path Identifier usually starts with a zero
/// octet, which would read as Route Type 0. Otherwise the block is ADD-PATH
/// only if every Path Identifier is followed by an assigned Route Type with a
/// plausible Length (see [`evpn_route_length_plausible`]).
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_evpn(data: &[u8]) -> bool {
    !evpn_block_parses(data, 0, |route_type, _| route_type != 0)
        && evpn_block_parses(data, PATH_ID_SIZE, evpn_route_length_plausible)
}

/// Parses an EVPN NLRI block (AFI 25 / SAFI 70) into one object per route,
/// and returns the number of octets consumed.
///
/// RFC 7432, Section 7 — <https://www.rfc-editor.org/rfc/rfc7432#section-7>
///
/// Each entry is Route Type (1), Length (1) and the Route Type specific
/// field (see [`parse_evpn_route_body`]). With RFC 7911 ADD-PATH each entry
/// is preceded by a Path Identifier (see [`detect_add_path_evpn`]).
fn parse_evpn_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    vni_label: bool,
) -> usize {
    let id_len = if detect_add_path_evpn(data) {
        PATH_ID_SIZE
    } else {
        0
    };
    let f = &EVPN_NLRI_FIELDS;
    let mut pos = 0;
    while pos + id_len + EVPN_NLRI_HEADER_SIZE <= data.len() {
        let entry = pos + id_len;
        let route_type = data[entry];
        let len = usize::from(data[entry + 1]);
        let end = entry + EVPN_NLRI_HEADER_SIZE + len;
        if end > data.len() {
            break;
        }
        let abs = base_offset + pos;
        let entry_abs = base_offset + entry;
        let obj_idx = buf.begin_container(
            &EVPN_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_EVPN_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_EVPN_ROUTE_TYPE],
            FieldValue::U16(u16::from(route_type)),
            entry_abs..entry_abs + 1,
        );
        buf.push_field(
            &f[FD_EVPN_LENGTH],
            FieldValue::U8(data[entry + 1]),
            entry_abs + 1..entry_abs + 2,
        );
        let body = &data[entry + EVPN_NLRI_HEADER_SIZE..end];
        let body_abs = entry_abs + EVPN_NLRI_HEADER_SIZE;
        let mark = buf.fields().len();
        if !parse_evpn_route_body(buf, route_type, body, body_abs, vni_label) {
            buf.truncate_fields(mark);
            if !body.is_empty() {
                buf.push_field(
                    &f[FD_EVPN_VALUE],
                    FieldValue::Bytes(body),
                    body_abs..body_abs + body.len(),
                );
            }
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    pos
}

/// Reads the fields of an EVPN Route Type specific field in order, pushing
/// each one; every read fails (returns `None`) past the end of the field.
struct EvpnReader<'a, 'pkt> {
    buf: &'a mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    pos: usize,
}

impl<'pkt> EvpnReader<'_, 'pkt> {
    /// Takes the next `n` octets and their absolute range.
    fn take(&mut self, n: usize) -> Option<(&'pkt [u8], core::ops::Range<usize>)> {
        let bytes = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        let range = self.offset + self.pos..self.offset + self.pos + n;
        self.pos += n;
        Some((bytes, range))
    }

    /// Pushes the next `n` octets with the value built by `value`.
    fn push(
        &mut self,
        fd: usize,
        n: usize,
        value: impl FnOnce(&'pkt [u8]) -> FieldValue<'pkt>,
    ) -> Option<()> {
        let (bytes, range) = self.take(n)?;
        self.buf
            .push_field(&EVPN_NLRI_FIELDS[fd], value(bytes), range);
        Some(())
    }

    /// Route Distinguisher (8 octets, RFC 4364, Section 4.2 —
    /// <https://www.rfc-editor.org/rfc/rfc4364#section-4.2>).
    fn rd(&mut self) -> Option<()> {
        self.push(FD_EVPN_RD, RD_SIZE, FieldValue::Bytes)
    }

    /// Ethernet Segment Identifier (10 octets).
    fn esi(&mut self) -> Option<()> {
        self.push(FD_EVPN_ESI, ESI_SIZE, FieldValue::Bytes)
    }

    /// Ethernet Tag ID (4 octets).
    fn ethernet_tag_id(&mut self) -> Option<()> {
        self.push(FD_EVPN_ETHERNET_TAG_ID, 4, |b| {
            FieldValue::U32(read_be_u32(b, 0).unwrap_or_default())
        })
    }

    /// A 3-octet MPLS Label field: "The MPLS Label1 field is encoded as 3
    /// octets, where the high-order 20 bits contain the label value"
    /// (RFC 7432, Section 9.2.1 —
    /// <https://www.rfc-editor.org/rfc/rfc7432#section-9.2.1>), or, with a
    /// VXLAN / NVGRE / VXLAN GPE encapsulation, a VNI where "the entire 24-bit
    /// field is used to encode the VNI value" (RFC 8365, Section 5.1.3 —
    /// <https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3>).
    fn label(&mut self, label_fd: usize, vni_fd: usize, vni: bool) -> Option<()> {
        let fd = if vni { vni_fd } else { label_fd };
        self.push(fd, 3, |b| {
            let raw = read_be_u24(b, 0).unwrap_or_default();
            FieldValue::U32(if vni { raw } else { raw >> 4 })
        })
    }

    /// An IP Address Length in bits (1 octet) followed by an address of that
    /// length (`allow_empty` permits the length 0 of RFC 7432, Section 7.2 —
    /// <https://www.rfc-editor.org/rfc/rfc7432#section-7.2>).
    fn ip(&mut self, fd: usize, allow_empty: bool) -> Option<()> {
        let (len, range) = self.take(1)?;
        let octets = match len[0] {
            0 if allow_empty => 0,
            32 => 4,
            128 => 16,
            _ => return None,
        };
        self.buf.push_field(
            &EVPN_NLRI_FIELDS[FD_EVPN_IP_LENGTH],
            FieldValue::U8(len[0]),
            range,
        );
        if octets != 0 {
            self.push(fd, octets, |b| format_address(b, octets == 16))?;
        }
        Some(())
    }

    /// Whether the whole field has been read.
    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// Parses the Route Type specific field of an EVPN route. Returns `false`
/// when the Route Type is not decoded or the field does not match its layout
/// exactly (the caller then discards what was pushed and keeps the field as
/// `value`).
fn parse_evpn_route_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    route_type: u8,
    data: &'pkt [u8],
    offset: usize,
    vni: bool,
) -> bool {
    let mut r = EvpnReader {
        buf,
        data,
        offset,
        pos: 0,
    };
    let parsed = match route_type {
        EVPN_ROUTE_ETHERNET_AD => r.ethernet_ad(vni),
        EVPN_ROUTE_MAC_IP => r.mac_ip(vni),
        EVPN_ROUTE_IMET => r.imet(),
        EVPN_ROUTE_ETHERNET_SEGMENT => r.ethernet_segment(),
        EVPN_ROUTE_IP_PREFIX => r.ip_prefix(vni),
        _ => None,
    };
    parsed.is_some() && r.done()
}

impl EvpnReader<'_, '_> {
    /// Ethernet Auto-discovery route: RD, ESI, Ethernet Tag ID, MPLS Label
    /// (RFC 7432, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc7432#section-7.1>).
    fn ethernet_ad(&mut self, vni: bool) -> Option<()> {
        self.rd()?;
        self.esi()?;
        self.ethernet_tag_id()?;
        self.label(FD_EVPN_MPLS_LABEL, FD_EVPN_VNI, vni)
    }

    /// MAC/IP Advertisement route: RD, ESI, Ethernet Tag ID, MAC Address
    /// Length, MAC Address, IP Address Length, IP Address (0, 4 or 16
    /// octets), MPLS Label1, MPLS Label2 (0 or 3 octets); "Both the IP and MAC
    /// address lengths are in bits."
    /// (RFC 7432, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc7432#section-7.2>).
    fn mac_ip(&mut self, vni: bool) -> Option<()> {
        self.rd()?;
        self.esi()?;
        self.ethernet_tag_id()?;
        let (mac_len, range) = self.take(1)?;
        if mac_len[0] != 48 {
            return None;
        }
        self.buf.push_field(
            &EVPN_NLRI_FIELDS[FD_EVPN_MAC_LENGTH],
            FieldValue::U8(48),
            range,
        );
        self.push(FD_EVPN_MAC, 6, |b| {
            FieldValue::MacAddr(MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]))
        })?;
        self.ip(FD_EVPN_IP_ADDRESS, true)?;
        self.label(FD_EVPN_MPLS_LABEL1, FD_EVPN_VNI1, vni)?;
        if !self.done() {
            self.label(FD_EVPN_MPLS_LABEL2, FD_EVPN_VNI2, vni)?;
        }
        Some(())
    }

    /// Inclusive Multicast Ethernet Tag route: RD, Ethernet Tag ID, IP
    /// Address Length, Originating Router's IP Address
    /// (RFC 7432, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc7432#section-7.3>).
    fn imet(&mut self) -> Option<()> {
        self.rd()?;
        self.ethernet_tag_id()?;
        self.ip(FD_EVPN_IP_ADDRESS, false)
    }

    /// Ethernet Segment route: RD, ESI, IP Address Length, Originating
    /// Router's IP Address
    /// (RFC 7432, Section 7.4 — <https://www.rfc-editor.org/rfc/rfc7432#section-7.4>).
    fn ethernet_segment(&mut self) -> Option<()> {
        self.rd()?;
        self.esi()?;
        self.ip(FD_EVPN_IP_ADDRESS, false)
    }

    /// IP Prefix route: RD, ESI, Ethernet Tag ID, IP Prefix Length, IP Prefix,
    /// GW IP Address, MPLS Label, with 4-octet (Length 34) or 16-octet
    /// (Length 58) addresses
    /// (RFC 9136, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9136#section-3.1>).
    fn ip_prefix(&mut self, vni: bool) -> Option<()> {
        // "The Length field of the BGP EVPN NLRI for an EVPN IP Prefix route
        // MUST be either 34 (if IPv4 addresses are carried) or 58 (if IPv6
        // addresses are carried)."
        let (octets, max_bits, descriptor) = match self.data.len() {
            34 => (4, 32, &PREFIX_ENTRY_IPV4_DESCRIPTOR),
            58 => (16, 128, &PREFIX_ENTRY_IPV6_DESCRIPTOR),
            _ => return None,
        };
        self.rd()?;
        self.esi()?;
        self.ethernet_tag_id()?;
        let (prefix_len, len_range) = self.take(1)?;
        let bits = prefix_len[0];
        if usize::from(bits) > max_bits {
            return None;
        }
        let (prefix, prefix_range) = self.take(octets)?;
        // `[length, octets...]` in the scratch buffer, as for the other NLRI
        // prefixes.
        let scratch = self.buf.push_scratch(&[bits]);
        self.buf
            .extend_scratch(&prefix[..usize::from(bits).div_ceil(8)]);
        self.buf.push_field(
            descriptor,
            FieldValue::Scratch(scratch.start..self.buf.scratch_len()),
            len_range.start..prefix_range.end,
        );
        self.push(FD_EVPN_GATEWAY_IP, octets, |b| {
            format_address(b, octets == 16)
        })?;
        self.label(FD_EVPN_MPLS_LABEL, FD_EVPN_VNI, vni)
    }
}

/// Writes an Ethernet Segment Identifier as colon-separated hex octets
/// (e.g. `"00:01:02:03:04:05:06:07:08:09"`).
///
/// RFC 7432, Section 5 — <https://www.rfc-editor.org/rfc/rfc7432#section-5>
fn format_esi(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match value {
        FieldValue::Bytes(b) if b.len() == ESI_SIZE => {
            w.write_all(b"\"")?;
            for (i, octet) in b.iter().enumerate() {
                if i != 0 {
                    w.write_all(b":")?;
                }
                write!(w, "{octet:02x}")?;
            }
            w.write_all(b"\"")
        }
        _ => w.write_all(b"\"\""),
    }
}

/// Returns a human-readable name for an IPv4 Flow Specification component
/// type.
///
/// IANA Flow Spec Component Types —
/// <https://www.iana.org/assignments/flow-spec/flow-spec.xhtml#flow-spec-2>
/// RFC 8955, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2>
fn flowspec_ipv4_component_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Destination Prefix"),
        2 => Some("Source Prefix"),
        3 => Some("IP Protocol"),
        7 => Some("ICMP Type"),
        8 => Some("ICMP Code"),
        _ => flowspec_common_component_name(v),
    }
}

/// Returns a human-readable name for an IPv6 Flow Specification component
/// type.
///
/// IANA Flow Spec Component Types —
/// <https://www.iana.org/assignments/flow-spec/flow-spec.xhtml#flow-spec-2>
/// RFC 8956, Section 3 — <https://www.rfc-editor.org/rfc/rfc8956#section-3>
fn flowspec_ipv6_component_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Destination IPv6 Prefix"),
        2 => Some("Source IPv6 Prefix"),
        3 => Some("Upper-Layer Protocol"),
        7 => Some("ICMPv6 Type"),
        8 => Some("ICMPv6 Code"),
        FLOWSPEC_FLOW_LABEL => Some("Flow Label"),
        _ => flowspec_common_component_name(v),
    }
}

/// Component types with the same name for IPv4 and IPv6 (RFC 8955,
/// Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2>).
fn flowspec_common_component_name(v: u8) -> Option<&'static str> {
    match v {
        4 => Some("Port"),
        5 => Some("Destination Port"),
        6 => Some("Source Port"),
        FLOWSPEC_TCP_FLAGS => Some("TCP Flags"),
        10 => Some("Packet Length"),
        11 => Some("DSCP"),
        FLOWSPEC_FRAGMENT => Some("Fragment"),
        _ => None,
    }
}

/// Returns the relational operation of the lt / gt / eq bits of a numeric
/// operator.
///
/// RFC 8955, Section 4.2.1.1, Table 1 —
/// <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1.1>
fn flowspec_comparison_name(v: u8) -> Option<&'static str> {
    match v {
        0b000 => Some("false"),
        0b001 => Some("=="),
        0b010 => Some(">"),
        0b011 => Some(">="),
        0b100 => Some("<"),
        0b101 => Some("<="),
        0b110 => Some("!="),
        0b111 => Some("true"),
        _ => None,
    }
}

/// Flow Specification component types with a special encoding (RFC 8955,
/// Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2>;
/// RFC 8956, Section 3.7 — <https://www.rfc-editor.org/rfc/rfc8956#section-3.7>).
const FLOWSPEC_DESTINATION_PREFIX: u8 = 1;
const FLOWSPEC_SOURCE_PREFIX: u8 = 2;
const FLOWSPEC_TCP_FLAGS: u8 = 9;
const FLOWSPEC_FRAGMENT: u8 = 12;
const FLOWSPEC_FLOW_LABEL: u8 = 13;
/// SAFIs for Flow Specification rules (RFC 8955, Sections 4 and 8 —
/// <https://www.rfc-editor.org/rfc/rfc8955#section-4>).
const SAFI_FLOWSPEC: u8 = 133;
const SAFI_FLOWSPEC_VPN: u8 = 134;
/// First octet of an extended (2-octet) Flow Specification NLRI length:
/// "If the NLRI length is smaller than 240 (0xf0 hex) octets, the length
/// field can be encoded as a single octet" (RFC 8955, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc8955#section-4.1>).
const FLOWSPEC_EXTENDED_LENGTH: u8 = 0xf0;

/// Returns `(value length, length field size)` of the Flow Specification
/// rule at `pos`, or `None` when its length field is truncated.
///
/// RFC 8955, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.1>
fn flowspec_rule_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)?;
    if first >= FLOWSPEC_EXTENDED_LENGTH {
        let low = *data.get(pos + 1)?;
        Some((usize::from(first & 0x0f) << 8 | usize::from(low), 2))
    } else {
        Some((usize::from(first), 1))
    }
}

/// Returns `true` when `data` is exactly a sequence of well-formed Flow
/// Specification rules (see [`flowspec_value_valid`]), each preceded by
/// `path_id_len` octets of Path Identifier.
fn flowspec_block_parses(data: &[u8], path_id_len: usize, ipv6: bool, vpn: bool) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let rule = pos + path_id_len;
        let Some((len, header_len)) = flowspec_rule_length(data, rule) else {
            return false;
        };
        let Some(value) = data.get(rule + header_len..rule + header_len + len) else {
            return false;
        };
        if !flowspec_value_valid(value, ipv6, vpn) {
            return false;
        }
        pos = rule + header_len + len;
    }
    true
}

/// Returns `true` when a Flow Specification block carries RFC 7911 ADD-PATH
/// Path Identifiers: it does not parse as well-formed rules without them, and
/// does with them.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_flowspec(data: &[u8], ipv6: bool, vpn: bool) -> bool {
    !flowspec_block_parses(data, 0, ipv6, vpn)
        && flowspec_block_parses(data, PATH_ID_SIZE, ipv6, vpn)
}

/// Parses a Flow Specification NLRI block (SAFI 133, or 134 with an RD) into
/// one object per rule and returns the number of octets consumed.
///
/// RFC 8955, Sections 4.1-4.2 and 8 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.1>
/// RFC 8956, Section 3 — <https://www.rfc-editor.org/rfc/rfc8956#section-3>
///
/// Each rule is a 1- or 2-octet length (Section 4.1), the RD for SAFI 134
/// (Section 8), and the components; with RFC 7911 ADD-PATH a Path Identifier
/// precedes it (see [`detect_add_path_flowspec`]). A rule whose value is "not
/// encoded as specified" keeps its value as `value`.
fn parse_flowspec_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ipv6: bool,
    vpn: bool,
) -> usize {
    let f = &FLOWSPEC_NLRI_FIELDS;
    let id_len = if detect_add_path_flowspec(data, ipv6, vpn) {
        PATH_ID_SIZE
    } else {
        0
    };
    let mut pos = 0;
    while pos < data.len() {
        let rule = pos + id_len;
        let Some((len, header_len)) = flowspec_rule_length(data, rule) else {
            break;
        };
        let end = rule + header_len + len;
        if end > data.len() {
            break;
        }
        let abs = base_offset + pos;
        let rule_abs = base_offset + rule;
        let obj_idx = buf.begin_container(
            &FLOWSPEC_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_FS_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_FS_NLRI_LENGTH],
            FieldValue::U16(len as u16),
            rule_abs..rule_abs + header_len,
        );
        let value = &data[rule + header_len..end];
        let value_abs = rule_abs + header_len;
        if flowspec_value_valid(value, ipv6, vpn) {
            push_flowspec_value(buf, value, value_abs, ipv6, vpn);
        } else if !value.is_empty() {
            buf.push_field(
                &f[FD_FS_VALUE],
                FieldValue::Bytes(value),
                value_abs..value_abs + value.len(),
            );
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    pos
}

/// Returns `true` when `data` is a well-formed Flow Specification rule value:
/// the RD for SAFI 134 (RFC 8955, Section 8 —
/// <https://www.rfc-editor.org/rfc/rfc8955#section-8>), then one or more
/// components ("Encoding: <[component]+>") of known types in strictly
/// increasing type order, each well formed (see [`flowspec_component_end`]).
///
/// RFC 8955, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2>:
/// "An NLRI value not encoded as specified here, including an NLRI that
/// contains an unknown component type, is considered malformed".
fn flowspec_value_valid(data: &[u8], ipv6: bool, vpn: bool) -> bool {
    let mut pos = if vpn { RD_SIZE } else { 0 };
    if pos >= data.len() {
        return false;
    }
    let mut previous_type = 0;
    while pos < data.len() {
        let component_type = data[pos];
        if component_type <= previous_type {
            return false;
        }
        previous_type = component_type;
        match flowspec_component_end(data, pos, ipv6) {
            Some(end) => pos = end,
            None => return false,
        }
    }
    true
}

/// How a Flow Specification component's parameter is encoded.
enum FlowSpecParameter {
    /// IPv4 `<length, prefix>` (RFC 8955, Section 4.2.2.1 —
    /// <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2.1>).
    Ipv4Prefix,
    /// IPv6 `<length, offset, pattern>` (RFC 8956, Section 3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc8956#section-3.1>).
    Ipv6Prefix,
    /// `[numeric_op, value]+` (RFC 8955, Section 4.2.1.1 —
    /// <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1.1>).
    Numeric,
    /// `[bitmask_op, bitmask]+` (RFC 8955, Section 4.2.1.2 —
    /// <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1.2>).
    Bitmask,
}

/// Returns the parameter encoding of a component type, or `None` for a type
/// that is not defined for the address family.
///
/// RFC 8955, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2>
/// RFC 8956, Section 3 — <https://www.rfc-editor.org/rfc/rfc8956#section-3>
fn flowspec_parameter(component_type: u8, ipv6: bool) -> Option<FlowSpecParameter> {
    match component_type {
        FLOWSPEC_DESTINATION_PREFIX | FLOWSPEC_SOURCE_PREFIX if ipv6 => {
            Some(FlowSpecParameter::Ipv6Prefix)
        }
        FLOWSPEC_DESTINATION_PREFIX | FLOWSPEC_SOURCE_PREFIX => Some(FlowSpecParameter::Ipv4Prefix),
        FLOWSPEC_TCP_FLAGS | FLOWSPEC_FRAGMENT => Some(FlowSpecParameter::Bitmask),
        FLOWSPEC_FLOW_LABEL if ipv6 => Some(FlowSpecParameter::Numeric),
        3..=8 | 10 | 11 => Some(FlowSpecParameter::Numeric),
        _ => None,
    }
}

/// Returns the offset just past the component at `pos`, or `None` when it is
/// malformed: an unknown type, a truncated parameter, an IPv4 prefix longer
/// than 32 bits, an IPv6 prefix outside "offset < length < 129" (RFC 8956,
/// Section 3.1 — <https://www.rfc-editor.org/rfc/rfc8956#section-3.1>), or an
/// operator list without the end-of-list bit.
fn flowspec_component_end(data: &[u8], pos: usize, ipv6: bool) -> Option<usize> {
    let end = match flowspec_parameter(data[pos], ipv6)? {
        FlowSpecParameter::Ipv4Prefix => {
            let bits = *data.get(pos + 1)?;
            if bits > 32 {
                return None;
            }
            pos + 2 + usize::from(bits).div_ceil(8)
        }
        FlowSpecParameter::Ipv6Prefix => {
            let (bits, bit_offset) = (*data.get(pos + 1)?, *data.get(pos + 2)?);
            // "If length = 0 and offset = 0, this component matches every
            // address; otherwise, length MUST be in the range offset < length
            // < 129 or the component is malformed."
            if !(bits == 0 && bit_offset == 0 || bit_offset < bits && bits < 129) {
                return None;
            }
            pos + 3 + usize::from(bits - bit_offset).div_ceil(8)
        }
        FlowSpecParameter::Numeric | FlowSpecParameter::Bitmask => {
            let mut p = pos + 1;
            loop {
                let op = *data.get(p)?;
                p += 1 + (1usize << ((op >> 4) & 0x03));
                // "e (end-of-list bit): Set in the last {op, value} pair in
                // the list"
                if op & 0x80 != 0 {
                    break p;
                }
            }
        }
    };
    (end <= data.len()).then_some(end)
}

/// Pushes a Flow Specification rule value already validated by
/// [`flowspec_value_valid`]: the RD for SAFI 134 and the `components`.
fn push_flowspec_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ipv6: bool,
    vpn: bool,
) {
    let mut pos = 0;
    if vpn {
        buf.push_field(
            &FLOWSPEC_NLRI_FIELDS[FD_FS_RD],
            FieldValue::Bytes(&data[..RD_SIZE]),
            offset..offset + RD_SIZE,
        );
        pos = RD_SIZE;
    }
    let array_idx = buf.begin_container(
        &FLOWSPEC_NLRI_FIELDS[FD_FS_COMPONENTS],
        FieldValue::Array(0..0),
        offset + pos..offset + data.len(),
    );
    while let Some(end) = flowspec_component_end(data, pos, ipv6) {
        push_flowspec_component(buf, &data[pos..end], offset + pos, ipv6);
        pos = end;
        if pos >= data.len() {
            break;
        }
    }
    buf.end_container(array_idx);
}

/// Pushes one validated component (`data` is exactly the component).
///
/// RFC 8955, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2>
/// RFC 8956, Section 3 — <https://www.rfc-editor.org/rfc/rfc8956#section-3>
fn push_flowspec_component<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ipv6: bool,
) {
    let c = &FLOWSPEC_COMPONENT_FIELDS;
    let component_type = data[0];
    let obj_idx = buf.begin_container(
        &FLOWSPEC_COMPONENT_OBJECT_DESCRIPTOR,
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    let type_fd = if ipv6 {
        &FLOWSPEC_IPV6_COMPONENT_TYPE_FIELD
    } else {
        &c[FD_FSC_TYPE]
    };
    buf.push_field(type_fd, FieldValue::U8(component_type), offset..offset + 1);
    match flowspec_parameter(component_type, ipv6) {
        // "The length and prefix fields are encoded as in BGP UPDATE
        // messages" (RFC 8955, Section 4.2.2.1 —
        // https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2.1).
        Some(FlowSpecParameter::Ipv4Prefix) => buf.push_field(
            &PREFIX_ENTRY_IPV4_DESCRIPTOR,
            FieldValue::Bytes(&data[1..]),
            offset + 1..offset + data.len(),
        ),
        Some(FlowSpecParameter::Ipv6Prefix) => push_flowspec_ipv6_prefix(buf, data, offset),
        Some(FlowSpecParameter::Numeric) => push_flowspec_operators(buf, data, offset, true),
        Some(FlowSpecParameter::Bitmask) => push_flowspec_operators(buf, data, offset, false),
        None => {}
    }
    buf.end_container(obj_idx);
}

/// Pushes a validated IPv6 prefix component (length, offset, pattern).
///
/// RFC 8956, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc8956#section-3.1>.
/// With a zero offset the pattern is shown as a `prefix`; otherwise as
/// `prefix_length` and `pattern`.
fn push_flowspec_ipv6_prefix<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let c = &FLOWSPEC_COMPONENT_FIELDS;
    let (bits, bit_offset) = (data[1], data[2]);
    let pattern = &data[3..];
    buf.push_field(
        &c[FD_FSC_PREFIX_OFFSET],
        FieldValue::U8(bit_offset),
        offset + 2..offset + 3,
    );
    if bit_offset == 0 {
        // `[length, octets...]` in the scratch buffer, as for the other NLRI
        // prefixes.
        let scratch = buf.push_scratch(&[bits]);
        buf.extend_scratch(pattern);
        buf.push_field(
            &PREFIX_ENTRY_IPV6_DESCRIPTOR,
            FieldValue::Scratch(scratch.start..buf.scratch_len()),
            offset + 1..offset + data.len(),
        );
    } else {
        buf.push_field(
            &c[FD_FSC_PREFIX_LENGTH],
            FieldValue::U8(bits),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &c[FD_FSC_PATTERN],
            FieldValue::Bytes(pattern),
            offset + 3..offset + data.len(),
        );
    }
}

/// Pushes the validated {operator, value} pairs of a component into
/// `operators`.
///
/// RFC 8955, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1>:
/// the numeric operator is `e | a | len | 0 | lt | gt | eq` and the bitmask
/// operator `e | a | len | 0 | 0 | not | m`, with a value of `1 << len`
/// octets. The AND bit of the first operator "MUST be treated as always
/// unset on decoding".
fn push_flowspec_operators<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    numeric: bool,
) {
    let o = &FLOWSPEC_OPERATOR_FIELDS;
    let array_idx = buf.begin_container(
        &FLOWSPEC_COMPONENT_FIELDS[FD_FSC_OPERATORS],
        FieldValue::Array(0..0),
        offset + 1..offset + data.len(),
    );
    let mut p = 1;
    while p < data.len() {
        let op = data[p];
        let value_len = 1usize << ((op >> 4) & 0x03);
        let value = &data[p + 1..p + 1 + value_len];
        let abs = offset + p;
        let item_idx = buf.begin_container(
            &FLOWSPEC_OPERATOR_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..abs + 1 + value_len,
        );
        let and = if p == 1 { 0 } else { (op >> 6) & 1 };
        buf.push_field(&o[FD_FSO_OPERATOR], FieldValue::U8(op), abs..abs + 1);
        buf.push_field(
            &o[FD_FSO_END_OF_LIST],
            FieldValue::U8(op >> 7),
            abs..abs + 1,
        );
        buf.push_field(&o[FD_FSO_AND], FieldValue::U8(and), abs..abs + 1);
        if numeric {
            buf.push_field(
                &o[FD_FSO_COMPARISON],
                FieldValue::U8(op & 0x07),
                abs..abs + 1,
            );
        } else {
            buf.push_field(&o[FD_FSO_NOT], FieldValue::U8((op >> 1) & 1), abs..abs + 1);
            buf.push_field(&o[FD_FSO_MATCH], FieldValue::U8(op & 1), abs..abs + 1);
        }
        let v = value.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        buf.push_field(
            &o[FD_FSO_VALUE],
            FieldValue::U64(v),
            abs + 1..abs + 1 + value_len,
        );
        buf.end_container(item_idx);
        p += 1 + value_len;
    }
    buf.end_container(array_idx);
}

/// Returns a human-readable name for a BGP-LS NLRI Type.
///
/// IANA BGP-LS NLRI Types —
/// <https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#nlri-types>
fn bgp_ls_nlri_type_name(v: u16) -> Option<&'static str> {
    match v {
        // RFC 9552, Section 5.2 — https://www.rfc-editor.org/rfc/rfc9552#section-5.2
        1 => Some("Node NLRI"),
        2 => Some("Link NLRI"),
        3 => Some("IPv4 Topology Prefix NLRI"),
        4 => Some("IPv6 Topology Prefix NLRI"),
        // RFC 9857 — https://www.rfc-editor.org/rfc/rfc9857
        5 => Some("SR Policy Candidate Path NLRI"),
        // RFC 9514 — https://www.rfc-editor.org/rfc/rfc9514
        6 => Some("SRv6 SID NLRI"),
        _ => None,
    }
}

/// Returns a human-readable name for a BGP-LS Protocol-ID.
///
/// IANA BGP-LS Protocol-IDs —
/// <https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#protocol-ids>
fn bgp_ls_protocol_id_name(v: u8) -> Option<&'static str> {
    match v {
        // RFC 9552, Section 5.2 — https://www.rfc-editor.org/rfc/rfc9552#section-5.2
        1 => Some("IS-IS Level 1"),
        2 => Some("IS-IS Level 2"),
        3 => Some("OSPFv2"),
        4 => Some("Direct"),
        5 => Some("Static configuration"),
        6 => Some("OSPFv3"),
        // RFC 9086 — https://www.rfc-editor.org/rfc/rfc9086
        7 => Some("BGP"),
        // RFC 9857 — https://www.rfc-editor.org/rfc/rfc9857
        9 => Some("Segment Routing"),
        _ => None,
    }
}

/// NLRI Type (2) + Total NLRI Length (2) (RFC 9552, Section 5.2).
const BGP_LS_NLRI_HEADER_SIZE: usize = 4;
/// Protocol-ID (1) + Identifier (8) (RFC 9552, Section 5.2).
const BGP_LS_NLRI_FIXED_SIZE: usize = 9;
/// Highest NLRI Type whose body is Protocol-ID, Identifier and TLVs: Node,
/// Link, IPv4 / IPv6 Topology Prefix (RFC 9552, Section 5.2), SR Policy
/// Candidate Path (RFC 9857 — <https://www.rfc-editor.org/rfc/rfc9857>) and
/// SRv6 SID (RFC 9514 — <https://www.rfc-editor.org/rfc/rfc9514>).
const BGP_LS_NLRI_TYPE_MAX_DECODED: u16 = 6;
/// Local / Remote Node Descriptors TLVs, whose values are sub-TLVs (RFC 9552,
/// Sections 5.2.1.2-5.2.1.3 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.2.1.2>).
const BGP_LS_LOCAL_NODE_DESCRIPTORS: u16 = 256;
const BGP_LS_REMOTE_NODE_DESCRIPTORS: u16 = 257;

/// Returns how many leading octets of `data` frame as Link-State NLRI (NLRI
/// Type, Total NLRI Length, body), each preceded by `path_id_len` octets of
/// Path Identifier. The framing stops at the Reserved NLRI Type 0, and at an
/// NLRI of Types 1-6 whose body does not parse (see [`bgp_ls_body_valid`]).
fn bgp_ls_block_framed_len(data: &[u8], path_id_len: usize, vpn: bool) -> usize {
    let mut pos = 0;
    while pos < data.len() {
        let nlri = pos + path_id_len;
        let (Ok(nlri_type), Ok(len)) = (read_be_u16(data, nlri), read_be_u16(data, nlri + 2))
        else {
            break;
        };
        let end = nlri + BGP_LS_NLRI_HEADER_SIZE + usize::from(len);
        if nlri_type == 0 || end > data.len() {
            break;
        }
        if (1..=BGP_LS_NLRI_TYPE_MAX_DECODED).contains(&nlri_type)
            && !bgp_ls_body_valid(&data[nlri + BGP_LS_NLRI_HEADER_SIZE..end], vpn)
        {
            break;
        }
        pos = end;
    }
    pos
}

/// Returns `true` when a BGP-LS block carries RFC 7911 ADD-PATH Path
/// Identifiers: it does not frame as Link-State NLRI without them — a Path
/// Identifier usually starts with zero octets, which would read as the
/// Reserved NLRI Type 0, or as a Node NLRI without a Protocol-ID — and
/// frames further with them.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_bgp_ls(data: &[u8], vpn: bool) -> bool {
    let plain = bgp_ls_block_framed_len(data, 0, vpn);
    plain != data.len() && bgp_ls_block_framed_len(data, PATH_ID_SIZE, vpn) > plain
}

/// Parses a BGP-LS NLRI block (AFI 16388, SAFI 71, or 72 with an RD) into
/// one object per Link-State NLRI and returns the number of octets consumed.
///
/// RFC 9552, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.2>
///
/// Each NLRI is NLRI Type, Total NLRI Length ("the cumulative length, in
/// octets, of the rest of the NLRI, not including the NLRI Type field or
/// itself. For VPN applications, it also includes the length of the Route
/// Distinguisher"), the RD for SAFI 72, then for NLRI Types 1-6 a
/// Protocol-ID, an Identifier and descriptor TLVs. "An implementation MUST
/// handle unknown Link-State NLRI types as opaque objects": their body, and
/// a body that does not parse, stay as `value`.
fn parse_bgp_ls_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    vpn: bool,
) -> usize {
    let f = &BGP_LS_NLRI_FIELDS;
    let id_len = if detect_add_path_bgp_ls(data, vpn) {
        PATH_ID_SIZE
    } else {
        0
    };
    let mut pos = 0;
    while pos + id_len + BGP_LS_NLRI_HEADER_SIZE <= data.len() {
        let nlri = pos + id_len;
        let nlri_type = read_be_u16(data, nlri).unwrap_or_default();
        let len = read_be_u16(data, nlri + 2).unwrap_or_default();
        let end = nlri + BGP_LS_NLRI_HEADER_SIZE + usize::from(len);
        if end > data.len() {
            break;
        }
        let abs = base_offset + pos;
        let nlri_abs = base_offset + nlri;
        let obj_idx = buf.begin_container(
            &BGP_LS_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_LS_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_LS_NLRI_TYPE],
            FieldValue::U16(nlri_type),
            nlri_abs..nlri_abs + 2,
        );
        buf.push_field(
            &f[FD_LS_TOTAL_NLRI_LENGTH],
            FieldValue::U16(len),
            nlri_abs + 2..nlri_abs + BGP_LS_NLRI_HEADER_SIZE,
        );
        let body = &data[nlri + BGP_LS_NLRI_HEADER_SIZE..end];
        let body_abs = nlri_abs + BGP_LS_NLRI_HEADER_SIZE;
        let decoded =
            (1..=BGP_LS_NLRI_TYPE_MAX_DECODED).contains(&nlri_type) && bgp_ls_body_valid(body, vpn);
        if decoded {
            push_bgp_ls_body(buf, body, body_abs, vpn);
        } else if !body.is_empty() {
            buf.push_field(
                &f[FD_LS_VALUE],
                FieldValue::Bytes(body),
                body_abs..body_abs + body.len(),
            );
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    pos
}

/// Returns `true` when a Link-State NLRI body is the RD (SAFI 72), a
/// Protocol-ID, an Identifier and exactly a sequence of TLVs whose Node
/// Descriptors TLVs are exactly sequences of sub-TLVs.
fn bgp_ls_body_valid(body: &[u8], vpn: bool) -> bool {
    let start = if vpn { RD_SIZE } else { 0 } + BGP_LS_NLRI_FIXED_SIZE;
    let Some(tlvs) = body.get(start..) else {
        return false;
    };
    let header_len = BGP_LS_TLV_SHAPE.header_len();
    let mut pos = 0;
    while pos < tlvs.len() {
        let Some((tlv_type, value_len)) = tlv_at(tlvs, pos, BGP_LS_TLV_SHAPE) else {
            return false;
        };
        let value = &tlvs[pos + header_len..pos + header_len + value_len];
        if is_bgp_ls_node_descriptors(tlv_type) && !tlvs_fit(value, BGP_LS_TLV_SHAPE) {
            return false;
        }
        pos += header_len + value_len;
    }
    true
}

/// Returns `true` when `data` is exactly a sequence of TLVs of the given
/// shape; an empty sequence fits.
fn tlvs_fit(data: &[u8], shape: TlvShape) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        match tlv_at(data, pos, shape) {
            Some((_, value_len)) => pos += shape.header_len() + value_len,
            None => return false,
        }
    }
    true
}

/// Whether a descriptor TLV is a Local / Remote Node Descriptors TLV.
fn is_bgp_ls_node_descriptors(tlv_type: u16) -> bool {
    tlv_type == BGP_LS_LOCAL_NODE_DESCRIPTORS || tlv_type == BGP_LS_REMOTE_NODE_DESCRIPTORS
}

/// Pushes a Link-State NLRI body validated by [`bgp_ls_body_valid`].
///
/// RFC 9552, Sections 5.2.1-5.2.3 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.2.1>:
/// the Local / Remote Node Descriptors TLVs carry sub-TLVs; the other
/// descriptor TLVs keep their value as bytes.
fn push_bgp_ls_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    offset: usize,
    vpn: bool,
) {
    let f = &BGP_LS_NLRI_FIELDS;
    let mut pos = 0;
    if vpn {
        buf.push_field(
            &f[FD_LS_RD],
            FieldValue::Bytes(&body[..RD_SIZE]),
            offset..offset + RD_SIZE,
        );
        pos = RD_SIZE;
    }
    buf.push_field(
        &f[FD_LS_PROTOCOL_ID],
        FieldValue::U8(body[pos]),
        offset + pos..offset + pos + 1,
    );
    buf.push_field(
        &f[FD_LS_IDENTIFIER],
        FieldValue::U64(read_be_u64(body, pos + 1).unwrap_or_default()),
        offset + pos + 1..offset + pos + BGP_LS_NLRI_FIXED_SIZE,
    );
    pos += BGP_LS_NLRI_FIXED_SIZE;
    let tlvs = &body[pos..];
    let tlvs_offset = offset + pos;
    let array_idx = buf.begin_container(
        &f[FD_LS_DESCRIPTORS],
        FieldValue::Array(0..0),
        tlvs_offset..tlvs_offset + tlvs.len(),
    );
    let d = &BGP_LS_DESCRIPTOR_FIELDS;
    let mut p = 0;
    while let Some(tlv) = begin_tlv_object(
        buf,
        &BGP_LS_DESCRIPTOR_OBJECT_DESCRIPTOR,
        d,
        tlvs,
        p,
        tlvs_offset,
        BGP_LS_TLV_SHAPE,
    ) {
        if is_bgp_ls_node_descriptors(tlv.tlv_type) {
            push_generic_tlvs(
                buf,
                &d[FD_LSD_SUB_TLVS],
                &BGP_LS_TLV_OBJECT_DESCRIPTOR,
                BGP_LS_TLV_CHILDREN,
                tlv.value,
                tlv.value_offset,
                BGP_LS_TLV_SHAPE,
            );
        } else {
            push_bytes_nonempty(buf, &d[FD_LSD_VALUE], tlv.value, tlv.value_offset);
        }
        buf.end_container(tlv.idx);
        p = tlv.next;
    }
    buf.end_container(array_idx);
}

/// Size of the origin AS field of a Route Target membership NLRI (RFC 4684,
/// Section 4 — <https://www.rfc-editor.org/rfc/rfc4684#section-4>).
const RTC_ORIGIN_AS_SIZE: usize = 4;
/// Shortest non-default Route Target membership prefix: "Except for the
/// default route target, which is encoded as a zero-length prefix, the
/// minimum prefix length is 32 bits." (RFC 4684, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc4684#section-4>).
const RTC_MIN_PREFIX_BITS: u8 = 32;
/// Longest Route Target membership prefix: origin AS (4) and Route Target
/// (8) octets, "a prefix of 0 to 96 bits" (RFC 4684, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc4684#section-4>).
const RTC_MAX_PREFIX_BITS: u8 = 96;

/// Returns the number of octets of a Route Target membership prefix of
/// `bits` bits, or `None` for a length RFC 4684, Section 4 does not allow
/// (see [`RTC_MIN_PREFIX_BITS`] and [`RTC_MAX_PREFIX_BITS`]).
///
/// RFC 4684, Section 4 — <https://www.rfc-editor.org/rfc/rfc4684#section-4>
fn rtc_prefix_octets(bits: u8) -> Option<usize> {
    (bits == 0 || (RTC_MIN_PREFIX_BITS..=RTC_MAX_PREFIX_BITS).contains(&bits))
        .then(|| usize::from(bits).div_ceil(8))
}

/// Frames the leading Route Target membership NLRI of `data`, each preceded
/// by `path_id_len` octets of Path Identifier, stopping at a length that is
/// not 0 or 32-96 bits. Returns the number of octets framed, and whether a
/// default route target (zero-length prefix) shares the block with other
/// entries.
fn rtc_block_framing(data: &[u8], path_id_len: usize) -> (usize, bool) {
    let mut pos = 0;
    let mut entries = 0usize;
    let mut has_default = false;
    while pos < data.len() {
        let Some(octets) = data
            .get(pos + path_id_len)
            .copied()
            .and_then(rtc_prefix_octets)
        else {
            break;
        };
        let end = pos + path_id_len + 1 + octets;
        if end > data.len() {
            break;
        }
        has_default |= octets == 0;
        entries += 1;
        pos = end;
    }
    (pos, has_default && entries > 1)
}

/// Returns `true` when a Route Target membership NLRI block carries RFC 7911
/// ADD-PATH Path Identifiers. As in [`detect_add_path_prefixes`], it does
/// when the block frames further with them than without, or frames fully
/// with them while the plain reading contains a default route target that
/// is not the sole entry — a Path Identifier with zero octets reads as
/// default route targets.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_rt_constraint(data: &[u8]) -> bool {
    let (plain, suspicious) = rtc_block_framing(data, 0);
    if plain == data.len() && !suspicious {
        return false;
    }
    let (add_path, _) = rtc_block_framing(data, PATH_ID_SIZE);
    add_path > plain || (suspicious && add_path == data.len())
}

/// Parses a Route Target membership NLRI block (AFI 1, SAFI 132) into one
/// object per NLRI and returns the number of octets consumed.
///
/// RFC 4684, Section 4 — <https://www.rfc-editor.org/rfc/rfc4684#section-4>
///
/// Each NLRI is "a prefix of 0 to 96 bits, encoded as defined in Section 4
/// of [5]" — [5] is RFC 2858 (Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc2858#section-4>), obsoleted by RFC
/// 4760, whose Section 5 (<https://www.rfc-editor.org/rfc/rfc4760#section-5>)
/// carries the same `<length, prefix>` encoding — structured as origin AS (4 octets) and Route Target (0-8
/// octets, as corrected by Verified Erratum 6246 —
/// <https://www.rfc-editor.org/errata/eid6246>). The prefix length is
/// `prefix_length`; the covered octets are
/// `origin_as` (for 32 bits or more) and `route_target` (the covered
/// octets of the Route Target, if any). The framing stops at the first
/// length that is not allowed, and the rest stays raw.
fn parse_rt_constraint_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
) -> usize {
    let f = &RTC_NLRI_FIELDS;
    let id_len = if detect_add_path_rt_constraint(data) {
        PATH_ID_SIZE
    } else {
        0
    };
    let (consumed, _) = rtc_block_framing(data, id_len);
    let mut pos = 0;
    while pos < consumed {
        let bits_pos = pos + id_len;
        let bits = data[bits_pos];
        let octets = rtc_prefix_octets(bits).unwrap_or_default();
        let prefix = bits_pos + 1;
        let end = prefix + octets;
        let abs = base_offset + pos;
        let obj_idx = buf.begin_container(
            &RTC_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_RTC_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_RTC_PREFIX_LENGTH],
            FieldValue::U8(bits),
            base_offset + bits_pos..base_offset + prefix,
        );
        if octets >= RTC_ORIGIN_AS_SIZE {
            let rt = prefix + RTC_ORIGIN_AS_SIZE;
            buf.push_field(
                &f[FD_RTC_ORIGIN_AS],
                FieldValue::U32(read_be_u32(data, prefix).unwrap_or_default()),
                base_offset + prefix..base_offset + rt,
            );
            if end > rt {
                buf.push_field(
                    &f[FD_RTC_ROUTE_TARGET],
                    FieldValue::Bytes(&data[rt..end]),
                    base_offset + rt..base_offset + end,
                );
            }
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    consumed
}

/// Distinguisher (4) + Color (4) octets of an SR Policy NLRI (RFC 9830,
/// Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>).
const SR_POLICY_FIXED_SIZE: usize = 8;

/// Returns the only NLRI Length an SR Policy NLRI of the given AFI may
/// carry, in bits: "When AFI = 1, the value MUST be 96; when AFI = 2, the
/// value MUST be 192." (RFC 9830, Section 2.1 —
/// <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>).
fn sr_policy_nlri_bits(ipv6: bool) -> u8 {
    if ipv6 { 192 } else { 96 }
}

/// Returns the size of an SR Policy NLRI of the given AFI preceded by
/// `path_id_len` octets of Path Identifier.
fn sr_policy_entry_len(path_id_len: usize, ipv6: bool) -> usize {
    path_id_len + 1 + usize::from(sr_policy_nlri_bits(ipv6) / 8)
}

/// Returns how many leading octets of `data` frame as SR Policy NLRI of the
/// given AFI, each preceded by `path_id_len` octets of Path Identifier.
fn sr_policy_block_framed_len(data: &[u8], path_id_len: usize, ipv6: bool) -> usize {
    let bits = sr_policy_nlri_bits(ipv6);
    let entry_len = sr_policy_entry_len(path_id_len, ipv6);
    let mut pos = 0;
    while pos + entry_len <= data.len() && data[pos + path_id_len] == bits {
        pos += entry_len;
    }
    pos
}

/// Returns `true` when an SR Policy NLRI block carries RFC 7911 ADD-PATH
/// Path Identifiers: as in [`detect_add_path_prefixes`], it does when it
/// frames exactly with them and not without them — a Path Identifier whose
/// first octet is the NLRI Length 96 / 192 lets the first NLRI frame without
/// Path Identifiers too, so the first NLRI alone does not decide. A block
/// that frames exactly neither way is ADD-PATH when its first NLRI frames
/// only with Path Identifiers; plain encoding wins when both readings frame
/// exactly.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_sr_policy(data: &[u8], ipv6: bool) -> bool {
    let plain = sr_policy_block_framed_len(data, 0, ipv6);
    let with_path_id = sr_policy_block_framed_len(data, PATH_ID_SIZE, ipv6);
    (with_path_id == data.len() && plain != data.len()) || (plain == 0 && with_path_id != 0)
}

/// Parses an SR Policy NLRI block (AFI 1 / 2, SAFI 73) into one object per
/// NLRI and returns the number of octets consumed.
///
/// RFC 9830, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>
///
/// Each NLRI is NLRI Length (in bits), Distinguisher (4 octets), Color (4
/// octets) and Endpoint ("an IPv4 (4-octet) address or an IPv6 (16-octet)
/// address according to the AFI of the NLRI"). The framing stops at the
/// first NLRI Length other than 96 (AFI 1) / 192 (AFI 2), and the rest
/// stays raw.
fn parse_sr_policy_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    ipv6: bool,
) -> usize {
    let f = &SR_POLICY_NLRI_FIELDS;
    let id_len = if detect_add_path_sr_policy(data, ipv6) {
        PATH_ID_SIZE
    } else {
        0
    };
    let consumed = sr_policy_block_framed_len(data, id_len, ipv6);
    let entry_len = sr_policy_entry_len(id_len, ipv6);
    let mut pos = 0;
    while pos < consumed {
        let abs = base_offset + pos;
        let len_pos = pos + id_len;
        let fixed = len_pos + 1;
        let endpoint = fixed + SR_POLICY_FIXED_SIZE;
        let end = pos + entry_len;
        let obj_idx = buf.begin_container(
            &SR_POLICY_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_SRP_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_SRP_NLRI_LENGTH],
            FieldValue::U8(data[len_pos]),
            base_offset + len_pos..base_offset + fixed,
        );
        buf.push_field(
            &f[FD_SRP_DISTINGUISHER],
            FieldValue::U32(read_be_u32(data, fixed).unwrap_or_default()),
            base_offset + fixed..base_offset + fixed + 4,
        );
        buf.push_field(
            &f[FD_SRP_COLOR],
            FieldValue::U32(read_be_u32(data, fixed + 4).unwrap_or_default()),
            base_offset + fixed + 4..base_offset + endpoint,
        );
        let endpoint_value = if ipv6 {
            FieldValue::Ipv6Addr(read_ipv6_addr(data, endpoint).unwrap_or_default())
        } else {
            FieldValue::Ipv4Addr(read_ipv4_addr(data, endpoint).unwrap_or_default())
        };
        buf.push_field(
            &f[FD_SRP_ENDPOINT],
            endpoint_value,
            base_offset + endpoint..base_offset + end,
        );
        buf.end_container(obj_idx);
        pos = end;
    }
    consumed
}

/// Returns a human-readable name for MCAST-VPN Route Types.
///
/// IANA "BGP MCAST-VPN Route Types" registry —
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#mcast-vpn-route-types>
fn mcast_vpn_route_type_name(v: u8) -> Option<&'static str> {
    match v {
        // RFC 6514, Section 4 — https://www.rfc-editor.org/rfc/rfc6514#section-4
        1 => Some("Intra-AS I-PMSI A-D route"),
        2 => Some("Inter-AS I-PMSI A-D route"),
        3 => Some("S-PMSI A-D route"),
        4 => Some("Leaf A-D route"),
        5 => Some("Source Active A-D route"),
        6 => Some("Shared Tree Join route"),
        7 => Some("Source Tree Join route"),
        // RFC 7441, Section 3 — https://www.rfc-editor.org/rfc/rfc7441#section-3
        0x43 => Some("S-PMSI A-D route for C-multicast mLDP"),
        0x44 => Some("Leaf A-D route for C-multicast mLDP"),
        0x47 => Some("Source Tree Join route for C-multicast mLDP"),
        _ => None,
    }
}

/// Route Type (1) + Length (1) of an MCAST-VPN NLRI (RFC 6514, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc6514#section-4>).
const MCAST_VPN_HEADER_SIZE: usize = 2;
/// Size of the Source AS field (RFC 6514, Sections 4.2 and 4.6 —
/// <https://www.rfc-editor.org/rfc/rfc6514#section-4.2>).
const MCAST_VPN_SOURCE_AS_SIZE: usize = 4;

/// Returns the end of a Multicast Source / Group Length field and its
/// address at `pos`, or `None` if it overruns `body` or its length in bits
/// is not a whole number of octets.
///
/// RFC 6514, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc6514#section-4.3>
fn mcast_vpn_address_end(body: &[u8], pos: usize) -> Option<usize> {
    let bits = usize::from(*body.get(pos)?);
    let end = pos + 1 + bits / 8;
    (bits % 8 == 0 && end <= body.len()).then_some(end)
}

/// Returns `true` when `len` octets can be an Originating Router's IP
/// Address: "either 4 for IPv4 or 16 for IPv6" (RFC 6515, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc6515#section-2>).
fn is_originating_router_ip_len(len: usize) -> bool {
    len == 4 || len == 16
}

/// Returns `true` when the Route Type specific field of an MCAST-VPN NLRI of
/// Route Type 1-7 matches its layout (RFC 6514, Sections 4.1-4.6).
///
/// RFC 6514, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6514#section-4.1>
fn mcast_vpn_body_valid(route_type: u8, body: &[u8]) -> bool {
    let sg_end = |start: usize| {
        mcast_vpn_address_end(body, start).and_then(|src| mcast_vpn_address_end(body, src))
    };
    match route_type {
        1 => body
            .len()
            .checked_sub(RD_SIZE)
            .is_some_and(is_originating_router_ip_len),
        2 => body.len() == RD_SIZE + MCAST_VPN_SOURCE_AS_SIZE,
        3 => sg_end(RD_SIZE).is_some_and(|end| is_originating_router_ip_len(body.len() - end)),
        // "If the value of this octet is 0x01, 0x02, or 0x03, then this Leaf
        // A-D route was originated in response to an S-PMSI or I-PMSI A-D
        // route" and its Route Key is that route's NLRI; the Global Table
        // Multicast Route Key is not decoded (RFC 7524, Section 6.2.2 —
        // https://www.rfc-editor.org/rfc/rfc7524#section-6.2.2).
        4 => match body {
            [1..=3, key_len, ..] => {
                let key_end = MCAST_VPN_HEADER_SIZE + usize::from(*key_len);
                key_end <= body.len() && is_originating_router_ip_len(body.len() - key_end)
            }
            _ => false,
        },
        5 => sg_end(RD_SIZE) == Some(body.len()),
        6 | 7 => sg_end(RD_SIZE + MCAST_VPN_SOURCE_AS_SIZE) == Some(body.len()),
        _ => false,
    }
}

/// Returns `true` when `data` frames exactly as MCAST-VPN NLRI, each
/// preceded by `path_id_len` octets of Path Identifier, none of them of the
/// Reserved Route Type 0 — and, with `assigned_only`, all of an assigned
/// Route Type.
fn mcast_vpn_block_parses(data: &[u8], path_id_len: usize, assigned_only: bool) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let entry = pos + path_id_len;
        let (Some(&route_type), Some(&len)) = (data.get(entry), data.get(entry + 1)) else {
            return false;
        };
        if route_type == 0 || (assigned_only && mcast_vpn_route_type_name(route_type).is_none()) {
            return false;
        }
        pos = entry + MCAST_VPN_HEADER_SIZE + usize::from(len);
        if pos > data.len() {
            return false;
        }
    }
    true
}

/// Returns `true` when an MCAST-VPN block carries RFC 7911 ADD-PATH Path
/// Identifiers: it does not frame without them — a Path Identifier usually
/// starts with a zero octet, which would read as the Reserved Route Type 0
/// — and does with them, every Path Identifier being followed by an
/// assigned Route Type.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_mcast_vpn(data: &[u8]) -> bool {
    !mcast_vpn_block_parses(data, 0, false) && mcast_vpn_block_parses(data, PATH_ID_SIZE, true)
}

/// Parses an MCAST-VPN NLRI block (AFI 1 / 2, SAFI 5) into one object per
/// route and returns the number of octets consumed.
///
/// RFC 6514, Section 4 — <https://www.rfc-editor.org/rfc/rfc6514#section-4>
///
/// Each route is Route Type, Length ("the length in octets of the Route Type
/// specific field") and the Route Type specific field, decoded for Route
/// Types 1-7 (see [`push_mcast_vpn_body`]). Other Route Types, and bodies
/// that do not match their layout, keep a `value`.
fn parse_mcast_vpn_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
) -> usize {
    let f = &MCAST_VPN_NLRI_FIELDS;
    let id_len = if detect_add_path_mcast_vpn(data) {
        PATH_ID_SIZE
    } else {
        0
    };
    let mut pos = 0;
    while pos + id_len + MCAST_VPN_HEADER_SIZE <= data.len() {
        let entry = pos + id_len;
        let route_type = data[entry];
        let len = data[entry + 1];
        let body_start = entry + MCAST_VPN_HEADER_SIZE;
        let end = body_start + usize::from(len);
        if end > data.len() {
            break;
        }
        let abs = base_offset + pos;
        let entry_abs = base_offset + entry;
        let obj_idx = buf.begin_container(
            &MCAST_VPN_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_MVPN_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_MVPN_ROUTE_TYPE],
            FieldValue::U16(u16::from(route_type)),
            entry_abs..entry_abs + 1,
        );
        buf.push_field(
            &f[FD_MVPN_LENGTH],
            FieldValue::U8(len),
            entry_abs + 1..entry_abs + MCAST_VPN_HEADER_SIZE,
        );
        let body = &data[body_start..end];
        let body_abs = base_offset + body_start;
        if mcast_vpn_body_valid(route_type, body) {
            push_mcast_vpn_body(buf, route_type, body, body_abs);
        } else if !body.is_empty() {
            buf.push_field(
                &f[FD_MVPN_VALUE],
                FieldValue::Bytes(body),
                body_abs..body_abs + body.len(),
            );
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    pos
}

/// Pushes a Multicast Source / Group Length field at `pos` and its address,
/// if not empty (a zero length is a wildcard; RFC 6625, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc6625#section-2>). Returns its end.
fn push_mcast_vpn_address<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    pos: usize,
    offset: usize,
    length_desc: &'static FieldDescriptor,
    addr_desc: &'static FieldDescriptor,
) -> usize {
    let end = mcast_vpn_address_end(body, pos).unwrap_or(body.len());
    buf.push_field(
        length_desc,
        FieldValue::U8(body[pos]),
        offset + pos..offset + pos + 1,
    );
    if end > pos + 1 {
        buf.push_field(
            addr_desc,
            format_address(&body[pos + 1..end], end - pos - 1 == 16),
            offset + pos + 1..offset + end,
        );
    }
    end
}

/// Pushes the Route Type specific field of an MCAST-VPN NLRI validated by
/// [`mcast_vpn_body_valid`].
///
/// RFC 6514, Sections 4.1-4.6 — <https://www.rfc-editor.org/rfc/rfc6514#section-4.1>
fn push_mcast_vpn_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    route_type: u8,
    body: &'pkt [u8],
    offset: usize,
) {
    let f = &MCAST_VPN_NLRI_FIELDS;
    let mut pos = if route_type == 4 {
        // "the Route Key of the Leaf A-D route is set to the NLRI of the
        // received route" (RFC 6514, Section 4.4 —
        // https://www.rfc-editor.org/rfc/rfc6514#section-4.4).
        let key_end = MCAST_VPN_HEADER_SIZE + usize::from(body[1]);
        buf.push_field(
            &f[FD_MVPN_ROUTE_KEY],
            FieldValue::Bytes(&body[..key_end]),
            offset..offset + key_end,
        );
        key_end
    } else {
        buf.push_field(
            &f[FD_MVPN_RD],
            FieldValue::Bytes(&body[..RD_SIZE]),
            offset..offset + RD_SIZE,
        );
        RD_SIZE
    };
    if matches!(route_type, 2 | 6 | 7) {
        buf.push_field(
            &f[FD_MVPN_SOURCE_AS],
            FieldValue::U32(read_be_u32(body, pos).unwrap_or_default()),
            offset + pos..offset + pos + MCAST_VPN_SOURCE_AS_SIZE,
        );
        pos += MCAST_VPN_SOURCE_AS_SIZE;
    }
    if matches!(route_type, 3 | 5 | 6 | 7) {
        pos = push_mcast_vpn_address(
            buf,
            body,
            pos,
            offset,
            &f[FD_MVPN_SOURCE_LENGTH],
            &f[FD_MVPN_SOURCE],
        );
        pos = push_mcast_vpn_address(
            buf,
            body,
            pos,
            offset,
            &f[FD_MVPN_GROUP_LENGTH],
            &f[FD_MVPN_GROUP],
        );
    }
    if matches!(route_type, 1 | 3 | 4) {
        buf.push_field(
            &f[FD_MVPN_ORIGINATING_ROUTER_IP],
            format_address(&body[pos..], body.len() - pos == 16),
            offset + pos..offset + body.len(),
        );
    }
}

/// Length field of a VPLS / BGP-AD NLRI: "The Length field is in octets"
/// (RFC 4761, Section 3.2.2 — <https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2>).
const VPLS_LENGTH_SIZE: usize = 2;
/// Length of a VPLS NLRI: "VPLS-BGP [RFC4761] uses a 17-byte NLRI length"
/// (RFC 6074, Section 7 — <https://www.rfc-editor.org/rfc/rfc6074#section-7>).
const VPLS_NLRI_LENGTH: u16 = 17;
/// Length of a BGP-AD NLRI: "The BGP-AD NLRI has an NLRI length of 12
/// bytes, containing only an 8-byte RD and a 4-byte VSI-ID" (RFC 6074,
/// Section 7 — <https://www.rfc-editor.org/rfc/rfc6074#section-7>).
const VPLS_AD_NLRI_LENGTH: u16 = 12;

/// Returns how many leading octets of `data` frame as VPLS / BGP-AD NLRI
/// of 12 or 17 octets, each preceded by `path_id_len` octets of Path
/// Identifier.
fn vpls_block_framed_len(data: &[u8], path_id_len: usize) -> usize {
    let mut pos = 0;
    while let Ok(len) = read_be_u16(data, pos + path_id_len) {
        let end = pos + path_id_len + VPLS_LENGTH_SIZE + usize::from(len);
        if (len != VPLS_NLRI_LENGTH && len != VPLS_AD_NLRI_LENGTH) || end > data.len() {
            break;
        }
        pos = end;
    }
    pos
}

/// Returns `true` when a VPLS NLRI block carries RFC 7911 ADD-PATH Path
/// Identifiers: it does not frame fully as 12- / 17-octet NLRI without them
/// — a Path Identifier usually starts with zero octets, which would read as
/// a zero Length — and frames further with them.
///
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
fn detect_add_path_vpls(data: &[u8]) -> bool {
    let plain = vpls_block_framed_len(data, 0);
    plain != data.len() && vpls_block_framed_len(data, PATH_ID_SIZE) > plain
}

/// Parses a VPLS NLRI block (AFI 25, SAFI 65) into one object per NLRI and
/// returns the number of octets consumed.
///
/// Both VPLS and BGP-AD NLRI use this AFI / SAFI, and "the NLRI length must
/// be used as a demultiplexer" (RFC 6074, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc6074#section-7>):
///
/// - 17 octets: RD, VE ID, VE Block Offset, VE Block Size and Label Base
///   (RFC 4761, Section 3.2.2 —
///   <https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2>). RFC 4761 gives
///   the Label Base only as "3 octets"; like labeled NLRI (RFC 8277,
///   Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>), the
///   label is taken from its high-order 20 bits.
/// - 12 octets: RD and PE_addr (RFC 6074, Section 3.2.2.1 —
///   <https://www.rfc-editor.org/rfc/rfc6074#section-3.2.2.1>).
///
/// NLRI of other lengths keep a `value`; the framing stops at a Length too
/// short for an RD, and the rest stays raw.
fn parse_vpls_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
) -> usize {
    let f = &VPLS_NLRI_FIELDS;
    let id_len = if detect_add_path_vpls(data) {
        PATH_ID_SIZE
    } else {
        0
    };
    let mut pos = 0;
    while pos + id_len + VPLS_LENGTH_SIZE <= data.len() {
        let len_pos = pos + id_len;
        let len = read_be_u16(data, len_pos).unwrap_or_default();
        let body_start = len_pos + VPLS_LENGTH_SIZE;
        let end = body_start + usize::from(len);
        if usize::from(len) < RD_SIZE || end > data.len() {
            break;
        }
        let abs = base_offset + pos;
        let obj_idx = buf.begin_container(
            &VPLS_NLRI_OBJECT_DESCRIPTOR,
            FieldValue::Object(0..0),
            abs..base_offset + end,
        );
        if id_len != 0 {
            buf.push_field(
                &f[FD_VPLS_PATH_ID],
                FieldValue::U32(read_be_u32(data, pos).unwrap_or_default()),
                abs..abs + PATH_ID_SIZE,
            );
        }
        buf.push_field(
            &f[FD_VPLS_NLRI_LENGTH],
            FieldValue::U16(len),
            base_offset + len_pos..base_offset + body_start,
        );
        let o = base_offset + body_start;
        let body = &data[body_start..end];
        let push_rd = |buf: &mut DissectBuffer<'pkt>| {
            buf.push_field(
                &f[FD_VPLS_RD],
                FieldValue::Bytes(&body[..RD_SIZE]),
                o..o + RD_SIZE,
            );
        };
        match len {
            VPLS_NLRI_LENGTH => {
                push_rd(buf);
                for (i, fd) in [
                    FD_VPLS_VE_ID,
                    FD_VPLS_VE_BLOCK_OFFSET,
                    FD_VPLS_VE_BLOCK_SIZE,
                ]
                .into_iter()
                .enumerate()
                {
                    let at = RD_SIZE + 2 * i;
                    buf.push_field(
                        &f[fd],
                        FieldValue::U16(read_be_u16(body, at).unwrap_or_default()),
                        o + at..o + at + 2,
                    );
                }
                let label_at = RD_SIZE + 6;
                buf.push_field(
                    &f[FD_VPLS_LABEL_BASE],
                    FieldValue::U32(read_be_u24(body, label_at).unwrap_or_default() >> 4),
                    o + label_at..o + body.len(),
                );
            }
            VPLS_AD_NLRI_LENGTH => {
                push_rd(buf);
                buf.push_field(
                    &f[FD_VPLS_PE_ADDRESS],
                    FieldValue::Ipv4Addr(read_ipv4_addr(body, RD_SIZE).unwrap_or_default()),
                    o + RD_SIZE..o + body.len(),
                );
            }
            _ => buf.push_field(
                &f[FD_VPLS_VALUE],
                FieldValue::Bytes(body),
                o..o + body.len(),
            ),
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    pos
}

/// Selects the NLRI encoding for an (AFI, SAFI) pair.
///
/// Only the SAFIs that use the plain `<length, prefix>` encoding of RFC 4760,
/// Section 5 may go to [`parse_prefixes`]: other SAFIs of AFI 1/2 (labeled
/// unicast, L3VPN, FlowSpec, SR Policy, ...) have different NLRI layouts —
/// decoded by their own [`MpNlriEncoding`] where implemented — and the ADD-PATH
/// heuristic would otherwise turn them into plausible looking but wrong
/// prefixes. Returns `None` for an (AFI, SAFI) whose NLRI is not decoded.
///
/// RFC 4760, Section 5 — <https://www.rfc-editor.org/rfc/rfc4760#section-5>
fn mp_nlri_encoding(afi: u16, safi: u8) -> Option<MpNlriEncoding> {
    let ipv6 = afi == AFI_IPV6;
    match (afi, safi) {
        (AFI_IPV4 | AFI_IPV6, SAFI_UNICAST | SAFI_MULTICAST) => {
            Some(MpNlriEncoding::Prefixes { ipv6 })
        }
        (AFI_IPV4 | AFI_IPV6, SAFI_MPLS_LABEL) => {
            Some(MpNlriEncoding::Labeled { ipv6, vpn: false })
        }
        (AFI_IPV4 | AFI_IPV6, SAFI_MPLS_VPN) => Some(MpNlriEncoding::Labeled { ipv6, vpn: true }),
        (_, SAFI_MUP) => Some(MpNlriEncoding::Mup { ipv6 }),
        (AFI_L2VPN, SAFI_EVPN) => Some(MpNlriEncoding::Evpn),
        (AFI_L2VPN, SAFI_VPLS) => Some(MpNlriEncoding::Vpls),
        (AFI_BGP_LS, SAFI_BGP_LS) => Some(MpNlriEncoding::BgpLs { vpn: false }),
        (AFI_BGP_LS, SAFI_BGP_LS_VPN) => Some(MpNlriEncoding::BgpLs { vpn: true }),
        (AFI_IPV4, SAFI_RT_CONSTRAINT) => Some(MpNlriEncoding::RtConstraint),
        (AFI_IPV4 | AFI_IPV6, SAFI_SR_POLICY) => Some(MpNlriEncoding::SrPolicy { ipv6 }),
        (AFI_IPV4 | AFI_IPV6, SAFI_MCAST_VPN) => Some(MpNlriEncoding::McastVpn),
        (AFI_IPV4 | AFI_IPV6, SAFI_MULTICAST_VPN) => {
            Some(MpNlriEncoding::MulticastVpnPrefixes { ipv6 })
        }
        (AFI_IPV4 | AFI_IPV6, SAFI_FLOWSPEC) => Some(MpNlriEncoding::FlowSpec { ipv6, vpn: false }),
        (AFI_IPV4 | AFI_IPV6, SAFI_FLOWSPEC_VPN) => {
            Some(MpNlriEncoding::FlowSpec { ipv6, vpn: true })
        }
        _ => None,
    }
}

/// Parses the NLRI / Withdrawn Routes block of an MP_REACH_NLRI /
/// MP_UNREACH_NLRI attribute.
///
/// Decoded entries go into an Array described by `array_desc`. Octets that
/// are not decoded — the whole block for an (AFI, SAFI) whose encoding is not
/// implemented, or the malformed tail of a decoded block — are pushed as raw
/// bytes with `raw_desc`, so that routes are never silently dropped.
///
/// `vni_label` selects the VNI reading of the EVPN MPLS Label fields (see
/// [`AttrContext::vni_label`]).
///
/// RFC 4760, Sections 3-4 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
#[allow(clippy::too_many_arguments)]
fn parse_mp_nlri_block<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    afi: u16,
    safi: u8,
    withdraw: bool,
    vni_label: bool,
    array_desc: &'static FieldDescriptor,
    raw_desc: &'static FieldDescriptor,
) {
    let mut consumed = 0;
    if let Some(encoding) = mp_nlri_encoding(afi, safi) {
        let array_idx = buf.begin_container(
            array_desc,
            FieldValue::Array(0..0),
            offset..offset + data.len(),
        );
        let before = buf.field_count();
        consumed = match encoding {
            MpNlriEncoding::Prefixes { ipv6 } => parse_prefixes(buf, data, offset, ipv6),
            MpNlriEncoding::Mup { ipv6 } => parse_mup_nlri(buf, data, offset, ipv6),
            MpNlriEncoding::Labeled { ipv6, vpn } => {
                parse_labeled_nlri(buf, data, offset, &LabeledNlri::new(ipv6, vpn, withdraw))
            }
            MpNlriEncoding::Evpn => parse_evpn_nlri(buf, data, offset, vni_label),
            MpNlriEncoding::FlowSpec { ipv6, vpn } => {
                parse_flowspec_nlri(buf, data, offset, ipv6, vpn)
            }
            MpNlriEncoding::BgpLs { vpn } => parse_bgp_ls_nlri(buf, data, offset, vpn),
            MpNlriEncoding::RtConstraint => parse_rt_constraint_nlri(buf, data, offset),
            MpNlriEncoding::SrPolicy { ipv6 } => parse_sr_policy_nlri(buf, data, offset, ipv6),
            MpNlriEncoding::McastVpn => parse_mcast_vpn_nlri(buf, data, offset),
            MpNlriEncoding::Vpls => parse_vpls_nlri(buf, data, offset),
            MpNlriEncoding::MulticastVpnPrefixes { ipv6 } => {
                parse_labeled_nlri(buf, data, offset, &LabeledNlri::unlabeled_vpn(ipv6))
            }
        };
        if buf.field_count() == before {
            buf.pop_field(); // remove empty array placeholder
        } else {
            buf.end_container(array_idx);
        }
    }
    if consumed < data.len() {
        buf.push_field(
            raw_desc,
            FieldValue::Bytes(&data[consumed..]),
            offset + consumed..offset + data.len(),
        );
    }
}

/// Returns `true` for the SAFIs whose next hop is a VPN address, i.e. an
/// 8-octet Route Distinguisher (set to zero) followed by an IP address.
///
/// RFC 4364, Section 4.3.2 — <https://www.rfc-editor.org/rfc/rfc4364#section-4.3.2>
/// RFC 8950, Section 3 — <https://www.rfc-editor.org/rfc/rfc8950#section-3>
fn is_vpn_next_hop_safi(safi: u8) -> bool {
    safi == SAFI_MPLS_VPN || safi == SAFI_MULTICAST_VPN
}

/// Parses the Network Address of Next Hop field of MP_REACH_NLRI.
///
/// The layout is selected by the AFI, the SAFI and the Length of Next Hop
/// Network Address:
///
/// - AFI 1 or 25 (L2VPN), non-VPN SAFI, length 4: IPv4 address.
/// - AFI 25 (L2VPN), non-VPN SAFI, length 16 or 32: IPv6 address(es), as
///   for AFI 2 (RFC 7432, Section 9.2.1).
/// - AFI 16388 (BGP-LS): as AFI 1 / 2, with SAFI 72 as the VPN SAFI; a
///   40 octet SAFI 72 next hop is one RD followed by a global and a
///   link-local IPv6 address (RFC 9552, Section 5.5).
/// - SAFI 5 (MCAST-VPN): an IPv4 (4 octets) or IPv6 (16 octets) address
///   for AFI 1 and 2 alike (RFC 6515, Section 2).
/// - SAFI 73 (SR Policy): 4, 16 or 32 octets as above for AFI 1 and 2
///   alike, "independent of the SR Policy AFI" (RFC 9830, Section 2.1).
/// - AFI 1 or 2, non-VPN SAFI, length 16 or 32: IPv6 global address,
///   optionally followed by a link-local address (RFC 2545, Section 3; for
///   AFI 1 RFC 8950, Section 3).
/// - AFI 1, VPN SAFI, length 12: VPN-IPv4 address, "encoded as a VPN-IPv4
///   address with an RD of 0" (RFC 4364, Section 4.3.2).
/// - AFI 1 or 2, VPN SAFI, length 24 or 48: VPN-IPv6 global address,
///   optionally followed by a VPN-IPv6 link-local address, each "whose
///   8-octet RD is set to zero" (RFC 4659, Section 3.2.1.1; for AFI 1
///   RFC 8950, Section 3).
///
/// Anything else is pushed as raw bytes.
///
/// RFC 4760, Section 3 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
/// RFC 2545, Section 3 — <https://www.rfc-editor.org/rfc/rfc2545#section-3>
/// RFC 4364, Section 4.3.2 — <https://www.rfc-editor.org/rfc/rfc4364#section-4.3.2>
/// RFC 4659, Section 3.2.1.1 — <https://www.rfc-editor.org/rfc/rfc4659#section-3.2.1.1>
/// RFC 8950, Section 3 — <https://www.rfc-editor.org/rfc/rfc8950#section-3>
/// RFC 7432, Section 9.2.1 — <https://www.rfc-editor.org/rfc/rfc7432#section-9.2.1>
/// RFC 9552, Section 5.5 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.5>
/// RFC 9830, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>
/// RFC 6515, Section 2 — <https://www.rfc-editor.org/rfc/rfc6515#section-2>
fn parse_mp_next_hop<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    afi: u16,
    safi: u8,
    nh: &'pkt [u8],
    offset: usize,
) {
    let ip_afi = afi == AFI_IPV4 || afi == AFI_IPV6;
    // The L2VPN AFI carries a plain IPv4 or IPv6 next hop: "The Next Hop
    // field of the MP_REACH_NLRI attribute of the route MUST be set to the
    // IPv4 or IPv6 address of the advertising PE" (RFC 7432, Section 9.2.1 —
    // https://www.rfc-editor.org/rfc/rfc7432#section-9.2.1).
    // BGP-LS: "If the next-hop length is 4, then the next hop is an IPv4
    // address; if the next-hop length is 16, then it is a global IPv6
    // address; and if the next-hop length is 32, then there is one global
    // IPv6 address followed by an IPv6 link-local address. ... For VPN
    // Subsequent Address Family Identifier (SAFI), as per custom, an 8-byte
    // Route Distinguisher set to all zero is prepended to the next hop"
    // (RFC 9552, Section 5.5 — https://www.rfc-editor.org/rfc/rfc9552#section-5.5).
    // SR Policy: "The next-hop network address field in SR Policy SAFI (73)
    // updates may be either a 4-octet IPv4 address or a 16-octet IPv6
    // address, independent of the SR Policy AFI." (RFC 9830, Section 2.1 —
    // https://www.rfc-editor.org/rfc/rfc9830#section-2.1).
    // MCAST-VPN: "it is always clear whether the address is an IPv4 address
    // (length is 4) or an IPv6 address (length is 16).  If the length of the
    // next hop address is neither 4 nor 16, the MP_REACH_NLRI attribute MUST
    // be considered to be "incorrect"" (RFC 6515, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc6515#section-2).
    let bgp_ls = afi == AFI_BGP_LS;
    let sr_policy = ip_afi && safi == SAFI_SR_POLICY;
    let mcast_vpn = ip_afi && safi == SAFI_MCAST_VPN;
    let vpn = is_vpn_next_hop_safi(safi) || (bgp_ls && safi == SAFI_BGP_LS_VPN);
    let other_afi = (afi == AFI_L2VPN || bgp_ls || sr_policy) && !vpn;
    // Length of the Route Distinguisher preceding each address, if any.
    let rd_len = match (vpn, nh.len()) {
        (false, 4 | 16) if mcast_vpn => 0,
        (false, 4) if afi == AFI_IPV4 || other_afi => 0,
        (false, 16 | 32) if (ip_afi && !mcast_vpn) || other_afi => 0,
        (true, 12) if afi == AFI_IPV4 || bgp_ls => RD_SIZE,
        (true, 24 | 48) if ip_afi || bgp_ls => RD_SIZE,
        // BGP-LS-VPN: a single RD prepended to a global + link-local IPv6
        // next hop (RFC 9552, Section 5.5 —
        // https://www.rfc-editor.org/rfc/rfc9552#section-5.5).
        (true, 40) if bgp_ls => RD_SIZE,
        _ => {
            buf.push_field(
                &MP_CHILDREN[FD_MP_NEXT_HOP],
                FieldValue::Bytes(nh),
                offset..offset + nh.len(),
            );
            return;
        }
    };

    // A 32 / 48 octet next hop is a global address followed by a link-local
    // address of the same shape; a 40 octet one is an RD followed by a
    // global and a link-local address.
    let entry_len = match nh.len() {
        32 | 48 => nh.len() / 2,
        40 => RD_SIZE + 16,
        len => len,
    };
    // Only the 48 octet shape repeats the RD before the link-local address.
    let link_local_rd_len = if nh.len() == 48 { rd_len } else { 0 };
    let has_link_local = entry_len != nh.len();

    if rd_len != 0 {
        buf.push_field(
            &MP_CHILDREN[FD_MP_NEXT_HOP_RD],
            FieldValue::Bytes(&nh[..rd_len]),
            offset..offset + rd_len,
        );
    }
    let global = &nh[rd_len..entry_len];
    let global_value = if global.len() == 4 {
        FieldValue::Ipv4Addr(read_ipv4_addr(global, 0).unwrap_or_default())
    } else {
        FieldValue::Ipv6Addr(read_ipv6_addr(global, 0).unwrap_or_default())
    };
    buf.push_field(
        &MP_CHILDREN[FD_MP_NEXT_HOP],
        global_value,
        offset + rd_len..offset + entry_len,
    );

    if has_link_local {
        if link_local_rd_len != 0 {
            buf.push_field(
                &MP_CHILDREN[FD_MP_NEXT_HOP_LINK_LOCAL_RD],
                FieldValue::Bytes(&nh[entry_len..entry_len + link_local_rd_len]),
                offset + entry_len..offset + entry_len + link_local_rd_len,
            );
        }
        buf.push_field(
            &MP_CHILDREN[FD_MP_NEXT_HOP_LINK_LOCAL],
            FieldValue::Ipv6Addr(
                read_ipv6_addr(nh, entry_len + link_local_rd_len).unwrap_or_default(),
            ),
            offset + entry_len + link_local_rd_len..offset + nh.len(),
        );
    }
}

/// Parses MP_REACH_NLRI attribute value.
///
/// RFC 4760, Section 3 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
fn parse_mp_reach_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    vni_label: bool,
) -> MpAfiSafi {
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
        return MpAfiSafi { afi, safi, offset };
    }

    parse_mp_next_hop(buf, afi, safi, &data[nh_start..nh_end], offset + nh_start);

    // Skip Reserved byte
    let nlri_start = nh_end + 1;
    if nlri_start < data.len() {
        parse_mp_nlri_block(
            buf,
            &data[nlri_start..],
            offset + nlri_start,
            afi,
            safi,
            false,
            vni_label,
            &MP_CHILDREN[FD_MP_NLRI],
            &MP_CHILDREN[FD_MP_NLRI_RAW],
        );
    }

    buf.end_container(obj_idx);

    MpAfiSafi { afi, safi, offset }
}

/// Parses MP_UNREACH_NLRI attribute value.
///
/// RFC 4760, Section 4 — <https://www.rfc-editor.org/rfc/rfc4760#section-4>
fn parse_mp_unreach_nlri<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    vni_label: bool,
) -> MpAfiSafi {
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
        parse_mp_nlri_block(
            buf,
            &data[wr_start..],
            offset + wr_start,
            afi,
            safi,
            true,
            vni_label,
            &MP_CHILDREN[FD_MP_WITHDRAWN_ROUTES],
            &MP_CHILDREN[FD_MP_WITHDRAWN_ROUTES_RAW],
        );
    }

    buf.end_container(obj_idx);

    MpAfiSafi { afi, safi, offset }
}

/// Parses UPDATE message body and appends fields.
///
/// RFC 4271, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>
fn parse_update<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    as_size: Option<AsNumberSize>,
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
    let mut first_mp_afi_safi: Option<MpAfiSafi> = None;
    if path_attr_len > 0 {
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_PATH_ATTRIBUTES],
            FieldValue::Array(0..0),
            offset + pa_start..offset + pa_end,
        );
        let before = buf.field_count();
        let mut pos = 0;
        let attr_data = &data[pa_start..pa_end];
        let mut ctx = AttrContext::for_update(attr_data);
        // A size known from outside the message (e.g. the BMP A flag) takes
        // precedence over the size inferred from the other attributes.
        if let Some(as_size) = as_size {
            ctx.as_size_hint = Some(as_size.octets());
        }
        while pos < attr_data.len() {
            if let Some((consumed, mp_afi_safi)) =
                parse_path_attribute(buf, &attr_data[pos..], offset + pa_start + pos, ctx)
            {
                if first_mp_afi_safi.is_none() {
                    first_mp_afi_safi = mp_afi_safi;
                }
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

    // Mirror the AFI/SAFI of the first MP_REACH_NLRI / MP_UNREACH_NLRI
    // attribute (in attribute order) as top-level `afi`/`safi` fields, so a
    // consumer can filter on the address family of an UPDATE without
    // reaching into `path_attributes`. Plain IPv4 unicast UPDATEs carry no
    // MP attribute and get no top-level afi/safi — only what is on the wire
    // is decoded.
    //
    // RFC 4760, Section 3 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
    // RFC 4760, Section 4 — <https://www.rfc-editor.org/rfc/rfc4760#section-4>
    if let Some(mp) = first_mp_afi_safi {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_AFI],
            FieldValue::U16(mp.afi),
            mp.offset..mp.offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SAFI],
            FieldValue::U8(mp.safi),
            mp.offset + 2..mp.offset + 3,
        );
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

/// Schema entry for the prefix inside a MUP/IP union NLRI entry object.
///
/// Used in [`NLRI_ENTRY_FIELDS`], the MUP/IP union that describes every
/// `nlri` / `withdrawn_routes` array (top level and inside
/// `MP_REACH_NLRI` / `MP_UNREACH_NLRI` values): a MUP (SAFI 85) entry may
/// omit `prefix` entirely (e.g. Route Type 2 "Direct Segment Discovery",
/// which carries `address` instead), so in that union it must be optional.
///
/// The `format_fn` renders the CIDR string. The address-family specific runtime
/// descriptors ([`PREFIX_ENTRY_IPV4_DESCRIPTOR`] / [`PREFIX_ENTRY_IPV6_DESCRIPTOR`])
/// are what actually serialise a value; this entry only advertises the field in
/// the schema, so the IPv4 formatter stands in for both families.
const NLRI_PREFIX_FIELD: FieldDescriptor = PREFIX_ENTRY_IPV4_FIELD.optional();

/// Field descriptor index for [`NLRI_ENTRY_CHILDREN`] (index 1 is `prefix`,
/// pushed through the address-family specific `PREFIX_ENTRY_*` descriptors).
const FD_NLRI_PATH_ID: usize = 0;
const FD_NLRI_LABEL_STACK: usize = 12;
const FD_NLRI_COMPATIBILITY: usize = 13;

/// Field descriptor indices for [`LABEL_ENTRY_CHILDREN`].
const FD_LABEL_LABEL: usize = 0;
const FD_LABEL_RSRV: usize = 1;
const FD_LABEL_S: usize = 2;

/// Child field descriptors of one Label / Rsrv / S entry of a labeled NLRI.
///
/// RFC 8277, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8277#section-2.2>
const LABEL_ENTRY_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("label", "Label", FieldType::U32),
    FieldDescriptor::new("rsrv", "Reserved", FieldType::U8),
    FieldDescriptor::new("s", "Bottom of Stack", FieldType::U8),
];

/// Slice form of [`LABEL_ENTRY_FIELDS`].
static LABEL_ENTRY_CHILDREN: &[FieldDescriptor] = &LABEL_ENTRY_FIELDS;

/// Object descriptor for label entries inside `label_stack`.
static LABEL_ENTRY_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("entry", "Label Entry", FieldType::Object)
        .with_children(&LABEL_ENTRY_FIELDS);

/// Object descriptor for NLRI / withdrawn route entries.
static NLRI_ENTRY_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("nlri_entry", "NLRI Entry", FieldType::Object)
        .with_children(NLRI_ENTRY_CHILDREN);

/// Union of every field that can appear in an NLRI entry object.
///
/// Shared by the top-level `nlri` / `withdrawn_routes` arrays (RFC 4271,
/// Section 4.3 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.3>) and by
/// the ones inside an MP_REACH_NLRI / MP_UNREACH_NLRI attribute value, so a
/// consumer resolving a path such as `BGP.nlri.route_type` finds the same
/// schema on either array.
///
/// The element shape depends on the SAFI: SAFI 70 (EVPN) yields EVPN entries,
/// SAFI 85 (BGP-MUP) yields MUP entries, SAFI 133 / 134 yield Flow
/// Specification entries, SAFI 71 / 72 yield Link-State NLRI entries,
/// SAFI 132 yields Route Target membership entries, SAFI 73 yields SR
/// Policy entries, SAFI 5 yields MCAST-VPN entries, SAFI 129 yields `rd` and
/// `prefix` entries, AFI 25 / SAFI 65 yields VPLS / BGP-AD entries,
/// SAFI 4 / 128 yield labeled entries (`label_stack` or `compatibility`, `rd`
/// for SAFI 128, `prefix`), and SAFI 1 / 2 yield plain prefix entries. All
/// fields are therefore optional.
///
/// RFC 4760 — <https://www.rfc-editor.org/rfc/rfc4760>
/// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
/// RFC 7432, Section 7 — <https://www.rfc-editor.org/rfc/rfc7432#section-7>
/// RFC 8955, Section 4 — <https://www.rfc-editor.org/rfc/rfc8955#section-4>
/// RFC 9552, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.2>
/// RFC 4684, Section 4 — <https://www.rfc-editor.org/rfc/rfc4684#section-4>
/// RFC 9830, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>
/// RFC 6514, Sections 4 and 10 — <https://www.rfc-editor.org/rfc/rfc6514#section-4>
/// RFC 4761, Section 3.2.2 — <https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2>
/// draft-ietf-bess-mup-safi-01 —
/// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
const NLRI_ENTRY_FIELDS: [FieldDescriptor; 54] = [
    PATH_ID_FIELD,
    NLRI_PREFIX_FIELD,
    // MUP NLRI entry fields (`path_id` and `prefix` are already listed above).
    MUP_NLRI_FIELDS[FD_MUP_ARCH_TYPE].optional(),
    // BGP-MUP (U16), EVPN and MCAST-VPN (U8 widened to U16) Route Type; an
    // entry with an `architecture_type` is a MUP route, one with an
    // MCAST-VPN specific field an MCAST-VPN route.
    FieldDescriptor::new("route_type", "Route Type", FieldType::U16)
        .optional()
        .with_display_fn(|v, siblings| {
            let FieldValue::U16(t) = v else {
                return None;
            };
            let has = |name: &str| siblings.iter().any(|f| f.name() == name);
            if has("architecture_type") {
                mup_route_type_name(*t)
            } else if [
                "route_key",
                "source_as",
                "multicast_source_length",
                "originating_router_ip",
            ]
            .into_iter()
            .any(has)
            {
                u8::try_from(*t).ok().and_then(mcast_vpn_route_type_name)
            } else {
                u8::try_from(*t).ok().and_then(evpn_route_type_name)
            }
        }),
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
    MUP_NLRI_FIELDS[FD_MUP_RD],
    MUP_NLRI_FIELDS[FD_MUP_ADDRESS],
    MUP_NLRI_FIELDS[FD_MUP_TEID],
    MUP_NLRI_FIELDS[FD_MUP_QFI],
    MUP_NLRI_FIELDS[FD_MUP_ENDPOINT_ADDRESS],
    MUP_NLRI_FIELDS[FD_MUP_SOURCE_ADDRESS],
    MUP_NLRI_FIELDS[FD_MUP_TLVS],
    // Labeled NLRI fields (RFC 8277, Sections 2.2-2.4 —
    // https://www.rfc-editor.org/rfc/rfc8277#section-2.2); VPN NLRI also carry
    // `rd`, listed above (RFC 4364, Section 4.3.4 —
    // https://www.rfc-editor.org/rfc/rfc4364#section-4.3.4).
    FieldDescriptor::new("label_stack", "Label Stack", FieldType::Array)
        .optional()
        .with_children(&LABEL_ENTRY_FIELDS),
    FieldDescriptor::new("compatibility", "Compatibility", FieldType::U32).optional(),
    // EVPN NLRI fields (RFC 7432, Section 7 —
    // https://www.rfc-editor.org/rfc/rfc7432#section-7; RFC 9136, Section 3.1 —
    // https://www.rfc-editor.org/rfc/rfc9136#section-3.1); `path_id`,
    // `route_type`, `value`, `rd` and `prefix` are listed above.
    EVPN_NLRI_FIELDS[FD_EVPN_LENGTH],
    EVPN_NLRI_FIELDS[FD_EVPN_ESI],
    EVPN_NLRI_FIELDS[FD_EVPN_ETHERNET_TAG_ID],
    EVPN_NLRI_FIELDS[FD_EVPN_MAC_LENGTH],
    EVPN_NLRI_FIELDS[FD_EVPN_MAC],
    EVPN_NLRI_FIELDS[FD_EVPN_IP_LENGTH],
    EVPN_NLRI_FIELDS[FD_EVPN_IP_ADDRESS],
    EVPN_NLRI_FIELDS[FD_EVPN_GATEWAY_IP],
    EVPN_NLRI_FIELDS[FD_EVPN_MPLS_LABEL],
    EVPN_NLRI_FIELDS[FD_EVPN_MPLS_LABEL1],
    EVPN_NLRI_FIELDS[FD_EVPN_MPLS_LABEL2],
    EVPN_NLRI_FIELDS[FD_EVPN_VNI],
    EVPN_NLRI_FIELDS[FD_EVPN_VNI1],
    EVPN_NLRI_FIELDS[FD_EVPN_VNI2],
    // Flow Specification NLRI fields (RFC 8955, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc8955#section-4); `rd` and `value`
    // are listed above.
    FLOWSPEC_NLRI_FIELDS[FD_FS_NLRI_LENGTH],
    FLOWSPEC_NLRI_FIELDS[FD_FS_COMPONENTS],
    // Link-State NLRI fields (RFC 9552, Section 5.2 —
    // https://www.rfc-editor.org/rfc/rfc9552#section-5.2); `path_id`, `rd`
    // and `value` are listed above.
    BGP_LS_NLRI_FIELDS[FD_LS_NLRI_TYPE],
    BGP_LS_NLRI_FIELDS[FD_LS_TOTAL_NLRI_LENGTH],
    BGP_LS_NLRI_FIELDS[FD_LS_PROTOCOL_ID],
    BGP_LS_NLRI_FIELDS[FD_LS_IDENTIFIER],
    BGP_LS_NLRI_FIELDS[FD_LS_DESCRIPTORS],
    // Route Target membership NLRI fields (RFC 4684, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc4684#section-4); `path_id` is listed
    // above.
    RTC_NLRI_FIELDS[FD_RTC_PREFIX_LENGTH],
    RTC_NLRI_FIELDS[FD_RTC_ORIGIN_AS],
    RTC_NLRI_FIELDS[FD_RTC_ROUTE_TARGET],
    // SR Policy NLRI fields (RFC 9830, Section 2.1 —
    // https://www.rfc-editor.org/rfc/rfc9830#section-2.1); `path_id` is
    // listed above.
    SR_POLICY_NLRI_FIELDS[FD_SRP_NLRI_LENGTH],
    SR_POLICY_NLRI_FIELDS[FD_SRP_DISTINGUISHER],
    SR_POLICY_NLRI_FIELDS[FD_SRP_COLOR],
    SR_POLICY_NLRI_FIELDS[FD_SRP_ENDPOINT],
    // MCAST-VPN NLRI fields (RFC 6514, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc6514#section-4); `path_id`,
    // `route_type`, `length`, `value` and `rd` are listed above.
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_ROUTE_KEY],
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_SOURCE_AS],
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_SOURCE_LENGTH],
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_SOURCE],
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_GROUP_LENGTH],
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_GROUP],
    MCAST_VPN_NLRI_FIELDS[FD_MVPN_ORIGINATING_ROUTER_IP],
    // VPLS / BGP-AD NLRI fields (RFC 4761, Section 3.2.2 —
    // https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2; RFC 6074,
    // Section 3.2.2.1 — https://www.rfc-editor.org/rfc/rfc6074#section-3.2.2.1);
    // `path_id`, `nlri_length`, `rd` and `value` are listed above.
    VPLS_NLRI_FIELDS[FD_VPLS_VE_ID],
    VPLS_NLRI_FIELDS[FD_VPLS_VE_BLOCK_OFFSET],
    VPLS_NLRI_FIELDS[FD_VPLS_VE_BLOCK_SIZE],
    VPLS_NLRI_FIELDS[FD_VPLS_LABEL_BASE],
    VPLS_NLRI_FIELDS[FD_VPLS_PE_ADDRESS],
];

/// Slice form of [`NLRI_ENTRY_FIELDS`].
static NLRI_ENTRY_CHILDREN: &[FieldDescriptor] = &NLRI_ENTRY_FIELDS;

/// Field descriptor indices for [`EVPN_NLRI_FIELDS`].
const FD_EVPN_PATH_ID: usize = 0;
const FD_EVPN_ROUTE_TYPE: usize = 1;
const FD_EVPN_LENGTH: usize = 2;
const FD_EVPN_VALUE: usize = 3;
const FD_EVPN_RD: usize = 4;
const FD_EVPN_ESI: usize = 5;
const FD_EVPN_ETHERNET_TAG_ID: usize = 6;
const FD_EVPN_MAC_LENGTH: usize = 7;
const FD_EVPN_MAC: usize = 8;
const FD_EVPN_IP_LENGTH: usize = 9;
const FD_EVPN_IP_ADDRESS: usize = 10;
const FD_EVPN_GATEWAY_IP: usize = 11;
const FD_EVPN_MPLS_LABEL: usize = 12;
const FD_EVPN_MPLS_LABEL1: usize = 13;
const FD_EVPN_MPLS_LABEL2: usize = 14;
const FD_EVPN_VNI: usize = 15;
const FD_EVPN_VNI1: usize = 16;
const FD_EVPN_VNI2: usize = 17;

/// Child field descriptors of an EVPN NLRI entry.
///
/// `route_type` is a U16 like the BGP-MUP one it shares the NLRI entry union
/// with. The IP Prefix route's `prefix` is pushed with the address-family
/// specific `PREFIX_ENTRY_*` descriptors (see [`NLRI_PREFIX_FIELD`]).
///
/// RFC 7432, Section 7 — <https://www.rfc-editor.org/rfc/rfc7432#section-7>
/// RFC 9136, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9136#section-3.1>
/// RFC 8365, Section 5.1.3 — <https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3>
const EVPN_NLRI_FIELDS: [FieldDescriptor; 18] = [
    PATH_ID_FIELD,
    FieldDescriptor::new("route_type", "Route Type", FieldType::U16).with_display_fn(
        |v, _| match v {
            FieldValue::U16(t) => u8::try_from(*t).ok().and_then(evpn_route_type_name),
            _ => None,
        },
    ),
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
    MUP_NLRI_FIELDS[FD_MUP_RD],
    FieldDescriptor::new("esi", "Ethernet Segment Identifier", FieldType::Bytes)
        .optional()
        .with_format_fn(format_esi),
    FieldDescriptor::new("ethernet_tag_id", "Ethernet Tag ID", FieldType::U32).optional(),
    FieldDescriptor::new("mac_length", "MAC Address Length", FieldType::U8).optional(),
    FieldDescriptor::new("mac", "MAC Address", FieldType::MacAddr).optional(),
    FieldDescriptor::new("ip_length", "IP Address Length", FieldType::U8).optional(),
    FieldDescriptor::new("ip_address", "IP Address", FieldType::Any).optional(),
    FieldDescriptor::new("gateway_ip", "GW IP Address", FieldType::Any).optional(),
    FieldDescriptor::new("mpls_label", "MPLS Label", FieldType::U32).optional(),
    FieldDescriptor::new("mpls_label1", "MPLS Label1", FieldType::U32).optional(),
    FieldDescriptor::new("mpls_label2", "MPLS Label2", FieldType::U32).optional(),
    FieldDescriptor::new("vni", "VNI", FieldType::U32).optional(),
    FieldDescriptor::new("vni1", "VNI (MPLS Label1)", FieldType::U32).optional(),
    FieldDescriptor::new("vni2", "VNI (MPLS Label2)", FieldType::U32).optional(),
];

/// Object descriptor for EVPN NLRI entries.
static EVPN_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("evpn_route", "EVPN Route", FieldType::Object)
        .with_children(&EVPN_NLRI_FIELDS);

/// Field descriptor indices for [`FLOWSPEC_NLRI_FIELDS`].
const FD_FS_NLRI_LENGTH: usize = 0;
const FD_FS_RD: usize = 1;
const FD_FS_COMPONENTS: usize = 2;
const FD_FS_VALUE: usize = 3;
const FD_FS_PATH_ID: usize = 4;

/// Child field descriptors of a Flow Specification NLRI entry.
///
/// RFC 8955, Sections 4 and 8 — <https://www.rfc-editor.org/rfc/rfc8955#section-4>
const FLOWSPEC_NLRI_FIELDS: [FieldDescriptor; 5] = [
    FieldDescriptor::new("nlri_length", "NLRI Length", FieldType::U16).optional(),
    MUP_NLRI_FIELDS[FD_MUP_RD],
    FieldDescriptor::new("components", "Components", FieldType::Array)
        .optional()
        .with_children(&FLOWSPEC_COMPONENT_FIELDS),
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
    PATH_ID_FIELD,
];

/// Object descriptor for Flow Specification NLRI entries.
static FLOWSPEC_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("flowspec_rule", "Flow Specification", FieldType::Object)
        .with_children(&FLOWSPEC_NLRI_FIELDS);

/// Field descriptor indices for [`FLOWSPEC_COMPONENT_FIELDS`].
const FD_FSC_TYPE: usize = 0;
const FD_FSC_PREFIX_LENGTH: usize = 2;
const FD_FSC_PREFIX_OFFSET: usize = 3;
const FD_FSC_PATTERN: usize = 4;
const FD_FSC_OPERATORS: usize = 5;

/// Child field descriptors of a Flow Specification component.
///
/// `type` is named from the IPv4 registry column here; IPv6 rules push
/// [`FLOWSPEC_IPV6_COMPONENT_TYPE_FIELD`], so the serialized `type_name`
/// follows the rule's address family while the schema shows the IPv4 names.
/// `prefix` is pushed with the address-family specific `PREFIX_ENTRY_*`
/// descriptors.
///
/// RFC 8955, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.2>
/// RFC 8956, Section 3 — <https://www.rfc-editor.org/rfc/rfc8956#section-3>
const FLOWSPEC_COMPONENT_FIELDS: [FieldDescriptor; 6] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => flowspec_ipv4_component_name(*t),
        _ => None,
    }),
    NLRI_PREFIX_FIELD,
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("prefix_offset", "Prefix Offset", FieldType::U8).optional(),
    FieldDescriptor::new("pattern", "Pattern", FieldType::Bytes).optional(),
    FieldDescriptor::new("operators", "Operators", FieldType::Array)
        .optional()
        .with_children(&FLOWSPEC_OPERATOR_FIELDS),
];

/// `type` of an IPv6 Flow Specification component (RFC 8956, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc8956#section-3>).
static FLOWSPEC_IPV6_COMPONENT_TYPE_FIELD: FieldDescriptor =
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => flowspec_ipv6_component_name(*t),
        _ => None,
    });

/// Object descriptor for Flow Specification components.
static FLOWSPEC_COMPONENT_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("component", "Component", FieldType::Object)
        .with_children(&FLOWSPEC_COMPONENT_FIELDS);

/// Field descriptor indices for [`FLOWSPEC_OPERATOR_FIELDS`].
const FD_FSO_OPERATOR: usize = 0;
const FD_FSO_END_OF_LIST: usize = 1;
const FD_FSO_AND: usize = 2;
const FD_FSO_COMPARISON: usize = 3;
const FD_FSO_NOT: usize = 4;
const FD_FSO_MATCH: usize = 5;
const FD_FSO_VALUE: usize = 6;

/// Child field descriptors of a Flow Specification {operator, value} pair.
///
/// Numeric operators carry `comparison` (lt / gt / eq); bitmask operators
/// `not` and `match`.
///
/// RFC 8955, Section 4.2.1 — <https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1>
const FLOWSPEC_OPERATOR_FIELDS: [FieldDescriptor; 7] = [
    FieldDescriptor::new("operator", "Operator", FieldType::U8),
    FieldDescriptor::new("end_of_list", "End-of-List", FieldType::U8),
    FieldDescriptor::new("and", "AND", FieldType::U8),
    FieldDescriptor::new("comparison", "Comparison", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => flowspec_comparison_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("not", "NOT", FieldType::U8).optional(),
    FieldDescriptor::new("match", "Match", FieldType::U8).optional(),
    FieldDescriptor::new("value", "Value", FieldType::U64),
];

/// Object descriptor for Flow Specification {operator, value} pairs.
static FLOWSPEC_OPERATOR_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("operator", "Operator", FieldType::Object)
        .with_children(&FLOWSPEC_OPERATOR_FIELDS);

/// Field descriptor indices for [`BGP_LS_NLRI_FIELDS`].
const FD_LS_PATH_ID: usize = 0;
const FD_LS_NLRI_TYPE: usize = 1;
const FD_LS_TOTAL_NLRI_LENGTH: usize = 2;
const FD_LS_RD: usize = 3;
const FD_LS_PROTOCOL_ID: usize = 4;
const FD_LS_IDENTIFIER: usize = 5;
const FD_LS_DESCRIPTORS: usize = 6;
const FD_LS_VALUE: usize = 7;

/// Child field descriptors of a Link-State NLRI entry.
///
/// RFC 9552, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.2>
const BGP_LS_NLRI_FIELDS: [FieldDescriptor; 8] = [
    PATH_ID_FIELD,
    FieldDescriptor::new("nlri_type", "NLRI Type", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(t) => bgp_ls_nlri_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("total_nlri_length", "Total NLRI Length", FieldType::U16).optional(),
    MUP_NLRI_FIELDS[FD_MUP_RD],
    FieldDescriptor::new("protocol_id", "Protocol-ID", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(p) => bgp_ls_protocol_id_name(*p),
            _ => None,
        }),
    FieldDescriptor::new("identifier", "Identifier", FieldType::U64).optional(),
    FieldDescriptor::new("descriptors", "Descriptor TLVs", FieldType::Array)
        .optional()
        .with_children(&BGP_LS_DESCRIPTOR_FIELDS),
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
];

/// Object descriptor for Link-State NLRI entries.
static BGP_LS_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("link_state_nlri", "Link-State NLRI", FieldType::Object)
        .with_children(&BGP_LS_NLRI_FIELDS);

/// Field descriptor indices for [`RTC_NLRI_FIELDS`].
const FD_RTC_PATH_ID: usize = 0;
const FD_RTC_PREFIX_LENGTH: usize = 1;
const FD_RTC_ORIGIN_AS: usize = 2;
const FD_RTC_ROUTE_TARGET: usize = 3;

/// Child field descriptors of a Route Target membership NLRI entry.
///
/// RFC 4684, Section 4 — <https://www.rfc-editor.org/rfc/rfc4684#section-4>
const RTC_NLRI_FIELDS: [FieldDescriptor; 4] = [
    PATH_ID_FIELD,
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("origin_as", "Origin AS", FieldType::U32).optional(),
    FieldDescriptor::new("route_target", "Route Target", FieldType::Bytes).optional(),
];

/// Object descriptor for Route Target membership NLRI entries.
static RTC_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor = FieldDescriptor::new(
    "rt_membership_nlri",
    "Route Target Membership NLRI",
    FieldType::Object,
)
.with_children(&RTC_NLRI_FIELDS);

/// Field descriptor indices for [`SR_POLICY_NLRI_FIELDS`].
const FD_SRP_PATH_ID: usize = 0;
const FD_SRP_NLRI_LENGTH: usize = 1;
const FD_SRP_DISTINGUISHER: usize = 2;
const FD_SRP_COLOR: usize = 3;
const FD_SRP_ENDPOINT: usize = 4;

/// Child field descriptors of an SR Policy NLRI entry.
///
/// RFC 9830, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc9830#section-2.1>
const SR_POLICY_NLRI_FIELDS: [FieldDescriptor; 5] = [
    PATH_ID_FIELD,
    FieldDescriptor::new("nlri_length_bits", "NLRI Length (bits)", FieldType::U8).optional(),
    FieldDescriptor::new("distinguisher", "Distinguisher", FieldType::U32).optional(),
    FieldDescriptor::new("color", "Color", FieldType::U32).optional(),
    FieldDescriptor::new("endpoint", "Endpoint", FieldType::Any).optional(),
];

/// Object descriptor for SR Policy NLRI entries.
static SR_POLICY_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("sr_policy_nlri", "SR Policy NLRI", FieldType::Object)
        .with_children(&SR_POLICY_NLRI_FIELDS);

/// Field descriptor indices for [`MCAST_VPN_NLRI_FIELDS`].
const FD_MVPN_PATH_ID: usize = 0;
const FD_MVPN_ROUTE_TYPE: usize = 1;
const FD_MVPN_LENGTH: usize = 2;
const FD_MVPN_VALUE: usize = 3;
const FD_MVPN_RD: usize = 4;
const FD_MVPN_ROUTE_KEY: usize = 5;
const FD_MVPN_SOURCE_AS: usize = 6;
const FD_MVPN_SOURCE_LENGTH: usize = 7;
const FD_MVPN_SOURCE: usize = 8;
const FD_MVPN_GROUP_LENGTH: usize = 9;
const FD_MVPN_GROUP: usize = 10;
const FD_MVPN_ORIGINATING_ROUTER_IP: usize = 11;

/// Child field descriptors of an MCAST-VPN NLRI entry.
///
/// RFC 6514, Sections 4-4.6 — <https://www.rfc-editor.org/rfc/rfc6514#section-4>
const MCAST_VPN_NLRI_FIELDS: [FieldDescriptor; 12] = [
    PATH_ID_FIELD,
    FieldDescriptor::new("route_type", "Route Type", FieldType::U16).with_display_fn(
        |v, _| match v {
            FieldValue::U16(t) => u8::try_from(*t).ok().and_then(mcast_vpn_route_type_name),
            _ => None,
        },
    ),
    EVPN_NLRI_FIELDS[FD_EVPN_LENGTH],
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
    MUP_NLRI_FIELDS[FD_MUP_RD],
    FieldDescriptor::new("route_key", "Route Key", FieldType::Bytes).optional(),
    FieldDescriptor::new("source_as", "Source AS", FieldType::U32).optional(),
    FieldDescriptor::new(
        "multicast_source_length",
        "Multicast Source Length",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("multicast_source", "Multicast Source", FieldType::Any).optional(),
    FieldDescriptor::new(
        "multicast_group_length",
        "Multicast Group Length",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("multicast_group", "Multicast Group", FieldType::Any).optional(),
    FieldDescriptor::new(
        "originating_router_ip",
        "Originating Router's IP Address",
        FieldType::Any,
    )
    .optional(),
];

/// Object descriptor for MCAST-VPN NLRI entries.
static MCAST_VPN_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("mcast_vpn_nlri", "MCAST-VPN NLRI", FieldType::Object)
        .with_children(&MCAST_VPN_NLRI_FIELDS);

/// Field descriptor indices for [`VPLS_NLRI_FIELDS`].
const FD_VPLS_PATH_ID: usize = 0;
const FD_VPLS_NLRI_LENGTH: usize = 1;
const FD_VPLS_RD: usize = 2;
const FD_VPLS_VE_ID: usize = 3;
const FD_VPLS_VE_BLOCK_OFFSET: usize = 4;
const FD_VPLS_VE_BLOCK_SIZE: usize = 5;
const FD_VPLS_LABEL_BASE: usize = 6;
const FD_VPLS_PE_ADDRESS: usize = 7;
const FD_VPLS_VALUE: usize = 8;

/// Child field descriptors of a VPLS / BGP-AD NLRI entry; `nlri_length` is
/// in octets.
///
/// RFC 4761, Section 3.2.2 — <https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2>
/// RFC 6074, Section 3.2.2.1 — <https://www.rfc-editor.org/rfc/rfc6074#section-3.2.2.1>
const VPLS_NLRI_FIELDS: [FieldDescriptor; 9] = [
    PATH_ID_FIELD,
    FLOWSPEC_NLRI_FIELDS[FD_FS_NLRI_LENGTH],
    MUP_NLRI_FIELDS[FD_MUP_RD],
    FieldDescriptor::new("ve_id", "VE ID", FieldType::U16).optional(),
    FieldDescriptor::new("ve_block_offset", "VE Block Offset", FieldType::U16).optional(),
    FieldDescriptor::new("ve_block_size", "VE Block Size", FieldType::U16).optional(),
    FieldDescriptor::new("label_base", "Label Base", FieldType::U32).optional(),
    FieldDescriptor::new("pe_address", "PE Address", FieldType::Ipv4Addr).optional(),
    MUP_NLRI_FIELDS[FD_MUP_VALUE],
];

/// Object descriptor for VPLS / BGP-AD NLRI entries.
static VPLS_NLRI_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("vpls_nlri", "VPLS NLRI", FieldType::Object)
        .with_children(&VPLS_NLRI_FIELDS);

/// Field descriptor indices for [`BGP_LS_DESCRIPTOR_FIELDS`].
const FD_LSD_SUB_TLVS: usize = 2;
const FD_LSD_VALUE: usize = 3;

/// Child field descriptors of a Link-State NLRI descriptor TLV: Node
/// Descriptors TLVs carry `sub_tlvs`, the others a `value`.
///
/// RFC 9552, Sections 5.2.1-5.2.3 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.2.1>
const BGP_LS_DESCRIPTOR_FIELDS: [FieldDescriptor; 4] = [
    BGP_LS_TLV_FIELDS[0],
    BGP_LS_TLV_FIELDS[1],
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&BGP_LS_TLV_FIELDS),
    BGP_LS_TLV_FIELDS[2],
];

/// Object descriptor for Link-State NLRI descriptor TLVs.
static BGP_LS_DESCRIPTOR_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("descriptor", "Descriptor TLV", FieldType::Object)
        .with_children(&BGP_LS_DESCRIPTOR_FIELDS);

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

/// Field descriptor indices for [`EXT_COMMUNITY_CHILDREN`].
const FD_EC_TYPE: usize = 0;
const FD_EC_SUB_TYPE: usize = 1;
const FD_EC_GLOBAL_ADMIN: usize = 2;
const FD_EC_LOCAL_ADMIN: usize = 3;
const FD_EC_BANDWIDTH: usize = 4;
const FD_EC_RATE: usize = 5;
const FD_EC_COLOR_FLAGS: usize = 6;
const FD_EC_COLOR: usize = 7;
const FD_EC_ENCAP_TUNNEL_TYPE: usize = 8;
const FD_EC_OSPF_AREA: usize = 9;
const FD_EC_OSPF_ROUTE_TYPE: usize = 10;
const FD_EC_OSPF_OPTIONS: usize = 11;
const FD_EC_EVPN_FLAGS: usize = 12;
const FD_EC_SEQUENCE_NUMBER: usize = 13;
const FD_EC_ESI_LABEL: usize = 14;
const FD_EC_MAC: usize = 15;
const FD_EC_SAMPLE: usize = 16;
const FD_EC_TERMINAL_ACTION: usize = 17;
const FD_EC_DSCP: usize = 18;
const FD_EC_VALIDATION_STATE: usize = 19;
const FD_EC_VALUE: usize = 20;

/// Child field descriptors of an Extended Community object.
///
/// `type` / `sub_type` are always present; the other fields depend on the
/// (Type, Sub-Type) pair (see [`ext_community_sub_type`]), so they are
/// optional. `global_admin` is a U32 AS number, an IPv4 address or (for the
/// IPv6 Address Specific Extended Community) an IPv6 address.
///
/// RFC 4360, Section 2 — <https://www.rfc-editor.org/rfc/rfc4360#section-2>
/// RFC 7153 — <https://www.rfc-editor.org/rfc/rfc7153>
const EXT_COMMUNITY_FIELDS: [FieldDescriptor; 21] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => ext_community_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("sub_type", "Sub-Type", FieldType::U8).with_display_fn(
        |v, siblings| match (v, sibling_ext_type(siblings)) {
            (FieldValue::U8(s), Some(t)) => ext_community_sub_type_name(t, *s),
            _ => None,
        },
    ),
    FieldDescriptor::new("global_admin", "Global Administrator", FieldType::Any).optional(),
    FieldDescriptor::new("local_admin", "Local Administrator", FieldType::U32).optional(),
    // Link Bandwidth (RFC 10005, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc10005#section-2): bytes per second.
    FieldDescriptor::new("bandwidth", "Bandwidth", FieldType::Bytes)
        .optional()
        .with_format_fn(format_ieee754_f32),
    // traffic-rate-bytes / traffic-rate-packets (RFC 8955, Sections 7.1-7.2 —
    // https://www.rfc-editor.org/rfc/rfc8955#section-7.1).
    FieldDescriptor::new("rate", "Rate", FieldType::Bytes)
        .optional()
        .with_format_fn(format_ieee754_f32),
    // Color (RFC 9012, Section 4.3 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-4.3).
    FieldDescriptor::new("color_flags", "Color Flags", FieldType::U16).optional(),
    FieldDescriptor::new("color", "Color Value", FieldType::U32).optional(),
    // Encapsulation (RFC 9012, Section 4.1 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-4.1).
    FieldDescriptor::new("encap_tunnel_type", "Tunnel Type", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(t) => tunnel_type_name(*t),
            _ => None,
        }),
    // OSPF Route Type (RFC 4577, Section 4.2.6 —
    // https://www.rfc-editor.org/rfc/rfc4577#section-4.2.6).
    FieldDescriptor::new("ospf_area", "Area Number", FieldType::U32).optional(),
    FieldDescriptor::new("ospf_route_type", "OSPF Route Type", FieldType::U8).optional(),
    FieldDescriptor::new("ospf_options", "Options", FieldType::U8).optional(),
    // MAC Mobility / ESI Label / ES-Import RT / Router's MAC (RFC 7432,
    // Sections 7.5-7.7 — https://www.rfc-editor.org/rfc/rfc7432#section-7.5;
    // RFC 9135, Section 8.1 — https://www.rfc-editor.org/rfc/rfc9135#section-8.1).
    FieldDescriptor::new("evpn_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32).optional(),
    FieldDescriptor::new("esi_label", "ESI Label", FieldType::U32).optional(),
    FieldDescriptor::new("mac", "MAC Address", FieldType::MacAddr).optional(),
    // traffic-action / traffic-marking (RFC 8955, Sections 7.3 and 7.5 —
    // https://www.rfc-editor.org/rfc/rfc8955#section-7.3).
    FieldDescriptor::new("sample", "Sample", FieldType::U8).optional(),
    FieldDescriptor::new("terminal_action", "Terminal Action", FieldType::U8).optional(),
    FieldDescriptor::new("dscp", "DSCP", FieldType::U8).optional(),
    // BGP Origin Validation State (RFC 8097, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc8097#section-2).
    FieldDescriptor::new("validation_state", "Validation State", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(s) => origin_validation_state_name(*s),
            _ => None,
        }),
    // Value of a (Type, Sub-Type) that is not decoded.
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`EXT_COMMUNITY_FIELDS`].
static EXT_COMMUNITY_CHILDREN: &[FieldDescriptor] = &EXT_COMMUNITY_FIELDS;

/// Object descriptor for Extended Communities.
static EXT_COMMUNITY_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("ext_community", "Extended Community", FieldType::Object)
        .with_children(&EXT_COMMUNITY_FIELDS);

/// Child field descriptors of an IPv6 Address Specific Extended Community
/// object: `type` / `sub_type` named from the IPv6 registries, and the
/// `global_admin` / `local_admin` of [`EXT_COMMUNITY_FIELDS`].
///
/// RFC 5701, Section 2 — <https://www.rfc-editor.org/rfc/rfc5701#section-2>
const IPV6_EXT_COMMUNITY_FIELDS: [FieldDescriptor; 4] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => ipv6_ext_community_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("sub_type", "Sub-Type", FieldType::U8).with_display_fn(
        |v, siblings| match (v, sibling_ext_type(siblings)) {
            (FieldValue::U8(s), Some(t)) => ipv6_ext_community_sub_type_name(t, *s),
            _ => None,
        },
    ),
    EXT_COMMUNITY_FIELDS[FD_EC_GLOBAL_ADMIN],
    EXT_COMMUNITY_FIELDS[FD_EC_LOCAL_ADMIN],
];

/// Slice form of [`IPV6_EXT_COMMUNITY_FIELDS`].
static IPV6_EXT_COMMUNITY_CHILDREN: &[FieldDescriptor] = &IPV6_EXT_COMMUNITY_FIELDS;

/// Object descriptor for IPv6 Address Specific Extended Communities.
static IPV6_EXT_COMMUNITY_OBJECT_DESCRIPTOR: FieldDescriptor = FieldDescriptor::new(
    "ipv6_ext_community",
    "IPv6 Address Specific Extended Community",
    FieldType::Object,
)
.with_children(&IPV6_EXT_COMMUNITY_FIELDS);

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
const FD_MP_NLRI_RAW: usize = 6;
const FD_MP_WITHDRAWN_ROUTES_RAW: usize = 7;
const FD_MP_NEXT_HOP_RD: usize = 8;
const FD_MP_NEXT_HOP_LINK_LOCAL_RD: usize = 9;

/// Child field descriptors for MP_REACH_NLRI / MP_UNREACH_NLRI objects.
///
/// RFC 4760, Sections 3-4 — <https://www.rfc-editor.org/rfc/rfc4760#section-3>
const MP_FIELDS: [FieldDescriptor; 10] = [
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
        .with_children(NLRI_ENTRY_CHILDREN),
    FieldDescriptor::new("withdrawn_routes", "Withdrawn Routes", FieldType::Array)
        .optional()
        .with_children(NLRI_ENTRY_CHILDREN),
    // Raw NLRI / Withdrawn Routes of an (AFI, SAFI) whose encoding is not
    // decoded (e.g. SR Policy, BGP-LS), or the tail of a block that does not
    // parse.
    FieldDescriptor::new("nlri_raw", "NLRI (raw)", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "withdrawn_routes_raw",
        "Withdrawn Routes (raw)",
        FieldType::Bytes,
    )
    .optional(),
    // Route Distinguishers (always zero) of VPN next hops (RFC 4364,
    // Section 4.3.2 — https://www.rfc-editor.org/rfc/rfc4364#section-4.3.2;
    // RFC 4659, Section 3.2.1.1 —
    // https://www.rfc-editor.org/rfc/rfc4659#section-3.2.1.1).
    FieldDescriptor::new(
        "next_hop_rd",
        "Next Hop Route Distinguisher",
        FieldType::Bytes,
    )
    .optional()
    .with_format_fn(format_route_distinguisher),
    FieldDescriptor::new(
        "next_hop_link_local_rd",
        "Next Hop Link-Local Route Distinguisher",
        FieldType::Bytes,
    )
    .optional()
    .with_format_fn(format_route_distinguisher),
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
const FD_AS_LABEL_COUNT: usize = 7;
const FD_AS_ORFS: usize = 8;

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
    // Multiple Labels Capability Count (RFC 8277, Section 2.1 —
    // https://www.rfc-editor.org/rfc/rfc8277#section-2.1).
    FieldDescriptor::new("label_count", "Count", FieldType::U8).optional(),
    // Outbound Route Filtering Capability (RFC 5291, Section 5 —
    // https://www.rfc-editor.org/rfc/rfc5291#section-5).
    FieldDescriptor::new("orfs", "ORFs", FieldType::Array)
        .optional()
        .with_children(&ORF_CAP_FIELDS),
];

/// Child field descriptors of one (ORF Type, Send/Receive) pair of the
/// Outbound Route Filtering Capability.
///
/// RFC 5291, Section 5 — <https://www.rfc-editor.org/rfc/rfc5291#section-5>
const ORF_CAP_FIELDS: [FieldDescriptor; 2] = [
    ORF_TYPE_FIELD,
    FieldDescriptor::new("send_receive", "Send/Receive", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(sr) => orf_send_receive_name(*sr),
            _ => None,
        }
    }),
];

/// Object descriptor for the ORF Capability `orfs` elements.
static ORF_CAP_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("orf", "ORF", FieldType::Object).with_children(&ORF_CAP_FIELDS);

/// ORF Type field, named from the IANA registry (RFC 5291, Sections 4-5 —
/// <https://www.rfc-editor.org/rfc/rfc5291#section-4>).
const ORF_TYPE_FIELD: FieldDescriptor = FieldDescriptor::new("orf_type", "ORF Type", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(t) => orf_type_name(*t),
        _ => None,
    });

/// Field descriptor indices for [`ORF_FIELDS`].
const FD_ORF_TYPE: usize = 0;
const FD_ORF_LENGTH: usize = 1;
const FD_ORF_ENTRIES: usize = 2;
const FD_ORF_VALUE: usize = 3;

/// Child field descriptors of one ORF of a ROUTE-REFRESH message.
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>
const ORF_FIELDS: [FieldDescriptor; 4] = [
    ORF_TYPE_FIELD,
    FieldDescriptor::new("length", "Length of ORF entries", FieldType::U16),
    FieldDescriptor::new("entries", "ORF Entries", FieldType::Array)
        .optional()
        .with_children(&ORF_ENTRY_FIELDS),
    // Entries of an ORF type that is not decoded.
    FieldDescriptor::new("value", "ORF Entries (raw)", FieldType::Bytes).optional(),
];

/// Object descriptor for the ROUTE-REFRESH `orfs` elements.
static ORF_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("orf", "ORF", FieldType::Object).with_children(&ORF_FIELDS);

/// Field descriptor indices for [`ORF_ENTRY_FIELDS`].
const FD_ORFE_ACTION: usize = 0;
const FD_ORFE_MATCH: usize = 1;
const FD_ORFE_SEQUENCE: usize = 2;
const FD_ORFE_MINLEN: usize = 3;
const FD_ORFE_MAXLEN: usize = 4;
const FD_ORFE_PREFIX_RAW: usize = 5;

/// Child field descriptors of an Address Prefix ORF entry.
///
/// `prefix` is `[Length, Prefix...]`, formatted as a CIDR string for IPv4 /
/// IPv6 (the address-family specific `PREFIX_ENTRY_*` descriptors are pushed
/// at run time).
///
/// RFC 5291, Section 4 — <https://www.rfc-editor.org/rfc/rfc5291#section-4>
/// RFC 5292, Section 3 — <https://www.rfc-editor.org/rfc/rfc5292#section-3>
const ORF_ENTRY_FIELDS: [FieldDescriptor; 6] = [
    FieldDescriptor::new("action", "Action", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(a) => orf_action_name(*a),
        _ => None,
    }),
    FieldDescriptor::new("match", "Match", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(m) => orf_match_name(*m),
            _ => None,
        }),
    FieldDescriptor::new("sequence", "Sequence", FieldType::U32).optional(),
    FieldDescriptor::new("minlen", "Minlen", FieldType::U8).optional(),
    FieldDescriptor::new("maxlen", "Maxlen", FieldType::U8).optional(),
    FieldDescriptor::new("prefix", "Prefix", FieldType::Bytes).optional(),
];

/// Object descriptor for Address Prefix ORF entries.
static ORF_ENTRY_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("entry", "ORF Entry", FieldType::Object).with_children(&ORF_ENTRY_FIELDS);

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
const FD_OPT_BGPSEC_VERSION: usize = 13;
const FD_OPT_BGPSEC_DIRECTION: usize = 14;

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
    // BGPsec Capability (RFC 8205, Section 2.1 —
    // https://www.rfc-editor.org/rfc/rfc8205#section-2.1); its AFI is `afi`.
    FieldDescriptor::new("bgpsec_version", "BGPsec Version", FieldType::U8).optional(),
    FieldDescriptor::new("bgpsec_direction", "BGPsec Direction", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(d) => bgpsec_direction_name(*d),
            _ => None,
        }),
];

/// Field descriptor indices for [`PATH_ATTR_CHILDREN`].
const FD_PA_FLAGS: usize = 0;
const FD_PA_TYPE_CODE: usize = 1;
const FD_PA_ATTR_LENGTH: usize = 2;
const FD_PA_VALUE: usize = 3;
const FD_PA_AS_NUMBER_SIZE: usize = 4;

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
    PA_FLAGS_FIELD,
    PA_TYPE_CODE_FIELD,
    PA_ATTR_LENGTH_FIELD,
    PA_VALUE_FIELD.with_children(&PATH_ATTR_VALUE_FIELDS),
    PA_AS_NUMBER_SIZE_FIELD,
];

/// Schema of the path attributes nested in an ATTR_SET value (RFC 6368,
/// Section 5 — <https://www.rfc-editor.org/rfc/rfc6368#section-5>).
///
/// It mirrors [`PATH_ATTR_CHILDREN`], but its `value` union omits the
/// ATTR_SET-only `origin_as` / `path_attributes` so that the schema does not
/// recurse: a nested ATTR_SET is kept as raw bytes (see [`parse_attr_value`]).
/// At run time the nested attributes are pushed with the same descriptors as
/// the top-level ones, which have the same names and types.
const ATTR_SET_PATH_ATTR_FIELDS: [FieldDescriptor; 5] = [
    PA_FLAGS_FIELD,
    PA_TYPE_CODE_FIELD,
    PA_ATTR_LENGTH_FIELD,
    PA_VALUE_FIELD.with_children(&PATH_ATTR_VALUE_BASE_FIELDS),
    PA_AS_NUMBER_SIZE_FIELD,
];

/// Path attribute `flags` (RFC 4271, Section 4.3).
const PA_FLAGS_FIELD: FieldDescriptor = FieldDescriptor::new("flags", "Flags", FieldType::U8);

/// Path attribute `type_code` (RFC 4271, Section 4.3).
const PA_TYPE_CODE_FIELD: FieldDescriptor =
    FieldDescriptor::new("type_code", "Type Code", FieldType::U8).with_display_fn(
        |v, _siblings| match v {
            FieldValue::U8(t) => path_attr_type_name(*t),
            _ => None,
        },
    );

/// Path attribute `attr_length` (RFC 4271, Section 4.3).
const PA_ATTR_LENGTH_FIELD: FieldDescriptor =
    FieldDescriptor::new("attr_length", "Attribute Length", FieldType::U16);

/// Path attribute `value`, before its union `children` are attached.
const PA_VALUE_FIELD: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Any).optional();

/// AS_PATH only: the AS number size (2 or 4 octets) inferred from the
/// structure of the value, since the RFC 6793 capability exchange is not
/// visible to a stateless dissector (RFC 6793, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc6793#section-4.1>).
const PA_AS_NUMBER_SIZE_FIELD: FieldDescriptor =
    FieldDescriptor::new("as_number_size", "AS Number Size", FieldType::U8).optional();

/// Concatenates two descriptor arrays in a `const` context.
const fn concat_fields<const A: usize, const B: usize, const N: usize>(
    a: [FieldDescriptor; A],
    b: [FieldDescriptor; B],
) -> [FieldDescriptor; N] {
    assert!(A > 0 && A + B == N);
    let mut out = [a[0]; N];
    let mut i = 0;
    while i < A {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < B {
        out[A + j] = b[j];
        j += 1;
    }
    out
}

/// Field descriptor indices for the entries of [`PATH_ATTR_VALUE_BASE_FIELDS`]
/// that are pushed directly into a path attribute `value` object.
const FD_PAV_PMSI_FLAGS: usize = 20;
const FD_PAV_TUNNEL_TYPE: usize = 21;
const FD_PAV_MPLS_LABEL: usize = 22;
const FD_PAV_VNI: usize = 23;
const FD_PAV_TUNNEL_ENDPOINT: usize = 24;
const FD_PAV_TUNNEL_IDENTIFIER: usize = 25;
const FD_PAV_TUNNELS: usize = 26;
const FD_PAV_TLVS: usize = 27;
const FD_PAV_SECURE_PATH_LENGTH: usize = 28;
const FD_PAV_SECURE_PATH: usize = 29;
const FD_PAV_SIGNATURE_BLOCKS: usize = 30;
const FD_PAV_BFD_MODE: usize = 31;
const FD_PAV_BFD_DISCRIMINATOR: usize = 32;
const FD_PAV_OPTIONAL_TLVS: usize = 33;
/// Field descriptor indices of the ATTR_SET entries of
/// [`PATH_ATTR_VALUE_FIELDS`].
const FD_PAV_ORIGIN_AS: usize = 53;
const FD_PAV_PATH_ATTRIBUTES: usize = 54;

/// Union of every field that can appear inside a structured path attribute
/// `value`, except the ATTR_SET ones (see [`PATH_ATTR_VALUE_FIELDS`]).
///
/// A path attribute `value` is [`FieldType::Any`]: its runtime shape is selected
/// by the sibling `type_code`. It is an Object for MP_REACH_NLRI /
/// MP_UNREACH_NLRI (RFC 4760), PMSI_TUNNEL (RFC 6514), Tunnel Encapsulation
/// (RFC 9012), BGP-LS Attribute (RFC 9552), BGPsec_Path (RFC 8205), ATTR_SET
/// (RFC 6368) and BFD Discriminator (RFC 9026); an Array of TLV objects for
/// BGP Prefix-SID (RFC 8669 / RFC 9252), AIGP (RFC 7311) and the SFP
/// attribute (RFC 9015); an Array of segment objects for AS_PATH / AS4_PATH
/// (RFC 4271, Section 5.1.2); an Array of scalars for COMMUNITIES /
/// CLUSTER_LIST / LARGE_COMMUNITY; an Array of objects for EXTENDED
/// COMMUNITIES (RFC 4360) and IPv6 Address Specific Extended Community
/// (RFC 5701); a scalar for ORIGIN /
/// MULTI_EXIT_DISC / LOCAL_PREF / OTC (RFC 9234); an IPv4 address for
/// NEXT_HOP / ORIGINATOR_ID; and raw bytes for unknown or malformed
/// attributes.
///
/// This list is the union of the sub-fields of every *object* shape, so that a
/// schema walker can discover them. Every entry is optional because none of them
/// is present for all `type_code` values. Names are unique: where two shapes
/// would clash on a name with a different type or children, one of them is
/// wrapped (`tunnels`, `tlvs`) or prefixed (`pmsi_flags`).
const PATH_ATTR_VALUE_BASE_FIELDS: [FieldDescriptor; 53] = [
    // MP_REACH_NLRI / MP_UNREACH_NLRI object fields (RFC 4760).
    MP_FIELDS[FD_MP_AFI].optional(),
    MP_FIELDS[FD_MP_SAFI].optional(),
    MP_FIELDS[FD_MP_NEXT_HOP],
    MP_FIELDS[FD_MP_NEXT_HOP_LINK_LOCAL],
    MP_FIELDS[FD_MP_NLRI],
    MP_FIELDS[FD_MP_WITHDRAWN_ROUTES],
    MP_FIELDS[FD_MP_NLRI_RAW],
    MP_FIELDS[FD_MP_WITHDRAWN_ROUTES_RAW],
    MP_FIELDS[FD_MP_NEXT_HOP_RD],
    MP_FIELDS[FD_MP_NEXT_HOP_LINK_LOCAL_RD],
    // BGP Prefix-SID TLV element fields (RFC 8669, RFC 9252); the SFP
    // attribute TLVs (RFC 9015, Section 3.2.1 —
    // https://www.rfc-editor.org/rfc/rfc9015#section-3.2.1) and AIGP TLVs
    // (RFC 7311, Section 3 — https://www.rfc-editor.org/rfc/rfc7311#section-3)
    // share `type`, `length` and `value`.
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
    // AIGP TLV (RFC 7311, Section 3 —
    // https://www.rfc-editor.org/rfc/rfc7311#section-3).
    AIGP_TLV_FIELDS[FD_AIGP_METRIC],
    // PMSI_TUNNEL (RFC 6514, Section 5 —
    // https://www.rfc-editor.org/rfc/rfc6514#section-5).
    FieldDescriptor::new("pmsi_flags", "PMSI Tunnel Flags", FieldType::U8).optional(),
    FieldDescriptor::new("tunnel_type", "Tunnel Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => pmsi_tunnel_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("mpls_label", "MPLS Label", FieldType::U32).optional(),
    // The MPLS Label field carries a 24-bit VNI with a VXLAN / NVGRE /
    // VXLAN-GPE encapsulation (RFC 8365, Section 5.1.3 —
    // https://www.rfc-editor.org/rfc/rfc8365#section-5.1.3).
    FieldDescriptor::new("vni", "VNI", FieldType::U32).optional(),
    FieldDescriptor::new("tunnel_endpoint", "Tunnel Endpoint", FieldType::Any).optional(),
    FieldDescriptor::new("tunnel_identifier", "Tunnel Identifier", FieldType::Bytes).optional(),
    // Tunnel Encapsulation (RFC 9012, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-2).
    FieldDescriptor::new("tunnels", "Tunnel TLVs", FieldType::Array)
        .optional()
        .with_children(&TUNNEL_TLV_FIELDS),
    // BGP-LS Attribute (RFC 9552, Section 5.3 —
    // https://www.rfc-editor.org/rfc/rfc9552#section-5.3).
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(&BGP_LS_TLV_FIELDS),
    // BGPsec_Path (RFC 8205, Section 3 —
    // https://www.rfc-editor.org/rfc/rfc8205#section-3).
    FieldDescriptor::new("secure_path_length", "Secure_Path Length", FieldType::U16).optional(),
    FieldDescriptor::new("secure_path", "Secure_Path", FieldType::Array)
        .optional()
        .with_children(&BGPSEC_SEGMENT_FIELDS),
    FieldDescriptor::new("signature_blocks", "Signature_Blocks", FieldType::Array)
        .optional()
        .with_children(&BGPSEC_BLOCK_FIELDS),
    // BFD Discriminator (RFC 9026, Section 3.1.6 —
    // https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6).
    FieldDescriptor::new("bfd_mode", "BFD Mode", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(m) => bfd_mode_name(*m),
            _ => None,
        }),
    FieldDescriptor::new("bfd_discriminator", "BFD Discriminator", FieldType::U32).optional(),
    FieldDescriptor::new("optional_tlvs", "Optional TLVs", FieldType::Array)
        .optional()
        .with_children(&BFD_TLV_FIELDS),
    // Extended Community / IPv6 Address Specific Extended Community element
    // fields (RFC 4360, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc4360#section-2; RFC 5701, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc5701#section-2); they share `type` and
    // `value` with the TLVs above.
    EXT_COMMUNITY_FIELDS[FD_EC_SUB_TYPE].optional(),
    EXT_COMMUNITY_FIELDS[FD_EC_GLOBAL_ADMIN],
    EXT_COMMUNITY_FIELDS[FD_EC_LOCAL_ADMIN],
    EXT_COMMUNITY_FIELDS[FD_EC_BANDWIDTH],
    EXT_COMMUNITY_FIELDS[FD_EC_RATE],
    EXT_COMMUNITY_FIELDS[FD_EC_COLOR_FLAGS],
    EXT_COMMUNITY_FIELDS[FD_EC_COLOR],
    EXT_COMMUNITY_FIELDS[FD_EC_ENCAP_TUNNEL_TYPE],
    EXT_COMMUNITY_FIELDS[FD_EC_OSPF_AREA],
    EXT_COMMUNITY_FIELDS[FD_EC_OSPF_ROUTE_TYPE],
    EXT_COMMUNITY_FIELDS[FD_EC_OSPF_OPTIONS],
    EXT_COMMUNITY_FIELDS[FD_EC_EVPN_FLAGS],
    EXT_COMMUNITY_FIELDS[FD_EC_SEQUENCE_NUMBER],
    EXT_COMMUNITY_FIELDS[FD_EC_ESI_LABEL],
    EXT_COMMUNITY_FIELDS[FD_EC_MAC],
    EXT_COMMUNITY_FIELDS[FD_EC_SAMPLE],
    EXT_COMMUNITY_FIELDS[FD_EC_TERMINAL_ACTION],
    EXT_COMMUNITY_FIELDS[FD_EC_DSCP],
    EXT_COMMUNITY_FIELDS[FD_EC_VALIDATION_STATE],
];

/// Union of every field that can appear inside a structured path attribute
/// `value`: [`PATH_ATTR_VALUE_BASE_FIELDS`] plus the ATTR_SET fields (RFC 6368,
/// Section 5 — <https://www.rfc-editor.org/rfc/rfc6368#section-5>).
const PATH_ATTR_VALUE_FIELDS: [FieldDescriptor; 55] = concat_fields(
    PATH_ATTR_VALUE_BASE_FIELDS,
    [
        FieldDescriptor::new("origin_as", "Origin AS", FieldType::U32).optional(),
        FieldDescriptor::new("path_attributes", "Path Attributes", FieldType::Array)
            .optional()
            .with_children(&ATTR_SET_PATH_ATTR_FIELDS),
    ],
);

/// Slice form of [`PATH_ATTR_VALUE_FIELDS`].
static PATH_ATTR_VALUE_CHILDREN: &[FieldDescriptor] = &PATH_ATTR_VALUE_FIELDS;

/// Field descriptor indices for [`AIGP_TLV_CHILDREN`].
const FD_AIGP_METRIC: usize = 2;
const FD_AIGP_VALUE: usize = 3;

/// Child field descriptors of an AIGP TLV.
///
/// RFC 7311, Section 3 — <https://www.rfc-editor.org/rfc/rfc7311#section-3>
const AIGP_TLV_FIELDS: [FieldDescriptor; 4] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => aigp_tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("metric", "Accumulated IGP Metric", FieldType::U64).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`AIGP_TLV_FIELDS`].
static AIGP_TLV_CHILDREN: &[FieldDescriptor] = &AIGP_TLV_FIELDS;

/// Object descriptor for AIGP TLVs.
static AIGP_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(&AIGP_TLV_FIELDS);

/// Field descriptor index for [`TUNNEL_TLV_CHILDREN`].
const FD_TUN_SUB_TLVS: usize = 2;

/// Child field descriptors of a Tunnel Encapsulation TLV.
///
/// RFC 9012, Section 2 — <https://www.rfc-editor.org/rfc/rfc9012#section-2>
const TUNNEL_TLV_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("tunnel_type", "Tunnel Type", FieldType::U16).with_display_fn(|v, _| {
        match v {
            FieldValue::U16(t) => tunnel_type_name(*t),
            _ => None,
        }
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array)
        .with_children(&TUNNEL_SUB_TLV_FIELDS),
];

/// Slice form of [`TUNNEL_TLV_FIELDS`].
static TUNNEL_TLV_CHILDREN: &[FieldDescriptor] = &TUNNEL_TLV_FIELDS;

/// Object descriptor for Tunnel Encapsulation TLVs.
static TUNNEL_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tunnel", "Tunnel TLV", FieldType::Object)
        .with_children(&TUNNEL_TLV_FIELDS);

/// Field descriptor indices for [`TUNNEL_SUB_TLV_CHILDREN`].
const FD_TSUB_ADDRESS_FAMILY: usize = 2;
const FD_TSUB_ADDRESS: usize = 3;
const FD_TSUB_FLAGS: usize = 4;
const FD_TSUB_COLOR: usize = 5;
const FD_TSUB_UDP_PORT: usize = 6;
const FD_TSUB_PROTOCOL_TYPE: usize = 7;
const FD_TSUB_VALUE: usize = 8;

/// Child field descriptors of a Tunnel Encapsulation sub-TLV.
///
/// The Sub-TLV Length is exposed as a U16 whether it is encoded in 1 or 2
/// octets.
///
/// RFC 9012, Sections 2 and 3 — <https://www.rfc-editor.org/rfc/rfc9012#section-3>
const TUNNEL_SUB_TLV_FIELDS: [FieldDescriptor; 9] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => tunnel_sub_tlv_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    // Tunnel Egress Endpoint (RFC 9012, Section 3.1 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-3.1).
    FieldDescriptor::new("address_family", "Address Family", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(a) => afi_name(*a),
            _ => None,
        }),
    FieldDescriptor::new("address", "Address", FieldType::Any).optional(),
    // Color (RFC 9012, Sections 3.4.2 and 4.3 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-4.3).
    FieldDescriptor::new("flags", "Flags", FieldType::U16).optional(),
    FieldDescriptor::new("color", "Color Value", FieldType::U32).optional(),
    // UDP Destination Port (RFC 9012, Section 3.3.2 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-3.3.2).
    FieldDescriptor::new("udp_port", "UDP Destination Port", FieldType::U16).optional(),
    // Protocol Type (RFC 9012, Section 3.4.1 —
    // https://www.rfc-editor.org/rfc/rfc9012#section-3.4.1).
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U16).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`TUNNEL_SUB_TLV_FIELDS`].
static TUNNEL_SUB_TLV_CHILDREN: &[FieldDescriptor] = &TUNNEL_SUB_TLV_FIELDS;

/// Object descriptor for Tunnel Encapsulation sub-TLVs.
static TUNNEL_SUB_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("sub_tlv", "Sub-TLV", FieldType::Object)
        .with_children(&TUNNEL_SUB_TLV_FIELDS);

/// Child field descriptors of a BGP-LS Attribute TLV.
///
/// RFC 9552, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9552#section-5.1>
const BGP_LS_TLV_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("type", "Type", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => bgp_ls_tlv_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`BGP_LS_TLV_FIELDS`].
static BGP_LS_TLV_CHILDREN: &[FieldDescriptor] = &BGP_LS_TLV_FIELDS;

/// Object descriptor for BGP-LS Attribute TLVs.
static BGP_LS_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(&BGP_LS_TLV_FIELDS);

/// Child field descriptors of an SFP attribute TLV.
///
/// RFC 9015, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc9015#section-3.2.1>
const SFP_TLV_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => sfp_tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`SFP_TLV_FIELDS`].
static SFP_TLV_CHILDREN: &[FieldDescriptor] = &SFP_TLV_FIELDS;

/// Object descriptor for SFP attribute TLVs.
static SFP_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(&SFP_TLV_FIELDS);

/// Field descriptor indices for [`BGPSEC_SEGMENT_CHILDREN`].
const FD_BSEG_PCOUNT: usize = 0;
const FD_BSEG_FLAGS: usize = 1;
const FD_BSEG_ASN: usize = 2;

/// Child field descriptors of a BGPsec Secure_Path Segment.
///
/// RFC 8205, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc8205#section-3.1>
const BGPSEC_SEGMENT_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("pcount", "pCount", FieldType::U8),
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("asn", "AS Number", FieldType::U32),
];

/// Slice form of [`BGPSEC_SEGMENT_FIELDS`].
static BGPSEC_SEGMENT_CHILDREN: &[FieldDescriptor] = &BGPSEC_SEGMENT_FIELDS;

/// Object descriptor for BGPsec Secure_Path Segments.
static BGPSEC_SEGMENT_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("segment", "Secure_Path Segment", FieldType::Object)
        .with_children(&BGPSEC_SEGMENT_FIELDS);

/// Field descriptor indices for [`BGPSEC_BLOCK_CHILDREN`].
const FD_BBLK_LENGTH: usize = 0;
const FD_BBLK_ALGORITHM_SUITE: usize = 1;
const FD_BBLK_SIGNATURE_SEGMENTS: usize = 2;

/// Child field descriptors of a BGPsec Signature_Block.
///
/// RFC 8205, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8205#section-3.2>
const BGPSEC_BLOCK_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("length", "Signature_Block Length", FieldType::U16),
    FieldDescriptor::new(
        "algorithm_suite",
        "Algorithm Suite Identifier",
        FieldType::U8,
    ),
    FieldDescriptor::new("signature_segments", "Signature Segments", FieldType::Array)
        .with_children(&BGPSEC_SIGNATURE_FIELDS),
];

/// Slice form of [`BGPSEC_BLOCK_FIELDS`].
static BGPSEC_BLOCK_CHILDREN: &[FieldDescriptor] = &BGPSEC_BLOCK_FIELDS;

/// Object descriptor for BGPsec Signature_Blocks.
static BGPSEC_BLOCK_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("signature_block", "Signature_Block", FieldType::Object)
        .with_children(&BGPSEC_BLOCK_FIELDS);

/// Field descriptor indices for [`BGPSEC_SIGNATURE_CHILDREN`].
const FD_BSIG_SKI: usize = 0;
const FD_BSIG_SIGNATURE_LENGTH: usize = 1;
const FD_BSIG_SIGNATURE: usize = 2;

/// Child field descriptors of a BGPsec Signature Segment.
///
/// RFC 8205, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc8205#section-3.2>
const BGPSEC_SIGNATURE_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("ski", "Subject Key Identifier", FieldType::Bytes),
    FieldDescriptor::new("signature_length", "Signature Length", FieldType::U16),
    FieldDescriptor::new("signature", "Signature", FieldType::Bytes).optional(),
];

/// Slice form of [`BGPSEC_SIGNATURE_FIELDS`].
static BGPSEC_SIGNATURE_CHILDREN: &[FieldDescriptor] = &BGPSEC_SIGNATURE_FIELDS;

/// Object descriptor for BGPsec Signature Segments.
static BGPSEC_SIGNATURE_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("signature_segment", "Signature Segment", FieldType::Object)
        .with_children(&BGPSEC_SIGNATURE_FIELDS);

/// Field descriptor indices for [`BFD_TLV_CHILDREN`].
const FD_BFDT_SOURCE_ADDRESS: usize = 2;
const FD_BFDT_VALUE: usize = 3;

/// Child field descriptors of a BFD Discriminator Optional TLV.
///
/// RFC 9026, Section 3.1.6 — <https://www.rfc-editor.org/rfc/rfc9026#section-3.1.6>
const BFD_TLV_FIELDS: [FieldDescriptor; 4] = [
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => bfd_optional_tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("source_address", "Source IP Address", FieldType::Any).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Slice form of [`BFD_TLV_FIELDS`].
static BFD_TLV_CHILDREN: &[FieldDescriptor] = &BFD_TLV_FIELDS;

/// Object descriptor for BFD Discriminator Optional TLVs.
static BFD_TLV_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(&BFD_TLV_FIELDS);

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
// ROUTE-REFRESH fields (RFC 2918, RFC 7313). `FD_AFI`/`FD_SAFI` are reused at
// the UPDATE layer top level to mirror the first MP_REACH_NLRI /
// MP_UNREACH_NLRI attribute's address family (RFC 4760, Sections 3/4) — see
// `parse_update`.
const FD_AFI: usize = 13;
const FD_SAFI: usize = 14;
const FD_MESSAGE_SUBTYPE: usize = 15;
// UPDATE fields (RFC 4271, Section 4.3)
const FD_WITHDRAWN_ROUTES_LENGTH: usize = 16;
const FD_WITHDRAWN_ROUTES: usize = 17;
const FD_TOTAL_PATH_ATTRIBUTE_LENGTH: usize = 18;
const FD_PATH_ATTRIBUTES: usize = 19;
const FD_NLRI: usize = 20;
// NOTIFICATION data (RFC 9003 — https://www.rfc-editor.org/rfc/rfc9003;
// RFC 8538 — https://www.rfc-editor.org/rfc/rfc8538) and ROUTE-REFRESH ORFs
// (RFC 5291 — https://www.rfc-editor.org/rfc/rfc5291)
const FD_SHUTDOWN_COMMUNICATION_LENGTH: usize = 21;
const FD_SHUTDOWN_COMMUNICATION: usize = 22;
const FD_HARD_RESET: usize = 23;
const FD_WHEN_TO_REFRESH: usize = 24;
const FD_ORFS: usize = 25;

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
    ERROR_CODE_FIELD,
    ERROR_SUBCODE_FIELD,
    // NOTIFICATION Data; for ROUTE-REFRESH, KEEPALIVE and unknown message
    // types, the octets that are not otherwise decoded.
    DATA_FIELD,
    // Top-level `afi`/`safi`:
    // - ROUTE-REFRESH (RFC 2918, Section 3) — decoded directly from the
    //   message body.
    // - UPDATE (RFC 4271, Section 4.3) — mirrors the AFI/SAFI of the first
    //   MP_REACH_NLRI (RFC 4760, Section 3 —
    //   <https://www.rfc-editor.org/rfc/rfc4760#section-3>) or
    //   MP_UNREACH_NLRI (RFC 4760, Section 4 —
    //   <https://www.rfc-editor.org/rfc/rfc4760#section-4>) path attribute, in
    //   attribute order, so a consumer can filter on address family without
    //   reaching into `path_attributes`. Absent for a plain IPv4 unicast
    //   UPDATE, which carries no MP attribute — only what is on the wire is
    //   decoded, IPv4 unicast is never synthesised.
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
        .with_children(NLRI_ENTRY_CHILDREN),
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
        .with_children(NLRI_ENTRY_CHILDREN),
    // NOTIFICATION Shutdown Communication (RFC 9003, Section 2 —
    // https://www.rfc-editor.org/rfc/rfc9003#section-2).
    SHUTDOWN_COMMUNICATION_LENGTH_FIELD,
    SHUTDOWN_COMMUNICATION_FIELD,
    // NOTIFICATION Hard Reset (RFC 8538, Section 3.1 —
    // https://www.rfc-editor.org/rfc/rfc8538#section-3.1).
    FieldDescriptor::new("hard_reset", "Hard Reset", FieldType::Object)
        .optional()
        .with_children(&HARD_RESET_FIELDS),
    // ROUTE-REFRESH ORFs (RFC 5291, Section 4 —
    // https://www.rfc-editor.org/rfc/rfc5291#section-4).
    FieldDescriptor::new("when_to_refresh", "When-to-refresh", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(w) => when_to_refresh_name(*w),
            _ => None,
        }),
    FieldDescriptor::new("orfs", "ORFs", FieldType::Array)
        .optional()
        .with_children(&ORF_FIELDS),
];

/// NOTIFICATION Error Code (RFC 4271, Section 4.5 —
/// <https://www.rfc-editor.org/rfc/rfc4271#section-4.5>).
const ERROR_CODE_FIELD: FieldDescriptor =
    FieldDescriptor::new("error_code", "Error Code", FieldType::U8)
        .optional()
        .with_display_fn(|v, _siblings| match v {
            FieldValue::U8(c) => error_code_name(*c),
            _ => None,
        });

/// NOTIFICATION Error Subcode, named for the sibling `error_code` (IANA BGP
/// Error Subcodes —
/// <https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-5>).
const ERROR_SUBCODE_FIELD: FieldDescriptor =
    FieldDescriptor::new("error_subcode", "Error Subcode", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| {
            let FieldValue::U8(subcode) = v else {
                return None;
            };
            let error_code = siblings
                .iter()
                .find(|f| f.name() == "error_code")
                .and_then(|f| f.value.as_u8())?;
            error_subcode_name(error_code, *subcode)
        });

/// NOTIFICATION Data (RFC 4271, Section 4.5 —
/// <https://www.rfc-editor.org/rfc/rfc4271#section-4.5>).
const DATA_FIELD: FieldDescriptor =
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional();

/// Shutdown Communication Length (RFC 9003, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc9003#section-2>).
const SHUTDOWN_COMMUNICATION_LENGTH_FIELD: FieldDescriptor = FieldDescriptor::new(
    "shutdown_communication_length",
    "Shutdown Communication Length",
    FieldType::U8,
)
.optional();

/// Shutdown Communication text (RFC 9003, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc9003#section-2>).
const SHUTDOWN_COMMUNICATION_FIELD: FieldDescriptor = FieldDescriptor::new(
    "shutdown_communication",
    "Shutdown Communication",
    FieldType::Str,
)
.optional();

/// Child field descriptors of the `hard_reset` object: the encapsulated
/// Error Code, Subcode and Data (RFC 8538, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc8538#section-3.1>).
const HARD_RESET_FIELDS: [FieldDescriptor; 5] = [
    ERROR_CODE_FIELD,
    ERROR_SUBCODE_FIELD,
    DATA_FIELD,
    SHUTDOWN_COMMUNICATION_LENGTH_FIELD,
    SHUTDOWN_COMMUNICATION_FIELD,
];

/// Parses a single BGP message from the start of `data` and appends one layer.
/// Returns the number of bytes consumed.
///
/// RFC 4271, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc4271#section-4.1>
fn dissect_one_message<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    as_size: Option<AsNumberSize>,
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
        MSG_UPDATE => parse_update(buf, msg_data, offset, as_size)?,
        MSG_NOTIFICATION => parse_notification(buf, msg_data, offset)?,
        MSG_ROUTE_REFRESH => parse_route_refresh(buf, msg_data, offset)?,
        // KEEPALIVE is only the header (RFC 4271, Section 4.4 —
        // https://www.rfc-editor.org/rfc/rfc4271#section-4.4), and an
        // unrecognized Type is a "Bad Message Type" error (RFC 4271,
        // Section 6.1 — https://www.rfc-editor.org/rfc/rfc4271#section-6.1):
        // any octets after the header are kept as `data`.
        _ => {
            if msg_len > HEADER_SIZE {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DATA],
                    FieldValue::Bytes(&msg_data[HEADER_SIZE..]),
                    offset + HEADER_SIZE..offset + msg_len,
                );
            }
        }
    }

    buf.end_layer();

    Ok(consumed)
}

/// Specification references for the BGP-4 dissector.
///
/// Mirrors the `## References` list in this crate's module documentation.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 4271",
        "A Border Gateway Protocol 4 (BGP-4)",
        "https://www.rfc-editor.org/rfc/rfc4271",
    ),
    SpecReference::new(
        "RFC 1997",
        "BGP Communities Attribute",
        "https://www.rfc-editor.org/rfc/rfc1997",
    ),
    SpecReference::new(
        "RFC 2545",
        "Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing",
        "https://www.rfc-editor.org/rfc/rfc2545",
    ),
    SpecReference::new(
        "RFC 2918",
        "Route Refresh Capability for BGP-4",
        "https://www.rfc-editor.org/rfc/rfc2918",
    ),
    SpecReference::new(
        "RFC 4360",
        "BGP Extended Communities Attribute",
        "https://www.rfc-editor.org/rfc/rfc4360",
    ),
    SpecReference::new(
        "RFC 4577",
        "OSPF as the Provider/Customer Edge Protocol for BGP/MPLS IP Virtual Private Networks (VPNs)",
        "https://www.rfc-editor.org/rfc/rfc4577",
    ),
    SpecReference::new(
        "RFC 5668",
        "4-Octet AS Specific BGP Extended Community",
        "https://www.rfc-editor.org/rfc/rfc5668",
    ),
    SpecReference::new(
        "RFC 5701",
        "IPv6 Address Specific BGP Extended Community Attribute",
        "https://www.rfc-editor.org/rfc/rfc5701",
    ),
    SpecReference::new(
        "RFC 7153",
        "IANA Registries for BGP Extended Communities",
        "https://www.rfc-editor.org/rfc/rfc7153",
    ),
    SpecReference::new(
        "RFC 7432",
        "BGP MPLS-Based Ethernet VPN",
        "https://www.rfc-editor.org/rfc/rfc7432",
    ),
    SpecReference::new(
        "RFC 8097",
        "BGP Prefix Origin Validation State Extended Community",
        "https://www.rfc-editor.org/rfc/rfc8097",
    ),
    SpecReference::new(
        "RFC 8955",
        "Dissemination of Flow Specification Rules",
        "https://www.rfc-editor.org/rfc/rfc8955",
    ),
    SpecReference::new(
        "RFC 9135",
        "Integrated Routing and Bridging in Ethernet VPN (EVPN)",
        "https://www.rfc-editor.org/rfc/rfc9135",
    ),
    SpecReference::new(
        "RFC 10005",
        "BGP Link Bandwidth Extended Community",
        "https://www.rfc-editor.org/rfc/rfc10005",
    ),
    SpecReference::new(
        "RFC 4364",
        "BGP/MPLS IP Virtual Private Networks (VPNs)",
        "https://www.rfc-editor.org/rfc/rfc4364",
    ),
    SpecReference::new(
        "RFC 4456",
        "BGP Route Reflection: An Alternative to Full Mesh Internal BGP (IBGP)",
        "https://www.rfc-editor.org/rfc/rfc4456",
    ),
    SpecReference::new(
        "RFC 4486",
        "Subcodes for BGP Cease Notification Message",
        "https://www.rfc-editor.org/rfc/rfc4486",
    ),
    SpecReference::new(
        "RFC 4659",
        "BGP-MPLS IP Virtual Private Network (VPN) Extension for IPv6 VPN",
        "https://www.rfc-editor.org/rfc/rfc4659",
    ),
    SpecReference::new(
        "RFC 4684",
        "Constrained Route Distribution for Border Gateway Protocol/MultiProtocol Label Switching (BGP/MPLS) Internet Protocol (IP) Virtual Private Networks (VPNs)",
        "https://www.rfc-editor.org/rfc/rfc4684",
    ),
    SpecReference::new(
        "RFC 4724",
        "Graceful Restart Mechanism for BGP",
        "https://www.rfc-editor.org/rfc/rfc4724",
    ),
    SpecReference::new(
        "RFC 4760",
        "Multiprotocol Extensions for BGP-4",
        "https://www.rfc-editor.org/rfc/rfc4760",
    ),
    SpecReference::new(
        "RFC 4761",
        "Virtual Private LAN Service (VPLS) Using BGP for Auto-Discovery and Signaling",
        "https://www.rfc-editor.org/rfc/rfc4761",
    ),
    SpecReference::new(
        "RFC 5065",
        "Autonomous System Confederations for BGP",
        "https://www.rfc-editor.org/rfc/rfc5065",
    ),
    SpecReference::new(
        "RFC 5492",
        "Capabilities Advertisement with BGP-4",
        "https://www.rfc-editor.org/rfc/rfc5492",
    ),
    SpecReference::new(
        "RFC 6793",
        "BGP Support for Four-Octet Autonomous System (AS) Number Space",
        "https://www.rfc-editor.org/rfc/rfc6793",
    ),
    SpecReference::new(
        "RFC 7313",
        "Enhanced Route Refresh Capability for BGP-4",
        "https://www.rfc-editor.org/rfc/rfc7313",
    ),
    SpecReference::new(
        "RFC 7606",
        "Revised Error Handling for BGP UPDATE Messages",
        "https://www.rfc-editor.org/rfc/rfc7606",
    ),
    SpecReference::new(
        "RFC 7911",
        "Advertisement of Multiple Paths in BGP",
        "https://www.rfc-editor.org/rfc/rfc7911",
    ),
    SpecReference::new(
        "RFC 8092",
        "BGP Large Communities Attribute",
        "https://www.rfc-editor.org/rfc/rfc8092",
    ),
    SpecReference::new(
        "RFC 9003",
        "Extended BGP Administrative Shutdown Communication",
        "https://www.rfc-editor.org/rfc/rfc9003",
    ),
    SpecReference::new(
        "RFC 8538",
        "Notification Message Support for BGP Graceful Restart",
        "https://www.rfc-editor.org/rfc/rfc8538",
    ),
    SpecReference::new(
        "RFC 9384",
        "A BGP Cease NOTIFICATION Subcode for Bidirectional Forwarding Detection (BFD)",
        "https://www.rfc-editor.org/rfc/rfc9384",
    ),
    SpecReference::new(
        "RFC 6608",
        "Subcodes for BGP Finite State Machine Error",
        "https://www.rfc-editor.org/rfc/rfc6608",
    ),
    SpecReference::new(
        "RFC 5291",
        "Outbound Route Filtering Capability for BGP-4",
        "https://www.rfc-editor.org/rfc/rfc5291",
    ),
    SpecReference::new(
        "RFC 5292",
        "Address-Prefix-Based Outbound Route Filter for BGP-4",
        "https://www.rfc-editor.org/rfc/rfc5292",
    ),
    SpecReference::new(
        "RFC 8205",
        "BGPsec Protocol Specification",
        "https://www.rfc-editor.org/rfc/rfc8205",
    ),
    SpecReference::new(
        "RFC 8277",
        "Using BGP to Bind MPLS Labels to Address Prefixes",
        "https://www.rfc-editor.org/rfc/rfc8277",
    ),
    SpecReference::new(
        "RFC 8654",
        "Extended Message Support for BGP",
        "https://www.rfc-editor.org/rfc/rfc8654",
    ),
    SpecReference::new(
        "RFC 8669",
        "Segment Routing Prefix Segment Identifier Extensions for BGP",
        "https://www.rfc-editor.org/rfc/rfc8669",
    ),
    SpecReference::new(
        "RFC 8950",
        "Advertising IPv4 Network Layer Reachability Information (NLRI) with an IPv6 Next Hop",
        "https://www.rfc-editor.org/rfc/rfc8950",
    ),
    SpecReference::new(
        "RFC 9012",
        "The BGP Tunnel Encapsulation Attribute",
        "https://www.rfc-editor.org/rfc/rfc9012",
    ),
    SpecReference::new(
        "RFC 9072",
        "Extended Optional Parameters Length for BGP OPEN Message",
        "https://www.rfc-editor.org/rfc/rfc9072",
    ),
    SpecReference::new(
        "RFC 9234",
        "Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages",
        "https://www.rfc-editor.org/rfc/rfc9234",
    ),
    SpecReference::new(
        "RFC 6368",
        "Internal BGP as the Provider/Customer Edge Protocol for BGP/MPLS IP Virtual Private Networks (VPNs)",
        "https://www.rfc-editor.org/rfc/rfc6368",
    ),
    SpecReference::new(
        "RFC 6074",
        "Provisioning, Auto-Discovery, and Signaling in Layer 2 Virtual Private Networks (L2VPNs)",
        "https://www.rfc-editor.org/rfc/rfc6074",
    ),
    SpecReference::new(
        "RFC 6514",
        "BGP Encodings and Procedures for Multicast in MPLS/BGP IP VPNs",
        "https://www.rfc-editor.org/rfc/rfc6514",
    ),
    SpecReference::new(
        "RFC 6515",
        "IPv4 and IPv6 Infrastructure Addresses in BGP Updates for Multicast VPN",
        "https://www.rfc-editor.org/rfc/rfc6515",
    ),
    SpecReference::new(
        "RFC 6625",
        "Wildcards in Multicast VPN Auto-Discovery Routes",
        "https://www.rfc-editor.org/rfc/rfc6625",
    ),
    SpecReference::new(
        "RFC 7441",
        "Encoding Multipoint LDP (mLDP) Forwarding Equivalence Classes (FECs) in the NLRI of BGP MCAST-VPN Routes",
        "https://www.rfc-editor.org/rfc/rfc7441",
    ),
    SpecReference::new(
        "RFC 7524",
        "Inter-Area Point-to-Multipoint (P2MP) Segmented Label Switched Paths (LSPs)",
        "https://www.rfc-editor.org/rfc/rfc7524",
    ),
    SpecReference::new(
        "RFC 7311",
        "The Accumulated IGP Metric Attribute for BGP",
        "https://www.rfc-editor.org/rfc/rfc7311",
    ),
    SpecReference::new(
        "RFC 8205",
        "BGPsec Protocol Specification",
        "https://www.rfc-editor.org/rfc/rfc8205",
    ),
    SpecReference::new(
        "RFC 8365",
        "A Network Virtualization Overlay Solution Using Ethernet VPN (EVPN)",
        "https://www.rfc-editor.org/rfc/rfc8365",
    ),
    SpecReference::new(
        "RFC 7432",
        "BGP MPLS-Based Ethernet VPN",
        "https://www.rfc-editor.org/rfc/rfc7432",
    ),
    SpecReference::new(
        "RFC 9136",
        "IP Prefix Advertisement in Ethernet VPN (EVPN)",
        "https://www.rfc-editor.org/rfc/rfc9136",
    ),
    SpecReference::new(
        "RFC 8955",
        "Dissemination of Flow Specification Rules",
        "https://www.rfc-editor.org/rfc/rfc8955",
    ),
    SpecReference::new(
        "RFC 8956",
        "Dissemination of Flow Specification Rules for IPv6",
        "https://www.rfc-editor.org/rfc/rfc8956",
    ),
    SpecReference::new(
        "RFC 9514",
        "Border Gateway Protocol - Link State (BGP-LS) Extensions for Segment Routing over IPv6 (SRv6)",
        "https://www.rfc-editor.org/rfc/rfc9514",
    ),
    SpecReference::new(
        "RFC 9857",
        "Advertisement of Segment Routing Policies Using BGP - Link State",
        "https://www.rfc-editor.org/rfc/rfc9857",
    ),
    SpecReference::new(
        "RFC 9086",
        "Border Gateway Protocol - Link State (BGP-LS) Extensions for Segment Routing BGP Egress Peer Engineering",
        "https://www.rfc-editor.org/rfc/rfc9086",
    ),
    SpecReference::new(
        "RFC 9135",
        "Integrated Routing and Bridging in Ethernet VPN (EVPN)",
        "https://www.rfc-editor.org/rfc/rfc9135",
    ),
    SpecReference::new(
        "RFC 9251",
        "Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Proxies for Ethernet VPN (EVPN)",
        "https://www.rfc-editor.org/rfc/rfc9251",
    ),
    SpecReference::new(
        "RFC 9572",
        "Updates to EVPN Broadcast, Unknown Unicast, or Multicast (BUM) Procedures",
        "https://www.rfc-editor.org/rfc/rfc9572",
    ),
    SpecReference::new(
        "RFC 9015",
        "BGP Control Plane for the Network Service Header in Service Function Chaining",
        "https://www.rfc-editor.org/rfc/rfc9015",
    ),
    SpecReference::new(
        "RFC 9026",
        "Multicast VPN Fast Upstream Failover",
        "https://www.rfc-editor.org/rfc/rfc9026",
    ),
    SpecReference::new(
        "RFC 9552",
        "Distribution of Link-State and Traffic Engineering Information Using BGP",
        "https://www.rfc-editor.org/rfc/rfc9552",
    ),
    SpecReference::new(
        "RFC 9252",
        "BGP Overlay Services Based on Segment Routing over IPv6 (SRv6)",
        "https://www.rfc-editor.org/rfc/rfc9252",
    ),
    SpecReference::new(
        "RFC 9494",
        "Long-Lived Graceful Restart for BGP",
        "https://www.rfc-editor.org/rfc/rfc9494",
    ),
    SpecReference::new(
        "RFC 9830",
        "Advertising Segment Routing Policies in BGP",
        "https://www.rfc-editor.org/rfc/rfc9830",
    ),
    SpecReference::new(
        "IANA Capability Codes",
        "BGP Capability Codes registry",
        "https://www.iana.org/assignments/capability-codes/capability-codes.xhtml",
    ),
    SpecReference::new(
        "draft-abraitis-idr-addpath-paths-limit-04",
        "Paths Limit for Multiple Paths in BGP",
        "https://datatracker.ietf.org/doc/draft-abraitis-idr-addpath-paths-limit/",
    ),
    SpecReference::new(
        "draft-ietf-bess-mup-safi-01",
        "BGP Extensions for the Mobile User Plane (MUP) SAFI",
        "https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/",
    ),
    SpecReference::new(
        "draft-walton-bgp-hostname-capability-02",
        "Hostname Capability for BGP",
        "https://datatracker.ietf.org/doc/draft-walton-bgp-hostname-capability/",
    ),
];

/// Size of the AS numbers in the AS_PATH attribute of an UPDATE.
///
/// Between NEW BGP speakers AS_PATH carries 4-octet AS numbers, and towards
/// an OLD speaker 2-octet ones (RFC 6793, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc6793#section-4>). The size is
/// negotiated in OPEN, so a lone UPDATE does not say which one it uses; an
/// encapsulating protocol may (e.g. the BMP per-peer header A flag, RFC 7854,
/// Section 4.2 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.2>).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsNumberSize {
    /// 2-octet AS numbers ("the legacy 2-byte AS_PATH format").
    TwoOctet,
    /// 4-octet AS numbers (RFC 6793).
    FourOctet,
}

impl AsNumberSize {
    /// Number of octets of one AS number.
    const fn octets(self) -> usize {
        match self {
            Self::TwoOctet => 2,
            Self::FourOctet => 4,
        }
    }
}

/// BGP-4 dissector.
pub struct BgpDissector;

impl BgpDissector {
    /// Dissects the single BGP message at the start of `data` and appends
    /// one `BGP` layer. Returns the number of bytes the message occupies
    /// (its Length field); bytes after it are left alone.
    ///
    /// This is the entry point for protocols that carry BGP messages, such
    /// as BMP (RFC 7854, Section 4 —
    /// <https://www.rfc-editor.org/rfc/rfc7854#section-4>). `as_size` is the
    /// AS number size of AS_PATH when the carrier knows it; it is preferred
    /// over the size inferred from the UPDATE itself, which is used when the
    /// AS_PATH does not fit it. `None` infers the size as
    /// [`Dissector::dissect`] does.
    ///
    /// # Errors
    ///
    /// [`PacketError::Truncated`] when `data` is shorter than the header or
    /// the message Length, and the errors of [`Dissector::dissect`] for a
    /// malformed message.
    pub fn dissect_message<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        as_size: Option<AsNumberSize>,
    ) -> Result<usize, PacketError> {
        dissect_one_message(data, buf, offset, as_size)
    }
}

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

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
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
            let consumed = dissect_one_message(&data[pos..], buf, offset + pos, None)?;
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

        // RFC 8538, Section 3 — Cease subcode 9 = "Hard Reset".
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&21u16.to_be_bytes());
        raw.push(3); // Type = NOTIFICATION
        raw.push(6); // Cease
        raw.push(9); // Hard Reset (RFC 8538)

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "error_subcode_name"),
            Some("Hard Reset")
        );

        // For non-Cease error codes, error_subcode_name must NOT decode as a
        // Cease subcode (the lookup table is error-code specific): Message
        // Header Error subcode 2 is "Bad Message Length" (RFC 4271,
        // Section 6.1 — https://www.rfc-editor.org/rfc/rfc4271#section-6.1),
        // not "Administrative Shutdown".
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&21u16.to_be_bytes());
        raw.push(3); // Type = NOTIFICATION
        raw.push(1); // Error Code = Message Header Error
        raw.push(2); // Subcode (not Cease subcode)

        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "error_subcode_name"),
            Some("Bad Message Length")
        );
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

    /// Helper: collect the ranges of the direct entry objects in an NLRI array.
    ///
    /// Built on [`direct_children`] rather than `nested_fields` directly:
    /// `nested_fields` flattens every descendant field in `range`, so for a
    /// MUP entry carrying its own nested `tlvs` array, the nested TLV
    /// object(s) would otherwise be miscounted as additional entries.
    /// `direct_children` stops at each child container's own range, so only
    /// the entry objects themselves are returned.
    fn nlri_entry_ranges(
        buf: &DissectBuffer<'_>,
        range: &core::ops::Range<u32>,
    ) -> Vec<core::ops::Range<u32>> {
        direct_children(buf, range)
            .iter()
            .filter_map(|f| f.value.as_container_range().cloned())
            .collect()
    }

    /// RFC 7911 (ADD-PATH) regression: a MUP (SAFI 85) NLRI entry that itself
    /// carries a nested `tlvs` array must still count as exactly one entry.
    ///
    /// `nlri_entry_ranges` used to collect every container inside the array
    /// range — grandchildren included — so a single MUP entry with one nested
    /// TLV object was miscounted as two entries.
    ///
    /// RFC 7911, Section 3 — <https://www.rfc-editor.org/rfc/rfc7911#section-3>
    /// draft-ietf-bess-mup-safi-01, Section 3 —
    /// <https://datatracker.ietf.org/doc/draft-ietf-bess-mup-safi/>
    #[test]
    fn nlri_entry_ranges_counts_direct_entries_only_with_mup_tlvs() {
        // Type 1 ST MUP entry (Architecture Type 1, Route Type 3) with a
        // Source Address Length of 0 followed by a trailing Source Address
        // TLV (Type 3), i.e. the same shape as `parse_bgp_update_mup_type1_st_tlvs`.
        let mut val = Vec::new();
        val.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        val.push(85); // SAFI = MUP
        val.push(4); // Next Hop Length
        val.extend_from_slice(&[10, 0, 0, 1]); // Next Hop
        val.push(0); // Reserved
        val.push(1); // Architecture Type = 3gpp-5g
        val.extend_from_slice(&3u16.to_be_bytes()); // Route Type = Type 1 ST
        let tlv = [3u8, 4, 10, 0, 0, 9]; // Type 3: Source Address TLV, IPv4
        let rt_len = 8 + 1 + 4 + 4 + 1 + 1 + 4 + 1 + tlv.len();
        val.push(rt_len as u8); // Length
        val.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // RD
        val.push(32); // Prefix Length
        val.extend_from_slice(&[10, 1, 1, 1]); // Prefix
        val.extend_from_slice(&0x12345678u32.to_be_bytes()); // TEID
        val.push(9); // QFI
        val.push(32); // Endpoint Address Length
        val.extend_from_slice(&[10, 0, 0, 2]); // Endpoint Address
        val.push(0); // Source Address Length = 0 (not carried inline)
        val.extend_from_slice(&tlv);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let entries_range = mp_nlri_range(&buf, "nlri");
        let entries = nlri_entry_ranges(&buf, &entries_range);
        // Exactly one MUP entry, even though it carries a nested `tlvs` array
        // with one TLV object of its own.
        assert_eq!(entries.len(), 1);
        let FieldValue::Array(ref tlvs_range) = *nested_field_value(&buf, &entries[0], "tlvs")
        else {
            panic!("expected Array for tlvs");
        };
        assert_eq!(direct_children(&buf, tlvs_range).len(), 1);
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
        assert_eq!(afi_name(16388), Some("BGP-LS"));
        assert_eq!(afi_name(0), None);

        // IANA SAFI Namespace.
        for (v, expected) in [
            (1u8, "Unicast"),
            (2, "Multicast"),
            (4, "MPLS Labels"),
            (5, "MCAST-VPN"),
            (65, "VPLS"),
            (70, "EVPN"),
            (71, "BGP-LS"),
            (72, "BGP-LS-VPN"),
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
    fn parse_bgp_update_mup_truncated_entry_is_raw() {
        // MUP entry whose declared Route Type Length runs past the end of the
        // NLRI block: the walk stops, the empty array placeholder is removed
        // and the bytes are kept as `nlri_raw`.
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
        // The undecodable entry is kept as raw bytes instead of being dropped.
        assert_eq!(
            *nested_field_value(&buf, mp_range, "nlri_raw"),
            FieldValue::Bytes(&[1, 0, 1, 200, 0xAA])
        );
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = BgpDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(!reference.title.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }

    #[test]
    fn field_schema_exposes_nlri_and_path_attribute_value_children() {
        /// Recursively look up a descriptor by name.
        fn find<'a>(descs: &'a [FieldDescriptor], name: &str) -> Option<&'a FieldDescriptor> {
            descs.iter().find(|d| d.name == name)
        }

        let descs = BgpDissector.field_descriptors();

        // Top-level `nlri` / `withdrawn_routes` expose the same MUP/IP union
        // as the MP_REACH_NLRI / MP_UNREACH_NLRI ones, so a consumer can
        // resolve a path such as `BGP.nlri.route_type` against either array.
        // Every member of a union is optional.
        for name in ["nlri", "withdrawn_routes"] {
            let d = find(descs, name).unwrap_or_else(|| panic!("{name} descriptor missing"));
            assert_eq!(d.field_type, FieldType::Array);
            let children = d
                .children
                .unwrap_or_else(|| panic!("{name} has no children"));
            let path_id = find(children, "path_id").expect("path_id missing");
            assert_eq!(path_id.field_type, FieldType::U32);
            assert!(path_id.optional);
            for child_name in [
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
                let child = find(children, child_name)
                    .unwrap_or_else(|| panic!("{child_name} missing from {name} union"));
                assert!(
                    child.optional,
                    "{child_name} in the {name} union must be optional"
                );
            }
        }

        // `label_stack` entries expose the RFC 8277 Label / Rsrv / S fields.
        let label_stack = find(
            find(descs, "nlri").unwrap().children.unwrap(),
            "label_stack",
        )
        .expect("label_stack missing");
        let label_children = label_stack.children.expect("label_stack has no children");
        for name in ["label", "rsrv", "s"] {
            assert!(find(label_children, name).is_some(), "{name} missing");
        }

        // `path_attributes.value` is polymorphic and lists the union of every
        // structured shape it can take.
        let pa = find(descs, "path_attributes").expect("path_attributes missing");
        let pa_children = pa.children.expect("path_attributes has no children");
        let as_number_size = find(pa_children, "as_number_size").expect("as_number_size missing");
        assert_eq!(as_number_size.field_type, FieldType::U8);
        assert!(as_number_size.optional);
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
            "nlri_raw",
            "withdrawn_routes_raw",
            "next_hop_rd",
            "next_hop_link_local_rd",
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
            "label_stack",
            "compatibility",
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

    // -------------------------------------------------------------------
    // RFC 4760 top-level `afi`/`safi` mirroring for UPDATE messages
    // (https://www.rfc-editor.org/rfc/rfc4760#section-3,
    // https://www.rfc-editor.org/rfc/rfc4760#section-4).
    // -------------------------------------------------------------------

    /// Helper: look up a *direct* (top-level, not nested in a container)
    /// layer field by name, or `None` if it is absent at the top level (it
    /// may still exist nested inside `path_attributes`).
    fn direct_layer_field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        let layer = &buf.layers()[0];
        direct_children(buf, &layer.field_range)
            .into_iter()
            .find(|f| f.name() == name)
    }

    #[test]
    fn parse_bgp_update_top_level_afi_safi_from_mp_reach() {
        // UPDATE with a single MP_REACH_NLRI (IPv6 unicast): top-level
        // afi/safi must mirror it directly, not just the nested MP_REACH
        // object fields.
        let mut val = Vec::new();
        val.extend_from_slice(&2u16.to_be_bytes()); // AFI = IPv6
        val.push(1); // SAFI = unicast
        val.push(16); // Next Hop length
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        val.push(0); // Reserved
        val.push(48);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);

        let attr = build_attr(0x80 | 0x10, 14, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let afi = direct_layer_field(&buf, "afi").expect("top-level afi");
        assert_eq!(afi.value, FieldValue::U16(2));
        let safi = direct_layer_field(&buf, "safi").expect("top-level safi");
        assert_eq!(safi.value, FieldValue::U8(1));

        // `afi_name`/`safi_name` display_fn companions must still resolve.
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "afi_name"), Some("IPv6"));
        assert_eq!(
            buf.resolve_display_name(layer, "safi_name"),
            Some("Unicast")
        );
    }

    #[test]
    fn parse_bgp_update_top_level_afi_safi_from_mp_unreach_only() {
        // UPDATE with only an MP_UNREACH_NLRI: top-level afi/safi are taken
        // from it.
        let mut val = Vec::new();
        val.extend_from_slice(&2u16.to_be_bytes()); // AFI = IPv6
        val.push(1); // SAFI = unicast
        val.push(32);
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let attr = build_attr(0x80 | 0x10, 15, &val);
        let data = build_update(&attr, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let afi = direct_layer_field(&buf, "afi").expect("top-level afi");
        assert_eq!(afi.value, FieldValue::U16(2));
        let safi = direct_layer_field(&buf, "safi").expect("top-level safi");
        assert_eq!(safi.value, FieldValue::U8(1));
    }

    #[test]
    fn parse_bgp_update_top_level_afi_safi_first_attribute_wins() {
        // UPDATE with MP_UNREACH_NLRI (IPv4 unicast) followed by MP_REACH_NLRI
        // (IPv4 BGP-MUP, SAFI 85): the first attribute in attribute order
        // determines the top-level afi/safi, regardless of type.
        let mut unreach_val = Vec::new();
        unreach_val.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        unreach_val.push(1); // SAFI = unicast
        unreach_val.push(8);
        unreach_val.push(10);
        let unreach_attr = build_attr(0x80 | 0x10, 15, &unreach_val);

        let mut reach_val = Vec::new();
        reach_val.extend_from_slice(&1u16.to_be_bytes()); // AFI = IPv4
        reach_val.push(85); // SAFI = BGP-MUP
        reach_val.push(4); // Next Hop length
        reach_val.extend_from_slice(&[10, 0, 0, 1]);
        reach_val.push(0); // Reserved
        let reach_attr = build_attr(0x80 | 0x10, 14, &reach_val);

        let mut attrs = unreach_attr;
        attrs.extend_from_slice(&reach_attr);

        let data = build_update(&attrs, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let afi = direct_layer_field(&buf, "afi").expect("top-level afi");
        assert_eq!(afi.value, FieldValue::U16(1));
        // MP_UNREACH_NLRI came first, so its SAFI (unicast = 1) wins over the
        // later MP_REACH_NLRI's SAFI (BGP-MUP = 85).
        let safi = direct_layer_field(&buf, "safi").expect("top-level safi");
        assert_eq!(safi.value, FieldValue::U8(1));
    }

    #[test]
    fn parse_bgp_update_plain_ipv4_unicast_has_no_top_level_afi_safi() {
        // A plain IPv4 unicast UPDATE (no MP_REACH_NLRI / MP_UNREACH_NLRI
        // attribute) must not get synthesised top-level afi/safi — only what
        // is on the wire is decoded.
        let attr = build_attr(0x40, 1, &[0]); // ORIGIN = IGP
        let nlri = [24, 192, 168, 1]; // 192.168.1.0/24
        let data = build_update(&attr, &nlri);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert!(direct_layer_field(&buf, "afi").is_none());
        assert!(direct_layer_field(&buf, "safi").is_none());
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

    // -------------------------------------------------------------------
    // AS_PATH AS number size detection (RFC 6793, Section 4.1 —
    // https://www.rfc-editor.org/rfc/rfc6793#section-4.1; RFC 7606,
    // Section 7.2 — https://www.rfc-editor.org/rfc/rfc7606#section-7.2).
    // -------------------------------------------------------------------

    /// Helper: decode the AS_PATH segments of the first path attribute as
    /// `(segment_type, as_numbers)` pairs.
    fn first_attr_as_path_segments(buf: &DissectBuffer<'_>) -> Vec<(u8, Vec<u32>)> {
        let obj_range = first_pa_obj_range(buf);
        let FieldValue::Array(ref segs_range) = *nested_field_value(buf, &obj_range, "value")
        else {
            panic!("expected Array for AS path value");
        };
        direct_children(buf, segs_range)
            .iter()
            .map(|seg| {
                let seg_range = seg.value.as_container_range().unwrap();
                let FieldValue::U8(seg_type) = *nested_field_value(buf, seg_range, "segment_type")
                else {
                    panic!("expected U8 segment_type");
                };
                let asns_range = nested_field_by_name(buf, seg_range, "as_numbers")
                    .value
                    .as_container_range()
                    .unwrap();
                let asns = buf
                    .nested_fields(asns_range)
                    .iter()
                    .map(|f| match f.value {
                        FieldValue::U32(v) => v,
                        _ => panic!("expected U32 AS number"),
                    })
                    .collect();
                (seg_type, asns)
            })
            .collect()
    }

    /// Helper: the `as_number_size` of the first path attribute, if present.
    fn first_attr_as_number_size<'pkt>(buf: &DissectBuffer<'pkt>) -> Option<FieldValue<'pkt>> {
        let obj_range = first_pa_obj_range(buf);
        nested_field_by_name_opt(buf, &obj_range, "as_number_size").map(|f| f.value.clone())
    }

    #[test]
    fn parse_bgp_update_as_path_two_octet_size() {
        // AS_SEQUENCE { 65001, 65002 } with 2-octet AS numbers cannot be read
        // as 4-octet (the segment would need 8 value octets).
        let value = [2, 2, 0xFD, 0xE9, 0xFD, 0xEA];
        let data = build_update(&build_attr(0x40, 2, &value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            first_attr_as_path_segments(&buf),
            vec![(2, vec![65001, 65002])]
        );
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(2)));
    }

    #[test]
    fn parse_bgp_update_as_path_four_octet() {
        // Reproduction from the issue: AS_SEQUENCE { 65536 } with 4-octet AS
        // numbers, as sent between two NEW BGP speakers (RFC 6793, Section 4.1).
        let mut value = vec![2, 1];
        value.extend_from_slice(&65536u32.to_be_bytes());
        let data = build_update(&build_attr(0x40, 2, &value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(first_attr_as_path_segments(&buf), vec![(2, vec![65536])]);
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(4)));
    }

    #[test]
    fn parse_bgp_update_as_path_four_octet_multi_segment() {
        // AS_SEQUENCE { 65001, 4200000000 } + AS_SET { 65536 }.
        let mut value = vec![2, 2];
        value.extend_from_slice(&65001u32.to_be_bytes());
        value.extend_from_slice(&4_200_000_000u32.to_be_bytes());
        value.extend_from_slice(&[1, 1]);
        value.extend_from_slice(&65536u32.to_be_bytes());
        let data = build_update(&build_attr(0x40, 2, &value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            first_attr_as_path_segments(&buf),
            vec![(2, vec![65001, 4_200_000_000]), (1, vec![65536])]
        );
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(4)));
    }

    #[test]
    fn parse_bgp_update_as_path_two_octet_multi_segment() {
        // AS_CONFED_SEQUENCE { 64512 } + AS_SEQUENCE { 65001, 65002, 65003 }
        // with 2-octet AS numbers; the 4-octet reading would overrun.
        let value = [3, 1, 0xFC, 0x00, 2, 3, 0xFD, 0xE9, 0xFD, 0xEA, 0xFD, 0xEB];
        let data = build_update(&build_attr(0x40, 2, &value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            first_attr_as_path_segments(&buf),
            vec![(3, vec![64512]), (2, vec![65001, 65002, 65003])]
        );
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(2)));
    }

    #[test]
    fn parse_bgp_update_as_path_ambiguous_prefers_four_octet() {
        // Valid both as 4-octet AS_SEQUENCE { 65538, 16842755 } and as
        // 2-octet AS_SEQUENCE { 1, 2 } + AS_SET { 3 }: 4-octet wins.
        let value = [2, 2, 0, 1, 0, 2, 1, 1, 0, 3];
        let data = build_update(&build_attr(0x40, 2, &value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(
            first_attr_as_path_segments(&buf),
            vec![(2, vec![65538, 16_842_755])]
        );
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(4)));
    }

    #[test]
    fn parse_bgp_update_as_path_empty() {
        // An empty AS_PATH (e.g. iBGP, locally originated) has no segments
        // and gives no evidence of the AS number size.
        let data = build_update(&build_attr(0x40, 2, &[]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert!(first_attr_as_path_segments(&buf).is_empty());
        assert_eq!(first_attr_as_number_size(&buf), None);
    }

    #[test]
    fn parse_bgp_update_as_path_malformed_is_raw() {
        for value in [
            // Segment length overruns the attribute for both sizes.
            &[2u8, 5, 0, 1][..],
            // Zero Path Segment Length (RFC 7606, Section 7.2).
            &[2, 0],
            // Unrecognized segment type 0.
            &[0, 1, 0, 1],
            // Single trailing octet after a valid segment (underrun).
            &[2, 1, 0, 1, 2],
        ] {
            let data = build_update(&build_attr(0x40, 2, value), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();

            let obj_range = first_pa_obj_range(&buf);
            assert_eq!(
                *nested_field_value(&buf, &obj_range, "value"),
                FieldValue::Bytes(value),
                "value {value:?}"
            );
            assert_eq!(first_attr_as_number_size(&buf), None);
        }
    }

    #[test]
    fn parse_bgp_update_as4_path_malformed_is_raw() {
        // AS4_PATH always uses 4-octet AS numbers (RFC 6793, Section 3); a
        // segment encoded with 2-octet numbers overruns and is kept raw.
        let value = [2, 2, 0xFD, 0xE9, 0xFD, 0xEA];
        let data = build_update(&build_attr(0xC0, 17, &value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj_range = first_pa_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj_range, "value"),
            FieldValue::Bytes(&value)
        );
    }

    #[test]
    fn as_path_fits_checks_structure() {
        assert!(as_path_fits(&[], 2));
        assert!(as_path_fits(&[], 4));
        assert!(as_path_fits(&[2, 1, 0, 1], 2));
        assert!(!as_path_fits(&[2, 1, 0, 1], 4));
        assert!(as_path_fits(&[4, 1, 0, 0, 0, 1], 4));
        assert!(!as_path_fits(&[5, 1, 0, 0, 0, 1], 4));
        assert!(!as_path_fits(&[2, 0], 2));
        assert!(!as_path_fits(&[2], 2));
    }

    // -------------------------------------------------------------------
    // MP_REACH_NLRI / MP_UNREACH_NLRI NLRI selection by AFI/SAFI
    // (RFC 4760, Sections 3-5 — https://www.rfc-editor.org/rfc/rfc4760#section-3).
    // -------------------------------------------------------------------

    /// Helper: build an MP_REACH_NLRI attribute value.
    fn build_mp_reach(afi: u16, safi: u8, next_hop: &[u8], nlri: &[u8]) -> Vec<u8> {
        let mut val = afi.to_be_bytes().to_vec();
        val.push(safi);
        val.push(next_hop.len() as u8);
        val.extend_from_slice(next_hop);
        val.push(0); // Reserved
        val.extend_from_slice(nlri);
        val
    }

    /// Helper: build an MP_UNREACH_NLRI attribute value.
    fn build_mp_unreach(afi: u16, safi: u8, withdrawn: &[u8]) -> Vec<u8> {
        let mut val = afi.to_be_bytes().to_vec();
        val.push(safi);
        val.extend_from_slice(withdrawn);
        val
    }

    /// Helper: build an UPDATE whose only path attribute is an optional,
    /// extended-length attribute `type_code` carrying `value`.
    fn build_single_attr_update(type_code: u8, value: &[u8]) -> Vec<u8> {
        build_update(&build_attr(0x90, type_code, value), &[])
    }

    /// Helper: the child range of the first path attribute's Object `value`.
    fn first_attr_value_obj_range(buf: &DissectBuffer<'_>) -> core::ops::Range<u32> {
        let obj_range = first_pa_obj_range(buf);
        let FieldValue::Object(ref mp_range) = *nested_field_value(buf, &obj_range, "value") else {
            panic!("expected Object value");
        };
        mp_range.clone()
    }

    #[test]
    fn parse_bgp_update_mp_reach_unsupported_ip_safi_is_raw() {
        // MDT SAFI (AFI 1, SAFI 66; RFC 6037 —
        // https://www.rfc-editor.org/rfc/rfc6037) is not decoded:
        // its NLRI is not a plain prefix list and is kept raw.
        let nlri = [0x05, 0x01, 0x08, 0x0a, 0x81, 0x06];
        let val = build_mp_reach(1, 66, &[], &nlri);
        let data = build_single_attr_update(14, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "nlri_raw"),
            FieldValue::Bytes(&nlri)
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "nlri").is_none());
    }

    #[test]
    fn parse_bgp_update_mp_unreach_unsupported_ip_safi_is_raw() {
        // MDT (AFI 1, SAFI 66; RFC 6037, Section 4.4.1 —
        // https://www.rfc-editor.org/rfc/rfc6037#section-4.4.1): "the
        // 8-byte-RD:IPv4-address followed by the MDT group address", not a
        // plain prefix list.
        let wr = [
            128, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 192, 0, 2, 1, 232, 1, 1, 1,
        ];
        let val = build_mp_unreach(1, 66, &wr);
        let data = build_single_attr_update(15, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "withdrawn_routes_raw"),
            FieldValue::Bytes(&wr)
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "withdrawn_routes").is_none());
    }

    #[test]
    fn parse_bgp_update_mp_reach_ipv4_multicast_prefixes() {
        // SAFI 2 (multicast) uses the plain prefix encoding (RFC 4760, Section 5).
        let val = build_mp_reach(1, 2, &[192, 0, 2, 1], &[24, 198, 51, 100]);
        let data = build_single_attr_update(14, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let mp = first_attr_value_obj_range(&buf);
        let FieldValue::Array(ref nlri) = *nested_field_value(&buf, &mp, "nlri") else {
            panic!("expected Array");
        };
        let entries = nlri_entry_ranges(&buf, nlri);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "prefix"),
            FieldValue::Bytes(&[24, 198, 51, 100])
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "nlri_raw").is_none());
    }

    // -------------------------------------------------------------------
    // MP_REACH_NLRI next hop encodings: VPN (RFC 4364, Section 4.3.2;
    // RFC 4659, Section 3.2.1) and IPv6 next hop for IPv4 NLRI (RFC 8950,
    // Section 3 — https://www.rfc-editor.org/rfc/rfc8950#section-3).
    // -------------------------------------------------------------------

    const NH_V6_GLOBAL: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const NH_V6_LL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// Helper: dissect an MP_REACH_NLRI with an empty NLRI and return the
    /// `(name, value)` pairs of the next hop fields.
    fn mp_reach_next_hop_fields(afi: u16, safi: u8, next_hop: &[u8]) -> Vec<(String, String)> {
        let val = build_mp_reach(afi, safi, next_hop, &[]);
        let data = build_single_attr_update(14, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        direct_children(&buf, &mp)
            .iter()
            .filter(|f| f.name().starts_with("next_hop"))
            .map(|f| (f.name().to_string(), format!("{:?}", f.value)))
            .collect()
    }

    fn nh(name: &str, value: FieldValue<'_>) -> (String, String) {
        (name.to_string(), format!("{value:?}"))
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpn_ipv4_next_hop() {
        // RFC 4364, Section 4.3.2: VPN-IPv4 next hop with an RD of 0.
        let mut next_hop = vec![0u8; 8];
        next_hop.extend_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            mp_reach_next_hop_fields(1, 128, &next_hop),
            vec![
                nh("next_hop_rd", FieldValue::Bytes(&[0; 8])),
                nh("next_hop", FieldValue::Ipv4Addr([192, 0, 2, 1])),
            ]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpn_ipv6_next_hop() {
        // RFC 4659, Section 3.2.1.1: VPN-IPv6 next hop (length 24).
        let mut next_hop = vec![0u8; 8];
        next_hop.extend_from_slice(&NH_V6_GLOBAL);
        assert_eq!(
            mp_reach_next_hop_fields(2, 128, &next_hop),
            vec![
                nh("next_hop_rd", FieldValue::Bytes(&[0; 8])),
                nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL)),
            ]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpn_ipv6_next_hop_link_local() {
        // RFC 4659, Section 3.2.1.1: global + link-local VPN-IPv6 (length 48).
        let mut next_hop = vec![0u8; 8];
        next_hop.extend_from_slice(&NH_V6_GLOBAL);
        next_hop.extend_from_slice(&[0u8; 8]);
        next_hop.extend_from_slice(&NH_V6_LL);
        assert_eq!(
            mp_reach_next_hop_fields(2, 128, &next_hop),
            vec![
                nh("next_hop_rd", FieldValue::Bytes(&[0; 8])),
                nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL)),
                nh("next_hop_link_local_rd", FieldValue::Bytes(&[0; 8])),
                nh("next_hop_link_local", FieldValue::Ipv6Addr(NH_V6_LL)),
            ]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_ipv4_nlri_ipv6_next_hop() {
        // RFC 8950, Section 3: AFI 1 / SAFI 1, 2, 4 with a 16 or 32 octet
        // IPv6 next hop.
        assert_eq!(
            mp_reach_next_hop_fields(1, 1, &NH_V6_GLOBAL),
            vec![nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL))]
        );
        let mut next_hop = NH_V6_GLOBAL.to_vec();
        next_hop.extend_from_slice(&NH_V6_LL);
        assert_eq!(
            mp_reach_next_hop_fields(1, 4, &next_hop),
            vec![
                nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL)),
                nh("next_hop_link_local", FieldValue::Ipv6Addr(NH_V6_LL)),
            ]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpn_ipv4_nlri_ipv6_next_hop() {
        // RFC 8950, Section 3: AFI 1 / SAFI 128 with a 24 octet VPN-IPv6
        // next hop.
        let mut next_hop = vec![0u8; 8];
        next_hop.extend_from_slice(&NH_V6_GLOBAL);
        assert_eq!(
            mp_reach_next_hop_fields(1, 128, &next_hop),
            vec![
                nh("next_hop_rd", FieldValue::Bytes(&[0; 8])),
                nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL)),
            ]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_unexpected_next_hop_length_is_raw() {
        // A 4 octet next hop is not a VPN-IPv4 address (RFC 4364, Section
        // 4.3.2), so it is kept as raw bytes.
        assert_eq!(
            mp_reach_next_hop_fields(1, 128, &[192, 0, 2, 1]),
            vec![nh("next_hop", FieldValue::Bytes(&[192, 0, 2, 1]))]
        );
        assert_eq!(
            mp_reach_next_hop_fields(2, 1, &[192, 0, 2, 1]),
            vec![nh("next_hop", FieldValue::Bytes(&[192, 0, 2, 1]))]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_bgp_ls_vpn_next_hop_link_local() {
        // RFC 9552, Section 5.5 (https://www.rfc-editor.org/rfc/rfc9552#section-5.5):
        // "if the next-hop length is 32, then there is one global IPv6
        // address followed by an IPv6 link-local address. ... For VPN
        // Subsequent Address Family Identifier (SAFI), as per custom, an
        // 8-byte Route Distinguisher set to all zero is prepended to the next
        // hop." — one RD before both addresses, 40 octets in all.
        let mut next_hop = vec![0u8; 8];
        next_hop.extend_from_slice(&NH_V6_GLOBAL);
        next_hop.extend_from_slice(&NH_V6_LL);
        assert_eq!(
            mp_reach_next_hop_fields(16388, 72, &next_hop),
            vec![
                nh("next_hop_rd", FieldValue::Bytes(&[0; 8])),
                nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL)),
                nh("next_hop_link_local", FieldValue::Ipv6Addr(NH_V6_LL)),
            ]
        );
        // The 40-octet shape is specific to BGP-LS-VPN.
        assert_eq!(
            mp_reach_next_hop_fields(2, 128, &next_hop),
            vec![nh("next_hop", FieldValue::Bytes(&next_hop))]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_mcast_vpn_next_hop() {
        // RFC 6515, Section 2 (https://www.rfc-editor.org/rfc/rfc6515#section-2):
        // the MCAST-VPN next hop "is an IPv4 address (length is 4) or an IPv6
        // address (length is 16)", whatever the AFI.
        assert_eq!(
            mp_reach_next_hop_fields(2, 5, &[192, 0, 2, 1]),
            vec![nh("next_hop", FieldValue::Ipv4Addr([192, 0, 2, 1]))]
        );
        assert_eq!(
            mp_reach_next_hop_fields(1, 5, &NH_V6_GLOBAL),
            vec![nh("next_hop", FieldValue::Ipv6Addr(NH_V6_GLOBAL))]
        );
        // "If the length of the next hop address is neither 4 nor 16, the
        // MP_REACH_NLRI attribute MUST be considered to be "incorrect"".
        let mut next_hop = NH_V6_GLOBAL.to_vec();
        next_hop.extend_from_slice(&NH_V6_LL);
        assert_eq!(
            mp_reach_next_hop_fields(2, 5, &next_hop),
            vec![nh("next_hop", FieldValue::Bytes(&next_hop))]
        );
    }

    // -------------------------------------------------------------------
    // Labeled unicast (RFC 8277, Sections 2.2-2.4 —
    // https://www.rfc-editor.org/rfc/rfc8277#section-2.2) and VPN-IPv4 /
    // VPN-IPv6 NLRI (RFC 4364, Section 4.3.4; RFC 4659, Section 3.2).
    // -------------------------------------------------------------------

    const RD_65000_100: [u8; 8] = [0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64];

    /// A decoded labeled NLRI entry: `(path_id, labels as (label, rsrv, s),
    /// compatibility, rd, prefix as [len, octets...])`.
    type LabeledEntry = (
        Option<u32>,
        Vec<(u32, u8, u8)>,
        Option<u32>,
        Option<Vec<u8>>,
        Vec<u8>,
    );

    /// Helper: dissect an MP_REACH_NLRI (`type_code` 14) or MP_UNREACH_NLRI
    /// (15) attribute and decode its entries.
    fn labeled_entries(type_code: u8, afi: u16, safi: u8, nlri: &[u8]) -> Vec<LabeledEntry> {
        let (val, array_name) = if type_code == 14 {
            let next_hop: &[u8] = if safi == 128 {
                &[0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1]
            } else {
                &[192, 0, 2, 1]
            };
            (build_mp_reach(afi, safi, next_hop, nlri), "nlri")
        } else {
            (build_mp_unreach(afi, safi, nlri), "withdrawn_routes")
        };
        let data = build_single_attr_update(type_code, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let FieldValue::Array(ref arr) = *nested_field_value(&buf, &mp, array_name) else {
            panic!("expected Array for {array_name}");
        };
        nlri_entry_ranges(&buf, arr)
            .iter()
            .map(|entry| {
                let path_id = nested_field_by_name_opt(&buf, entry, "path_id").map(|f| {
                    let FieldValue::U32(v) = f.value else {
                        panic!("path_id")
                    };
                    v
                });
                let labels = nested_field_by_name_opt(&buf, entry, "label_stack")
                    .map(|f| {
                        let range = f.value.as_container_range().unwrap();
                        direct_children(&buf, range)
                            .iter()
                            .map(|l| {
                                let r = l.value.as_container_range().unwrap();
                                let FieldValue::U32(label) = *nested_field_value(&buf, r, "label")
                                else {
                                    panic!("label")
                                };
                                let FieldValue::U8(rsrv) = *nested_field_value(&buf, r, "rsrv")
                                else {
                                    panic!("rsrv")
                                };
                                let FieldValue::U8(s) = *nested_field_value(&buf, r, "s") else {
                                    panic!("s")
                                };
                                (label, rsrv, s)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let compatibility =
                    nested_field_by_name_opt(&buf, entry, "compatibility").map(|f| {
                        let FieldValue::U32(v) = f.value else {
                            panic!("compatibility")
                        };
                        v
                    });
                let rd = nested_field_by_name_opt(&buf, entry, "rd").map(|f| {
                    let FieldValue::Bytes(b) = f.value else {
                        panic!("rd")
                    };
                    b.to_vec()
                });
                let prefix = match nested_field_value(&buf, entry, "prefix") {
                    FieldValue::Scratch(r) => {
                        buf.scratch()[r.start as usize..r.end as usize].to_vec()
                    }
                    FieldValue::Bytes(b) => b.to_vec(),
                    other => panic!("unexpected prefix {other:?}"),
                };
                (path_id, labels, compatibility, rd, prefix)
            })
            .collect()
    }

    /// Helper: the raw NLRI / withdrawn routes of an MP attribute, if any.
    fn mp_raw(type_code: u8, afi: u16, safi: u8, nlri: &[u8]) -> Option<Vec<u8>> {
        let (val, raw_name) = if type_code == 14 {
            (build_mp_reach(afi, safi, &[192, 0, 2, 1], nlri), "nlri_raw")
        } else {
            (build_mp_unreach(afi, safi, nlri), "withdrawn_routes_raw")
        };
        let data = build_single_attr_update(type_code, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        nested_field_by_name_opt(&buf, &mp, raw_name).map(|f| {
            let FieldValue::Bytes(b) = f.value else {
                panic!("raw")
            };
            b.to_vec()
        })
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpn_ipv4_nlri() {
        // Reproduction from the issue: label 100 (S=1), RD 0:65000:100,
        // 10.0.0.0/24 — 112 bits.
        let mut nlri = vec![0x70, 0x00, 0x06, 0x41];
        nlri.extend_from_slice(&RD_65000_100);
        nlri.extend_from_slice(&[10, 0, 0]);
        assert_eq!(
            labeled_entries(14, 1, 128, &nlri),
            vec![(
                None,
                vec![(100, 0, 1)],
                None,
                Some(RD_65000_100.to_vec()),
                vec![24, 10, 0, 0]
            )]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpn_ipv6_nlri() {
        // Label 16 (S=1), RD 0:65000:100, 2001:db8:1::/48 — 24+64+48 bits.
        let mut nlri = vec![24 + 64 + 48, 0x00, 0x01, 0x01];
        nlri.extend_from_slice(&RD_65000_100);
        nlri.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        let mut next_hop = vec![0u8; 8];
        next_hop.extend_from_slice(&NH_V6_GLOBAL);
        let val = build_mp_reach(2, 128, &next_hop, &nlri);
        let data = build_single_attr_update(14, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let FieldValue::Array(ref arr) = *nested_field_value(&buf, &mp, "nlri") else {
            panic!("expected Array");
        };
        let entries = nlri_entry_ranges(&buf, arr);
        assert_eq!(entries.len(), 1);
        let prefix = nested_field_by_name(&buf, &entries[0], "prefix");
        let FieldValue::Scratch(ref r) = prefix.value else {
            panic!("expected Scratch prefix");
        };
        assert_eq!(
            &buf.scratch()[r.start as usize..r.end as usize],
            &[48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]
        );
        // The prefix field covers the prefix octets in the packet.
        assert_eq!(prefix.range.end - prefix.range.start, 6);
        // It is serialised with the IPv6 CIDR formatter.
        let ctx = FormatContext {
            packet_data: &data,
            scratch: buf.scratch(),
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        (prefix.descriptor.format_fn.unwrap())(&prefix.value, &ctx, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"2001:db8:1::/48\"");
    }

    #[test]
    fn parse_bgp_update_mp_reach_labeled_ipv4_nlri() {
        // Reproduction from the issue: SAFI 4, label 100, 10.0.0.0/24.
        assert_eq!(
            labeled_entries(14, 1, 4, &[0x30, 0x00, 0x06, 0x41, 10, 0, 0]),
            vec![(None, vec![(100, 0, 1)], None, None, vec![24, 10, 0, 0])]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_labeled_ipv6_nlri() {
        // SAFI 4, AFI 2 (RFC 8277, Section 2): label 3, 2001:db8::/32.
        assert_eq!(
            labeled_entries(14, 2, 4, &[0x38, 0x00, 0x00, 0x31, 0x20, 0x01, 0x0d, 0xb8]),
            vec![(
                None,
                vec![(3, 0, 1)],
                None,
                None,
                vec![32, 0x20, 0x01, 0x0d, 0xb8]
            )]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_labeled_multiple_labels() {
        // RFC 8277, Section 2.3: labels 100 (S=0) and 200 (S=1), 10.0.0.0/24.
        assert_eq!(
            labeled_entries(
                14,
                1,
                4,
                &[0x48, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81, 10, 0, 0]
            ),
            vec![(
                None,
                vec![(100, 0, 0), (200, 0, 1)],
                None,
                None,
                vec![24, 10, 0, 0]
            )]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_labeled_single_label_s_bit_ignored() {
        // RFC 8277, Section 2.2: with a single label the S bit "MUST be
        // ignored on reception". Label 100 with S=0 and Rsrv bits set.
        assert_eq!(
            labeled_entries(14, 1, 4, &[0x30, 0x00, 0x06, 0x4e, 10, 0, 0]),
            vec![(None, vec![(100, 7, 0)], None, None, vec![24, 10, 0, 0])]
        );
    }

    #[test]
    fn parse_bgp_update_mp_unreach_vpn_ipv4_withdraw() {
        // RFC 8277, Section 2.4: Compatibility field 0x800000, then RD and
        // prefix.
        let mut nlri = vec![0x70, 0x80, 0x00, 0x00];
        nlri.extend_from_slice(&RD_65000_100);
        nlri.extend_from_slice(&[10, 0, 0]);
        assert_eq!(
            labeled_entries(15, 1, 128, &nlri),
            vec![(
                None,
                vec![],
                Some(0x80_0000),
                Some(RD_65000_100.to_vec()),
                vec![24, 10, 0, 0]
            )]
        );
    }

    #[test]
    fn parse_bgp_update_mp_unreach_labeled_withdraw_zero_compatibility() {
        // RFC 8277, Section 2.4: "some implementations set it to 0x000000".
        assert_eq!(
            labeled_entries(15, 1, 4, &[0x30, 0, 0, 0, 10, 0, 0]),
            vec![(None, vec![], Some(0), None, vec![24, 10, 0, 0])]
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_labeled_add_path() {
        // RFC 8277, Section 2.2: "If the procedures of [RFC7911] are being
        // used, a four-octet "path identifier" ... precedes the Length field."
        let nlri = [
            0, 0, 0, 1, 0x30, 0x00, 0x06, 0x41, 10, 0, 0, //
            0, 0, 0, 2, 0x30, 0x00, 0x0c, 0x81, 10, 0, 1,
        ];
        assert_eq!(
            labeled_entries(14, 1, 4, &nlri),
            vec![
                (Some(1), vec![(100, 0, 1)], None, None, vec![24, 10, 0, 0]),
                (Some(2), vec![(200, 0, 1)], None, None, vec![24, 10, 0, 1]),
            ]
        );
    }

    #[test]
    fn parse_bgp_update_mp_labeled_malformed_is_raw() {
        for (type_code, safi, nlri) in [
            // Length shorter than one label.
            (14, 4, &[0x10, 0x00, 0x06][..]),
            // Entry overruns the NLRI field.
            (14, 4, &[0x30, 0x00, 0x06, 0x41, 10]),
            // VPN-IPv4 prefix longer than 32 bits (RFC 8277, Section 2.2).
            (
                14,
                128,
                &[
                    24 + 64 + 40,
                    0,
                    0x06,
                    0x41,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    10,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            // Withdrawal shorter than the Compatibility field and RD.
            (15, 128, &[0x40, 0x80, 0, 0, 0, 0, 0, 0, 0]),
        ] {
            assert_eq!(
                mp_raw(type_code, 1, safi, nlri),
                Some(nlri.to_vec()),
                "nlri {nlri:?}"
            );
        }
    }

    #[test]
    fn format_nlri_prefix_from_scratch() {
        let scratch = [24u8, 10, 0, 0, 32, 0x20, 0x01, 0x0d, 0xb8];
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &scratch,
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        format_nlri_ipv4_prefix(&FieldValue::Scratch(0..4), &ctx, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"10.0.0.0/24\"");
        let mut out = Vec::new();
        format_nlri_ipv6_prefix(&FieldValue::Scratch(4..9), &ctx, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"2001:db8::/32\"");
        // An out-of-range scratch reference formats as an empty string.
        let mut out = Vec::new();
        format_nlri_ipv4_prefix(&FieldValue::Scratch(8..20), &ctx, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"\"");
    }

    // -------------------------------------------------------------------
    // AS_PATH AS number size hints from the same UPDATE (RFC 6793,
    // Sections 4.1 and 4.2.2 — https://www.rfc-editor.org/rfc/rfc6793#section-4.2.2).
    // -------------------------------------------------------------------

    /// AS_PATH that is valid both as 4-octet AS_SEQUENCE { 65538, 16842755 }
    /// and as 2-octet AS_SEQUENCE { 1, 2 } + AS_SET { 3 }.
    const AMBIGUOUS_AS_PATH: [u8; 10] = [2, 2, 0, 1, 0, 2, 1, 1, 0, 3];

    /// Helper: dissect an UPDATE whose first attribute is the ambiguous
    /// AS_PATH followed by `other_attrs`.
    fn dissect_ambiguous_as_path_with(other_attrs: &[u8]) -> (Vec<(u8, Vec<u32>)>, Option<u8>) {
        let mut attrs = build_attr(0x40, 2, &AMBIGUOUS_AS_PATH);
        attrs.extend_from_slice(other_attrs);
        let data = build_update(&attrs, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let size = match first_attr_as_number_size(&buf) {
            Some(FieldValue::U8(v)) => Some(v),
            None => None,
            other => panic!("unexpected as_number_size {other:?}"),
        };
        (first_attr_as_path_segments(&buf), size)
    }

    #[test]
    fn parse_bgp_update_as_path_two_octet_hint_from_as4_path() {
        // AS4_PATH is only sent towards OLD speakers, whose AS_PATH uses
        // 2-octet AS numbers (RFC 6793, Section 4.2.2).
        let mut as4_path = vec![2, 1];
        as4_path.extend_from_slice(&200_000u32.to_be_bytes());
        assert_eq!(
            dissect_ambiguous_as_path_with(&build_attr(0xC0, 17, &as4_path)),
            (vec![(2, vec![1, 2]), (1, vec![3])], Some(2))
        );
    }

    #[test]
    fn parse_bgp_update_as_path_two_octet_hint_from_as4_aggregator() {
        let mut as4_aggregator = 200_000u32.to_be_bytes().to_vec();
        as4_aggregator.extend_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            dissect_ambiguous_as_path_with(&build_attr(0xC0, 18, &as4_aggregator)),
            (vec![(2, vec![1, 2]), (1, vec![3])], Some(2))
        );
    }

    #[test]
    fn parse_bgp_update_as_path_size_hint_from_aggregator_length() {
        // AGGREGATOR uses the same AS number size as AS_PATH (RFC 6793,
        // Section 4.1): 6 octets means 2-octet, 8 octets means 4-octet.
        assert_eq!(
            dissect_ambiguous_as_path_with(&build_attr(0xC0, 7, &[0xFD, 0xE9, 192, 0, 2, 1])),
            (vec![(2, vec![1, 2]), (1, vec![3])], Some(2))
        );
        assert_eq!(
            dissect_ambiguous_as_path_with(&build_attr(0xC0, 7, &[0, 1, 0, 0, 192, 0, 2, 1])),
            (vec![(2, vec![65538, 16_842_755])], Some(4))
        );
    }

    /// Bytes consumed, AS_PATH segments and `as_number_size` of one UPDATE.
    type DissectedAsPath = (usize, Vec<(u8, Vec<u32>)>, Option<u8>);

    /// Helper: dissect one UPDATE with [`BgpDissector::dissect_message`].
    fn dissect_message_as_path(attrs: &[u8], as_size: Option<AsNumberSize>) -> DissectedAsPath {
        let data = build_update(attrs, &[]);
        let mut buf = DissectBuffer::new();
        let consumed = BgpDissector
            .dissect_message(&data, &mut buf, 0, as_size)
            .unwrap();
        let size = first_attr_as_number_size(&buf).and_then(|v| v.as_u8());
        (consumed, first_attr_as_path_segments(&buf), size)
    }

    #[test]
    fn dissect_message_known_two_octet_as_size() {
        // An encapsulating protocol (e.g. BMP's A flag, RFC 7854, Section
        // 4.2) says the AS_PATH uses 2-octet AS numbers.
        let attrs = build_attr(0x40, 2, &AMBIGUOUS_AS_PATH);
        let (consumed, segments, size) =
            dissect_message_as_path(&attrs, Some(AsNumberSize::TwoOctet));
        assert_eq!(consumed, 23 + attrs.len());
        assert_eq!(segments, vec![(2, vec![1, 2]), (1, vec![3])]);
        assert_eq!(size, Some(2));
    }

    #[test]
    fn dissect_message_known_four_octet_as_size_overrides_inference() {
        // AS4_PATH would select 2-octet, but the known size wins.
        let mut attrs = build_attr(0x40, 2, &AMBIGUOUS_AS_PATH);
        let mut as4_path = vec![2, 1];
        as4_path.extend_from_slice(&200_000u32.to_be_bytes());
        attrs.extend_from_slice(&build_attr(0xC0, 17, &as4_path));
        let (_, segments, size) = dissect_message_as_path(&attrs, Some(AsNumberSize::FourOctet));
        assert_eq!(segments, vec![(2, vec![65538, 16_842_755])]);
        assert_eq!(size, Some(4));
    }

    #[test]
    fn dissect_message_known_size_that_does_not_fit_falls_back() {
        // One 2-octet AS number: not a valid 4-octet AS_PATH.
        let attrs = build_attr(0x40, 2, &[2, 1, 0xFD, 0xE9]);
        let (_, segments, size) = dissect_message_as_path(&attrs, Some(AsNumberSize::FourOctet));
        assert_eq!(segments, vec![(2, vec![65001])]);
        assert_eq!(size, Some(2));
    }

    #[test]
    fn dissect_message_without_as_size_infers_and_stops_after_one_message() {
        let mut data = build_update(&build_attr(0x40, 2, &AMBIGUOUS_AS_PATH), &[]);
        let first_len = data.len();
        data.extend_from_slice(&build_keepalive());
        let mut buf = DissectBuffer::new();
        let consumed = BgpDissector
            .dissect_message(&data, &mut buf, 0, None)
            .unwrap();
        assert_eq!(consumed, first_len);
        assert_eq!(buf.layers().len(), 1);
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(4)));
    }

    #[test]
    fn dissect_message_truncated() {
        let data = build_keepalive();
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            BgpDissector.dissect_message(&data[..10], &mut buf, 0, None),
            Err(PacketError::Truncated {
                expected: 19,
                actual: 10
            })
        ));
    }

    #[test]
    fn parse_bgp_update_as_path_hint_ignored_when_it_does_not_fit() {
        // A 2-octet hint does not override an AS_PATH that is only valid
        // with 4-octet AS numbers.
        let mut as_path = vec![2, 1];
        as_path.extend_from_slice(&65536u32.to_be_bytes());
        let mut attrs = build_attr(0x40, 2, &as_path);
        attrs.extend_from_slice(&build_attr(0xC0, 7, &[0xFD, 0xE9, 192, 0, 2, 1]));
        let data = build_update(&attrs, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(first_attr_as_path_segments(&buf), vec![(2, vec![65536])]);
        assert_eq!(first_attr_as_number_size(&buf), Some(FieldValue::U8(4)));
    }

    // -------------------------------------------------------------------
    // Undecodable tail of a plain prefix / MUP MP NLRI block is kept raw
    // (RFC 4760, Section 5 — https://www.rfc-editor.org/rfc/rfc4760#section-5).
    // -------------------------------------------------------------------

    #[test]
    fn parse_bgp_update_mp_reach_prefix_tail_is_raw() {
        // 10.0.0.0/24 followed by a prefix length of 40 (> 32 for IPv4).
        let val = build_mp_reach(1, 1, &[192, 0, 2, 1], &[24, 10, 0, 0, 40, 1, 2]);
        let data = build_single_attr_update(14, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let FieldValue::Array(ref nlri) = *nested_field_value(&buf, &mp, "nlri") else {
            panic!("expected Array");
        };
        assert_eq!(nlri_entry_ranges(&buf, nlri).len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &mp, "nlri_raw"),
            FieldValue::Bytes(&[40, 1, 2])
        );
    }

    #[test]
    fn parse_bgp_update_mp_unreach_invalid_prefixes_are_raw() {
        // No entry decodes at all: the whole block is kept raw.
        let val = build_mp_unreach(1, 1, &[40, 1, 2]);
        let data = build_single_attr_update(15, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &mp, "withdrawn_routes").is_none());
        assert_eq!(
            *nested_field_value(&buf, &mp, "withdrawn_routes_raw"),
            FieldValue::Bytes(&[40, 1, 2])
        );
    }

    // ---------------------------------------------------------------------
    // Path attribute value decoding: OTC, AIGP, PMSI_TUNNEL, Tunnel
    // Encapsulation, BGP-LS Attribute, BGPsec_Path, ATTR_SET, SFP and BFD
    // Discriminator.
    // ---------------------------------------------------------------------

    /// Helper: the direct element objects of the first path attribute's Array
    /// `value`.
    fn first_attr_value_array_objs(buf: &DissectBuffer<'_>) -> Vec<core::ops::Range<u32>> {
        let FieldValue::Array(ref arr) = *extract_pa_value(buf) else {
            panic!("expected Array value, got {:?}", extract_pa_value(buf));
        };
        nlri_entry_ranges(buf, arr)
    }

    /// Helper: the direct element objects of the named Array field in `range`.
    fn array_objs(
        buf: &DissectBuffer<'_>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> Vec<core::ops::Range<u32>> {
        let FieldValue::Array(ref arr) = *nested_field_value(buf, range, name) else {
            panic!("expected Array for {name}");
        };
        nlri_entry_ranges(buf, arr)
    }

    #[test]
    fn parse_bgp_update_otc() {
        // Example from the issue: flags 0xC0, type 35, length 4, AS 64500.
        let data = build_update(&[0xc0, 0x23, 0x04, 0x00, 0x00, 0xfb, 0xf4], &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::U32(64500));
    }

    #[test]
    fn parse_bgp_update_otc_bad_length_is_raw() {
        // RFC 9234, Section 5: "a length of 4 octets".
        let data = build_update(&build_attr(0xc0, 35, &[0, 0xfb, 0xf4]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&[0, 0xfb, 0xf4]));
    }

    #[test]
    fn parse_bgp_update_aigp() {
        // RFC 7311, Section 3: AIGP TLV (Type 1, Length 11, 8-octet metric)
        // followed by a TLV of an unknown type, which is kept as bytes.
        let mut val = vec![1u8];
        val.extend_from_slice(&11u16.to_be_bytes());
        val.extend_from_slice(&1_000_000u64.to_be_bytes());
        val.extend_from_slice(&[2, 0, 5, 0xaa, 0xbb]);
        let data = build_update(&build_attr(0x80, 26, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let tlvs = first_attr_value_array_objs(&buf);
        assert_eq!(tlvs.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "type"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "length"),
            FieldValue::U16(11)
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "metric"),
            FieldValue::U64(1_000_000)
        );
        assert!(nested_field_by_name_opt(&buf, &tlvs[0], "value").is_none());
        assert_eq!(
            *nested_field_value(&buf, &tlvs[1], "type"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[1], "value"),
            FieldValue::Bytes(&[0xaa, 0xbb])
        );
        assert!(nested_field_by_name_opt(&buf, &tlvs[1], "metric").is_none());
    }

    #[test]
    fn parse_bgp_update_aigp_malformed_is_raw() {
        // RFC 7311, Section 3: "the minimum length is 3". A TLV Length below
        // 3, or one that overruns the attribute, keeps the value raw.
        // An AIGP TLV must have Length 11 (RFC 7311, Section 3).
        for val in [
            &[1u8, 0, 2][..],
            &[1, 0, 11, 0, 0, 0, 0][..],
            &[1, 0, 7, 0, 0, 0, 5][..],
        ] {
            let data = build_update(&build_attr(0x80, 26, val), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(val));
        }
    }

    #[test]
    fn parse_bgp_update_pmsi_tunnel_ingress_replication() {
        // RFC 6514, Section 5: Flags (L bit set), Tunnel Type 6 (Ingress
        // Replication), MPLS Label 100 in the high-order 20 bits, and the
        // unicast tunnel endpoint as Tunnel Identifier.
        let val = [0x01, 6, 0x00, 0x06, 0x41, 192, 0, 2, 1];
        let data = build_update(&build_attr(0xc0, 22, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj, "pmsi_flags"),
            FieldValue::U8(1)
        );
        let tunnel_type = nested_field_by_name(&buf, &obj, "tunnel_type");
        assert_eq!(tunnel_type.value, FieldValue::U8(6));
        assert_eq!(
            (tunnel_type.descriptor.display_fn.unwrap())(&tunnel_type.value, &[]),
            Some("Ingress Replication")
        );
        assert_eq!(
            *nested_field_value(&buf, &obj, "mpls_label"),
            FieldValue::U32(100)
        );
        assert_eq!(
            *nested_field_value(&buf, &obj, "tunnel_endpoint"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert!(nested_field_by_name_opt(&buf, &obj, "tunnel_identifier").is_none());
    }

    #[test]
    fn parse_bgp_update_pmsi_tunnel_ingress_replication_ipv6() {
        let mut val = vec![0x00, 6, 0, 0, 0];
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = build_update(&build_attr(0xc0, 22, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj, "tunnel_endpoint"),
            FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn parse_bgp_update_pmsi_tunnel_other_type_keeps_identifier_bytes() {
        // RFC 6514, Section 5: PIM-SM Tree (4), <Sender Address, P-Multicast
        // Group>. Tunnel identifiers other than Ingress Replication stay bytes.
        let val = [0x00, 4, 0, 0, 0, 192, 0, 2, 1, 239, 1, 1, 1];
        let data = build_update(&build_attr(0xc0, 22, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj, "tunnel_type"),
            FieldValue::U8(4)
        );
        assert_eq!(
            *nested_field_value(&buf, &obj, "mpls_label"),
            FieldValue::U32(0)
        );
        assert_eq!(
            *nested_field_value(&buf, &obj, "tunnel_identifier"),
            FieldValue::Bytes(&[192, 0, 2, 1, 239, 1, 1, 1])
        );
        assert!(nested_field_by_name_opt(&buf, &obj, "tunnel_endpoint").is_none());
    }

    #[test]
    fn parse_bgp_update_pmsi_tunnel_no_identifier_and_truncated() {
        // Tunnel Type 0 "No tunnel information present": no identifier.
        let data = build_update(&build_attr(0xc0, 22, &[0x01, 0, 0, 0, 0]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let obj = first_attr_value_obj_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &obj, "tunnel_identifier").is_none());
        assert!(nested_field_by_name_opt(&buf, &obj, "tunnel_endpoint").is_none());

        // Shorter than the 5-octet fixed part: raw.
        let data = build_update(&build_attr(0xc0, 22, &[0x01, 6, 0, 0]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&[0x01, 6, 0, 0]));
    }

    /// Helper: a Tunnel Encapsulation sub-TLV (RFC 9012, Section 2), with a
    /// 2-octet length for types 128-255.
    fn build_tunnel_sub_tlv(sub_type: u8, value: &[u8]) -> Vec<u8> {
        let mut raw = vec![sub_type];
        if sub_type >= 128 {
            raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            raw.push(value.len() as u8);
        }
        raw.extend_from_slice(value);
        raw
    }

    #[test]
    fn parse_bgp_update_tunnel_encapsulation() {
        // RFC 9012, Section 2: one VXLAN (8) Tunnel TLV carrying the Tunnel
        // Egress Endpoint (6), Color (4), UDP Destination Port (8), Protocol
        // Type (2), Encapsulation (1) and a 2-octet-length sub-TLV (128).
        let mut subs = Vec::new();
        subs.extend(build_tunnel_sub_tlv(6, &[0, 0, 0, 0, 0, 1, 192, 0, 2, 1]));
        subs.extend(build_tunnel_sub_tlv(4, &[0x03, 0x0b, 0, 0, 0, 0, 0, 100]));
        subs.extend(build_tunnel_sub_tlv(8, &4789u16.to_be_bytes()));
        subs.extend(build_tunnel_sub_tlv(2, &0x6558u16.to_be_bytes()));
        subs.extend(build_tunnel_sub_tlv(1, &[0, 0, 0, 0, 0, 0, 0, 10]));
        subs.extend(build_tunnel_sub_tlv(128, &[1, 2, 3]));
        let mut val = 8u16.to_be_bytes().to_vec();
        val.extend_from_slice(&(subs.len() as u16).to_be_bytes());
        val.extend_from_slice(&subs);
        let data = build_update(&build_attr(0xc0, 23, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        let tunnels = array_objs(&buf, &obj, "tunnels");
        assert_eq!(tunnels.len(), 1);
        let tunnel_type = nested_field_by_name(&buf, &tunnels[0], "tunnel_type");
        assert_eq!(tunnel_type.value, FieldValue::U16(8));
        assert_eq!(
            (tunnel_type.descriptor.display_fn.unwrap())(&tunnel_type.value, &[]),
            Some("VXLAN Encapsulation")
        );
        assert_eq!(
            *nested_field_value(&buf, &tunnels[0], "length"),
            FieldValue::U16(subs.len() as u16)
        );

        let subs = array_objs(&buf, &tunnels[0], "sub_tlvs");
        assert_eq!(subs.len(), 6);
        // Tunnel Egress Endpoint (RFC 9012, Section 3.1).
        let sub_type = nested_field_by_name(&buf, &subs[0], "type");
        assert_eq!(sub_type.value, FieldValue::U8(6));
        assert_eq!(
            (sub_type.descriptor.display_fn.unwrap())(&sub_type.value, &[]),
            Some("Tunnel Egress Endpoint")
        );
        assert_eq!(
            *nested_field_value(&buf, &subs[0], "length"),
            FieldValue::U16(10)
        );
        assert_eq!(
            *nested_field_value(&buf, &subs[0], "address_family"),
            FieldValue::U16(1)
        );
        assert_eq!(
            *nested_field_value(&buf, &subs[0], "address"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        // Color (RFC 9012, Section 3.4.2).
        assert_eq!(
            *nested_field_value(&buf, &subs[1], "color"),
            FieldValue::U32(100)
        );
        assert_eq!(
            *nested_field_value(&buf, &subs[1], "flags"),
            FieldValue::U16(0)
        );
        // UDP Destination Port (RFC 9012, Section 3.3.2).
        assert_eq!(
            *nested_field_value(&buf, &subs[2], "udp_port"),
            FieldValue::U16(4789)
        );
        // Protocol Type (RFC 9012, Section 3.4.1).
        assert_eq!(
            *nested_field_value(&buf, &subs[3], "protocol_type"),
            FieldValue::U16(0x6558)
        );
        // Encapsulation (RFC 9012, Section 3.2) and the 2-octet-length
        // sub-TLV stay bytes.
        assert_eq!(
            *nested_field_value(&buf, &subs[4], "value"),
            FieldValue::Bytes(&[0, 0, 0, 0, 0, 0, 0, 10])
        );
        assert_eq!(
            *nested_field_value(&buf, &subs[5], "length"),
            FieldValue::U16(3)
        );
        assert_eq!(
            *nested_field_value(&buf, &subs[5], "value"),
            FieldValue::Bytes(&[1, 2, 3])
        );
    }

    #[test]
    fn parse_bgp_update_tunnel_encapsulation_sub_tlv_variants() {
        // RFC 9012, Section 3.1: Address Family 0 (next hop, no Address) and
        // IPv6; a Color sub-TLV that does not start with 0x030b and a
        // malformed endpoint are kept as bytes (Sections 3.4.2 and 13).
        let mut subs = Vec::new();
        subs.extend(build_tunnel_sub_tlv(6, &[0, 0, 0, 0, 0, 0]));
        let mut v6 = vec![0, 0, 0, 0, 0, 2];
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        subs.extend(build_tunnel_sub_tlv(6, &v6));
        subs.extend(build_tunnel_sub_tlv(4, &[0x00, 0x02, 0, 0, 0, 0, 0, 100]));
        subs.extend(build_tunnel_sub_tlv(6, &[0, 0, 0, 0, 0, 1, 192, 0]));
        let mut val = 7u16.to_be_bytes().to_vec(); // IP in IP
        val.extend_from_slice(&(subs.len() as u16).to_be_bytes());
        val.extend_from_slice(&subs);
        let data = build_update(&build_attr(0xc0, 23, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        let tunnels = array_objs(&buf, &obj, "tunnels");
        let subs = array_objs(&buf, &tunnels[0], "sub_tlvs");
        assert_eq!(
            *nested_field_value(&buf, &subs[0], "address_family"),
            FieldValue::U16(0)
        );
        assert!(nested_field_by_name_opt(&buf, &subs[0], "address").is_none());
        assert_eq!(
            *nested_field_value(&buf, &subs[1], "address"),
            FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert!(nested_field_by_name_opt(&buf, &subs[2], "color").is_none());
        assert_eq!(
            *nested_field_value(&buf, &subs[2], "value"),
            FieldValue::Bytes(&[0x00, 0x02, 0, 0, 0, 0, 0, 100])
        );
        assert!(nested_field_by_name_opt(&buf, &subs[3], "address").is_none());
        assert_eq!(
            *nested_field_value(&buf, &subs[3], "value"),
            FieldValue::Bytes(&[0, 0, 0, 0, 0, 1, 192, 0])
        );
    }

    #[test]
    fn parse_bgp_update_tunnel_encapsulation_malformed_is_raw() {
        // A sub-TLV that overruns its Tunnel TLV, and a Tunnel TLV that
        // overruns the attribute (RFC 9012, Section 13), keep the value raw.
        let overrun_sub = [0, 8, 0, 3, 6, 10, 0];
        let overrun_tlv = [0, 8, 0, 9, 8, 2, 0x12];
        for val in [&overrun_sub[..], &overrun_tlv[..], &[0, 8, 0][..]] {
            let data = build_update(&build_attr(0xc0, 23, val), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(val));
        }
    }

    #[test]
    fn parse_bgp_update_bgp_ls_attribute() {
        // RFC 9552, Section 5.3: Node Name (1026) and IGP Metric (1095) TLVs,
        // each a 2-octet Type, 2-octet Length and Value (Section 5.1).
        let mut val = Vec::new();
        val.extend_from_slice(&1026u16.to_be_bytes());
        val.extend_from_slice(&2u16.to_be_bytes());
        val.extend_from_slice(b"r1");
        val.extend_from_slice(&1095u16.to_be_bytes());
        val.extend_from_slice(&3u16.to_be_bytes());
        val.extend_from_slice(&[0, 0, 10]);
        let data = build_update(&build_attr(0x80, 29, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        let tlvs = array_objs(&buf, &obj, "tlvs");
        assert_eq!(tlvs.len(), 2);
        let tlv_type = nested_field_by_name(&buf, &tlvs[0], "type");
        assert_eq!(tlv_type.value, FieldValue::U16(1026));
        assert_eq!(
            (tlv_type.descriptor.display_fn.unwrap())(&tlv_type.value, &[]),
            Some("Node Name")
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "length"),
            FieldValue::U16(2)
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "value"),
            FieldValue::Bytes(b"r1")
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[1], "value"),
            FieldValue::Bytes(&[0, 0, 10])
        );
    }

    #[test]
    fn parse_bgp_update_bgp_ls_attribute_malformed_is_raw() {
        let val = [0x04, 0x02, 0x00, 0x05, b'r'];
        let data = build_update(&build_attr(0x80, 29, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&val));
    }

    /// Helper: a BGPsec_Path value (RFC 8205, Section 3) with the given
    /// Secure_Path Segments `(pCount, Flags, AS)` and one Signature_Block of
    /// Algorithm Suite 1 whose Signature Segments carry `sig_len`-octet
    /// signatures.
    fn build_bgpsec_path(segments: &[(u8, u8, u32)], sig_len: usize) -> Vec<u8> {
        let mut val = Vec::new();
        val.extend_from_slice(&((2 + 6 * segments.len()) as u16).to_be_bytes());
        for &(pcount, flags, asn) in segments {
            val.push(pcount);
            val.push(flags);
            val.extend_from_slice(&asn.to_be_bytes());
        }
        let block_len = 2 + 1 + segments.len() * (20 + 2 + sig_len);
        val.extend_from_slice(&(block_len as u16).to_be_bytes());
        val.push(1); // Algorithm Suite Identifier
        for i in 0..segments.len() {
            val.extend_from_slice(&[i as u8 + 0xa0; 20]); // SKI
            val.extend_from_slice(&(sig_len as u16).to_be_bytes());
            val.extend(std::iter::repeat_n(0x5a, sig_len));
        }
        val
    }

    #[test]
    fn parse_bgp_update_bgpsec_path() {
        let val = build_bgpsec_path(&[(1, 0x00, 65001), (2, 0x80, 65002)], 4);
        let data = build_update(&build_attr(0x90, 33, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj, "secure_path_length"),
            FieldValue::U16(14)
        );
        let segs = array_objs(&buf, &obj, "secure_path");
        assert_eq!(segs.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &segs[1], "pcount"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *nested_field_value(&buf, &segs[1], "flags"),
            FieldValue::U8(0x80)
        );
        assert_eq!(
            *nested_field_value(&buf, &segs[1], "asn"),
            FieldValue::U32(65002)
        );

        let blocks = array_objs(&buf, &obj, "signature_blocks");
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &blocks[0], "length"),
            FieldValue::U16(2 + 1 + 2 * 26)
        );
        assert_eq!(
            *nested_field_value(&buf, &blocks[0], "algorithm_suite"),
            FieldValue::U8(1)
        );
        let sigs = array_objs(&buf, &blocks[0], "signature_segments");
        assert_eq!(sigs.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &sigs[1], "ski"),
            FieldValue::Bytes(&[0xa1; 20])
        );
        assert_eq!(
            *nested_field_value(&buf, &sigs[1], "signature_length"),
            FieldValue::U16(4)
        );
        assert_eq!(
            *nested_field_value(&buf, &sigs[1], "signature"),
            FieldValue::Bytes(&[0x5a; 4])
        );
    }

    #[test]
    fn parse_bgp_update_bgpsec_path_malformed_is_raw() {
        // Secure_Path Length not 2 + 6n, a Signature_Block that overruns the
        // attribute, and a truncated Signature Segment keep the value raw.
        let mut bad_sp_len = build_bgpsec_path(&[(1, 0, 65001)], 4);
        bad_sp_len[1] = 7;
        let mut bad_block = build_bgpsec_path(&[(1, 0, 65001)], 4);
        bad_block[9] += 1;
        let mut bad_sig = build_bgpsec_path(&[(1, 0, 65001)], 4);
        bad_sig[32] = 9;
        // "A Signature_Block ... has exactly one Signature Segment ... for each
        // Secure_Path Segment", and there are "one or two Signature_Blocks".
        let mut empty_block = build_bgpsec_path(&[(1, 0, 65001)], 4);
        empty_block.truncate(8);
        empty_block.extend_from_slice(&[0, 3, 1]);
        let one = build_bgpsec_path(&[(1, 0, 65001)], 4);
        let mut three_blocks = one.clone();
        for _ in 0..2 {
            three_blocks.extend_from_slice(&one[8..]);
        }
        let mut two_blocks = one.clone();
        two_blocks.extend_from_slice(&one[8..]);
        let data = build_update(&build_attr(0x90, 33, &two_blocks), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let obj = first_attr_value_obj_range(&buf);
        assert_eq!(array_objs(&buf, &obj, "signature_blocks").len(), 2);
        for val in [
            bad_sp_len,
            bad_block,
            bad_sig,
            empty_block,
            three_blocks,
            vec![0],
        ] {
            let data = build_update(&build_attr(0x90, 33, &val), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&val));
        }
    }

    #[test]
    fn parse_bgp_update_attr_set() {
        // RFC 6368, Section 5: Origin AS 65001, then ORIGIN, a 4-octet AS_PATH
        // and LOCAL_PREF encoded as path attributes.
        let mut val = 65001u32.to_be_bytes().to_vec();
        val.extend(build_attr(0x40, 1, &[0]));
        let mut as_path = vec![2, 1];
        as_path.extend_from_slice(&65001u32.to_be_bytes());
        val.extend(build_attr(0x40, 2, &as_path));
        val.extend(build_attr(0x40, 5, &100u32.to_be_bytes()));
        let data = build_update(&build_attr(0xc0, 128, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &obj, "origin_as"),
            FieldValue::U32(65001)
        );
        let attrs = array_objs(&buf, &obj, "path_attributes");
        assert_eq!(attrs.len(), 3);
        assert_eq!(
            *nested_field_value(&buf, &attrs[0], "type_code"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *nested_field_value(&buf, &attrs[0], "value"),
            FieldValue::U8(0)
        );
        // "The AS_PATH and AGGREGATOR attributes contained within an ATTR_SET
        // attribute MUST be encoded using 4-octet AS numbers".
        assert_eq!(
            *nested_field_value(&buf, &attrs[1], "as_number_size"),
            FieldValue::U8(4)
        );
        assert_eq!(
            *nested_field_value(&buf, &attrs[2], "value"),
            FieldValue::U32(100)
        );
        // The UPDATE carries no MP attribute: no top-level afi/safi.
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "afi").is_none());
    }

    #[test]
    fn parse_bgp_update_attr_set_with_mp_reach_is_raw() {
        // RFC 6368, Section 5: "The ATTR_SET attribute SHALL be considered
        // malformed if ... The original path attributes carried in the
        // variable-length attribute data include the MP_REACH or MP_UNREACH
        // attribute." The whole value is kept raw and does not set the
        // top-level afi/safi.
        let mp_reach = [
            0u8, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        ];
        for type_code in [14u8, 15] {
            let mut val = 65001u32.to_be_bytes().to_vec();
            val.extend(build_attr(0x40, 1, &[0]));
            val.extend(build_attr(0x80, type_code, &mp_reach));
            let data = build_update(&build_attr(0xc0, 128, &val), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&val));
            let layer = &buf.layers()[0];
            assert!(buf.field_by_name(layer, "afi").is_none());
        }
    }

    #[test]
    fn parse_bgp_update_attr_set_nested_attributes_constrained() {
        // Inside an ATTR_SET a further ATTR_SET is kept raw, and "The AS_PATH
        // and AGGREGATOR attributes contained within an ATTR_SET attribute MUST
        // be encoded using 4-octet AS numbers" (RFC 6368, Section 5): a
        // 2-octet AS_PATH or a 6-octet AGGREGATOR is kept raw.
        let inner_set = [0u8, 0, 0xfd, 0xe9, 0x40, 1, 1, 0];
        let as_path_2 = [2u8, 2, 0xfd, 0xe9, 0xfd, 0xea];
        let aggregator_2 = [0xfd, 0xe9, 192, 0, 2, 1];
        let aggregator_4 = [0, 0, 0xfd, 0xe9, 192, 0, 2, 1];
        let mut val = 65001u32.to_be_bytes().to_vec();
        val.extend(build_attr(0xc0, 128, &inner_set));
        val.extend(build_attr(0x40, 2, &as_path_2));
        val.extend(build_attr(0xc0, 7, &aggregator_2));
        val.extend(build_attr(0xc0, 7, &aggregator_4));
        let data = build_update(&build_attr(0xc0, 128, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        let attrs = array_objs(&buf, &obj, "path_attributes");
        assert_eq!(attrs.len(), 4);
        assert_eq!(
            *nested_field_value(&buf, &attrs[0], "value"),
            FieldValue::Bytes(&inner_set)
        );
        assert_eq!(
            *nested_field_value(&buf, &attrs[1], "value"),
            FieldValue::Bytes(&as_path_2)
        );
        assert!(nested_field_by_name_opt(&buf, &attrs[1], "as_number_size").is_none());
        assert_eq!(
            *nested_field_value(&buf, &attrs[2], "value"),
            FieldValue::Bytes(&aggregator_2)
        );
        let aggregator = nested_field_by_name(&buf, &attrs[3], "value");
        assert_eq!(aggregator.value, FieldValue::Bytes(&aggregator_4));
        assert!(aggregator.descriptor.format_fn.is_some());
        let raw = nested_field_by_name(&buf, &attrs[2], "value");
        assert!(raw.descriptor.format_fn.is_none());
    }

    #[test]
    fn parse_bgp_update_pmsi_tunnel_vni_with_vxlan_encapsulation() {
        // RFC 8365, Section 5.1.3: with a VXLAN encapsulation (Encapsulation
        // Extended Community, RFC 9012 Section 4.1, tunnel type 8) "the entire
        // 24-bit field is used to encode the VNI value". Here VNI 10100
        // (0x002774), which would read as label 631 under RFC 6514.
        let pmsi = [0x00, 6, 0x00, 0x27, 0x74, 192, 0, 2, 1];
        for (tunnel_type, expect_vni) in [(8u8, true), (9, true), (12, true), (10, false)] {
            let mut attrs = build_attr(0xc0, 16, &[0x03, 0x0c, 0, 0, 0, 0, 0, tunnel_type]);
            attrs.extend(build_attr(0xc0, 22, &pmsi));
            let data = build_update(&attrs, &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();

            let layer = &buf.layers()[0];
            let FieldValue::Array(ref pa) =
                buf.field_by_name(layer, "path_attributes").unwrap().value
            else {
                panic!("expected Array");
            };
            let pmsi_attr = &nlri_entry_ranges(&buf, pa)[1];
            let FieldValue::Object(ref obj) = *nested_field_value(&buf, pmsi_attr, "value") else {
                panic!("expected Object");
            };
            if expect_vni {
                assert_eq!(
                    *nested_field_value(&buf, obj, "vni"),
                    FieldValue::U32(10100),
                    "tunnel type {tunnel_type}"
                );
                assert!(nested_field_by_name_opt(&buf, obj, "mpls_label").is_none());
            } else {
                assert_eq!(
                    *nested_field_value(&buf, obj, "mpls_label"),
                    FieldValue::U32(631)
                );
                assert!(nested_field_by_name_opt(&buf, obj, "vni").is_none());
            }
        }
    }

    #[test]
    fn attr_context_scans_encapsulation_community() {
        let vni = |attrs: &[u8]| AttrContext::for_update(attrs).vni_label;
        // Truncated attribute headers or values stop the scan without a match.
        assert!(!vni(&[0xc0]));
        assert!(!vni(&[0xc0, 16]));
        assert!(!vni(&[0xd0, 16, 0]));
        assert!(!vni(&[0xc0, 16, 8, 0x03, 0x0c]));
        // A non-transitive (0x43) community is not the Encapsulation Extended
        // Community; an extended-length attribute is walked.
        assert!(!vni(&[0xc0, 16, 8, 0x43, 0x0c, 0, 0, 0, 0, 0, 8]));
        assert!(vni(&[0xd0, 16, 0, 8, 0x03, 0x0c, 0, 0, 0, 0, 0, 8]));
        // A later attribute is reached past an unrelated one.
        assert!(vni(&[
            0x40, 1, 1, 0, 0xc0, 16, 8, 0x03, 0x0c, 0, 0, 0, 0, 0, 9
        ]));
    }

    #[test]
    fn parse_bgp_update_attr_set_malformed_is_raw() {
        // "Its length is less than 4 octets", and nested path attributes that
        // do not parse, keep the value raw.
        for val in [&[0u8, 0, 0xfd][..], &[0, 0, 0xfd, 0xe9, 0x40, 1, 5, 0][..]] {
            let data = build_update(&build_attr(0xc0, 128, val), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(val));
        }
    }

    #[test]
    fn parse_bgp_update_sfp_attribute() {
        // RFC 9015, Section 3.2.1: 1-octet Type, 2-octet Length (of the data
        // following the Length field), Value.
        let val = [1u8, 0, 2, 0xaa, 0xbb, 2, 0, 0];
        let data = build_update(&build_attr(0xc0, 37, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let tlvs = first_attr_value_array_objs(&buf);
        assert_eq!(tlvs.len(), 2);
        let tlv_type = nested_field_by_name(&buf, &tlvs[0], "type");
        assert_eq!(tlv_type.value, FieldValue::U8(1));
        assert_eq!(
            (tlv_type.descriptor.display_fn.unwrap())(&tlv_type.value, &[]),
            Some("Association TLV")
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "value"),
            FieldValue::Bytes(&[0xaa, 0xbb])
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[1], "length"),
            FieldValue::U16(0)
        );
        assert!(nested_field_by_name_opt(&buf, &tlvs[1], "value").is_none());

        // "TLV length that suggests the TLV extends beyond the end of the SFP
        // attribute" is malformed: raw.
        let bad = [2u8, 0, 3, 0];
        let data = build_update(&build_attr(0xc0, 37, &bad), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&bad));
    }

    #[test]
    fn parse_bgp_update_bfd_discriminator() {
        // RFC 9026, Section 3.1.6: BFD Mode 1 (P2MP BFD Session), BFD
        // Discriminator, and a Source IP Address TLV (Type 1, Length 4).
        let val = [1u8, 0, 0, 0x12, 0x34, 1, 4, 192, 0, 2, 1, 250, 1, 0xee];
        let data = build_update(&build_attr(0xc0, 38, &val), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();

        let obj = first_attr_value_obj_range(&buf);
        let mode = nested_field_by_name(&buf, &obj, "bfd_mode");
        assert_eq!(mode.value, FieldValue::U8(1));
        assert_eq!(
            (mode.descriptor.display_fn.unwrap())(&mode.value, &[]),
            Some("P2MP BFD Session")
        );
        assert_eq!(
            *nested_field_value(&buf, &obj, "bfd_discriminator"),
            FieldValue::U32(0x1234)
        );
        let tlvs = array_objs(&buf, &obj, "optional_tlvs");
        assert_eq!(tlvs.len(), 2);
        let tlv_type = nested_field_by_name(&buf, &tlvs[0], "type");
        assert_eq!(
            (tlv_type.descriptor.display_fn.unwrap())(&tlv_type.value, &[]),
            Some("Source IP Address")
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "length"),
            FieldValue::U8(4)
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[0], "source_address"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert_eq!(
            *nested_field_value(&buf, &tlvs[1], "value"),
            FieldValue::Bytes(&[0xee])
        );
    }

    #[test]
    fn parse_bgp_update_bfd_discriminator_malformed_is_raw() {
        // Shorter than Mode + Discriminator, and Optional TLVs that are "not
        // well formed", keep the value raw.
        // "The BFD Discriminator attribute MUST be considered malformed if its
        // length is smaller than 11 octets or if Optional TLVs are present but
        // not well formed."
        for val in [
            &[1u8, 0, 0, 0][..],
            &[1, 0, 0, 0, 1][..],
            &[1, 0, 0, 0, 1, 1, 4, 192, 0][..],
            &[1, 0, 0, 0, 1, 1, 4, 192, 0, 2, 1, 250, 5, 0][..],
            // Source IP Address TLV: "The Length field is 4 for the IPv4
            // address family and 16 for the IPv6 address family.  The TLV is
            // considered malformed if the field is set to any other value."
            &[1, 0, 0, 0, 1, 1, 5, 192, 0, 2, 1, 9][..],
        ] {
            let data = build_update(&build_attr(0xc0, 38, val), &[]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&data, &mut buf, 0).unwrap();
            assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(val));
        }
    }

    #[test]
    fn path_attribute_value_name_tables() {
        // IANA BGP Path Attributes.
        for (v, expected) in [
            (24u8, "Traffic Engineering"),
            (25, "IPv6 Address Specific Extended Community"),
            (27, "PE Distinguisher Labels"),
            (36, "BGP Domain Path (D-PATH)"),
            (37, "SFP attribute"),
            (38, "BFD Discriminator"),
            (41, "BIER"),
            (128, "ATTR_SET"),
        ] {
            assert_eq!(path_attr_type_name(v), Some(expected), "type {v}");
        }
        assert_eq!(path_attr_type_name(0), None);

        // IANA P-Multicast Service Interface Tunnel (PMSI Tunnel) Types.
        assert_eq!(
            pmsi_tunnel_type_name(0),
            Some("No tunnel information present")
        );
        assert_eq!(pmsi_tunnel_type_name(0x0B), Some("BIER"));
        assert_eq!(pmsi_tunnel_type_name(0x09), None);

        // IANA BGP Tunnel Encapsulation Attribute Tunnel Types / Sub-TLVs.
        assert_eq!(tunnel_type_name(2), Some("GRE"));
        assert_eq!(tunnel_type_name(15), Some("SR Policy"));
        assert_eq!(tunnel_type_name(0), None);
        assert_eq!(tunnel_sub_tlv_name(1), Some("Encapsulation"));
        assert_eq!(tunnel_sub_tlv_name(128), Some("Segment List"));
        assert_eq!(tunnel_sub_tlv_name(0), None);

        // IANA BGP-LS Node/Link/Prefix Descriptor and Attribute TLVs.
        assert_eq!(bgp_ls_tlv_name(256), Some("Local Node Descriptors"));
        assert_eq!(bgp_ls_tlv_name(1095), Some("IGP Metric"));
        assert_eq!(bgp_ls_tlv_name(1157), Some("Opaque Prefix Attribute"));
        assert_eq!(bgp_ls_tlv_name(0), None);

        // IANA AIGP, SFP attribute TLV, BFD Mode and BFD Discriminator
        // Optional TLV types.
        assert_eq!(aigp_tlv_type_name(1), Some("AIGP"));
        assert_eq!(aigp_tlv_type_name(2), None);
        assert_eq!(sfp_tlv_type_name(5), Some("SFP Traversal With MPLS"));
        assert_eq!(sfp_tlv_type_name(0), None);
        assert_eq!(bfd_mode_name(0), None);
        assert_eq!(bfd_optional_tlv_type_name(2), None);
    }

    #[test]
    fn field_schema_exposes_new_path_attribute_value_children() {
        fn find<'a>(descs: &'a [FieldDescriptor], name: &str) -> Option<&'a FieldDescriptor> {
            descs.iter().find(|d| d.name == name)
        }
        let descs = BgpDissector.field_descriptors();
        let pa = find(descs, "path_attributes").unwrap().children.unwrap();
        let value_children = find(pa, "value").unwrap().children.unwrap();
        for name in [
            "metric",
            "pmsi_flags",
            "tunnel_type",
            "mpls_label",
            "vni",
            "tunnel_endpoint",
            "tunnel_identifier",
            "tunnels",
            "tlvs",
            "secure_path_length",
            "secure_path",
            "signature_blocks",
            "origin_as",
            "path_attributes",
            "bfd_mode",
            "bfd_discriminator",
            "optional_tlvs",
        ] {
            let child =
                find(value_children, name).unwrap_or_else(|| panic!("{name} missing from union"));
            assert!(child.optional, "{name} in a union must be optional");
        }

        // The union holds one descriptor per name.
        for (i, d) in value_children.iter().enumerate() {
            assert!(
                !value_children[i + 1..].iter().any(|o| o.name == d.name),
                "duplicate {} in the value union",
                d.name
            );
        }

        // ATTR_SET nests path attributes one level deep; their `value` union
        // does not recurse into another `path_attributes`.
        let nested = find(value_children, "path_attributes")
            .unwrap()
            .children
            .unwrap();
        for name in [
            "flags",
            "type_code",
            "attr_length",
            "value",
            "as_number_size",
        ] {
            assert!(find(nested, name).is_some(), "{name} missing");
        }
        let nested_value = find(nested, "value").unwrap().children.unwrap();
        assert!(find(nested_value, "tunnels").is_some());
        assert!(find(nested_value, "path_attributes").is_none());
        assert!(find(nested_value, "origin_as").is_none());

        for (name, children) in [
            ("tunnels", &["tunnel_type", "length", "sub_tlvs"][..]),
            ("tlvs", &["type", "length", "value"][..]),
            ("secure_path", &["pcount", "flags", "asn"][..]),
            (
                "signature_blocks",
                &["length", "algorithm_suite", "signature_segments"][..],
            ),
            (
                "optional_tlvs",
                &["type", "length", "source_address", "value"][..],
            ),
        ] {
            let d = find(value_children, name).unwrap().children.unwrap();
            for c in children {
                assert!(find(d, c).is_some(), "{c} missing from {name}");
            }
        }
    }

    #[test]
    fn path_attribute_name_tables_have_unique_non_empty_names() {
        // Walk every code point of each table: each name is non-empty and
        // unique within its table, and the tables hold the expected number
        // of registered values (IANA registries cited on each function).
        fn check<T: Copy>(
            values: impl Iterator<Item = T>,
            f: fn(T) -> Option<&'static str>,
        ) -> usize {
            let names: Vec<&str> = values.filter_map(f).collect();
            for (i, n) in names.iter().enumerate() {
                assert!(!n.is_empty());
                assert!(!names[i + 1..].contains(n), "duplicate name {n}");
            }
            names.len()
        }
        assert_eq!(check(0..=u8::MAX, path_attr_type_name), 31);
        assert_eq!(check(0..=u8::MAX, pmsi_tunnel_type_name), 14);
        assert_eq!(check(0..=u16::MAX, tunnel_type_name), 13);
        assert_eq!(check(0..=u8::MAX, tunnel_sub_tlv_name), 19);
        assert_eq!(check(0..=u16::MAX, bgp_ls_tlv_name), 109);
        assert_eq!(check(0..=u8::MAX, aigp_tlv_type_name), 1);
        assert_eq!(check(0..=u8::MAX, sfp_tlv_type_name), 5);
        assert_eq!(check(0..=u8::MAX, bfd_mode_name), 1);
        assert_eq!(check(0..=u8::MAX, bfd_optional_tlv_type_name), 1);
    }

    // ---------------------------------------------------------------------
    // Extended Communities (RFC 4360 / RFC 7153) and IPv6 Address Specific
    // Extended Communities (RFC 5701) as structured objects.
    // ---------------------------------------------------------------------

    /// Helper: dissect an UPDATE whose only attribute is EXTENDED COMMUNITIES
    /// (type 16) or, with `type_code` 25, IPv6 Address Specific Extended
    /// Community, and run `check` on each community object range.
    fn with_ext_communities(
        type_code: u8,
        value: &[u8],
        check: impl FnOnce(&DissectBuffer<'_>, &[core::ops::Range<u32>]),
    ) {
        let data = build_update(&build_attr(0xc0, type_code, value), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let comms = first_attr_value_array_objs(&buf);
        check(&buf, &comms);
    }

    /// Helper: the display name of the named field of an object, resolved
    /// with the object's fields as siblings (as the serializer does).
    fn display_of(
        buf: &DissectBuffer<'_>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> Option<&'static str> {
        let field = nested_field_by_name(buf, range, name);
        let siblings = buf.nested_fields(range);
        (field.descriptor.display_fn?)(&field.value, siblings)
    }

    #[test]
    fn parse_bgp_update_extended_communities() {
        // RFC 4360, Section 3.1 (Two-Octet AS Specific Route Target 65001:100)
        // and RFC 9012, Section 4.3 (Color 1000): the type, sub-type and the
        // value sub-fields of each community are separate fields.
        let mut val = vec![0x00, 0x02];
        val.extend_from_slice(&65001u16.to_be_bytes());
        val.extend_from_slice(&100u32.to_be_bytes());
        val.extend_from_slice(&[0x03, 0x0B, 0x00, 0x01]);
        val.extend_from_slice(&1000u32.to_be_bytes());
        with_ext_communities(16, &val, |buf, comms| {
            assert_eq!(comms.len(), 2);
            let rt = &comms[0];
            assert_eq!(*nested_field_value(buf, rt, "type"), FieldValue::U8(0x00));
            assert_eq!(
                display_of(buf, rt, "type"),
                Some("Transitive Two-Octet AS-Specific")
            );
            assert_eq!(
                *nested_field_value(buf, rt, "sub_type"),
                FieldValue::U8(0x02)
            );
            assert_eq!(display_of(buf, rt, "sub_type"), Some("Route Target"));
            assert_eq!(
                *nested_field_value(buf, rt, "global_admin"),
                FieldValue::U32(65001)
            );
            assert_eq!(
                *nested_field_value(buf, rt, "local_admin"),
                FieldValue::U32(100)
            );
            assert!(nested_field_by_name_opt(buf, rt, "value").is_none());

            let color = &comms[1];
            assert_eq!(display_of(buf, color, "sub_type"), Some("Color"));
            assert_eq!(
                *nested_field_value(buf, color, "color_flags"),
                FieldValue::U16(1)
            );
            assert_eq!(
                *nested_field_value(buf, color, "color"),
                FieldValue::U32(1000)
            );
        });
    }

    #[test]
    fn parse_bgp_update_extended_communities_admin_layouts() {
        // RFC 4360, Sections 3.1-3.2, RFC 5668, Section 2 and RFC 8955,
        // Section 7.4 (rt-redirect 0x8008 / 0x8108 / 0x8208) share the
        // Global / Local Administrator layouts.
        let cases: [([u8; 8], &str, FieldValue<'static>, u32); 8] = [
            (
                [0x00, 0x03, 0xfd, 0xe9, 0, 0, 1, 0xf4],
                "Route Origin",
                FieldValue::U32(65001),
                500,
            ),
            (
                [0x01, 0x02, 192, 168, 1, 1, 0, 100],
                "Route Target",
                FieldValue::Ipv4Addr([192, 168, 1, 1]),
                100,
            ),
            (
                [0x01, 0x03, 10, 0, 0, 1, 0, 200],
                "Route Origin",
                FieldValue::Ipv4Addr([10, 0, 0, 1]),
                200,
            ),
            (
                [0x02, 0x02, 0, 1, 0, 0, 0, 100],
                "Route Target",
                FieldValue::U32(65536),
                100,
            ),
            (
                [0x01, 0x07, 192, 0, 2, 1, 0, 0],
                "OSPF Router ID",
                FieldValue::Ipv4Addr([192, 0, 2, 1]),
                0,
            ),
            (
                [0x80, 0x08, 0xfd, 0xe9, 0, 0, 0, 100],
                "Flow spec rt-redirect AS-2octet",
                FieldValue::U32(65001),
                100,
            ),
            (
                [0x81, 0x08, 192, 0, 2, 1, 0, 100],
                "Flow spec rt-redirect IPv4",
                FieldValue::Ipv4Addr([192, 0, 2, 1]),
                100,
            ),
            (
                [0x82, 0x08, 0, 0, 0xfd, 0xe9, 0, 100],
                "Flow spec rt-redirect AS-4octet",
                FieldValue::U32(65001),
                100,
            ),
        ];
        for (bytes, name, global, local) in cases {
            with_ext_communities(16, &bytes, |buf, comms| {
                let c = &comms[0];
                assert_eq!(display_of(buf, c, "sub_type"), Some(name), "{bytes:02x?}");
                assert_eq!(*nested_field_value(buf, c, "global_admin"), global);
                assert_eq!(
                    *nested_field_value(buf, c, "local_admin"),
                    FieldValue::U32(local)
                );
            });
        }
    }

    #[test]
    fn parse_bgp_update_extended_communities_link_bandwidth() {
        // RFC 10005, Section 2: Type 0x00 / 0x40, Sub-Type 0x04, 2-octet
        // Global Administrator and a 4-octet IEEE 754 bandwidth in bytes per
        // second (here 125000000.0, 1 Gb/s).
        for type_high in [0x00u8, 0x40] {
            let mut val = vec![type_high, 0x04, 0xfd, 0xe9];
            val.extend_from_slice(&125_000_000f32.to_bits().to_be_bytes());
            with_ext_communities(16, &val, |buf, comms| {
                let c = &comms[0];
                assert_eq!(display_of(buf, c, "sub_type"), Some("Link Bandwidth"));
                assert_eq!(
                    *nested_field_value(buf, c, "global_admin"),
                    FieldValue::U32(65001)
                );
                let bw = nested_field_by_name(buf, c, "bandwidth");
                assert_eq!(
                    bw.value,
                    FieldValue::Bytes(&125_000_000f32.to_bits().to_be_bytes())
                );
                assert_eq!(
                    call_format_fn(bw.descriptor.format_fn.unwrap(), &bw.value),
                    "125000000"
                );
                assert!(nested_field_by_name_opt(buf, c, "local_admin").is_none());
            });
        }
    }

    #[test]
    fn parse_bgp_update_extended_communities_evpn() {
        // RFC 7432, Sections 7.5-7.7 and RFC 9135, Section 8.1.
        let mut val = Vec::new();
        val.extend_from_slice(&[0x06, 0x00, 0x01, 0x00, 0, 0, 0, 5]); // MAC Mobility
        val.extend_from_slice(&[0x06, 0x01, 0x01, 0x00, 0, 0x00, 0x06, 0x41]); // ESI Label 100
        val.extend_from_slice(&[0x06, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // ES-Import RT
        val.extend_from_slice(&[0x06, 0x03, 0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]); // Router's MAC
        val.extend_from_slice(&[0x06, 0x04, 0, 0, 0, 0, 0x05, 0xdc]); // Layer 2 Attributes
        with_ext_communities(16, &val, |buf, comms| {
            assert_eq!(comms.len(), 5);
            assert_eq!(display_of(buf, &comms[0], "type"), Some("EVPN"));
            assert_eq!(display_of(buf, &comms[0], "sub_type"), Some("MAC Mobility"));
            assert_eq!(
                *nested_field_value(buf, &comms[0], "evpn_flags"),
                FieldValue::U8(1)
            );
            assert_eq!(
                *nested_field_value(buf, &comms[0], "sequence_number"),
                FieldValue::U32(5)
            );
            assert_eq!(display_of(buf, &comms[1], "sub_type"), Some("ESI Label"));
            assert_eq!(
                *nested_field_value(buf, &comms[1], "evpn_flags"),
                FieldValue::U8(1)
            );
            assert_eq!(
                *nested_field_value(buf, &comms[1], "esi_label"),
                FieldValue::U32(100)
            );
            assert_eq!(
                display_of(buf, &comms[2], "sub_type"),
                Some("ES-Import Route Target")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[2], "mac"),
                FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
            );
            assert_eq!(
                display_of(buf, &comms[3], "sub_type"),
                Some("EVPN Router's MAC")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[3], "mac"),
                FieldValue::MacAddr(MacAddr([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            );
            assert_eq!(
                display_of(buf, &comms[4], "sub_type"),
                Some("EVPN Layer 2 Attributes")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[4], "value"),
                FieldValue::Bytes(&[0, 0, 0, 0, 0x05, 0xdc])
            );
        });
    }

    #[test]
    fn parse_bgp_update_extended_communities_opaque_and_ospf() {
        // RFC 9012, Section 4.1 (Encapsulation, VXLAN), RFC 7432, Section 7.8
        // (Default Gateway), RFC 4577, Section 4.2.6 (OSPF Route Type 0x0306
        // and its backward-compatible 0x8000 form, OSPF Domain Identifier
        // 0x0005 / 0x8005) and RFC 8097, Section 2 (Origin Validation State).
        let mut val = Vec::new();
        val.extend_from_slice(&[0x03, 0x0c, 0, 0, 0, 0, 0, 8]);
        val.extend_from_slice(&[0x03, 0x0d, 0, 0, 0, 0, 0, 0]);
        val.extend_from_slice(&[0x03, 0x06, 0, 0, 0, 1, 5, 1]);
        val.extend_from_slice(&[0x80, 0x00, 0, 0, 0, 0, 3, 0]);
        val.extend_from_slice(&[0x00, 0x05, 0, 0, 0, 0, 0, 7]);
        val.extend_from_slice(&[0x80, 0x05, 0, 0, 0, 0, 0, 7]);
        val.extend_from_slice(&[0x43, 0x00, 0, 0, 0, 0, 0, 2]);
        with_ext_communities(16, &val, |buf, comms| {
            assert_eq!(comms.len(), 7);
            assert_eq!(
                display_of(buf, &comms[0], "sub_type"),
                Some("Encapsulation")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[0], "encap_tunnel_type"),
                FieldValue::U16(8)
            );
            assert_eq!(
                display_of(buf, &comms[0], "encap_tunnel_type"),
                Some("VXLAN Encapsulation")
            );
            assert_eq!(
                display_of(buf, &comms[1], "sub_type"),
                Some("Default Gateway")
            );
            // "The Value field of this community is reserved": kept as bytes.
            assert_eq!(
                *nested_field_value(buf, &comms[1], "value"),
                FieldValue::Bytes(&[0; 6])
            );
            for (c, area, route_type, options) in [(&comms[2], 1, 5, 1), (&comms[3], 0, 3, 0)] {
                assert_eq!(
                    *nested_field_value(buf, c, "ospf_area"),
                    FieldValue::U32(area)
                );
                assert_eq!(
                    *nested_field_value(buf, c, "ospf_route_type"),
                    FieldValue::U8(route_type)
                );
                assert_eq!(
                    *nested_field_value(buf, c, "ospf_options"),
                    FieldValue::U8(options)
                );
            }
            assert_eq!(
                display_of(buf, &comms[2], "sub_type"),
                Some("OSPF Route Type")
            );
            assert_eq!(
                display_of(buf, &comms[3], "sub_type"),
                Some("OSPF Route Type (deprecated)")
            );
            assert_eq!(
                display_of(buf, &comms[4], "sub_type"),
                Some("OSPF Domain Identifier")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[5], "local_admin"),
                FieldValue::U32(7)
            );
            let ov = nested_field_by_name(buf, &comms[6], "validation_state");
            assert_eq!(ov.value, FieldValue::U8(2));
            assert_eq!(
                display_of(buf, &comms[6], "validation_state"),
                Some("Invalid")
            );
            assert_eq!(
                display_of(buf, &comms[6], "sub_type"),
                Some("BGP Origin Validation State")
            );
        });
    }

    #[test]
    fn parse_bgp_update_extended_communities_flowspec_actions() {
        // RFC 8955, Sections 7.1-7.5.
        let mut val = Vec::new();
        val.extend_from_slice(&[0x80, 0x06, 0xfd, 0xe9]);
        val.extend_from_slice(&0f32.to_bits().to_be_bytes());
        val.extend_from_slice(&[0x80, 0x0c, 0, 0]);
        val.extend_from_slice(&1000f32.to_bits().to_be_bytes());
        val.extend_from_slice(&[0x80, 0x07, 0, 0, 0, 0, 0, 0x03]);
        val.extend_from_slice(&[0x80, 0x09, 0, 0, 0, 0, 0, 0xee]);
        with_ext_communities(16, &val, |buf, comms| {
            assert_eq!(comms.len(), 4);
            assert_eq!(
                display_of(buf, &comms[0], "sub_type"),
                Some("Flow spec traffic-rate-bytes")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[0], "global_admin"),
                FieldValue::U32(65001)
            );
            let rate = nested_field_by_name(buf, &comms[1], "rate");
            assert_eq!(
                call_format_fn(rate.descriptor.format_fn.unwrap(), &rate.value),
                "1000"
            );
            assert_eq!(
                display_of(buf, &comms[2], "sub_type"),
                Some("Flow spec traffic-action")
            );
            assert_eq!(
                *nested_field_value(buf, &comms[2], "value"),
                FieldValue::Bytes(&[0, 0, 0, 0, 0, 0x03])
            );
            assert_eq!(
                *nested_field_value(buf, &comms[2], "sample"),
                FieldValue::U8(1)
            );
            assert_eq!(
                *nested_field_value(buf, &comms[2], "terminal_action"),
                FieldValue::U8(1)
            );
            // "the 6 least significant bits of the Extended Community value".
            assert_eq!(
                *nested_field_value(buf, &comms[3], "dscp"),
                FieldValue::U8(0x2e)
            );
        });
    }

    #[test]
    fn parse_bgp_update_extended_communities_mup() {
        // draft-ietf-bess-mup-safi-01, Section 3.2: Direct / Interwork Segment
        // in 2-Octet AS, IPv4 and 4-Octet AS layouts.
        let cases: [([u8; 8], &str, FieldValue<'static>, u32); 6] = [
            (
                [0x0C, 0x00, 0xFD, 0xE9, 0, 0, 0, 100],
                "MUP Direct Segment (2-Octet AS)",
                FieldValue::U32(65001),
                100,
            ),
            (
                [0x0C, 0x01, 10, 0, 0, 1, 0, 100],
                "MUP Direct Segment (IPv4 Address)",
                FieldValue::Ipv4Addr([10, 0, 0, 1]),
                100,
            ),
            (
                [0x0C, 0x02, 0, 0, 0xFD, 0xE9, 0, 100],
                "MUP Direct Segment (4-Octet AS)",
                FieldValue::U32(65001),
                100,
            ),
            (
                [0x0C, 0x03, 0xFD, 0xEA, 0, 0, 0, 200],
                "MUP Interwork Segment (2-Octet AS)",
                FieldValue::U32(65002),
                200,
            ),
            (
                [0x0C, 0x04, 10, 0, 0, 2, 0, 200],
                "MUP Interwork Segment (IPv4 Address)",
                FieldValue::Ipv4Addr([10, 0, 0, 2]),
                200,
            ),
            (
                [0x0C, 0x05, 0, 0, 0xFD, 0xEA, 0, 200],
                "MUP Interwork Segment (4-Octet AS)",
                FieldValue::U32(65002),
                200,
            ),
        ];
        for (bytes, name, global, local) in cases {
            with_ext_communities(16, &bytes, |buf, comms| {
                let c = &comms[0];
                assert_eq!(display_of(buf, c, "sub_type"), Some(name));
                assert_eq!(*nested_field_value(buf, c, "global_admin"), global);
                assert_eq!(
                    *nested_field_value(buf, c, "local_admin"),
                    FieldValue::U32(local)
                );
            });
        }
        // Unknown MUP sub-type: value bytes, no name.
        with_ext_communities(16, &[0x0C, 0x99, 1, 2, 3, 4, 5, 6], |buf, comms| {
            assert_eq!(display_of(buf, &comms[0], "sub_type"), None);
            assert_eq!(
                *nested_field_value(buf, &comms[0], "value"),
                FieldValue::Bytes(&[1, 2, 3, 4, 5, 6])
            );
        });
    }

    #[test]
    fn parse_bgp_update_extended_communities_unknown() {
        with_ext_communities(16, &[0x99, 0x99, 1, 2, 3, 4, 5, 6], |buf, comms| {
            let c = &comms[0];
            assert_eq!(*nested_field_value(buf, c, "type"), FieldValue::U8(0x99));
            assert_eq!(display_of(buf, c, "type"), None);
            assert_eq!(display_of(buf, c, "sub_type"), None);
            assert_eq!(
                *nested_field_value(buf, c, "value"),
                FieldValue::Bytes(&[1, 2, 3, 4, 5, 6])
            );
        });
        // A length that is not a multiple of 8 keeps the attribute raw.
        let data = build_update(&build_attr(0xc0, 16, &[0, 2, 0, 1]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&[0, 2, 0, 1]));
    }

    #[test]
    fn parse_bgp_update_ipv6_address_specific_extended_community() {
        // RFC 5701, Section 2: Type 0x00, Sub-Type 0x02 (Route Target), a
        // 16-octet Global Administrator IPv6 address and a 2-octet Local
        // Administrator.
        let mut val = vec![0x00, 0x02];
        val.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        val.extend_from_slice(&100u16.to_be_bytes());
        val.extend_from_slice(&[0x40, 0x99]);
        val.extend_from_slice(&[0u8; 18]);
        with_ext_communities(25, &val, |buf, comms| {
            assert_eq!(comms.len(), 2);
            let c = &comms[0];
            assert_eq!(
                display_of(buf, c, "type"),
                Some("Transitive IPv6-Address-Specific")
            );
            assert_eq!(display_of(buf, c, "sub_type"), Some("Route Target"));
            assert_eq!(
                *nested_field_value(buf, c, "global_admin"),
                FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            );
            assert_eq!(
                *nested_field_value(buf, c, "local_admin"),
                FieldValue::U32(100)
            );
            assert_eq!(
                display_of(buf, &comms[1], "type"),
                Some("Non-Transitive IPv6-Address-Specific")
            );
            assert_eq!(display_of(buf, &comms[1], "sub_type"), None);
        });
        // A length that is not a multiple of 20 keeps the attribute raw.
        let data = build_update(&build_attr(0xc0, 25, &[0, 2, 0]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(*extract_pa_value(&buf), FieldValue::Bytes(&[0, 2, 0]));
    }

    #[test]
    fn extended_community_name_tables() {
        // IANA BGP Extended Communities registries.
        for (t, name) in [
            (0x00u8, "Transitive Two-Octet AS-Specific"),
            (0x01, "Transitive IPv4-Address-Specific"),
            (0x02, "Transitive Four-Octet AS-Specific"),
            (0x03, "Transitive Opaque"),
            (0x06, "EVPN"),
            (0x40, "Non-Transitive Two-Octet AS-Specific"),
            (0x43, "Non-Transitive Opaque"),
            (0x80, "Generic Transitive"),
            (0x81, "Generic Transitive Part 2"),
            (0x82, "Generic Transitive Part 3"),
        ] {
            assert_eq!(ext_community_type_name(t), Some(name), "type {t:#04x}");
        }
        assert_eq!(ext_community_type_name(0x3f), None);
        assert_eq!(ext_community_sub_type_name(0x00, 0x09), Some("Source AS"));
        assert_eq!(
            ext_community_sub_type_name(0x01, 0x0b),
            Some("VRF Route Import")
        );
        assert_eq!(
            ext_community_sub_type_name(0x06, 0x0a),
            Some("EVI-RT Type 0")
        );
        assert_eq!(ext_community_sub_type_name(0x40, 0x02), None);
        assert_eq!(
            ipv6_ext_community_sub_type_name(0x00, 0x0b),
            Some("VRF Route Import")
        );
        assert_eq!(ipv6_ext_community_sub_type_name(0x40, 0x02), None);
        assert_eq!(origin_validation_state_name(0), Some("Valid"));
        assert_eq!(origin_validation_state_name(1), Some("NotFound"));
        assert_eq!(origin_validation_state_name(3), None);
        // Non-finite IEEE 754 values are written as strings.
        let fmt = EXT_COMMUNITY_FIELDS[FD_EC_RATE].format_fn.unwrap();
        let nan = f32::NAN.to_be_bytes();
        assert_eq!(call_format_fn(fmt, &FieldValue::Bytes(&nan)), "\"NaN\"");
        let v = 1.5f32.to_be_bytes();
        assert_eq!(call_format_fn(fmt, &FieldValue::Bytes(&v)), "1.5");
        assert_eq!(call_format_fn(fmt, &FieldValue::Bytes(&[0; 3])), "null");
    }

    #[test]
    fn extended_community_name_tables_have_unique_non_empty_names() {
        // Walk every (Type, Sub-Type) pair: names are non-empty, and unique
        // within each Type (the same sub-type name recurs across Types, e.g.
        // Route Target).
        for type_high in 0..=u8::MAX {
            let names: Vec<&str> = (0..=u8::MAX)
                .filter_map(|s| ext_community_sub_type_name(type_high, s))
                .collect();
            for (i, n) in names.iter().enumerate() {
                assert!(!n.is_empty());
                assert!(!names[i + 1..].contains(n), "duplicate {n}");
            }
            let v6: Vec<&str> = (0..=u8::MAX)
                .filter_map(|s| ipv6_ext_community_sub_type_name(type_high, s))
                .collect();
            assert!(v6.iter().all(|n| !n.is_empty()));
        }
        let count = |f: fn(u8) -> Option<&'static str>| (0..=u8::MAX).filter_map(f).count();
        assert_eq!(count(ext_community_type_name), 16);
        assert_eq!(count(ipv6_ext_community_type_name), 2);
        let pairs = (0..=u8::MAX)
            .flat_map(|t| (0..=u8::MAX).map(move |s| (t, s)))
            .filter(|&(t, s)| ext_community_sub_type_name(t, s).is_some())
            .count();
        assert_eq!(pairs, 65);
    }

    // ---------------------------------------------------------------------
    // OPEN capabilities 3 / 7 / 8, NOTIFICATION data, ROUTE-REFRESH ORF
    // entries and message types without a body definition.
    // ---------------------------------------------------------------------

    /// Helper: the direct element object ranges of the named Array in `range`.
    fn array_entry_ranges(
        buf: &DissectBuffer<'_>,
        range: &core::ops::Range<u32>,
        name: &str,
    ) -> Vec<core::ops::Range<u32>> {
        let FieldValue::Array(ref arr) = nested_field_by_name(buf, range, name).value else {
            panic!("expected Array for {name}");
        };
        nlri_entry_ranges(buf, arr)
    }

    #[test]
    fn parse_bgp_open_capability_orf() {
        // RFC 5291, Section 5: AFI 1 / SAFI 1 with two ORF types (Address
        // Prefix ORF, receive; CP-ORF, both), then AFI 2 / SAFI 1 with none.
        let caps = cap_tlv(3, &[0, 1, 0, 1, 2, 64, 1, 65, 3, 0, 2, 0, 1, 0]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        assert_eq!(
            buf.resolve_nested_display_name(&range, "code_name"),
            Some("Outbound Route Filtering Capability")
        );
        let entries = array_entry_ranges(&buf, &range, "afi_safis");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "afi"),
            FieldValue::U16(1)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "safi"),
            FieldValue::U16(1)
        );
        let orfs = array_entry_ranges(&buf, &entries[0], "orfs");
        assert_eq!(orfs.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &orfs[0], "orf_type"),
            FieldValue::U8(64)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&orfs[0], "orf_type_name"),
            Some("Address Prefix ORF")
        );
        assert_eq!(
            buf.resolve_nested_display_name(&orfs[0], "send_receive_name"),
            Some("receive")
        );
        assert_eq!(
            buf.resolve_nested_display_name(&orfs[1], "send_receive_name"),
            Some("both")
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[1], "afi"),
            FieldValue::U16(2)
        );
        assert!(array_entry_ranges(&buf, &entries[1], "orfs").is_empty());
    }

    #[test]
    fn parse_bgp_open_capability_orf_malformed_is_raw() {
        // A Number of ORFs that overruns the value leaves it undecoded.
        let caps = cap_tlv(3, &[0, 1, 0, 1, 2, 64, 1]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &range, "afi_safis").is_none());
        assert_eq!(
            *nested_field_value(&buf, &range, "value"),
            FieldValue::Bytes(&[0, 1, 0, 1, 2, 64, 1])
        );
    }

    #[test]
    fn parse_bgp_open_capability_multiple_labels() {
        // RFC 8277, Section 2.1: <AFI, SAFI, Count> triples.
        let caps = cap_tlv(8, &[0, 1, 4, 2, 0, 2, 128, 255]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        let entries = array_entry_ranges(&buf, &range, "afi_safis");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "safi"),
            FieldValue::U16(4)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "label_count"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[1], "afi"),
            FieldValue::U16(2)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[1], "label_count"),
            FieldValue::U8(255)
        );

        // Not a multiple of 4 octets: undecoded.
        let caps = cap_tlv(8, &[0, 1, 4]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &range, "afi_safis").is_none());
    }

    #[test]
    fn parse_bgp_open_capability_bgpsec() {
        // RFC 8205, Section 2.1: Version 0, Dir 1 (send), AFI 2.
        let caps = cap_tlv(7, &[0x08, 0, 2]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &range, "bgpsec_version"),
            FieldValue::U8(0)
        );
        assert_eq!(
            *nested_field_value(&buf, &range, "bgpsec_direction"),
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&range, "bgpsec_direction_name"),
            Some("send")
        );
        assert_eq!(*nested_field_value(&buf, &range, "afi"), FieldValue::U16(2));

        // "The capability length for this capability MUST be set to 3."
        let caps = cap_tlv(7, &[0x08, 0]);
        let data = build_open_with_caps(&caps);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &range, "bgpsec_version").is_none());
    }

    /// Helper: a NOTIFICATION message with the given code, subcode and data.
    fn build_notification(code: u8, subcode: u8, data: &[u8]) -> Vec<u8> {
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&((21 + data.len()) as u16).to_be_bytes());
        raw.push(3);
        raw.push(code);
        raw.push(subcode);
        raw.extend_from_slice(data);
        raw
    }

    #[test]
    fn parse_bgp_notification_shutdown_communication() {
        // RFC 9003, Section 2: Cease / Administrative Shutdown (2) and
        // Administrative Reset (4) with a length-prefixed UTF-8 string.
        let text = "maintenance – back in 2h";
        for subcode in [2u8, 4] {
            let mut body = vec![text.len() as u8];
            body.extend_from_slice(text.as_bytes());
            let raw = build_notification(6, subcode, &body);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "shutdown_communication_length")
                    .unwrap()
                    .value,
                FieldValue::U8(text.len() as u8)
            );
            assert_eq!(
                buf.field_by_name(layer, "shutdown_communication")
                    .unwrap()
                    .value,
                FieldValue::Str(text)
            );
            // The raw data stays available.
            assert_eq!(
                buf.field_by_name(layer, "data").unwrap().value,
                FieldValue::Bytes(&body)
            );
        }

        // "When the length value is zero, no Shutdown Communication field
        // follows."
        let raw = build_notification(6, 2, &[0]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "shutdown_communication_length")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        assert!(buf.field_by_name(layer, "shutdown_communication").is_none());

        // "A receiving BGP speaker MUST NOT interpret invalid UTF-8
        // sequences", and a Length that does not cover exactly the rest of
        // the data is not decoded.
        for body in [&[2u8, 0xff, 0xfe][..], &[5, b'a'][..], &[1, b'a', 1, 2][..]] {
            let raw = build_notification(6, 2, body);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert!(buf.field_by_name(layer, "shutdown_communication").is_none());
            assert!(
                buf.field_by_name(layer, "shutdown_communication_length")
                    .is_none()
            );
        }
    }

    #[test]
    fn parse_bgp_notification_hard_reset() {
        // RFC 8538, Section 3.1: the Hard Reset data encapsulates an Error
        // Code, Subcode and Data — here Cease / Administrative Reset with a
        // Shutdown Communication.
        let raw = build_notification(6, 9, &[6, 4, 3, b'b', b'y', b'e']);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "error_subcode_name"),
            Some("Hard Reset")
        );
        let FieldValue::Object(ref hr) = buf.field_by_name(layer, "hard_reset").unwrap().value
        else {
            panic!("expected Object for hard_reset");
        };
        assert_eq!(
            *nested_field_value(&buf, hr, "error_code"),
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.resolve_nested_display_name(hr, "error_code_name"),
            Some("Cease")
        );
        assert_eq!(
            buf.resolve_nested_display_name(hr, "error_subcode_name"),
            Some("Administrative Reset")
        );
        assert_eq!(
            *nested_field_value(&buf, hr, "shutdown_communication"),
            FieldValue::Str("bye")
        );
        assert_eq!(
            *nested_field_value(&buf, hr, "data"),
            FieldValue::Bytes(&[3, b'b', b'y', b'e'])
        );

        // An encapsulated error without data, and a truncated Hard Reset
        // (fewer than the Error Code and Subcode octets).
        let raw = build_notification(6, 9, &[4, 0]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let FieldValue::Object(ref hr) = buf.field_by_name(layer, "hard_reset").unwrap().value
        else {
            panic!("expected Object for hard_reset");
        };
        assert_eq!(
            buf.resolve_nested_display_name(hr, "error_code_name"),
            Some("Hold Timer Expired")
        );
        assert!(nested_field_by_name_opt(&buf, hr, "data").is_none());

        let raw = build_notification(6, 9, &[4]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "hard_reset").is_none());
    }

    #[test]
    fn notification_subcode_names() {
        // IANA BGP Error Subcodes (RFC 4271, Section 6; RFC 5492; RFC 9234;
        // RFC 6608; RFC 4486; RFC 8538; RFC 9384; RFC 7313).
        for (code, sub, name) in [
            (1u8, 1u8, "Connection Not Synchronized"),
            (1, 3, "Bad Message Type"),
            (2, 2, "Bad Peer AS"),
            (2, 7, "Unsupported Capability"),
            (2, 11, "Role Mismatch"),
            (3, 11, "Malformed AS_PATH"),
            (5, 3, "Receive Unexpected Message in Established State"),
            (6, 9, "Hard Reset"),
            (6, 10, "BFD Down"),
            (7, 1, "Invalid Message Length"),
        ] {
            assert_eq!(error_subcode_name(code, sub), Some(name), "{code}/{sub}");
        }
        assert_eq!(error_subcode_name(1, 0), Some("Unspecific"));
        assert_eq!(error_subcode_name(4, 0), None);
        assert_eq!(error_subcode_name(6, 11), None);
        assert_eq!(error_code_name(9), Some("Loss of LSDB Synchronization"));

        // Through the display_fn, with the sibling `error_code`.
        let raw = build_notification(2, 7, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "error_subcode_name"),
            Some("Unsupported Capability")
        );
    }

    /// Helper: a ROUTE-REFRESH message for (AFI, subtype, SAFI) with `body`
    /// after the fixed part.
    fn build_route_refresh(afi: u16, subtype: u8, safi: u8, body: &[u8]) -> Vec<u8> {
        let mut raw = vec![0xFF; 16];
        raw.extend_from_slice(&((23 + body.len()) as u16).to_be_bytes());
        raw.push(5);
        raw.extend_from_slice(&afi.to_be_bytes());
        raw.push(subtype);
        raw.push(safi);
        raw.extend_from_slice(body);
        raw
    }

    #[test]
    fn parse_bgp_route_refresh_address_prefix_orf() {
        // RFC 5291, Section 4 and RFC 5292, Section 3: IMMEDIATE, one
        // Address Prefix ORF (type 64) with an ADD/PERMIT entry for
        // 10.0.0.0/8 le 24 and a REMOVE-ALL entry.
        let mut entries = vec![0x00];
        entries.extend_from_slice(&10u32.to_be_bytes()); // Sequence
        entries.extend_from_slice(&[9, 24, 8, 10]); // Minlen, Maxlen, Length, Prefix
        entries.push(0x80); // REMOVE-ALL
        let mut body = vec![1, 64];
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        body.extend_from_slice(&entries);
        let raw = build_route_refresh(1, 0, 1, &body);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "when_to_refresh").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "when_to_refresh_name"),
            Some("IMMEDIATE")
        );
        let FieldValue::Array(ref orfs) = buf.field_by_name(layer, "orfs").unwrap().value else {
            panic!("expected Array for orfs");
        };
        let orfs = nlri_entry_ranges(&buf, orfs);
        assert_eq!(orfs.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &orfs[0], "orf_type"),
            FieldValue::U8(64)
        );
        assert_eq!(
            *nested_field_value(&buf, &orfs[0], "length"),
            FieldValue::U16(entries.len() as u16)
        );
        let es = array_entry_ranges(&buf, &orfs[0], "entries");
        assert_eq!(es.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &es[0], "action"),
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_nested_display_name(&es[0], "action_name"),
            Some("ADD")
        );
        assert_eq!(
            buf.resolve_nested_display_name(&es[0], "match_name"),
            Some("PERMIT")
        );
        assert_eq!(
            *nested_field_value(&buf, &es[0], "sequence"),
            FieldValue::U32(10)
        );
        assert_eq!(
            *nested_field_value(&buf, &es[0], "minlen"),
            FieldValue::U8(9)
        );
        assert_eq!(
            *nested_field_value(&buf, &es[0], "maxlen"),
            FieldValue::U8(24)
        );
        let prefix = nested_field_by_name(&buf, &es[0], "prefix");
        assert_eq!(prefix.value, FieldValue::Bytes(&[8, 10]));
        assert_eq!(
            call_format_fn(prefix.descriptor.format_fn.unwrap(), &prefix.value),
            "\"10.0.0.0/8\""
        );
        assert_eq!(
            buf.resolve_nested_display_name(&es[1], "action_name"),
            Some("REMOVE-ALL")
        );
        assert!(nested_field_by_name_opt(&buf, &es[1], "sequence").is_none());
        // Match "is significant only when the value of the Action field is
        // either ADD or REMOVE".
        assert!(nested_field_by_name_opt(&buf, &es[1], "match").is_none());
        assert!(buf.field_by_name(layer, "data").is_none());
    }

    #[test]
    fn parse_bgp_route_refresh_orf_other_types() {
        // IPv6 Address Prefix ORF entry, and an ORF type whose entries are
        // not decoded (CP-ORF, 65): each entry is kept as `value`.
        let mut v6 = vec![0x20];
        v6.extend_from_slice(&1u32.to_be_bytes());
        v6.extend_from_slice(&[0, 0, 32, 0x20, 0x01, 0x0d, 0xb8]);
        let mut body = vec![2, 64];
        body.extend_from_slice(&(v6.len() as u16).to_be_bytes());
        body.extend_from_slice(&v6);
        body.extend_from_slice(&[65, 0, 3, 0xaa, 0xbb, 0xcc]);
        let raw = build_route_refresh(2, 0, 1, &body);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "when_to_refresh_name"),
            Some("DEFER")
        );
        let FieldValue::Array(ref orfs) = buf.field_by_name(layer, "orfs").unwrap().value else {
            panic!("expected Array for orfs");
        };
        let orfs = nlri_entry_ranges(&buf, orfs);
        assert_eq!(orfs.len(), 2);
        let es = array_entry_ranges(&buf, &orfs[0], "entries");
        assert_eq!(
            buf.resolve_nested_display_name(&es[0], "match_name"),
            Some("DENY")
        );
        let prefix = nested_field_by_name(&buf, &es[0], "prefix");
        assert_eq!(
            call_format_fn(prefix.descriptor.format_fn.unwrap(), &prefix.value),
            "\"2001:db8::/32\""
        );
        assert!(nested_field_by_name_opt(&buf, &orfs[1], "entries").is_none());
        assert_eq!(
            *nested_field_value(&buf, &orfs[1], "value"),
            FieldValue::Bytes(&[0xaa, 0xbb, 0xcc])
        );
    }

    #[test]
    fn parse_bgp_route_refresh_malformed_orf_is_raw() {
        // An ORF whose length overruns the message, an Address Prefix ORF
        // entry that overruns its ORF, and a BoRR (RFC 7313) with trailing
        // octets keep the bytes after the fixed part as `data`.
        // An IPv4 prefix Length above 32 is malformed too.
        // So are a body shorter than When-to-refresh + ORF Type + Length, and
        // an entry whose prefix Length reaches past the end of its ORF.
        let cases: [(u8, &[u8]); 6] = [
            (0, &[1, 64, 0, 9, 0]),
            (0, &[1, 64, 0, 3, 0x00, 0, 0]),
            (0, &[1, 64, 0, 13, 0, 0, 0, 0, 1, 0, 0, 33, 10, 0, 0, 0, 0]),
            (0, &[1, 64, 0]),
            (0, &[1, 64, 0, 8, 0x00, 0, 0, 0, 1, 0, 0, 8]),
            (1, &[1, 2, 3]),
        ];
        for (subtype, body) in cases {
            let raw = build_route_refresh(1, subtype, 1, body);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert!(buf.field_by_name(layer, "orfs").is_none());
            assert!(buf.field_by_name(layer, "when_to_refresh").is_none());
            assert_eq!(
                buf.field_by_name(layer, "data").unwrap().value,
                FieldValue::Bytes(body)
            );
        }
    }

    #[test]
    fn parse_bgp_unknown_message_type_keeps_body() {
        // RFC 4271, Section 6.1: an unrecognized Type is a "Bad Message
        // Type" error; the body is still exposed as `data`. A KEEPALIVE
        // longer than its header (Section 4.4) keeps the extra octets too.
        for msg_type in [9u8, 4] {
            let mut raw = vec![0xFF; 16];
            raw.extend_from_slice(&22u16.to_be_bytes());
            raw.push(msg_type);
            raw.extend_from_slice(&[1, 2, 3]);
            let mut buf = DissectBuffer::new();
            BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "data").unwrap().value,
                FieldValue::Bytes(&[1, 2, 3])
            );
        }
        // A bare KEEPALIVE has no `data`.
        let data = build_keepalive();
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "data").is_none());
    }

    #[test]
    fn open_notification_refresh_name_tables() {
        assert_eq!(orf_type_name(64), Some("Address Prefix ORF"));
        assert_eq!(orf_type_name(65), Some("CP-ORF"));
        assert_eq!(orf_type_name(0), None);
        assert_eq!(orf_send_receive_name(2), Some("send"));
        assert_eq!(orf_send_receive_name(0), None);
        assert_eq!(orf_action_name(1), Some("REMOVE"));
        assert_eq!(orf_action_name(3), None);
        assert_eq!(when_to_refresh_name(0), None);
        assert_eq!(bgpsec_direction_name(0), Some("receive"));
        assert_eq!(bgpsec_direction_name(2), None);
        assert_eq!(orf_match_name(0), Some("PERMIT"));
        assert_eq!(orf_match_name(2), None);
        assert_eq!(capability_code_name(7), Some("BGPsec Capability"));
        assert_eq!(capability_code_name(8), Some("Multiple Labels Capability"));
    }

    #[test]
    fn open_notification_refresh_display_fns_ignore_other_types() {
        // Each display_fn names only the U8 it is attached to.
        let other = FieldValue::U16(1);
        for fd in [
            &ORF_CAP_FIELDS[1],
            &ORF_TYPE_FIELD,
            &ORF_ENTRY_FIELDS[FD_ORFE_ACTION],
            &ORF_ENTRY_FIELDS[FD_ORFE_MATCH],
            &OPT_PARAM_CHILDREN[FD_OPT_BGPSEC_DIRECTION],
            &FIELD_DESCRIPTORS[FD_WHEN_TO_REFRESH],
            &ERROR_CODE_FIELD,
            &ERROR_SUBCODE_FIELD,
        ] {
            assert_eq!((fd.display_fn.unwrap())(&other, &[]), None, "{}", fd.name);
        }
    }

    #[test]
    fn notification_subcode_names_rfc4271_and_rfc6608() {
        // RFC 4271, Sections 6.1-6.3 and RFC 6608, Section 4.
        for (code, sub, name) in [
            (1u8, 2u8, "Bad Message Length"),
            (2, 1, "Unsupported Version Number"),
            (2, 3, "Bad BGP Identifier"),
            (2, 4, "Unsupported Optional Parameter"),
            (2, 6, "Unacceptable Hold Time"),
            (3, 1, "Malformed Attribute List"),
            (3, 2, "Unrecognized Well-known Attribute"),
            (3, 3, "Missing Well-known Attribute"),
            (3, 4, "Attribute Flags Error"),
            (3, 5, "Attribute Length Error"),
            (3, 6, "Invalid ORIGIN Attribute"),
            (3, 8, "Invalid NEXT_HOP Attribute"),
            (3, 9, "Optional Attribute Error"),
            (3, 10, "Invalid Network Field"),
            (5, 0, "Unspecified Error"),
            (5, 1, "Receive Unexpected Message in OpenSent State"),
            (5, 2, "Receive Unexpected Message in OpenConfirm State"),
        ] {
            assert_eq!(error_subcode_name(code, sub), Some(name), "{code}/{sub}");
        }
        // Deprecated / unassigned values stay unnamed.
        assert_eq!(error_subcode_name(2, 5), None);
        assert_eq!(error_subcode_name(3, 7), None);
    }

    #[test]
    fn parse_bgp_empty_orf_capability_and_shutdown_data() {
        // An ORF Capability without entries is not decoded.
        let data = build_open_with_caps(&cap_tlv(3, &[]));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let range = single_capability_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &range, "afi_safis").is_none());

        // RFC 9003, Section 2: a Cease / Administrative Shutdown without data
        // carries no Shutdown Communication.
        let raw = build_notification(6, 2, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "shutdown_communication").is_none());
    }

    #[test]
    fn parse_bgp_route_refresh_orf_other_afi_keeps_prefix_raw() {
        // The prefix is formatted as CIDR only for IPv4 and IPv6; for another
        // AFI (here L2VPN) it stays `[Length, Prefix]` (RFC 5292, Section 3).
        let entry = [0x00, 0, 0, 0, 5, 0, 0, 8, 0xaa];
        let mut body = vec![1, 64];
        body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        body.extend_from_slice(&entry);
        let raw = build_route_refresh(25, 0, 70, &body);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let FieldValue::Array(ref orfs) = buf.field_by_name(layer, "orfs").unwrap().value else {
            panic!("expected Array for orfs");
        };
        let orfs = nlri_entry_ranges(&buf, orfs);
        let es = array_entry_ranges(&buf, &orfs[0], "entries");
        assert_eq!(
            *nested_field_value(&buf, &es[0], "sequence"),
            FieldValue::U32(5)
        );
        assert_eq!(
            *nested_field_value(&buf, &es[0], "prefix"),
            FieldValue::Bytes(&[8, 0xaa])
        );
    }

    // ---------------------------------------------------------------------
    // EVPN NLRI (AFI 25 / SAFI 70; RFC 7432, Section 7; RFC 9136, Section 3)
    // ---------------------------------------------------------------------

    /// Helper: run a field's `format_fn` with the buffer's scratch data (for
    /// values assembled in the scratch buffer).
    fn call_format_fn_ctx(buf: &DissectBuffer<'_>, field: &Field<'_>) -> String {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: buf.scratch(),
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        (field.descriptor.format_fn.unwrap())(&field.value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// RD 65000:100 (Type 0) used by the EVPN tests.
    const EVPN_RD: [u8; 8] = [0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64];
    /// A Type 0 ESI used by the EVPN tests.
    const EVPN_ESI: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    /// Helper: an EVPN NLRI entry (Route Type, Length, body).
    fn evpn_route(route_type: u8, body: &[u8]) -> Vec<u8> {
        let mut raw = vec![route_type, body.len() as u8];
        raw.extend_from_slice(body);
        raw
    }

    /// Helper: dissect an UPDATE carrying `attrs` and run `check` on the
    /// entry objects of the MP_REACH_NLRI `nlri` array, which is the last
    /// attribute.
    fn with_evpn_nlri(
        attrs: &[u8],
        check: impl FnOnce(&DissectBuffer<'_>, &[core::ops::Range<u32>]),
    ) {
        let data = build_update(attrs, &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let FieldValue::Array(ref pa) = buf.field_by_name(layer, "path_attributes").unwrap().value
        else {
            panic!("expected Array");
        };
        let attr = nlri_entry_ranges(&buf, pa).pop().unwrap();
        let FieldValue::Object(ref mp) = *nested_field_value(&buf, &attr, "value") else {
            panic!("expected Object");
        };
        assert!(nested_field_by_name_opt(&buf, mp, "nlri_raw").is_none());
        let entries = array_objs(&buf, mp, "nlri");
        check(&buf, &entries);
    }

    /// Helper: an MP_REACH_NLRI attribute (AFI 25, SAFI 70, next hop
    /// 192.0.2.1) carrying `nlri`.
    fn evpn_mp_reach(nlri: &[u8]) -> Vec<u8> {
        build_attr(0x90, 14, &build_mp_reach(25, 70, &[192, 0, 2, 1], nlri))
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_imet() {
        // EVPN IMET route from the issue (RFC 7432, Section 7.3): RD
        // 65000:100, Ethernet Tag 0, Originating Router's IP 192.0.2.1.
        let nlri = [
            0x03, 0x11, 0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64, 0, 0, 0, 0, 0x20, 0xc0, 0, 2, 1,
        ];
        with_evpn_nlri(&evpn_mp_reach(&nlri), |buf, entries| {
            assert_eq!(entries.len(), 1);
            let e = &entries[0];
            assert_eq!(
                *nested_field_value(buf, e, "route_type"),
                FieldValue::U16(3)
            );
            assert_eq!(
                buf.resolve_nested_display_name(e, "route_type_name"),
                Some("Inclusive Multicast Ethernet Tag")
            );
            assert_eq!(*nested_field_value(buf, e, "length"), FieldValue::U8(17));
            let rd = nested_field_by_name(buf, e, "rd");
            assert_eq!(rd.value, FieldValue::Bytes(&EVPN_RD));
            assert_eq!(
                call_format_fn(rd.descriptor.format_fn.unwrap(), &rd.value),
                "\"0:65000:100\""
            );
            assert_eq!(
                *nested_field_value(buf, e, "ethernet_tag_id"),
                FieldValue::U32(0)
            );
            assert_eq!(*nested_field_value(buf, e, "ip_length"), FieldValue::U8(32));
            assert_eq!(
                *nested_field_value(buf, e, "ip_address"),
                FieldValue::Ipv4Addr([192, 0, 2, 1])
            );
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_next_hop() {
        // RFC 7432, Section 9.2.1: "The Next Hop field of the MP_REACH_NLRI
        // attribute of the route MUST be set to the IPv4 or IPv6 address of
        // the advertising PE."
        let data = build_update(&evpn_mp_reach(&[]), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let data = build_update(
            &build_attr(0x90, 14, &build_mp_reach(25, 70, &v6, &[])),
            &[],
        );
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv6Addr(v6)
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_mac_ip() {
        // RFC 7432, Section 7.2: MAC/IP Advertisement with an IPv4 address and
        // MPLS Label1 100 only; then with an IPv6 address and Label2 200
        // (RFC 9135, Section 8.1 —
        // https://www.rfc-editor.org/rfc/rfc9135#section-8.1); then MAC only.
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut body = EVPN_RD.to_vec();
        body.extend_from_slice(&EVPN_ESI);
        body.extend_from_slice(&7u32.to_be_bytes());
        body.push(48);
        body.extend_from_slice(&mac);
        let mut v4 = body.clone();
        v4.extend_from_slice(&[32, 10, 0, 0, 1, 0x00, 0x06, 0x41]);
        let mut v6 = body.clone();
        v6.push(128);
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend_from_slice(&[0x00, 0x06, 0x41, 0x00, 0x0c, 0x81]);
        let mut mac_only = body.clone();
        mac_only.extend_from_slice(&[0, 0x00, 0x06, 0x41]);
        let mut nlri = evpn_route(2, &v4);
        nlri.extend(evpn_route(2, &v6));
        nlri.extend(evpn_route(2, &mac_only));
        with_evpn_nlri(&evpn_mp_reach(&nlri), |buf, entries| {
            assert_eq!(entries.len(), 3);
            let e = &entries[0];
            assert_eq!(
                buf.resolve_nested_display_name(e, "route_type_name"),
                Some("MAC/IP Advertisement")
            );
            let esi = nested_field_by_name(buf, e, "esi");
            assert_eq!(esi.value, FieldValue::Bytes(&EVPN_ESI));
            assert_eq!(
                call_format_fn(esi.descriptor.format_fn.unwrap(), &esi.value),
                "\"00:01:02:03:04:05:06:07:08:09\""
            );
            assert_eq!(
                *nested_field_value(buf, e, "ethernet_tag_id"),
                FieldValue::U32(7)
            );
            assert_eq!(
                *nested_field_value(buf, e, "mac_length"),
                FieldValue::U8(48)
            );
            assert_eq!(
                *nested_field_value(buf, e, "mac"),
                FieldValue::MacAddr(MacAddr(mac))
            );
            assert_eq!(
                *nested_field_value(buf, e, "ip_address"),
                FieldValue::Ipv4Addr([10, 0, 0, 1])
            );
            assert_eq!(
                *nested_field_value(buf, e, "mpls_label1"),
                FieldValue::U32(100)
            );
            assert!(nested_field_by_name_opt(buf, e, "mpls_label2").is_none());

            let e = &entries[1];
            assert_eq!(
                *nested_field_value(buf, e, "ip_length"),
                FieldValue::U8(128)
            );
            assert_eq!(
                *nested_field_value(buf, e, "ip_address"),
                FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            );
            assert_eq!(
                *nested_field_value(buf, e, "mpls_label2"),
                FieldValue::U32(200)
            );

            let e = &entries[2];
            assert_eq!(*nested_field_value(buf, e, "ip_length"), FieldValue::U8(0));
            assert!(nested_field_by_name_opt(buf, e, "ip_address").is_none());
            assert_eq!(
                *nested_field_value(buf, e, "mpls_label1"),
                FieldValue::U32(100)
            );
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_ead_es_ip_prefix() {
        // RFC 7432, Sections 7.1 and 7.4; RFC 9136, Section 3.1.
        let mut ead = EVPN_RD.to_vec();
        ead.extend_from_slice(&EVPN_ESI);
        ead.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
        ead.extend_from_slice(&[0x00, 0x00, 0x01]); // label 0, S bit
        let mut es = EVPN_RD.to_vec();
        es.extend_from_slice(&EVPN_ESI);
        es.push(128);
        es.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut pfx4 = EVPN_RD.to_vec();
        pfx4.extend_from_slice(&[0; 10]);
        pfx4.extend_from_slice(&0u32.to_be_bytes());
        pfx4.extend_from_slice(&[24, 10, 1, 2, 0, 192, 0, 2, 254, 0x00, 0x06, 0x41]);
        let mut pfx6 = EVPN_RD.to_vec();
        pfx6.extend_from_slice(&[0; 10]);
        pfx6.extend_from_slice(&0u32.to_be_bytes());
        pfx6.push(32);
        pfx6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        pfx6.extend_from_slice(&[0; 16]);
        pfx6.extend_from_slice(&[0x00, 0x06, 0x41]);
        let mut nlri = evpn_route(1, &ead);
        nlri.extend(evpn_route(4, &es));
        nlri.extend(evpn_route(5, &pfx4));
        nlri.extend(evpn_route(5, &pfx6));
        with_evpn_nlri(&evpn_mp_reach(&nlri), |buf, entries| {
            assert_eq!(entries.len(), 4);
            assert_eq!(
                buf.resolve_nested_display_name(&entries[0], "route_type_name"),
                Some("Ethernet Auto-discovery")
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "ethernet_tag_id"),
                FieldValue::U32(0xffff_ffff)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "mpls_label"),
                FieldValue::U32(0)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&entries[1], "route_type_name"),
                Some("Ethernet Segment")
            );
            assert_eq!(
                *nested_field_value(buf, &entries[1], "esi"),
                FieldValue::Bytes(&EVPN_ESI)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[1], "ip_length"),
                FieldValue::U8(128)
            );
            let e = &entries[2];
            assert_eq!(
                buf.resolve_nested_display_name(e, "route_type_name"),
                Some("IP Prefix")
            );
            let prefix = nested_field_by_name(buf, e, "prefix");
            assert_eq!(call_format_fn_ctx(buf, prefix), "\"10.1.2.0/24\"");
            assert_eq!(
                *nested_field_value(buf, e, "gateway_ip"),
                FieldValue::Ipv4Addr([192, 0, 2, 254])
            );
            assert_eq!(
                *nested_field_value(buf, e, "mpls_label"),
                FieldValue::U32(100)
            );
            let prefix = nested_field_by_name(buf, &entries[3], "prefix");
            assert_eq!(call_format_fn_ctx(buf, prefix), "\"2001:db8::/32\"");
            assert_eq!(
                *nested_field_value(buf, &entries[3], "gateway_ip"),
                FieldValue::Ipv6Addr([0; 16])
            );
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_vni_with_vxlan_encapsulation() {
        // RFC 8365, Section 5.1.3: with a VXLAN Encapsulation Extended
        // Community, "the entire 24-bit field is used to encode the VNI
        // value" in MPLS Label1 / Label2 and the Ethernet A-D / IP Prefix
        // MPLS Label. VNI 10100 = 0x002774.
        let mut mac_ip = EVPN_RD.to_vec();
        mac_ip.extend_from_slice(&[0; 10]);
        mac_ip.extend_from_slice(&0u32.to_be_bytes());
        mac_ip.extend_from_slice(&[48, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0]);
        mac_ip.extend_from_slice(&[0x00, 0x27, 0x74, 0x00, 0x4e, 0x20]);
        let mut ead = EVPN_RD.to_vec();
        ead.extend_from_slice(&EVPN_ESI);
        ead.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x27, 0x74]);
        let mut nlri = evpn_route(2, &mac_ip);
        nlri.extend(evpn_route(1, &ead));
        let mut attrs = build_attr(0xc0, 16, &[0x03, 0x0c, 0, 0, 0, 0, 0, 8]);
        attrs.extend(evpn_mp_reach(&nlri));
        with_evpn_nlri(&attrs, |buf, entries| {
            assert_eq!(
                *nested_field_value(buf, &entries[0], "vni1"),
                FieldValue::U32(10100)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "vni2"),
                FieldValue::U32(20000)
            );
            assert!(nested_field_by_name_opt(buf, &entries[0], "mpls_label1").is_none());
            assert_eq!(
                *nested_field_value(buf, &entries[1], "vni"),
                FieldValue::U32(10100)
            );
            assert!(nested_field_by_name_opt(buf, &entries[1], "mpls_label").is_none());
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_undecoded_routes_keep_value() {
        // A Route Type without a decoder (RFC 9251 SMET, 6) and a MAC/IP
        // route whose body does not match its layout keep `value`.
        let mut nlri = evpn_route(6, &[1, 2, 3]);
        nlri.extend(evpn_route(2, &[0xaa; 20]));
        with_evpn_nlri(&evpn_mp_reach(&nlri), |buf, entries| {
            assert_eq!(entries.len(), 2);
            assert_eq!(
                buf.resolve_nested_display_name(&entries[0], "route_type_name"),
                Some("Selective Multicast Ethernet Tag Route")
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "value"),
                FieldValue::Bytes(&[1, 2, 3])
            );
            assert_eq!(
                *nested_field_value(buf, &entries[1], "value"),
                FieldValue::Bytes(&[0xaa; 20])
            );
            assert!(nested_field_by_name_opt(buf, &entries[1], "rd").is_none());
        });
    }

    #[test]
    fn parse_bgp_update_mp_unreach_evpn_withdrawn() {
        // RFC 7432, Section 7: withdrawn EVPN routes use the same encoding.
        let mut body = EVPN_RD.to_vec();
        body.extend_from_slice(&[0, 0, 0, 0, 32, 192, 0, 2, 1]);
        let mut wr = evpn_route(3, &body);
        wr.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);
        let val = build_mp_unreach(25, 70, &wr);
        let data = build_single_attr_update(15, &val);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let entries = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(entries.len(), 2);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "ip_address"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[1], "value"),
            FieldValue::Bytes(&[0xaa, 0xbb])
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "withdrawn_routes_raw").is_none());
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_add_path_and_truncated_tail() {
        // RFC 7911, Section 3: a Path Identifier before each EVPN route when
        // the block only parses that way; a truncated tail is kept raw.
        let mut body = EVPN_RD.to_vec();
        body.extend_from_slice(&[0, 0, 0, 0, 32, 192, 0, 2, 1]);
        let route = evpn_route(3, &body);
        let mut nlri = 7u32.to_be_bytes().to_vec();
        nlri.extend_from_slice(&route);
        let data = build_update(&evpn_mp_reach(&nlri), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let entries = array_objs(&buf, &mp, "nlri");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "path_id"),
            FieldValue::U32(7)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "ip_address"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );

        let mut nlri = route.clone();
        nlri.extend_from_slice(&[0x02, 0x30, 0x00]);
        let data = build_update(&evpn_mp_reach(&nlri), &[]);
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(array_objs(&buf, &mp, "nlri").len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &mp, "nlri_raw"),
            FieldValue::Bytes(&[0x02, 0x30, 0x00])
        );
    }

    #[test]
    fn evpn_name_tables() {
        let names: Vec<&str> = (0..=u8::MAX).filter_map(evpn_route_type_name).collect();
        assert_eq!(names.len(), 11);
        assert_eq!(evpn_route_type_name(0), None);
        assert_eq!(evpn_route_type_name(11), Some("Leaf A-D route"));
        assert_eq!(
            call_format_fn(format_esi, &FieldValue::Bytes(&[1, 2])),
            "\"\""
        );
    }

    #[test]
    fn field_schema_exposes_evpn_nlri_children() {
        fn find<'a>(descs: &'a [FieldDescriptor], name: &str) -> Option<&'a FieldDescriptor> {
            descs.iter().find(|d| d.name == name)
        }
        let descs = BgpDissector.field_descriptors();
        let nlri = find(descs, "nlri").unwrap().children.unwrap();
        for name in [
            "route_type",
            "length",
            "rd",
            "esi",
            "ethernet_tag_id",
            "mac_length",
            "mac",
            "ip_length",
            "ip_address",
            "gateway_ip",
            "mpls_label",
            "mpls_label1",
            "mpls_label2",
            "vni",
            "vni1",
            "vni2",
            "value",
            "nlri_length",
            "components",
        ] {
            let child = find(nlri, name).unwrap_or_else(|| panic!("{name} missing"));
            assert!(child.optional, "{name} in a union must be optional");
        }
        for (i, d) in nlri.iter().enumerate() {
            assert!(
                !nlri[i + 1..].iter().any(|o| o.name == d.name),
                "duplicate {} in the NLRI entry union",
                d.name
            );
        }
    }

    #[test]
    fn parse_bgp_update_mp_reach_evpn_layout_mismatches_keep_value() {
        // Field values that break the layouts of RFC 7432, Section 7 and
        // RFC 9136, Section 3.1 keep the whole field as `value`: a MAC Address
        // Length other than 48, an IP Address Length other than 0 / 32 / 128,
        // an IMET route with IP Address Length 0, and an IPv4 IP Prefix Length
        // above 32.
        let mut mac_ip = EVPN_RD.to_vec();
        mac_ip.extend_from_slice(&[0; 14]);
        mac_ip.extend_from_slice(&[40, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 1]);
        let mut bad_ip = EVPN_RD.to_vec();
        bad_ip.extend_from_slice(&[0; 14]);
        bad_ip.extend_from_slice(&[48, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 24, 10, 0, 0, 0, 0, 1]);
        let mut imet = EVPN_RD.to_vec();
        imet.extend_from_slice(&[0, 0, 0, 0, 0]);
        let mut pfx = EVPN_RD.to_vec();
        pfx.extend_from_slice(&[0; 14]);
        pfx.extend_from_slice(&[33, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        for (route_type, body) in [(2u8, mac_ip), (2, bad_ip), (3, imet), (5, pfx)] {
            let nlri = evpn_route(route_type, &body);
            with_evpn_nlri(&evpn_mp_reach(&nlri), |buf, entries| {
                let e = &entries[0];
                assert_eq!(
                    *nested_field_value(buf, e, "value"),
                    FieldValue::Bytes(&body),
                    "route type {route_type}"
                );
                assert!(nested_field_by_name_opt(buf, e, "rd").is_none());
                assert!(nested_field_by_name_opt(buf, e, "prefix").is_none());
            });
        }
    }

    #[test]
    fn parse_bgp_update_mp_reach_l2vpn_vpn_safi_next_hop_is_raw() {
        // A VPN-shaped next hop is not defined for AFI 25: kept raw.
        let nh = [0u8; 24];
        let data = build_update(
            &build_attr(0x90, 14, &build_mp_reach(25, 128, &nh, &[])),
            &[],
        );
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Bytes(&nh)
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "next_hop_rd").is_none());
    }

    #[test]
    fn nlri_union_route_type_name_follows_the_entry_kind() {
        // The schema's `route_type` names a MUP route when the entry has an
        // `architecture_type`, an EVPN route otherwise.
        let descs = BgpDissector.field_descriptors();
        let nlri = descs.iter().find(|d| d.name == "nlri").unwrap();
        let route_type = nlri
            .children
            .unwrap()
            .iter()
            .find(|d| d.name == "route_type")
            .unwrap();
        let display = route_type.display_fn.unwrap();
        let arch = Field {
            descriptor: &MUP_NLRI_CHILDREN[FD_MUP_ARCH_TYPE],
            value: FieldValue::U8(1),
            range: 0..1,
        };
        assert_eq!(
            display(&FieldValue::U16(1), core::slice::from_ref(&arch)),
            mup_route_type_name(1)
        );
        assert_eq!(
            display(&FieldValue::U16(3), &[]),
            Some("Inclusive Multicast Ethernet Tag")
        );
        assert_eq!(display(&FieldValue::U8(3), &[]), None);
        assert_eq!(display(&FieldValue::U16(300), &[]), None);
    }

    #[test]
    fn detect_add_path_evpn_prefers_plain_encoding() {
        let mut body = EVPN_RD.to_vec();
        body.extend_from_slice(&[0, 0, 0, 0, 32, 192, 0, 2, 1]);
        let route = evpn_route(3, &body);
        // Plain framing without a Route Type 0: plain.
        assert!(!detect_add_path_evpn(&route));
        // A route type assigned after RFC 9572 still frames as plain.
        assert!(!detect_add_path_evpn(&evpn_route(200, &[1, 2])));
        let mut add_path = 1u32.to_be_bytes().to_vec();
        add_path.extend_from_slice(&route);
        assert!(detect_add_path_evpn(&add_path));
        // Neither framing: not ADD-PATH.
        assert!(!detect_add_path_evpn(&[0, 0, 0, 1, 3]));
    }

    // ---------------------------------------------------------------------
    // Flow Specification NLRI (SAFI 133 / 134; RFC 8955, Section 4;
    // RFC 8956, Section 3)
    // ---------------------------------------------------------------------

    /// Helper: dissect an MP_REACH_NLRI with (AFI, SAFI) and `nlri` and run
    /// `check` on the `nlri` entry objects.
    fn with_mp_reach_nlri(
        afi: u16,
        safi: u8,
        nlri: &[u8],
        check: impl FnOnce(&DissectBuffer<'_>, &core::ops::Range<u32>, &[core::ops::Range<u32>]),
    ) {
        let data = build_single_attr_update(14, &build_mp_reach(afi, safi, &[], nlri));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let entries = match nested_field_by_name_opt(&buf, &mp, "nlri") {
            Some(_) => array_objs(&buf, &mp, "nlri"),
            None => Vec::new(),
        };
        check(&buf, &mp, &entries);
    }

    /// Helper: the (operator range, value) pairs of a component.
    fn flowspec_operators(
        buf: &DissectBuffer<'_>,
        component: &core::ops::Range<u32>,
    ) -> Vec<core::ops::Range<u32>> {
        array_objs(buf, component, "operators")
    }

    #[test]
    fn parse_bgp_update_mp_reach_flowspec_ipv4_examples() {
        // RFC 8955, Section 4.3.1 (https://www.rfc-editor.org/rfc/rfc8955#section-4.3.1):
        // "all packets to 192.0.2.0/24 and TCP port 25"; Section 4.3.2: "... from 203.0.113.0/24 and port {range [137,
        // 139] or 8080}"; Section 4.3.3: "... to 192.0.2.1/32 and fragment {
        // DF or FF }".
        let mut nlri = vec![
            0x0b, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x03, 0x81, 0x06, 0x04, 0x81, 0x19,
        ];
        nlri.extend_from_slice(&[
            0x12, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x02, 0x18, 0xcb, 0x00, 0x71, 0x04, 0x03, 0x89,
            0x45, 0x8b, 0x91, 0x1f, 0x90,
        ]);
        nlri.extend_from_slice(&[0x09, 0x01, 0x20, 0xc0, 0x00, 0x02, 0x01, 0x0c, 0x80, 0x05]);
        with_mp_reach_nlri(1, 133, &nlri, |buf, mp, entries| {
            assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_none());
            assert_eq!(entries.len(), 3);

            let e = &entries[0];
            assert_eq!(
                *nested_field_value(buf, e, "nlri_length"),
                FieldValue::U16(11)
            );
            let comps = array_objs(buf, e, "components");
            assert_eq!(comps.len(), 3);
            assert_eq!(
                *nested_field_value(buf, &comps[0], "type"),
                FieldValue::U8(1)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&comps[0], "type_name"),
                Some("Destination Prefix")
            );
            let prefix = nested_field_by_name(buf, &comps[0], "prefix");
            assert_eq!(call_format_fn_ctx(buf, prefix), "\"192.0.2.0/24\"");
            assert_eq!(
                buf.resolve_nested_display_name(&comps[1], "type_name"),
                Some("IP Protocol")
            );
            let ops = flowspec_operators(buf, &comps[1]);
            assert_eq!(ops.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &ops[0], "operator"),
                FieldValue::U8(0x81)
            );
            assert_eq!(
                *nested_field_value(buf, &ops[0], "end_of_list"),
                FieldValue::U8(1)
            );
            assert_eq!(*nested_field_value(buf, &ops[0], "and"), FieldValue::U8(0));
            assert_eq!(
                *nested_field_value(buf, &ops[0], "comparison"),
                FieldValue::U8(1)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&ops[0], "comparison_name"),
                Some("==")
            );
            assert_eq!(
                *nested_field_value(buf, &ops[0], "value"),
                FieldValue::U64(6)
            );
            let ops = flowspec_operators(buf, &comps[2]);
            assert_eq!(
                *nested_field_value(buf, &ops[0], "value"),
                FieldValue::U64(25)
            );

            let comps = array_objs(buf, &entries[1], "components");
            let prefix = nested_field_by_name(buf, &comps[1], "prefix");
            assert_eq!(call_format_fn_ctx(buf, prefix), "\"203.0.113.0/24\"");
            let ops = flowspec_operators(buf, &comps[2]);
            assert_eq!(ops.len(), 3);
            assert_eq!(
                buf.resolve_nested_display_name(&ops[0], "comparison_name"),
                Some(">=")
            );
            assert_eq!(*nested_field_value(buf, &ops[1], "and"), FieldValue::U8(1));
            assert_eq!(
                buf.resolve_nested_display_name(&ops[1], "comparison_name"),
                Some("<=")
            );
            assert_eq!(
                *nested_field_value(buf, &ops[1], "value"),
                FieldValue::U64(139)
            );
            assert_eq!(
                *nested_field_value(buf, &ops[2], "value"),
                FieldValue::U64(8080)
            );

            let comps = array_objs(buf, &entries[2], "components");
            assert_eq!(
                buf.resolve_nested_display_name(&comps[1], "type_name"),
                Some("Fragment")
            );
            let ops = flowspec_operators(buf, &comps[1]);
            assert_eq!(*nested_field_value(buf, &ops[0], "not"), FieldValue::U8(0));
            assert_eq!(
                *nested_field_value(buf, &ops[0], "match"),
                FieldValue::U8(0)
            );
            assert_eq!(
                *nested_field_value(buf, &ops[0], "value"),
                FieldValue::U64(5)
            );
            assert!(nested_field_by_name_opt(buf, &ops[0], "comparison").is_none());
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_flowspec_ipv6_examples() {
        // RFC 8956, Section 3.8.2 (https://www.rfc-editor.org/rfc/rfc8956#section-3.8.2):
        // "from ::1234:5678:9a00:0/65-104 to
        // 2001:db8::/32", plus a TCP Flags (bitmask, not + match) and a
        // Flow Label component with a 4-octet value.
        let mut nlri = vec![
            0x18, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x02, 0x68, 0x41, 0x24, 0x68, 0xac,
            0xf1, 0x34,
        ];
        nlri.extend_from_slice(&[0x09, 0x83, 0x02, 0x0d, 0xa0, 0x00, 0x01, 0x23, 0x45]);
        with_mp_reach_nlri(2, 133, &nlri, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            let comps = array_objs(buf, &entries[0], "components");
            assert_eq!(comps.len(), 4);
            assert_eq!(
                buf.resolve_nested_display_name(&comps[0], "type_name"),
                Some("Destination IPv6 Prefix")
            );
            assert_eq!(
                *nested_field_value(buf, &comps[0], "prefix_offset"),
                FieldValue::U8(0)
            );
            let prefix = nested_field_by_name(buf, &comps[0], "prefix");
            assert_eq!(call_format_fn_ctx(buf, prefix), "\"2001:db8::/32\"");
            // Non-zero offset: length, offset and the raw pattern.
            assert_eq!(
                *nested_field_value(buf, &comps[1], "prefix_length"),
                FieldValue::U8(104)
            );
            assert_eq!(
                *nested_field_value(buf, &comps[1], "prefix_offset"),
                FieldValue::U8(65)
            );
            assert_eq!(
                *nested_field_value(buf, &comps[1], "pattern"),
                FieldValue::Bytes(&[0x24, 0x68, 0xac, 0xf1, 0x34])
            );
            assert!(nested_field_by_name_opt(buf, &comps[1], "prefix").is_none());
            let ops = flowspec_operators(buf, &comps[2]);
            assert_eq!(*nested_field_value(buf, &ops[0], "not"), FieldValue::U8(1));
            assert_eq!(
                *nested_field_value(buf, &ops[0], "match"),
                FieldValue::U8(1)
            );
            assert_eq!(
                *nested_field_value(buf, &ops[0], "value"),
                FieldValue::U64(2)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&comps[3], "type_name"),
                Some("Flow Label")
            );
            let ops = flowspec_operators(buf, &comps[3]);
            assert_eq!(
                *nested_field_value(buf, &ops[0], "value"),
                FieldValue::U64(0x12345)
            );
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_flowspec_vpn_and_extended_length() {
        // RFC 8955, Section 8 (https://www.rfc-editor.org/rfc/rfc8955#section-8):
        // SAFI 134 carries an RD before the components,
        // counted in the length. Section 4.1: a length of 240 or more is
        // "encoded as an extended-length 2-octet value in which the most
        // significant nibble has the hex value 0xf".
        let mut value = vec![
            0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64, 0x01, 0x18, 0xc0, 0x00, 0x02,
        ];
        let mut vpn = vec![value.len() as u8];
        vpn.append(&mut value);
        // Packet Length with 116 {op, value} pairs of 2 octets, and a last
        // one: 1 + 117 * 2 + 5 (Destination Prefix) = 240 octets.
        let mut long = vec![0x01, 0x18, 0xc0, 0x00, 0x02, 0x0a];
        for _ in 0..116 {
            long.extend_from_slice(&[0x01, 0x40]);
        }
        long.extend_from_slice(&[0x81, 0x40]);
        assert_eq!(long.len(), 240);
        let mut ext = vec![0xf0, 0xf0];
        ext.extend_from_slice(&long);
        with_mp_reach_nlri(1, 134, &vpn, |buf, _, entries| {
            let e = &entries[0];
            let rd = nested_field_by_name(buf, e, "rd");
            assert_eq!(
                call_format_fn(rd.descriptor.format_fn.unwrap(), &rd.value),
                "\"0:65000:100\""
            );
            assert_eq!(array_objs(buf, e, "components").len(), 1);
        });
        with_mp_reach_nlri(1, 133, &ext, |buf, _, entries| {
            let e = &entries[0];
            assert_eq!(
                *nested_field_value(buf, e, "nlri_length"),
                FieldValue::U16(240)
            );
            let comps = array_objs(buf, e, "components");
            assert_eq!(flowspec_operators(buf, &comps[1]).len(), 117);
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_flowspec_malformed_rules_keep_value() {
        // RFC 8955, Section 4.2: "An NLRI value not encoded as specified here,
        // including an NLRI that contains an unknown component type, is
        // considered malformed": an unknown type (0x81), components out of
        // order, an operator list without the end-of-list bit, an IPv4 prefix
        // longer than 32 bits, and a Flow Label (13) in IPv4 each keep the
        // NLRI value as `value`.
        let cases: [&[u8]; 6] = [
            &[0x01, 0x08, 0x0a, 0x81, 0x06],
            &[0x03, 0x81, 0x06, 0x01, 0x08, 0x0a],
            &[0x03, 0x01, 0x06],
            &[0x01, 0x21, 0, 0, 0, 0, 0],
            &[0x0d, 0x81, 0x01],
            // A valid IPv4 prefix followed by an unknown type.
            &[0x01, 0x08, 0x0a, 0xff],
        ];
        for value in cases {
            let mut nlri = vec![value.len() as u8];
            nlri.extend_from_slice(value);
            with_mp_reach_nlri(1, 133, &nlri, |buf, _, entries| {
                assert_eq!(entries.len(), 1, "{value:02x?}");
                assert!(nested_field_by_name_opt(buf, &entries[0], "components").is_none());
                assert_eq!(
                    *nested_field_value(buf, &entries[0], "value"),
                    FieldValue::Bytes(value)
                );
            });
        }
        // A length that overruns the block leaves it as `nlri_raw`.
        with_mp_reach_nlri(1, 133, &[0x09, 0x01, 0x08, 0x0a], |buf, mp, entries| {
            assert!(entries.is_empty());
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&[0x09, 0x01, 0x08, 0x0a])
            );
        });
    }

    #[test]
    fn parse_bgp_update_mp_unreach_flowspec_withdrawn() {
        let wr = [0x05, 0x01, 0x18, 0xc0, 0x00, 0x02];
        let data = build_single_attr_update(15, &build_mp_unreach(1, 133, &wr));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let entries = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(entries.len(), 1);
        assert_eq!(array_objs(&buf, &entries[0], "components").len(), 1);
    }

    #[test]
    fn flowspec_name_tables() {
        let v4 = (0..=u8::MAX)
            .filter_map(flowspec_ipv4_component_name)
            .count();
        let v6 = (0..=u8::MAX)
            .filter_map(flowspec_ipv6_component_name)
            .count();
        assert_eq!((v4, v6), (12, 13));
        assert_eq!(flowspec_ipv4_component_name(13), None);
        assert_eq!(
            flowspec_ipv6_component_name(3),
            Some("Upper-Layer Protocol")
        );
        let ops: Vec<_> = (0..8).filter_map(flowspec_comparison_name).collect();
        assert_eq!(ops, ["false", "==", ">", ">=", "<", "<=", "!=", "true"]);
        assert_eq!(flowspec_comparison_name(8), None);
    }

    #[test]
    fn parse_bgp_update_mp_reach_flowspec_empty_rules_and_first_and_bit() {
        // "Encoding: <[component]+>" (RFC 8955, Section 4.2 —
        // https://www.rfc-editor.org/rfc/rfc8955#section-4.2): a rule without
        // components, and a SAFI 134 rule with only an RD, are malformed.
        with_mp_reach_nlri(1, 133, &[0x00], |buf, _, entries| {
            assert!(nested_field_by_name_opt(buf, &entries[0], "components").is_none());
            assert!(nested_field_by_name_opt(buf, &entries[0], "value").is_none());
        });
        let rd_only = [0x08, 0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64];
        with_mp_reach_nlri(1, 134, &rd_only, |buf, _, entries| {
            assert!(nested_field_by_name_opt(buf, &entries[0], "rd").is_none());
            assert_eq!(
                *nested_field_value(buf, &entries[0], "value"),
                FieldValue::Bytes(&rd_only[1..])
            );
        });
        // The AND bit of the first operator "MUST be treated as always unset
        // on decoding" (RFC 8955, Section 4.2.1.1 —
        // https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1.1).
        with_mp_reach_nlri(
            1,
            133,
            &[0x05, 0x03, 0x41, 0x06, 0xc1, 0x11],
            |buf, _, entries| {
                let comps = array_objs(buf, &entries[0], "components");
                let ops = flowspec_operators(buf, &comps[0]);
                assert_eq!(*nested_field_value(buf, &ops[0], "and"), FieldValue::U8(0));
                assert_eq!(*nested_field_value(buf, &ops[1], "and"), FieldValue::U8(1));
            },
        );
    }

    #[test]
    fn parse_bgp_update_mp_reach_flowspec_add_path() {
        // RFC 7911, Section 3 (https://www.rfc-editor.org/rfc/rfc7911#section-3):
        // a Path Identifier before each rule, detected because the block only
        // parses as rules with it.
        let mut nlri = 1u32.to_be_bytes().to_vec();
        nlri.extend_from_slice(&[0x05, 0x01, 0x18, 0xc0, 0x00, 0x02]);
        with_mp_reach_nlri(1, 133, &nlri, |buf, mp, entries| {
            assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_none());
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(1)
            );
            assert_eq!(array_objs(buf, &entries[0], "components").len(), 1);
        });
        assert!(!detect_add_path_flowspec(
            &[0x05, 0x01, 0x18, 0xc0, 0x00, 0x02],
            false,
            false
        ));
        assert!(!detect_add_path_flowspec(&[0, 0, 0], false, false));
        assert!(!flowspec_block_parses(&[0xf0], 0, false, false));
    }

    // ---------------------------------------------------------------------
    // BGP-LS NLRI (AFI 16388 / SAFI 71, 72; RFC 9552, Section 5.2)
    // ---------------------------------------------------------------------

    /// Helper: a BGP-LS TLV with a 2-octet Type and Length.
    fn ls_tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let mut raw = tlv_type.to_be_bytes().to_vec();
        raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
        raw.extend_from_slice(value);
        raw
    }

    /// Helper: a Link-State NLRI of `nlri_type` with `body` after the Total
    /// NLRI Length.
    fn ls_nlri(nlri_type: u16, body: &[u8]) -> Vec<u8> {
        let mut raw = nlri_type.to_be_bytes().to_vec();
        raw.extend_from_slice(&(body.len() as u16).to_be_bytes());
        raw.extend_from_slice(body);
        raw
    }

    /// Helper: Protocol-ID, Identifier and a Local Node Descriptors TLV with
    /// an Autonomous System (65000) and an IS-IS IGP Router-ID sub-TLV.
    fn ls_node_body(protocol_id: u8) -> Vec<u8> {
        let mut subs = ls_tlv(512, &65000u32.to_be_bytes());
        subs.extend(ls_tlv(515, &[0x19, 0x21, 0x68, 0x00, 0x00, 0x01]));
        let mut body = vec![protocol_id];
        body.extend_from_slice(&7u64.to_be_bytes());
        body.extend(ls_tlv(256, &subs));
        body
    }

    #[test]
    fn parse_bgp_update_mp_reach_bgp_ls_node_link_prefix() {
        // RFC 9552, Section 5.2: Node (1), Link (2) and IPv4 Topology Prefix
        // (3) NLRI with Local / Remote Node Descriptors (Section 5.2.1), Link
        // Descriptors (Section 5.2.2) and Prefix Descriptors (Section 5.2.3).
        let node = ls_nlri(1, &ls_node_body(2));
        let mut link = ls_node_body(3);
        link.extend(ls_tlv(257, &ls_tlv(515, &[192, 0, 2, 2])));
        link.extend(ls_tlv(259, &[10, 0, 0, 1]));
        link.extend(ls_tlv(260, &[10, 0, 0, 2]));
        let link = ls_nlri(2, &link);
        let mut prefix = ls_node_body(1);
        prefix.extend(ls_tlv(265, &[24, 10, 1, 2]));
        let prefix = ls_nlri(3, &prefix);
        let mut nlri = node.clone();
        nlri.extend(&link);
        nlri.extend(&prefix);
        with_mp_reach_nlri(16388, 71, &nlri, |buf, mp, entries| {
            assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_none());
            assert_eq!(entries.len(), 3);
            let e = &entries[0];
            assert_eq!(*nested_field_value(buf, e, "nlri_type"), FieldValue::U16(1));
            assert_eq!(
                buf.resolve_nested_display_name(e, "nlri_type_name"),
                Some("Node NLRI")
            );
            assert_eq!(
                *nested_field_value(buf, e, "total_nlri_length"),
                FieldValue::U16((node.len() - 4) as u16)
            );
            assert_eq!(
                *nested_field_value(buf, e, "protocol_id"),
                FieldValue::U8(2)
            );
            assert_eq!(
                buf.resolve_nested_display_name(e, "protocol_id_name"),
                Some("IS-IS Level 2")
            );
            assert_eq!(
                *nested_field_value(buf, e, "identifier"),
                FieldValue::U64(7)
            );
            let descs = array_objs(buf, e, "descriptors");
            assert_eq!(descs.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &descs[0], "type"),
                FieldValue::U16(256)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&descs[0], "type_name"),
                Some("Local Node Descriptors")
            );
            let subs = array_objs(buf, &descs[0], "sub_tlvs");
            assert_eq!(subs.len(), 2);
            assert_eq!(
                buf.resolve_nested_display_name(&subs[0], "type_name"),
                Some("Autonomous System")
            );
            assert_eq!(
                *nested_field_value(buf, &subs[0], "value"),
                FieldValue::Bytes(&65000u32.to_be_bytes())
            );
            assert!(
                !direct_children(buf, &descs[0])
                    .iter()
                    .any(|f| f.name() == "value")
            );

            let descs = array_objs(buf, &entries[1], "descriptors");
            assert_eq!(descs.len(), 4);
            assert_eq!(
                buf.resolve_nested_display_name(&descs[1], "type_name"),
                Some("Remote Node Descriptors")
            );
            assert_eq!(array_objs(buf, &descs[1], "sub_tlvs").len(), 1);
            assert_eq!(
                *nested_field_value(buf, &descs[2], "value"),
                FieldValue::Bytes(&[10, 0, 0, 1])
            );
            assert!(nested_field_by_name_opt(buf, &descs[2], "sub_tlvs").is_none());

            let descs = array_objs(buf, &entries[2], "descriptors");
            assert_eq!(
                buf.resolve_nested_display_name(&descs[1], "type_name"),
                Some("IP Reachability Information")
            );
        });
    }

    #[test]
    fn parse_bgp_update_mp_reach_bgp_ls_vpn_unknown_and_malformed() {
        // SAFI 72 carries an RD after the Total NLRI Length (RFC 9552,
        // Section 5.2, Figure 6). "An implementation MUST handle unknown
        // Link-State NLRI types as opaque objects": NLRI type 7 keeps
        // `value`, as does a Node NLRI whose descriptors overrun it.
        let mut vpn = vec![0, 0, 0xfd, 0xe8, 0, 0, 0, 0x64];
        vpn.extend(ls_node_body(3));
        let vpn = ls_nlri(1, &vpn);
        with_mp_reach_nlri(16388, 72, &vpn, |buf, _, entries| {
            let rd = nested_field_by_name(buf, &entries[0], "rd");
            assert_eq!(
                call_format_fn(rd.descriptor.format_fn.unwrap(), &rd.value),
                "\"0:65000:100\""
            );
            assert_eq!(array_objs(buf, &entries[0], "descriptors").len(), 1);
        });
        let mut bad = ls_node_body(3);
        bad.extend_from_slice(&[1, 0x08, 0, 9, 0]);
        let mut nlri = ls_nlri(7, &[1, 2, 3]);
        nlri.extend(ls_nlri(1, &bad));
        nlri.extend(ls_nlri(1, &[3, 0, 0]));
        with_mp_reach_nlri(16388, 71, &nlri, |buf, _, entries| {
            assert_eq!(entries.len(), 3);
            assert_eq!(
                buf.resolve_nested_display_name(&entries[0], "nlri_type_name"),
                None
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "value"),
                FieldValue::Bytes(&[1, 2, 3])
            );
            assert!(nested_field_by_name_opt(buf, &entries[0], "protocol_id").is_none());
            assert_eq!(
                *nested_field_value(buf, &entries[1], "value"),
                FieldValue::Bytes(&bad)
            );
            assert!(nested_field_by_name_opt(buf, &entries[1], "descriptors").is_none());
            assert_eq!(
                *nested_field_value(buf, &entries[2], "value"),
                FieldValue::Bytes(&[3, 0, 0])
            );
        });
    }

    #[test]
    fn parse_bgp_update_bgp_ls_withdrawn_add_path_and_tail() {
        // Withdrawn Link-State NLRI (RFC 9552, Section 5.2), an ADD-PATH block
        // (RFC 7911, Section 3 — https://www.rfc-editor.org/rfc/rfc7911#section-3)
        // and a truncated tail kept raw.
        let node = ls_nlri(1, &ls_node_body(2));
        let data = build_single_attr_update(15, &build_mp_unreach(16388, 71, &node));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(array_objs(&buf, &mp, "withdrawn_routes").len(), 1);

        let mut add_path = 9u32.to_be_bytes().to_vec();
        add_path.extend(&node);
        with_mp_reach_nlri(16388, 71, &add_path, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(9)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "protocol_id"),
                FieldValue::U8(2)
            );
        });
        assert!(!detect_add_path_bgp_ls(&node, false));
        assert!(!detect_add_path_bgp_ls(&[0, 0, 0], false));
        // A Path Identifier whose low octets are zero reads as a Node NLRI
        // without a body, which does not parse: ADD-PATH.
        let mut low_zero = 0x0001_0000u32.to_be_bytes().to_vec();
        low_zero.extend(&node);
        assert!(detect_add_path_bgp_ls(&low_zero, false));
        // An ADD-PATH block with a malformed tail still frames further with
        // Path Identifiers.
        let mut add_path_tail = add_path.clone();
        add_path_tail.extend_from_slice(&[0, 0, 0, 1, 0, 1, 0, 9]);
        assert!(detect_add_path_bgp_ls(&add_path_tail, false));
        with_mp_reach_nlri(16388, 71, &add_path_tail, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(9)
            );
        });

        let mut tail = node.clone();
        tail.extend_from_slice(&[0, 1, 0, 9]);
        with_mp_reach_nlri(16388, 71, &tail, |buf, mp, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&[0, 1, 0, 9])
            );
        });
    }

    #[test]
    fn bgp_ls_nlri_name_tables() {
        assert_eq!((0..=u16::MAX).filter_map(bgp_ls_nlri_type_name).count(), 6);
        assert_eq!(bgp_ls_nlri_type_name(6), Some("SRv6 SID NLRI"));
        assert_eq!((0..=u8::MAX).filter_map(bgp_ls_protocol_id_name).count(), 8);
        assert_eq!(bgp_ls_protocol_id_name(9), Some("Segment Routing"));
        assert_eq!(bgp_ls_protocol_id_name(8), None);
    }

    #[test]
    fn parse_bgp_update_mp_reach_bgp_ls_next_hop() {
        // RFC 9552, Section 5.5 (https://www.rfc-editor.org/rfc/rfc9552#section-5.5):
        // an IPv4 next hop for SAFI 71 and an RD + IPv6 next hop for SAFI 72.
        let data = build_single_attr_update(14, &build_mp_reach(16388, 71, &[192, 0, 2, 1], &[]));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        let mut nh = vec![0u8; 8];
        nh.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = build_single_attr_update(14, &build_mp_reach(16388, 72, &nh, &[]));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop_rd"),
            FieldValue::Bytes(&[0; 8])
        );
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    /// Helper: a Route Target membership NLRI of `bits` prefix bits covering
    /// origin AS 65000 and the Route Target 0x0002_fde8_0000_0064.
    fn rtc_nlri(bits: u8) -> Vec<u8> {
        let mut full = 65000u32.to_be_bytes().to_vec();
        full.extend_from_slice(&[0x00, 0x02, 0xfd, 0xe8, 0, 0, 0, 100]);
        let mut raw = vec![bits];
        raw.extend_from_slice(&full[..usize::from(bits).div_ceil(8)]);
        raw
    }

    #[test]
    fn parse_bgp_update_mp_reach_rt_constraint() {
        // RFC 4684, Section 4 (https://www.rfc-editor.org/rfc/rfc4684#section-4):
        // the default route target (zero-length prefix), an origin AS only
        // (32 bits), a partial Route Target (48 bits) and a full one (96 bits).
        let mut nlri = rtc_nlri(0);
        nlri.extend(rtc_nlri(32));
        nlri.extend(rtc_nlri(48));
        nlri.extend(rtc_nlri(96));
        let data = build_single_attr_update(14, &build_mp_reach(1, 132, &[192, 0, 2, 1], &nlri));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "nlri_raw").is_none());
        let entries = array_objs(&buf, &mp, "nlri");
        assert_eq!(entries.len(), 4);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "prefix_length"),
            FieldValue::U8(0)
        );
        assert!(nested_field_by_name_opt(&buf, &entries[0], "origin_as").is_none());
        assert!(nested_field_by_name_opt(&buf, &entries[0], "route_target").is_none());
        assert_eq!(
            *nested_field_value(&buf, &entries[1], "origin_as"),
            FieldValue::U32(65000)
        );
        assert!(nested_field_by_name_opt(&buf, &entries[1], "route_target").is_none());
        assert_eq!(
            *nested_field_value(&buf, &entries[2], "prefix_length"),
            FieldValue::U8(48)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[2], "route_target"),
            FieldValue::Bytes(&[0x00, 0x02])
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[3], "route_target"),
            FieldValue::Bytes(&[0x00, 0x02, 0xfd, 0xe8, 0, 0, 0, 100])
        );
        // "as a IPv6 address whenever the length of the NextHop address is
        // 16 octets".
        let nh = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let data = build_single_attr_update(14, &build_mp_reach(1, 132, &nh, &rtc_nlri(0)));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv6Addr(nh)
        );
        assert_eq!(array_objs(&buf, &mp, "nlri").len(), 1);
        // Only AFI 1 is defined for SAFI 132: AFI 2 stays raw.
        with_mp_reach_nlri(2, 132, &rtc_nlri(96), |buf, mp, entries| {
            assert!(entries.is_empty());
            assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_some());
        });
    }

    #[test]
    fn parse_bgp_update_rt_constraint_malformed_withdrawn_add_path() {
        // RFC 4684, Section 4 (https://www.rfc-editor.org/rfc/rfc4684#section-4):
        // "Except for the default route target, which is encoded as a zero-length prefix, the minimum prefix length is 32
        // bits"; the prefix is "of 0 to 96 bits". Entries from the first
        // invalid length on stay raw.
        for bad in [vec![16, 0, 0], vec![97], rtc_nlri(96)[..5].to_vec()] {
            let mut nlri = rtc_nlri(96);
            nlri.extend(&bad);
            with_mp_reach_nlri(1, 132, &nlri, |buf, mp, entries| {
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    *nested_field_value(buf, mp, "nlri_raw"),
                    FieldValue::Bytes(&bad)
                );
            });
        }

        // Withdrawn membership NLRI.
        let data = build_single_attr_update(15, &build_mp_unreach(1, 132, &rtc_nlri(64)));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let withdrawn = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &withdrawn[0], "route_target"),
            FieldValue::Bytes(&[0x00, 0x02, 0xfd, 0xe8])
        );

        // RFC 7911, Section 3 (https://www.rfc-editor.org/rfc/rfc7911#section-3):
        // a Path Identifier reads as default route targets followed by an
        // invalid length without ADD-PATH.
        let mut add_path = 1u32.to_be_bytes().to_vec();
        add_path.extend(rtc_nlri(96));
        assert!(detect_add_path_rt_constraint(&add_path));
        assert!(!detect_add_path_rt_constraint(&rtc_nlri(96)));
        // A zero Path Identifier reads as default route targets sharing the
        // block with other entries: ADD-PATH.
        let mut zero_id = vec![0u8; 4];
        zero_id.extend(rtc_nlri(96));
        assert!(detect_add_path_rt_constraint(&zero_id));
        assert!(detect_add_path_rt_constraint(&[0, 0, 0, 0, 0]));
        // A lone default route target is plain.
        assert!(!detect_add_path_rt_constraint(&[0]));
        with_mp_reach_nlri(1, 132, &add_path, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(1)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "origin_as"),
                FieldValue::U32(65000)
            );
        });
    }

    /// Helper: an SR Policy NLRI (distinguisher 1, color 100) for `endpoint`.
    fn sr_policy_nlri(endpoint: &[u8]) -> Vec<u8> {
        let mut raw = vec![u8::try_from((8 + endpoint.len()) * 8).unwrap()];
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&100u32.to_be_bytes());
        raw.extend_from_slice(endpoint);
        raw
    }

    const SR_POLICY_V6_ENDPOINT: [u8; 16] =
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[test]
    fn parse_bgp_update_mp_reach_sr_policy() {
        // RFC 9830, Section 2.1 (https://www.rfc-editor.org/rfc/rfc9830#section-2.1):
        // NLRI Length (96 for AFI 1, 192 for AFI 2), Distinguisher, Color,
        // Endpoint.
        let data = build_single_attr_update(
            14,
            &build_mp_reach(1, 73, &[192, 0, 2, 254], &sr_policy_nlri(&[192, 0, 2, 1])),
        );
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert!(nested_field_by_name_opt(&buf, &mp, "nlri_raw").is_none());
        let entries = array_objs(&buf, &mp, "nlri");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(
            *nested_field_value(&buf, e, "nlri_length_bits"),
            FieldValue::U8(96)
        );
        assert_eq!(
            *nested_field_value(&buf, e, "distinguisher"),
            FieldValue::U32(1)
        );
        assert_eq!(*nested_field_value(&buf, e, "color"), FieldValue::U32(100));
        assert_eq!(
            *nested_field_value(&buf, e, "endpoint"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );

        // "The next-hop network address field in SR Policy SAFI (73) updates
        // may be either a 4-octet IPv4 address or a 16-octet IPv6 address,
        // independent of the SR Policy AFI."
        let data = build_single_attr_update(
            14,
            &build_mp_reach(
                2,
                73,
                &[192, 0, 2, 254],
                &sr_policy_nlri(&SR_POLICY_V6_ENDPOINT),
            ),
        );
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv4Addr([192, 0, 2, 254])
        );
        let entries = array_objs(&buf, &mp, "nlri");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "nlri_length_bits"),
            FieldValue::U8(192)
        );
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "endpoint"),
            FieldValue::Ipv6Addr(SR_POLICY_V6_ENDPOINT)
        );

        // "If the next-hop length is 32, then it has a global IPv6 address
        // followed by a link-local IPv6 address", also for AFI 1.
        let mut nh = SR_POLICY_V6_ENDPOINT.to_vec();
        nh.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = build_single_attr_update(
            14,
            &build_mp_reach(1, 73, &nh, &sr_policy_nlri(&[192, 0, 2, 1])),
        );
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv6Addr(SR_POLICY_V6_ENDPOINT)
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "next_hop_link_local").is_some());
        assert_eq!(array_objs(&buf, &mp, "nlri").len(), 1);
    }

    #[test]
    fn parse_bgp_update_sr_policy_malformed_withdrawn_add_path() {
        // RFC 9830, Section 2.1 (https://www.rfc-editor.org/rfc/rfc9830#section-2.1):
        // "When AFI = 1, the value MUST be 96; when AFI = 2, the value MUST be
        // 192." Entries from the first other length on stay raw, as does a
        // truncated NLRI.
        let v4 = sr_policy_nlri(&[192, 0, 2, 1]);
        for bad in [sr_policy_nlri(&SR_POLICY_V6_ENDPOINT), v4[..9].to_vec()] {
            let mut nlri = v4.clone();
            nlri.extend(&bad);
            with_mp_reach_nlri(1, 73, &nlri, |buf, mp, entries| {
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    *nested_field_value(buf, mp, "nlri_raw"),
                    FieldValue::Bytes(&bad)
                );
            });
        }

        // Withdrawn SR Policy NLRI.
        let data = build_single_attr_update(
            15,
            &build_mp_unreach(2, 73, &sr_policy_nlri(&SR_POLICY_V6_ENDPOINT)),
        );
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let withdrawn = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &withdrawn[0], "color"),
            FieldValue::U32(100)
        );

        // A 96-bit NLRI under AFI 2 stays raw.
        with_mp_reach_nlri(2, 73, &v4, |buf, mp, entries| {
            assert!(entries.is_empty());
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&v4)
            );
        });

        // RFC 7911, Section 3 (https://www.rfc-editor.org/rfc/rfc7911#section-3).
        let mut add_path = 7u32.to_be_bytes().to_vec();
        add_path.extend(&v4);
        assert!(detect_add_path_sr_policy(&add_path, false));
        assert!(!detect_add_path_sr_policy(&v4, false));
        // A plain NLRI followed by a malformed tail stays plain.
        let mut tail = v4.clone();
        tail.extend_from_slice(&[1, 2, 3, 4]);
        assert!(!detect_add_path_sr_policy(&tail, false));
        // A Path Identifier whose first octet is the NLRI Length 96 / 192
        // frames one NLRI without Path Identifiers too, but the block frames
        // further with them.
        for (path_id, ipv6, nlri) in [
            (0x6000_0001u32, false, v4.clone()),
            (0xc0a8_0101, true, sr_policy_nlri(&SR_POLICY_V6_ENDPOINT)),
        ] {
            let mut block = path_id.to_be_bytes().to_vec();
            block.extend(&nlri);
            assert!(detect_add_path_sr_policy(&block, ipv6));
            with_mp_reach_nlri(if ipv6 { 2 } else { 1 }, 73, &block, |buf, mp, entries| {
                assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_none());
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    *nested_field_value(buf, &entries[0], "path_id"),
                    FieldValue::U32(path_id)
                );
                assert_eq!(
                    *nested_field_value(buf, &entries[0], "color"),
                    FieldValue::U32(100)
                );
            });
        }
        let mut add_path_v6 = 7u32.to_be_bytes().to_vec();
        add_path_v6.extend(sr_policy_nlri(&SR_POLICY_V6_ENDPOINT));
        with_mp_reach_nlri(2, 73, &add_path_v6, |buf, mp, entries| {
            assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_none());
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "endpoint"),
                FieldValue::Ipv6Addr(SR_POLICY_V6_ENDPOINT)
            );
        });
        with_mp_reach_nlri(1, 73, &add_path, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(7)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "distinguisher"),
                FieldValue::U32(1)
            );
        });
    }

    /// Helper: an MCAST-VPN NLRI of `route_type` with `body`.
    fn mvpn_route(route_type: u8, body: &[u8]) -> Vec<u8> {
        let mut raw = vec![route_type, u8::try_from(body.len()).unwrap()];
        raw.extend_from_slice(body);
        raw
    }

    const MVPN_RD: [u8; 8] = [0, 0, 0xfd, 0xe8, 0, 0, 0, 1];

    /// Helper: RD, then optionally a Source AS, then Multicast Source and
    /// Group fields with their bit lengths.
    fn mvpn_sg(source_as: Option<u32>, source: &[u8], group: &[u8]) -> Vec<u8> {
        let mut body = MVPN_RD.to_vec();
        if let Some(asn) = source_as {
            body.extend_from_slice(&asn.to_be_bytes());
        }
        body.push(u8::try_from(source.len() * 8).unwrap());
        body.extend_from_slice(source);
        body.push(u8::try_from(group.len() * 8).unwrap());
        body.extend_from_slice(group);
        body
    }

    #[test]
    fn parse_bgp_update_mp_reach_mcast_vpn_route_types() {
        // RFC 6514, Sections 4.1-4.6 (https://www.rfc-editor.org/rfc/rfc6514#section-4.1).
        let mut intra = MVPN_RD.to_vec();
        intra.extend_from_slice(&[192, 0, 2, 1]);
        let mut inter = MVPN_RD.to_vec();
        inter.extend_from_slice(&65001u32.to_be_bytes());
        let mut spmsi = mvpn_sg(None, &[10, 0, 0, 1], &[232, 1, 1, 1]);
        spmsi.extend_from_slice(&[192, 0, 2, 1]);
        let spmsi_route = mvpn_route(3, &spmsi);
        let mut leaf = spmsi_route.clone();
        leaf.extend_from_slice(&[192, 0, 2, 2]);
        let sa = mvpn_sg(None, &[10, 0, 0, 1], &[239, 1, 1, 1]);
        let shared = mvpn_sg(Some(65001), &[10, 0, 0, 2], &[239, 1, 1, 1]);
        let source = mvpn_sg(Some(65001), &[10, 0, 0, 1], &[232, 1, 1, 1]);
        let mut nlri = mvpn_route(1, &intra);
        nlri.extend(mvpn_route(2, &inter));
        nlri.extend(&spmsi_route);
        nlri.extend(mvpn_route(4, &leaf));
        nlri.extend(mvpn_route(5, &sa));
        nlri.extend(mvpn_route(6, &shared));
        nlri.extend(mvpn_route(7, &source));
        with_mp_reach_nlri(1, 5, &nlri, |buf, mp, entries| {
            assert!(nested_field_by_name_opt(buf, mp, "nlri_raw").is_none());
            assert_eq!(entries.len(), 7);
            let e = &entries[0];
            assert_eq!(
                *nested_field_value(buf, e, "route_type"),
                FieldValue::U16(1)
            );
            assert_eq!(
                buf.resolve_nested_display_name(e, "route_type_name"),
                Some("Intra-AS I-PMSI A-D route")
            );
            assert_eq!(*nested_field_value(buf, e, "length"), FieldValue::U8(12));
            assert_eq!(
                *nested_field_value(buf, e, "rd"),
                FieldValue::Bytes(&MVPN_RD)
            );
            assert_eq!(
                *nested_field_value(buf, e, "originating_router_ip"),
                FieldValue::Ipv4Addr([192, 0, 2, 1])
            );
            assert_eq!(
                *nested_field_value(buf, &entries[1], "source_as"),
                FieldValue::U32(65001)
            );
            let e = &entries[2];
            assert_eq!(
                *nested_field_value(buf, e, "multicast_source_length"),
                FieldValue::U8(32)
            );
            assert_eq!(
                *nested_field_value(buf, e, "multicast_source"),
                FieldValue::Ipv4Addr([10, 0, 0, 1])
            );
            assert_eq!(
                *nested_field_value(buf, e, "multicast_group_length"),
                FieldValue::U8(32)
            );
            assert_eq!(
                *nested_field_value(buf, e, "multicast_group"),
                FieldValue::Ipv4Addr([232, 1, 1, 1])
            );
            assert_eq!(
                *nested_field_value(buf, e, "originating_router_ip"),
                FieldValue::Ipv4Addr([192, 0, 2, 1])
            );
            let e = &entries[3];
            assert_eq!(
                *nested_field_value(buf, e, "route_key"),
                FieldValue::Bytes(&spmsi_route)
            );
            assert_eq!(
                *nested_field_value(buf, e, "originating_router_ip"),
                FieldValue::Ipv4Addr([192, 0, 2, 2])
            );
            assert!(nested_field_by_name_opt(buf, &entries[4], "originating_router_ip").is_none());
            assert_eq!(
                *nested_field_value(buf, &entries[4], "multicast_group"),
                FieldValue::Ipv4Addr([239, 1, 1, 1])
            );
            for e in &entries[5..] {
                assert_eq!(
                    *nested_field_value(buf, e, "source_as"),
                    FieldValue::U32(65001)
                );
                assert!(nested_field_by_name_opt(buf, e, "multicast_source").is_some());
            }
            assert_eq!(
                buf.resolve_nested_display_name(&entries[6], "route_type_name"),
                Some("Source Tree Join route")
            );
        });
    }

    #[test]
    fn parse_bgp_update_mcast_vpn_ipv6_and_wildcards() {
        // RFC 6514, Section 4 (https://www.rfc-editor.org/rfc/rfc6514#section-4):
        // AFI 2 carries IPv6 C-S / C-G addresses. RFC 6515, Section 2
        // (https://www.rfc-editor.org/rfc/rfc6515#section-2): the length of
        // the Originating Router's IP Address "can thus be inferred from the
        // NLRI length field", independent of the AFI. RFC 6625, Section 2
        // (https://www.rfc-editor.org/rfc/rfc6625#section-2): a wildcard is
        // encoded with a zero Multicast Source / Group Length.
        let v6_source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let v6_group = [0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut spmsi = mvpn_sg(None, &[], &v6_group);
        spmsi.extend_from_slice(&[192, 0, 2, 1]);
        let mut nlri = mvpn_route(7, &mvpn_sg(Some(65001), &v6_source, &v6_group));
        nlri.extend(mvpn_route(3, &spmsi));
        with_mp_reach_nlri(2, 5, &nlri, |buf, _, entries| {
            assert_eq!(entries.len(), 2);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "multicast_source"),
                FieldValue::Ipv6Addr(v6_source)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "multicast_group"),
                FieldValue::Ipv6Addr(v6_group)
            );
            let e = &entries[1];
            assert_eq!(
                *nested_field_value(buf, e, "multicast_source_length"),
                FieldValue::U8(0)
            );
            assert!(nested_field_by_name_opt(buf, e, "multicast_source").is_none());
            assert_eq!(
                *nested_field_value(buf, e, "originating_router_ip"),
                FieldValue::Ipv4Addr([192, 0, 2, 1])
            );
        });
        let mut intra = MVPN_RD.to_vec();
        intra.extend_from_slice(&v6_source);
        with_mp_reach_nlri(1, 5, &mvpn_route(1, &intra), |buf, _, entries| {
            assert_eq!(
                *nested_field_value(buf, &entries[0], "originating_router_ip"),
                FieldValue::Ipv6Addr(v6_source)
            );
        });
    }

    #[test]
    fn parse_bgp_update_mcast_vpn_malformed_withdrawn_add_path() {
        // RFC 6515, Section 2 (https://www.rfc-editor.org/rfc/rfc6515#section-2):
        // an Originating Router's IP Address "neither 4 nor 16" is incorrect;
        // such routes, RFC 7441 mLDP route types
        // (https://www.rfc-editor.org/rfc/rfc7441#section-3) and unassigned
        // route types keep a `value`.
        let mut bad_intra = MVPN_RD.to_vec();
        bad_intra.extend_from_slice(&[192, 0, 2, 1, 9]);
        let bad_source = [MVPN_RD.as_slice(), &[32, 10, 0]].concat();
        let mut nlri = mvpn_route(1, &bad_intra);
        nlri.extend(mvpn_route(5, &bad_source));
        nlri.extend(mvpn_route(0x43, &[1, 2, 3]));
        nlri.extend(mvpn_route(9, &[]));
        nlri.extend_from_slice(&[7, 40, 0]);
        with_mp_reach_nlri(1, 5, &nlri, |buf, mp, entries| {
            assert_eq!(entries.len(), 4);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "value"),
                FieldValue::Bytes(&bad_intra)
            );
            assert!(nested_field_by_name_opt(buf, &entries[0], "rd").is_none());
            assert_eq!(
                *nested_field_value(buf, &entries[1], "value"),
                FieldValue::Bytes(&bad_source)
            );
            assert_eq!(
                buf.resolve_nested_display_name(&entries[2], "route_type_name"),
                Some("S-PMSI A-D route for C-multicast mLDP")
            );
            assert_eq!(
                *nested_field_value(buf, &entries[2], "value"),
                FieldValue::Bytes(&[1, 2, 3])
            );
            assert!(nested_field_by_name_opt(buf, &entries[3], "value").is_none());
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&[7, 40, 0])
            );
        });

        // A Leaf A-D Route Key that overruns, one that leaves a 5-octet
        // address, a Global Table Multicast Route Key (RFC 7524, Section
        // 6.2.2 — https://www.rfc-editor.org/rfc/rfc7524#section-6.2.2) and
        // a Source AS route of the wrong length keep a `value`.
        let mut gtm = vec![0u8; 8];
        gtm.extend_from_slice(&[0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
        for (route_type, body) in [
            (4, vec![3, 40, 0, 0, 192, 0, 2, 1]),
            (4, [mvpn_route(2, &[0; 12]), vec![192, 0, 2, 1, 9]].concat()),
            (4, gtm),
            (2, vec![0; 13]),
            (
                6,
                [mvpn_sg(Some(1), &[10, 0, 0, 1], &[232, 1, 1, 1]), vec![0]].concat(),
            ),
        ] {
            with_mp_reach_nlri(1, 5, &mvpn_route(route_type, &body), |buf, _, entries| {
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    *nested_field_value(buf, &entries[0], "value"),
                    FieldValue::Bytes(&body)
                );
            });
        }

        // Withdrawn C-multicast route.
        let route = mvpn_route(7, &mvpn_sg(Some(65001), &[10, 0, 0, 1], &[232, 1, 1, 1]));
        let data = build_single_attr_update(15, &build_mp_unreach(1, 5, &route));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let withdrawn = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &withdrawn[0], "source_as"),
            FieldValue::U32(65001)
        );

        // RFC 7911, Section 3 (https://www.rfc-editor.org/rfc/rfc7911#section-3).
        let mut add_path = 3u32.to_be_bytes().to_vec();
        add_path.extend(&route);
        assert!(detect_add_path_mcast_vpn(&add_path));
        assert!(!detect_add_path_mcast_vpn(&route));
        // Path Identifiers followed by unassigned Route Types: not ADD-PATH.
        let mut unassigned = 3u32.to_be_bytes().to_vec();
        unassigned.extend(mvpn_route(9, &[]));
        assert!(!detect_add_path_mcast_vpn(&unassigned));
        with_mp_reach_nlri(1, 5, &add_path, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(3)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "route_type"),
                FieldValue::U16(7)
            );
        });
    }

    #[test]
    fn parse_bgp_update_multicast_vpn_safi_129() {
        // RFC 6514, Section 10 (https://www.rfc-editor.org/rfc/rfc6514#section-10):
        // SAFI 129 NLRI is a Length in bits and "a Route Distinguisher as
        // defined in [RFC4364] prepended to an IPv4 or IPv6 address prefix".
        let mut nlri = vec![64 + 24];
        nlri.extend_from_slice(&MVPN_RD);
        nlri.extend_from_slice(&[10, 1, 2]);
        let mut nh = vec![0u8; 8];
        nh.extend_from_slice(&[192, 0, 2, 1]);
        let data = build_single_attr_update(14, &build_mp_reach(1, 129, &nh, &nlri));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        let entries = array_objs(&buf, &mp, "nlri");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &entries[0], "rd"),
            FieldValue::Bytes(&MVPN_RD)
        );
        assert!(nested_field_by_name_opt(&buf, &entries[0], "label_stack").is_none());
        let prefix = nested_field_by_name(&buf, &entries[0], "prefix");
        let FieldValue::Scratch(ref r) = prefix.value else {
            panic!("expected Scratch prefix");
        };
        assert_eq!(
            &buf.scratch()[r.start as usize..r.end as usize],
            &[24, 10, 1, 2]
        );

        // RFC 7911, Section 3 (https://www.rfc-editor.org/rfc/rfc7911#section-3):
        // a Path Identifier before the entry.
        let mut add_path = 5u32.to_be_bytes().to_vec();
        add_path.extend(&nlri);
        with_mp_reach_nlri(1, 129, &add_path, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(5)
            );
            assert!(nested_field_by_name_opt(buf, &entries[0], "rd").is_some());
        });

        // An IPv6 withdrawal has no Compatibility field.
        let mut wr = vec![64 + 32];
        wr.extend_from_slice(&MVPN_RD);
        wr.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let data = build_single_attr_update(15, &build_mp_unreach(2, 129, &wr));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let withdrawn = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(withdrawn.len(), 1);
        assert!(nested_field_by_name_opt(&buf, &withdrawn[0], "compatibility").is_none());

        // A prefix longer than the address after the RD stays raw.
        let bad = [64 + 40, 0, 0, 0, 0, 0, 0, 0, 1, 10, 1, 2, 3, 4];
        with_mp_reach_nlri(1, 129, &bad, |buf, mp, entries| {
            assert!(entries.is_empty());
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&bad)
            );
        });
    }

    #[test]
    fn mcast_vpn_route_type_name_table() {
        // IANA BGP MCAST-VPN Route Types
        // (https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#mcast-vpn-route-types).
        assert_eq!(
            (0..=u8::MAX).filter_map(mcast_vpn_route_type_name).count(),
            10
        );
        assert_eq!(mcast_vpn_route_type_name(4), Some("Leaf A-D route"));
        assert_eq!(
            mcast_vpn_route_type_name(0x44),
            Some("Leaf A-D route for C-multicast mLDP")
        );
        assert_eq!(
            mcast_vpn_route_type_name(0x47),
            Some("Source Tree Join route for C-multicast mLDP")
        );
        assert_eq!(mcast_vpn_route_type_name(0), None);
    }

    const VPLS_RD: [u8; 8] = [0, 0, 0xfd, 0xe8, 0, 0, 0, 10];

    /// Helper: a VPLS NLRI (RFC 4761, Section 3.2.2) with VE ID 1, VE Block
    /// Offset 1, VE Block Size 8 and Label Base 800000.
    fn vpls_nlri() -> Vec<u8> {
        let mut raw = 17u16.to_be_bytes().to_vec();
        raw.extend_from_slice(&VPLS_RD);
        raw.extend_from_slice(&[0, 1, 0, 1, 0, 8]);
        raw.extend_from_slice(&(800_000u32 << 4 | 1).to_be_bytes()[1..]);
        raw
    }

    #[test]
    fn parse_bgp_update_mp_reach_vpls() {
        // RFC 4761, Section 3.2.2 (https://www.rfc-editor.org/rfc/rfc4761#section-3.2.2):
        // Length (in octets), RD, VE ID, VE Block Offset, VE Block Size,
        // Label Base. RFC 6074, Section 3.2.2.1
        // (https://www.rfc-editor.org/rfc/rfc6074#section-3.2.2.1): the
        // BGP-AD NLRI is Length, RD and PE_addr.
        let mut nlri = vpls_nlri();
        nlri.extend_from_slice(&12u16.to_be_bytes());
        nlri.extend_from_slice(&VPLS_RD);
        nlri.extend_from_slice(&[192, 0, 2, 1]);
        let data = build_single_attr_update(14, &build_mp_reach(25, 65, &[192, 0, 2, 1], &nlri));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        assert_eq!(
            *nested_field_value(&buf, &mp, "next_hop"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert!(nested_field_by_name_opt(&buf, &mp, "nlri_raw").is_none());
        let entries = array_objs(&buf, &mp, "nlri");
        assert_eq!(entries.len(), 2);
        let e = &entries[0];
        assert_eq!(
            *nested_field_value(&buf, e, "nlri_length"),
            FieldValue::U16(17)
        );
        assert_eq!(
            *nested_field_value(&buf, e, "rd"),
            FieldValue::Bytes(&VPLS_RD)
        );
        assert_eq!(*nested_field_value(&buf, e, "ve_id"), FieldValue::U16(1));
        assert_eq!(
            *nested_field_value(&buf, e, "ve_block_offset"),
            FieldValue::U16(1)
        );
        assert_eq!(
            *nested_field_value(&buf, e, "ve_block_size"),
            FieldValue::U16(8)
        );
        assert_eq!(
            *nested_field_value(&buf, e, "label_base"),
            FieldValue::U32(800_000)
        );
        let e = &entries[1];
        assert_eq!(
            *nested_field_value(&buf, e, "nlri_length"),
            FieldValue::U16(12)
        );
        assert_eq!(
            *nested_field_value(&buf, e, "rd"),
            FieldValue::Bytes(&VPLS_RD)
        );
        assert_eq!(
            *nested_field_value(&buf, e, "pe_address"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert!(nested_field_by_name_opt(&buf, e, "ve_id").is_none());
    }

    #[test]
    fn parse_bgp_update_vpls_malformed_withdrawn_add_path() {
        // RFC 6074, Section 7 (https://www.rfc-editor.org/rfc/rfc6074#section-7):
        // "the NLRI length must be used as a demultiplexer" between the
        // 12-octet BGP-AD and 17-octet VPLS NLRI; other lengths keep a
        // `value`, and an NLRI that overruns the block stays raw.
        let mut nlri = vpls_nlri();
        nlri.extend_from_slice(&[0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        nlri.extend_from_slice(&[0, 9, 1]);
        with_mp_reach_nlri(25, 65, &nlri, |buf, mp, entries| {
            assert_eq!(entries.len(), 2);
            assert_eq!(
                *nested_field_value(buf, &entries[1], "value"),
                FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9])
            );
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&[0, 9, 1])
            );
        });
        // A Length too short for an RD ends the decoded entries.
        let mut short = vpls_nlri();
        short.extend_from_slice(&[0, 0, 0, 1, 7]);
        with_mp_reach_nlri(25, 65, &short, |buf, mp, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&[0, 0, 0, 1, 7])
            );
        });

        // Withdrawn VPLS NLRI.
        let data = build_single_attr_update(15, &build_mp_unreach(25, 65, &vpls_nlri()));
        let mut buf = DissectBuffer::new();
        BgpDissector.dissect(&data, &mut buf, 0).unwrap();
        let mp = first_attr_value_obj_range(&buf);
        let withdrawn = array_objs(&buf, &mp, "withdrawn_routes");
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(
            *nested_field_value(&buf, &withdrawn[0], "ve_block_size"),
            FieldValue::U16(8)
        );

        // RFC 7911, Section 3 (https://www.rfc-editor.org/rfc/rfc7911#section-3).
        let mut add_path = 2u32.to_be_bytes().to_vec();
        add_path.extend(vpls_nlri());
        assert!(detect_add_path_vpls(&add_path));
        assert!(!detect_add_path_vpls(&vpls_nlri()));
        // An ADD-PATH block with a malformed tail is still ADD-PATH.
        let mut tail = add_path.clone();
        tail.push(0);
        assert!(detect_add_path_vpls(&tail));
        with_mp_reach_nlri(25, 65, &tail, |buf, mp, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(2)
            );
            assert_eq!(
                *nested_field_value(buf, mp, "nlri_raw"),
                FieldValue::Bytes(&[0])
            );
        });
        with_mp_reach_nlri(25, 65, &add_path, |buf, _, entries| {
            assert_eq!(entries.len(), 1);
            assert_eq!(
                *nested_field_value(buf, &entries[0], "path_id"),
                FieldValue::U32(2)
            );
            assert_eq!(
                *nested_field_value(buf, &entries[0], "ve_id"),
                FieldValue::U16(1)
            );
        });
    }
}
