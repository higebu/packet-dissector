# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.6.1] - 2026-10-01

### 🚀 Features

- Report cross-packet state use per dissection ([#330](https://github.com/higebu/packet-dissector/issues/330))

### 🐛 Bug Fixes

- List dispatched and embedded dissectors in field schemas ([#331](https://github.com/higebu/packet-dissector/issues/331))
## [0.6.0] - 2026-10-01

### 🚀 Features

- *(dtls)* Add DTLS 1.2/1.3 dissector ([#300](https://github.com/higebu/packet-dissector/issues/300))
- *(rtp)* Decode RFC 8285 header extension elements and name static payload types ([#252](https://github.com/higebu/packet-dissector/issues/252))
- *(rtcp)* Add RTCP dissector with rtcp-mux support in RTP ([#287](https://github.com/higebu/packet-dissector/issues/287))
- *(radius)* Decode extended dictionary, VSAs and CoA codes ([#236](https://github.com/higebu/packet-dissector/issues/236))
- *(pfcp)* [**breaking**] Decode common N4/Sx IEs and vendor-specific IEs ([#265](https://github.com/higebu/packet-dissector/issues/265))
- *(ntp)* Dissect extension fields, NTS and MACs ([#245](https://github.com/higebu/packet-dissector/issues/245))
- *(ngap)* Decode PDU session resource lists, transfers and common IEs ([#269](https://github.com/higebu/packet-dissector/issues/269))
- *(nas5g)* Decode 5GMM and 5GSM information elements ([#250](https://github.com/higebu/packet-dissector/issues/250))
- *(isis)* [**breaking**] Decode sub-TLVs, MT, Router Capability and SRv6 TLVs ([#264](https://github.com/higebu/packet-dissector/issues/264))
- *(ike)* Decode IKEv1 and IKEv2 payload bodies ([#262](https://github.com/higebu/packet-dissector/issues/262))
- *(http2)* Track HPACK dynamic tables and CONTINUATION per connection ([#295](https://github.com/higebu/packet-dissector/issues/295))
- *(esp)* [**breaking**] Add ESN, GCM ICV lengths and more ESP algorithms ([#268](https://github.com/higebu/packet-dissector/issues/268))
- *(llmnr)* Add LLMNR dissector on UDP/TCP 5355 ([#293](https://github.com/higebu/packet-dissector/issues/293))
- *(diameter)* Name enumerated values and extend AVP dictionary ([#249](https://github.com/higebu/packet-dissector/issues/249))
- *(eap)* Decode EAP in RADIUS, Diameter and IKEv2 ([#312](https://github.com/higebu/packet-dissector/issues/312))
- *(dhcp)* Concatenate split options per RFC 3396 ([#263](https://github.com/higebu/packet-dissector/issues/263))
- Verify SCTP, IGMP, GRE, VRRP, OSPF and ICMP extension checksums ([#299](https://github.com/higebu/packet-dissector/issues/299))
- [**breaking**] Add IEEE 802.11 and radiotap dissectors ([#291](https://github.com/higebu/packet-dissector/issues/291))
- [**breaking**] Add M3UA and SCCP dissectors ([#292](https://github.com/higebu/packet-dissector/issues/292))
- *(snmp)* Add SNMP dissector and core BER walker ([#302](https://github.com/higebu/packet-dissector/issues/302))
- *(bgp)* Decode structured path attribute values ([#248](https://github.com/higebu/packet-dissector/issues/248))
- *(bgp)* [**breaking**] Decode extended communities as objects ([#261](https://github.com/higebu/packet-dissector/issues/261))
- *(bgp)* Decode ORF/BGPsec/Multiple Labels capabilities, NOTIFICATION data and ORFs ([#267](https://github.com/higebu/packet-dissector/issues/267))
- *(bgp)* Decode EVPN NLRI ([#270](https://github.com/higebu/packet-dissector/issues/270))
- *(bgp)* Decode Flow Specification NLRI ([#272](https://github.com/higebu/packet-dissector/issues/272))
- *(bgp)* Decode BGP-LS NLRI ([#273](https://github.com/higebu/packet-dissector/issues/273))
- *(bgp)* Decode Route Target membership NLRI ([#274](https://github.com/higebu/packet-dissector/issues/274))
- *(bgp)* Decode SR Policy NLRI ([#275](https://github.com/higebu/packet-dissector/issues/275))
- *(bgp)* Decode MCAST-VPN NLRI ([#276](https://github.com/higebu/packet-dissector/issues/276))
- *(bgp)* Decode VPLS NLRI ([#277](https://github.com/higebu/packet-dissector/issues/277))
- *(bmp)* Add BGP Monitoring Protocol dissector ([#286](https://github.com/higebu/packet-dissector/issues/286))
- *(dhcp, dhcpv6)* Decode more options, DUIDs and RFC 7341 messages ([#254](https://github.com/higebu/packet-dissector/issues/254))
- *(tcp)* [**breaking**] Decode TCP options and the AE flag ([#234](https://github.com/higebu/packet-dissector/issues/234))
- [**breaking**] Decode IPv4/IPv6 options, routing types and MH messages ([#242](https://github.com/higebu/packet-dissector/issues/242))
- *(gtpv1u)* Decode extension headers and signalling IEs ([#237](https://github.com/higebu/packet-dissector/issues/237))
- *(dns)* Decode SvcParams, EDNS options, type bitmaps and more RR types ([#240](https://github.com/higebu/packet-dissector/issues/240))
- *(vxlan,geneve)* Add VXLAN-GPE, VXLAN-GBP and Geneve option TLVs ([#241](https://github.com/higebu/packet-dissector/issues/241))
- *(gtpv2c)* [**breaking**] Decode common IEs and piggybacked messages ([#257](https://github.com/higebu/packet-dissector/issues/257))
- Decode more ICMPv6 messages, NDP options and ICMP names ([#260](https://github.com/higebu/packet-dissector/issues/260))
- *(lldp)* Decode org-specific TLVs, capability bits and network IDs ([#266](https://github.com/higebu/packet-dissector/issues/266))
- *(l2tp)* Dissect L2TPv2 AVPs and L2TPv3 typed AVPs and data payload ([#271](https://github.com/higebu/packet-dissector/issues/271))
- [**breaking**] Decode SCTP chunk bodies and dispatch user data by PPID ([#247](https://github.com/higebu/packet-dissector/issues/247))
- *(tls)* Decode extensions and handshake message bodies ([#258](https://github.com/higebu/packet-dissector/issues/258))
- *(stp)* Decode MST and SPT BPDUs ([#259](https://github.com/higebu/packet-dissector/issues/259))
- *(ospf)* [**breaking**] Decode LSA bodies, extended TLVs and trailers ([#251](https://github.com/higebu/packet-dissector/issues/251))
- *(mpls)* [**breaking**] Decode PW control word, ACH and special-purpose labels ([#255](https://github.com/higebu/packet-dissector/issues/255))
- *(stun)* [**breaking**] Decode attribute values and name TURN, ICE and RFC 5780 codes ([#243](https://github.com/higebu/packet-dissector/issues/243))
- *(quic)* [**breaking**] Decrypt client Initial packets and parse frames ([#246](https://github.com/higebu/packet-dissector/issues/246))
- *(registry)* Reassemble IPv4 and IPv6 fragments ([#301](https://github.com/higebu/packet-dissector/issues/301))
- *(registry)* Register assigned TLS, SIP, RADIUS, RARP and Ethernet dispatch keys ([#280](https://github.com/higebu/packet-dissector/issues/280))
- *(pppoe)* Add PPPoE (RFC 2516) dissector ([#283](https://github.com/higebu/packet-dissector/issues/283))
- *(gtpv1c)* Add GTPv1-C dissector ([#284](https://github.com/higebu/packet-dissector/issues/284))
- *(mpls)* Add decode-as rules for PW payloads by label ([#296](https://github.com/higebu/packet-dissector/issues/296))
- *(nas-eps)* Add EPS NAS dissector ([#297](https://github.com/higebu/packet-dissector/issues/297))
- *(ethernet)* Add standalone 802.1Q/802.1ad VLAN tag dissector ([#285](https://github.com/higebu/packet-dissector/issues/285))
- *(sgsap)* Add SGsAP dissector ([#309](https://github.com/higebu/packet-dissector/issues/309))
- *(eap)* Add EAP and EAPOL dissectors ([#294](https://github.com/higebu/packet-dissector/issues/294))
- *(core)* Add opt-in checksum verification ([#289](https://github.com/higebu/packet-dissector/issues/289))
- *(cdp)* [**breaking**] Add CDP dissector and SNAP OUI/PID dispatch ([#303](https://github.com/higebu/packet-dissector/issues/303))
- Add XnAP, F1AP and E1AP dissectors ([#304](https://github.com/higebu/packet-dissector/issues/304))
- *(nsh)* Add NSH (RFC 8300) dissector ([#288](https://github.com/higebu/packet-dissector/issues/288))

### 🐛 Bug Fixes

- *(radius)* Do not interpret Long Extended fragments or empty EVS values ([#322](https://github.com/higebu/packet-dissector/issues/322))
- *(tls,quic)* Address post-merge review findings ([#318](https://github.com/higebu/packet-dissector/issues/318))
- *(nas5g, ngap)* Address post-merge review findings ([#317](https://github.com/higebu/packet-dissector/issues/317))
- *(mpls)* Stop decoding OAM Alert payload as PW control word ([#315](https://github.com/higebu/packet-dissector/issues/315))
- *(ospf,isis)* Bound SRv6 sub-TLV nesting and dedupe raw leftovers ([#316](https://github.com/higebu/packet-dissector/issues/316))
- *(ike)* Do not name IP protocol ID 0 as HOPOPT ([#323](https://github.com/higebu/packet-dissector/issues/323))
- *(http)* Declare header value as Any for obs-text bytes ([#327](https://github.com/higebu/packet-dissector/issues/327))
- Correct 3GPP message type tables and ciphered 5G NAS handling ([#222](https://github.com/higebu/packet-dissector/issues/222))
- *(gtpv1u,pfcp)* Address post-merge review findings ([#324](https://github.com/higebu/packet-dissector/issues/324))
- *(dns)* Bound RDATA-embedded names by RDLENGTH ([#229](https://github.com/higebu/packet-dissector/issues/229))
- L2TPv3 AVP names, IKEv1 encrypted payloads, DHCP chaddr/BOOTP ([#224](https://github.com/higebu/packet-dissector/issues/224))
- *(dns, dhcp, ntp)* Address post-merge review findings ([#320](https://github.com/higebu/packet-dissector/issues/320))
- *(bgp)* Decode 4-octet AS_PATH and SAFI-aware MP NLRI ([#227](https://github.com/higebu/packet-dissector/issues/227))
- *(bgp)* Correct BFD TLV, next hop and SR Policy ADD-PATH decoding ([#326](https://github.com/higebu/packet-dissector/issues/326))
- *(s1ap)* Keep PrivateMessage raw and decode names as strings
- *(ngap)* Decode IE values bit-aligned per APER ([#228](https://github.com/higebu/packet-dissector/issues/228))
- [**breaking**] Dissect NULL/LOOP/raw IP link types and reject unknown ones ([#223](https://github.com/higebu/packet-dissector/issues/223))
- VRRPv2, BFD Echo, NTP mode 6/7 and IGMP MRD decoding ([#225](https://github.com/higebu/packet-dissector/issues/225))
- Bound payload by IP/UDP/802.3 length and accept snaplen truncation ([#226](https://github.com/higebu/packet-dissector/issues/226))
- *(stun)* Accept TURN ChannelData and classic STUN on port 3478 ([#232](https://github.com/higebu/packet-dissector/issues/232))
- [**breaking**] Dispatch every bundled SCTP DATA chunk and skip fragments ([#233](https://github.com/higebu/packet-dissector/issues/233))
- *(quic)* [**breaking**] Split coalesced packets and drop protected key_phase ([#231](https://github.com/higebu/packet-dissector/issues/231))
- [**breaking**] Decode every TLS handshake message and label by negotiated version ([#235](https://github.com/higebu/packet-dissector/issues/235))
- *(gre)* Decode Enhanced GRE v1, RFC 1701 routing and NVGRE key ([#230](https://github.com/higebu/packet-dissector/issues/230))
- *(sip)* Frame UDP bodies per datagram and accept CRLF keep-alives ([#244](https://github.com/higebu/packet-dissector/issues/244))
- *(ethernet)* Decode LLC control length, SNAP and cooked LLC payloads ([#253](https://github.com/higebu/packet-dissector/issues/253))
- *(http)* Determine body length per RFC 9112 6.3 ([#256](https://github.com/higebu/packet-dissector/issues/256))
- *(lacp)* Dissect all Slow Protocols subtypes and LACPv2 TLVs ([#238](https://github.com/higebu/packet-dissector/issues/238))
- [**breaking**] Track TCP connection lifecycle in stream reassembly ([#239](https://github.com/higebu/packet-dissector/issues/239))
- *(http2)* Keep dissecting HTTP/2 frames after the connection preface ([#282](https://github.com/higebu/packet-dissector/issues/282))
- *(ipv4,ipv6)* Keep option octets that do not fit the decoded layout ([#319](https://github.com/higebu/packet-dissector/issues/319))
- *(icmpv6)* Keep NDP option octets past the decoded layout ([#321](https://github.com/higebu/packet-dissector/issues/321))
- *(tcp)* Keep reassembly on early FIN, fix eviction and projection ([#325](https://github.com/higebu/packet-dissector/issues/325))
- *(stp)* Report truncated MSTI messages instead of RST fallback ([#314](https://github.com/higebu/packet-dissector/issues/314))

### 💼 Other

- Merge remote-tracking branch 'origin/main' into feat-s1ap
- Merge remote-tracking branch 'origin/main' into feat-s1ap
## [0.5.0] - 2026-09-15

### 🚀 Features

- *(esp)* Decode NULL-encrypted ESP behind an ICV
- *(esp)* Dissect UDP-encapsulated ESP on port 4500
## [0.4.2] - 2026-09-06

### 🚀 Features

- *(core)* Add SpecReference and ProtocolLayer dissector metadata
- Report specification references and layer for every dissector

### 🐛 Bug Fixes

- Address review findings on dispatcher references and spec ids
## [0.4.1] - 2026-09-05

### 🚀 Features

- *(bgp)* Mirror MP_REACH/MP_UNREACH AFI/SAFI at the UPDATE top level

### 📚 Documentation

- *(bgp)* Condense the README output-shape notes
## [0.4.0] - 2026-09-05

### 🚀 Features

- *(srv6)* Describe flags children
- *(bgp)* Decode OPEN capabilities
- *(core)* Add FieldType::Any for values whose type varies at runtime

### 🐛 Bug Fixes

- *(bgp,srv6)* Address review findings on NLRI schema and SRv6 children

### 💼 Other

- Merge branch 'bgp-capabilities' into feat/bgp-addpath-capabilities
## [0.3.5] - 2026-07-29

### 🐛 Bug Fixes

- *(esp)* Avoid deprecated Array::from_slice with aes-gcm 0.11
## [0.3.4] - 2026-07-27

### 🚀 Features

- *(bgp)* Follow draft-ietf-bess-mup-safi-01
- *(sdp)* Add SDP (RFC 8866) dissector

### 🐛 Bug Fixes

- *(sdp)* Align parsing with RFC 8866 ABNF
- *(bgp)* Correct Type 2 ST endpoint address/TEID field order
- *(bgp)* Derive Type 2 ST TLV boundary from declared Endpoint Length
- *(tcp)* End dispatch after content-type body sub-dissection
- *(tcp)* Count content-type body as consumed on parse failure

### 📚 Documentation

- *(registry)* Add missing RFC 3261 link
## [0.3.3] - 2026-06-11

### 🚀 Features

- *(pfcp)* Parse UE IP Address and other common IEs
- Add shallow dissect APIs for summaries and field projection

### 🚜 Refactor

- *(pfcp,gtpv2c)* Defer FQDN label decoding to format_fn

### 📚 Documentation

- Address review comments on shallow dissect APIs
## [0.3.2] - 2026-04-17

### 🚀 Features

- *(core)* Resolve container display name from children

### 🐛 Bug Fixes

- *(vrrp)* Flatten single-address Object into Array children
- *(tls)* Derive extension container label from inner type
- *(stun)* Derive attribute container label from inner type
- *(srv6)* Derive TLV container label from inner type
- *(sip)* Separate header container descriptor from inner name field
- *(sctp)* Derive chunk container label from inner type
- *(radius)* Derive attribute container label from inner type
- *(ppp)* Derive option container label from inner type
- *(pfcp)* Derive IE container label from inner type
- *(ospf)* Derive LSR entry container label from inner ls_type
- *(ngap)* Derive IE container label from inner id
- *(lldp)* Derive TLV container label from inner type
- *(l2tpv3)* Derive AVP container label from inner vendor_id/attribute_type
- *(isis)* Derive Protocols-Supported container label from inner nlpid
- *(ike)* Derive payload container label from inner type
- *(igmp)* Derive group record container label from inner record_type
- *(icmpv6)* Derive NDP option container label from inner type
- *(http2)* Separate header container descriptor from inner name field
- *(http)* Separate header container descriptor from inner name field
- *(gtpv2c)* Derive IE container label from inner type
- *(gtpv1u)* Derive extension header container label from inner type
- *(dns)* Derive EDNS option container label from inner code
- *(diameter)* Derive AVP container label from inner code
- *(dhcpv6)* Derive option container label from inner code
- *(dhcp)* Derive relay agent sub-option container label from inner code

### 📚 Documentation

- Update README version to 0.3
## [0.3.1] - 2026-04-17

### 📚 Documentation

- Describe property-based test layer in AGENTS.md and README

### 🧪 Testing

- *(pbt)* Add tcp property-based tests
## [0.3.0] - 2026-04-17

### 🚀 Features

- *(tls)* Name RFC 8446 §4.2 extensions 19, 20, 48
- *(tls)* Name heartbeat/encrypt_then_mac/record_size_limit/compress_certificate
- *(ppp)* Align PPP/LCP/IPCP/PAP/CHAP with their RFCs
- *(lacp)* Expose TLV type and length fields per IEEE 802.1AX-2020
- *(isis)* Add RFC 5310 auth type 3 and expand RFC references
- *(icmp)* Parse RFC 4884 ICMP Extension Structure
- *(mdns)* Parse QU and cache-flush bits per RFC 6762

### 🐛 Bug Fixes

- *(vrrp)* Drop bogus format_fn on IPvX address child
- *(stun)* Correct ALTERNATE-DOMAIN code and add PASSWORD-ALGORITHMS
- *(rtp)* Claim entire packet and expose payload field
- *(radius)* Align attribute classifications with RFC 2865/2866
- *(quic)* Honor RFC 9369 v2 packet types and parse Retry Integrity Tag
- *(ospf)* Correct OSPFv3 LSA function code 7 name and neighbor alignment error
- *(ntp)* Audit dissector against RFC 5905 and updates
- *(mpls)* Add GAL dispatch and correct RFC citations
- *(lldp)* Align dissector with IEEE 802.1AB-2016
- *(l2tpv3)* Expose L and S bits in UDP control header
- *(ipv6)* Add RFC URL references, reserved fields, and unit tests
- *(ipv4)* Correct flags field byte range and add RFC citations
- *(ike)* Align with RFC 7296/2408 and fix version-specific fields
- *(icmpv6)* Parse invoking packet for Type 2/4, fix Ext Echo seq width
- *(icmp)* Correct Photuris pointer type and Router Advertisement preference signedness
- *(dns)* Correct CAA tag range and remove NAPTR allocation
- *(http2)* Correct padded frame offsets and enforce fixed-length frames
- *(gre)* Enforce RFC 2784 reserved-bit discard rule and expose Reserved0
- *(ethernet)* Reject truncated inner VLAN tag in QinQ frames
- *(esp)* Correct RFC 4303 section refs and add AES-192-GCM
- *(dhcpv6)* Align MAX_RELAY_DEPTH with RFC 9915 HOP_COUNT_LIMIT=8
- *(dhcp)* Handle RFC 3397 compression pointers and add missing coverage tests
- *(bgp)* Align dissector with RFC 7313, RFC 9072, and RFC 4486/8203
- *(bfd)* Enforce RFC 5880 reception checks and fix auth length
- *(arp)* Classify RFC 5227 probe/announcement and IANA name lookups
- *(igmp)* Align IGMPv3 fields with RFC 9776

### 💼 Other

- Merge pull request #71 from higebu/rfc-verify-mdns
- Merge pull request #64 from higebu/rfc-verify-ntp

### 📚 Documentation

- *(tcp)* Add RFC 9293 URL to field comments

### 🧪 Testing

- *(udp)* Add RFC 768/9868 unit tests and surplus-area note
- *(sctp)* Add RFC 9260 unit tests and missing chunk types
- *(l2tp)* Verify reserved bits are ignored per RFC 2661 §3.1
- *(geneve)* Align RFC 8926 refs and extend coverage
- *(ah)* Verify RFC 4302 receiver-side behaviors
## [0.2.5] - 2026-04-15

### 🚀 Features

- *(pfcp)* Add IE type names for types 118-402 per TS 29.244
- *(pfcp)* Add specialized parsers for common leaf IEs

### 🐛 Bug Fixes

- *(pfcp)* Add missing grouped IE types to parser

### 🧪 Testing

- *(pfcp)* Cover every ie_type_name match arm
## [0.2.4] - 2026-04-12

### 🚀 Features

- *(srv6)* Add hex format_fn for SID structure fields
- *(isis)* Add ISO 10589 format functions for system/node/LSP IDs
- *(bgp)* Format NLRI prefixes as CIDR notation
- *(bgp)* Add format_fn for aggregator, ext community, large community, RD, and TEID

### 📚 Documentation

- Fix outdated comment on NTP reference_id format_fn
## [0.2.3] - 2026-04-11

### 🚀 Features

- *(esp)* Decode inner packet for NULL encryption by default
## [0.2.2] - 2026-04-05

### 🚀 Features

- *(ci)* Add error threshold after 30 samples in bencher benchmarks
- *(icmpv6)* Parse invoking packet in type 1/3
- *(icmp)* Parse transport ports in invoking packet

### 🐛 Bug Fixes

- *(renovate)* Upgrade to config:best-practices and fix semanticCommits preset

### ⚙️ Miscellaneous Tasks

- Remove redundant renovate config
- Add conventionalCommits preset to renovate
## [0.2.1] - 2026-04-02

### 🚀 Features

- *(core)* Add DissectBuffer::clear_into for lifetime rebinding

### ⚙️ Miscellaneous Tasks

- *(release)* V0.2.1
## [0.2.0] - 2026-04-01

### 🚀 Features

- *(diameter)* Add 3GPP Gx, Rx, Cx/Dx, Sh interface support

### 🐛 Bug Fixes

- Replace find().is_none() with !any() in dns_test.rs

### 🧪 Testing

- *(dhcpv6)* Add comprehensive unit tests to improve coverage from 18% to 99%

### ⚙️ Miscellaneous Tasks

- Fix codecov-action
- Update AGENTS.md
- Update taplo.toml
- Add publish.yml
- Fix benchmarks.yml
- Update justfile
- *(release)* V0.2.0
## [0.1.0] - 2026-03-31

### ⚙️ Miscellaneous Tasks

- Initial commit
- *(release)* V0.1.0
