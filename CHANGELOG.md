# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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
