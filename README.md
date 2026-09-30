# packet-dissector

A Rust crate for layered network packet parsing with registry-based protocol chaining.

[![CI](https://github.com/higebu/packet-dissector/actions/workflows/ci.yml/badge.svg)](https://github.com/higebu/packet-dissector/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/packet-dissector.svg)](https://crates.io/crates/packet-dissector)
[![docs.rs](https://docs.rs/packet-dissector/badge.svg)](https://docs.rs/packet-dissector)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
packet-dissector = "0.3"
```

## Features

- **Zero-copy on the normal path** — dissectors borrow directly from `&[u8]` slices when parsing a single packet; TCP reassembly, IP fragment reassembly and decrypted-payload paths copy into auxiliary storage
- **Extensible** — add new protocols by implementing the `Dissector` trait
- **Layered dissection** — automatic chaining from Ethernet through IP, TCP/UDP, to application protocols
- **Safe Rust** — minimal `unsafe` in the registry only, documented with `// SAFETY:` comments
- **Modular** — enable only the protocols you need via feature flags

## Supported Protocols

The set of built-in dissectors is feature-gated and keeps growing. Representative
protocols include:

| Category | Protocols |
|----------|-----------|
| L2 | Ethernet II (with IEEE 802.2 LLC and SNAP), Linux SLL, Linux SLL2, BSD loopback (NULL / LOOP), raw IP link types (RAW / IPV4 / IPV6), IEEE 802.11 (MAC header, management elements, LLC/SNAP, A-MSDU), radiotap, 802.1Q VLAN, 802.1ad QinQ (stacked tags; also standalone tags after SLL, SLL2 or GRE), ARP, Slow Protocols (LACP, Marker, OAM, OSSP/ESMC), LLDP, STP, CDP, PPPoE, EAPOL / EAP (802.1X) |
| L3 / routing | IPv4, IPv6, IPv6 extension headers (Hop-by-Hop, Routing, Fragment, Destination Options, Mobility), ICMP, ICMPv6, IGMP, OSPF, VRRP, PIM, IS-IS, AH, ESP, SRv6, GRE, MPLS |
| L4 / tunneling | TCP, UDP, SCTP, L2TP, L2TPv3, GENEVE, VXLAN, VXLAN-GPE, NSH |
| Application / control | DNS, mDNS, DHCP, DHCPv6, HTTP/1.1, HTTP/2, SIP, SDP, Diameter, NTP, BFD, BGP, BMP, TLS, PPP, RADIUS, RTP, QUIC, STUN |
| 3GPP | GTPv1-U, GTPv1-C, GTPv2-C, PFCP, NAS5G, NAS-EPS, NGAP, XnAP, F1AP, E1AP, SGsAP |

See `crates/packet-dissector/Cargo.toml` and `crates/packet-dissector/src/lib.rs`
for the current feature-gated protocol list.

## Feature Flags

All built-in dissectors are enabled by default. Disable `default-features` to
select only what you need:

```toml
# All protocols (default)
packet-dissector = "0.3"

# Only Ethernet + IPv4 + TCP
packet-dissector = { version = "0.3", default-features = false, features = ["ethernet", "ipv4", "tcp"] }

# Convenience groups
packet-dissector = { version = "0.3", default-features = false, features = ["layer2", "layer3", "layer4"] }
```

Representative feature flags:

- Link layer: `ethernet`, `linux_sll`, `linux_sll2`, `null`, `raw_ip`, `ieee80211`, `radiotap`, `arp`, `lacp`, `lldp`, `eap`, `stp`, `cdp`, `pppoe`
- Network / routing: `ipv4`, `ipv6`, `icmp`, `icmpv6`, `igmp`, `ospf`, `vrrp`, `pim`, `isis`, `ah`, `esp`, `ike`, `srv6`, `gre`, `mpls`
- Transport / tunneling: `tcp`, `udp`, `sctp`, `l2tp`, `l2tpv3`, `geneve`, `vxlan`, `nsh`
- Application / control: `dns`, `mdns`, `dhcp`, `dhcpv6`, `http`, `http2`, `sip`, `sdp`, `diameter`, `ntp`, `bfd`, `bgp`, `bmp`, `tls`, `ppp`, `radius`, `rtp`, `quic`, `stun`
- 3GPP: `gtpv1u`, `gtpv1c`, `gtpv2c`, `pfcp`, `nas5g`, `nas-eps`, `ngap`, `xnap`, `f1ap`, `e1ap`, `sgsap`
- `esp-decrypt` enables ESP payload decryption support
- `quic-decrypt` enables QUIC client Initial decryption and frame decoding
- `ip-reassembly` enables IPv4 / IPv6 fragment reassembly in the registry (without it, non-initial fragments still end the chain after the IP layer)

Convenience groups:

- `layer2 = ["ethernet", "linux_sll", "linux_sll2", "null", "raw_ip", "ieee80211", "radiotap", "arp", "lacp", "lldp", "eap", "stp", "cdp", "ppp", "pppoe"]`
- `layer3 = ["ipv4", "ipv6", "icmp", "icmpv6", "igmp", "srv6"]`
- `layer4 = ["tcp", "udp", "sctp"]`
- `application = ["dns", "mdns", "dhcp", "dhcpv6", "http", "http2", "sip", "sdp", "diameter", "ntp", "radius", "rtp", "tls", "quic", "stun"]`
- `tunneling = ["gre", "geneve", "vxlan", "l2tp", "l2tpv3", "mpls", "nsh"]`
- `routing = ["ospf", "isis", "bgp", "bmp", "bfd", "vrrp", "pim"]`
- `ipsec = ["ah", "esp", "ike"]`
- `3gpp = ["gtpv1u", "gtpv1c", "gtpv2c", "pfcp", "nas5g", "nas-eps", "ngap", "xnap", "f1ap", "e1ap", "sgsap"]`

For the authoritative, exhaustive list, see
`crates/packet-dissector/Cargo.toml`.

## Quick Start

```rust
use packet_dissector::registry::DissectorRegistry;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::field::FieldValue;

// Build a registry with all built-in dissectors
let registry = DissectorRegistry::default();

// An Ethernet + IPv4 + UDP packet (minimal example)
let packet_bytes: &[u8] = &[
    // Ethernet header (14 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src MAC
    0x08, 0x00,                         // EtherType: IPv4
    // IPv4 header (20 bytes)
    0x45, 0x00, 0x00, 0x1c,             // ver, ihl, len=28
    0x00, 0x00, 0x00, 0x00,             // id, flags, frag
    0x40, 0x11, 0x00, 0x00,             // ttl=64, proto=UDP, checksum
    0x0a, 0x00, 0x00, 0x01,             // src: 10.0.0.1
    0x0a, 0x00, 0x00, 0x02,             // dst: 10.0.0.2
    // UDP header (8 bytes)
    0x30, 0x39, 0x00, 0x50,             // src=12345, dst=80
    0x00, 0x08, 0x00, 0x00,             // len=8, checksum
];

let mut buf = DissectBuffer::new();
registry.dissect(packet_bytes, &mut buf).unwrap();

assert_eq!(buf.layers.len(), 3); // Ethernet, IPv4, UDP
assert_eq!(buf.layers[0].name, "Ethernet");
assert_eq!(buf.layers[1].name, "IPv4");
assert_eq!(buf.layers[2].name, "UDP");

let udp = buf.layer_by_name("UDP").unwrap();
let src_port = buf.field_by_name(udp, "src_port").unwrap();
assert_eq!(src_port.value, FieldValue::U16(12345));
```

## Link-Layer Types

`DissectorRegistry::dissect()` always starts with the entry dissector
(Ethernet). For pcap / pcapng input, pass the file's link-layer type to
`dissect_with_link_type()` (or the `_summary_` / `_projected_` variants). The
default registry handles these
[link-layer types](https://www.tcpdump.org/linktypes.html):

| Value | Name | Feature |
|------:|------|---------|
| 0 | `LINKTYPE_NULL` | `null` |
| 1 | `LINKTYPE_ETHERNET` | `ethernet` |
| 9 | `LINKTYPE_PPP` | `ppp` |
| 50 | `LINKTYPE_PPP_HDLC` | `ppp` |
| 101 | `LINKTYPE_RAW` | `raw_ip` |
| 105 | `LINKTYPE_IEEE802_11` | `ieee80211` |
| 108 | `LINKTYPE_LOOP` | `null` |
| 113 | `LINKTYPE_LINUX_SLL` | `linux_sll` |
| 127 | `LINKTYPE_IEEE802_11_RADIOTAP` | `radiotap` |
| 228 | `LINKTYPE_IPV4` | `raw_ip` |
| 229 | `LINKTYPE_IPV6` | `raw_ip` |
| 276 | `LINKTYPE_LINUX_SLL2` | `linux_sll2` |

Any other link type returns `PacketError::UnsupportedLinkType`; register a
dissector with `register_by_link_type()` to handle it.

## Checksum Verification

Checksums are not verified by default. Enable verification with
`registry.set_verify_checksums(true)`: the IPv4, ICMP (including RFC 4884
extensions), ICMPv6, TCP, UDP, SCTP (CRC32c), IGMP, GRE, VRRP and OSPF
dissectors then add an optional `checksum_status` field next to the checksum
(`good`, `bad`, `unverified` or `not_present`; see
`packet_dissector::checksum::ChecksumStatus`). A bad checksum is never a
dissection error. `unverified` means the checksum could not be computed, e.g.
the capture is cut by the snaplen or a fragment could not be reassembled.

Captures taken on the sending host often carry wrong TCP/UDP/IPv4 checksums
because the NIC computes them after the capture point (checksum offload), so
`bad` on locally sent packets does not necessarily mean corruption.

## Adding a Custom Dissector

Implement the `Dissector` trait and register it. For external crates, depend on
`packet-dissector-core` for the trait and types:

```rust
use packet_dissector_core::dissector::{Dissector, DissectResult, DispatchHint};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::FieldDescriptor;
use packet_dissector_core::packet::DissectBuffer;

struct MyProtocol;

impl Dissector for MyProtocol {
    fn name(&self) -> &'static str { "MyProtocol" }
    fn short_name(&self) -> &'static str { "myproto" }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] { &[] }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let _ = (buf, offset);
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}
```

## Testing

Four complementary test layers run in CI:

- **Unit tests** — per-protocol example-based tests inside each
  `packet-dissector-<protocol>` crate.
- **Integration tests** — multi-layer dissection through `DissectorRegistry`
  in `crates/packet-dissector/tests/`.
- **Allocation tests** — `packet-dissector-test-alloc` verifies zero heap
  allocations during dissection.
- **Property-based tests** — `packet-dissector-pbt` uses `proptest` to check
  universal parser invariants (no panic, `bytes_consumed ≤ data.len()`,
  `Truncated.actual == data.len()`, determinism) across arbitrary and
  structured inputs. Run with `cargo test -p packet-dissector-pbt`, or
  `PROPTEST_CASES=10000 cargo test -p packet-dissector-pbt` for long runs.
  Shrunk counter-examples are written to `proptest-regressions/` and
  committed for reproducibility.

## Documentation

Full API documentation is available on [docs.rs](https://docs.rs/packet-dissector).

See `crates/packet-dissector/examples/` for runnable examples:

- **parse_packet** — parse a raw packet and inspect layers/fields
- **custom_dissector** — implement and register a custom protocol dissector

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
