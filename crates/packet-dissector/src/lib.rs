//! # packet-dissector
//!
//! A Rust crate for zero-copy parsing of layered network packets with
//! registry-based protocol chaining. Protocol dissectors can be registered
//! and chained to parse layered packets from L2 through L7.
//!
//! ## Features
//!
//! - **Zero-copy parsing** — works directly on `&[u8]` slices
//! - **Extensible** — add new protocols by implementing the [`dissector::Dissector`] trait
//! - **Layered** — automatic chaining from Ethernet → IP → TCP/UDP → Application
//! - **Safe Rust** — minimal `unsafe` (lifetime extension in the registry only, with `// SAFETY:` comments)
//! - **Modular** — enable only the protocols you need via feature flags
//!
//! [`DissectorRegistry::default()`](registry::DissectorRegistry::default) registers all
//! built-in protocol dissectors. See its documentation for the full list.
//!
//! ## Quick Start
//!
//! ```
//! use packet_dissector::registry::DissectorRegistry;
//! use packet_dissector::packet::DissectBuffer;
//! use packet_dissector::field::FieldValue;
//!
//! // Build a registry with all built-in dissectors
//! let registry = DissectorRegistry::default();
//!
//! // An Ethernet + IPv4 + UDP packet (minimal example)
//! let packet_bytes: &[u8] = &[
//!     // Ethernet header (14 bytes)
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst MAC
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src MAC
//!     0x08, 0x00,                         // EtherType: IPv4
//!     // IPv4 header (20 bytes)
//!     0x45, 0x00, 0x00, 0x1c,             // ver, ihl, len=28
//!     0x00, 0x00, 0x00, 0x00,             // id, flags, frag
//!     0x40, 0x11, 0x00, 0x00,             // ttl=64, proto=UDP, checksum
//!     0x0a, 0x00, 0x00, 0x01,             // src: 10.0.0.1
//!     0x0a, 0x00, 0x00, 0x02,             // dst: 10.0.0.2
//!     // UDP header (8 bytes)
//!     0x30, 0x39, 0x00, 0x50,             // src=12345, dst=80
//!     0x00, 0x08, 0x00, 0x00,             // len=8, checksum
//! ];
//!
//! let mut buf = DissectBuffer::new();
//! registry.dissect(packet_bytes, &mut buf).unwrap();
//! assert_eq!(buf.layers().len(), 3); // Ethernet, IPv4, UDP
//! assert_eq!(buf.layers()[0].name, "Ethernet");
//! assert_eq!(buf.layers()[1].name, "IPv4");
//! assert_eq!(buf.layers()[2].name, "UDP");
//!
//! // Look up layers by name
//! let udp = buf.layer_by_name("UDP").unwrap();
//! let src_port = buf.field_by_name(udp, "src_port").unwrap();
//! assert_eq!(src_port.value, FieldValue::U16(12345));
//! ```

#![deny(missing_docs)]

// Re-export core types so users can `use packet_dissector::dissector::Dissector` etc.
pub use packet_dissector_core::dissector;
pub use packet_dissector_core::error;
pub use packet_dissector_core::field;
pub use packet_dissector_core::packet;

/// Re-exports of built-in protocol dissector crates.
///
/// Each protocol is gated behind a feature flag. All are enabled by default.
pub mod dissectors {

    #[cfg(feature = "ethernet")]
    pub use packet_dissector_ethernet as ethernet;

    #[cfg(feature = "linux_sll")]
    pub use packet_dissector_linux_sll as linux_sll;

    #[cfg(feature = "linux_sll2")]
    pub use packet_dissector_linux_sll2 as linux_sll2;

    #[cfg(feature = "arp")]
    pub use packet_dissector_arp as arp;

    #[cfg(feature = "lacp")]
    pub use packet_dissector_lacp as lacp;

    #[cfg(feature = "ipv4")]
    pub use packet_dissector_ipv4 as ipv4;

    #[cfg(feature = "ipv6")]
    pub use packet_dissector_ipv6 as ipv6;

    #[cfg(feature = "icmp")]
    pub use packet_dissector_icmp as icmp;

    #[cfg(feature = "icmpv6")]
    pub use packet_dissector_icmpv6 as icmpv6;

    #[cfg(feature = "igmp")]
    pub use packet_dissector_igmp as igmp;

    #[cfg(feature = "tcp")]
    pub use packet_dissector_tcp as tcp;

    #[cfg(feature = "udp")]
    pub use packet_dissector_udp as udp;

    #[cfg(feature = "sctp")]
    pub use packet_dissector_sctp as sctp;

    #[cfg(feature = "dns")]
    pub use packet_dissector_dns as dns;

    #[cfg(feature = "mdns")]
    pub use packet_dissector_mdns as mdns;

    #[cfg(feature = "dhcp")]
    pub use packet_dissector_dhcp as dhcp;

    #[cfg(feature = "dhcpv6")]
    pub use packet_dissector_dhcpv6 as dhcpv6;

    #[cfg(feature = "srv6")]
    pub use packet_dissector_srv6 as srv6;

    #[cfg(feature = "gtpv1u")]
    pub use packet_dissector_gtpv1u as gtpv1u;

    #[cfg(feature = "gtpv2c")]
    pub use packet_dissector_gtpv2c as gtpv2c;

    #[cfg(feature = "pfcp")]
    pub use packet_dissector_pfcp as pfcp;

    #[cfg(feature = "http")]
    pub use packet_dissector_http as http;

    #[cfg(feature = "http2")]
    pub use packet_dissector_http2 as http2;

    #[cfg(feature = "sip")]
    pub use packet_dissector_sip as sip;

    #[cfg(feature = "diameter")]
    pub use packet_dissector_diameter as diameter;

    #[cfg(feature = "nas5g")]
    pub use packet_dissector_nas5g as nas5g;
    #[cfg(feature = "ngap")]
    pub use packet_dissector_ngap as ngap;

    #[cfg(feature = "geneve")]
    pub use packet_dissector_geneve as geneve;

    #[cfg(feature = "gre")]
    pub use packet_dissector_gre as gre;

    #[cfg(feature = "mpls")]
    pub use packet_dissector_mpls as mpls;

    #[cfg(feature = "vxlan")]
    pub use packet_dissector_vxlan as vxlan;

    #[cfg(feature = "lldp")]
    pub use packet_dissector_lldp as lldp;

    #[cfg(feature = "stp")]
    pub use packet_dissector_stp as stp;

    #[cfg(feature = "ntp")]
    pub use packet_dissector_ntp as ntp;

    #[cfg(feature = "ospf")]
    pub use packet_dissector_ospf as ospf;

    #[cfg(feature = "vrrp")]
    pub use packet_dissector_vrrp as vrrp;

    #[cfg(feature = "bfd")]
    pub use packet_dissector_bfd as bfd;

    #[cfg(feature = "isis")]
    pub use packet_dissector_isis as isis;

    #[cfg(feature = "bgp")]
    pub use packet_dissector_bgp as bgp;

    #[cfg(feature = "l2tp")]
    pub use packet_dissector_l2tp as l2tp;

    #[cfg(feature = "l2tpv3")]
    pub use packet_dissector_l2tpv3 as l2tpv3;

    #[cfg(feature = "tls")]
    pub use packet_dissector_tls as tls;

    #[cfg(feature = "ppp")]
    pub use packet_dissector_ppp as ppp;

    #[cfg(feature = "radius")]
    pub use packet_dissector_radius as radius;

    #[cfg(feature = "ah")]
    pub use packet_dissector_ah as ah;

    #[cfg(feature = "esp")]
    pub use packet_dissector_esp as esp;

    #[cfg(feature = "ike")]
    pub use packet_dissector_ike as ike;

    #[cfg(feature = "rtp")]
    pub use packet_dissector_rtp as rtp;

    #[cfg(feature = "quic")]
    pub use packet_dissector_quic as quic;

    #[cfg(feature = "stun")]
    pub use packet_dissector_stun as stun;
}

#[cfg(feature = "tcp")]
mod tcp_reassembly;

pub mod registry;
