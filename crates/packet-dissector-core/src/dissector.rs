//! Dissector trait and related types.

use crate::error::PacketError;
use crate::field::FieldDescriptor;
use crate::packet::DissectBuffer;

/// Hint for the registry about which dispatch table and key to use
/// for finding the next protocol dissector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchHint {
    /// Look up the next dissector by EtherType value.
    ByEtherType(u16),
    /// Look up the next dissector by IP protocol number.
    ByIpProtocol(u8),
    /// Look up the next dissector by TCP port numbers (source, destination).
    ///
    /// The registry tries the lower port first, then the higher port as a
    /// fallback, mirroring Wireshark's `tcp.port` dual-port dispatch strategy.
    ByTcpPort(u16, u16),
    /// Look up the next dissector by UDP port numbers (source, destination).
    ///
    /// The registry tries the lower port first, then the higher port as a
    /// fallback, mirroring Wireshark's `udp.port` dual-port dispatch strategy.
    ByUdpPort(u16, u16),
    /// Look up the next dissector by SCTP port numbers (source, destination).
    ///
    /// The registry tries the lower port first, then the higher port as a
    /// fallback, mirroring Wireshark's `sctp.port` dual-port dispatch strategy.
    BySctpPort(u16, u16),
    /// Look up the next dissector for one SCTP user message by its Payload
    /// Protocol Identifier, falling back to the SCTP ports.
    ///
    /// The registry tries the PPID table first (unless `ppid` is 0, which
    /// means "unspecified"), then the lower and the higher port like
    /// [`BySctpPort`](Self::BySctpPort).
    ///
    /// RFC 9260, Section 3.3.1 — "The value 0 indicates that no application
    /// identifier is specified by the upper layer for this payload data." —
    /// <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>
    BySctpPpid {
        /// Payload Protocol Identifier of the DATA / I-DATA chunk.
        ppid: u32,
        /// SCTP source port.
        src_port: u16,
        /// SCTP destination port.
        dst_port: u16,
    },
    /// Look up the next dissector by IPv6 Routing Header type.
    ///
    /// Uses a dedicated routing-type table, mirroring Wireshark's
    /// `ipv6.routing.type` dissector table design.
    ByIpv6RoutingType(u8),
    /// Look up the next dissector by MIME content type (e.g., `"application/sdp"`).
    ///
    /// Uses a dedicated content-type table, enabling application-layer
    /// protocols (such as SIP or HTTP) to dispatch message bodies to
    /// specialised body dissectors based on the `Content-Type` header.
    ///
    /// Only well-known MIME types (interned as `&'static str`) are supported
    /// to avoid heap allocation. Unknown content types should not dispatch.
    ByContentType(&'static str),
    /// Look up the next dissector by IEEE 802.2 LLC DSAP value.
    ///
    /// Used by the Ethernet dissector when the type/length field indicates
    /// an IEEE 802.3 LLC frame (value ≤ 1500). The DSAP byte identifies
    /// the upper-layer protocol (e.g., `0x42` for STP/RSTP).
    ByLlcSap(u8),
    /// Look up the next dissector by SNAP Organization Code and Protocol
    /// Identifier.
    ///
    /// Used by the SNAP dissector when the Organization Code is not one whose
    /// Protocol Identifier is an EtherType (e.g., OUI `0x00000C` with PID
    /// `0x2000` for Cisco CDP). IEEE Std 802-2014, Clause 10 —
    /// <https://standards.ieee.org/standard/802-2014.html>.
    BySnap {
        /// 24-bit Organization Code (OUI) in the low three octets.
        oui: u32,
        /// Protocol Identifier.
        pid: u16,
    },
    /// Look up the next dissector by MPLS Generic Associated Channel (G-ACh)
    /// Channel Type.
    ///
    /// Used after an Associated Channel Header (ACH), whose 16-bit Channel
    /// Type identifies the message that follows (e.g., `0x0007` for BFD
    /// without IP/UDP headers, `0x0021` for IPv4). RFC 5586, Section 2.1 —
    /// <https://www.rfc-editor.org/rfc/rfc5586#section-2.1>; RFC 4385,
    /// Section 5 — <https://www.rfc-editor.org/rfc/rfc4385#section-5>.
    ByAchChannelType(u16),
    /// Look up the next dissector by SS7 MTP3 Service Indicator.
    ///
    /// Used by MTP3-User adaptation layers such as M3UA, whose Protocol Data
    /// carries the Service Indicator of the original MTP3 message (e.g. `3`
    /// for SCCP). Mirrors Wireshark's `mtp3.service_indicator` table. RFC 4666,
    /// Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc4666#section-3.3.1>;
    /// ITU-T Q.704, clause 14.2.1 —
    /// <https://www.itu.int/rec/T-REC-Q.704>.
    ByMtp3ServiceIndicator(u8),
    /// Look up the next dissector for SCCP user data by subsystem number.
    ///
    /// The registry tries the called party SSN first, then the calling party
    /// SSN. SSN 0 ("SSN not known/not used", ITU-T Q.713, clause 3.4.2.2 —
    /// <https://www.itu.int/rec/T-REC-Q.713>) is never looked up. Mirrors
    /// Wireshark's `sccp.ssn` table.
    BySccpSsn {
        /// Subsystem number of the called party address (0 when absent).
        called: u8,
        /// Subsystem number of the calling party address (0 when absent).
        calling: u8,
    },
    /// Look up the next dissector in the link-layer type table, by pcap
    /// `LINKTYPE_` value.
    ///
    /// Used by pseudo-headers that precede another link-layer frame, e.g.
    /// radiotap (`LINKTYPE_IEEE802_11_RADIOTAP`, 127) followed by an IEEE
    /// 802.11 frame (`LINKTYPE_IEEE802_11`, 105) —
    /// <https://www.tcpdump.org/linktypes.html>.
    ByLinkType(u32),
    /// No further dissection is needed.
    End,
}

/// Identifies a dispatch table (and key) where a dissector should be registered.
///
/// This enum allows dissector crates to declaratively describe their
/// registration requirements without depending on the registry itself.
/// Third-party dissectors can use this with [`DissectorPlugin`] to integrate
/// with the registry without modifying core code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DissectorTable {
    /// The entry-point dissector (typically Ethernet).
    Entry,
    /// Register by EtherType value (e.g., `0x0800` for IPv4).
    EtherType(u16),
    /// Register by IP protocol number (e.g., `6` for TCP).
    IpProtocol(u8),
    /// Register by TCP port number (e.g., `53` for DNS).
    TcpPort(u16),
    /// Register by UDP port number (e.g., `53` for DNS).
    UdpPort(u16),
    /// Register by SCTP port number.
    SctpPort(u16),
    /// Register by SCTP Payload Protocol Identifier (e.g., `46` for
    /// Diameter), from the IANA "SCTP Payload Protocol Identifiers"
    /// registry. PPID 0 ("unspecified") is never looked up; see
    /// [`DispatchHint::BySctpPpid`].
    SctpPpid(u32),
    /// Register by IPv6 Routing Header type (e.g., `4` for SRv6).
    Ipv6RoutingType(u8),
    /// Register by MIME content type (e.g., `"application/sdp"`).
    ContentType(&'static str),
    /// Register by IEEE 802.2 LLC DSAP value (e.g., `0x42` for STP).
    LlcSap(u8),
    /// Register by SNAP Organization Code and Protocol Identifier (e.g.,
    /// OUI `0x00000C`, PID `0x2000` for CDP).
    Snap {
        /// 24-bit Organization Code (OUI) in the low three octets.
        oui: u32,
        /// Protocol Identifier.
        pid: u16,
    },
    /// Register by MPLS G-ACh Channel Type (e.g., `0x0007` for BFD).
    AchChannelType(u16),
    /// Register by SS7 MTP3 Service Indicator (e.g., `3` for SCCP). See
    /// [`DispatchHint::ByMtp3ServiceIndicator`].
    Mtp3ServiceIndicator(u8),
    /// Register by SCCP subsystem number (e.g., `6` for the HLR). SSN 0 is
    /// never looked up; see [`DispatchHint::BySccpSsn`].
    SccpSsn(u8),
    /// The fallback dissector for unrecognised IPv6 Routing Header types.
    Ipv6RoutingFallback,
    /// Register by pcap link-layer header type (e.g., `1` for Ethernet, `113` for Linux SLL).
    ///
    /// Used by the registry to dispatch the first dissector based on the
    /// link-layer type found in pcap / pcapng file headers.
    LinkType(u32),
}

/// A plugin that provides one or more dissector registrations.
///
/// Implement this trait to declare how your dissectors should be registered
/// in a [`DissectorRegistry`](crate). Third-party crates can implement this
/// to integrate with the registry without modifying core code.
///
/// # Example
///
/// ```ignore
/// use packet_dissector_core::dissector::{Dissector, DissectorPlugin, DissectorTable};
///
/// pub struct MyPlugin;
///
/// impl DissectorPlugin for MyPlugin {
///     fn dissectors(&self) -> Vec<(DissectorTable, Box<dyn Dissector>)> {
///         vec![
///             (DissectorTable::UdpPort(4789), Box::new(MyDissector)),
///         ]
///     }
/// }
/// ```
pub trait DissectorPlugin {
    /// Returns the list of (dispatch table, dissector) pairs to register.
    fn dissectors(&self) -> Vec<(DissectorTable, Box<dyn Dissector>)>;
}

/// Directional TCP stream key: (source address, destination address, source
/// port, destination port). IP addresses are encoded as 16 bytes
/// (IPv4-mapped for IPv4).
///
/// See [`TcpStreamContext::stream_key`].
pub type TcpStreamKey = ([u8; 16], [u8; 16], u16, u16);

/// Context for TCP stream reassembly, provided by the TCP dissector
/// when dispatching to upper-layer protocol dissectors.
///
/// The registry uses this information to drive centralized TCP stream
/// reassembly, buffering segments until enough contiguous data is
/// available for the upper-layer dissector.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpStreamContext {
    /// Directional stream key identifying the TCP flow (src_ip, dst_ip, src_port, dst_port).
    /// Each direction of a connection has its own key, so the reverse direction
    /// (dst→src) maintains a separate reassembly buffer and sequence space.
    /// IP addresses are encoded as 16 bytes (IPv4-mapped for IPv4).
    pub stream_key: TcpStreamKey,
    /// TCP sequence number of this segment's first payload octet.
    ///
    /// For a SYN segment this is ISN+1, not the header's Sequence Number:
    /// RFC 9293, Section 3.1 — "If SYN is set, the sequence number is the
    /// initial sequence number (ISN) and the first data octet is ISN+1."
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
    pub seq: u32,
    /// Length of the TCP payload in this segment.
    pub payload_len: usize,
    /// TCP control bits of this segment (the header's 8-bit flags field).
    ///
    /// The registry uses SYN, FIN and RST to start and release per-stream
    /// reassembly state (RFC 9293, Sections 3.5 and 3.6 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.5>).
    pub flags: u8,
    /// Sequence number of the first data octet of this direction (ISN+1),
    /// when the direction's SYN has been seen.
    ///
    /// Data at or after it that was never handed to the upper layer can be
    /// placed in front of a buffered stream when it arrives late.
    pub stream_start: Option<u32>,
}

impl TcpStreamContext {
    /// FIN control bit — RFC 9293, Section 3.1 — "No more data from sender."
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
    pub const FLAG_FIN: u8 = 0x01;
    /// SYN control bit — RFC 9293, Section 3.1 — "Synchronize sequence numbers."
    pub const FLAG_SYN: u8 = 0x02;
    /// RST control bit — RFC 9293, Section 3.1 — "Reset the connection."
    pub const FLAG_RST: u8 = 0x04;

    /// Create a stream context. `seq` is the sequence number of the first
    /// payload octet (see [`TcpStreamContext::seq`]).
    pub fn new(stream_key: TcpStreamKey, seq: u32, payload_len: usize, flags: u8) -> Self {
        Self {
            stream_key,
            seq,
            payload_len,
            flags,
            stream_start: None,
        }
    }

    /// Set [`TcpStreamContext::stream_start`].
    pub fn with_stream_start(mut self, stream_start: Option<u32>) -> Self {
        self.stream_start = stream_start;
        self
    }

    /// Whether the SYN control bit is set.
    pub fn is_syn(&self) -> bool {
        self.flags & Self::FLAG_SYN != 0
    }

    /// Whether the FIN control bit is set.
    pub fn is_fin(&self) -> bool {
        self.flags & Self::FLAG_FIN != 0
    }

    /// Whether the RST control bit is set.
    pub fn is_rst(&self) -> bool {
        self.flags & Self::FLAG_RST != 0
    }

    /// Stream key of the opposite direction of the same connection.
    pub fn reverse_key(&self) -> TcpStreamKey {
        let (src, dst, sport, dport) = self.stream_key;
        (dst, src, dport, sport)
    }
}

/// Context for IP fragment reassembly, provided by the IPv4 dissector and
/// the IPv6 Fragment header dissector for every fragment that is not a whole
/// datagram.
///
/// A fragment is a datagram (or packet) whose More Fragments flag is set or
/// whose Fragment Offset is non-zero. RFC 791, Section 3.2 — "If this is a
/// whole datagram (that is both the fragment offset and the more fragments
/// fields are zero), then any reassembly resources associated with this
/// buffer identifier are released and the datagram is forwarded to the next
/// step in datagram processing." —
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.2>. RFC 8200,
/// Section 4.5 — "If the fragment is a whole datagram (that is, both the
/// Fragment Offset field and the M flag are zero), then it does not need
/// any further reassembly" —
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>.
///
/// The registry uses this context to buffer fragments and to dissect the
/// upper layers of the reassembled datagram once every fragment has arrived.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFragmentContext {
    /// Reassembly key: (source address, destination address, protocol,
    /// identification). Addresses are encoded as 16 bytes (IPv4-mapped for
    /// IPv4, see [`ipv4_mapped`](crate::util::ipv4_mapped)).
    ///
    /// IPv4 fragments are grouped by source, destination, protocol and
    /// identification (RFC 791, Section 3.2 — "The internet identification
    /// field (ID) is used together with the source and destination address,
    /// and the protocol fields, to identify datagram fragments for
    /// reassembly." —
    /// <https://www.rfc-editor.org/rfc/rfc791#section-3.2>).
    ///
    /// IPv6 fragments are grouped by source, destination and identification
    /// only (RFC 8200, Section 4.5 — "An original packet is reassembled only
    /// from fragment packets that have the same Source Address, Destination
    /// Address, and Fragment Identification." —
    /// <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>), so the
    /// protocol element of an IPv6 key is always
    /// [`IpFragmentContext::IPV6_KEY_PROTOCOL`].
    pub frag_key: ([u8; 16], [u8; 16], u8, u32),
    /// Protocol of the fragmentable part as carried by this fragment: the
    /// IPv4 Protocol field, or the Next Header field of the IPv6 Fragment
    /// header. The registry dispatches the reassembled payload by the value
    /// of the fragment whose offset is zero.
    pub protocol: u8,
    /// Offset of this fragment's data in the reassembled payload, in bytes
    /// (the Fragment Offset field multiplied by 8).
    pub offset_bytes: usize,
    /// More Fragments flag (IPv4 MF / IPv6 M).
    pub more_fragments: bool,
    /// Length of this fragment's data as declared by the IP length fields
    /// (it may exceed the captured bytes when the capture was truncated).
    pub payload_len: usize,
    /// Octets that the reassembled datagram's length field counts in
    /// addition to the fragment data: the IPv4 header (Total Length includes
    /// it), or the IPv6 extension headers between the IPv6 header and the
    /// Fragment header (Payload Length excludes the IPv6 header itself).
    ///
    /// The registry uses it to discard fragments that would make the
    /// reassembled length field exceed 65,535 octets.
    pub unfragmentable_len: usize,
}

impl IpFragmentContext {
    /// Protocol element of every IPv6 reassembly key: 44, the IPv6 Fragment
    /// header's own protocol number. The IPv6 key does not include the Next
    /// Header value (RFC 8200, Section 4.5 — "The Next Header values in the
    /// Fragment headers of different fragments of the same original packet
    /// may differ." — <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>).
    pub const IPV6_KEY_PROTOCOL: u8 = 44;

    /// Create a fragment context. [`unfragmentable_len`] starts at 0; set it
    /// with [`with_unfragmentable_len`](Self::with_unfragmentable_len).
    ///
    /// [`unfragmentable_len`]: IpFragmentContext::unfragmentable_len
    pub fn new(
        frag_key: ([u8; 16], [u8; 16], u8, u32),
        protocol: u8,
        offset_bytes: usize,
        more_fragments: bool,
        payload_len: usize,
    ) -> Self {
        Self {
            frag_key,
            protocol,
            offset_bytes,
            more_fragments,
            payload_len,
            unfragmentable_len: 0,
        }
    }

    /// Set [`IpFragmentContext::unfragmentable_len`].
    pub fn with_unfragmentable_len(mut self, unfragmentable_len: usize) -> Self {
        self.unfragmentable_len = unfragmentable_len;
        self
    }

    /// Whether this is the first fragment (Fragment Offset zero).
    pub fn is_first(&self) -> bool {
        self.offset_bytes == 0
    }
}

/// Decrypted payload produced by a protocol dissector (e.g. ESP).
///
/// When a dissector successfully decrypts an encrypted payload, it returns
/// this structure so the registry dispatch loop can continue dissection on
/// the decrypted plaintext rather than the original encrypted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPayload {
    /// Decrypted plaintext bytes (inner protocol data without padding).
    pub data: Vec<u8>,
    /// Dispatch hint derived from the decrypted "Next Header" field.
    pub next: DispatchHint,
}

/// An upper-layer payload embedded inside a layer, recorded with
/// [`DissectBuffer::push_embedded_payload`].
///
/// A dissector records one entry per upper-layer message it carries when
/// those messages are not contiguous with its header, or when there is more
/// than one of them. The registry dispatches each entry independently with
/// its own [`DispatchHint`], so every message gets its own upper-layer chain.
///
/// RFC 9260, Section 6.10 — several DATA chunks may be bundled into one SCTP
/// packet, each carrying its own user message —
/// <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedPayload {
    /// Absolute byte range of the payload in the original packet buffer.
    pub range: core::ops::Range<usize>,
    /// Hint for the registry to find the dissector for this payload.
    pub next: DispatchHint,
}

/// The result of a successful dissection.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectResult {
    /// Number of bytes consumed by this dissector (header size).
    pub bytes_consumed: usize,
    /// Hint for the registry to find the next dissector.
    pub next: DispatchHint,
    /// Optional TCP stream context for registry-driven reassembly.
    /// Set by the TCP dissector when dispatching to upper-layer protocols.
    pub tcp_stream_context: Option<TcpStreamContext>,
    /// Optional absolute byte range in the original packet buffer identifying
    /// an embedded payload for the next dissector.
    ///
    /// When set, the dispatch loop passes `&data[range]` to the next dissector
    /// instead of `&data[offset + bytes_consumed ..]`. This is needed for
    /// protocols like L2TP where the payload is bounded by a length field
    /// rather than extending to the end of the packet.
    ///
    /// A layer carrying more than one upper-layer message (e.g. bundled
    /// SCTP DATA chunks) records them with
    /// [`DissectBuffer::push_embedded_payload`] instead.
    pub embedded_payload: Option<core::ops::Range<usize>>,
    /// Optional decrypted payload from an encrypted protocol (e.g. ESP).
    ///
    /// When set, the dispatch loop uses the decrypted bytes instead of the
    /// original packet data for further dissection.
    pub decrypted_payload: Option<Box<DecryptedPayload>>,
    /// Optional length of this layer's payload, counted from the end of the
    /// consumed header (`bytes_consumed`), as declared by a length field in
    /// the header.
    ///
    /// When set, the dispatch loop ends the input of every subsequent
    /// dissector at `offset + bytes_consumed + payload_len`, or at the
    /// current end if that is smaller. Bytes past that point (e.g. Ethernet
    /// padding after a short IP datagram) are not passed to upper layers.
    /// A captured buffer shorter than the declared length (snaplen
    /// truncation) keeps its actual end.
    ///
    /// Set by dissectors whose header carries the length of the enclosed
    /// data, e.g. IPv4 Total Length (RFC 791, Section 3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>) and IPv6
    /// Payload Length (RFC 8200, Section 3 —
    /// <https://www.rfc-editor.org/rfc/rfc8200#section-3>).
    pub payload_len: Option<usize>,
    /// Optional IP fragment context for registry-driven fragment
    /// reassembly. Set by the IPv4 dissector and the IPv6 Fragment header
    /// dissector for fragments that are not whole datagrams.
    pub ip_fragment_context: Option<IpFragmentContext>,
}

impl DissectResult {
    /// Create a new `DissectResult` without TCP stream context.
    pub fn new(bytes_consumed: usize, next: DispatchHint) -> Self {
        Self {
            bytes_consumed,
            next,
            tcp_stream_context: None,
            embedded_payload: None,
            decrypted_payload: None,
            payload_len: None,
            ip_fragment_context: None,
        }
    }

    /// Create a new `DissectResult` with TCP stream context for reassembly.
    pub fn with_tcp_context(
        bytes_consumed: usize,
        next: DispatchHint,
        ctx: TcpStreamContext,
    ) -> Self {
        Self {
            bytes_consumed,
            next,
            tcp_stream_context: Some(ctx),
            embedded_payload: None,
            decrypted_payload: None,
            payload_len: None,
            ip_fragment_context: None,
        }
    }

    /// Create a new `DissectResult` with an embedded payload range.
    ///
    /// The `payload_range` specifies the absolute byte range within the
    /// original packet buffer where the upper-layer payload resides.
    pub fn with_embedded_payload(
        bytes_consumed: usize,
        next: DispatchHint,
        payload_range: core::ops::Range<usize>,
    ) -> Self {
        Self {
            bytes_consumed,
            next,
            tcp_stream_context: None,
            embedded_payload: Some(payload_range),
            decrypted_payload: None,
            payload_len: None,
            ip_fragment_context: None,
        }
    }

    /// Bound the payload that follows this layer's header to `payload_len`
    /// bytes. See [`DissectResult::payload_len`].
    pub fn with_payload_len(mut self, payload_len: usize) -> Self {
        self.payload_len = Some(payload_len);
        self
    }

    /// Attach an IP fragment context. See
    /// [`DissectResult::ip_fragment_context`].
    pub fn with_ip_fragment_context(mut self, ctx: IpFragmentContext) -> Self {
        self.ip_fragment_context = Some(ctx);
        self
    }

    /// Create a new `DissectResult` with a decrypted payload.
    ///
    /// Used by encrypted protocol dissectors (e.g. ESP) to pass decrypted
    /// plaintext to the registry dispatch loop for further dissection.
    pub fn with_decrypted_payload(bytes_consumed: usize, decrypted: DecryptedPayload) -> Self {
        Self {
            bytes_consumed,
            next: DispatchHint::End,
            tcp_stream_context: None,
            embedded_payload: None,
            decrypted_payload: Some(Box::new(decrypted)),
            payload_len: None,
            ip_fragment_context: None,
        }
    }
}

/// A specification a dissector is implemented against.
///
/// `id` is the document identifier as commonly cited (`"RFC 4271"`,
/// `"3GPP TS 29.281"`, `"IEEE 802.1Q"`), `title` its title, and `url` a
/// direct link to the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpecReference {
    /// Document identifier, e.g. `"RFC 4271"` or `"3GPP TS 29.281"`.
    pub id: &'static str,
    /// Document title, e.g. `"A Border Gateway Protocol 4 (BGP-4)"`.
    pub title: &'static str,
    /// Direct link to the document.
    pub url: &'static str,
}

impl SpecReference {
    /// Create a reference in a `const` context.
    pub const fn new(id: &'static str, title: &'static str, url: &'static str) -> Self {
        Self { id, title, url }
    }
}

/// Where a protocol sits in the dissection stack.
///
/// This describes the position of the layer a dissector produces relative
/// to its neighbours, not a strict OSI classification: tunnelling protocols
/// that carry another link or network layer (GTP-U, VXLAN, GRE, ...) are
/// [`Tunnel`](Self::Tunnel) regardless of the transport they run over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolLayer {
    /// Link layer (Ethernet, PPP, LLDP, STP, ...).
    Link,
    /// Network layer (IPv4, IPv6, ARP, ICMP, MPLS, IPv6 extension headers, ...).
    Network,
    /// Transport layer (TCP, UDP, SCTP, QUIC, ...).
    Transport,
    /// Encapsulation carrying another link or network layer (GTP-U, VXLAN, GRE, ...).
    Tunnel,
    /// Application layer (DNS, HTTP, BGP, Diameter, ...).
    Application,
}

impl ProtocolLayer {
    /// Lowercase machine-readable name (`"link"`, `"network"`, `"transport"`,
    /// `"tunnel"`, `"application"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Network => "network",
            Self::Transport => "transport",
            Self::Tunnel => "tunnel",
            Self::Application => "application",
        }
    }
}

impl core::fmt::Display for ProtocolLayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Trait that all protocol dissectors must implement.
///
/// The `Send` bound allows the registry to be moved to another thread (e.g.
/// one thread per capture file), while intentionally omitting `Sync` to
/// prevent sharing a single registry across threads via `Arc`.  Benchmarking
/// shows that concurrent access through a shared registry degrades throughput;
/// the recommended pattern is to give each thread its own registry instance.
pub trait Dissector: Send {
    /// Full protocol name (e.g., "Internet Protocol version 4").
    fn name(&self) -> &'static str;

    /// Short protocol name (e.g., "IPv4").
    ///
    /// This name is used as the layer identifier in parsed packets. It should
    /// be unique across all registered dissectors to avoid ambiguity when
    /// looking up layers via [`Packet::layer_by_name`](crate::packet::Packet::layer_by_name).
    fn short_name(&self) -> &'static str;

    /// Returns metadata describing all fields this dissector can produce.
    ///
    /// The returned descriptors cover every possible field, including
    /// conditional ones (marked with [`FieldDescriptor::optional`] = `true`).
    fn field_descriptors(&self) -> &'static [FieldDescriptor];

    /// Specifications this dissector is implemented against.
    ///
    /// Defaults to an empty slice; dissectors should list the RFCs, 3GPP
    /// technical specifications or other standards they decode.
    fn references(&self) -> &'static [SpecReference] {
        &[]
    }

    /// Position of this protocol in the dissection stack.
    ///
    /// Defaults to `None`; dissectors should override it.
    fn layer(&self) -> Option<ProtocolLayer> {
        None
    }

    /// Dissect the given bytes and append a protocol layer to the buffer.
    ///
    /// `offset` is the byte offset in the original packet where this layer starts.
    ///
    /// The `'pkt` lifetime ties the input data to the buffer, allowing
    /// [`FieldValue::Bytes`](crate::field::FieldValue::Bytes) and
    /// [`FieldValue::Str`](crate::field::FieldValue::Str) to borrow
    /// directly from `data` without copying (zero-copy).
    ///
    /// A dissector whose output depends on, or changes, state kept across
    /// packets (for example a stream table or a template cache) must call
    /// [`DissectBuffer::mark_cross_packet_state`] whenever it reads or
    /// updates that state.
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError>;

    /// Dissect one message of a TCP byte stream.
    ///
    /// The registry's TCP reassembly middleware calls this method, instead
    /// of [`dissect`](Self::dissect), for every upper-layer message it
    /// dissects from a TCP stream. `stream` identifies the direction of the
    /// connection the message belongs to ([`TcpStreamContext::stream_key`])
    /// and carries the control bits of the segment that completed the
    /// message; its sequence number and payload length describe that
    /// segment, not the message.
    ///
    /// Dissectors that keep per-connection state (for example which
    /// protocol a connection switched to) override this method and key the
    /// state by `stream.stream_key`. The default implementation ignores
    /// `stream` and calls [`dissect`](Self::dissect).
    fn dissect_tcp_stream<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        stream: &TcpStreamContext,
    ) -> Result<DissectResult, PacketError> {
        let _ = stream;
        self.dissect(data, buf, offset)
    }

    /// Release any state kept for one direction of a TCP connection.
    ///
    /// The registry calls this on the upper-layer dissector of a TCP
    /// connection when it drops its own reassembly state for the direction
    /// `stream_key`: before the data of a SYN segment (the 4-tuple starts a
    /// new connection, RFC 9293, Section 3.5 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.5>), after the data
    /// of a FIN segment that leaves no data missing before it (no more data
    /// from the sender, RFC 9293, Section 3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>),
    /// and for both directions after an RST segment (RFC 9293,
    /// Section 3.10.7.4 —
    /// <https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4>).
    ///
    /// The default implementation does nothing.
    fn release_tcp_stream(&self, stream_key: &TcpStreamKey) {
        let _ = stream_key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dissector that overrides nothing beyond the required methods, so it
    /// exercises the [`Dissector::references`] / [`Dissector::layer`] defaults.
    struct DefaultsDissector;

    impl Dissector for DefaultsDissector {
        fn name(&self) -> &'static str {
            "Defaults"
        }

        fn short_name(&self) -> &'static str {
            "defaults"
        }

        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }

        fn dissect<'pkt>(
            &self,
            _data: &'pkt [u8],
            _buf: &mut DissectBuffer<'pkt>,
            _offset: usize,
        ) -> Result<DissectResult, PacketError> {
            Ok(DissectResult::new(0, DispatchHint::End))
        }
    }

    #[test]
    fn protocol_layer_as_str_covers_every_variant() {
        assert_eq!(ProtocolLayer::Link.as_str(), "link");
        assert_eq!(ProtocolLayer::Network.as_str(), "network");
        assert_eq!(ProtocolLayer::Transport.as_str(), "transport");
        assert_eq!(ProtocolLayer::Tunnel.as_str(), "tunnel");
        assert_eq!(ProtocolLayer::Application.as_str(), "application");
    }

    #[test]
    fn protocol_layer_display_matches_as_str() {
        for layer in [
            ProtocolLayer::Link,
            ProtocolLayer::Network,
            ProtocolLayer::Transport,
            ProtocolLayer::Tunnel,
            ProtocolLayer::Application,
        ] {
            assert_eq!(layer.to_string(), layer.as_str());
        }
    }

    #[test]
    fn spec_reference_new_stores_all_parts() {
        const REFERENCE: SpecReference = SpecReference::new(
            "RFC 4271",
            "A Border Gateway Protocol 4 (BGP-4)",
            "https://www.rfc-editor.org/rfc/rfc4271",
        );

        assert_eq!(REFERENCE.id, "RFC 4271");
        assert_eq!(REFERENCE.title, "A Border Gateway Protocol 4 (BGP-4)");
        assert_eq!(REFERENCE.url, "https://www.rfc-editor.org/rfc/rfc4271");
        assert_eq!(
            REFERENCE,
            SpecReference {
                id: "RFC 4271",
                title: "A Border Gateway Protocol 4 (BGP-4)",
                url: "https://www.rfc-editor.org/rfc/rfc4271",
            }
        );
    }

    #[test]
    fn dissect_result_constructors_leave_payload_len_unset() {
        assert_eq!(DissectResult::new(20, DispatchHint::End).payload_len, None);
        assert_eq!(
            DissectResult::with_embedded_payload(12, DispatchHint::End, 28..32).payload_len,
            None
        );
    }

    #[test]
    fn dissect_result_with_payload_len_sets_bound() {
        let result = DissectResult::new(20, DispatchHint::ByIpProtocol(6)).with_payload_len(16);
        assert_eq!(result.bytes_consumed, 20);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));
        assert_eq!(result.payload_len, Some(16));
    }

    #[test]
    fn dissector_defaults_dissect_tcp_stream_as_dissect() {
        let dissector = DefaultsDissector;
        let ctx = TcpStreamContext::new(([0; 16], [1; 16], 1, 2), 0, 1, 0);
        let mut buf = DissectBuffer::new();

        let result = dissector.dissect_tcp_stream(&[0], &mut buf, 0, &ctx);
        assert_eq!(result, Ok(DissectResult::new(0, DispatchHint::End)));
        // The default release hook has nothing to release.
        dissector.release_tcp_stream(&ctx.stream_key);
    }

    #[test]
    fn dissect_result_constructors_leave_ip_fragment_context_unset() {
        assert_eq!(
            DissectResult::new(20, DispatchHint::End).ip_fragment_context,
            None
        );
        assert_eq!(
            DissectResult::with_tcp_context(
                20,
                DispatchHint::End,
                TcpStreamContext::new(([0; 16], [0; 16], 1, 2), 0, 0, 0),
            )
            .ip_fragment_context,
            None
        );
        assert_eq!(
            DissectResult::with_embedded_payload(12, DispatchHint::End, 28..32).ip_fragment_context,
            None
        );
        assert_eq!(
            DissectResult::with_decrypted_payload(
                8,
                DecryptedPayload {
                    data: vec![],
                    next: DispatchHint::End,
                },
            )
            .ip_fragment_context,
            None
        );
    }

    #[test]
    fn dissect_result_with_ip_fragment_context_sets_context() {
        let ctx = IpFragmentContext::new(([1; 16], [2; 16], 17, 0x2a), 17, 8, false, 8)
            .with_unfragmentable_len(20);
        let result =
            DissectResult::new(20, DispatchHint::End).with_ip_fragment_context(ctx.clone());
        assert_eq!(result.bytes_consumed, 20);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(result.ip_fragment_context, Some(ctx));
    }

    #[test]
    fn ip_fragment_context_new_stores_all_parts() {
        let ctx = IpFragmentContext::new(([1; 16], [2; 16], 44, 0xDEAD_BEEF), 6, 1448, true, 1448);
        assert_eq!(ctx.frag_key, ([1; 16], [2; 16], 44, 0xDEAD_BEEF));
        assert_eq!(ctx.protocol, 6);
        assert_eq!(ctx.offset_bytes, 1448);
        assert!(ctx.more_fragments);
        assert_eq!(ctx.payload_len, 1448);
        assert_eq!(ctx.unfragmentable_len, 0);
        assert!(!ctx.is_first());
        assert!(IpFragmentContext::new(([0; 16], [0; 16], 17, 1), 17, 0, true, 8).is_first());
    }

    #[test]
    fn dissector_defaults_report_no_references_and_no_layer() {
        let dissector = DefaultsDissector;

        assert!(dissector.references().is_empty());
        assert_eq!(dissector.layer(), None);
    }
}
