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
    /// Register by IPv6 Routing Header type (e.g., `4` for SRv6).
    Ipv6RoutingType(u8),
    /// Register by MIME content type (e.g., `"application/sdp"`).
    ContentType(&'static str),
    /// Register by IEEE 802.2 LLC DSAP value (e.g., `0x42` for STP).
    LlcSap(u8),
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

/// Context for TCP stream reassembly, provided by the TCP dissector
/// when dispatching to upper-layer protocol dissectors.
///
/// The registry uses this information to drive centralized TCP stream
/// reassembly, buffering segments until enough contiguous data is
/// available for the upper-layer dissector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpStreamContext {
    /// Directional stream key identifying the TCP flow (src_ip, dst_ip, src_port, dst_port).
    /// Each direction of a connection has its own key, so the reverse direction
    /// (dst→src) maintains a separate reassembly buffer and sequence space.
    /// IP addresses are encoded as 16 bytes (IPv4-mapped for IPv4).
    pub stream_key: ([u8; 16], [u8; 16], u16, u16),
    /// TCP sequence number of this segment's payload.
    pub seq: u32,
    /// Length of the TCP payload in this segment.
    pub payload_len: usize,
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
    /// protocols like SCTP where user data is embedded inside a chunk structure
    /// rather than following the header contiguously.
    ///
    /// RFC 9260, Section 3.3.1 — SCTP DATA chunk embeds user data after a
    /// 16-byte chunk header.
    pub embedded_payload: Option<core::ops::Range<usize>>,
    /// Optional decrypted payload from an encrypted protocol (e.g. ESP).
    ///
    /// When set, the dispatch loop uses the decrypted bytes instead of the
    /// original packet data for further dissection.
    pub decrypted_payload: Option<Box<DecryptedPayload>>,
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
        }
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
        }
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

    /// Dissect the given bytes and append a protocol layer to the buffer.
    ///
    /// `offset` is the byte offset in the original packet where this layer starts.
    ///
    /// The `'pkt` lifetime ties the input data to the buffer, allowing
    /// [`FieldValue::Bytes`](crate::field::FieldValue::Bytes) and
    /// [`FieldValue::Str`](crate::field::FieldValue::Str) to borrow
    /// directly from `data` without copying (zero-copy).
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError>;
}
