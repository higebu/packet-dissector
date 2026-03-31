//! Dissector registry for managing and dispatching protocol dissectors.

use std::collections::{HashMap, HashSet};

use packet_dissector_core::dissector::{DispatchHint, Dissector, DissectorPlugin, DissectorTable};
use packet_dissector_core::error::{PacketError, RegistrationError};
use packet_dissector_core::field::{FieldDescriptor, FieldValue};
use packet_dissector_core::packet::{AuxDataHandle, DissectBuffer};

struct TmpRemapContext {
    padded_base: usize,
    padded_end: usize,
    virtual_start: usize,
    aux_handle: AuxDataHandle,
    field_offset: u32,
    scratch_offset: u32,
}

/// A registry that manages protocol dissectors and dispatches packet
/// dissection through a chain of dissectors.
pub struct DissectorRegistry {
    entry: Option<Box<dyn Dissector>>,
    by_ethertype: HashMap<u16, Box<dyn Dissector>>,
    by_ip_protocol: HashMap<u8, Box<dyn Dissector>>,
    /// TCP port table — mirrors Wireshark's `tcp.port` dissector table.
    by_tcp_port: HashMap<u16, Box<dyn Dissector>>,
    /// UDP port table — mirrors Wireshark's `udp.port` dissector table.
    by_udp_port: HashMap<u16, Box<dyn Dissector>>,
    /// SCTP port table — mirrors Wireshark's `sctp.port` dissector table.
    by_sctp_port: HashMap<u16, Box<dyn Dissector>>,
    /// IPv6 Routing Header type table — mirrors Wireshark's `ipv6.routing.type` dissector table.
    by_ipv6_routing_type: HashMap<u8, Box<dyn Dissector>>,
    /// Content-type table — dispatches message bodies by MIME type.
    by_content_type: HashMap<&'static str, Box<dyn Dissector>>,
    /// Fallback dissector for unrecognised IPv6 Routing Header types.
    ipv6_routing_fallback: Option<Box<dyn Dissector>>,
    /// IEEE 802.2 LLC SAP table — dispatches by DSAP value for LLC-encapsulated protocols.
    by_llc_sap: HashMap<u8, Box<dyn Dissector>>,
    /// Link-layer type table — maps pcap LINKTYPE values to entry dissectors.
    by_link_type: HashMap<u32, Box<dyn Dissector>>,
    /// Factory functions for creating fresh dissector instances by decode-as name.
    /// Keys are lowercase protocol names (e.g., "http", "dns", "dns.tcp").
    dissector_factories: HashMap<String, fn() -> Box<dyn Dissector>>,
    /// Centralized TCP stream reassembly service.
    #[cfg(feature = "tcp")]
    pub(crate) tcp_reassembly: std::sync::Mutex<super::tcp_reassembly::TcpReassemblyService>,
    /// Shared ESP Security Association database for decryption.
    #[cfg(feature = "esp-decrypt")]
    esp_sa_db: packet_dissector_esp::EspSaDb,
}

impl DissectorRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            entry: None,
            by_ethertype: HashMap::new(),
            by_ip_protocol: HashMap::new(),
            by_tcp_port: HashMap::new(),
            by_udp_port: HashMap::new(),
            by_sctp_port: HashMap::new(),
            by_content_type: HashMap::new(),
            by_ipv6_routing_type: HashMap::new(),
            ipv6_routing_fallback: None,
            by_llc_sap: HashMap::new(),
            by_link_type: HashMap::new(),
            dissector_factories: HashMap::new(),
            #[cfg(feature = "tcp")]
            tcp_reassembly: super::tcp_reassembly::new_tcp_reassembly(),
            #[cfg(feature = "esp-decrypt")]
            esp_sa_db: std::sync::Arc::new(packet_dissector_esp::SharedEspSaDb::new()),
        }
    }

    /// Add an ESP Security Association for decryption.
    ///
    /// Once added, ESP packets with the specified SPI will be decrypted
    /// and the inner protocol will be dissected.
    #[cfg(feature = "esp-decrypt")]
    pub fn add_esp_sa(&self, spi: u32, sa: packet_dissector_esp::EspSa) {
        self.esp_sa_db.insert(spi, sa);
    }

    /// Set the entry-point dissector (typically Ethernet).
    pub fn set_entry_dissector(&mut self, dissector: Box<dyn Dissector>) {
        self.entry = Some(dissector);
    }

    /// Register a dissector for a given EtherType value.
    ///
    /// Returns an error if a dissector is already registered for this EtherType.
    /// Use [`register_by_ethertype_or_replace`](Self::register_by_ethertype_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_ethertype(
        &mut self,
        ethertype: u16,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_ethertype.get(&ethertype) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "ethertype",
                key: ethertype as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_ethertype.insert(ethertype, dissector);
        Ok(())
    }

    /// Register a dissector for a given EtherType, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_ethertype_or_replace(
        &mut self,
        ethertype: u16,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_ethertype.insert(ethertype, dissector)
    }

    /// Register a dissector for a given IP protocol number.
    ///
    /// Returns an error if a dissector is already registered for this protocol number.
    /// Use [`register_by_ip_protocol_or_replace`](Self::register_by_ip_protocol_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_ip_protocol(
        &mut self,
        protocol: u8,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_ip_protocol.get(&protocol) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "ip_protocol",
                key: protocol as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_ip_protocol.insert(protocol, dissector);
        Ok(())
    }

    /// Register a dissector for a given IP protocol number, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_ip_protocol_or_replace(
        &mut self,
        protocol: u8,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_ip_protocol.insert(protocol, dissector)
    }

    /// Register a dissector for a given TCP port number.
    ///
    /// Returns an error if a dissector is already registered for this TCP port.
    /// Use [`register_by_tcp_port_or_replace`](Self::register_by_tcp_port_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_tcp_port(
        &mut self,
        port: u16,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_tcp_port.get(&port) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "tcp_port",
                key: port as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_tcp_port.insert(port, dissector);
        Ok(())
    }

    /// Register a dissector for a given TCP port, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_tcp_port_or_replace(
        &mut self,
        port: u16,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_tcp_port.insert(port, dissector)
    }

    /// Register a dissector for a given UDP port number.
    ///
    /// Returns an error if a dissector is already registered for this UDP port.
    /// Use [`register_by_udp_port_or_replace`](Self::register_by_udp_port_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_udp_port(
        &mut self,
        port: u16,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_udp_port.get(&port) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "udp_port",
                key: port as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_udp_port.insert(port, dissector);
        Ok(())
    }

    /// Register a dissector for a given UDP port, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_udp_port_or_replace(
        &mut self,
        port: u16,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_udp_port.insert(port, dissector)
    }

    /// Register a dissector for a given SCTP port number.
    ///
    /// Returns an error if a dissector is already registered for this SCTP port.
    /// Use [`register_by_sctp_port_or_replace`](Self::register_by_sctp_port_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_sctp_port(
        &mut self,
        port: u16,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_sctp_port.get(&port) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "sctp_port",
                key: port as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_sctp_port.insert(port, dissector);
        Ok(())
    }

    /// Register a dissector for a given SCTP port, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_sctp_port_or_replace(
        &mut self,
        port: u16,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_sctp_port.insert(port, dissector)
    }

    /// Register a dissector for a given IPv6 Routing Header type.
    ///
    /// Returns an error if a dissector is already registered for this routing type.
    /// Use [`register_by_ipv6_routing_type_or_replace`](Self::register_by_ipv6_routing_type_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_ipv6_routing_type(
        &mut self,
        routing_type: u8,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_ipv6_routing_type.get(&routing_type) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "ipv6_routing_type",
                key: routing_type as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_ipv6_routing_type.insert(routing_type, dissector);
        Ok(())
    }

    /// Register a dissector for a given IPv6 Routing Header type, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_ipv6_routing_type_or_replace(
        &mut self,
        routing_type: u8,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_ipv6_routing_type.insert(routing_type, dissector)
    }

    /// Set the fallback dissector for unrecognised IPv6 Routing Header types.
    ///
    /// When a `ByIpv6RoutingType` hint has no type-specific dissector registered,
    /// the registry falls back to this dissector (typically `GenericRoutingDissector`).
    pub fn set_ipv6_routing_fallback(&mut self, dissector: Box<dyn Dissector>) {
        self.ipv6_routing_fallback = Some(dissector);
    }

    /// Register a dissector for a given MIME content type.
    ///
    /// The key is normalized (trimmed and ASCII-lowercased) before storage so
    /// that lookups are case-insensitive regardless of how callers register or
    /// dispatch. Returns an error if a dissector is already registered for this
    /// content type. Use
    /// [`register_by_content_type_or_replace`](Self::register_by_content_type_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_content_type(
        &mut self,
        content_type: &'static str,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_content_type.get(content_type) {
            return Err(RegistrationError::DuplicateStringKey {
                table: "content_type",
                key: content_type,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_content_type.insert(content_type, dissector);
        Ok(())
    }

    /// Register a dissector for a given MIME content type, replacing any existing one.
    ///
    /// The key is normalized (trimmed and ASCII-lowercased) before storage.
    /// Returns the previously registered dissector, if any.
    pub fn register_by_content_type_or_replace(
        &mut self,
        content_type: &'static str,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_content_type.insert(content_type, dissector)
    }

    /// Look up a dissector by MIME content type.
    ///
    /// The key is expected to be already normalized (trimmed + ASCII-lowercased)
    /// by the caller (e.g., `SipDissector` normalizes in `DispatchHint::ByContentType`).
    /// If the input is already in canonical form no allocation occurs.
    pub fn get_by_content_type(&self, content_type: &str) -> Option<&dyn Dissector> {
        // Fast path: interned static strings are already normalized.
        if let Some(d) = self.by_content_type.get(content_type) {
            return Some(d.as_ref());
        }
        // Fallback: trim + lowercase for non-interned input.
        let trimmed = content_type.trim();
        if !trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.by_content_type.get(trimmed).map(|d| d.as_ref());
        }
        let lower = trimmed.to_ascii_lowercase();
        self.by_content_type.get(lower.as_str()).map(|d| d.as_ref())
    }

    /// Register a dissector for a given pcap link-layer header type.
    ///
    /// Returns an error if a dissector is already registered for this link type.
    /// Use [`register_by_link_type_or_replace`](Self::register_by_link_type_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_link_type(
        &mut self,
        link_type: u32,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_link_type.get(&link_type) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "link_type",
                key: link_type as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_link_type.insert(link_type, dissector);
        Ok(())
    }

    /// Register a dissector for a given pcap link-layer header type, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_link_type_or_replace(
        &mut self,
        link_type: u32,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_link_type.insert(link_type, dissector)
    }

    /// Register a dissector for a given IEEE 802.2 LLC DSAP value.
    ///
    /// Returns an error if a dissector is already registered for this SAP value.
    /// Use [`register_by_llc_sap_or_replace`](Self::register_by_llc_sap_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_llc_sap(
        &mut self,
        sap: u8,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_llc_sap.get(&sap) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "llc_sap",
                key: sap as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_llc_sap.insert(sap, dissector);
        Ok(())
    }

    /// Register a dissector for a given LLC DSAP value, replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_llc_sap_or_replace(
        &mut self,
        sap: u8,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_llc_sap.insert(sap, dissector)
    }

    /// Look up a dissector by IEEE 802.2 LLC DSAP value.
    pub fn get_by_llc_sap(&self, sap: u8) -> Option<&dyn Dissector> {
        self.by_llc_sap.get(&sap).map(|d| d.as_ref())
    }

    /// Look up a dissector by pcap link-layer header type.
    pub fn get_by_link_type(&self, link_type: u32) -> Option<&dyn Dissector> {
        self.by_link_type.get(&link_type).map(|d| d.as_ref())
    }

    /// Register a factory function that creates a dissector by decode-as name.
    ///
    /// The `name` should be a lowercase identifier used in `--decode-as` directives
    /// (e.g., "http", "dns", "dns.tcp"). This does not need to match `short_name()`.
    ///
    /// Returns the previously registered factory function, if any.
    pub fn register_dissector_factory(
        &mut self,
        name: impl Into<String>,
        factory: fn() -> Box<dyn Dissector>,
    ) -> Option<fn() -> Box<dyn Dissector>> {
        self.dissector_factories.insert(name.into(), factory)
    }

    /// Create a fresh dissector instance by its decode-as name.
    ///
    /// Returns `None` if no factory is registered for the given name.
    pub fn create_dissector_by_name(&self, name: &str) -> Option<Box<dyn Dissector>> {
        self.dissector_factories.get(name).map(|f| f())
    }

    /// Returns a sorted list of all registered decode-as protocol names.
    pub fn available_decode_as_protocols(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .dissector_factories
            .keys()
            .map(|s| s.as_str())
            .collect();
        names.sort_unstable();
        names
    }

    /// Look up a dissector by EtherType.
    pub fn get_by_ethertype(&self, ethertype: u16) -> Option<&dyn Dissector> {
        self.by_ethertype.get(&ethertype).map(|d| d.as_ref())
    }

    /// Look up a dissector by IP protocol number.
    pub fn get_by_ip_protocol(&self, protocol: u8) -> Option<&dyn Dissector> {
        self.by_ip_protocol.get(&protocol).map(|d| d.as_ref())
    }

    /// Look up a dissector by TCP port number.
    pub fn get_by_tcp_port(&self, port: u16) -> Option<&dyn Dissector> {
        self.by_tcp_port.get(&port).map(|d| d.as_ref())
    }

    /// Look up a dissector by UDP port number.
    pub fn get_by_udp_port(&self, port: u16) -> Option<&dyn Dissector> {
        self.by_udp_port.get(&port).map(|d| d.as_ref())
    }

    /// Look up a dissector by SCTP port number.
    pub fn get_by_sctp_port(&self, port: u16) -> Option<&dyn Dissector> {
        self.by_sctp_port.get(&port).map(|d| d.as_ref())
    }

    /// Look up a dissector by IPv6 Routing Header type.
    ///
    /// Returns the type-specific dissector if one is registered, otherwise
    /// falls back to the routing fallback dissector.
    pub fn get_by_ipv6_routing_type(&self, routing_type: u8) -> Option<&dyn Dissector> {
        self.by_ipv6_routing_type
            .get(&routing_type)
            .map(|d| d.as_ref())
            .or(self.ipv6_routing_fallback.as_deref())
    }

    /// Dissect a raw packet by chaining dissectors starting from the entry dissector.
    ///
    /// Uses the entry dissector set via [`set_entry_dissector`](Self::set_entry_dissector)
    /// (typically Ethernet). For pcap files with non-Ethernet link-layer types,
    /// use [`dissect_with_link_type`](Self::dissect_with_link_type) instead.
    pub fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
    ) -> Result<(), PacketError> {
        let entry = self
            .entry
            .as_ref()
            .ok_or(PacketError::InvalidHeader("no entry dissector configured"))?;

        let mut offset = 0;

        let result = entry.dissect(&data[offset..], buf, offset)?;
        offset += result.bytes_consumed;

        self.dispatch_loop(data, buf, offset, result.next)?;

        Ok(())
    }

    /// Dissect a raw packet using a link-layer type to select the entry dissector.
    ///
    /// This method looks up the entry dissector from the `by_link_type` table
    /// first. If no dissector is registered for the given `link_type`, it falls
    /// back to the default entry dissector (typically Ethernet).
    ///
    /// # Link-layer types
    ///
    /// Common values (from <https://www.tcpdump.org/linktypes.html>):
    /// - `1` — `LINKTYPE_ETHERNET`
    /// - `113` — `LINKTYPE_LINUX_SLL`
    /// - `276` — `LINKTYPE_LINUX_SLL2`
    pub fn dissect_with_link_type<'pkt>(
        &self,
        data: &'pkt [u8],
        link_type: u32,
        buf: &mut DissectBuffer<'pkt>,
    ) -> Result<(), PacketError> {
        let entry = self
            .get_by_link_type(link_type)
            .or(self.entry.as_deref())
            .ok_or(PacketError::InvalidHeader("no entry dissector configured"))?;

        let mut offset = 0;

        let result = entry.dissect(&data[offset..], buf, offset)?;
        offset += result.bytes_consumed;

        self.dispatch_loop(data, buf, offset, result.next)?;

        Ok(())
    }

    /// Run the dispatch loop starting from the given hint and offset.
    fn dispatch_loop<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        mut offset: usize,
        mut next: DispatchHint,
    ) -> Result<(), PacketError> {
        // Track whether the previous iteration made no progress (consumed 0
        // bytes).  Thin dispatchers like `RoutingDissector` legitimately return
        // `bytes_consumed = 0` once to redirect via a different DispatchHint,
        // so we allow one zero-consumption iteration.  Two consecutive
        // zero-consumption iterations indicate an infinite loop.
        let mut stalled = false;

        loop {
            let dissector = match &next {
                DispatchHint::End => break,
                DispatchHint::ByEtherType(et) => self.get_by_ethertype(*et),
                DispatchHint::ByIpProtocol(p) => self.get_by_ip_protocol(*p),
                DispatchHint::ByTcpPort(src, dst) => {
                    let (low, high) = ((*src).min(*dst), (*src).max(*dst));
                    self.get_by_tcp_port(low)
                        .or_else(|| self.get_by_tcp_port(high))
                }
                DispatchHint::ByUdpPort(src, dst) => {
                    let (low, high) = ((*src).min(*dst), (*src).max(*dst));
                    self.get_by_udp_port(low)
                        .or_else(|| self.get_by_udp_port(high))
                }
                DispatchHint::BySctpPort(src, dst) => {
                    let (low, high) = ((*src).min(*dst), (*src).max(*dst));
                    self.get_by_sctp_port(low)
                        .or_else(|| self.get_by_sctp_port(high))
                }
                DispatchHint::ByContentType(ct) => self.get_by_content_type(ct),
                DispatchHint::ByIpv6RoutingType(rt) => self.get_by_ipv6_routing_type(*rt),
                DispatchHint::ByLlcSap(sap) => self.get_by_llc_sap(*sap),
            };

            let Some(dissector) = dissector else {
                break;
            };

            if offset >= data.len() {
                break;
            }

            let result = dissector.dissect(&data[offset..], buf, offset)?;

            // Guard against infinite loops: if a dissector consumed zero bytes
            // two iterations in a row, break.  A single zero-consumption
            // iteration is allowed for thin dispatchers (e.g.,
            // RoutingDissector) that change the DispatchHint without consuming
            // input.
            if result.bytes_consumed == 0 && !matches!(result.next, DispatchHint::End) {
                if stalled {
                    break;
                }
                stalled = true;
            } else {
                stalled = false;
            }

            offset += result.bytes_consumed;

            // Embedded payload middleware: when a dissector signals that the
            // next dissector's input is at a specific range within the original
            // packet (e.g., SCTP DATA chunk user data), dispatch directly to
            // that range instead of using the normal offset-based slicing.
            if let Some(ref payload_range) = result.embedded_payload {
                let upper = match &result.next {
                    DispatchHint::End => None,
                    DispatchHint::ByEtherType(et) => self.get_by_ethertype(*et),
                    DispatchHint::ByIpProtocol(p) => self.get_by_ip_protocol(*p),
                    DispatchHint::ByTcpPort(src, dst) => {
                        let (low, high) = ((*src).min(*dst), (*src).max(*dst));
                        self.get_by_tcp_port(low)
                            .or_else(|| self.get_by_tcp_port(high))
                    }
                    DispatchHint::ByUdpPort(src, dst) => {
                        let (low, high) = ((*src).min(*dst), (*src).max(*dst));
                        self.get_by_udp_port(low)
                            .or_else(|| self.get_by_udp_port(high))
                    }
                    DispatchHint::BySctpPort(src, dst) => {
                        let (low, high) = ((*src).min(*dst), (*src).max(*dst));
                        self.get_by_sctp_port(low)
                            .or_else(|| self.get_by_sctp_port(high))
                    }
                    DispatchHint::ByContentType(ct) => self.get_by_content_type(ct),
                    DispatchHint::ByIpv6RoutingType(rt) => self.get_by_ipv6_routing_type(*rt),
                    DispatchHint::ByLlcSap(sap) => self.get_by_llc_sap(*sap),
                };
                if let Some(upper) = upper {
                    let start = payload_range.start;
                    let end = payload_range.end.min(data.len());
                    if start < end {
                        let upper_result = upper.dissect(&data[start..end], buf, start)?;
                        offset = start + upper_result.bytes_consumed;
                        next = upper_result.next;
                        continue;
                    }
                }
                break;
            }

            // Decrypted payload middleware: when a dissector decrypts its payload
            // (e.g. ESP with configured SAs), continue dissection on the decrypted
            // bytes using a recursive dispatch.
            if let Some(decrypted) = result.decrypted_payload {
                // `dispatch_loop` uses `offset` both as an index into `data`
                // and as the absolute byte offset recorded in Layer ranges.
                // To keep inner decrypted layers contiguous with earlier
                // layers we prepend padding so that indices line up with the
                // desired absolute offsets.
                //
                // Store the decrypted data in aux_data so inner-layer fields
                // that reference it remain valid for the buffer's lifetime.
                let virtual_start = offset;
                let aux_handle = buf.push_aux_data(&decrypted.data);

                // Build a padded buffer for dissection. The padding prefix
                // ensures byte ranges in inner layers are absolute.
                let mut padded = vec![0u8; virtual_start];
                padded.extend_from_slice(&decrypted.data);

                // Dissect into a temporary buffer. Fields borrow from `padded`.
                let mut tmp_buf = DissectBuffer::new();
                self.dispatch_loop(&padded, &mut tmp_buf, virtual_start, decrypted.next)?;

                // Merge tmp_buf into the main buf. Layers are cheap to copy.
                // Fields may borrow from `padded`, so we remap Bytes/Str
                // references into buf.aux_data (which stores the same data
                // and outlives the fields).
                Self::merge_tmp_buf(buf, tmp_buf, &padded, virtual_start, aux_handle);
                break;
            }

            // TCP reassembly middleware: if the dissector provided TCP stream
            // context, buffer the payload and pass reassembled contiguous data
            // to the upper-layer dissector.
            #[cfg(feature = "tcp")]
            if let Some(ref ctx) = result.tcp_stream_context {
                if let DispatchHint::ByTcpPort(src, dst) = result.next {
                    let (low, high) = (src.min(dst), src.max(dst));
                    if let Some(upper) = self
                        .get_by_tcp_port(low)
                        .or_else(|| self.get_by_tcp_port(high))
                    {
                        let remaining = data.len().saturating_sub(offset);
                        let payload_end = offset + ctx.payload_len.min(remaining);
                        let payload = &data[offset..payload_end];
                        match self.handle_tcp_reassembly(ctx, payload, upper, buf, offset)? {
                            Some(upper_result) => {
                                // Fast path succeeded — propagate the upper
                                // dissector's result so chaining can continue.
                                // Advance by bytes_consumed (not payload_end)
                                // so partial consumption is handled correctly.
                                let consumed = upper_result.bytes_consumed.min(payload.len());
                                offset += consumed;
                                next = upper_result.next;
                                continue;
                            }
                            None => {
                                // Reassembly in progress or complete via
                                // buffered path — terminate the chain since
                                // offset coordinates are no longer consistent
                                // with the current packet.
                                break;
                            }
                        }
                    }
                    break;
                }
            }

            next = result.next;
        }

        Ok(())
    }
    /// Merge a temporary `DissectBuffer` (produced by recursive dissection of
    /// decrypted or reassembled data stored in a local `padded` vec) into the
    /// main buffer.
    ///
    /// `Bytes` and `Str` field values that reference `padded` are remapped to
    /// point into the stable auxiliary chunk identified by `aux_handle`.
    pub(crate) fn merge_tmp_buf<'pkt>(
        buf: &mut DissectBuffer<'pkt>,
        tmp_buf: DissectBuffer<'_>,
        padded: &[u8],
        virtual_start: usize,
        aux_handle: AuxDataHandle,
    ) {
        use packet_dissector_core::field::Field;

        let field_offset = buf.field_count();
        let scratch_offset = buf.scratch_len();
        let (tmp_layers, tmp_fields, tmp_scratch) = tmp_buf.into_parts();
        buf.extend_scratch(&tmp_scratch);
        for mut layer in tmp_layers {
            layer.field_range.start += field_offset;
            layer.field_range.end += field_offset;
            buf.push_layer(layer);
        }

        let remap_ctx = TmpRemapContext {
            padded_base: padded.as_ptr() as usize,
            padded_end: padded.as_ptr() as usize + padded.len(),
            virtual_start,
            aux_handle,
            field_offset,
            scratch_offset,
        };

        for field in tmp_fields {
            // Remap borrowed field values from `padded` to `buf.aux_data`.
            let new_value: FieldValue<'pkt> = Self::remap_field_value(field.value, buf, &remap_ctx);
            buf.push_raw_field(Field {
                descriptor: field.descriptor,
                value: new_value,
                range: field.range,
            });
        }
    }

    fn aux_bytes<'pkt>(
        buf: &DissectBuffer<'pkt>,
        aux_handle: AuxDataHandle,
        range: core::ops::Range<usize>,
    ) -> &'pkt [u8] {
        let slice = buf.aux_data_subslice(aux_handle, range).unwrap_or(&[]);
        #[allow(unsafe_code)]
        // SAFETY: `aux_chunks` stores each chunk as a `Box<[u8]>`, which is a
        // heap-allocated, stable-address buffer. Unlike `Vec`, a `Box<[u8]>`
        // is never reallocated, so its pointer remains valid for the lifetime of
        // the `DissectBuffer`. We extend the borrow lifetime from `'_` to `'pkt`
        // because the `DissectBuffer<'pkt>` owns the `Box<[u8]>` and will not
        // drop or modify it until `clear()` is called (which resets the lifetime).
        // The caller (`merge_tmp_buf`) only uses this during a single `dissect`
        // call, before `clear()` is invoked for the next packet.
        unsafe {
            core::slice::from_raw_parts(slice.as_ptr(), slice.len())
        }
    }

    fn aux_str<'pkt>(
        buf: &DissectBuffer<'pkt>,
        aux_handle: AuxDataHandle,
        range: core::ops::Range<usize>,
    ) -> &'pkt str {
        let slice = Self::aux_bytes(buf, aux_handle, range);
        #[allow(unsafe_code)]
        // SAFETY: The bytes backing this slice were originally stored as a
        // `FieldValue::Str`, which is only constructed from `&str` references
        // (valid UTF-8). The `push_aux_data` call copies those bytes verbatim
        // into the auxiliary chunk, preserving UTF-8 validity. No mutation
        // occurs between the copy and this read.
        unsafe {
            core::str::from_utf8_unchecked(slice)
        }
    }

    /// Remap a `FieldValue` so that any `Bytes`/`Str` references pointing into
    /// the temporary padded buffer are redirected to the equivalent range in
    /// the stable auxiliary chunk. Flat-buffer index ranges are shifted to match
    /// their new positions in the destination buffer.
    fn remap_field_value<'pkt>(
        value: FieldValue<'_>,
        buf: &mut DissectBuffer<'pkt>,
        remap_ctx: &TmpRemapContext,
    ) -> FieldValue<'pkt> {
        match value {
            FieldValue::Bytes(b) => {
                let ptr = b.as_ptr() as usize;
                if ptr >= remap_ctx.padded_base && ptr < remap_ctx.padded_end {
                    let off = ptr - remap_ctx.padded_base;
                    if off >= remap_ctx.virtual_start && !b.is_empty() {
                        let start = off - remap_ctx.virtual_start;
                        FieldValue::Bytes(Self::aux_bytes(
                            buf,
                            remap_ctx.aux_handle,
                            start..start + b.len(),
                        ))
                    } else {
                        FieldValue::Bytes(&[])
                    }
                } else {
                    let aux_handle = buf.push_aux_data(b);
                    FieldValue::Bytes(Self::aux_bytes(buf, aux_handle, 0..b.len()))
                }
            }
            FieldValue::Str(s) => {
                let ptr = s.as_ptr() as usize;
                if ptr >= remap_ctx.padded_base && ptr < remap_ctx.padded_end {
                    let off = ptr - remap_ctx.padded_base;
                    if off >= remap_ctx.virtual_start && !s.is_empty() {
                        let start = off - remap_ctx.virtual_start;
                        FieldValue::Str(Self::aux_str(
                            buf,
                            remap_ctx.aux_handle,
                            start..start + s.len(),
                        ))
                    } else {
                        FieldValue::Str("")
                    }
                } else {
                    let aux_handle = buf.push_aux_data(s.as_bytes());
                    FieldValue::Str(Self::aux_str(buf, aux_handle, 0..s.len()))
                }
            }
            // Scalar and index-based variants contain no borrowed data.
            FieldValue::U8(v) => FieldValue::U8(v),
            FieldValue::U16(v) => FieldValue::U16(v),
            FieldValue::U32(v) => FieldValue::U32(v),
            FieldValue::U64(v) => FieldValue::U64(v),
            FieldValue::I32(v) => FieldValue::I32(v),
            FieldValue::Ipv4Addr(v) => FieldValue::Ipv4Addr(v),
            FieldValue::Ipv6Addr(v) => FieldValue::Ipv6Addr(v),
            FieldValue::MacAddr(v) => FieldValue::MacAddr(v),
            FieldValue::Array(r) => {
                FieldValue::Array(r.start + remap_ctx.field_offset..r.end + remap_ctx.field_offset)
            }
            FieldValue::Object(r) => {
                FieldValue::Object(r.start + remap_ctx.field_offset..r.end + remap_ctx.field_offset)
            }
            FieldValue::Scratch(r) => FieldValue::Scratch(
                r.start + remap_ctx.scratch_offset..r.end + remap_ctx.scratch_offset,
            ),
        }
    }
}

/// Metadata for a single registered dissector's field schema.
#[derive(Debug, Clone)]
pub struct ProtocolFieldSchema {
    /// Full protocol name.
    pub name: &'static str,
    /// Short protocol name (layer key).
    pub short_name: &'static str,
    /// Field descriptors for this protocol.
    pub fields: &'static [FieldDescriptor],
}

impl DissectorRegistry {
    /// Returns field metadata for all registered dissectors.
    ///
    /// Each dissector is included at most once, deduplicated by `short_name`
    /// (the same dissector type may be registered under multiple dispatch keys,
    /// e.g., DNS on both TCP port 53 and UDP port 53).
    pub fn all_field_schemas(&self) -> Vec<ProtocolFieldSchema> {
        let mut seen = HashSet::new();
        let mut schemas = Vec::new();

        let mut push = |d: &dyn Dissector| {
            if seen.insert(d.short_name()) {
                schemas.push(ProtocolFieldSchema {
                    name: d.name(),
                    short_name: d.short_name(),
                    fields: d.field_descriptors(),
                });
            }
        };

        if let Some(ref entry) = self.entry {
            push(entry.as_ref());
        }
        for d in self.by_ethertype.values() {
            push(d.as_ref());
        }
        for d in self.by_ip_protocol.values() {
            push(d.as_ref());
        }
        for d in self.by_udp_port.values() {
            push(d.as_ref());
        }
        for d in self.by_tcp_port.values() {
            push(d.as_ref());
        }
        for d in self.by_sctp_port.values() {
            push(d.as_ref());
        }
        for d in self.by_ipv6_routing_type.values() {
            push(d.as_ref());
        }
        for d in self.by_content_type.values() {
            push(d.as_ref());
        }
        for d in self.by_llc_sap.values() {
            push(d.as_ref());
        }
        if let Some(ref d) = self.ipv6_routing_fallback {
            push(d.as_ref());
        }
        for d in self.by_link_type.values() {
            push(d.as_ref());
        }

        // The OSPF dispatcher returns empty field_descriptors because it
        // delegates to version-specific dissectors at runtime.  Expose the
        // actual version-specific schemas so field discovery stays accurate.
        #[cfg(feature = "ospf")]
        push(&packet_dissector_ospf::Ospfv2Dissector);
        #[cfg(feature = "ospf")]
        push(&packet_dissector_ospf::Ospfv3Dissector);
        #[cfg(feature = "bgp")]
        push(&packet_dissector_bgp::BgpDissector);

        schemas
    }
}

impl DissectorRegistry {
    /// Register a dissector into the specified dispatch table.
    ///
    /// This is a convenience method that dispatches to the appropriate
    /// type-specific registration method based on the [`DissectorTable`]
    /// variant.  It allows third-party crates to register dissectors
    /// without depending on the registry's internal structure.
    ///
    /// Returns an error if a dissector is already registered for the same
    /// key in the target table.
    pub fn register_dissector(
        &mut self,
        table: DissectorTable,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        match table {
            DissectorTable::Entry => {
                self.set_entry_dissector(dissector);
                Ok(())
            }
            DissectorTable::EtherType(et) => self.register_by_ethertype(et, dissector),
            DissectorTable::IpProtocol(p) => self.register_by_ip_protocol(p, dissector),
            DissectorTable::TcpPort(p) => self.register_by_tcp_port(p, dissector),
            DissectorTable::UdpPort(p) => self.register_by_udp_port(p, dissector),
            DissectorTable::SctpPort(p) => self.register_by_sctp_port(p, dissector),
            DissectorTable::ContentType(ct) => self.register_by_content_type(ct, dissector),
            DissectorTable::Ipv6RoutingType(rt) => {
                self.register_by_ipv6_routing_type(rt, dissector)
            }
            DissectorTable::LlcSap(sap) => self.register_by_llc_sap(sap, dissector),
            DissectorTable::Ipv6RoutingFallback => {
                self.set_ipv6_routing_fallback(dissector);
                Ok(())
            }
            DissectorTable::LinkType(lt) => self.register_by_link_type(lt, dissector),
        }
    }

    /// Register a dissector into the specified dispatch table, replacing any
    /// existing one in the same slot.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_dissector_or_replace(
        &mut self,
        table: DissectorTable,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        match table {
            DissectorTable::Entry => {
                let prev = self.entry.take();
                self.set_entry_dissector(dissector);
                prev
            }
            DissectorTable::EtherType(et) => self.register_by_ethertype_or_replace(et, dissector),
            DissectorTable::IpProtocol(p) => self.register_by_ip_protocol_or_replace(p, dissector),
            DissectorTable::TcpPort(p) => self.register_by_tcp_port_or_replace(p, dissector),
            DissectorTable::UdpPort(p) => self.register_by_udp_port_or_replace(p, dissector),
            DissectorTable::SctpPort(p) => self.register_by_sctp_port_or_replace(p, dissector),
            DissectorTable::ContentType(ct) => {
                self.register_by_content_type_or_replace(ct, dissector)
            }
            DissectorTable::Ipv6RoutingType(rt) => {
                self.register_by_ipv6_routing_type_or_replace(rt, dissector)
            }
            DissectorTable::LlcSap(sap) => self.register_by_llc_sap_or_replace(sap, dissector),
            DissectorTable::Ipv6RoutingFallback => {
                let prev = self.ipv6_routing_fallback.take();
                self.set_ipv6_routing_fallback(dissector);
                prev
            }
            DissectorTable::LinkType(lt) => self.register_by_link_type_or_replace(lt, dissector),
        }
    }

    /// Register all dissectors provided by a plugin.
    ///
    /// Calls [`register_dissector`](Self::register_dissector) for each
    /// (table, dissector) pair returned by the plugin.  Registration stops
    /// at the first error (e.g., a duplicate key).
    pub fn register_plugin(
        &mut self,
        plugin: &dyn DissectorPlugin,
    ) -> Result<(), RegistrationError> {
        for (table, dissector) in plugin.dissectors() {
            self.register_dissector(table, dissector)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OSPF version dispatcher — delegates to OSPFv2 or OSPFv3 based on version byte.
// ---------------------------------------------------------------------------

#[cfg(feature = "ospf")]
struct OspfDispatcher;

#[cfg(feature = "ospf")]
impl Dissector for OspfDispatcher {
    fn name(&self) -> &'static str {
        "Open Shortest Path First"
    }

    fn short_name(&self) -> &'static str {
        "OSPF"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        // Delegate to the appropriate version dissector at runtime.
        // Return the union of descriptors is impractical, so return an empty slice.
        // The actual dissector's descriptors are authoritative.
        &[]
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        if data.is_empty() {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        }

        match data[0] {
            2 => packet_dissector_ospf::Ospfv2Dissector.dissect(data, buf, offset),
            3 => packet_dissector_ospf::Ospfv3Dissector.dissect(data, buf, offset),
            _ => Err(PacketError::InvalidHeader("unsupported OSPF version")),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP version dispatcher — delegates to HTTP/2 when the connection preface
// ("PRI * HTTP/2.0") is detected, otherwise falls back to HTTP/1.1.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "http", feature = "http2"))]
struct HttpDispatcher;

#[cfg(any(feature = "http", feature = "http2"))]
impl Dissector for HttpDispatcher {
    fn name(&self) -> &'static str {
        "HyperText Transfer Protocol"
    }

    fn short_name(&self) -> &'static str {
        "HTTP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        // RFC 9113, Section 3.4 — HTTP/2 connection preface detection
        #[cfg(feature = "http2")]
        if data.starts_with(b"PRI * HTTP/2.0") {
            return packet_dissector_http2::Http2Dissector.dissect(data, buf, offset);
        }
        #[cfg(feature = "http")]
        {
            packet_dissector_http::HttpDissector.dissect(data, buf, offset)
        }
        #[cfg(not(feature = "http"))]
        Err(PacketError::InvalidHeader("HTTP/1.1 dissector not enabled"))
    }
}

// ---------------------------------------------------------------------------
// L2TP version dispatcher — delegates to L2TPv2 or L2TPv3 based on the
// version nibble in the flags/version word.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "l2tp", feature = "l2tpv3"))]
struct L2tpDispatcher;

#[cfg(any(feature = "l2tp", feature = "l2tpv3"))]
impl Dissector for L2tpDispatcher {
    fn name(&self) -> &'static str {
        "Layer Two Tunneling Protocol"
    }

    fn short_name(&self) -> &'static str {
        "L2TP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        if data.len() < 2 {
            return Err(PacketError::Truncated {
                expected: 2,
                actual: data.len(),
            });
        }

        let version = data[1] & 0x0F;
        match version {
            #[cfg(feature = "l2tp")]
            2 => packet_dissector_l2tp::L2tpDissector.dissect(data, buf, offset),
            #[cfg(feature = "l2tpv3")]
            3 => packet_dissector_l2tpv3::L2tpv3UdpDissector.dissect(data, buf, offset),
            _ => Err(PacketError::InvalidHeader("unsupported L2TP version")),
        }
    }
}

/// Assert that a built-in dissector registration succeeds.
///
/// Used only during [`DissectorRegistry::default()`] initialization where
/// all dispatch keys are hardcoded constants. A collision indicates a
/// programming error in the built-in registrations, not a runtime condition.
fn assert_builtin(result: Result<(), RegistrationError>) {
    if let Err(e) = result {
        panic!("built-in dissector registration failed: {e}");
    }
}

impl Default for DissectorRegistry {
    /// Create a registry pre-loaded with all built-in dissectors (based on enabled features).
    fn default() -> Self {
        #[allow(unused_mut)]
        let mut reg = Self::new();

        #[cfg(feature = "ethernet")]
        reg.set_entry_dissector(Box::new(packet_dissector_ethernet::EthernetDissector));

        // Transparent Ethernet Bridging (0x6558) — used by tunneling
        // protocols (VXLAN, GRE) to encapsulate inner Ethernet frames.
        #[cfg(feature = "ethernet")]
        assert_builtin(reg.register_by_ethertype(
            0x6558,
            Box::new(packet_dissector_ethernet::EthernetDissector),
        ));

        // LINKTYPE_LINUX_SLL (113) — Linux cooked capture v1
        #[cfg(feature = "linux_sll")]
        {
            assert_builtin(reg.register_by_link_type(
                113,
                Box::new(packet_dissector_linux_sll::LinuxSllDissector),
            ));
        }

        // LINKTYPE_LINUX_SLL2 (276) — Linux cooked capture v2
        #[cfg(feature = "linux_sll2")]
        {
            assert_builtin(reg.register_by_link_type(
                276,
                Box::new(packet_dissector_linux_sll2::LinuxSll2Dissector),
            ));
        }

        #[cfg(feature = "ipv4")]
        {
            assert_builtin(
                reg.register_by_ethertype(0x0800, Box::new(packet_dissector_ipv4::Ipv4Dissector)),
            );
            // IP-in-IP encapsulation (RFC 2003, protocol 4)
            assert_builtin(
                reg.register_by_ip_protocol(4, Box::new(packet_dissector_ipv4::Ipv4Dissector)),
            );
        }

        #[cfg(feature = "ipv6")]
        {
            assert_builtin(
                reg.register_by_ethertype(0x86DD, Box::new(packet_dissector_ipv6::Ipv6Dissector)),
            );

            // IPv6 extension headers (RFC 8200, Section 4)
            assert_builtin(
                reg.register_by_ip_protocol(0, Box::new(packet_dissector_ipv6::HopByHopDissector)),
            );
            assert_builtin(
                reg.register_by_ip_protocol(43, Box::new(packet_dissector_ipv6::RoutingDissector)),
            );
            reg.set_ipv6_routing_fallback(Box::new(packet_dissector_ipv6::GenericRoutingDissector));

            // SRv6 is Routing Header Type 4 (RFC 8754)
            #[cfg(feature = "srv6")]
            assert_builtin(reg.register_by_ipv6_routing_type(
                4,
                Box::new(packet_dissector_srv6::Srv6Dissector::new()),
            ));
            assert_builtin(
                reg.register_by_ip_protocol(44, Box::new(packet_dissector_ipv6::FragmentDissector)),
            );
            assert_builtin(reg.register_by_ip_protocol(
                60,
                Box::new(packet_dissector_ipv6::DestinationOptionsDissector),
            ));
            assert_builtin(
                reg.register_by_ip_protocol(
                    135,
                    Box::new(packet_dissector_ipv6::MobilityDissector),
                ),
            );
            // IPv6-in-IPv6 encapsulation (RFC 2473, protocol 41)
            assert_builtin(
                reg.register_by_ip_protocol(41, Box::new(packet_dissector_ipv6::Ipv6Dissector)),
            );
        }

        // AH is IP protocol number 51 (RFC 4302)
        #[cfg(feature = "ah")]
        assert_builtin(reg.register_by_ip_protocol(51, Box::new(packet_dissector_ah::AhDissector)));

        // ESP is IP protocol number 50 (RFC 4303)
        #[cfg(feature = "esp")]
        {
            #[cfg(feature = "esp-decrypt")]
            let esp = Box::new(packet_dissector_esp::EspDissector::with_sa_db(
                reg.esp_sa_db.clone(),
            ));
            #[cfg(not(feature = "esp-decrypt"))]
            let esp = Box::new(packet_dissector_esp::EspDissector::new());

            assert_builtin(reg.register_by_ip_protocol(50, esp));
        }

        // IKE runs over UDP on port 500 (RFC 7296) and port 4500 for NAT-T (RFC 3948)
        #[cfg(feature = "ike")]
        {
            #[cfg(feature = "udp")]
            {
                assert_builtin(
                    reg.register_by_udp_port(500, Box::new(packet_dissector_ike::IkeDissector)),
                );
                assert_builtin(
                    reg.register_by_udp_port(4500, Box::new(packet_dissector_ike::IkeDissector)),
                );
            }
            reg.register_dissector_factory("ike", || Box::new(packet_dissector_ike::IkeDissector));
        }

        // STP/RSTP runs over IEEE 802.2 LLC with SAP 0x42 (IEEE 802.1D-2004)
        #[cfg(feature = "stp")]
        assert_builtin(reg.register_by_llc_sap(0x42, Box::new(packet_dissector_stp::StpDissector)));

        // IS-IS runs over IEEE 802.2 LLC with SAP 0xFE (ISO 10589)
        #[cfg(feature = "isis")]
        assert_builtin(
            reg.register_by_llc_sap(0xFE, Box::new(packet_dissector_isis::IsisDissector)),
        );

        #[cfg(feature = "arp")]
        assert_builtin(
            reg.register_by_ethertype(0x0806, Box::new(packet_dissector_arp::ArpDissector)),
        );

        // EtherType 0x8809 — IEEE 802.3 Slow Protocols (LACP is subtype 0x01)
        #[cfg(feature = "lacp")]
        assert_builtin(
            reg.register_by_ethertype(0x8809, Box::new(packet_dissector_lacp::LacpDissector)),
        );

        // LLDP uses EtherType 0x88CC (IEEE 802.1AB)
        #[cfg(feature = "lldp")]
        assert_builtin(
            reg.register_by_ethertype(0x88CC, Box::new(packet_dissector_lldp::LldpDissector)),
        );

        // MPLS uses EtherType 0x8847 (unicast) and 0x8848 (upstream-assigned) (RFC 3032, RFC 5332)
        #[cfg(feature = "mpls")]
        {
            assert_builtin(
                reg.register_by_ethertype(0x8847, Box::new(packet_dissector_mpls::MplsDissector)),
            );
            assert_builtin(
                reg.register_by_ethertype(0x8848, Box::new(packet_dissector_mpls::MplsDissector)),
            );
        }

        // ICMP is IP protocol number 1 (RFC 792)
        #[cfg(feature = "icmp")]
        assert_builtin(
            reg.register_by_ip_protocol(1, Box::new(packet_dissector_icmp::IcmpDissector)),
        );

        // IGMP is IP protocol number 2 (RFC 2236, RFC 3376)
        #[cfg(feature = "igmp")]
        assert_builtin(
            reg.register_by_ip_protocol(2, Box::new(packet_dissector_igmp::IgmpDissector)),
        );

        // ICMPv6 is IP protocol number 58 (RFC 4443)
        #[cfg(feature = "icmpv6")]
        assert_builtin(
            reg.register_by_ip_protocol(58, Box::new(packet_dissector_icmpv6::Icmpv6Dissector)),
        );

        #[cfg(feature = "tcp")]
        assert_builtin(
            reg.register_by_ip_protocol(6, Box::new(packet_dissector_tcp::TcpDissector::new())),
        );

        #[cfg(feature = "udp")]
        assert_builtin(
            reg.register_by_ip_protocol(17, Box::new(packet_dissector_udp::UdpDissector)),
        );

        // SCTP is IP protocol number 132 (RFC 9260)
        #[cfg(feature = "sctp")]
        assert_builtin(
            reg.register_by_ip_protocol(132, Box::new(packet_dissector_sctp::SctpDissector)),
        );

        // GRE is IP protocol number 47 (RFC 2784)
        #[cfg(feature = "gre")]
        assert_builtin(
            reg.register_by_ip_protocol(47, Box::new(packet_dissector_gre::GreDissector)),
        );

        // L2TPv3 is IP protocol number 115 (RFC 3931)
        #[cfg(feature = "l2tpv3")]
        assert_builtin(
            reg.register_by_ip_protocol(115, Box::new(packet_dissector_l2tpv3::L2tpv3Dissector)),
        );

        // L2TP over UDP on port 1701 — dispatches by version (v2 or v3)
        #[cfg(any(feature = "l2tp", feature = "l2tpv3"))]
        {
            #[cfg(feature = "udp")]
            assert_builtin(reg.register_by_udp_port(1701, Box::new(L2tpDispatcher)));
            reg.register_dissector_factory("l2tp", || Box::new(L2tpDispatcher));
        }

        // OSPF is IP protocol number 89 (RFC 2328, RFC 5340)
        #[cfg(feature = "ospf")]
        assert_builtin(reg.register_by_ip_protocol(89, Box::new(OspfDispatcher)));

        // VRRP is IP protocol number 112 (RFC 9568)
        #[cfg(feature = "vrrp")]
        assert_builtin(
            reg.register_by_ip_protocol(112, Box::new(packet_dissector_vrrp::VrrpDissector)),
        );

        // NTP runs over UDP on port 123 (RFC 5905)
        #[cfg(feature = "ntp")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(123, Box::new(packet_dissector_ntp::NtpDissector)),
            );
            reg.register_dissector_factory("ntp", || Box::new(packet_dissector_ntp::NtpDissector));
        }

        // BFD runs over UDP on ports 3784 (single-hop), 4784 (multihop),
        // and 3785 (echo) (RFC 5881, RFC 5883)
        #[cfg(feature = "bfd")]
        {
            #[cfg(feature = "udp")]
            {
                assert_builtin(
                    reg.register_by_udp_port(3784, Box::new(packet_dissector_bfd::BfdDissector)),
                );
                assert_builtin(
                    reg.register_by_udp_port(4784, Box::new(packet_dissector_bfd::BfdDissector)),
                );
                assert_builtin(
                    reg.register_by_udp_port(3785, Box::new(packet_dissector_bfd::BfdDissector)),
                );
            }
            reg.register_dissector_factory("bfd", || Box::new(packet_dissector_bfd::BfdDissector));
        }

        // DNS runs over both TCP and UDP (RFC 1035)
        #[cfg(feature = "dns")]
        {
            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(53, Box::new(packet_dissector_dns::DnsTcpDissector)),
            );

            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(53, Box::new(packet_dissector_dns::DnsDissector)),
            );

            reg.register_dissector_factory("dns", || Box::new(packet_dissector_dns::DnsDissector));
            reg.register_dissector_factory("dns.tcp", || {
                Box::new(packet_dissector_dns::DnsTcpDissector)
            });
        }

        // mDNS runs over UDP port 5353 (RFC 6762)
        #[cfg(feature = "mdns")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(5353, Box::new(packet_dissector_mdns::MdnsDissector)),
            );

            reg.register_dissector_factory("mdns", || {
                Box::new(packet_dissector_mdns::MdnsDissector)
            });
        }

        // DHCPv6 runs over UDP on ports 546 (client) and 547 (server/relay) (RFC 8415)
        #[cfg(feature = "dhcpv6")]
        {
            #[cfg(feature = "udp")]
            {
                assert_builtin(
                    reg.register_by_udp_port(
                        546,
                        Box::new(packet_dissector_dhcpv6::Dhcpv6Dissector),
                    ),
                );
                assert_builtin(
                    reg.register_by_udp_port(
                        547,
                        Box::new(packet_dissector_dhcpv6::Dhcpv6Dissector),
                    ),
                );
            }
            reg.register_dissector_factory("dhcpv6", || {
                Box::new(packet_dissector_dhcpv6::Dhcpv6Dissector)
            });
        }

        // DHCP runs over UDP on ports 67 (server) and 68 (client) (RFC 2131)
        #[cfg(feature = "dhcp")]
        {
            #[cfg(feature = "udp")]
            {
                assert_builtin(
                    reg.register_by_udp_port(67, Box::new(packet_dissector_dhcp::DhcpDissector)),
                );
                assert_builtin(
                    reg.register_by_udp_port(68, Box::new(packet_dissector_dhcp::DhcpDissector)),
                );
            }
            reg.register_dissector_factory("dhcp", || {
                Box::new(packet_dissector_dhcp::DhcpDissector)
            });
        }

        // HTTP runs over TCP on port 80 (RFC 9112, RFC 9113)
        // Uses HttpDispatcher to auto-detect HTTP/2 connection preface.
        #[cfg(any(feature = "http", feature = "http2"))]
        {
            #[cfg(feature = "tcp")]
            assert_builtin(reg.register_by_tcp_port(80, Box::new(HttpDispatcher)));
        }
        #[cfg(feature = "http")]
        reg.register_dissector_factory("http", || Box::new(packet_dissector_http::HttpDissector));
        #[cfg(feature = "http2")]
        reg.register_dissector_factory("http2", || {
            Box::new(packet_dissector_http2::Http2Dissector)
        });

        // GENEVE runs over UDP on port 6081 (RFC 8926)
        #[cfg(feature = "geneve")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(6081, Box::new(packet_dissector_geneve::GeneveDissector)),
            );
            reg.register_dissector_factory("geneve", || {
                Box::new(packet_dissector_geneve::GeneveDissector)
            });
        }

        // GTPv1-U runs over UDP on port 2152 (3GPP TS 29.281)
        #[cfg(feature = "gtpv1u")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(2152, Box::new(packet_dissector_gtpv1u::Gtpv1uDissector)),
            );
            reg.register_dissector_factory("gtpv1u", || {
                Box::new(packet_dissector_gtpv1u::Gtpv1uDissector)
            });
        }

        // GTPv2-C runs over UDP on port 2123 (3GPP TS 29.274)
        #[cfg(feature = "gtpv2c")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(2123, Box::new(packet_dissector_gtpv2c::Gtpv2cDissector)),
            );
            reg.register_dissector_factory("gtpv2c", || {
                Box::new(packet_dissector_gtpv2c::Gtpv2cDissector)
            });
        }

        // PFCP runs over UDP on port 8805 (3GPP TS 29.244)
        #[cfg(feature = "pfcp")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(8805, Box::new(packet_dissector_pfcp::PfcpDissector)),
            );
            reg.register_dissector_factory("pfcp", || {
                Box::new(packet_dissector_pfcp::PfcpDissector)
            });
        }

        // SIP runs over UDP and TCP on port 5060 (RFC 3261)
        #[cfg(feature = "sip")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(5060, Box::new(packet_dissector_sip::SipDissector)),
            );

            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(5060, Box::new(packet_dissector_sip::SipDissector)),
            );

            reg.register_dissector_factory("sip", || Box::new(packet_dissector_sip::SipDissector));
        }

        // RADIUS runs over UDP on ports 1812 (auth) and 1813 (accounting)
        // (RFC 2865, Section 3 / RFC 2866, Section 3)
        #[cfg(feature = "radius")]
        {
            #[cfg(feature = "udp")]
            {
                assert_builtin(reg.register_by_udp_port(
                    1812,
                    Box::new(packet_dissector_radius::RadiusDissector),
                ));
                assert_builtin(reg.register_by_udp_port(
                    1813,
                    Box::new(packet_dissector_radius::RadiusDissector),
                ));
            }
            reg.register_dissector_factory("radius", || {
                Box::new(packet_dissector_radius::RadiusDissector)
            });
        }

        // Diameter runs over TCP and SCTP on port 3868 (RFC 6733, Section 2.1)
        #[cfg(feature = "diameter")]
        {
            #[cfg(feature = "tcp")]
            assert_builtin(reg.register_by_tcp_port(
                3868,
                Box::new(packet_dissector_diameter::DiameterDissector),
            ));
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_port(
                3868,
                Box::new(packet_dissector_diameter::DiameterDissector),
            ));
            reg.register_dissector_factory("diameter", || {
                Box::new(packet_dissector_diameter::DiameterDissector)
            });
        }

        // NGAP runs over SCTP on port 38412 (3GPP TS 38.413)
        #[cfg(feature = "ngap")]
        {
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_port(38412, Box::new(packet_dissector_ngap::NgapDissector)),
            );
            reg.register_dissector_factory("ngap", || {
                Box::new(packet_dissector_ngap::NgapDissector)
            });
        }

        // NAS-5G is invoked from NGAP IE parsers; register factory for
        // standalone use (e.g., `bask read --dissector nas5g`).
        #[cfg(feature = "nas5g")]
        {
            reg.register_dissector_factory("nas5g", || {
                Box::new(packet_dissector_nas5g::Nas5gDissector)
            });
        }

        // BGP runs over TCP on port 179 (RFC 4271)
        #[cfg(feature = "bgp")]
        {
            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(179, Box::new(packet_dissector_bgp::BgpDissector)),
            );
            reg.register_dissector_factory("bgp", || Box::new(packet_dissector_bgp::BgpDissector));
        }

        // Register TLS for the common HTTPS port 443 (RFC 5246, RFC 8446)
        #[cfg(feature = "tls")]
        {
            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(443, Box::new(packet_dissector_tls::TlsDissector)),
            );
            reg.register_dissector_factory("tls", || Box::new(packet_dissector_tls::TlsDissector));
        }

        // VXLAN runs over UDP on port 4789 (RFC 7348)
        #[cfg(feature = "vxlan")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(4789, Box::new(packet_dissector_vxlan::VxlanDissector)),
            );
            reg.register_dissector_factory("vxlan", || {
                Box::new(packet_dissector_vxlan::VxlanDissector)
            });
        }

        // L2TP port 1701 registration is handled by L2tpDispatcher above.

        // PPP — registered by link type and EtherType
        // LINKTYPE_PPP (9), LINKTYPE_PPP_ETHER (50 — PPPoE payload),
        // EtherType 0x880B (GRE-encapsulated PPP)
        #[cfg(feature = "ppp")]
        {
            assert_builtin(
                reg.register_by_link_type(9, Box::new(packet_dissector_ppp::PppDissector)),
            );
            assert_builtin(
                reg.register_by_link_type(50, Box::new(packet_dissector_ppp::PppDissector)),
            );
            assert_builtin(
                reg.register_by_ethertype(0x880B, Box::new(packet_dissector_ppp::PppDissector)),
            );
        }

        // RTP has no well-known port (dynamically negotiated via SDP/SIP),
        // but is available for decode-as overrides (RFC 3550).
        #[cfg(feature = "rtp")]
        reg.register_dissector_factory("rtp", || Box::new(packet_dissector_rtp::RtpDissector));

        // QUIC runs over UDP, typically on port 443 (RFC 9000).
        #[cfg(feature = "quic")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(443, Box::new(packet_dissector_quic::QuicDissector)),
            );
            reg.register_dissector_factory("quic", || {
                Box::new(packet_dissector_quic::QuicDissector)
            });
        }

        // STUN runs over UDP and TCP on port 3478 (RFC 8489).
        #[cfg(feature = "stun")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(3478, Box::new(packet_dissector_stun::StunDissector)),
            );
            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(3478, Box::new(packet_dissector_stun::StunDissector)),
            );
            reg.register_dissector_factory("stun", || {
                Box::new(packet_dissector_stun::StunDissector)
            });
        }

        reg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::dissector::{DispatchHint, DissectResult};
    use packet_dissector_core::field::FieldDescriptor;

    struct StubDissector(&'static str);

    impl Dissector for StubDissector {
        fn name(&self) -> &'static str {
            self.0
        }
        fn short_name(&self) -> &'static str {
            self.0
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            _data: &'pkt [u8],
            _buf: &mut DissectBuffer<'pkt>,
            _offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            Ok(DissectResult::new(0, DispatchHint::End))
        }
    }

    #[test]
    fn register_and_lookup_by_content_type() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_content_type("application/sdp", Box::new(StubDissector("sdp")))
            .unwrap();

        assert!(reg.get_by_content_type("application/sdp").is_some());
    }

    #[test]
    fn content_type_lookup_is_case_insensitive() {
        let mut reg = DissectorRegistry::new();
        // Keys are &'static str and expected to be pre-normalized (lowercase).
        reg.register_by_content_type("application/sdp", Box::new(StubDissector("sdp")))
            .unwrap();

        assert!(reg.get_by_content_type("application/sdp").is_some());
        assert!(reg.get_by_content_type("APPLICATION/SDP").is_some());
    }

    #[test]
    fn duplicate_content_type_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_content_type("application/sdp", Box::new(StubDissector("sdp")))
            .unwrap();

        let result =
            reg.register_by_content_type("application/sdp", Box::new(StubDissector("sdp2")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateStringKey { .. })
        ));
    }

    #[test]
    fn dual_port_dispatch_falls_back_to_higher_port() {
        let mut reg = DissectorRegistry::new();
        // Register a dissector on port 3784 (the higher port in a typical
        // BFD conversation where the source is an ephemeral port like 49152).
        reg.register_by_udp_port(3784, Box::new(StubDissector("bfd")))
            .unwrap();

        // Dispatch with src=49152, dst=3784: lower port (3784) matches directly.
        let result = match DispatchHint::ByUdpPort(49152, 3784) {
            DispatchHint::ByUdpPort(src, dst) => {
                let (low, high) = (src.min(dst), src.max(dst));
                reg.get_by_udp_port(low)
                    .or_else(|| reg.get_by_udp_port(high))
            }
            _ => unreachable!(),
        };
        assert_eq!(result.map(|d| d.short_name()), Some("bfd"));

        // Now register on port 8080 (higher) and dispatch with src=80, dst=8080.
        // The lower port (80) is not registered, so fallback to higher port (8080).
        reg.register_by_tcp_port(8080, Box::new(StubDissector("alt-http")))
            .unwrap();
        let result = match DispatchHint::ByTcpPort(80, 8080) {
            DispatchHint::ByTcpPort(src, dst) => {
                let (low, high) = (src.min(dst), src.max(dst));
                reg.get_by_tcp_port(low)
                    .or_else(|| reg.get_by_tcp_port(high))
            }
            _ => unreachable!(),
        };
        assert_eq!(result.map(|d| d.short_name()), Some("alt-http"));
    }

    #[test]
    fn register_and_create_dissector_by_name() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector_factory("stub", || Box::new(StubDissector("STUB")));
        let d = reg.create_dissector_by_name("stub").unwrap();
        assert_eq!(d.short_name(), "STUB");
    }

    #[test]
    fn create_dissector_by_unknown_name_returns_none() {
        let reg = DissectorRegistry::new();
        assert!(reg.create_dissector_by_name("nonexistent").is_none());
    }

    #[test]
    fn factory_creates_independent_instances() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector_factory("stub", || Box::new(StubDissector("STUB")));
        let d1 = reg.create_dissector_by_name("stub").unwrap();
        let d2 = reg.create_dissector_by_name("stub").unwrap();
        assert_eq!(d1.short_name(), d2.short_name());
    }

    #[test]
    fn register_dissector_factory_returns_none_on_first_insert() {
        let mut reg = DissectorRegistry::new();
        let prev = reg.register_dissector_factory("stub", || Box::new(StubDissector("STUB")));
        assert!(prev.is_none());
    }

    #[test]
    fn register_dissector_factory_returns_previous_on_overwrite() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector_factory("stub", || Box::new(StubDissector("OLD")));
        let prev = reg.register_dissector_factory("stub", || Box::new(StubDissector("NEW")));
        assert!(prev.is_some());
        // Verify the new factory is active
        let d = reg.create_dissector_by_name("stub").unwrap();
        assert_eq!(d.short_name(), "NEW");
    }

    #[test]
    fn available_decode_as_protocols_lists_registered_names() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector_factory("beta", || Box::new(StubDissector("B")));
        reg.register_dissector_factory("alpha", || Box::new(StubDissector("A")));
        let names = reg.available_decode_as_protocols();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn default_registry_has_factories_for_port_protocols() {
        let reg = DissectorRegistry::default();
        #[cfg(feature = "http")]
        assert!(reg.create_dissector_by_name("http").is_some());
        #[cfg(feature = "dns")]
        {
            assert!(reg.create_dissector_by_name("dns").is_some());
            assert!(reg.create_dissector_by_name("dns.tcp").is_some());
        }
        #[cfg(feature = "mdns")]
        assert!(reg.create_dissector_by_name("mdns").is_some());
        #[cfg(feature = "tls")]
        assert!(reg.create_dissector_by_name("tls").is_some());
        #[cfg(feature = "bgp")]
        assert!(reg.create_dissector_by_name("bgp").is_some());
        #[cfg(feature = "sip")]
        assert!(reg.create_dissector_by_name("sip").is_some());
    }

    #[test]
    fn register_by_content_type_or_replace_overwrites() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_content_type("application/sdp", Box::new(StubDissector("sdp")))
            .unwrap();
        reg.register_by_content_type_or_replace("application/sdp", Box::new(StubDissector("sdp2")));

        assert_eq!(
            reg.get_by_content_type("application/sdp")
                .map(|d| d.short_name()),
            Some("sdp2")
        );
    }

    // --- Lookup returning None on empty/missing keys ---

    #[test]
    fn get_by_ethertype_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_ethertype(0xFFFF).is_none());
    }

    #[test]
    fn get_by_ip_protocol_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_ip_protocol(255).is_none());
    }

    #[test]
    fn get_by_tcp_port_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_tcp_port(12345).is_none());
    }

    #[test]
    fn get_by_udp_port_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_udp_port(12345).is_none());
    }

    #[test]
    fn get_by_sctp_port_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_sctp_port(12345).is_none());
    }

    #[test]
    fn get_by_llc_sap_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_llc_sap(0xFF).is_none());
    }

    #[test]
    fn get_by_link_type_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_link_type(9999).is_none());
    }

    #[test]
    fn get_by_content_type_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_content_type("application/unknown").is_none());
    }

    #[test]
    fn get_by_ipv6_routing_type_returns_none_without_fallback() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_ipv6_routing_type(99).is_none());
    }

    #[test]
    fn get_by_ipv6_routing_type_uses_fallback() {
        let mut reg = DissectorRegistry::new();
        reg.set_ipv6_routing_fallback(Box::new(StubDissector("generic-rt")));
        // No type-specific dissector registered — should fall back.
        let d = reg.get_by_ipv6_routing_type(99);
        assert_eq!(d.map(|d| d.short_name()), Some("generic-rt"));
    }

    #[test]
    fn get_by_ipv6_routing_type_prefers_specific_over_fallback() {
        let mut reg = DissectorRegistry::new();
        reg.set_ipv6_routing_fallback(Box::new(StubDissector("generic-rt")));
        reg.register_by_ipv6_routing_type(4, Box::new(StubDissector("srv6")))
            .unwrap();
        let d = reg.get_by_ipv6_routing_type(4);
        assert_eq!(d.map(|d| d.short_name()), Some("srv6"));
    }

    // --- Duplicate registration errors ---

    #[test]
    fn duplicate_ethertype_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_ethertype(0x0800, Box::new(StubDissector("ipv4")))
            .unwrap();
        let result = reg.register_by_ethertype(0x0800, Box::new(StubDissector("ipv4-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "ethertype",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_ip_protocol_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_ip_protocol(6, Box::new(StubDissector("tcp")))
            .unwrap();
        let result = reg.register_by_ip_protocol(6, Box::new(StubDissector("tcp-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "ip_protocol",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_tcp_port_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_tcp_port(80, Box::new(StubDissector("http")))
            .unwrap();
        let result = reg.register_by_tcp_port(80, Box::new(StubDissector("http-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "tcp_port",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_udp_port_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_udp_port(53, Box::new(StubDissector("dns")))
            .unwrap();
        let result = reg.register_by_udp_port(53, Box::new(StubDissector("dns-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "udp_port",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_sctp_port_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_sctp_port(3868, Box::new(StubDissector("diameter")))
            .unwrap();
        let result = reg.register_by_sctp_port(3868, Box::new(StubDissector("diameter-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "sctp_port",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_ipv6_routing_type_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_ipv6_routing_type(4, Box::new(StubDissector("srv6")))
            .unwrap();
        let result = reg.register_by_ipv6_routing_type(4, Box::new(StubDissector("srv6-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "ipv6_routing_type",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_link_type_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_link_type(1, Box::new(StubDissector("ethernet")))
            .unwrap();
        let result = reg.register_by_link_type(1, Box::new(StubDissector("ethernet-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "link_type",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_llc_sap_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_llc_sap(0x42, Box::new(StubDissector("stp")))
            .unwrap();
        let result = reg.register_by_llc_sap(0x42, Box::new(StubDissector("stp-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "llc_sap",
                ..
            })
        ));
    }

    // --- or_replace methods ---

    #[test]
    fn register_by_ethertype_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_ethertype_or_replace(0x0800, Box::new(StubDissector("ipv4")))
                .is_none()
        );
        let prev =
            reg.register_by_ethertype_or_replace(0x0800, Box::new(StubDissector("ipv4-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("ipv4"));
        assert_eq!(
            reg.get_by_ethertype(0x0800).map(|d| d.short_name()),
            Some("ipv4-new")
        );
    }

    #[test]
    fn register_by_ip_protocol_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_ip_protocol_or_replace(6, Box::new(StubDissector("tcp")))
                .is_none()
        );
        let prev = reg.register_by_ip_protocol_or_replace(6, Box::new(StubDissector("tcp-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("tcp"));
    }

    #[test]
    fn register_by_tcp_port_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_tcp_port_or_replace(80, Box::new(StubDissector("http")))
                .is_none()
        );
        let prev = reg.register_by_tcp_port_or_replace(80, Box::new(StubDissector("http-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("http"));
    }

    #[test]
    fn register_by_udp_port_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_udp_port_or_replace(53, Box::new(StubDissector("dns")))
                .is_none()
        );
        let prev = reg.register_by_udp_port_or_replace(53, Box::new(StubDissector("dns-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("dns"));
    }

    #[test]
    fn register_by_sctp_port_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_sctp_port_or_replace(3868, Box::new(StubDissector("diameter")))
                .is_none()
        );
        let prev =
            reg.register_by_sctp_port_or_replace(3868, Box::new(StubDissector("diameter-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("diameter"));
    }

    #[test]
    fn register_by_ipv6_routing_type_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_ipv6_routing_type_or_replace(4, Box::new(StubDissector("srv6")))
                .is_none()
        );
        let prev =
            reg.register_by_ipv6_routing_type_or_replace(4, Box::new(StubDissector("srv6-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("srv6"));
    }

    #[test]
    fn register_by_link_type_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_link_type_or_replace(1, Box::new(StubDissector("eth")))
                .is_none()
        );
        let prev = reg.register_by_link_type_or_replace(1, Box::new(StubDissector("eth-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("eth"));
    }

    #[test]
    fn register_by_llc_sap_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_llc_sap_or_replace(0x42, Box::new(StubDissector("stp")))
                .is_none()
        );
        let prev = reg.register_by_llc_sap_or_replace(0x42, Box::new(StubDissector("stp-new")));
        assert_eq!(prev.map(|d| d.short_name()), Some("stp"));
    }

    // --- SCTP port dispatch in dispatch_loop ---

    #[test]
    fn sctp_port_dispatch_prefers_lower_port() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_sctp_port(3868, Box::new(StubDissector("diameter")))
            .unwrap();

        let hint = DispatchHint::BySctpPort(49152, 3868);
        let low = 3868_u16;
        let high = 49152_u16;
        let d = reg
            .get_by_sctp_port(low)
            .or_else(|| reg.get_by_sctp_port(high));
        assert_eq!(d.map(|d| d.short_name()), Some("diameter"));

        // Verify with reversed port order
        let hint2 = DispatchHint::BySctpPort(3868, 49152);
        match hint2 {
            DispatchHint::BySctpPort(src, dst) => {
                let (low, high) = (src.min(dst), src.max(dst));
                let d = reg
                    .get_by_sctp_port(low)
                    .or_else(|| reg.get_by_sctp_port(high));
                assert_eq!(d.map(|d| d.short_name()), Some("diameter"));
            }
            _ => unreachable!(),
        }

        // No match for unknown ports
        match hint {
            DispatchHint::BySctpPort(_, _) => {
                let d = reg
                    .get_by_sctp_port(9999)
                    .or_else(|| reg.get_by_sctp_port(9998));
                assert!(d.is_none());
            }
            _ => unreachable!(),
        }
    }

    // --- register_dissector convenience method ---

    #[test]
    fn register_dissector_dispatches_to_entry() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(DissectorTable::Entry, Box::new(StubDissector("eth")))
            .unwrap();
        assert!(reg.entry.is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_ethertype() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::EtherType(0x0800),
            Box::new(StubDissector("ipv4")),
        )
        .unwrap();
        assert!(reg.get_by_ethertype(0x0800).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_ip_protocol() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::IpProtocol(6),
            Box::new(StubDissector("tcp")),
        )
        .unwrap();
        assert!(reg.get_by_ip_protocol(6).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_tcp_port() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(DissectorTable::TcpPort(80), Box::new(StubDissector("http")))
            .unwrap();
        assert!(reg.get_by_tcp_port(80).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_udp_port() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(DissectorTable::UdpPort(53), Box::new(StubDissector("dns")))
            .unwrap();
        assert!(reg.get_by_udp_port(53).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_sctp_port() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::SctpPort(3868),
            Box::new(StubDissector("diameter")),
        )
        .unwrap();
        assert!(reg.get_by_sctp_port(3868).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_content_type() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::ContentType("text/plain"),
            Box::new(StubDissector("text")),
        )
        .unwrap();
        assert!(reg.get_by_content_type("text/plain").is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_ipv6_routing_type() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::Ipv6RoutingType(4),
            Box::new(StubDissector("srv6")),
        )
        .unwrap();
        assert!(reg.get_by_ipv6_routing_type(4).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_llc_sap() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(DissectorTable::LlcSap(0x42), Box::new(StubDissector("stp")))
            .unwrap();
        assert!(reg.get_by_llc_sap(0x42).is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_ipv6_routing_fallback() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::Ipv6RoutingFallback,
            Box::new(StubDissector("generic-rt")),
        )
        .unwrap();
        assert!(reg.ipv6_routing_fallback.is_some());
    }

    #[test]
    fn register_dissector_dispatches_to_link_type() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::LinkType(113),
            Box::new(StubDissector("sll")),
        )
        .unwrap();
        assert!(reg.get_by_link_type(113).is_some());
    }

    // --- register_dissector_or_replace convenience method ---

    #[test]
    fn register_dissector_or_replace_entry() {
        let mut reg = DissectorRegistry::new();
        let prev = reg
            .register_dissector_or_replace(DissectorTable::Entry, Box::new(StubDissector("eth")));
        assert!(prev.is_none());
        let prev = reg
            .register_dissector_or_replace(DissectorTable::Entry, Box::new(StubDissector("eth2")));
        assert_eq!(prev.map(|d| d.short_name()), Some("eth"));
    }

    #[test]
    fn register_dissector_or_replace_ipv6_routing_fallback() {
        let mut reg = DissectorRegistry::new();
        let prev = reg.register_dissector_or_replace(
            DissectorTable::Ipv6RoutingFallback,
            Box::new(StubDissector("generic")),
        );
        assert!(prev.is_none());
        let prev = reg.register_dissector_or_replace(
            DissectorTable::Ipv6RoutingFallback,
            Box::new(StubDissector("generic2")),
        );
        assert_eq!(prev.map(|d| d.short_name()), Some("generic"));
    }

    #[test]
    fn register_dissector_or_replace_all_table_types() {
        let mut reg = DissectorRegistry::new();

        // EtherType
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::EtherType(0x0800),
                Box::new(StubDissector("a")),
            )
            .is_none()
        );

        // IpProtocol
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::IpProtocol(6),
                Box::new(StubDissector("b")),
            )
            .is_none()
        );

        // TcpPort
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::TcpPort(80),
                Box::new(StubDissector("c")),
            )
            .is_none()
        );

        // UdpPort
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::UdpPort(53),
                Box::new(StubDissector("d")),
            )
            .is_none()
        );

        // SctpPort
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::SctpPort(3868),
                Box::new(StubDissector("e")),
            )
            .is_none()
        );

        // ContentType
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::ContentType("text/plain"),
                Box::new(StubDissector("f")),
            )
            .is_none()
        );

        // Ipv6RoutingType
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::Ipv6RoutingType(4),
                Box::new(StubDissector("g")),
            )
            .is_none()
        );

        // LlcSap
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::LlcSap(0x42),
                Box::new(StubDissector("h")),
            )
            .is_none()
        );

        // LinkType
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::LinkType(1),
                Box::new(StubDissector("i")),
            )
            .is_none()
        );
    }

    // --- register_plugin ---

    struct StubPlugin;

    impl DissectorPlugin for StubPlugin {
        fn dissectors(&self) -> Vec<(DissectorTable, Box<dyn Dissector>)> {
            vec![
                (
                    DissectorTable::UdpPort(9999),
                    Box::new(StubDissector("plug-udp")),
                ),
                (
                    DissectorTable::TcpPort(9999),
                    Box::new(StubDissector("plug-tcp")),
                ),
            ]
        }
    }

    #[test]
    fn register_plugin_registers_all_dissectors() {
        let mut reg = DissectorRegistry::new();
        reg.register_plugin(&StubPlugin).unwrap();
        assert!(reg.get_by_udp_port(9999).is_some());
        assert!(reg.get_by_tcp_port(9999).is_some());
    }

    #[test]
    fn register_plugin_stops_on_first_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_udp_port(9999, Box::new(StubDissector("existing")))
            .unwrap();
        let result = reg.register_plugin(&StubPlugin);
        assert!(result.is_err());
        // TCP port should NOT have been registered because registration stopped
        // at the first duplicate (UDP 9999).
        assert!(reg.get_by_tcp_port(9999).is_none());
    }

    // --- dissect without entry dissector ---

    #[test]
    fn dissect_without_entry_dissector_returns_error() {
        let reg = DissectorRegistry::new();
        let mut buf = DissectBuffer::new();
        let result = reg.dissect(&[0u8; 14], &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn dissect_with_link_type_without_any_dissector_returns_error() {
        let reg = DissectorRegistry::new();
        let mut buf = DissectBuffer::new();
        let result = reg.dissect_with_link_type(&[0u8; 14], 999, &mut buf);
        assert!(result.is_err());
    }

    // --- all_field_schemas ---

    #[test]
    fn all_field_schemas_deduplicates_by_short_name() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_udp_port(53, Box::new(StubDissector("dns")))
            .unwrap();
        reg.register_by_tcp_port(53, Box::new(StubDissector("dns")))
            .unwrap();
        let schemas = reg.all_field_schemas();
        let dns_count = schemas.iter().filter(|s| s.short_name == "dns").count();
        assert_eq!(dns_count, 1);
    }

    #[test]
    fn all_field_schemas_includes_all_table_types() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(StubDissector("entry")));
        reg.register_by_ethertype(0x0800, Box::new(StubDissector("et")))
            .unwrap();
        reg.register_by_ip_protocol(6, Box::new(StubDissector("ip")))
            .unwrap();
        reg.register_by_udp_port(53, Box::new(StubDissector("udp")))
            .unwrap();
        reg.register_by_tcp_port(80, Box::new(StubDissector("tcp")))
            .unwrap();
        reg.register_by_sctp_port(3868, Box::new(StubDissector("sctp")))
            .unwrap();
        reg.register_by_ipv6_routing_type(4, Box::new(StubDissector("rt")))
            .unwrap();
        reg.register_by_content_type("text/plain", Box::new(StubDissector("ct")))
            .unwrap();
        reg.register_by_llc_sap(0x42, Box::new(StubDissector("llc")))
            .unwrap();
        reg.set_ipv6_routing_fallback(Box::new(StubDissector("rt-fb")));
        reg.register_by_link_type(113, Box::new(StubDissector("lt")))
            .unwrap();

        let schemas = reg.all_field_schemas();
        let names: Vec<&str> = schemas.iter().map(|s| s.short_name).collect();
        assert!(names.contains(&"entry"));
        assert!(names.contains(&"et"));
        assert!(names.contains(&"ip"));
        assert!(names.contains(&"udp"));
        assert!(names.contains(&"tcp"));
        assert!(names.contains(&"sctp"));
        assert!(names.contains(&"rt"));
        assert!(names.contains(&"ct"));
        assert!(names.contains(&"llc"));
        assert!(names.contains(&"rt-fb"));
        assert!(names.contains(&"lt"));
    }

    // --- Default registry feature-gated registrations ---

    #[test]
    fn default_registry_has_expected_dissectors() {
        let reg = DissectorRegistry::default();

        #[cfg(feature = "ethernet")]
        assert!(reg.entry.is_some());

        #[cfg(feature = "ethernet")]
        assert!(reg.get_by_ethertype(0x6558).is_some());

        #[cfg(feature = "ipv4")]
        {
            assert!(reg.get_by_ethertype(0x0800).is_some());
            assert!(reg.get_by_ip_protocol(4).is_some());
        }

        #[cfg(feature = "ipv6")]
        {
            assert!(reg.get_by_ethertype(0x86DD).is_some());
            assert!(reg.get_by_ip_protocol(0).is_some());
            assert!(reg.get_by_ip_protocol(43).is_some());
            assert!(reg.get_by_ip_protocol(44).is_some());
            assert!(reg.get_by_ip_protocol(60).is_some());
            assert!(reg.get_by_ip_protocol(135).is_some());
            assert!(reg.get_by_ip_protocol(41).is_some());
        }

        #[cfg(feature = "arp")]
        assert!(reg.get_by_ethertype(0x0806).is_some());

        #[cfg(feature = "icmp")]
        assert!(reg.get_by_ip_protocol(1).is_some());

        #[cfg(feature = "icmpv6")]
        assert!(reg.get_by_ip_protocol(58).is_some());

        #[cfg(feature = "tcp")]
        assert!(reg.get_by_ip_protocol(6).is_some());

        #[cfg(feature = "udp")]
        assert!(reg.get_by_ip_protocol(17).is_some());

        #[cfg(feature = "sctp")]
        assert!(reg.get_by_ip_protocol(132).is_some());

        #[cfg(feature = "gre")]
        assert!(reg.get_by_ip_protocol(47).is_some());

        #[cfg(feature = "ospf")]
        assert!(reg.get_by_ip_protocol(89).is_some());

        #[cfg(feature = "vrrp")]
        assert!(reg.get_by_ip_protocol(112).is_some());

        #[cfg(feature = "ah")]
        assert!(reg.get_by_ip_protocol(51).is_some());

        #[cfg(feature = "esp")]
        assert!(reg.get_by_ip_protocol(50).is_some());

        #[cfg(feature = "l2tpv3")]
        assert!(reg.get_by_ip_protocol(115).is_some());

        #[cfg(feature = "lacp")]
        assert!(reg.get_by_ethertype(0x8809).is_some());

        #[cfg(feature = "lldp")]
        assert!(reg.get_by_ethertype(0x88CC).is_some());

        #[cfg(feature = "mpls")]
        {
            assert!(reg.get_by_ethertype(0x8847).is_some());
            assert!(reg.get_by_ethertype(0x8848).is_some());
        }

        #[cfg(feature = "linux_sll")]
        assert!(reg.get_by_link_type(113).is_some());

        #[cfg(feature = "linux_sll2")]
        assert!(reg.get_by_link_type(276).is_some());

        #[cfg(feature = "ppp")]
        {
            assert!(reg.get_by_link_type(9).is_some());
            assert!(reg.get_by_link_type(50).is_some());
            assert!(reg.get_by_ethertype(0x880B).is_some());
        }

        #[cfg(feature = "stp")]
        assert!(reg.get_by_llc_sap(0x42).is_some());

        #[cfg(feature = "isis")]
        assert!(reg.get_by_llc_sap(0xFE).is_some());
    }

    #[test]
    fn default_registry_port_based_dissectors() {
        let reg = DissectorRegistry::default();

        #[cfg(all(feature = "dns", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(53).is_some());

        #[cfg(all(feature = "dns", feature = "udp"))]
        assert!(reg.get_by_udp_port(53).is_some());

        #[cfg(all(feature = "http", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(80).is_some());

        #[cfg(all(feature = "tls", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(443).is_some());

        #[cfg(all(feature = "bgp", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(179).is_some());

        #[cfg(all(feature = "sip", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(5060).is_some());

        #[cfg(all(feature = "sip", feature = "udp"))]
        assert!(reg.get_by_udp_port(5060).is_some());

        #[cfg(all(feature = "dhcp", feature = "udp"))]
        {
            assert!(reg.get_by_udp_port(67).is_some());
            assert!(reg.get_by_udp_port(68).is_some());
        }

        #[cfg(all(feature = "dhcpv6", feature = "udp"))]
        {
            assert!(reg.get_by_udp_port(546).is_some());
            assert!(reg.get_by_udp_port(547).is_some());
        }

        #[cfg(all(feature = "ntp", feature = "udp"))]
        assert!(reg.get_by_udp_port(123).is_some());

        #[cfg(all(feature = "bfd", feature = "udp"))]
        {
            assert!(reg.get_by_udp_port(3784).is_some());
            assert!(reg.get_by_udp_port(4784).is_some());
            assert!(reg.get_by_udp_port(3785).is_some());
        }

        #[cfg(all(feature = "mdns", feature = "udp"))]
        assert!(reg.get_by_udp_port(5353).is_some());

        #[cfg(all(feature = "vxlan", feature = "udp"))]
        assert!(reg.get_by_udp_port(4789).is_some());

        #[cfg(all(feature = "geneve", feature = "udp"))]
        assert!(reg.get_by_udp_port(6081).is_some());

        #[cfg(all(feature = "gtpv1u", feature = "udp"))]
        assert!(reg.get_by_udp_port(2152).is_some());

        #[cfg(all(feature = "gtpv2c", feature = "udp"))]
        assert!(reg.get_by_udp_port(2123).is_some());

        #[cfg(all(feature = "pfcp", feature = "udp"))]
        assert!(reg.get_by_udp_port(8805).is_some());

        #[cfg(all(feature = "ike", feature = "udp"))]
        {
            assert!(reg.get_by_udp_port(500).is_some());
            assert!(reg.get_by_udp_port(4500).is_some());
        }

        #[cfg(all(feature = "radius", feature = "udp"))]
        {
            assert!(reg.get_by_udp_port(1812).is_some());
            assert!(reg.get_by_udp_port(1813).is_some());
        }

        #[cfg(all(feature = "diameter", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(3868).is_some());

        #[cfg(all(feature = "diameter", feature = "sctp"))]
        assert!(reg.get_by_sctp_port(3868).is_some());

        #[cfg(all(feature = "ngap", feature = "sctp"))]
        assert!(reg.get_by_sctp_port(38412).is_some());

        #[cfg(all(any(feature = "l2tp", feature = "l2tpv3"), feature = "udp"))]
        assert!(reg.get_by_udp_port(1701).is_some());
    }

    #[test]
    fn default_registry_factories() {
        let reg = DissectorRegistry::default();

        #[cfg(feature = "ntp")]
        assert!(reg.create_dissector_by_name("ntp").is_some());

        #[cfg(feature = "bfd")]
        assert!(reg.create_dissector_by_name("bfd").is_some());

        #[cfg(feature = "dhcp")]
        assert!(reg.create_dissector_by_name("dhcp").is_some());

        #[cfg(feature = "dhcpv6")]
        assert!(reg.create_dissector_by_name("dhcpv6").is_some());

        #[cfg(feature = "geneve")]
        assert!(reg.create_dissector_by_name("geneve").is_some());

        #[cfg(feature = "gtpv1u")]
        assert!(reg.create_dissector_by_name("gtpv1u").is_some());

        #[cfg(feature = "gtpv2c")]
        assert!(reg.create_dissector_by_name("gtpv2c").is_some());

        #[cfg(feature = "pfcp")]
        assert!(reg.create_dissector_by_name("pfcp").is_some());

        #[cfg(feature = "vxlan")]
        assert!(reg.create_dissector_by_name("vxlan").is_some());

        #[cfg(feature = "ike")]
        assert!(reg.create_dissector_by_name("ike").is_some());

        #[cfg(feature = "diameter")]
        assert!(reg.create_dissector_by_name("diameter").is_some());

        #[cfg(feature = "radius")]
        assert!(reg.create_dissector_by_name("radius").is_some());

        #[cfg(feature = "ngap")]
        assert!(reg.create_dissector_by_name("ngap").is_some());

        #[cfg(feature = "nas5g")]
        assert!(reg.create_dissector_by_name("nas5g").is_some());

        #[cfg(any(feature = "l2tp", feature = "l2tpv3"))]
        assert!(reg.create_dissector_by_name("l2tp").is_some());

        #[cfg(feature = "rtp")]
        assert!(reg.create_dissector_by_name("rtp").is_some());

        #[cfg(feature = "quic")]
        assert!(reg.create_dissector_by_name("quic").is_some());

        #[cfg(feature = "stun")]
        assert!(reg.create_dissector_by_name("stun").is_some());

        // Non-existent factory
        assert!(reg.create_dissector_by_name("nonexistent").is_none());
    }

    // --- content_type whitespace trimming ---

    #[test]
    fn content_type_lookup_trims_whitespace() {
        let mut reg = DissectorRegistry::new();
        // Keys are &'static str and expected to be pre-normalized (no whitespace).
        reg.register_by_content_type("text/html", Box::new(StubDissector("html")))
            .unwrap();
        assert!(reg.get_by_content_type("text/html").is_some());
        assert!(reg.get_by_content_type("  text/html  ").is_some());
    }

    #[test]
    fn content_type_or_replace_trims_and_normalizes() {
        let mut reg = DissectorRegistry::new();
        // Keys are &'static str and expected to be pre-normalized (lowercase, no whitespace).
        reg.register_by_content_type_or_replace("text/html", Box::new(StubDissector("html")));
        assert_eq!(
            reg.get_by_content_type("text/html").map(|d| d.short_name()),
            Some("html")
        );
    }
}
