//! Dissector registry for managing and dispatching protocol dissectors.

use std::collections::{HashMap, HashSet};
#[cfg(feature = "mpls")]
use std::sync::atomic::Ordering;

use packet_dissector_core::dissector::{
    DispatchHint, Dissector, DissectorPlugin, DissectorTable, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::{PacketError, RegistrationError};
use packet_dissector_core::field::{FieldDescriptor, FieldValue};
use packet_dissector_core::packet::{AuxDataHandle, DissectBuffer};

use crate::summary::{DissectSummary, FieldProjection};

/// Always-`false` early-termination predicate used for full dissection.
///
/// A free fn (single concrete type) rather than a closure, so the recursive
/// `dispatch_loop` instantiation for decrypted payloads does not create an
/// unbounded chain of monomorphizations.
pub(crate) fn no_stop(_: &DissectBuffer<'_>, _: &DispatchHint) -> bool {
    false
}

/// Shrink the dispatch end bound to the payload a dissector declared.
///
/// `payload_start` is the absolute offset right after the dissector's header
/// and `payload_len` is [`DissectResult::payload_len`]. The result never
/// exceeds `end`, so a captured buffer shorter than the declared length
/// (snaplen truncation) keeps its actual end.
pub(crate) fn bound_payload_end(
    end: usize,
    payload_start: usize,
    payload_len: Option<usize>,
) -> usize {
    match payload_len {
        Some(len) => end.min(payload_start.saturating_add(len)),
        None => end,
    }
}

/// Number of layers, fields and scratch bytes at the start of a temporary
/// buffer that were copied from the main buffer and must not be merged back.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TmpPrefix {
    pub(crate) layers: usize,
    pub(crate) fields: u32,
    pub(crate) scratch: u32,
}

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
    by_sctp_ppid: HashMap<u32, Box<dyn Dissector>>,
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
    /// MPLS G-ACh Channel Type table — dispatches the message after an
    /// Associated Channel Header (RFC 5586, Section 2.1).
    by_ach_channel_type: HashMap<u16, Box<dyn Dissector>>,
    /// SS7 MTP3 Service Indicator table — mirrors Wireshark's
    /// `mtp3.service_indicator` dissector table.
    by_mtp3_service_indicator: HashMap<u8, Box<dyn Dissector>>,
    /// SCCP subsystem number table — mirrors Wireshark's `sccp.ssn`
    /// dissector table.
    by_sccp_ssn: HashMap<u8, Box<dyn Dissector>>,
    /// SNAP (Organization Code, Protocol Identifier) table — dispatches SNAP
    /// payloads whose PID is not an EtherType (IEEE Std 802-2014, Clause 10).
    by_snap: HashMap<(u32, u16), Box<dyn Dissector>>,
    /// Factory functions for creating fresh dissector instances by decode-as name.
    /// Keys are lowercase protocol names (e.g., "http", "dns", "dns.tcp").
    dissector_factories: HashMap<String, fn() -> Box<dyn Dissector>>,
    /// Centralized IP fragment reassembly service.
    #[cfg(feature = "ip-reassembly")]
    pub(crate) ip_reassembly: std::sync::Mutex<super::ip_reassembly::IpReassemblyService>,
    /// Centralized TCP stream reassembly service.
    #[cfg(feature = "tcp")]
    pub(crate) tcp_reassembly: std::sync::Mutex<super::tcp_reassembly::TcpReassemblyService>,
    /// Shared ESP Security Association database for decryption.
    #[cfg(feature = "esp-decrypt")]
    esp_sa_db: packet_dissector_esp::EspSaDb,
    /// MPLS label table — decode-as rules for the payload after a
    /// bottom-of-stack label, shared with the built-in MPLS dispatcher.
    #[cfg(feature = "mpls")]
    mpls_labels: std::sync::Arc<MplsLabelTable>,
    /// Whether dissectors verify checksums; see
    /// [`set_verify_checksums`](Self::set_verify_checksums).
    verify_checksums: bool,
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
            by_sctp_ppid: HashMap::new(),
            by_content_type: HashMap::new(),
            by_ipv6_routing_type: HashMap::new(),
            ipv6_routing_fallback: None,
            by_llc_sap: HashMap::new(),
            by_link_type: HashMap::new(),
            by_ach_channel_type: HashMap::new(),
            by_mtp3_service_indicator: HashMap::new(),
            by_sccp_ssn: HashMap::new(),
            by_snap: HashMap::new(),
            dissector_factories: HashMap::new(),
            #[cfg(feature = "ip-reassembly")]
            ip_reassembly: super::ip_reassembly::new_ip_reassembly(),
            #[cfg(feature = "tcp")]
            tcp_reassembly: super::tcp_reassembly::new_tcp_reassembly(),
            #[cfg(feature = "esp-decrypt")]
            esp_sa_db: std::sync::Arc::new(packet_dissector_esp::SharedEspSaDb::new()),
            #[cfg(feature = "mpls")]
            mpls_labels: std::sync::Arc::new(MplsLabelTable::default()),
            verify_checksums: false,
        }
    }

    /// Enable or disable checksum verification (off by default).
    ///
    /// When enabled, dissectors that carry a checksum compute it and add an
    /// informational `checksum_status` field holding a
    /// [`ChecksumStatus`](packet_dissector_core::checksum::ChecksumStatus)
    /// (`good`, `bad`, `unverified` or `not_present`). A bad checksum is never
    /// a dissection error.
    ///
    /// Verification is off by default because captures taken on the sending
    /// host often carry checksums that the NIC fills in after the capture
    /// point (TX checksum offload), which would be reported as `bad`.
    pub fn set_verify_checksums(&mut self, verify: bool) {
        self.verify_checksums = verify;
    }

    /// Whether checksum verification is enabled; see
    /// [`set_verify_checksums`](Self::set_verify_checksums).
    pub fn verify_checksums(&self) -> bool {
        self.verify_checksums
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
    ///
    /// The entry dissector is used only by [`dissect`](Self::dissect),
    /// [`dissect_summary`](Self::dissect_summary) and
    /// [`dissect_projected`](Self::dissect_projected). The `*_with_link_type`
    /// methods look the entry dissector up in the link-type table and do not
    /// fall back to this one; register it there as well with
    /// [`register_by_link_type`](Self::register_by_link_type) (for example
    /// link type `1`, `LINKTYPE_ETHERNET`) or, on a
    /// [`default`](Self::default) registry, replace the built-in entry with
    /// [`register_by_link_type_or_replace`](Self::register_by_link_type_or_replace).
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

    /// Register a dissector for a given SCTP Payload Protocol Identifier.
    ///
    /// Used for [`DispatchHint::BySctpPpid`], before the SCTP ports are
    /// tried. PPID 0 means "unspecified" (RFC 9260, Section 3.3.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1>) and is never
    /// looked up, so a dissector registered for it is not used. Returns an
    /// error if a dissector is already registered for this PPID. Use
    /// [`register_by_sctp_ppid_or_replace`](Self::register_by_sctp_ppid_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_sctp_ppid(
        &mut self,
        ppid: u32,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_sctp_ppid.get(&ppid) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "sctp_ppid",
                key: ppid as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_sctp_ppid.insert(ppid, dissector);
        Ok(())
    }

    /// Register a dissector for a given SCTP Payload Protocol Identifier,
    /// replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_sctp_ppid_or_replace(
        &mut self,
        ppid: u32,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_sctp_ppid.insert(ppid, dissector)
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

    /// Register a dissector for a given MPLS G-ACh Channel Type.
    ///
    /// Returns an error if a dissector is already registered for this
    /// channel type. Use
    /// [`register_by_ach_channel_type_or_replace`](Self::register_by_ach_channel_type_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_ach_channel_type(
        &mut self,
        channel_type: u16,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_ach_channel_type.get(&channel_type) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "ach_channel_type",
                key: channel_type as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_ach_channel_type.insert(channel_type, dissector);
        Ok(())
    }

    /// Register a dissector for a given G-ACh Channel Type, replacing any
    /// existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_ach_channel_type_or_replace(
        &mut self,
        channel_type: u16,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_ach_channel_type.insert(channel_type, dissector)
    }

    /// Look up a dissector by MPLS G-ACh Channel Type.
    pub fn get_by_ach_channel_type(&self, channel_type: u16) -> Option<&dyn Dissector> {
        self.by_ach_channel_type
            .get(&channel_type)
            .map(|d| d.as_ref())
    }

    /// Register a dissector for a given SS7 MTP3 Service Indicator.
    ///
    /// Returns an error if a dissector is already registered for this
    /// Service Indicator. Use
    /// [`register_by_mtp3_service_indicator_or_replace`](Self::register_by_mtp3_service_indicator_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_mtp3_service_indicator(
        &mut self,
        si: u8,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_mtp3_service_indicator.get(&si) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "mtp3_service_indicator",
                key: si as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_mtp3_service_indicator.insert(si, dissector);
        Ok(())
    }

    /// Register a dissector for a given SS7 MTP3 Service Indicator,
    /// replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_mtp3_service_indicator_or_replace(
        &mut self,
        si: u8,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_mtp3_service_indicator.insert(si, dissector)
    }

    /// Look up a dissector by SS7 MTP3 Service Indicator.
    pub fn get_by_mtp3_service_indicator(&self, si: u8) -> Option<&dyn Dissector> {
        self.by_mtp3_service_indicator.get(&si).map(|d| d.as_ref())
    }

    /// Register a dissector for a given SCCP subsystem number.
    ///
    /// Used for [`DispatchHint::BySccpSsn`]. SSN 0 ("SSN not known/not
    /// used", ITU-T Q.713, clause 3.4.2.2) is accepted but never looked up.
    /// Returns an error if a dissector is already registered for this SSN.
    /// Use [`register_by_sccp_ssn_or_replace`](Self::register_by_sccp_ssn_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_sccp_ssn(
        &mut self,
        ssn: u8,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_sccp_ssn.get(&ssn) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "sccp_ssn",
                key: ssn as u64,
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_sccp_ssn.insert(ssn, dissector);
        Ok(())
    }

    /// Register a dissector for a given SCCP subsystem number, replacing any
    /// existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_sccp_ssn_or_replace(
        &mut self,
        ssn: u8,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_sccp_ssn.insert(ssn, dissector)
    }

    /// Look up a dissector by SCCP subsystem number.
    pub fn get_by_sccp_ssn(&self, ssn: u8) -> Option<&dyn Dissector> {
        self.by_sccp_ssn.get(&ssn).map(|d| d.as_ref())
    }

    /// Register a dissector for the payload after the bottom-of-stack MPLS
    /// label `label` (a decode-as rule, e.g. `pw-eth` or `pw-eth-cw`).
    ///
    /// The PW type, and hence the payload type, is signalled out of band
    /// (RFC 4385, Section 3 — <https://www.rfc-editor.org/rfc/rfc4385#section-3>),
    /// so the MPLS dissector otherwise guesses it from the first nibble
    /// (RFC 4928, Section 3 — <https://www.rfc-editor.org/rfc/rfc4928#section-3>).
    /// A rule replaces that guess for `label`. It is consulted by the
    /// built-in MPLS dissector registered for EtherType 0x8847 only:
    /// upstream-assigned labels (0x8848) come from a context-specific label
    /// space (RFC 5331, Section 3 —
    /// <https://www.rfc-editor.org/rfc/rfc5331#section-3>). It is never
    /// consulted for bottom labels with a fixed meaning (IPv4 / IPv6
    /// Explicit NULL and the GAL) or for a bottom entropy label, and it has
    /// no effect once 0x8847 is re-registered with another dissector.
    /// Labels are 20 bits wide, so a larger value never matches.
    ///
    /// Returns an error if a dissector is already registered for this
    /// label. Use
    /// [`register_by_mpls_label_or_replace`](Self::register_by_mpls_label_or_replace)
    /// to intentionally override an existing registration.
    #[cfg(feature = "mpls")]
    pub fn register_by_mpls_label(
        &mut self,
        label: u32,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        let mut rules = self.mpls_labels.lock();
        if let Some(existing) = rules.get(&label) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "mpls_label",
                key: u64::from(label),
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        rules.insert(label, dissector);
        self.mpls_labels.has_rules.store(true, Ordering::Release);
        Ok(())
    }

    /// Register a dissector for the payload after the bottom-of-stack MPLS
    /// label `label`, replacing any existing one.
    ///
    /// See [`register_by_mpls_label`](Self::register_by_mpls_label). Returns
    /// the previously registered dissector, if any.
    #[cfg(feature = "mpls")]
    pub fn register_by_mpls_label_or_replace(
        &mut self,
        label: u32,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        let previous = self.mpls_labels.lock().insert(label, dissector);
        self.mpls_labels.has_rules.store(true, Ordering::Release);
        previous
    }

    /// Short name of the dissector registered for MPLS label `label`, if
    /// any.
    #[cfg(feature = "mpls")]
    pub fn mpls_label_short_name(&self, label: u32) -> Option<&'static str> {
        self.mpls_labels.lock().get(&label).map(|d| d.short_name())
    }

    /// Register a dissector for a SNAP Organization Code (OUI) and Protocol
    /// Identifier.
    ///
    /// The SNAP dissector looks this table up only for Organization Codes
    /// whose Protocol Identifier is not an EtherType, so registering OUI
    /// 00-00-00 or 00-00-F8 has no effect. `oui` holds the 24-bit code in
    /// its low three octets.
    ///
    /// Returns an error if a dissector is already registered for this pair.
    /// Use [`register_by_snap_or_replace`](Self::register_by_snap_or_replace)
    /// to intentionally override an existing registration.
    pub fn register_by_snap(
        &mut self,
        oui: u32,
        pid: u16,
        dissector: Box<dyn Dissector>,
    ) -> Result<(), RegistrationError> {
        if let Some(existing) = self.by_snap.get(&(oui, pid)) {
            return Err(RegistrationError::DuplicateDispatchKey {
                table: "snap",
                key: (u64::from(oui) << 16) | u64::from(pid),
                existing: existing.short_name(),
                new: dissector.short_name(),
            });
        }
        self.by_snap.insert((oui, pid), dissector);
        Ok(())
    }

    /// Register a dissector for a SNAP OUI and Protocol Identifier,
    /// replacing any existing one.
    ///
    /// Returns the previously registered dissector, if any.
    pub fn register_by_snap_or_replace(
        &mut self,
        oui: u32,
        pid: u16,
        dissector: Box<dyn Dissector>,
    ) -> Option<Box<dyn Dissector>> {
        self.by_snap.insert((oui, pid), dissector)
    }

    /// Look up a dissector by SNAP Organization Code and Protocol Identifier.
    pub fn get_by_snap(&self, oui: u32, pid: u16) -> Option<&dyn Dissector> {
        self.by_snap.get(&(oui, pid)).map(|d| d.as_ref())
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

    /// Look up a dissector by SCTP Payload Protocol Identifier.
    pub fn get_by_sctp_ppid(&self, ppid: u32) -> Option<&dyn Dissector> {
        self.by_sctp_ppid.get(&ppid).map(|d| d.as_ref())
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

    /// Resolve the default entry dissector.
    fn entry_dissector(&self) -> Result<&dyn Dissector, PacketError> {
        self.entry
            .as_deref()
            .ok_or(PacketError::InvalidHeader("no entry dissector configured"))
    }

    /// Resolve the entry dissector for a pcap link-layer type.
    ///
    /// There is no fallback to the default entry dissector: a link type
    /// without a registered dissector is reported as
    /// [`PacketError::UnsupportedLinkType`] instead of being guessed.
    fn entry_dissector_for_link_type(&self, link_type: u32) -> Result<&dyn Dissector, PacketError> {
        self.get_by_link_type(link_type)
            .ok_or(PacketError::UnsupportedLinkType(link_type))
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
        let entry = self.entry_dissector()?;
        self.dissect_from_entry(entry, data, buf, &mut no_stop, true)
    }

    /// Dissect a raw packet using a link-layer type to select the entry dissector.
    ///
    /// The entry dissector is looked up in the `by_link_type` table (see
    /// [`register_by_link_type`](Self::register_by_link_type)). The default
    /// entry dissector set via
    /// [`set_entry_dissector`](Self::set_entry_dissector) is **not** used as a
    /// fallback.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::UnsupportedLinkType`] if no dissector is
    /// registered for `link_type`, and any error returned by the dissectors.
    ///
    /// # Link-layer types
    ///
    /// Registered by [`DissectorRegistry::default()`] (values from
    /// <https://www.tcpdump.org/linktypes.html>), subject to feature flags:
    /// - `0` — `LINKTYPE_NULL` (`null`)
    /// - `1` — `LINKTYPE_ETHERNET` (`ethernet`)
    /// - `9` — `LINKTYPE_PPP` (`ppp`)
    /// - `50` — `LINKTYPE_PPP_HDLC` (`ppp`)
    /// - `101` — `LINKTYPE_RAW` (`raw_ip`)
    /// - `105` — `LINKTYPE_IEEE802_11` (`ieee80211`)
    /// - `108` — `LINKTYPE_LOOP` (`null`)
    /// - `113` — `LINKTYPE_LINUX_SLL` (`linux_sll`)
    /// - `127` — `LINKTYPE_IEEE802_11_RADIOTAP` (`radiotap`)
    /// - `228` — `LINKTYPE_IPV4` (`raw_ip`)
    /// - `229` — `LINKTYPE_IPV6` (`raw_ip`)
    /// - `276` — `LINKTYPE_LINUX_SLL2` (`linux_sll2`)
    pub fn dissect_with_link_type<'pkt>(
        &self,
        data: &'pkt [u8],
        link_type: u32,
        buf: &mut DissectBuffer<'pkt>,
    ) -> Result<(), PacketError> {
        let entry = self.entry_dissector_for_link_type(link_type)?;
        self.dissect_from_entry(entry, data, buf, &mut no_stop, true)
    }

    /// Shallow dissection for row summaries: stop once the transport layer
    /// has been dissected, without building the application-layer field tree.
    ///
    /// The dispatch loop runs normally for link/network/transport layers and
    /// stops as soon as a port-based dispatch hint
    /// ([`ByTcpPort`](DispatchHint::ByTcpPort) /
    /// [`ByUdpPort`](DispatchHint::ByUdpPort) /
    /// [`BySctpPort`](DispatchHint::BySctpPort) /
    /// [`BySctpPpid`](DispatchHint::BySctpPpid)) is produced. The protocol
    /// that would handle the next layer is resolved from the dispatch tables
    /// and reported as [`DissectSummary::next_protocol`] so callers can still
    /// display it (e.g., in a packet-list protocol column).
    ///
    /// Chains that never produce a port-based hint (e.g., ARP, ICMP) are
    /// dissected fully, identical to [`dissect`](Self::dissect).
    ///
    /// Stopping before the upper-layer dissector also skips TCP reassembly
    /// and tunnel/inner-packet dissection, so for tunneled packets (e.g.,
    /// VXLAN) the summary describes the outermost transport.
    ///
    /// IP fragments are not fed to the stateful fragment reassembly (feature
    /// `ip-reassembly`): a first fragment is summarized by its own transport
    /// header and any other fragment ends after its IP layer, so summarizing
    /// a capture does not disturb a later full dissection of it.
    ///
    /// # Example
    ///
    /// ```
    /// use packet_dissector::registry::DissectorRegistry;
    /// use packet_dissector::packet::DissectBuffer;
    ///
    /// let registry = DissectorRegistry::default();
    /// let packet_bytes: &[u8] = &[
    ///     // Ethernet
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x08, 0x00,
    ///     // IPv4 (proto = UDP)
    ///     0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
    ///     0x40, 0x11, 0x00, 0x00,
    ///     0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
    ///     // UDP (dst port 53 = DNS)
    ///     0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
    /// ];
    ///
    /// let mut buf = DissectBuffer::new();
    /// let summary = registry.dissect_summary(packet_bytes, &mut buf).unwrap();
    /// assert_eq!(buf.layers().len(), 3); // Ethernet, IPv4, UDP — DNS skipped
    /// assert_eq!(summary.next_protocol, Some("DNS"));
    /// ```
    pub fn dissect_summary<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
    ) -> Result<DissectSummary, PacketError> {
        let entry = self.entry_dissector()?;
        let mut summary = DissectSummary::new();
        self.dissect_from_entry(
            entry,
            data,
            buf,
            &mut |buf, hint| self.summary_stop(buf, hint, &mut summary),
            false,
        )?;
        Ok(summary)
    }

    /// [`dissect_summary`](Self::dissect_summary) variant that selects the
    /// entry dissector by pcap link-layer type, like
    /// [`dissect_with_link_type`](Self::dissect_with_link_type).
    pub fn dissect_summary_with_link_type<'pkt>(
        &self,
        data: &'pkt [u8],
        link_type: u32,
        buf: &mut DissectBuffer<'pkt>,
    ) -> Result<DissectSummary, PacketError> {
        let entry = self.entry_dissector_for_link_type(link_type)?;
        let mut summary = DissectSummary::new();
        self.dissect_from_entry(
            entry,
            data,
            buf,
            &mut |buf, hint| self.summary_stop(buf, hint, &mut summary),
            false,
        )?;
        Ok(summary)
    }

    /// Summary stop predicate: stop at the first port-based dispatch hint
    /// and record the next protocol's short name.
    ///
    /// When the hint itself resolves to no dissector, the payloads the
    /// transport layer recorded in `buf` (e.g. bundled SCTP DATA chunks) are
    /// tried in order, so a later user message can name the protocol.
    fn summary_stop(
        &self,
        buf: &DissectBuffer<'_>,
        hint: &DispatchHint,
        summary: &mut DissectSummary,
    ) -> bool {
        match hint {
            DispatchHint::ByTcpPort(..)
            | DispatchHint::ByUdpPort(..)
            | DispatchHint::BySctpPort(..)
            | DispatchHint::BySctpPpid { .. } => {
                summary.next_protocol = self
                    .lookup_dissector(hint)
                    .or_else(|| {
                        buf.embedded_payloads()
                            .iter()
                            .find_map(|p| self.lookup_dissector(&p.next))
                    })
                    .map(|d| d.short_name());
                true
            }
            _ => false,
        }
    }

    /// Shallow dissection by field projection: stop as soon as every field
    /// requested in `projection` has been produced.
    ///
    /// The projection is checked at layer granularity — after each dissector
    /// finishes, newly added layers are scanned for the requested
    /// `(layer, field)` targets, and the dispatch loop stops before
    /// dissecting any deeper layer once all targets are found. If the packet
    /// never produces all targets, the chain runs to completion, identical
    /// to [`dissect`](Self::dissect) except that IP fragments are not
    /// reassembled (see below), and [`FieldProjection::is_satisfied`]
    /// returns `false`.
    ///
    /// Like [`dissect_summary`](Self::dissect_summary), projected
    /// dissection does not feed IP fragments to the stateful fragment
    /// reassembly (feature `ip-reassembly`): a first fragment is dissected
    /// from its own upper-layer header and any other fragment ends after
    /// its IP layer.
    ///
    /// `projection` is reset automatically, so it can be reused across
    /// packets without per-packet allocation. Read the extracted values from
    /// `buf` as usual (e.g., via
    /// [`field_by_name`](packet_dissector_core::packet::DissectBuffer::field_by_name)).
    ///
    /// # Example
    ///
    /// ```
    /// use packet_dissector::registry::DissectorRegistry;
    /// use packet_dissector::packet::DissectBuffer;
    /// use packet_dissector::summary::FieldProjection;
    ///
    /// let registry = DissectorRegistry::default();
    /// let packet_bytes: &[u8] = &[
    ///     // Ethernet
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x08, 0x00,
    ///     // IPv4 (proto = UDP)
    ///     0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
    ///     0x40, 0x11, 0x00, 0x00,
    ///     0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
    ///     // UDP
    ///     0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
    /// ];
    ///
    /// let mut projection = FieldProjection::new([("IPv4", "src"), ("IPv4", "dst")]);
    /// let mut buf = DissectBuffer::new();
    /// registry.dissect_projected(packet_bytes, &mut buf, &mut projection).unwrap();
    /// assert!(projection.is_satisfied());
    /// assert_eq!(buf.layers().len(), 2); // Ethernet, IPv4 — UDP skipped
    /// ```
    pub fn dissect_projected<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        projection: &mut FieldProjection,
    ) -> Result<(), PacketError> {
        let entry = self.entry_dissector()?;
        projection.reset();
        self.dissect_from_entry(entry, data, buf, &mut |buf, _| projection.scan(buf), false)
    }

    /// [`dissect_projected`](Self::dissect_projected) variant that selects
    /// the entry dissector by pcap link-layer type, like
    /// [`dissect_with_link_type`](Self::dissect_with_link_type).
    pub fn dissect_projected_with_link_type<'pkt>(
        &self,
        data: &'pkt [u8],
        link_type: u32,
        buf: &mut DissectBuffer<'pkt>,
        projection: &mut FieldProjection,
    ) -> Result<(), PacketError> {
        // Reset first so a reused projection never reports the previous
        // packet's state when the link type is unsupported.
        projection.reset();
        let entry = self.entry_dissector_for_link_type(link_type)?;
        self.dissect_from_entry(entry, data, buf, &mut |buf, _| projection.scan(buf), false)
    }

    /// Dissect with the given entry dissector, then run the dispatch loop.
    ///
    /// `stop` and `full` are described on
    /// [`dispatch_loop`](Self::dispatch_loop).
    fn dissect_from_entry<'pkt, F>(
        &self,
        entry: &dyn Dissector,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        stop: &mut F,
        full: bool,
    ) -> Result<(), PacketError>
    where
        F: FnMut(&DissectBuffer<'pkt>, &DispatchHint) -> bool,
    {
        buf.set_verify_checksums(self.verify_checksums);
        let payloads_base = buf.embedded_payloads().len();
        let result = match entry.dissect(data, buf, 0) {
            Ok(result) => result,
            Err(e) => {
                buf.truncate_embedded_payloads(payloads_base);
                return Err(e);
            }
        };
        if buf.embedded_payloads().len() > payloads_base {
            if stop(buf, &result.next) {
                buf.truncate_embedded_payloads(payloads_base);
                return Ok(());
            }
            return self.dispatch_embedded_payloads(
                data,
                buf,
                payloads_base,
                data.len(),
                stop,
                full,
            );
        }
        let end = bound_payload_end(data.len(), result.bytes_consumed, result.payload_len);
        // An IP entry dissector (e.g. set with `set_entry_dissector`) may
        // report a fragment itself.
        #[cfg(feature = "ip-reassembly")]
        if let Some(result) =
            self.reassemble_reported_fragment(&result, data, buf, result.bytes_consumed, end, full)
        {
            return result;
        }
        self.dispatch_loop(
            data,
            buf,
            result.bytes_consumed,
            end,
            result.next,
            stop,
            full,
        )
    }

    /// Dispatch the payloads a dissector recorded with
    /// [`DissectBuffer::push_embedded_payload`] (entries from index `base`
    /// on), each through its own dispatch chain, then drop those entries.
    ///
    /// `end` is the exclusive end of the recording layer's input; payload
    /// ranges are clipped to it. Every payload is dispatched even if an
    /// earlier one fails: the layers of all chains are kept (a failed chain
    /// keeps what it parsed before the error, as elsewhere in the registry)
    /// and the first error is returned once all payloads have been tried.
    ///
    /// RFC 9260, Section 6.10 — each DATA chunk bundled in an SCTP packet
    /// carries its own user message —
    /// <https://www.rfc-editor.org/rfc/rfc9260#section-6.10>.
    fn dispatch_embedded_payloads<'pkt, F>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        base: usize,
        end: usize,
        stop: &mut F,
        full: bool,
    ) -> Result<(), PacketError>
    where
        F: FnMut(&DissectBuffer<'pkt>, &DispatchHint) -> bool,
    {
        let count = buf.embedded_payloads().len();
        let mut first_err = None;
        for i in base..count {
            let payload = buf.embedded_payloads()[i].clone();
            let start = payload.range.start;
            let payload_end = payload.range.end.min(end);
            if start >= payload_end {
                continue;
            }
            if let Err(e) =
                self.dispatch_loop(data, buf, start, payload_end, payload.next, stop, full)
            {
                first_err.get_or_insert(e);
            }
        }
        buf.truncate_embedded_payloads(base);
        first_err.map_or(Ok(()), Err)
    }

    /// Look up the dissector responsible for a dispatch hint.
    ///
    /// Port-based hints try the lower port first, then the higher port,
    /// mirroring Wireshark's dual-port dispatch strategy.
    pub(crate) fn lookup_dissector(&self, hint: &DispatchHint) -> Option<&dyn Dissector> {
        match hint {
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
            DispatchHint::BySctpPpid {
                ppid,
                src_port,
                dst_port,
            } => {
                // RFC 9260, Section 3.3.1 — PPID 0 means no application
                // identifier is specified —
                // https://www.rfc-editor.org/rfc/rfc9260#section-3.3.1
                let by_ppid = match *ppid {
                    0 => None,
                    ppid => self.get_by_sctp_ppid(ppid),
                };
                by_ppid.or_else(|| {
                    self.lookup_dissector(&DispatchHint::BySctpPort(*src_port, *dst_port))
                })
            }
            DispatchHint::ByContentType(ct) => self.get_by_content_type(ct),
            DispatchHint::ByIpv6RoutingType(rt) => self.get_by_ipv6_routing_type(*rt),
            DispatchHint::ByLlcSap(sap) => self.get_by_llc_sap(*sap),
            DispatchHint::ByAchChannelType(ct) => self.get_by_ach_channel_type(*ct),
            DispatchHint::ByMtp3ServiceIndicator(si) => self.get_by_mtp3_service_indicator(*si),
            DispatchHint::BySccpSsn { called, calling } => {
                // ITU-T Q.713, clause 3.4.2.2 — SSN "00000000" is "SSN not
                // known/not used" — https://www.itu.int/rec/T-REC-Q.713
                let by_ssn = |ssn: u8| match ssn {
                    0 => None,
                    ssn => self.get_by_sccp_ssn(ssn),
                };
                by_ssn(*called).or_else(|| by_ssn(*calling))
            }
            DispatchHint::ByLinkType(lt) => self.get_by_link_type(*lt),
            DispatchHint::BySnap { oui, pid } => self.get_by_snap(*oui, *pid),
        }
    }

    /// Run the dispatch loop starting from the given hint and offset.
    ///
    /// `end` is the exclusive end of the bytes that belong to the enclosing
    /// layers (at most `data.len()`). Every dissector gets
    /// `&data[offset..end]`, and a dissector that reports
    /// [`DissectResult::payload_len`] shrinks `end` further, so bytes past an
    /// IP datagram or an 802.3 LLC PDU (e.g. Ethernet padding) never reach
    /// upper layers.
    ///
    /// `stop` is evaluated with the current buffer state and the pending
    /// dispatch hint before each dissector runs, and again immediately after
    /// each dissector returns (before reassembly / tunnel middleware). When
    /// it returns `true` the loop terminates early, leaving the layers
    /// dissected so far in `buf`. Full dissection passes a predicate that
    /// always returns `false`.
    ///
    /// The predicate is a generic parameter (not `&mut dyn FnMut`) so the
    /// full-dissection instantiation inlines the always-`false` predicate
    /// and keeps the existing fast path free of indirect calls.
    ///
    /// `full` is `true` for full dissection ([`dissect`](Self::dissect) and
    /// [`dissect_with_link_type`](Self::dissect_with_link_type)). Only full
    /// dissection feeds IP fragments to the (stateful) fragment reassembly;
    /// shallow dissection dispatches the first fragment's upper layers as
    /// if reassembly were disabled and leaves the reassembly state alone.
    #[cfg_attr(not(feature = "ip-reassembly"), allow(unused_variables))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_loop<'pkt, F>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        mut offset: usize,
        mut end: usize,
        mut next: DispatchHint,
        stop: &mut F,
        full: bool,
    ) -> Result<(), PacketError>
    where
        F: FnMut(&DissectBuffer<'pkt>, &DispatchHint) -> bool,
    {
        // Track whether the previous iteration made no progress (consumed 0
        // bytes).  Thin dispatchers like `RoutingDissector` legitimately return
        // `bytes_consumed = 0` once to redirect via a different DispatchHint,
        // so we allow one zero-consumption iteration.  Two consecutive
        // zero-consumption iterations indicate an infinite loop.
        let mut stalled = false;

        loop {
            // Early-termination check on the pending hint. Covers the
            // initial hint and the `continue` paths from the middleware
            // blocks below.
            if stop(buf, &next) {
                break;
            }

            let Some(dissector) = self.lookup_dissector(&next) else {
                break;
            };

            if offset >= end {
                break;
            }

            let payloads_base = buf.embedded_payloads().len();
            let layer_end = end;
            let result = match dissector.dissect(&data[offset..end], buf, offset) {
                Ok(result) => result,
                Err(e) => {
                    buf.truncate_embedded_payloads(payloads_base);
                    return Err(e);
                }
            };

            // Guard against infinite loops: if a dissector consumed zero bytes
            // two iterations in a row, break.  A single zero-consumption
            // iteration is allowed for thin dispatchers (e.g.,
            // RoutingDissector) that change the DispatchHint without consuming
            // input.
            if result.bytes_consumed == 0 && !matches!(result.next, DispatchHint::End) {
                if stalled {
                    buf.truncate_embedded_payloads(payloads_base);
                    break;
                }
                stalled = true;
            } else {
                stalled = false;
            }

            offset += result.bytes_consumed;
            end = bound_payload_end(end, offset, result.payload_len);

            // Early-termination check on the dissector's own hint, before
            // the reassembly / tunnel middleware below runs. This is what
            // lets `dissect_summary` stop right after the transport layer
            // without paying for TCP reassembly or inner-packet dissection.
            if stop(buf, &result.next) {
                buf.truncate_embedded_payloads(payloads_base);
                break;
            }

            // Embedded payload list middleware: a dissector that carries
            // several upper-layer messages (e.g. bundled SCTP DATA chunks)
            // records each one in the buffer, and each gets its own chain.
            if buf.embedded_payloads().len() > payloads_base {
                return self.dispatch_embedded_payloads(
                    data,
                    buf,
                    payloads_base,
                    layer_end,
                    stop,
                    full,
                );
            }

            // Embedded payload middleware: when a dissector signals that the
            // next dissector's input is at a specific range within the original
            // packet (e.g., SCTP DATA chunk user data), dispatch directly to
            // that range instead of using the normal offset-based slicing.
            // The next dissector then runs through this loop like any other,
            // so its own embedded payload (e.g. SCCP user data inside M3UA
            // Protocol Data) and middleware are honoured, and its input ends
            // at the embedded range.
            if let Some(ref payload_range) = result.embedded_payload {
                let start = payload_range.start;
                let range_end = payload_range.end.min(end);
                if start >= range_end {
                    break;
                }
                offset = start;
                end = range_end;
                next = result.next;
                continue;
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
                // Decrypted inner data is always dissected to the end: shallow
                // callers stop on the outer chain before reaching this point.
                // `no_stop` is a free fn (not a closure) so this recursive
                // instantiation does not depend on `F` and monomorphization
                // terminates. `full` is passed on so a shallow caller never
                // feeds inner IP fragments to the reassembly state.
                let mut tmp_buf = DissectBuffer::new();
                tmp_buf.set_verify_checksums(buf.verify_checksums());
                let mut inner_stop = no_stop;
                self.dispatch_loop(
                    &padded,
                    &mut tmp_buf,
                    virtual_start,
                    padded.len(),
                    decrypted.next,
                    &mut inner_stop,
                    full,
                )?;

                // Merge tmp_buf into the main buf. Layers are cheap to copy.
                // Fields may borrow from `padded`, so we remap Bytes/Str
                // references into buf.aux_data (which stores the same data
                // and outlives the fields).
                Self::merge_tmp_buf(buf, tmp_buf, &padded, virtual_start, aux_handle);
                break;
            }

            // IP fragment reassembly middleware: a fragment's data is
            // buffered, and the packet that completes a datagram continues
            // with the upper layers of the reassembled datagram. Packets
            // carrying an incomplete datagram end here, including the first
            // fragment. A fragment whose data was not captured in full
            // (snaplen truncation) cannot be reassembled; it, and every
            // fragment in shallow dissection, follows the dissector's own
            // hint (the first fragment's upper layers, or the end of the
            // chain).
            // RFC 791, Section 3.2 —
            // https://www.rfc-editor.org/rfc/rfc791#section-3.2
            // RFC 8200, Section 4.5 —
            // https://www.rfc-editor.org/rfc/rfc8200#section-4.5
            #[cfg(feature = "ip-reassembly")]
            if let Some(result) =
                self.reassemble_reported_fragment(&result, data, buf, offset, end, full)
            {
                return result;
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
                        let remaining = end.saturating_sub(offset);
                        let payload_end = offset + ctx.payload_len.min(remaining);
                        let payload = &data[offset..payload_end];
                        // The capture may hold fewer bytes than the segment
                        // occupies in sequence space (snaplen truncation).
                        let captured_all = payload.len() >= ctx.payload_len;
                        // The middleware dissects every message in the
                        // segment (and their bodies) itself, so the chain
                        // ends here.
                        self.handle_tcp_segment(ctx, payload, captured_all, upper, buf, offset)?;
                        break;
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
        Self::merge_tmp_tail(
            buf,
            tmp_buf,
            TmpPrefix::default(),
            padded,
            virtual_start,
            aux_handle,
        );
    }

    /// Like [`merge_tmp_buf`](Self::merge_tmp_buf), but skip the first
    /// `prefix` layers, fields and scratch bytes of `tmp_buf`: a copy of
    /// `buf`'s own content that seeded the temporary buffer so upper-layer
    /// dissectors could see the enclosing layers.
    pub(crate) fn merge_tmp_tail<'pkt>(
        buf: &mut DissectBuffer<'pkt>,
        tmp_buf: DissectBuffer<'_>,
        prefix: TmpPrefix,
        padded: &[u8],
        virtual_start: usize,
        aux_handle: AuxDataHandle,
    ) {
        use packet_dissector_core::field::Field;

        // Indices recorded in `tmp_buf` count the prefix; in `buf` they
        // start at its current length instead.
        let field_offset = buf.field_count() - prefix.fields;
        let scratch_offset = buf.scratch_len() - prefix.scratch;
        buf.extend_scratch(&tmp_buf.scratch()[prefix.scratch as usize..]);
        for layer in &tmp_buf.layers()[prefix.layers..] {
            let mut layer = layer.clone();
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

        // `tmp_buf` stays alive while its fields are remapped: values that
        // borrow from its own auxiliary data (e.g. TCP reassembly inside the
        // inner dissection) are copied into `buf` before it is dropped.
        for field in &tmp_buf.fields()[prefix.fields as usize..] {
            // Remap borrowed field values from `padded` to `buf.aux_data`.
            let new_value: FieldValue<'pkt> =
                Self::remap_field_value(field.value.clone(), buf, &remap_ctx);
            buf.push_raw_field(Field {
                descriptor: field.descriptor,
                value: new_value,
                range: field.range.clone(),
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

/// Metadata describing a single registered dissector.
///
/// Superset of [`ProtocolFieldSchema`], adding the specification references
/// and the stack position the dissector declares. Marked `#[non_exhaustive]`
/// so further metadata can be added without a breaking change; construct it
/// only through [`DissectorRegistry::all_protocol_info`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// Full protocol name.
    pub name: &'static str,
    /// Short protocol name (layer key).
    pub short_name: &'static str,
    /// Position of the protocol in the dissection stack, if declared.
    pub layer: Option<ProtocolLayer>,
    /// Specifications the dissector is implemented against.
    pub references: &'static [SpecReference],
    /// Field descriptors for this protocol.
    pub fields: &'static [FieldDescriptor],
}

impl DissectorRegistry {
    /// Visits every registered dissector exactly once, deduplicated by
    /// `short_name`.
    ///
    /// The same dissector type may be registered under multiple dispatch keys
    /// (e.g., DNS on both TCP port 53 and UDP port 53); only the first
    /// occurrence is passed to `visit`. Shared by
    /// [`all_field_schemas`](Self::all_field_schemas) and
    /// [`all_protocol_info`](Self::all_protocol_info) so the two cannot drift
    /// in content or order.
    fn for_each_unique_dissector(&self, mut visit: impl FnMut(&dyn Dissector)) {
        let mut seen = HashSet::new();

        let mut push = |d: &dyn Dissector| {
            if seen.insert(d.short_name()) {
                visit(d);
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
        for d in self.by_sctp_ppid.values() {
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
        for d in self.by_ach_channel_type.values() {
            push(d.as_ref());
        }
        for d in self.by_mtp3_service_indicator.values() {
            push(d.as_ref());
        }
        for d in self.by_sccp_ssn.values() {
            push(d.as_ref());
        }
        for d in self.by_snap.values() {
            push(d.as_ref());
        }
        if let Some(ref d) = self.ipv6_routing_fallback {
            push(d.as_ref());
        }
        #[cfg(feature = "mpls")]
        for d in self.mpls_labels.lock().values() {
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
        // BMP is registered by decode-as name only.
        #[cfg(feature = "bmp")]
        push(&packet_dissector_bmp::BmpDissector);
        // The MPLS dissector emits ACH and PW control word layers itself
        // (RFC 5586, Section 2.1 — https://www.rfc-editor.org/rfc/rfc5586#section-2.1;
        // RFC 4385, Section 3 — https://www.rfc-editor.org/rfc/rfc4385#section-3).
        #[cfg(feature = "mpls")]
        push(&packet_dissector_mpls::AchDissector);
        #[cfg(feature = "mpls")]
        push(&packet_dissector_mpls::PwControlWordDissector);
        // The Slow Protocols dispatcher delegates by subtype; expose the
        // schemas of the layers it produces.
        #[cfg(feature = "lacp")]
        {
            push(&packet_dissector_lacp::LacpDissector);
            push(&packet_dissector_lacp::MarkerDissector);
            push(&packet_dissector_lacp::OamDissector);
            push(&packet_dissector_lacp::OsspDissector);
            push(&packet_dissector_lacp::EsmcDissector);
        }
        // The EAPOL dissector emits EAP layers itself (RFC 3748 —
        // https://www.rfc-editor.org/rfc/rfc3748).
        #[cfg(feature = "eap")]
        push(&packet_dissector_eap::EapDissector);
        // GtpcDispatcher delegates by version; expose both GTP-C schemas.
        #[cfg(feature = "gtpv1c")]
        push(&packet_dissector_gtpv1c::Gtpv1cDissector);
        #[cfg(feature = "gtpv2c")]
        push(&packet_dissector_gtpv2c::Gtpv2cDissector);
        // StunDissector emits TURN ChannelData layers on the shared STUN port.
        #[cfg(feature = "stun")]
        push(&packet_dissector_stun::TurnChannelDataDissector);
        // The "netflow" decode-as dissector emits NetFlow v5, v9 and IPFIX
        // layers; IPFIX is also registered on port 4739 when a transport
        // feature is enabled.
        #[cfg(feature = "ipfix")]
        {
            push(&packet_dissector_ipfix::IpfixDissector::new());
            push(&packet_dissector_ipfix::NetflowV9Dissector::new());
            push(&packet_dissector_ipfix::NetflowV5Dissector);
        }
    }

    /// Returns field metadata for all registered dissectors.
    ///
    /// Each dissector is included at most once, deduplicated by `short_name`
    /// (the same dissector type may be registered under multiple dispatch keys,
    /// e.g., DNS on both TCP port 53 and UDP port 53).
    pub fn all_field_schemas(&self) -> Vec<ProtocolFieldSchema> {
        let mut schemas = Vec::new();
        self.for_each_unique_dissector(|d| {
            schemas.push(ProtocolFieldSchema {
                name: d.name(),
                short_name: d.short_name(),
                fields: d.field_descriptors(),
            });
        });
        schemas
    }

    /// Returns protocol metadata for all registered dissectors.
    ///
    /// Same dissectors, deduplication and order as
    /// [`all_field_schemas`](Self::all_field_schemas), with the specification
    /// references and stack position each dissector declares.
    pub fn all_protocol_info(&self) -> Vec<ProtocolInfo> {
        let mut infos = Vec::new();
        self.for_each_unique_dissector(|d| {
            infos.push(ProtocolInfo {
                name: d.name(),
                short_name: d.short_name(),
                layer: d.layer(),
                references: d.references(),
                fields: d.field_descriptors(),
            });
        });
        infos
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
            DissectorTable::SctpPpid(ppid) => self.register_by_sctp_ppid(ppid, dissector),
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
            DissectorTable::AchChannelType(ct) => self.register_by_ach_channel_type(ct, dissector),
            DissectorTable::Mtp3ServiceIndicator(si) => {
                self.register_by_mtp3_service_indicator(si, dissector)
            }
            DissectorTable::SccpSsn(ssn) => self.register_by_sccp_ssn(ssn, dissector),
            DissectorTable::Snap { oui, pid } => self.register_by_snap(oui, pid, dissector),
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
            DissectorTable::SctpPpid(ppid) => {
                self.register_by_sctp_ppid_or_replace(ppid, dissector)
            }
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
            DissectorTable::AchChannelType(ct) => {
                self.register_by_ach_channel_type_or_replace(ct, dissector)
            }
            DissectorTable::Mtp3ServiceIndicator(si) => {
                self.register_by_mtp3_service_indicator_or_replace(si, dissector)
            }
            DissectorTable::SccpSsn(ssn) => self.register_by_sccp_ssn_or_replace(ssn, dissector),
            DissectorTable::Snap { oui, pid } => {
                self.register_by_snap_or_replace(oui, pid, dissector)
            }
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

/// Specifications behind the versions the OSPF dispatcher routes to.
#[cfg(feature = "ospf")]
static OSPF_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2328",
        "OSPF Version 2",
        "https://www.rfc-editor.org/rfc/rfc2328",
    ),
    SpecReference::new(
        "RFC 5340",
        "OSPF for IPv6",
        "https://www.rfc-editor.org/rfc/rfc5340",
    ),
];

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

    fn references(&self) -> &'static [SpecReference] {
        OSPF_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
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
// ("PRI * HTTP/2.0") or an HTTP/2 frame header is detected, and keeps
// delegating for the rest of the connection; otherwise falls back to
// HTTP/1.1.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "http", feature = "http2"))]
struct HttpDispatcher {
    /// HTTP/2 dissector that tracks the connections whose client connection
    /// preface it has seen (HPACK dynamic tables, split header blocks).
    ///
    /// RFC 9113, Section 3.4 — the client connection preface is sent once,
    /// as "the first application data octets of a connection"
    /// (<https://www.rfc-editor.org/rfc/rfc9113#section-3.4>), so later
    /// segments of either direction are recognised by that tracking.
    #[cfg(feature = "http2")]
    http2: packet_dissector_http2::Http2ConnectionDissector,
}

#[cfg(any(feature = "http", feature = "http2"))]
impl HttpDispatcher {
    fn new() -> Self {
        Self {
            #[cfg(feature = "http2")]
            http2: packet_dissector_http2::Http2ConnectionDissector::new(),
        }
    }

    /// Whether `data` of the direction `stream` is HTTP/2.
    ///
    /// Only the client connection preface makes the connection (both
    /// directions) HTTP/2 for the following segments. A frame header
    /// recognised by [`is_http2_start`] alone is dissected as HTTP/2 but not
    /// remembered: an HTTP/1.1 body can start with octets that form a valid
    /// frame header, and remembering it would send the connection's later
    /// HTTP/1.1 messages to the HTTP/2 dissector.
    #[cfg(feature = "http2")]
    fn is_http2_stream(
        &self,
        data: &[u8],
        stream: &packet_dissector_core::dissector::TcpStreamContext,
    ) -> bool {
        self.http2.is_tracking(&stream.stream_key) || is_http2_start(data)
    }
}

/// Whether `data` starts like HTTP/2 without any knowledge of the connection:
/// with the client connection preface (RFC 9113, Section 3.4 —
/// <https://www.rfc-editor.org/rfc/rfc9113#section-3.4>) or with a frame
/// header (RFC 9113, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc9113#section-4.1>).
#[cfg(feature = "http2")]
fn is_http2_start(data: &[u8]) -> bool {
    data.starts_with(b"PRI * HTTP/2.0") || packet_dissector_http2::looks_like_frame_header(data)
}

/// Specifications behind both versions the HTTP dispatcher routes to.
#[cfg(all(feature = "http", feature = "http2"))]
static HTTP_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9110",
        "HTTP Semantics",
        "https://www.rfc-editor.org/rfc/rfc9110",
    ),
    SpecReference::new(
        "RFC 9112",
        "HTTP/1.1",
        "https://www.rfc-editor.org/rfc/rfc9112",
    ),
    SpecReference::new(
        "RFC 9113",
        "HTTP/2",
        "https://www.rfc-editor.org/rfc/rfc9113",
    ),
    SpecReference::new(
        "RFC 7541",
        "HPACK: Header Compression for HTTP/2",
        "https://www.rfc-editor.org/rfc/rfc7541",
    ),
];

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

    fn references(&self) -> &'static [SpecReference] {
        #[cfg(all(feature = "http", feature = "http2"))]
        {
            HTTP_REFERENCES
        }
        #[cfg(all(feature = "http", not(feature = "http2")))]
        {
            packet_dissector_http::HttpDissector.references()
        }
        #[cfg(not(feature = "http"))]
        {
            packet_dissector_http2::Http2Dissector.references()
        }
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        #[cfg(feature = "http2")]
        if is_http2_start(data) {
            return packet_dissector_http2::Http2Dissector.dissect(data, buf, offset);
        }
        dissect_http1(data, buf, offset)
    }

    fn dissect_tcp_stream<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
        stream: &packet_dissector_core::dissector::TcpStreamContext,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        #[cfg(feature = "http2")]
        if self.is_http2_stream(data, stream) {
            return self.http2.dissect_tcp_stream(data, buf, offset, stream);
        }
        #[cfg(not(feature = "http2"))]
        let _ = stream;
        dissect_http1(data, buf, offset)
    }

    fn release_tcp_stream(&self, stream_key: &packet_dissector_core::dissector::TcpStreamKey) {
        #[cfg(feature = "http2")]
        self.http2.release_tcp_stream(stream_key);
        #[cfg(not(feature = "http2"))]
        let _ = stream_key;
    }
}

/// Dissect `data` as HTTP/1.1, or fail when that dissector is disabled.
#[cfg(any(feature = "http", feature = "http2"))]
fn dissect_http1<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
    #[cfg(feature = "http")]
    {
        packet_dissector_http::HttpDissector.dissect(data, buf, offset)
    }
    #[cfg(not(feature = "http"))]
    {
        let _ = (data, buf, offset);
        Err(PacketError::InvalidHeader("HTTP/1.1 dissector not enabled"))
    }
}

// ---------------------------------------------------------------------------
// L2TP version dispatcher — delegates to L2TPv2 or L2TPv3 based on the
// version nibble in the flags/version word.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "l2tp", feature = "l2tpv3"))]
struct L2tpDispatcher;

/// Specifications behind both versions the L2TP dispatcher routes to.
#[cfg(all(feature = "l2tp", feature = "l2tpv3"))]
static L2TP_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2661",
        "Layer Two Tunneling Protocol \"L2TP\"",
        "https://www.rfc-editor.org/rfc/rfc2661",
    ),
    SpecReference::new(
        "RFC 3931",
        "Layer Two Tunneling Protocol - Version 3 (L2TPv3)",
        "https://www.rfc-editor.org/rfc/rfc3931",
    ),
    SpecReference::new(
        "RFC 5641",
        "Layer 2 Tunneling Protocol Version 3 (L2TPv3) Extended Circuit Status Values",
        "https://www.rfc-editor.org/rfc/rfc5641",
    ),
    SpecReference::new(
        "RFC 9601",
        "Propagating Explicit Congestion Notification across IP Tunnel Headers Separated by a Shim",
        "https://www.rfc-editor.org/rfc/rfc9601",
    ),
];

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

    fn references(&self) -> &'static [SpecReference] {
        #[cfg(all(feature = "l2tp", feature = "l2tpv3"))]
        {
            L2TP_REFERENCES
        }
        #[cfg(all(feature = "l2tp", not(feature = "l2tpv3")))]
        {
            packet_dissector_l2tp::L2tpDissector.references()
        }
        #[cfg(not(feature = "l2tp"))]
        {
            packet_dissector_l2tpv3::L2tpv3Dissector.references()
        }
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Tunnel)
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

// ---------------------------------------------------------------------------
// MPLS dispatcher — applies the MPLS label decode-as rules.
// ---------------------------------------------------------------------------

/// Decode-as rules keyed by bottom-of-stack MPLS label, shared between the
/// registry (which adds rules) and [`MplsDispatcher`] (which applies them).
///
/// `has_rules` lets the dispatcher skip the lock while no rule exists.
#[cfg(feature = "mpls")]
#[derive(Default)]
struct MplsLabelTable {
    rules: std::sync::Mutex<HashMap<u32, Box<dyn Dissector>>>,
    has_rules: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "mpls")]
impl MplsLabelTable {
    /// Lock the rules. A panic while the lock was held cannot leave the map
    /// half-updated, so a poisoned lock is recovered.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, Box<dyn Dissector>>> {
        self.rules
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// MPLS dissector that hands the payload after a bottom-of-stack label with
/// a decode-as rule to the rule's dissector.
///
/// The PW type is signalled out of band (RFC 4385, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc4385#section-3>), so without a rule
/// the MPLS dissector's own first-nibble heuristic applies.
#[cfg(feature = "mpls")]
struct MplsDispatcher {
    labels: std::sync::Arc<MplsLabelTable>,
}

#[cfg(feature = "mpls")]
impl Dissector for MplsDispatcher {
    fn name(&self) -> &'static str {
        packet_dissector_mpls::MplsDissector.name()
    }

    fn short_name(&self) -> &'static str {
        packet_dissector_mpls::MplsDissector.short_name()
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        packet_dissector_mpls::MplsDissector.field_descriptors()
    }

    fn references(&self) -> &'static [SpecReference] {
        packet_dissector_mpls::MplsDissector.references()
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        packet_dissector_mpls::MplsDissector.layer()
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        if !self.labels.has_rules.load(Ordering::Acquire) {
            return packet_dissector_mpls::MplsDissector.dissect(data, buf, offset);
        }
        let rules = self.labels.lock();
        packet_dissector_mpls::MplsDissector.dissect_with_payload_override(
            data,
            buf,
            offset,
            |label, payload, buf, payload_offset| {
                rules
                    .get(&label)
                    .map(|d| d.dissect(payload, buf, payload_offset))
            },
        )
    }
}

// ---------------------------------------------------------------------------
// UDP port 4500 dispatcher — RFC 3948 multiplexes UDP-encapsulated ESP, IKE
// (behind a Non-ESP marker) and NAT-keepalives onto a single port.
// ---------------------------------------------------------------------------

/// Routes UDP port 4500 traffic to ESP or IKE.
///
/// The ESP dissector is stateful (it owns a handle to the registry's shared
/// SA database), so this dispatcher holds an instance rather than being a
/// unit struct like the other dispatchers.
#[cfg(all(feature = "udp", feature = "esp"))]
struct UdpEncapDispatcher {
    esp: packet_dissector_esp::EspDissector,
}

#[cfg(all(feature = "udp", feature = "esp"))]
static UDP_ENCAP_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "RFC 3948",
    "UDP Encapsulation of IPsec ESP Packets",
    "https://www.rfc-editor.org/rfc/rfc3948",
)];

#[cfg(all(feature = "udp", feature = "esp"))]
impl Dissector for UdpEncapDispatcher {
    fn name(&self) -> &'static str {
        "UDP Encapsulation of IPsec ESP Packets"
    }

    fn short_name(&self) -> &'static str {
        "UDPENCAP"
    }

    /// Empty: this dispatcher never emits a layer of its own, it delegates to
    /// the ESP or IKE dissector, each of which is also registered under its
    /// own dispatch key and so already contributes its schema.
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn references(&self) -> &'static [SpecReference] {
        UDP_ENCAP_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Tunnel)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        use packet_dissector_core::dissector::DissectResult;

        // RFC 3948, Section 2.3 — "The sender MUST use a one-octet-long
        // payload with the value 0xFF."  A NAT-keepalive carries no protocol
        // payload, so dissection ends here.
        // <https://www.rfc-editor.org/rfc/rfc3948#section-2.3>
        const NAT_KEEPALIVE: [u8; 1] = [0xFF];
        if data == NAT_KEEPALIVE {
            return Ok(DissectResult::new(data.len(), DispatchHint::End));
        }

        // RFC 3948, Section 2.2 — "A Non-ESP Marker is 4 zero-valued bytes
        // aligning with the SPI field of an ESP packet."  Everything else is
        // UDP-encapsulated ESP, whose SPI "MUST NOT be a zero value"
        // (Section 2.1).
        // <https://www.rfc-editor.org/rfc/rfc3948#section-2.2>
        const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
        if data.len() >= NON_ESP_MARKER.len() && data[..NON_ESP_MARKER.len()] == NON_ESP_MARKER {
            // The IKE dissector skips the marker itself.
            #[cfg(feature = "ike")]
            return packet_dissector_ike::IkeDissector.dissect(data, buf, offset);
            #[cfg(not(feature = "ike"))]
            return Ok(DissectResult::new(data.len(), DispatchHint::End));
        }

        self.esp.dissect(data, buf, offset)
    }
}

// ---------------------------------------------------------------------------
// GTP-C version dispatcher — GTPv1-C and GTPv2-C share UDP port 2123 and are
// told apart by the version field in bits 8-6 of octet 1.
// ---------------------------------------------------------------------------

#[cfg(all(any(feature = "gtpv1c", feature = "gtpv2c"), feature = "udp"))]
struct GtpcDispatcher;

/// Specifications behind both versions the GTP-C dispatcher routes to.
#[cfg(all(feature = "gtpv1c", feature = "gtpv2c", feature = "udp"))]
static GTPC_REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 29.060",
        "General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP) across the Gn and \
         Gp interface",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.060/",
    ),
    SpecReference::new(
        "3GPP TS 29.274",
        "3GPP Evolved Packet System (EPS); Evolved General Packet Radio Service (GPRS) \
         Tunnelling Protocol for Control plane (GTPv2-C); Stage 3",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.274/",
    ),
];

#[cfg(all(any(feature = "gtpv1c", feature = "gtpv2c"), feature = "udp"))]
impl Dissector for GtpcDispatcher {
    fn name(&self) -> &'static str {
        "GPRS Tunnelling Protocol Control Plane"
    }

    fn short_name(&self) -> &'static str {
        "GTP-C"
    }

    /// Empty: this dispatcher never emits a layer of its own. The GTPv1-C
    /// and GTPv2-C schemas are exposed by
    /// [`DissectorRegistry::for_each_unique_dissector`].
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn references(&self) -> &'static [SpecReference] {
        #[cfg(all(feature = "gtpv1c", feature = "gtpv2c"))]
        {
            GTPC_REFERENCES
        }
        #[cfg(all(feature = "gtpv1c", not(feature = "gtpv2c")))]
        {
            packet_dissector_gtpv1c::Gtpv1cDissector.references()
        }
        #[cfg(not(feature = "gtpv1c"))]
        {
            packet_dissector_gtpv2c::Gtpv2cDissector.references()
        }
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<packet_dissector_core::dissector::DissectResult, PacketError> {
        let Some(&first) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };
        // 3GPP TS 29.060, Section 6 and TS 29.274, Section 5.1 — the
        // Version field is bits 8-6 of octet 1 in both headers; TS 29.060,
        // Section 11.1.1 covers a message "of an unsupported version".
        match first >> 5 {
            #[cfg(feature = "gtpv1c")]
            1 => packet_dissector_gtpv1c::Gtpv1cDissector.dissect(data, buf, offset),
            #[cfg(feature = "gtpv2c")]
            2 => packet_dissector_gtpv2c::Gtpv2cDissector.dissect(data, buf, offset),
            version => Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            }),
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
        {
            reg.set_entry_dissector(Box::new(packet_dissector_ethernet::EthernetDissector));
            // LINKTYPE_ETHERNET (1)
            assert_builtin(
                reg.register_by_link_type(
                    1,
                    Box::new(packet_dissector_ethernet::EthernetDissector),
                ),
            );
        }

        // LINKTYPE_NULL (0) and LINKTYPE_LOOP (108) — BSD loopback
        // https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
        // https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html
        #[cfg(feature = "null")]
        {
            assert_builtin(
                reg.register_by_link_type(0, Box::new(packet_dissector_null::NullDissector)),
            );
            assert_builtin(
                reg.register_by_link_type(108, Box::new(packet_dissector_null::LoopDissector)),
            );
        }

        // LINKTYPE_RAW (101), LINKTYPE_IPV4 (228), LINKTYPE_IPV6 (229) — no
        // link-layer header
        // https://www.tcpdump.org/linktypes/LINKTYPE_RAW.html
        #[cfg(feature = "raw_ip")]
        {
            assert_builtin(
                reg.register_by_link_type(101, Box::new(packet_dissector_raw_ip::RawIpDissector)),
            );
            assert_builtin(
                reg.register_by_link_type(228, Box::new(packet_dissector_raw_ip::RawIpv4Dissector)),
            );
            assert_builtin(
                reg.register_by_link_type(229, Box::new(packet_dissector_raw_ip::RawIpv6Dissector)),
            );
        }

        // LINKTYPE_IEEE802_11 (105) — IEEE 802.11 wireless LAN
        // https://www.tcpdump.org/linktypes.html
        #[cfg(feature = "ieee80211")]
        assert_builtin(reg.register_by_link_type(
            105,
            Box::new(packet_dissector_ieee80211::Ieee80211Dissector),
        ));

        // LINKTYPE_IEEE802_11_RADIOTAP (127) — radiotap header followed by
        // an 802.11 frame (dispatched through link type 105)
        // https://www.tcpdump.org/linktypes.html
        #[cfg(feature = "radiotap")]
        assert_builtin(
            reg.register_by_link_type(127, Box::new(packet_dissector_radiotap::RadiotapDissector)),
        );

        // Transparent Ethernet Bridging (0x6558) — used by tunneling
        // protocols (VXLAN, GRE) to encapsulate inner Ethernet frames.
        #[cfg(feature = "ethernet")]
        assert_builtin(reg.register_by_ethertype(
            0x6558,
            Box::new(packet_dissector_ethernet::EthernetDissector),
        ));

        // IEEE 802.1Q C-Tag (0x8100) and IEEE 802.1ad S-Tag (0x88A8) reached
        // by EtherType dispatch (e.g. SLL/SLL2 protocol type, GRE protocol
        // type); tags right after an Ethernet header are parsed inline by
        // the Ethernet dissector.
        // IEEE 802.1Q-2022, clause 9.6 — https://standards.ieee.org/ieee/802.1Q/10323/
        #[cfg(any(feature = "ethernet", feature = "linux_sll", feature = "linux_sll2"))]
        for tpid in [0x8100, 0x88A8] {
            assert_builtin(
                reg.register_by_ethertype(tpid, Box::new(packet_dissector_ethernet::VlanDissector)),
            );
        }
        // IP protocol 143 (Ethernet) — carries an Ethernet frame directly,
        // e.g. SRv6 L2 services (End.DX2 / End.DT2U / End.DT2M).
        // RFC 8986, Section 10.1 — https://www.rfc-editor.org/rfc/rfc8986#section-10.1
        #[cfg(feature = "ethernet")]
        assert_builtin(
            reg.register_by_ip_protocol(
                143,
                Box::new(packet_dissector_ethernet::EthernetDissector),
            ),
        );

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

        // IKE runs over UDP on port 500 (RFC 7296)
        #[cfg(feature = "ike")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(500, Box::new(packet_dissector_ike::IkeDissector)),
            );
            reg.register_dissector_factory("ike", || Box::new(packet_dissector_ike::IkeDissector));
        }

        // UDP port 4500 carries UDP-encapsulated ESP, IKE behind a Non-ESP
        // marker, and NAT-keepalives (RFC 3948).  Without ESP there is nothing
        // to multiplex, so IKE takes the port on its own.
        #[cfg(all(feature = "udp", feature = "esp"))]
        {
            #[cfg(feature = "esp-decrypt")]
            let esp = packet_dissector_esp::EspDissector::with_sa_db(reg.esp_sa_db.clone());
            #[cfg(not(feature = "esp-decrypt"))]
            let esp = packet_dissector_esp::EspDissector::new();

            assert_builtin(reg.register_by_udp_port(4500, Box::new(UdpEncapDispatcher { esp })));
        }
        #[cfg(all(feature = "udp", feature = "ike", not(feature = "esp")))]
        assert_builtin(
            reg.register_by_udp_port(4500, Box::new(packet_dissector_ike::IkeDissector)),
        );

        // STP/RSTP runs over IEEE 802.2 LLC with SAP 0x42 (IEEE 802.1D-2004)
        #[cfg(feature = "stp")]
        assert_builtin(reg.register_by_llc_sap(0x42, Box::new(packet_dissector_stp::StpDissector)));

        // SNAP follows an IEEE 802.2 LLC header with SAP 0xAA
        // (RFC 1042 — https://www.rfc-editor.org/rfc/rfc1042). Ethernet and
        // Linux cooked captures (protocol type 0x0004) both carry LLC.
        #[cfg(any(
            feature = "ethernet",
            feature = "linux_sll",
            feature = "linux_sll2",
            feature = "ieee80211"
        ))]
        assert_builtin(reg.register_by_llc_sap(
            packet_dissector_ethernet::llc::SAP_SNAP,
            Box::new(packet_dissector_ethernet::SnapDissector),
        ));

        // CDP runs over SNAP with the Cisco OUI 00-00-0C and PID 0x2000.
        #[cfg(feature = "cdp")]
        assert_builtin(reg.register_by_snap(
            packet_dissector_cdp::SNAP_OUI_CISCO,
            packet_dissector_cdp::SNAP_PID_CDP,
            Box::new(packet_dissector_cdp::CdpDissector),
        ));

        // IS-IS runs over IEEE 802.2 LLC with SAP 0xFE (ISO 10589)
        #[cfg(feature = "isis")]
        assert_builtin(
            reg.register_by_llc_sap(0xFE, Box::new(packet_dissector_isis::IsisDissector)),
        );

        #[cfg(feature = "arp")]
        {
            assert_builtin(
                reg.register_by_ethertype(0x0806, Box::new(packet_dissector_arp::ArpDissector)),
            );
            // RARP (0x8035) reuses the ARP packet format with opcodes 3/4.
            // RFC 903 — https://www.rfc-editor.org/rfc/rfc903
            assert_builtin(
                reg.register_by_ethertype(0x8035, Box::new(packet_dissector_arp::ArpDissector)),
            );
        }

        // EtherType 0x8809 — IEEE 802.3 Slow Protocols; the dispatcher selects
        // LACP, Marker, OAM or OSSP/ESMC by subtype (IEEE 802.3 Annex 57A)
        #[cfg(feature = "lacp")]
        assert_builtin(reg.register_by_ethertype(
            0x8809,
            Box::new(packet_dissector_lacp::SlowProtocolsDissector),
        ));

        // LLDP uses EtherType 0x88CC (IEEE 802.1AB)
        #[cfg(feature = "lldp")]
        assert_builtin(
            reg.register_by_ethertype(0x88CC, Box::new(packet_dissector_lldp::LldpDissector)),
        );

        // EAPOL uses EtherType 0x888E (IEEE 802.1X-2020, 11.3); the EAPOL
        // dissector hands an EAPOL-EAP body to EAP (RFC 3748) itself.
        #[cfg(feature = "eap")]
        assert_builtin(
            reg.register_by_ethertype(0x888E, Box::new(packet_dissector_eap::EapolDissector)),
        );

        // MPLS uses EtherType 0x8847 (unicast) and 0x8848 (upstream-assigned) (RFC 3032, RFC 5332).
        // The 0x8847 dispatcher applies the MPLS label decode-as rules.
        // Upstream-assigned labels come from a context-specific label space
        // (RFC 5331, Section 3 — https://www.rfc-editor.org/rfc/rfc5331#section-3),
        // so the rules, keyed by label value alone, do not apply to 0x8848.
        #[cfg(feature = "mpls")]
        {
            assert_builtin(reg.register_by_ethertype(
                0x8847,
                Box::new(MplsDispatcher {
                    labels: reg.mpls_labels.clone(),
                }),
            ));
            assert_builtin(
                reg.register_by_ethertype(0x8848, Box::new(packet_dissector_mpls::MplsDissector)),
            );
            // Decode-as names for MPLS label rules: an Ethernet PW without
            // and with the control word (RFC 4448, Section 4.6 —
            // https://www.rfc-editor.org/rfc/rfc4448#section-4.6).
            #[cfg(feature = "ethernet")]
            {
                reg.register_dissector_factory("pw-eth", || {
                    Box::new(packet_dissector_ethernet::EthernetDissector)
                });
                reg.register_dissector_factory("pw-eth-cw", || {
                    Box::new(packet_dissector_mpls::EthernetPwControlWordDissector)
                });
            }
        }

        // NSH uses EtherType 0x894F (RFC 8300, Section 10.1 —
        // https://www.rfc-editor.org/rfc/rfc8300#section-10.1), which also
        // covers GRE Protocol Type 0x894F and VXLAN-GPE Next Protocol 0x04.
        #[cfg(feature = "nsh")]
        assert_builtin(
            reg.register_by_ethertype(0x894F, Box::new(packet_dissector_nsh::NshDissector)),
        );

        // MPLS G-ACh / PW Associated Channel Types (IANA "MPLS Generalized
        // Associated Channel (G-ACh) Types" registry):
        // 0x0021 IPv4 and 0x0057 IPv6 (RFC 4385, Section 6 —
        // https://www.rfc-editor.org/rfc/rfc4385#section-6).
        #[cfg(all(feature = "mpls", feature = "ipv4"))]
        assert_builtin(
            reg.register_by_ach_channel_type(
                0x0021,
                Box::new(packet_dissector_ipv4::Ipv4Dissector),
            ),
        );
        #[cfg(all(feature = "mpls", feature = "ipv6"))]
        assert_builtin(
            reg.register_by_ach_channel_type(
                0x0057,
                Box::new(packet_dissector_ipv6::Ipv6Dissector),
            ),
        );
        // BFD Control without IP/UDP headers: 0x0007 (RFC 5885, Section 3.2 —
        // https://www.rfc-editor.org/rfc/rfc5885#section-3.2), S-BFD 0x0008
        // (RFC 7885, Section 2.3 — https://www.rfc-editor.org/rfc/rfc7885#section-2.3),
        // MPLS-TP CC 0x0022 and CV 0x0023 (RFC 6428, Section 3.3 —
        // https://www.rfc-editor.org/rfc/rfc6428#section-3.3).
        #[cfg(all(feature = "mpls", feature = "bfd"))]
        for channel_type in [0x0007, 0x0008, 0x0022, 0x0023] {
            assert_builtin(reg.register_by_ach_channel_type(
                channel_type,
                Box::new(packet_dissector_bfd::BfdDissector),
            ));
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

        // ERSPAN is carried in GRE with Protocol Type 0x88BE (Type I and II)
        // or 0x22EB (Type III) (draft-foschiano-erspan-03, Section 4 —
        // https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4).
        #[cfg(feature = "erspan")]
        {
            assert_builtin(
                reg.register_by_ethertype(
                    0x88BE,
                    Box::new(packet_dissector_erspan::ErspanDissector),
                ),
            );
            assert_builtin(reg.register_by_ethertype(
                0x22EB,
                Box::new(packet_dissector_erspan::ErspanType3Dissector),
            ));
        }

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

        // "All PIM control messages have IP protocol number 103." (RFC 7761,
        // Section 4.9 — https://www.rfc-editor.org/rfc/rfc7761#section-4.9)
        #[cfg(feature = "pim")]
        assert_builtin(
            reg.register_by_ip_protocol(103, Box::new(packet_dissector_pim::PimDissector)),
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

        // BFD Control runs over UDP on ports 3784 (single-hop, RFC 5881),
        // 4784 (multihop, RFC 5883), 6784 (Micro-BFD on LAG members,
        // RFC 7130, Section 2.2) and 7784 (S-BFD, RFC 7881, Section 2).
        // Port 3785 carries BFD Echo packets (RFC 5881, Section 4), whose
        // payload is a local matter (RFC 5880, Section 5) unless it uses the
        // Control format (RFC 9747, Section 2).
        //   <https://www.rfc-editor.org/rfc/rfc5881>
        //   <https://www.rfc-editor.org/rfc/rfc5883>
        //   <https://www.rfc-editor.org/rfc/rfc7130#section-2.2>
        //   <https://www.rfc-editor.org/rfc/rfc7881#section-2>
        //   <https://www.rfc-editor.org/rfc/rfc5881#section-4>
        //   <https://www.rfc-editor.org/rfc/rfc5880#section-5>
        //   <https://www.rfc-editor.org/rfc/rfc9747#section-2>
        #[cfg(feature = "bfd")]
        {
            #[cfg(feature = "udp")]
            {
                for port in [3784, 4784, 6784, 7784] {
                    assert_builtin(
                        reg.register_by_udp_port(
                            port,
                            Box::new(packet_dissector_bfd::BfdDissector),
                        ),
                    );
                }
                assert_builtin(
                    reg.register_by_udp_port(
                        3785,
                        Box::new(packet_dissector_bfd::BfdEchoDissector),
                    ),
                );
            }
            reg.register_dissector_factory("bfd", || Box::new(packet_dissector_bfd::BfdDissector));
            reg.register_dissector_factory("bfd.echo", || {
                Box::new(packet_dissector_bfd::BfdEchoDissector)
            });
        }

        // IPFIX runs over UDP, TCP and SCTP on port 4739. RFC 7011,
        // Section 10.1 — "By default, the Collecting Process listens for
        // connections on SCTP, TCP, and/or UDP port 4739."
        //   <https://www.rfc-editor.org/rfc/rfc7011#section-10.1>
        // NetFlow v5/v9 have no IANA-assigned port; "netflow" selects the
        // version-specific dissector by the version field for decode-as.
        #[cfg(feature = "ipfix")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(reg.register_by_udp_port(
                packet_dissector_ipfix::IPFIX_PORT,
                Box::new(packet_dissector_ipfix::IpfixDissector::new()),
            ));
            #[cfg(feature = "tcp")]
            assert_builtin(reg.register_by_tcp_port(
                packet_dissector_ipfix::IPFIX_PORT,
                Box::new(packet_dissector_ipfix::IpfixDissector::new()),
            ));
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_port(
                packet_dissector_ipfix::IPFIX_PORT,
                Box::new(packet_dissector_ipfix::IpfixDissector::new()),
            ));
            reg.register_dissector_factory("ipfix", || {
                Box::new(packet_dissector_ipfix::IpfixDissector::new())
            });
            reg.register_dissector_factory("netflow", || {
                Box::new(packet_dissector_ipfix::NetflowDissector::new())
            });
        }

        // SNMP runs over UDP on ports 161 (agent) and 162 (notifications).
        // RFC 3417, Section 3.2 — https://www.rfc-editor.org/rfc/rfc3417#section-3.2
        #[cfg(feature = "snmp")]
        {
            #[cfg(feature = "udp")]
            for port in [
                packet_dissector_snmp::SNMP_PORT,
                packet_dissector_snmp::SNMP_TRAP_PORT,
            ] {
                assert_builtin(
                    reg.register_by_udp_port(port, Box::new(packet_dissector_snmp::SnmpDissector)),
                );
            }
            reg.register_dissector_factory("snmp", || {
                Box::new(packet_dissector_snmp::SnmpDissector)
            });
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
        // Uses HttpDispatcher to auto-detect HTTP/2 connections.
        #[cfg(any(feature = "http", feature = "http2"))]
        {
            #[cfg(feature = "tcp")]
            assert_builtin(reg.register_by_tcp_port(80, Box::new(HttpDispatcher::new())));
        }
        #[cfg(feature = "http")]
        reg.register_dissector_factory("http", || Box::new(packet_dissector_http::HttpDissector));
        #[cfg(feature = "http2")]
        reg.register_dissector_factory("http2", || {
            Box::new(packet_dissector_http2::Http2ConnectionDissector::new())
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

        // GTPv1-C (3GPP TS 29.060, Section 10.1.1.1) and GTPv2-C (3GPP
        // TS 29.274) share UDP port 2123; GtpcDispatcher picks by version.
        #[cfg(all(any(feature = "gtpv1c", feature = "gtpv2c"), feature = "udp"))]
        assert_builtin(reg.register_by_udp_port(2123, Box::new(GtpcDispatcher)));
        #[cfg(feature = "gtpv1c")]
        reg.register_dissector_factory("gtpv1c", || {
            Box::new(packet_dissector_gtpv1c::Gtpv1cDissector)
        });
        #[cfg(feature = "gtpv2c")]
        {
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
            // RFC 3261, Section 18.3 — body framing differs between UDP and
            // stream transports, so UDP gets the datagram variant.
            // https://www.rfc-editor.org/rfc/rfc3261#section-18.3
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(
                    5060,
                    Box::new(packet_dissector_sip::SipDatagramDissector),
                ),
            );

            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(5060, Box::new(packet_dissector_sip::SipDissector)),
            );

            // RFC 3261, Section 18.1.1 — the default port "is 5060 for UDP,
            // TCP and SCTP". SCTP preserves message boundaries (RFC 4168,
            // Section 3.2), so each DATA chunk is framed like a datagram.
            // https://www.rfc-editor.org/rfc/rfc3261#section-18.1.1
            // https://www.rfc-editor.org/rfc/rfc4168#section-3.2
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_port(
                    5060,
                    Box::new(packet_dissector_sip::SipDatagramDissector),
                ),
            );

            reg.register_dissector_factory("sip", || Box::new(packet_dissector_sip::SipDissector));
            reg.register_dissector_factory("sip.udp", || {
                Box::new(packet_dissector_sip::SipDatagramDissector)
            });
        }

        // SDP is carried as a message body, dispatched by MIME content type
        // from SIP (RFC 3261, Section 7.4 —
        // https://www.rfc-editor.org/rfc/rfc3261#section-7.4) and HTTP.
        // RFC 8866 — https://www.rfc-editor.org/rfc/rfc8866
        //
        // Note: unlike Wireshark, SDP does not set up RTP conversations from
        // m=/a=rtpmap lines — the registry is immutable during dissection,
        // so RTP remains decode-as only (`register_dissector_factory("rtp")`).
        #[cfg(feature = "sdp")]
        {
            assert_builtin(reg.register_by_content_type(
                "application/sdp",
                Box::new(packet_dissector_sdp::SdpDissector),
            ));
            reg.register_dissector_factory("sdp", || Box::new(packet_dissector_sdp::SdpDissector));
        }

        // RADIUS runs over UDP on ports 1812 (auth) and 1813 (accounting)
        // (RFC 2865, Section 3 / RFC 2866, Section 3), plus:
        // - 3799: RFC 5176, Section 2.3 — "For either Disconnect-Request or
        //   CoA-Request packets UDP port 3799 is used as the destination port."
        //   https://www.rfc-editor.org/rfc/rfc5176#section-2.3
        // - 1645 / 1646: RFC 2865, Section 3 — "The early deployment of
        //   RADIUS was done using UDP port number 1645"; RFC 2866, Section 3
        //   — "The early deployment of RADIUS Accounting was done using UDP
        //   port number 1646".
        //   https://www.rfc-editor.org/rfc/rfc2865#section-3
        //   https://www.rfc-editor.org/rfc/rfc2866#section-3
        #[cfg(feature = "radius")]
        {
            #[cfg(feature = "udp")]
            for port in [1812, 1813, 3799, 1645, 1646] {
                assert_builtin(reg.register_by_udp_port(
                    port,
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
            // IANA "SCTP Payload Protocol Identifiers": 46 = Diameter in a
            // SCTP DATA chunk —
            // https://www.iana.org/assignments/sctp-parameters/
            // RFC 6733, Section 2.1.1 — https://www.rfc-editor.org/rfc/rfc6733#section-2.1.1
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_ppid(
                    46,
                    Box::new(packet_dissector_diameter::DiameterDissector),
                ),
            );
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
            // IANA "SCTP Payload Protocol Identifiers": 60 = NGAP
            // (3GPP TS 38.413) —
            // https://www.iana.org/assignments/sctp-parameters/
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_ppid(60, Box::new(packet_dissector_ngap::NgapDissector)),
            );
            reg.register_dissector_factory("ngap", || {
                Box::new(packet_dissector_ngap::NgapDissector)
            });
        }

        // XnAP runs over SCTP (3GPP TS 38.423). IANA "Service Name and Transport
        // Protocol Port Number Registry": 38422 `xn-control`; IANA "SCTP Payload
        // Protocol Identifiers": 61 = XnAP —
        // https://www.iana.org/assignments/service-names-port-numbers/
        // https://www.iana.org/assignments/sctp-parameters/
        #[cfg(feature = "xnap")]
        {
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_port(
                packet_dissector_xnap::SCTP_PORT,
                Box::new(packet_dissector_xnap::XnapDissector),
            ));
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_ppid(
                packet_dissector_xnap::SCTP_PPID,
                Box::new(packet_dissector_xnap::XnapDissector),
            ));
            reg.register_dissector_factory("xnap", || {
                Box::new(packet_dissector_xnap::XnapDissector)
            });
        }

        // F1AP runs over SCTP (3GPP TS 38.473). IANA "Service Name and Transport
        // Protocol Port Number Registry": 38472 `f1-control`; IANA "SCTP Payload
        // Protocol Identifiers": 62 = F1AP —
        // https://www.iana.org/assignments/service-names-port-numbers/
        // https://www.iana.org/assignments/sctp-parameters/
        #[cfg(feature = "f1ap")]
        {
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_port(
                packet_dissector_f1ap::SCTP_PORT,
                Box::new(packet_dissector_f1ap::F1apDissector),
            ));
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_ppid(
                packet_dissector_f1ap::SCTP_PPID,
                Box::new(packet_dissector_f1ap::F1apDissector),
            ));
            reg.register_dissector_factory("f1ap", || {
                Box::new(packet_dissector_f1ap::F1apDissector)
            });
        }

        // E1AP runs over SCTP (3GPP TS 37.483). IANA "Service Name and Transport
        // Protocol Port Number Registry": 38462 `e1-interface`; IANA "SCTP Payload
        // Protocol Identifiers": 64 = E1AP —
        // https://www.iana.org/assignments/service-names-port-numbers/
        // https://www.iana.org/assignments/sctp-parameters/
        #[cfg(feature = "e1ap")]
        {
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_port(
                packet_dissector_e1ap::SCTP_PORT,
                Box::new(packet_dissector_e1ap::E1apDissector),
            ));
            #[cfg(feature = "sctp")]
            assert_builtin(reg.register_by_sctp_ppid(
                packet_dissector_e1ap::SCTP_PPID,
                Box::new(packet_dissector_e1ap::E1apDissector),
            ));
            reg.register_dissector_factory("e1ap", || {
                Box::new(packet_dissector_e1ap::E1apDissector)
            });
        }

        // SGsAP runs over SCTP on the registered port 29118 (3GPP TS 29.118,
        // Section 6.3). Its payload protocol identifier is 0 ("unspecified"),
        // which cannot identify it, so only the port is registered.
        #[cfg(feature = "sgsap")]
        {
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_port(29118, Box::new(packet_dissector_sgsap::SgsapDissector)),
            );
            reg.register_dissector_factory("sgsap", || {
                Box::new(packet_dissector_sgsap::SgsapDissector)
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

        // M3UA runs over SCTP: PPID 3 and port 2905 (RFC 4666, Sections 7.1
        // and 7.2 — https://www.rfc-editor.org/rfc/rfc4666#section-7.1).
        #[cfg(feature = "m3ua")]
        {
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_port(2905, Box::new(packet_dissector_m3ua::M3uaDissector)),
            );
            #[cfg(feature = "sctp")]
            assert_builtin(
                reg.register_by_sctp_ppid(3, Box::new(packet_dissector_m3ua::M3uaDissector)),
            );
            reg.register_dissector_factory("m3ua", || {
                Box::new(packet_dissector_m3ua::M3uaDissector)
            });
        }

        // SCCP is the MTP3-User with Service Indicator 3 (ITU-T Q.704,
        // clause 14.2.1 — https://www.itu.int/rec/T-REC-Q.704).
        #[cfg(feature = "sccp")]
        {
            assert_builtin(reg.register_by_mtp3_service_indicator(
                3,
                Box::new(packet_dissector_sccp::SccpDissector),
            ));
            reg.register_dissector_factory("sccp", || {
                Box::new(packet_dissector_sccp::SccpDissector)
            });
        }
        // EPS NAS is carried inside S1AP; register as a factory for
        // standalone use (e.g., `bask read --dissector nas-eps`).
        #[cfg(feature = "nas-eps")]
        reg.register_dissector_factory("nas-eps", || {
            Box::new(packet_dissector_nas_eps::NasEpsDissector)
        });

        // TCAP is the SCCP user for the MAP subsystems — ITU-T Q.713, clause
        // 3.4.2.2 (5 = MAP) and 3GPP TS 23.003, clauses 8.1 (6 HLR, 7 VLR,
        // 8 MSC, 9 EIR) and 8.2 (145 GMLC, 147 gsmSCF, 148 SIWF, 149 SGSN,
        // 150 GGSN, 248 CSS). The MAP dissector decodes TCAP itself, so it
        // takes these SSNs when enabled. CAP (146) is TCAP-based as well.
        // https://www.itu.int/rec/T-REC-Q.713
        // https://www.3gpp.org/ftp/Specs/archive/23_series/23.003/
        #[cfg(feature = "tcap")]
        {
            const MAP_SSNS: [u8; 11] = [5, 6, 7, 8, 9, 145, 147, 148, 149, 150, 248];
            for ssn in MAP_SSNS {
                #[cfg(feature = "map")]
                assert_builtin(
                    reg.register_by_sccp_ssn(ssn, Box::new(packet_dissector_map::MapDissector)),
                );
                #[cfg(not(feature = "map"))]
                assert_builtin(
                    reg.register_by_sccp_ssn(ssn, Box::new(packet_dissector_tcap::TcapDissector)),
                );
            }
            assert_builtin(
                reg.register_by_sccp_ssn(146, Box::new(packet_dissector_tcap::TcapDissector)),
            );
            reg.register_dissector_factory("tcap", || {
                Box::new(packet_dissector_tcap::TcapDissector)
            });
            #[cfg(feature = "map")]
            reg.register_dissector_factory("map", || Box::new(packet_dissector_map::MapDissector));
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

        // BMP has no assigned port: "The passive party is configured to
        // listen on a particular TCP port" (RFC 7854, Section 3.2 —
        // https://www.rfc-editor.org/rfc/rfc7854#section-3.2), so it is only
        // available by decode-as name.
        #[cfg(feature = "bmp")]
        reg.register_dissector_factory("bmp", || Box::new(packet_dissector_bmp::BmpDissector));

        // Register TLS for the common HTTPS port 443 (RFC 5246, RFC 8446)
        // and for the ports whose assigned service runs over implicit TLS
        // (the TLS handshake is the first data exchanged on the connection):
        // - 465 submissions, 993 imaps, 995 pop3s: RFC 8314, Sections 7.1–7.3
        //   https://www.rfc-editor.org/rfc/rfc8314#section-7
        // - 636 ldaps, 990 ftps: IANA Service Name and Transport Protocol
        //   Port Number Registry
        //   https://www.iana.org/assignments/service-names-port-numbers/
        // - 853 domain-s (DNS over TLS): RFC 7858, Section 3.1
        //   https://www.rfc-editor.org/rfc/rfc7858#section-3.1
        // - 2083 radsec: RFC 6614, Section 2.1
        //   https://www.rfc-editor.org/rfc/rfc6614#section-2.1
        // - 5061 sips: RFC 3261, Section 18.2.1
        //   https://www.rfc-editor.org/rfc/rfc3261#section-18.2.1
        // - 5349 stuns: RFC 8489, Section 18.6
        //   https://www.rfc-editor.org/rfc/rfc8489#section-18.6
        // - 6697 ircs-u: RFC 7194, Section 4
        //   https://www.rfc-editor.org/rfc/rfc7194#section-4
        #[cfg(feature = "tls")]
        {
            #[cfg(feature = "tcp")]
            for port in [443, 465, 636, 853, 990, 993, 995, 2083, 5061, 5349, 6697] {
                assert_builtin(
                    reg.register_by_tcp_port(port, Box::new(packet_dissector_tls::TlsDissector)),
                );
            }
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
            // VXLAN-GPE runs over UDP port 4790 (draft-ietf-nvo3-vxlan-gpe-13,
            // Section 11.1 — https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-13#section-11.1)
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(4790, Box::new(packet_dissector_vxlan::VxlanGpeDissector)),
            );
            reg.register_dissector_factory("vxlan-gpe", || {
                Box::new(packet_dissector_vxlan::VxlanGpeDissector)
            });
        }

        // L2TP port 1701 registration is handled by L2tpDispatcher above.

        // PPP — registered by link type and EtherType
        // LINKTYPE_PPP (9), LINKTYPE_PPP_HDLC (50 — HDLC-like framing),
        // EtherType 0x880B (GRE-encapsulated PPP)
        // https://www.tcpdump.org/linktypes/LINKTYPE_PPP_HDLC.html
        // RFC 1662, Section 3.1 — https://www.rfc-editor.org/rfc/rfc1662#section-3.1
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

        // PPPoE — EtherType 0x8863 (Discovery) and 0x8864 (Session)
        // (RFC 2516, Section 4 — https://www.rfc-editor.org/rfc/rfc2516#section-4),
        // and LINKTYPE_PPP_ETHER (51), where the packet begins with the PPPoE
        // header (https://www.tcpdump.org/linktypes.html).
        #[cfg(feature = "pppoe")]
        {
            assert_builtin(reg.register_by_ethertype(
                0x8863,
                Box::new(packet_dissector_pppoe::PppoeDiscoveryDissector),
            ));
            assert_builtin(reg.register_by_ethertype(
                0x8864,
                Box::new(packet_dissector_pppoe::PppoeSessionDissector),
            ));
            assert_builtin(
                reg.register_by_link_type(51, Box::new(packet_dissector_pppoe::PppoeDissector)),
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

        // STUN runs over UDP and TCP on port 3478 (RFC 8489), shared with
        // TURN ChannelData (RFC 8656), whose framing differs on TCP.
        #[cfg(feature = "stun")]
        {
            #[cfg(feature = "udp")]
            assert_builtin(
                reg.register_by_udp_port(3478, Box::new(packet_dissector_stun::StunDissector)),
            );
            #[cfg(feature = "tcp")]
            assert_builtin(
                reg.register_by_tcp_port(3478, Box::new(packet_dissector_stun::StunTcpDissector)),
            );
            reg.register_dissector_factory("stun", || {
                Box::new(packet_dissector_stun::StunDissector)
            });
            // Stream framing for decode-as on other TCP ports (RFC 8656,
            // Section 12.5 — https://www.rfc-editor.org/rfc/rfc8656#section-12.5).
            reg.register_dissector_factory("stun.tcp", || {
                Box::new(packet_dissector_stun::StunTcpDissector)
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

    static MSG_FIELD: FieldDescriptor =
        FieldDescriptor::new("id", "Id", packet_dissector_core::field::FieldType::U8);

    /// Entry dissector that splits its input into 2-byte messages after a
    /// 2-byte header and records each one as an embedded payload, like
    /// bundled SCTP DATA chunks.
    struct BundleDissector;

    impl Dissector for BundleDissector {
        fn name(&self) -> &'static str {
            "Bundle"
        }
        fn short_name(&self) -> &'static str {
            "Bundle"
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.begin_layer("Bundle", None, &[], offset..offset + data.len());
            buf.end_layer();
            let mut pos = 2;
            while pos + 2 <= data.len() {
                buf.push_embedded_payload(
                    offset + pos..offset + pos + 2,
                    DispatchHint::ByLlcSap(0x42),
                );
                pos += 2;
            }
            Ok(DissectResult::new(data.len(), DispatchHint::End))
        }
    }

    /// Message dissector that fails after pushing a partial layer when the
    /// first byte is `0xFF`.
    struct MsgDissector;

    impl Dissector for MsgDissector {
        fn name(&self) -> &'static str {
            "Msg"
        }
        fn short_name(&self) -> &'static str {
            "Msg"
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.begin_layer("Msg", None, &[], offset..offset + data.len());
            buf.push_field(&MSG_FIELD, FieldValue::U8(data[0]), offset..offset + 1);
            if data[0] == 0xFF {
                return Err(PacketError::InvalidHeader("bad message"));
            }
            buf.end_layer();
            Ok(DissectResult::new(data.len(), DispatchHint::End))
        }
    }

    /// One-octet entry layer that hands the rest to LLC SAP 0x20.
    struct PrefixDissector;

    impl Dissector for PrefixDissector {
        fn name(&self) -> &'static str {
            "Prefix"
        }
        fn short_name(&self) -> &'static str {
            "Prefix"
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            _data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.begin_layer("Prefix", None, &[], offset..offset + 1);
            buf.end_layer();
            Ok(DissectResult::new(1, DispatchHint::ByLlcSap(0x20)))
        }
    }

    /// Dissector whose first octet is the length of an embedded payload that
    /// follows it; trailing octets after the payload belong to this layer
    /// (like M3UA's Protocol Data followed by a Correlation Id).
    struct WrapDissector(&'static str, u8);

    impl Dissector for WrapDissector {
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
            data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.begin_layer(self.0, None, &[], offset..offset + data.len());
            buf.end_layer();
            let len = usize::from(data[0]);
            Ok(DissectResult::with_embedded_payload(
                data.len(),
                DispatchHint::ByLlcSap(self.1),
                offset + 1..offset + 1 + len,
            ))
        }
    }

    /// An embedded payload inside an embedded payload is dispatched to its
    /// own range, not to the octets after the enclosing layer.
    #[test]
    fn nested_embedded_payload_ranges() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(PrefixDissector));
        reg.register_by_llc_sap(0x20, Box::new(WrapDissector("Outer", 0x10)))
            .unwrap();
        reg.register_by_llc_sap(0x10, Box::new(WrapDissector("Inner", 0x42)))
            .unwrap();
        reg.register_by_llc_sap(0x42, Box::new(MsgDissector))
            .unwrap();
        // Prefix, then Outer: payload [2, AA, BB] and trailer EE; Inner:
        // payload [AA, BB].
        let data = [0x00, 0x03, 0x02, 0xAA, 0xBB, 0xEE];
        let mut buf = DissectBuffer::new();
        reg.dissect(&data, &mut buf).unwrap();
        let layers: Vec<_> = buf
            .layers()
            .iter()
            .map(|l| (l.name, l.range.clone()))
            .collect();
        assert_eq!(
            layers,
            [
                ("Prefix", 0..1),
                ("Outer", 1..6),
                ("Inner", 2..5),
                ("Msg", 3..5)
            ]
        );
        assert_eq!(PrefixDissector.name(), "Prefix");
        assert!(PrefixDissector.field_descriptors().is_empty());
        assert!(WrapDissector("W", 0).field_descriptors().is_empty());
        assert_eq!(WrapDissector("W", 0).name(), "W");
    }

    fn bundle_registry() -> DissectorRegistry {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(BundleDissector));
        reg.register_by_llc_sap(0x42, Box::new(MsgDissector))
            .unwrap();
        reg
    }

    #[test]
    fn embedded_payloads_each_dispatched() {
        let reg = bundle_registry();
        let data = [0x00, 0x00, 0x01, 0xAA, 0x02, 0xBB, 0x03, 0xCC];
        let mut buf = DissectBuffer::new();
        reg.dissect(&data, &mut buf).unwrap();

        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["Bundle", "Msg", "Msg", "Msg"]);
        assert_eq!(buf.layers()[2].range, 4..6);
        assert!(buf.embedded_payloads().is_empty());
    }

    #[test]
    fn embedded_payload_error_does_not_stop_other_payloads() {
        let reg = bundle_registry();
        // Second message fails after pushing a layer and a field.
        let data = [0x00, 0x00, 0x01, 0xAA, 0xFF, 0xBB, 0x03, 0xCC];
        let mut buf = DissectBuffer::new();
        let err = reg.dissect(&data, &mut buf).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader("bad message")));

        // The failed message keeps what it parsed before the error, and the
        // third message is still dissected.
        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["Bundle", "Msg", "Msg", "Msg"]);
        assert_eq!(buf.layers()[2].range, 4..6);
        assert_eq!(buf.layers()[3].range, 6..8);
        let third = &buf.layers()[3];
        assert_eq!(
            buf.field_by_name(third, "id").unwrap().value,
            FieldValue::U8(0x03)
        );
        assert!(buf.embedded_payloads().is_empty());
    }

    /// Consumes nothing and hands off to LLC SAP `self.0`, like a thin
    /// dispatcher.
    struct ZeroStep(u8);

    impl Dissector for ZeroStep {
        fn name(&self) -> &'static str {
            "ZeroStep"
        }
        fn short_name(&self) -> &'static str {
            "ZeroStep"
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
            Ok(DissectResult::new(0, DispatchHint::ByLlcSap(self.0)))
        }
    }

    /// Records one payload and consumes nothing.
    struct RecordThenStall;

    impl Dissector for RecordThenStall {
        fn name(&self) -> &'static str {
            "RecordThenStall"
        }
        fn short_name(&self) -> &'static str {
            "RecordThenStall"
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            _data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.push_embedded_payload(offset..offset + 1, DispatchHint::End);
            Ok(DissectResult::new(0, DispatchHint::ByLlcSap(0x43)))
        }
    }

    #[test]
    fn stalled_dispatch_drops_recorded_payloads() {
        // Entry → 0x43 (zero progress) → 0x44 records a payload with zero
        // progress again, so the stall guard ends the loop.
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(ZeroStep(0x43)));
        reg.register_by_llc_sap(0x43, Box::new(ZeroStep(0x44)))
            .unwrap();
        reg.register_by_llc_sap(0x44, Box::new(RecordThenStall))
            .unwrap();
        let data = [0x00, 0x01];
        let mut buf = DissectBuffer::new();
        reg.dissect(&data, &mut buf).unwrap();
        assert!(buf.embedded_payloads().is_empty());
    }

    struct FailingRecorder;

    impl Dissector for FailingRecorder {
        fn name(&self) -> &'static str {
            "FailingRecorder"
        }
        fn short_name(&self) -> &'static str {
            "FailingRecorder"
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            _data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.push_embedded_payload(offset..offset + 1, DispatchHint::End);
            Err(PacketError::InvalidHeader("recorder failed"))
        }
    }

    #[test]
    fn failing_dissector_drops_recorded_payloads() {
        // Entry dissector fails after recording a payload.
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(FailingRecorder));
        let data = [0x00, 0x01];
        let mut buf = DissectBuffer::new();
        assert!(reg.dissect(&data, &mut buf).is_err());
        assert!(buf.embedded_payloads().is_empty());

        // Same dissector reached through the dispatch loop.
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(ZeroStep(0x43)));
        reg.register_by_llc_sap(0x43, Box::new(FailingRecorder))
            .unwrap();
        let mut buf = DissectBuffer::new();
        assert!(reg.dissect(&data, &mut buf).is_err());
        assert!(buf.embedded_payloads().is_empty());
    }

    /// Records a payload that starts past the end of its input.
    struct OutOfRangeRecorder;

    impl Dissector for OutOfRangeRecorder {
        fn name(&self) -> &'static str {
            "OutOfRangeRecorder"
        }
        fn short_name(&self) -> &'static str {
            "OutOfRangeRecorder"
        }
        fn field_descriptors(&self) -> &'static [FieldDescriptor] {
            &[]
        }
        fn dissect<'pkt>(
            &self,
            data: &'pkt [u8],
            buf: &mut DissectBuffer<'pkt>,
            offset: usize,
        ) -> Result<DissectResult, packet_dissector_core::error::PacketError> {
            buf.begin_layer("OutOfRangeRecorder", None, &[], offset..offset + data.len());
            buf.end_layer();
            let past_end = offset + data.len();
            buf.push_embedded_payload(past_end..past_end + 4, DispatchHint::ByLlcSap(0x42));
            Ok(DissectResult::new(data.len(), DispatchHint::End))
        }
    }

    #[test]
    fn embedded_payload_past_input_end_is_skipped() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(OutOfRangeRecorder));
        reg.register_by_llc_sap(0x42, Box::new(MsgDissector))
            .unwrap();
        let data = [0x00, 0x01];
        let mut buf = DissectBuffer::new();
        reg.dissect(&data, &mut buf).unwrap();
        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["OutOfRangeRecorder"]);
        assert!(buf.embedded_payloads().is_empty());
    }

    #[test]
    fn embedded_payload_test_dissectors_metadata() {
        let dissectors: [&dyn Dissector; 6] = [
            &BundleDissector,
            &MsgDissector,
            &ZeroStep(0x43),
            &RecordThenStall,
            &FailingRecorder,
            &OutOfRangeRecorder,
        ];
        for d in dissectors {
            assert_eq!(d.name(), d.short_name());
            assert!(d.field_descriptors().is_empty());
        }
    }

    #[test]
    fn summary_stop_drops_recorded_payloads() {
        // A stop on the entry dissector's hint drops its recorded payloads.
        let mut reg = bundle_registry();
        reg.register_by_llc_sap_or_replace(0x42, Box::new(MsgDissector));
        let data = [0x00, 0x00, 0x01, 0xAA];
        let mut buf = DissectBuffer::new();
        reg.dissect_from_entry(&BundleDissector, &data, &mut buf, &mut |_, _| true, false)
            .unwrap();
        assert_eq!(buf.layers().len(), 1);
        assert!(buf.embedded_payloads().is_empty());
    }

    #[test]
    fn embedded_payload_without_dissector_is_skipped() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(BundleDissector));
        let data = [0x00, 0x00, 0x01, 0xAA];
        let mut buf = DissectBuffer::new();
        reg.dissect(&data, &mut buf).unwrap();
        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["Bundle"]);
        assert!(buf.embedded_payloads().is_empty());
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
        #[cfg(feature = "bmp")]
        assert!(reg.create_dissector_by_name("bmp").is_some());
        #[cfg(feature = "sip")]
        assert!(reg.create_dissector_by_name("sip").is_some());
        #[cfg(feature = "sip")]
        assert!(reg.create_dissector_by_name("sip.udp").is_some());
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
    fn get_by_ach_channel_type_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_ach_channel_type(0x0007).is_none());
    }

    #[test]
    fn duplicate_ach_channel_type_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_ach_channel_type(0x0007, Box::new(StubDissector("bfd")))
            .unwrap();
        let result = reg.register_by_ach_channel_type(0x0007, Box::new(StubDissector("bfd-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "ach_channel_type",
                key: 0x0007,
                ..
            })
        ));
    }

    #[test]
    fn register_by_ach_channel_type_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_ach_channel_type_or_replace(0x0021, Box::new(StubDissector("a")))
                .is_none()
        );
        let prev =
            reg.register_by_ach_channel_type_or_replace(0x0021, Box::new(StubDissector("b")));
        assert_eq!(prev.map(|d| d.short_name()), Some("a"));
        assert_eq!(
            reg.get_by_ach_channel_type(0x0021).map(|d| d.short_name()),
            Some("b")
        );
    }

    #[test]
    fn register_dissector_dispatches_to_ach_channel_type() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::AchChannelType(0x0022),
            Box::new(StubDissector("bfd")),
        )
        .unwrap();
        assert!(reg.get_by_ach_channel_type(0x0022).is_some());
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::AchChannelType(0x0022),
                Box::new(StubDissector("bfd2")),
            )
            .is_some()
        );
        assert!(
            reg.all_field_schemas()
                .iter()
                .any(|schema| schema.short_name == "bfd2")
        );
    }

    /// The ACH and PW control word layers emitted by the MPLS dissector
    /// appear in the field schemas.
    #[cfg(feature = "mpls")]
    #[test]
    fn all_field_schemas_include_ach_and_pw_control_word() {
        let reg = DissectorRegistry::default();
        let schemas = reg.all_field_schemas();
        for name in ["ACH", "PW-CW"] {
            assert!(
                schemas.iter().any(|s| s.short_name == name),
                "{name} missing from all_field_schemas"
            );
        }
    }

    #[cfg(feature = "ipfix")]
    #[test]
    fn all_field_schemas_include_netflow_versions() {
        let reg = DissectorRegistry::default();
        let schemas = reg.all_field_schemas();
        for name in ["IPFIX", "NetFlow-v9", "NetFlow-v5"] {
            assert!(
                schemas.iter().any(|s| s.short_name == name),
                "{name} missing from all_field_schemas"
            );
        }
        let names = reg.available_decode_as_protocols();
        assert!(names.contains(&"ipfix"));
        assert!(names.contains(&"netflow"));
    }

    #[test]
    fn lookup_dissector_by_ach_channel_type_hint() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_ach_channel_type(0x0007, Box::new(StubDissector("bfd")))
            .unwrap();
        assert_eq!(
            reg.lookup_dissector(&DispatchHint::ByAchChannelType(0x0007))
                .map(|d| d.short_name()),
            Some("bfd")
        );
        assert!(
            reg.lookup_dissector(&DispatchHint::ByAchChannelType(0x0008))
                .is_none()
        );
    }

    #[test]
    fn mtp3_service_indicator_table() {
        let mut reg = DissectorRegistry::new();
        assert!(reg.get_by_mtp3_service_indicator(3).is_none());
        reg.register_by_mtp3_service_indicator(3, Box::new(StubDissector("sccp")))
            .unwrap();
        let dup = reg.register_by_mtp3_service_indicator(3, Box::new(StubDissector("dup")));
        assert!(matches!(
            dup,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "mtp3_service_indicator",
                key: 3,
                ..
            })
        ));
        assert_eq!(
            reg.lookup_dissector(&DispatchHint::ByMtp3ServiceIndicator(3))
                .map(|d| d.short_name()),
            Some("sccp")
        );
        assert!(
            reg.lookup_dissector(&DispatchHint::ByMtp3ServiceIndicator(5))
                .is_none()
        );
        let prev =
            reg.register_by_mtp3_service_indicator_or_replace(3, Box::new(StubDissector("b")));
        assert_eq!(prev.map(|d| d.short_name()), Some("sccp"));
        assert!(
            reg.register_dissector(
                DissectorTable::Mtp3ServiceIndicator(5),
                Box::new(StubDissector("isup")),
            )
            .is_ok()
        );
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::Mtp3ServiceIndicator(5),
                Box::new(StubDissector("isup2")),
            )
            .is_some()
        );
        let names: Vec<_> = reg
            .all_field_schemas()
            .iter()
            .map(|s| s.short_name)
            .collect();
        assert!(names.contains(&"b") && names.contains(&"isup2"));
    }

    #[test]
    fn sccp_ssn_table() {
        let mut reg = DissectorRegistry::new();
        assert!(reg.get_by_sccp_ssn(6).is_none());
        reg.register_by_sccp_ssn(6, Box::new(StubDissector("hlr")))
            .unwrap();
        reg.register_by_sccp_ssn(7, Box::new(StubDissector("vlr")))
            .unwrap();
        let dup = reg.register_by_sccp_ssn(6, Box::new(StubDissector("dup")));
        assert!(matches!(
            dup,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "sccp_ssn",
                key: 6,
                ..
            })
        ));
        let lookup = |called, calling| {
            reg.lookup_dissector(&DispatchHint::BySccpSsn { called, calling })
                .map(|d| d.short_name())
        };
        // The called SSN is tried first, then the calling SSN.
        assert_eq!(lookup(7, 6), Some("vlr"));
        assert_eq!(lookup(200, 6), Some("hlr"));
        // SSN 0 means "SSN not known/not used" and is never looked up.
        assert_eq!(lookup(0, 0), None);
        assert_eq!(lookup(0, 200), None);

        let mut reg = DissectorRegistry::new();
        reg.register_by_sccp_ssn(0, Box::new(StubDissector("zero")))
            .unwrap();
        assert!(
            reg.lookup_dissector(&DispatchHint::BySccpSsn {
                called: 0,
                calling: 0
            })
            .is_none()
        );
        let prev = reg.register_by_sccp_ssn_or_replace(0, Box::new(StubDissector("z2")));
        assert_eq!(prev.map(|d| d.short_name()), Some("zero"));
        assert!(
            reg.register_dissector(DissectorTable::SccpSsn(8), Box::new(StubDissector("msc")))
                .is_ok()
        );
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::SccpSsn(8),
                Box::new(StubDissector("msc2")),
            )
            .is_some()
        );
        assert!(
            reg.all_field_schemas()
                .iter()
                .any(|s| s.short_name == "msc2")
        );
    }

    #[test]
    fn lookup_dissector_by_link_type_hint() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_link_type(105, Box::new(StubDissector("802.11")))
            .unwrap();
        assert_eq!(
            reg.lookup_dissector(&DispatchHint::ByLinkType(105))
                .map(|d| d.short_name()),
            Some("802.11")
        );
        assert!(
            reg.lookup_dissector(&DispatchHint::ByLinkType(127))
                .is_none()
        );
    }

    #[test]
    fn get_by_snap_returns_none_for_unknown() {
        let reg = DissectorRegistry::new();
        assert!(reg.get_by_snap(0x00_000C, 0x2000).is_none());
    }

    #[test]
    fn duplicate_snap_registration_returns_error() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_snap(0x00_000C, 0x2000, Box::new(StubDissector("cdp")))
            .unwrap();
        let result = reg.register_by_snap(0x00_000C, 0x2000, Box::new(StubDissector("cdp-dup")));
        assert!(matches!(
            result,
            Err(RegistrationError::DuplicateDispatchKey {
                table: "snap",
                key: 0x0000_000C_2000,
                ..
            })
        ));
    }

    #[test]
    fn register_by_snap_or_replace_returns_previous() {
        let mut reg = DissectorRegistry::new();
        assert!(
            reg.register_by_snap_or_replace(0x00_000C, 0x2004, Box::new(StubDissector("a")))
                .is_none()
        );
        let prev = reg.register_by_snap_or_replace(0x00_000C, 0x2004, Box::new(StubDissector("b")));
        assert_eq!(prev.map(|d| d.short_name()), Some("a"));
        assert_eq!(
            reg.get_by_snap(0x00_000C, 0x2004).map(|d| d.short_name()),
            Some("b")
        );
    }

    #[test]
    fn register_dissector_dispatches_to_snap() {
        let mut reg = DissectorRegistry::new();
        reg.register_dissector(
            DissectorTable::Snap {
                oui: 0x00_000C,
                pid: 0x2000,
            },
            Box::new(StubDissector("cdp")),
        )
        .unwrap();
        assert!(reg.get_by_snap(0x00_000C, 0x2000).is_some());
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::Snap {
                    oui: 0x00_000C,
                    pid: 0x2000,
                },
                Box::new(StubDissector("cdp2")),
            )
            .is_some()
        );
        assert!(
            reg.all_field_schemas()
                .iter()
                .any(|schema| schema.short_name == "cdp2")
        );
    }

    #[test]
    fn lookup_dissector_by_snap_hint() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_snap(0x00_000C, 0x2000, Box::new(StubDissector("cdp")))
            .unwrap();
        assert_eq!(
            reg.lookup_dissector(&DispatchHint::BySnap {
                oui: 0x00_000C,
                pid: 0x2000
            })
            .map(|d| d.short_name()),
            Some("cdp")
        );
        assert!(
            reg.lookup_dissector(&DispatchHint::BySnap {
                oui: 0x00_000C,
                pid: 0x2004
            })
            .is_none()
        );
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
    fn register_by_sctp_ppid_rejects_duplicate_and_replaces() {
        let mut reg = DissectorRegistry::new();
        assert!(reg.get_by_sctp_ppid(46).is_none());
        reg.register_by_sctp_ppid(46, Box::new(StubDissector("diameter")))
            .unwrap();
        let err = reg
            .register_by_sctp_ppid(46, Box::new(StubDissector("diameter-dup")))
            .unwrap_err();
        assert_eq!(
            err,
            RegistrationError::DuplicateDispatchKey {
                table: "sctp_ppid",
                key: 46,
                existing: "diameter",
                new: "diameter-dup",
            }
        );
        let previous = reg
            .register_by_sctp_ppid_or_replace(46, Box::new(StubDissector("diameter-new")))
            .unwrap();
        assert_eq!(previous.short_name(), "diameter");
        assert_eq!(
            reg.get_by_sctp_ppid(46).unwrap().short_name(),
            "diameter-new"
        );

        // Through the generic DissectorTable API.
        reg.register_dissector(
            DissectorTable::SctpPpid(60),
            Box::new(StubDissector("ngap")),
        )
        .unwrap();
        assert!(
            reg.register_dissector_or_replace(
                DissectorTable::SctpPpid(60),
                Box::new(StubDissector("ngap-new"))
            )
            .is_some()
        );
        assert_eq!(reg.get_by_sctp_ppid(60).unwrap().short_name(), "ngap-new");
        assert!(
            reg.all_field_schemas()
                .iter()
                .any(|s| s.short_name == "ngap-new")
        );
    }

    #[test]
    fn sctp_ppid_hint_prefers_ppid_then_ports() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_sctp_ppid(46, Box::new(StubDissector("by-ppid")))
            .unwrap();
        reg.register_by_sctp_ppid(0, Box::new(StubDissector("ppid-zero")))
            .unwrap();
        reg.register_by_sctp_port(3868, Box::new(StubDissector("by-port")))
            .unwrap();
        let hint = |ppid, src_port, dst_port| DispatchHint::BySctpPpid {
            ppid,
            src_port,
            dst_port,
        };

        // PPID wins over the port.
        let d = reg.lookup_dissector(&hint(46, 49152, 3868)).unwrap();
        assert_eq!(d.short_name(), "by-ppid");
        // Unknown PPID falls back to the lower, then the higher port.
        let d = reg.lookup_dissector(&hint(9999, 49152, 3868)).unwrap();
        assert_eq!(d.short_name(), "by-port");
        let d = reg.lookup_dissector(&hint(9999, 3868, 1)).unwrap();
        assert_eq!(d.short_name(), "by-port");
        // PPID 0 ("unspecified") never uses the PPID table.
        let d = reg.lookup_dissector(&hint(0, 49152, 3868)).unwrap();
        assert_eq!(d.short_name(), "by-port");
        assert!(reg.lookup_dissector(&hint(0, 1, 2)).is_none());

        // The summary stops at a PPID hint and names the next protocol.
        let mut summary = DissectSummary::new();
        let buf = DissectBuffer::new();
        assert!(reg.summary_stop(&buf, &hint(46, 1, 2), &mut summary));
        assert_eq!(summary.next_protocol, Some("by-ppid"));
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
        assert_eq!(result, Err(PacketError::UnsupportedLinkType(999)));
    }

    #[test]
    fn unregistered_link_type_does_not_fall_back_to_entry() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(StubDissector("entry")));
        let data = [0u8; 14];

        let mut buf = DissectBuffer::new();
        assert_eq!(
            reg.dissect_with_link_type(&data, 147, &mut buf),
            Err(PacketError::UnsupportedLinkType(147))
        );
        let mut buf = DissectBuffer::new();
        assert_eq!(
            reg.dissect_summary_with_link_type(&data, 147, &mut buf)
                .map(|_| ()),
            Err(PacketError::UnsupportedLinkType(147))
        );
        let mut buf = DissectBuffer::new();
        let mut projection = crate::summary::FieldProjection::new([("entry", "x")]);
        assert_eq!(
            reg.dissect_projected_with_link_type(&data, 147, &mut buf, &mut projection),
            Err(PacketError::UnsupportedLinkType(147))
        );

        // The entry dissector is still used by `dissect()`.
        let mut buf = DissectBuffer::new();
        assert_eq!(reg.dissect(&data, &mut buf), Ok(()));
    }

    #[test]
    fn registered_link_type_is_used() {
        let mut reg = DissectorRegistry::new();
        reg.register_by_link_type(147, Box::new(StubDissector("user0")))
            .unwrap();
        let mut buf = DissectBuffer::new();
        assert_eq!(reg.dissect_with_link_type(&[0u8; 4], 147, &mut buf), Ok(()));
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

    // --- all_protocol_info ---

    #[test]
    fn all_protocol_info_mirrors_all_field_schemas_order() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(StubDissector("entry")));
        reg.register_by_ethertype(0x0800, Box::new(StubDissector("et")))
            .unwrap();
        reg.register_by_udp_port(53, Box::new(StubDissector("dns")))
            .unwrap();
        reg.register_by_tcp_port(53, Box::new(StubDissector("dns")))
            .unwrap();

        let infos = reg.all_protocol_info();
        let schemas = reg.all_field_schemas();

        let info_names: Vec<&str> = infos.iter().map(|i| i.short_name).collect();
        let schema_names: Vec<&str> = schemas.iter().map(|s| s.short_name).collect();
        assert_eq!(info_names, schema_names);
    }

    #[test]
    fn all_protocol_info_reports_trait_defaults_for_stubs() {
        let mut reg = DissectorRegistry::new();
        reg.set_entry_dissector(Box::new(StubDissector("entry")));

        let infos = reg.all_protocol_info();
        let entry = infos
            .iter()
            .find(|i| i.short_name == "entry")
            .expect("entry dissector should be present");
        assert_eq!(entry.name, "entry");
        assert!(entry.references.is_empty());
        assert_eq!(entry.layer, None);
    }

    // --- Default registry feature-gated registrations ---

    #[test]
    fn default_registry_has_expected_dissectors() {
        let reg = DissectorRegistry::default();

        #[cfg(feature = "ethernet")]
        assert!(reg.entry.is_some());

        #[cfg(feature = "ethernet")]
        assert!(reg.get_by_ethertype(0x6558).is_some());

        // IEEE 802.1Q-2022, clause 9.6 — standalone C-Tag / S-Tag.
        #[cfg(any(feature = "ethernet", feature = "linux_sll", feature = "linux_sll2"))]
        for tpid in [0x8100, 0x88A8] {
            assert_eq!(
                reg.get_by_ethertype(tpid).map(|d| d.short_name()),
                Some("VLAN")
            );
        }

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

        #[cfg(feature = "erspan")]
        {
            assert!(reg.get_by_ethertype(0x88BE).is_some());
            assert!(reg.get_by_ethertype(0x22EB).is_some());
        }

        #[cfg(feature = "ospf")]
        assert!(reg.get_by_ip_protocol(89).is_some());

        #[cfg(feature = "vrrp")]
        assert!(reg.get_by_ip_protocol(112).is_some());

        #[cfg(feature = "pim")]
        assert!(reg.get_by_ip_protocol(103).is_some());

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

        #[cfg(feature = "eap")]
        assert!(reg.get_by_ethertype(0x888E).is_some());

        #[cfg(feature = "mpls")]
        {
            assert!(reg.get_by_ethertype(0x8847).is_some());
            assert!(reg.get_by_ethertype(0x8848).is_some());
        }

        #[cfg(feature = "nsh")]
        assert!(reg.get_by_ethertype(0x894F).is_some());

        #[cfg(feature = "ethernet")]
        assert!(reg.get_by_link_type(1).is_some());

        #[cfg(feature = "ieee80211")]
        assert!(reg.get_by_link_type(105).is_some());

        #[cfg(feature = "radiotap")]
        assert!(reg.get_by_link_type(127).is_some());

        #[cfg(feature = "null")]
        {
            assert!(reg.get_by_link_type(0).is_some());
            assert!(reg.get_by_link_type(108).is_some());
        }

        #[cfg(feature = "raw_ip")]
        {
            assert!(reg.get_by_link_type(101).is_some());
            assert!(reg.get_by_link_type(228).is_some());
            assert!(reg.get_by_link_type(229).is_some());
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

        #[cfg(feature = "pppoe")]
        {
            assert!(reg.get_by_ethertype(0x8863).is_some());
            assert!(reg.get_by_ethertype(0x8864).is_some());
            assert!(reg.get_by_link_type(51).is_some());
        }

        #[cfg(feature = "stp")]
        assert!(reg.get_by_llc_sap(0x42).is_some());

        #[cfg(feature = "isis")]
        assert!(reg.get_by_llc_sap(0xFE).is_some());

        #[cfg(feature = "cdp")]
        assert!(reg.get_by_snap(0x00_000C, 0x2000).is_some());
    }

    /// RFC 4666, Sections 7.1 and 7.2 — M3UA on SCTP PPID 3 and port 2905;
    /// SCCP is the MTP3-User with Service Indicator 3 (ITU-T Q.704, clause
    /// 14.2.1).
    #[test]
    fn default_registry_sigtran_dissectors() {
        let reg = DissectorRegistry::default();

        #[cfg(all(feature = "m3ua", feature = "sctp"))]
        {
            assert_eq!(
                reg.get_by_sctp_ppid(3).map(|d| d.short_name()),
                Some("M3UA")
            );
            assert_eq!(
                reg.get_by_sctp_port(2905).map(|d| d.short_name()),
                Some("M3UA")
            );
        }
        #[cfg(feature = "m3ua")]
        assert!(reg.create_dissector_by_name("m3ua").is_some());

        #[cfg(feature = "sccp")]
        {
            assert_eq!(
                reg.get_by_mtp3_service_indicator(3).map(|d| d.short_name()),
                Some("SCCP")
            );
            assert!(reg.create_dissector_by_name("sccp").is_some());
        }

        #[cfg(feature = "tcap")]
        {
            let map_ssn = if cfg!(feature = "map") { "MAP" } else { "TCAP" };
            for ssn in [5, 6, 7, 8, 9, 145, 147, 148, 149, 150, 248] {
                assert_eq!(
                    reg.get_by_sccp_ssn(ssn).map(|d| d.short_name()),
                    Some(map_ssn),
                    "SSN {ssn}"
                );
            }
            assert_eq!(
                reg.get_by_sccp_ssn(146).map(|d| d.short_name()),
                Some("TCAP")
            );
            assert!(reg.create_dissector_by_name("tcap").is_some());
        }
        #[cfg(feature = "map")]
        assert!(reg.create_dissector_by_name("map").is_some());
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
            assert!(reg.get_by_udp_port(6784).is_some());
            assert!(reg.get_by_udp_port(7784).is_some());
        }

        // IPFIX: RFC 7011, Section 10.1 —
        // https://www.rfc-editor.org/rfc/rfc7011#section-10.1
        #[cfg(all(feature = "ipfix", feature = "udp"))]
        assert!(reg.get_by_udp_port(4739).is_some());
        #[cfg(all(feature = "ipfix", feature = "tcp"))]
        assert!(reg.get_by_tcp_port(4739).is_some());
        #[cfg(all(feature = "ipfix", feature = "sctp"))]
        assert!(reg.get_by_sctp_port(4739).is_some());

        // SNMP: RFC 3417, Section 3.2 —
        // https://www.rfc-editor.org/rfc/rfc3417#section-3.2
        #[cfg(all(feature = "snmp", feature = "udp"))]
        {
            assert!(reg.get_by_udp_port(161).is_some());
            assert!(reg.get_by_udp_port(162).is_some());
        }

        #[cfg(all(feature = "mdns", feature = "udp"))]
        assert!(reg.get_by_udp_port(5353).is_some());

        #[cfg(all(feature = "vxlan", feature = "udp"))]
        assert!(reg.get_by_udp_port(4789).is_some());
        #[cfg(all(feature = "vxlan", feature = "udp"))]
        assert!(reg.get_by_udp_port(4790).is_some());

        // G-ACh channel types: RFC 4385, Section 6
        // (https://www.rfc-editor.org/rfc/rfc4385#section-6), RFC 5885
        // (https://www.rfc-editor.org/rfc/rfc5885), RFC 6428
        // (https://www.rfc-editor.org/rfc/rfc6428)
        #[cfg(all(feature = "mpls", feature = "ipv4"))]
        assert!(reg.get_by_ach_channel_type(0x0021).is_some());
        #[cfg(all(feature = "mpls", feature = "ipv6"))]
        assert!(reg.get_by_ach_channel_type(0x0057).is_some());
        #[cfg(all(feature = "mpls", feature = "bfd"))]
        {
            assert!(reg.get_by_ach_channel_type(0x0007).is_some());
            assert!(reg.get_by_ach_channel_type(0x0008).is_some());
            assert!(reg.get_by_ach_channel_type(0x0022).is_some());
            assert!(reg.get_by_ach_channel_type(0x0023).is_some());
        }

        #[cfg(all(feature = "geneve", feature = "udp"))]
        assert!(reg.get_by_udp_port(6081).is_some());

        #[cfg(all(feature = "gtpv1u", feature = "udp"))]
        assert!(reg.get_by_udp_port(2152).is_some());

        #[cfg(all(any(feature = "gtpv1c", feature = "gtpv2c"), feature = "udp"))]
        assert!(reg.get_by_udp_port(2123).is_some());

        #[cfg(all(feature = "pfcp", feature = "udp"))]
        assert!(reg.get_by_udp_port(8805).is_some());

        #[cfg(all(feature = "ike", feature = "udp"))]
        assert!(reg.get_by_udp_port(500).is_some());

        // Port 4500 is taken by the RFC 3948 dispatcher when ESP is enabled,
        // and by IKE alone otherwise.
        #[cfg(all(any(feature = "ike", feature = "esp"), feature = "udp"))]
        assert!(reg.get_by_udp_port(4500).is_some());

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

        #[cfg(all(feature = "sgsap", feature = "sctp"))]
        assert_eq!(reg.get_by_sctp_port(29118).unwrap().short_name(), "SGsAP");
        #[cfg(all(feature = "sgsap", feature = "sctp"))]
        assert!(reg.get_by_sctp_ppid(0).is_none());

        // IANA "SCTP Payload Protocol Identifiers": 46 Diameter, 60 NGAP.
        #[cfg(all(feature = "diameter", feature = "sctp"))]
        assert_eq!(reg.get_by_sctp_ppid(46).unwrap().short_name(), "Diameter");
        #[cfg(all(feature = "ngap", feature = "sctp"))]
        assert_eq!(reg.get_by_sctp_ppid(60).unwrap().short_name(), "NGAP");

        // IANA: XnAP port 38422 / PPID 61, F1AP 38472 / 62, E1AP 38462 / 64.
        #[cfg(all(feature = "xnap", feature = "sctp"))]
        {
            assert_eq!(reg.get_by_sctp_port(38422).unwrap().short_name(), "XnAP");
            assert_eq!(reg.get_by_sctp_ppid(61).unwrap().short_name(), "XnAP");
        }
        #[cfg(all(feature = "f1ap", feature = "sctp"))]
        {
            assert_eq!(reg.get_by_sctp_port(38472).unwrap().short_name(), "F1AP");
            assert_eq!(reg.get_by_sctp_ppid(62).unwrap().short_name(), "F1AP");
        }
        #[cfg(all(feature = "e1ap", feature = "sctp"))]
        {
            assert_eq!(reg.get_by_sctp_port(38462).unwrap().short_name(), "E1AP");
            assert_eq!(reg.get_by_sctp_ppid(64).unwrap().short_name(), "E1AP");
        }

        #[cfg(all(any(feature = "l2tp", feature = "l2tpv3"), feature = "udp"))]
        assert!(reg.get_by_udp_port(1701).is_some());
    }

    #[cfg(all(feature = "gtpv1c", feature = "gtpv2c", feature = "udp"))]
    #[test]
    fn gtpc_dispatcher_routes_by_version() {
        let reg = DissectorRegistry::default();
        let d = reg.get_by_udp_port(2123).unwrap();
        assert_eq!(d.short_name(), "GTP-C");
        assert!(d.field_descriptors().is_empty());
        assert_eq!(d.references().len(), 2);
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert!(!d.name().is_empty());

        // GTPv1-C Echo Request (TS 29.060) and GTPv2-C Echo Request (TS 29.274)
        let v1 = [0x32, 1, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0];
        let v2 = [0x40, 1, 0, 4, 0, 0, 1, 0];
        let mut buf = DissectBuffer::new();
        d.dissect(&v1, &mut buf, 0).unwrap();
        d.dissect(&v2, &mut buf, 12).unwrap();
        let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
        assert_eq!(names, ["GTPv1-C", "GTPv2-C"]);

        let mut buf = DissectBuffer::new();
        assert!(matches!(
            d.dissect(&[], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 1,
                actual: 0
            })
        ));
        assert!(matches!(
            d.dissect(&[0x60, 1, 0, 4], &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 3
            })
        ));

        let schemas = reg.all_field_schemas();
        for name in ["GTPv1-C", "GTPv2-C"] {
            let schema = schemas.iter().find(|s| s.short_name == name).unwrap();
            assert!(schema.fields.iter().any(|f| f.name == "ies"), "{name}");
        }
    }

    #[test]
    fn default_registry_assigned_port_registrations() {
        let reg = DissectorRegistry::default();

        // Implicit-TLS service ports (see the references in `default()`):
        // RFC 7858, Section 3.1 — https://www.rfc-editor.org/rfc/rfc7858#section-3.1
        // RFC 8314, Section 7 — https://www.rfc-editor.org/rfc/rfc8314#section-7
        // RFC 6614, Section 2.1 — https://www.rfc-editor.org/rfc/rfc6614#section-2.1
        // RFC 3261, Section 18.2.1 — https://www.rfc-editor.org/rfc/rfc3261#section-18.2.1
        // RFC 8489, Section 18.6 — https://www.rfc-editor.org/rfc/rfc8489#section-18.6
        // RFC 7194, Section 4 — https://www.rfc-editor.org/rfc/rfc7194#section-4
        // IANA ldaps (636), ftps (990) — https://www.iana.org/assignments/service-names-port-numbers/
        #[cfg(all(feature = "tls", feature = "tcp"))]
        for port in [465, 636, 853, 990, 993, 995, 2083, 5061, 5349, 6697] {
            assert_eq!(
                reg.get_by_tcp_port(port).map(|d| d.short_name()),
                Some("TLS"),
                "TCP port {port}"
            );
        }

        // RFC 3261, Section 18.1.1 — SIP over SCTP on 5060.
        // https://www.rfc-editor.org/rfc/rfc3261#section-18.1.1
        #[cfg(all(feature = "sip", feature = "sctp"))]
        assert_eq!(
            reg.get_by_sctp_port(5060).map(|d| d.short_name()),
            Some("SIP")
        );

        // RFC 5176, Section 2.3 — https://www.rfc-editor.org/rfc/rfc5176#section-2.3
        // RFC 2865, Section 3 — https://www.rfc-editor.org/rfc/rfc2865#section-3
        // RFC 2866, Section 3 — https://www.rfc-editor.org/rfc/rfc2866#section-3
        #[cfg(all(feature = "radius", feature = "udp"))]
        for port in [1645, 1646, 3799] {
            assert_eq!(
                reg.get_by_udp_port(port).map(|d| d.short_name()),
                Some("RADIUS"),
                "UDP port {port}"
            );
        }

        // RFC 903 — RARP (EtherType 0x8035) uses the ARP packet format.
        // https://www.rfc-editor.org/rfc/rfc903
        #[cfg(feature = "arp")]
        assert_eq!(
            reg.get_by_ethertype(0x8035).map(|d| d.short_name()),
            Some("ARP")
        );

        // RFC 8986, Section 10.1 — IP protocol 143 (Ethernet).
        // https://www.rfc-editor.org/rfc/rfc8986#section-10.1
        #[cfg(feature = "ethernet")]
        assert_eq!(
            reg.get_by_ip_protocol(143).map(|d| d.short_name()),
            Some("Ethernet")
        );
    }

    #[test]
    fn default_registry_factories() {
        let reg = DissectorRegistry::default();

        #[cfg(feature = "ntp")]
        assert!(reg.create_dissector_by_name("ntp").is_some());

        #[cfg(feature = "bfd")]
        {
            assert!(reg.create_dissector_by_name("bfd").is_some());
            assert!(reg.create_dissector_by_name("bfd.echo").is_some());
        }

        #[cfg(feature = "snmp")]
        assert!(reg.create_dissector_by_name("snmp").is_some());

        #[cfg(feature = "dhcp")]
        assert!(reg.create_dissector_by_name("dhcp").is_some());

        #[cfg(feature = "dhcpv6")]
        assert!(reg.create_dissector_by_name("dhcpv6").is_some());

        #[cfg(feature = "geneve")]
        assert!(reg.create_dissector_by_name("geneve").is_some());

        #[cfg(feature = "gtpv1u")]
        assert!(reg.create_dissector_by_name("gtpv1u").is_some());

        #[cfg(feature = "gtpv1c")]
        assert!(reg.create_dissector_by_name("gtpv1c").is_some());

        #[cfg(feature = "gtpv2c")]
        assert!(reg.create_dissector_by_name("gtpv2c").is_some());

        #[cfg(feature = "pfcp")]
        assert!(reg.create_dissector_by_name("pfcp").is_some());

        #[cfg(feature = "vxlan")]
        assert!(reg.create_dissector_by_name("vxlan").is_some());
        #[cfg(feature = "vxlan")]
        assert!(reg.create_dissector_by_name("vxlan-gpe").is_some());

        #[cfg(feature = "ike")]
        assert!(reg.create_dissector_by_name("ike").is_some());

        #[cfg(feature = "diameter")]
        assert!(reg.create_dissector_by_name("diameter").is_some());

        #[cfg(feature = "radius")]
        assert!(reg.create_dissector_by_name("radius").is_some());

        #[cfg(feature = "ngap")]
        assert!(reg.create_dissector_by_name("ngap").is_some());

        #[cfg(feature = "xnap")]
        assert!(reg.create_dissector_by_name("xnap").is_some());

        #[cfg(feature = "f1ap")]
        assert!(reg.create_dissector_by_name("f1ap").is_some());

        #[cfg(feature = "e1ap")]
        assert!(reg.create_dissector_by_name("e1ap").is_some());

        #[cfg(feature = "sgsap")]
        assert!(reg.create_dissector_by_name("sgsap").is_some());

        #[cfg(feature = "nas5g")]
        assert!(reg.create_dissector_by_name("nas5g").is_some());

        #[cfg(feature = "nas-eps")]
        assert!(reg.create_dissector_by_name("nas-eps").is_some());

        #[cfg(any(feature = "l2tp", feature = "l2tpv3"))]
        assert!(reg.create_dissector_by_name("l2tp").is_some());

        #[cfg(feature = "rtp")]
        assert!(reg.create_dissector_by_name("rtp").is_some());

        #[cfg(feature = "quic")]
        assert!(reg.create_dissector_by_name("quic").is_some());

        #[cfg(feature = "stun")]
        {
            assert!(reg.create_dissector_by_name("stun").is_some());
            let tcp = reg.create_dissector_by_name("stun.tcp").unwrap();
            // Stream framing: an unpadded ChannelData message is incomplete.
            let mut buf = packet_dissector_core::packet::DissectBuffer::new();
            assert!(matches!(
                tcp.dissect(&[0x40, 0x00, 0x00, 0x01, 0xAA], &mut buf, 0),
                Err(PacketError::Truncated { expected: 8, .. })
            ));
        }

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
