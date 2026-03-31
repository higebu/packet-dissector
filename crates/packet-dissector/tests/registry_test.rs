use packet_dissector::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector::error::{PacketError, RegistrationError};
use packet_dissector::field::{FieldDescriptor, FieldValue};
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

/// Create a leaked static FieldDescriptor for tests.
#[cfg(test)]
fn test_desc(
    name: &'static str,
    display_name: &'static str,
) -> &'static packet_dissector::field::FieldDescriptor {
    Box::leak(Box::new(packet_dissector::field::FieldDescriptor {
        name,
        display_name,
        field_type: packet_dissector::field::FieldType::U8, // placeholder
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    }))
}

// --- Mock L2 dissector: reads 4 bytes [u16 ethertype, u16 dummy] ---

struct MockL2Dissector;

impl Dissector for MockL2Dissector {
    fn name(&self) -> &'static str {
        "Mock L2"
    }
    fn short_name(&self) -> &'static str {
        "L2"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let ethertype = u16::from_be_bytes([data[0], data[1]]);
        buf.begin_layer("L2", None, &[], offset..offset + 4);
        buf.push_field(
            test_desc("ethertype", "Ethertype"),
            FieldValue::U16(ethertype),
            offset..offset + 2,
        );
        buf.end_layer();
        Ok(DissectResult::new(4, DispatchHint::ByEtherType(ethertype)))
    }
}

// --- Mock L3 dissector: reads 4 bytes [u8 protocol, u8 x, u16 dummy] ---

struct MockL3Dissector;

impl Dissector for MockL3Dissector {
    fn name(&self) -> &'static str {
        "Mock L3"
    }
    fn short_name(&self) -> &'static str {
        "L3"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let protocol = data[0];
        buf.begin_layer("L3", None, &[], offset..offset + 4);
        buf.push_field(
            test_desc("protocol", "Protocol"),
            FieldValue::U8(protocol),
            offset..offset + 1,
        );
        buf.end_layer();
        Ok(DissectResult::new(4, DispatchHint::ByIpProtocol(protocol)))
    }
}

// --- Mock L4 dissector: reads 4 bytes [u16 src_port, u16 dst_port] ---

struct MockL4Dissector;

impl Dissector for MockL4Dissector {
    fn name(&self) -> &'static str {
        "Mock L4"
    }
    fn short_name(&self) -> &'static str {
        "L4"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 4 {
            return Err(PacketError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        buf.begin_layer("L4", None, &[], offset..offset + 4);
        buf.push_field(
            test_desc("dst_port", "Dst Port"),
            FieldValue::U16(dst_port),
            offset + 2..offset + 4,
        );
        buf.end_layer();
        Ok(DissectResult::new(
            4,
            DispatchHint::ByTcpPort(src_port, dst_port),
        ))
    }
}

// --- Mock routing dispatcher: peeks at byte 2 for routing type ---

struct MockRoutingDispatcher;

impl Dissector for MockRoutingDispatcher {
    fn name(&self) -> &'static str {
        "Mock Routing Dispatcher"
    }
    fn short_name(&self) -> &'static str {
        "RoutingDisp"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        _buf: &mut DissectBuffer<'pkt>,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 3 {
            return Err(PacketError::Truncated {
                expected: 3,
                actual: data.len(),
            });
        }
        Ok(DissectResult::new(
            0,
            DispatchHint::ByIpv6RoutingType(data[2]),
        ))
    }
}

// --- Mock type-specific routing dissector (e.g., SRv6) ---

struct MockSrv6Dissector;

impl Dissector for MockSrv6Dissector {
    fn name(&self) -> &'static str {
        "Mock SRv6"
    }
    fn short_name(&self) -> &'static str {
        "SRv6"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 8 {
            return Err(PacketError::Truncated {
                expected: 8,
                actual: data.len(),
            });
        }
        buf.begin_layer("SRv6", None, &[], offset..offset + 8);
        buf.push_field(
            test_desc("routing_type", "Routing Type"),
            FieldValue::U8(data[2]),
            offset + 2..offset + 3,
        );
        buf.end_layer();
        Ok(DissectResult::new(8, DispatchHint::ByIpProtocol(data[0])))
    }
}

// --- Mock generic routing fallback dissector ---

struct MockGenericRoutingDissector;

impl Dissector for MockGenericRoutingDissector {
    fn name(&self) -> &'static str {
        "Mock Generic Routing"
    }
    fn short_name(&self) -> &'static str {
        "GenRouting"
    }
    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }
    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < 8 {
            return Err(PacketError::Truncated {
                expected: 8,
                actual: data.len(),
            });
        }
        buf.begin_layer("GenRouting", None, &[], offset..offset + 8);
        buf.push_field(
            test_desc("routing_type", "Routing Type"),
            FieldValue::U8(data[2]),
            offset + 2..offset + 3,
        );
        buf.end_layer();
        Ok(DissectResult::new(8, DispatchHint::ByIpProtocol(data[0])))
    }
}

// --- Another mock dissector for duplicate-detection tests ---

struct MockL3AltDissector;

impl Dissector for MockL3AltDissector {
    fn name(&self) -> &'static str {
        "Mock L3 Alt"
    }
    fn short_name(&self) -> &'static str {
        "L3-Alt"
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

struct MockL4AltDissector;

impl Dissector for MockL4AltDissector {
    fn name(&self) -> &'static str {
        "Mock L4 Alt"
    }
    fn short_name(&self) -> &'static str {
        "L4-Alt"
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

// --- Registration tests ---

#[test]
fn register_and_lookup_by_ethertype() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ethertype(0x0800, Box::new(MockL3Dissector))
        .unwrap();

    assert!(registry.get_by_ethertype(0x0800).is_some());
    assert!(registry.get_by_ethertype(0x86DD).is_none());
}

#[test]
fn register_and_lookup_by_ip_protocol() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ip_protocol(6, Box::new(MockL4Dissector))
        .unwrap();

    assert!(registry.get_by_ip_protocol(6).is_some());
    assert!(registry.get_by_ip_protocol(17).is_none());
}

#[test]
fn register_and_lookup_by_tcp_port() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_tcp_port(80, Box::new(MockL4Dissector))
        .unwrap();

    assert!(registry.get_by_tcp_port(80).is_some());
    assert!(registry.get_by_tcp_port(53).is_none());
    // TCP port lookup must not bleed into the UDP table
    assert!(registry.get_by_udp_port(80).is_none());
}

#[test]
fn register_and_lookup_by_udp_port() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_udp_port(53, Box::new(MockL4Dissector))
        .unwrap();

    assert!(registry.get_by_udp_port(53).is_some());
    assert!(registry.get_by_udp_port(80).is_none());
    // UDP port lookup must not bleed into the TCP table
    assert!(registry.get_by_tcp_port(53).is_none());
}

#[test]
fn tcp_and_udp_same_port_independent() {
    // Regression: TCP:80 and UDP:80 must be independently registerable
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_tcp_port(80, Box::new(MockL4Dissector))
        .unwrap();
    // UDP:80 is intentionally not registered
    assert!(registry.get_by_tcp_port(80).is_some());
    assert!(registry.get_by_udp_port(80).is_none());
}

// --- Duplicate detection tests ---

#[test]
fn register_by_ethertype_duplicate_returns_error() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ethertype(0x0800, Box::new(MockL3Dissector))
        .unwrap();

    let err = registry
        .register_by_ethertype(0x0800, Box::new(MockL3AltDissector))
        .unwrap_err();
    assert_eq!(
        err,
        RegistrationError::DuplicateDispatchKey {
            table: "ethertype",
            key: 0x0800,
            existing: "L3",
            new: "L3-Alt",
        }
    );
    // Original dissector is still registered
    assert_eq!(
        registry.get_by_ethertype(0x0800).unwrap().short_name(),
        "L3"
    );
}

#[test]
fn register_by_ip_protocol_duplicate_returns_error() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ip_protocol(6, Box::new(MockL4Dissector))
        .unwrap();

    let err = registry
        .register_by_ip_protocol(6, Box::new(MockL4AltDissector))
        .unwrap_err();
    assert_eq!(
        err,
        RegistrationError::DuplicateDispatchKey {
            table: "ip_protocol",
            key: 6,
            existing: "L4",
            new: "L4-Alt",
        }
    );
}

#[test]
fn register_by_tcp_port_duplicate_returns_error() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_tcp_port(80, Box::new(MockL4Dissector))
        .unwrap();

    let err = registry
        .register_by_tcp_port(80, Box::new(MockL4AltDissector))
        .unwrap_err();
    assert_eq!(
        err,
        RegistrationError::DuplicateDispatchKey {
            table: "tcp_port",
            key: 80,
            existing: "L4",
            new: "L4-Alt",
        }
    );
}

#[test]
fn register_by_udp_port_duplicate_returns_error() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_udp_port(53, Box::new(MockL4Dissector))
        .unwrap();

    let err = registry
        .register_by_udp_port(53, Box::new(MockL4AltDissector))
        .unwrap_err();
    assert_eq!(
        err,
        RegistrationError::DuplicateDispatchKey {
            table: "udp_port",
            key: 53,
            existing: "L4",
            new: "L4-Alt",
        }
    );
}

#[test]
fn register_same_port_tcp_and_udp_succeeds() {
    // TCP:53 and UDP:53 are different tables — both must succeed
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_tcp_port(53, Box::new(MockL4Dissector))
        .unwrap();
    registry
        .register_by_udp_port(53, Box::new(MockL4AltDissector))
        .unwrap();

    assert_eq!(registry.get_by_tcp_port(53).unwrap().short_name(), "L4");
    assert_eq!(registry.get_by_udp_port(53).unwrap().short_name(), "L4-Alt");
}

#[test]
fn register_by_ethertype_or_replace_overwrites() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ethertype(0x0800, Box::new(MockL3Dissector))
        .unwrap();

    let old = registry.register_by_ethertype_or_replace(0x0800, Box::new(MockL3AltDissector));
    assert!(old.is_some());
    assert_eq!(old.unwrap().short_name(), "L3");

    // New dissector is now registered
    assert_eq!(
        registry.get_by_ethertype(0x0800).unwrap().short_name(),
        "L3-Alt"
    );
}

#[test]
fn register_by_ip_protocol_or_replace_overwrites() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ip_protocol(6, Box::new(MockL4Dissector))
        .unwrap();

    let old = registry.register_by_ip_protocol_or_replace(6, Box::new(MockL4AltDissector));
    assert!(old.is_some());
    assert_eq!(old.unwrap().short_name(), "L4");
    assert_eq!(
        registry.get_by_ip_protocol(6).unwrap().short_name(),
        "L4-Alt"
    );
}

#[test]
fn register_by_tcp_port_or_replace_overwrites() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_tcp_port(80, Box::new(MockL4Dissector))
        .unwrap();

    let old = registry.register_by_tcp_port_or_replace(80, Box::new(MockL4AltDissector));
    assert!(old.is_some());
    assert_eq!(registry.get_by_tcp_port(80).unwrap().short_name(), "L4-Alt");
}

#[test]
fn register_by_udp_port_or_replace_overwrites() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_udp_port(53, Box::new(MockL4Dissector))
        .unwrap();

    let old = registry.register_by_udp_port_or_replace(53, Box::new(MockL4AltDissector));
    assert!(old.is_some());
    assert_eq!(registry.get_by_udp_port(53).unwrap().short_name(), "L4-Alt");
}

// --- Chaining and dissection tests ---

#[test]
fn chained_dissection_l2_to_l3() {
    let mut registry = DissectorRegistry::new();
    registry.set_entry_dissector(Box::new(MockL2Dissector));
    registry
        .register_by_ethertype(0x0800, Box::new(MockL3Dissector))
        .unwrap();

    let data = [
        0x08, 0x00, 0x00, 0x00, // L2
        0x06, 0x00, 0x00, 0x00, // L3
    ];

    let mut buf = DissectBuffer::new();
    registry.dissect(&data, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 2);

    let l2 = buf.layer_by_name("L2").unwrap();
    assert_eq!(
        buf.field_by_name(l2, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );

    let l3 = buf.layer_by_name("L3").unwrap();
    assert_eq!(
        buf.field_by_name(l3, "protocol").unwrap().value,
        FieldValue::U8(6)
    );
}

#[test]
fn chained_dissection_l2_to_l3_to_l4() {
    let mut registry = DissectorRegistry::new();
    registry.set_entry_dissector(Box::new(MockL2Dissector));
    registry
        .register_by_ethertype(0x0800, Box::new(MockL3Dissector))
        .unwrap();
    registry
        .register_by_ip_protocol(6, Box::new(MockL4Dissector))
        .unwrap();

    let data = [
        0x08, 0x00, 0x00, 0x00, // L2: ethertype=0x0800
        0x06, 0x00, 0x00, 0x00, // L3: protocol=6
        0x1F, 0x90, 0x00, 0x50, // L4: src_port=8080, dst_port=80
    ];

    let mut buf = DissectBuffer::new();
    registry.dissect(&data, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3);

    let l4 = buf.layer_by_name("L4").unwrap();
    assert_eq!(
        buf.field_by_name(l4, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
    assert_eq!(l4.range, 8..12);
}

#[test]
fn dissect_stops_when_no_next_dissector() {
    let mut registry = DissectorRegistry::new();
    registry.set_entry_dissector(Box::new(MockL2Dissector));

    let data = [0x08, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];

    let mut buf = DissectBuffer::new();
    registry.dissect(&data, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 1);
}

#[test]
fn dissect_stops_when_data_exhausted() {
    let mut registry = DissectorRegistry::new();
    registry.set_entry_dissector(Box::new(MockL2Dissector));
    registry
        .register_by_ethertype(0x0800, Box::new(MockL3Dissector))
        .unwrap();

    let data = [0x08, 0x00, 0x00, 0x00];

    let mut buf = DissectBuffer::new();
    registry.dissect(&data, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 1);
}

#[test]
fn registry_default_has_builtin_dissectors() {
    let registry = DissectorRegistry::default();
    assert!(registry.get_by_ethertype(0x0800).is_some()); // IPv4
    assert!(registry.get_by_ethertype(0x86DD).is_some()); // IPv6
    assert!(registry.get_by_ethertype(0x0806).is_some()); // ARP
    assert!(registry.get_by_ip_protocol(1).is_some()); // ICMP
    assert!(registry.get_by_ip_protocol(6).is_some()); // TCP
    assert!(registry.get_by_ip_protocol(17).is_some()); // UDP
    assert!(registry.get_by_tcp_port(53).is_some()); // DNS over TCP
    assert!(registry.get_by_udp_port(53).is_some()); // DNS over UDP
}

#[test]
fn dissect_without_entry_dissector_returns_error() {
    let registry = DissectorRegistry::new();
    let data = [0x00; 4];

    let mut buf = DissectBuffer::new();
    let err = registry.dissect(&data, &mut buf).unwrap_err();
    assert!(matches!(err, PacketError::InvalidHeader(_)));
}

// --- Routing type dispatch tests ---

#[test]
fn register_and_lookup_by_ipv6_routing_type() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ipv6_routing_type(4, Box::new(MockSrv6Dissector))
        .unwrap();

    assert!(registry.get_by_ipv6_routing_type(4).is_some());
    assert_eq!(
        registry.get_by_ipv6_routing_type(4).unwrap().short_name(),
        "SRv6"
    );
    // No fallback set, so unknown type returns None
    assert!(registry.get_by_ipv6_routing_type(2).is_none());
}

#[test]
fn register_by_ipv6_routing_type_duplicate_returns_error() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ipv6_routing_type(4, Box::new(MockSrv6Dissector))
        .unwrap();

    let err = registry
        .register_by_ipv6_routing_type(4, Box::new(MockGenericRoutingDissector))
        .unwrap_err();
    assert_eq!(
        err,
        RegistrationError::DuplicateDispatchKey {
            table: "ipv6_routing_type",
            key: 4,
            existing: "SRv6",
            new: "GenRouting",
        }
    );
}

#[test]
fn register_by_ipv6_routing_type_or_replace_overwrites() {
    let mut registry = DissectorRegistry::new();
    registry
        .register_by_ipv6_routing_type(4, Box::new(MockSrv6Dissector))
        .unwrap();

    let old =
        registry.register_by_ipv6_routing_type_or_replace(4, Box::new(MockGenericRoutingDissector));
    assert!(old.is_some());
    assert_eq!(old.unwrap().short_name(), "SRv6");
    assert_eq!(
        registry.get_by_ipv6_routing_type(4).unwrap().short_name(),
        "GenRouting"
    );
}

#[test]
fn routing_type_fallback_used_for_unknown_type() {
    let mut registry = DissectorRegistry::new();
    registry.set_ipv6_routing_fallback(Box::new(MockGenericRoutingDissector));

    // No type-specific dissector for type 2, but fallback should be used
    let d = registry.get_by_ipv6_routing_type(2);
    assert!(d.is_some());
    assert_eq!(d.unwrap().short_name(), "GenRouting");
}

#[test]
fn routing_type_specific_takes_precedence_over_fallback() {
    let mut registry = DissectorRegistry::new();
    registry.set_ipv6_routing_fallback(Box::new(MockGenericRoutingDissector));
    registry
        .register_by_ipv6_routing_type(4, Box::new(MockSrv6Dissector))
        .unwrap();

    // Type 4 should use specific dissector, not fallback
    assert_eq!(
        registry.get_by_ipv6_routing_type(4).unwrap().short_name(),
        "SRv6"
    );
    // Type 2 should use fallback
    assert_eq!(
        registry.get_by_ipv6_routing_type(2).unwrap().short_name(),
        "GenRouting"
    );
}

#[test]
fn chained_dissection_with_routing_type_dispatch() {
    // L2 → L3(proto=43) → RoutingDispatcher(type=4) → SRv6
    let mut registry = DissectorRegistry::new();
    registry.set_entry_dissector(Box::new(MockL2Dissector));
    // Use MockL3Dissector to get to IP protocol 43
    registry
        .register_by_ethertype(0x86DD, Box::new(MockL3Dissector))
        .unwrap();
    registry
        .register_by_ip_protocol(43, Box::new(MockRoutingDispatcher))
        .unwrap();
    registry
        .register_by_ipv6_routing_type(4, Box::new(MockSrv6Dissector))
        .unwrap();

    let data = [
        0x86, 0xDD, 0x00, 0x00, // L2: ethertype=0x86DD
        43, 0x00, 0x00, 0x00, // L3: protocol=43
        // Routing header: NH=6(TCP), HdrExtLen=0, RoutingType=4, SegLeft=1, data
        6, 0, 4, 1, 0, 0, 0, 0,
    ];

    let mut buf = DissectBuffer::new();
    registry.dissect(&data, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3); // L2, L3, SRv6
    assert_eq!(buf.layers()[2].name, "SRv6");
}

#[test]
fn chained_dissection_with_routing_type_fallback() {
    // L2 → L3(proto=43) → RoutingDispatcher(type=99) → GenericRouting (fallback)
    let mut registry = DissectorRegistry::new();
    registry.set_entry_dissector(Box::new(MockL2Dissector));
    registry
        .register_by_ethertype(0x86DD, Box::new(MockL3Dissector))
        .unwrap();
    registry
        .register_by_ip_protocol(43, Box::new(MockRoutingDispatcher))
        .unwrap();
    registry.set_ipv6_routing_fallback(Box::new(MockGenericRoutingDissector));

    let data = [
        0x86, 0xDD, 0x00, 0x00, // L2: ethertype=0x86DD
        43, 0x00, 0x00, 0x00, // L3: protocol=43
        // Routing header: NH=6(TCP), HdrExtLen=0, RoutingType=99, SegLeft=0, data
        6, 0, 99, 0, 0, 0, 0, 0,
    ];

    let mut buf = DissectBuffer::new();
    registry.dissect(&data, &mut buf).unwrap();
    assert_eq!(buf.layers().len(), 3); // L2, L3, GenRouting
    assert_eq!(buf.layers()[2].name, "GenRouting");
}

#[test]
fn default_registry_has_ipv6_routing_fallback() {
    let registry = DissectorRegistry::default();
    // Unknown routing type should still resolve via fallback
    assert!(registry.get_by_ipv6_routing_type(255).is_some());
}
