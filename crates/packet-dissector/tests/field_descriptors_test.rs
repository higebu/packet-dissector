//! Tests for `Dissector::field_descriptors()` across all built-in protocol dissectors.
//!
//! Verifies that each dissector returns correct field metadata and that the
//! metadata is consistent with actual dissection output.

use packet_dissector::dissector::Dissector;
use packet_dissector::field::{FieldDescriptor, FieldType};
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

// --- Helper: verify that field_descriptors() names are unique ---

fn assert_names_unique(dissector: &dyn Dissector) {
    let descriptors = dissector.field_descriptors();
    let mut names: Vec<&str> = descriptors.iter().map(|d| d.name).collect();
    let original_len = names.len();
    names.sort();
    names.dedup();
    assert_eq!(
        names.len(),
        original_len,
        "{}: field_descriptors() has duplicate names",
        dissector.short_name()
    );
}

// --- Per-protocol field_descriptors() tests ---

#[test]
fn ethernet_field_descriptors() {
    use packet_dissector::dissectors::ethernet::EthernetDissector;
    let d = EthernetDissector;
    let descs = d.field_descriptors();

    // Must have dst, src as required; ethertype, VLAN, LLC fields as optional
    let dst = descs.iter().find(|d| d.name == "dst").unwrap();
    assert_eq!(dst.field_type, FieldType::MacAddr);
    assert!(!dst.optional);

    let src = descs.iter().find(|d| d.name == "src").unwrap();
    assert_eq!(src.field_type, FieldType::MacAddr);
    assert!(!src.optional);

    // ethertype is optional (absent in LLC frames)
    let ethertype = descs.iter().find(|d| d.name == "ethertype").unwrap();
    assert_eq!(ethertype.field_type, FieldType::U16);
    assert!(ethertype.optional);

    // VLAN fields must be optional
    for name in &["vlan_tpid", "vlan_pcp", "vlan_dei", "vlan_id"] {
        let vlan = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(vlan.optional, "VLAN field {name} should be optional");
    }

    // LLC fields must be optional
    for name in &["length", "llc_dsap", "llc_ssap", "llc_control"] {
        let llc = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(llc.optional, "LLC field {name} should be optional");
    }

    assert_names_unique(&d);
}

#[test]
fn ipv4_field_descriptors() {
    use packet_dissector::dissectors::ipv4::Ipv4Dissector;
    let d = Ipv4Dissector;
    let descs = d.field_descriptors();

    // Fixed fields
    for name in &[
        "version",
        "ihl",
        "dscp",
        "ecn",
        "total_length",
        "identification",
        "flags",
        "fragment_offset",
        "ttl",
        "protocol",
        "checksum",
        "src",
        "dst",
    ] {
        let field = descs
            .iter()
            .find(|d| d.name == *name)
            .unwrap_or_else(|| panic!("IPv4 missing field: {name}"));
        assert!(!field.optional, "IPv4 field {name} should be required");
    }

    // src/dst are Ipv4Addr
    assert_eq!(
        descs.iter().find(|d| d.name == "src").unwrap().field_type,
        FieldType::Ipv4Addr
    );
    assert_eq!(
        descs.iter().find(|d| d.name == "dst").unwrap().field_type,
        FieldType::Ipv4Addr
    );

    // options is optional
    let options = descs.iter().find(|d| d.name == "options").unwrap();
    assert!(options.optional);
    assert_eq!(options.field_type, FieldType::Bytes);

    assert_names_unique(&d);
}

#[test]
fn udp_field_descriptors() {
    use packet_dissector::dissectors::udp::UdpDissector;
    let d = UdpDissector;
    let descs = d.field_descriptors();

    assert_eq!(descs.len(), 4);
    assert_eq!(descs[0].name, "src_port");
    assert_eq!(descs[0].field_type, FieldType::U16);
    assert_eq!(descs[1].name, "dst_port");
    assert_eq!(descs[2].name, "length");
    assert_eq!(descs[3].name, "checksum");

    // All required
    assert!(descs.iter().all(|d| !d.optional));
    assert_names_unique(&d);
}

#[test]
fn tcp_field_descriptors() {
    use packet_dissector::dissectors::tcp::TcpDissector;
    let d = TcpDissector::new();
    let descs = d.field_descriptors();

    // Has options as optional
    let options = descs.iter().find(|d| d.name == "options").unwrap();
    assert!(options.optional);

    // Fixed fields are required
    for name in &[
        "src_port",
        "dst_port",
        "seq",
        "ack",
        "data_offset",
        "flags",
        "window",
        "checksum",
        "urgent_pointer",
    ] {
        let field = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(!field.optional, "TCP field {name} should be required");
    }

    assert_names_unique(&d);
}

#[test]
fn ipv6_field_descriptors() {
    use packet_dissector::dissectors::ipv6::Ipv6Dissector;
    let d = Ipv6Dissector;
    let descs = d.field_descriptors();

    assert_eq!(descs.len(), 8);
    assert_eq!(
        descs.iter().find(|d| d.name == "src").unwrap().field_type,
        FieldType::Ipv6Addr
    );
    assert_eq!(
        descs.iter().find(|d| d.name == "dst").unwrap().field_type,
        FieldType::Ipv6Addr
    );

    // next_header_name is now handled by display_fn on the "next_header" descriptor
    let next_header = descs.iter().find(|d| d.name == "next_header").unwrap();
    assert!(next_header.display_fn.is_some());

    // All IPv6 fields should be required
    for desc in descs.iter() {
        assert!(
            !desc.optional,
            "IPv6 field {} should be required",
            desc.name
        );
    }
    assert_names_unique(&d);
}

#[test]
fn arp_field_descriptors() {
    use packet_dissector::dissectors::arp::ArpDissector;
    let d = ArpDissector;
    let descs = d.field_descriptors();

    // 9 RFC 826 fields + optional `kind` for RFC 5227 classification.
    assert_eq!(descs.len(), 10);
    assert_eq!(
        descs.iter().find(|d| d.name == "sha").unwrap().field_type,
        FieldType::MacAddr
    );
    assert_eq!(
        descs.iter().find(|d| d.name == "spa").unwrap().field_type,
        FieldType::Ipv4Addr
    );
    // oper_name is now handled by display_fn on the "oper" descriptor
    let oper = descs.iter().find(|d| d.name == "oper").unwrap();
    assert!(oper.display_fn.is_some());
    // htype / ptype also get IANA-derived display names via display_fn.
    let htype = descs.iter().find(|d| d.name == "htype").unwrap();
    assert!(htype.display_fn.is_some());
    let ptype = descs.iter().find(|d| d.name == "ptype").unwrap();
    assert!(ptype.display_fn.is_some());
    // RFC 5227 classification is emitted only for matching packets.
    let kind = descs.iter().find(|d| d.name == "kind").unwrap();
    assert!(kind.optional);
    assert_eq!(kind.field_type, FieldType::Str);
    assert_names_unique(&d);
}

#[test]
fn icmp_field_descriptors_have_common_required_fields() {
    use packet_dissector::dissectors::icmp::IcmpDissector;
    let d = IcmpDissector;
    let descs = d.field_descriptors();

    // type, code, checksum are always present
    for name in &["type", "code", "checksum"] {
        let field = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(!field.optional, "ICMP {name} should be required");
    }

    // type-specific fields should be optional
    for name in &[
        "identifier",
        "sequence_number",
        "gateway",
        "invoking_packet",
    ] {
        let field = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(field.optional, "ICMP {name} should be optional");
    }
    assert_names_unique(&d);
}

#[test]
fn dns_field_descriptors() {
    use packet_dissector::dissectors::dns::DnsDissector;
    let d = DnsDissector;
    let descs = d.field_descriptors();

    // Header fields required
    for name in &["id", "qr", "opcode", "qdcount", "ancount"] {
        let field = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(!field.optional, "DNS {name} should be required");
    }

    // Section arrays are optional (may be empty/absent)
    let questions = descs.iter().find(|d| d.name == "questions").unwrap();
    assert!(questions.optional);
    assert_eq!(questions.field_type, FieldType::Array);

    // questions has child field descriptors
    let q_children = questions.children.expect("questions should have children");
    assert_eq!(q_children.len(), 3);
    assert_eq!(q_children[0].name, "name");
    assert_eq!(q_children[1].name, "type");
    assert!(
        q_children[1].display_fn.is_some(),
        "type should have display_fn"
    );
    assert_eq!(q_children[2].name, "class");
    assert!(
        q_children[2].display_fn.is_some(),
        "class should have display_fn"
    );

    // answers/authorities/additionals have RR child fields
    for section in &["answers", "authorities", "additionals"] {
        let desc = descs.iter().find(|d| d.name == *section).unwrap();
        let children = desc
            .children
            .unwrap_or_else(|| panic!("{section} should have children"));
        // Must contain common RR fields
        assert!(
            children.iter().any(|c| c.name == "name"),
            "{section} children should include 'name'"
        );
        assert!(
            children.iter().any(|c| c.name == "rdata"),
            "{section} children should include 'rdata'"
        );
    }

    assert_names_unique(&d);
}

#[test]
fn all_field_schemas_prefers_udp_dns_over_tcp() {
    let registry = DissectorRegistry::default();
    let schemas = registry.all_field_schemas();

    let dns_schema = schemas
        .iter()
        .find(|s| s.short_name == "DNS")
        .expect("DNS schema should be present");

    // The UDP variant ("Domain Name System") should win over TCP ("DNS over TCP")
    assert_eq!(
        dns_schema.name, "Domain Name System",
        "all_field_schemas() should prefer UDP DNS"
    );

    // The UDP variant includes tcp_length as optional so both variants are covered
    let tcp_length = dns_schema
        .fields
        .iter()
        .find(|f| f.name == "tcp_length")
        .expect("DNS schema should include tcp_length");
    assert!(
        tcp_length.optional,
        "tcp_length should be optional in the UDP DNS schema"
    );
}

#[test]
fn srv6_field_descriptors() {
    use packet_dissector::dissectors::srv6::Srv6Dissector;
    let d = Srv6Dissector::new();
    let descs = d.field_descriptors();

    let segments = descs.iter().find(|d| d.name == "segments").unwrap();
    assert_eq!(segments.field_type, FieldType::Array);
    assert!(!segments.optional);

    // SID structure and TLVs are optional
    for name in &["segments_structure", "csid_containers", "tlvs"] {
        let field = descs.iter().find(|d| d.name == *name).unwrap();
        assert!(field.optional, "SRv6 {name} should be optional");
    }

    assert_names_unique(&d);
}

// --- Consistency test: field_descriptors() vs actual dissect() output ---

#[test]
fn field_descriptors_consistent_with_dissect_for_ethernet_ipv4_udp() {
    let registry = DissectorRegistry::default();

    // Ethernet + IPv4 + UDP packet
    let data: &[u8] = &[
        // Ethernet
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src
        0x08, 0x00, // EtherType: IPv4
        // IPv4
        0x45, 0x00, 0x00, 0x1c, // ver=4, ihl=5, len=28
        0x00, 0x00, 0x00, 0x00, // id, flags, frag
        0x40, 0x11, 0x00, 0x00, // ttl=64, proto=UDP
        0x0a, 0x00, 0x00, 0x01, // src
        0x0a, 0x00, 0x00, 0x02, // dst
        // UDP
        0x30, 0x39, 0x00, 0x50, // src=12345, dst=80
        0x00, 0x08, 0x00, 0x00, // len=8, checksum
    ];

    let mut buf = DissectBuffer::new();
    registry.dissect(data, &mut buf).unwrap();
    let schemas = registry.all_field_schemas();

    for layer in buf.layers() {
        let schema = schemas
            .iter()
            .find(|s| s.short_name == layer.name)
            .unwrap_or_else(|| panic!("No schema for layer {}", layer.name));

        // Every field produced by dissect() must be declared in field_descriptors()
        for field in buf.layer_fields(layer) {
            let descriptor = schema
                .fields
                .iter()
                .find(|d: &&FieldDescriptor| d.name == field.name())
                .unwrap_or_else(|| {
                    panic!(
                        "Field '{}' in {} not found in field_descriptors()",
                        field.name(),
                        layer.name
                    )
                });
            assert_eq!(
                field.value.field_type(),
                descriptor.field_type,
                "Type mismatch for {}.{}",
                layer.name,
                field.name()
            );
        }
    }
}
