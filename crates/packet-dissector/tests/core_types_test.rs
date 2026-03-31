use packet_dissector::dissector::DispatchHint;
use packet_dissector::field::{Field, FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector::packet::DissectBuffer;

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

// --- FieldType and FieldDescriptor tests ---

#[test]
fn field_type_all_variants_are_distinct() {
    let types = [
        FieldType::U8,
        FieldType::U16,
        FieldType::U32,
        FieldType::U64,
        FieldType::I32,
        FieldType::Bytes,
        FieldType::Ipv4Addr,
        FieldType::Ipv6Addr,
        FieldType::MacAddr,
        FieldType::Str,
        FieldType::Array,
        FieldType::Object,
    ];
    for (i, a) in types.iter().enumerate() {
        for (j, b) in types.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn field_type_is_copy_and_hashable() {
    let t = FieldType::U16;
    let t2 = t; // Copy
    assert_eq!(t, t2);

    // Hash: put into HashSet
    let mut set = std::collections::HashSet::new();
    set.insert(FieldType::U8);
    set.insert(FieldType::U16);
    set.insert(FieldType::U8); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn field_value_field_type_returns_matching_variant() {
    assert_eq!(FieldValue::U8(0).field_type(), FieldType::U8);
    assert_eq!(FieldValue::U16(0).field_type(), FieldType::U16);
    assert_eq!(FieldValue::U32(0).field_type(), FieldType::U32);
    assert_eq!(FieldValue::U64(0).field_type(), FieldType::U64);
    assert_eq!(FieldValue::I32(0).field_type(), FieldType::I32);
    assert_eq!(FieldValue::Bytes(&[]).field_type(), FieldType::Bytes);
    assert_eq!(
        FieldValue::Ipv4Addr([0; 4]).field_type(),
        FieldType::Ipv4Addr
    );
    assert_eq!(
        FieldValue::Ipv6Addr([0; 16]).field_type(),
        FieldType::Ipv6Addr
    );
    assert_eq!(
        FieldValue::MacAddr(MacAddr([0; 6])).field_type(),
        FieldType::MacAddr
    );
    assert_eq!(FieldValue::Str("").field_type(), FieldType::Str);
    assert_eq!(FieldValue::Array(0..0).field_type(), FieldType::Array);
    assert_eq!(FieldValue::Object(0..0).field_type(), FieldType::Object);
}

#[test]
fn field_descriptor_construction() {
    let desc = FieldDescriptor {
        name: "src_port",
        display_name: "Source Port",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    };
    assert_eq!(desc.name, "src_port");
    assert_eq!(desc.display_name, "Source Port");
    assert_eq!(desc.field_type, FieldType::U16);
    assert!(!desc.optional);
}

#[test]
fn field_descriptor_optional_flag() {
    let required = FieldDescriptor {
        name: "version",
        display_name: "Version",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    };
    let optional = FieldDescriptor {
        name: "options",
        display_name: "Options",
        field_type: FieldType::Bytes,
        optional: true,
        children: None,
        display_fn: None,
        format_fn: None,
    };
    assert!(!required.optional);
    assert!(optional.optional);
    assert_ne!(required, optional);
}

#[test]
fn mac_addr_display() {
    let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
}

#[test]
fn mac_addr_display_leading_zeros() {
    let mac = MacAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(mac.to_string(), "01:02:03:04:05:06");
}

#[test]
fn field_value_variants() {
    assert_eq!(FieldValue::U8(42), FieldValue::U8(42));
    assert_ne!(FieldValue::U8(1), FieldValue::U16(1));

    let bytes = FieldValue::Bytes(&[0xde, 0xad]);
    assert_eq!(bytes, FieldValue::Bytes(&[0xde, 0xad]));

    let ipv4 = FieldValue::Ipv4Addr([192, 168, 1, 1]);
    assert_eq!(ipv4, FieldValue::Ipv4Addr([192, 168, 1, 1]));

    let ipv6 = FieldValue::Ipv6Addr([0; 16]);
    assert_eq!(ipv6, FieldValue::Ipv6Addr([0; 16]));

    let mac = FieldValue::MacAddr(MacAddr([0; 6]));
    assert_eq!(mac, FieldValue::MacAddr(MacAddr([0; 6])));

    let s = FieldValue::Str("hello");
    assert_eq!(s, FieldValue::Str("hello"));

    assert_eq!(FieldValue::U8(1), FieldValue::U8(1));
    assert_eq!(FieldValue::U32(0x1234), FieldValue::U32(0x1234));
    assert_eq!(FieldValue::U64(0xdead_beef), FieldValue::U64(0xdead_beef));
}

#[test]
fn field_construction() {
    let field = Field {
        descriptor: test_desc("src_port", "Src Port"),
        value: FieldValue::U16(80),
        range: 0..2,
    };
    assert_eq!(field.name(), "src_port");
    assert_eq!(field.value, FieldValue::U16(80));
    assert_eq!(field.range, 0..2);
}

#[test]
fn dissect_buffer_layer_field_lookup() {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("Test", None, &[], 0..4);
    buf.push_field(test_desc("src", "Src"), FieldValue::U16(1234), 0..2);
    buf.push_field(test_desc("dst", "Dst"), FieldValue::U16(80), 2..4);
    buf.end_layer();

    let layer = buf.layer_by_name("Test").unwrap();
    let src = buf.field_by_name(layer, "src").unwrap();
    assert_eq!(src.value, FieldValue::U16(1234));

    let dst = buf.field_by_name(layer, "dst").unwrap();
    assert_eq!(dst.value, FieldValue::U16(80));

    assert!(buf.field_by_name(layer, "nonexistent").is_none());
}

#[test]
fn dissect_buffer_add_and_lookup_layers() {
    let mut buf = DissectBuffer::new();
    assert!(buf.layers().is_empty());

    buf.begin_layer("Ethernet", None, &[], 0..14);
    buf.end_layer();
    buf.begin_layer("IPv4", None, &[], 14..34);
    buf.end_layer();

    assert_eq!(buf.layers().len(), 2);

    let eth = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(eth.name, "Ethernet");

    let ip = buf.layer_by_name("IPv4").unwrap();
    assert_eq!(ip.name, "IPv4");

    assert!(buf.layer_by_name("Unknown").is_none());
}

#[test]
fn dissect_buffer_default() {
    let buf = DissectBuffer::default();
    assert!(buf.layers().is_empty());
}

#[test]
fn next_dissector_by_tcp_port() {
    let nd = DispatchHint::ByTcpPort(54321, 80);
    assert_eq!(nd, DispatchHint::ByTcpPort(54321, 80));
    assert_ne!(nd, DispatchHint::ByTcpPort(54321, 443));
    assert_ne!(nd, DispatchHint::ByUdpPort(54321, 80));
}

#[test]
fn next_dissector_by_udp_port() {
    let nd = DispatchHint::ByUdpPort(12345, 53);
    assert_eq!(nd, DispatchHint::ByUdpPort(12345, 53));
    assert_ne!(nd, DispatchHint::ByUdpPort(12345, 123));
    assert_ne!(nd, DispatchHint::ByTcpPort(12345, 53));
}

#[test]
fn layers_by_name_returns_all_matching() {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.push_field(
        test_desc("src", "Src"),
        FieldValue::Ipv4Addr([10, 0, 0, 1]),
        14..18,
    );
    buf.end_layer();
    buf.begin_layer("GRE", None, &[], 20..24);
    buf.end_layer();
    buf.begin_layer("IPv4", None, &[], 24..44);
    buf.push_field(
        test_desc("src", "Src"),
        FieldValue::Ipv4Addr([192, 168, 1, 1]),
        28..32,
    );
    buf.end_layer();

    let ipv4_layers: Vec<_> = buf.layers().iter().filter(|l| l.name == "IPv4").collect();
    assert_eq!(ipv4_layers.len(), 2);
    assert_eq!(
        buf.field_by_name(ipv4_layers[0], "src").unwrap().value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
    assert_eq!(
        buf.field_by_name(ipv4_layers[1], "src").unwrap().value,
        FieldValue::Ipv4Addr([192, 168, 1, 1])
    );
}

#[test]
fn layers_by_name_returns_empty_for_no_match() {
    let buf = DissectBuffer::new();
    let ipv4_layers: Vec<_> = buf.layers().iter().filter(|l| l.name == "IPv4").collect();
    assert!(ipv4_layers.is_empty());
}

#[test]
fn field_array_access() {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("Test", None, &[], 0..40);
    let arr_idx = buf.begin_container(
        test_desc("segments", "Segments"),
        FieldValue::Array(0..0),
        8..40,
    );
    buf.push_field(
        test_desc("seg0", "Seg0"),
        FieldValue::Ipv6Addr([0; 16]),
        8..24,
    );
    buf.push_field(
        test_desc("seg1", "Seg1"),
        FieldValue::Ipv6Addr([1; 16]),
        24..40,
    );
    buf.end_container(arr_idx);
    buf.push_field(test_desc("scalar", "Scalar"), FieldValue::U8(42), 0..1);
    buf.end_layer();

    let layer = buf.layer_by_name("Test").unwrap();
    let segments_field = buf.field_by_name(layer, "segments").unwrap();
    let FieldValue::Array(ref range) = segments_field.value else {
        panic!("expected Array")
    };
    let segments = buf.nested_fields(range);
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].value, FieldValue::Ipv6Addr([0; 16]));
    assert_eq!(segments[1].value, FieldValue::Ipv6Addr([1; 16]));

    // Non-array field
    let scalar = buf.field_by_name(layer, "scalar").unwrap();
    assert!(!scalar.value.is_array());
}

#[test]
fn field_value_array_variant() {
    let arr = FieldValue::Array(0..2);
    assert_eq!(arr, FieldValue::Array(0..2));
    assert_eq!(FieldValue::Array(0..0), FieldValue::Array(0..0));
    assert_ne!(arr, FieldValue::Array(0..0));
}

#[test]
fn field_value_object_variant() {
    let obj = FieldValue::Object(0..2);
    assert_eq!(obj, FieldValue::Object(0..2));
    assert_eq!(FieldValue::Object(0..0), FieldValue::Object(0..0));
    assert_ne!(obj, FieldValue::Object(0..0));
}

#[test]
fn field_value_array_with_objects() {
    // Simulate TLV entries: Array containing an Object with child fields
    let mut buf = DissectBuffer::new();
    buf.begin_layer("Test", None, &[], 0..4);
    let arr_idx = buf.begin_container(test_desc("tlvs", "TLVs"), FieldValue::Array(0..0), 0..4);
    let obj_idx = buf.begin_container(test_desc("entry", "Entry"), FieldValue::Object(0..0), 0..4);
    buf.push_field(test_desc("type", "Type"), FieldValue::U8(4), 0..1);
    buf.push_field(test_desc("length", "Length"), FieldValue::U8(2), 1..2);
    buf.end_container(obj_idx);
    buf.end_container(arr_idx);
    buf.end_layer();

    let layer = buf.layer_by_name("Test").unwrap();
    let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
    let FieldValue::Array(ref arr_range) = tlvs_field.value else {
        panic!("expected Array")
    };
    let arr = buf.nested_fields(arr_range);
    let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(objects.len(), 1);
    let FieldValue::Object(ref obj_range) = objects[0].value else {
        panic!("expected Object")
    };
    let sub = buf.nested_fields(obj_range);
    assert_eq!(sub.len(), 2);
    assert_eq!(sub[0].name(), "type");
    assert_eq!(sub[0].value, FieldValue::U8(4));
}

#[test]
fn field_value_is_predicates() {
    assert!(FieldValue::Array(0..0).is_array());
    assert!(!FieldValue::Array(0..0).is_object());
    assert!(FieldValue::Object(0..0).is_object());
    assert!(!FieldValue::Object(0..0).is_array());
    assert!(!FieldValue::U8(0).is_array());
    assert!(!FieldValue::U8(0).is_object());
}

#[test]
fn field_value_scalar_accessors() {
    assert_eq!(FieldValue::U8(42).as_u8(), Some(42));
    assert_eq!(FieldValue::U16(1000).as_u16(), Some(1000));
    assert_eq!(FieldValue::U32(100_000).as_u32(), Some(100_000));
    assert_eq!(FieldValue::U64(1_000_000).as_u64(), Some(1_000_000));
    assert_eq!(FieldValue::Str("hi").as_str(), Some("hi"));
    assert_eq!(
        FieldValue::Bytes(&[1, 2]).as_bytes(),
        Some([1u8, 2].as_slice())
    );

    // Wrong type returns None
    assert!(FieldValue::U8(1).as_u16().is_none());
    assert!(FieldValue::U16(1).as_u8().is_none());
    assert!(FieldValue::U32(1).as_u64().is_none());
    assert!(FieldValue::Str("hi").as_u8().is_none());
    assert!(FieldValue::U8(1).as_str().is_none());
    assert!(FieldValue::U8(1).as_bytes().is_none());
}

#[test]
fn field_object_access() {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("Test", None, &[], 0..3);
    let obj_idx = buf.begin_container(
        test_desc("header", "Header"),
        FieldValue::Object(0..0),
        0..3,
    );
    buf.push_field(test_desc("version", "Version"), FieldValue::U8(4), 0..1);
    buf.push_field(test_desc("length", "Length"), FieldValue::U16(20), 1..3);
    buf.end_container(obj_idx);
    buf.end_layer();

    let layer = buf.layer_by_name("Test").unwrap();
    let header_field = buf.field_by_name(layer, "header").unwrap();
    let FieldValue::Object(ref obj_range) = header_field.value else {
        panic!("expected Object")
    };
    let header = buf.nested_fields(obj_range);
    assert_eq!(header.len(), 2);
    assert_eq!(header[0].name(), "version");
    assert_eq!(header[0].value, FieldValue::U8(4));

    // Non-object field
    assert!(buf.field_by_name(layer, "nonexistent").is_none());
}
