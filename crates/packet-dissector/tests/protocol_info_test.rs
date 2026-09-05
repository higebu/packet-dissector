//! Tests for `DissectorRegistry::all_protocol_info()`.
//!
//! Verifies that the protocol metadata view stays in lockstep with
//! `all_field_schemas()` and that every built-in dissector declares the
//! specifications it implements and where it sits in the stack.

use packet_dissector::registry::DissectorRegistry;

#[test]
fn all_protocol_info_matches_all_field_schemas() {
    let registry = DissectorRegistry::default();
    let infos = registry.all_protocol_info();
    let schemas = registry.all_field_schemas();

    assert_eq!(
        infos.len(),
        schemas.len(),
        "all_protocol_info() and all_field_schemas() must cover the same dissectors"
    );

    for (info, schema) in infos.iter().zip(schemas.iter()) {
        assert_eq!(
            info.short_name, schema.short_name,
            "all_protocol_info() must use the same order as all_field_schemas()"
        );
        assert_eq!(info.name, schema.name);
        assert!(
            std::ptr::eq(info.fields, schema.fields),
            "{}: fields must be the same descriptors",
            info.short_name
        );
    }
}

/// Every registered dissector must declare the specifications it implements
/// and its position in the dissection stack.
#[test]
fn every_registered_dissector_declares_references_and_layer() {
    let registry = DissectorRegistry::default();

    for info in registry.all_protocol_info() {
        assert!(
            !info.references.is_empty(),
            "{}: references() must not be empty",
            info.short_name
        );
        for reference in info.references {
            assert!(
                !reference.id.is_empty(),
                "{}: reference id must not be empty",
                info.short_name
            );
            assert!(
                !reference.title.is_empty(),
                "{}: reference title must not be empty",
                info.short_name
            );
            assert!(
                reference.url.starts_with("https://"),
                "{}: reference {} url must start with https:// (got {})",
                info.short_name,
                reference.id,
                reference.url
            );
        }
        assert!(
            info.layer.is_some(),
            "{}: layer() must not be None",
            info.short_name
        );
    }
}
