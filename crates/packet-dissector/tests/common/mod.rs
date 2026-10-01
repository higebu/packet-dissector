//! Helpers shared by the facade crate's integration tests.

use std::collections::HashMap;
use std::sync::OnceLock;

use packet_dissector::field::FieldDescriptor;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

/// Field schemas of the default registry, keyed by short name.
fn default_schemas() -> &'static HashMap<&'static str, &'static [FieldDescriptor]> {
    static SCHEMAS: OnceLock<HashMap<&'static str, &'static [FieldDescriptor]>> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        DissectorRegistry::default()
            .all_field_schemas()
            .into_iter()
            .map(|s| (s.short_name, s.fields))
            .collect()
    })
}

/// Assert that every layer in `buf` is listed by
/// [`DissectorRegistry::all_field_schemas`] of the default registry with a
/// non-empty schema, so field discovery covers every layer the registry
/// emits. Only for buffers dissected by a registry with the default
/// dissectors.
pub fn assert_layers_have_schema(buf: &DissectBuffer<'_>) {
    let schemas = default_schemas();
    for layer in buf.layers() {
        let Some(fields) = schemas.get(layer.name) else {
            panic!("layer '{}' is missing from all_field_schemas()", layer.name);
        };
        assert!(
            !fields.is_empty(),
            "layer '{}' has an empty schema in all_field_schemas()",
            layer.name
        );
    }
}
