//! Shared test helpers for the PFCP crate.

use core::ops::Range;

use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// Extract a named field from an Object's children in the buffer.
///
/// Panics if the field is missing.
#[allow(dead_code)]
pub(crate) fn obj_field_buf<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    obj_range: &Range<u32>,
    name: &str,
) -> &'a Field<'pkt> {
    buf.nested_fields(obj_range)
        .iter()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| panic!("field '{name}' not found"))
}

/// Extract a named field's value from an Object's children in the buffer.
///
/// Panics if the field is missing.
#[allow(dead_code)]
pub(crate) fn obj_field_value<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    obj_range: &Range<u32>,
    name: &str,
) -> &'a FieldValue<'pkt> {
    &obj_field_buf(buf, obj_range, name).value
}
