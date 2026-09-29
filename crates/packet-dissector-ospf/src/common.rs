//! Shared constants and helpers for OSPFv2 and OSPFv3 dissectors.

use packet_dissector_core::field::{FieldDescriptor, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::tlv::{push_unparsed, set_range_end};

/// LSA header size in bytes.
///
/// - RFC 2328, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.1>
/// - RFC 5340, Appendix A.4.2 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.2>
pub(crate) const LSA_HEADER_SIZE: usize = 20;

/// Link State Request entry size.
///
/// - RFC 2328, Appendix A.3.4 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.4>
/// - RFC 5340, Appendix A.3.4 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.4>
pub(crate) const LSR_ENTRY_SIZE: usize = 12;

/// Returns a human-readable name for OSPF message types.
///
/// Message types 1-5 are shared between OSPFv2 and OSPFv3.
///
/// - RFC 2328, Appendix A.3.1 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.3.1>
/// - RFC 5340, Appendix A.3.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.3.1>
pub(crate) fn msg_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Hello"),
        2 => Some("Database Description"),
        3 => Some("Link State Request"),
        4 => Some("Link State Update"),
        5 => Some("Link State Acknowledgment"),
        _ => None,
    }
}

/// Pushes an `array` of fixed-size LSA headers from a byte slice.
///
/// Each header becomes a `container` object; a trailing partial header is
/// pushed as `unparsed`. Used by Database Description (Type 2) and Link
/// State Acknowledgment (Type 5) in both OSPFv2 and OSPFv3.
pub(crate) fn push_lsa_headers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array: &'static FieldDescriptor,
    data: &'pkt [u8],
    base_offset: usize,
    container: &'static FieldDescriptor,
    parse_fn: fn(&mut DissectBuffer<'pkt>, &'pkt [u8], usize),
) {
    let array_idx = buf.begin_container(
        array,
        FieldValue::Array(0..0),
        base_offset..base_offset + data.len(),
    );
    let mut pos = 0;
    while pos + LSA_HEADER_SIZE <= data.len() {
        let abs = base_offset + pos;
        let obj_idx = buf.begin_container(
            container,
            FieldValue::Object(0..0),
            abs..abs + LSA_HEADER_SIZE,
        );
        parse_fn(buf, &data[pos..pos + LSA_HEADER_SIZE], abs);
        buf.end_container(obj_idx);
        pos += LSA_HEADER_SIZE;
    }
    buf.end_container(array_idx);
    set_range_end(buf, array_idx, base_offset + pos);
    push_unparsed(buf, &data[pos..], base_offset + pos);
}

/// Pushes an `array` of variable-length LSAs from a Link State Update body.
///
/// The body starts at the `# LSAs` field (4 bytes); this function parses
/// from byte offset 4 onward. Each LSA becomes a `container` object and
/// `parse_fn` receives the whole LSA as delimited by its `length` field.
/// Bytes after the last LSA that could be delimited are pushed as
/// `unparsed`. Used by LSU (Type 4) in both OSPFv2 and OSPFv3.
pub(crate) fn push_lsu_lsas<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array: &'static FieldDescriptor,
    body: &'pkt [u8],
    num_lsas: u32,
    body_offset: usize,
    container: &'static FieldDescriptor,
    parse_fn: fn(&mut DissectBuffer<'pkt>, &'pkt [u8], usize),
) {
    let array_idx = buf.begin_container(
        array,
        FieldValue::Array(0..0),
        body_offset + 4..body_offset + body.len(),
    );
    let mut pos: usize = 4;
    for _ in 0..num_lsas {
        if pos + LSA_HEADER_SIZE > body.len() {
            break;
        }
        let lsa_len = read_be_u16(body, pos + 18).unwrap_or_default() as usize;
        if lsa_len < LSA_HEADER_SIZE || pos + lsa_len > body.len() {
            break;
        }
        let abs = body_offset + pos;
        let obj_idx = buf.begin_container(container, FieldValue::Object(0..0), abs..abs + lsa_len);
        parse_fn(buf, &body[pos..pos + lsa_len], abs);
        buf.end_container(obj_idx);
        pos += lsa_len;
    }
    buf.end_container(array_idx);
    set_range_end(buf, array_idx, body_offset + pos);
    push_unparsed(buf, &body[pos..], body_offset + pos);
}

/// Helpers shared by the OSPFv2 and OSPFv3 unit tests.
#[cfg(test)]
pub(crate) mod test_util {
    use core::ops::Range;

    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::DissectBuffer;

    /// Returns the direct children of a container, skipping the descendants
    /// of nested containers.
    pub(crate) fn children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &Range<u32>,
    ) -> Vec<&'a Field<'pkt>> {
        let all = buf.nested_fields(range);
        let mut out = Vec::new();
        let mut i = 0;
        while i < all.len() {
            out.push(&all[i]);
            i += match all[i].value.as_container_range() {
                Some(r) => (r.end - r.start) as usize + 1,
                None => 1,
            };
        }
        out
    }

    /// Returns the direct child named `name`, panicking if it is missing.
    pub(crate) fn child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &Range<u32>,
        name: &str,
    ) -> &'a Field<'pkt> {
        children(buf, range)
            .into_iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("missing child field {name}"))
    }

    /// Returns whether a direct child named `name` exists.
    pub(crate) fn has_child(buf: &DissectBuffer<'_>, range: &Range<u32>, name: &str) -> bool {
        children(buf, range).iter().any(|f| f.name() == name)
    }

    /// Returns the child range of a container field.
    pub(crate) fn range(field: &Field<'_>) -> Range<u32> {
        field
            .value
            .as_container_range()
            .unwrap_or_else(|| panic!("{} is not a container", field.name()))
            .clone()
    }

    /// Returns the direct child `name` and asserts it equals `expected`.
    pub(crate) fn assert_child(
        buf: &DissectBuffer<'_>,
        range: &Range<u32>,
        name: &str,
        expected: FieldValue<'_>,
    ) {
        assert_eq!(child(buf, range, name).value, expected, "field {name}");
    }

    /// Returns the index of `field` within the buffer's flat field list.
    pub(crate) fn index_of(buf: &DissectBuffer<'_>, field: &Field<'_>) -> u32 {
        buf.fields()
            .iter()
            .position(|f| core::ptr::eq(f, field))
            .expect("field not in buffer") as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # Shared helper coverage
    //
    // | RFC Section              | Description                    | Test                        |
    // |--------------------------|--------------------------------|-----------------------------|
    // | RFC 2328 A.3.1           | Message type names             | msg_type_names              |
    // | RFC 2328 A.3.5           | # LSAs larger than the body    | lsu_stops_when_body_ends    |

    #[test]
    fn msg_type_names() {
        let names: Vec<_> = (0..=6).map(msg_type_name).collect();
        assert_eq!(
            names,
            [
                None,
                Some("Hello"),
                Some("Database Description"),
                Some("Link State Request"),
                Some("Link State Update"),
                Some("Link State Acknowledgment"),
                None,
            ]
        );
    }

    fn noop(_: &mut DissectBuffer<'_>, _: &[u8], _: usize) {}

    #[test]
    fn lsu_stops_when_body_ends() {
        static FD: FieldDescriptor =
            FieldDescriptor::new("x", "X", packet_dissector_core::field::FieldType::Array);
        let body = [0, 0, 0, 5, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        push_lsu_lsas(&mut buf, &FD, &body, 5, 0, &FD, noop);
        assert_eq!(buf.fields()[0].range, 4..4);
        assert_eq!(buf.fields()[1].value, FieldValue::Bytes(&[0, 0, 0]));
    }
}
