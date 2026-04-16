//! Shared constants and helpers for OSPFv2 and OSPFv3 dissectors.

use packet_dissector_core::field::{FieldDescriptor, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

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

/// Pushes fixed-size LSA headers from a byte slice into the buffer.
///
/// Used by Database Description (Type 2) and Link State Acknowledgment (Type 5)
/// in both OSPFv2 and OSPFv3.
pub(crate) fn push_lsa_headers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    base_offset: usize,
    child_fields: &'static [FieldDescriptor],
    parse_fn: fn(&mut DissectBuffer<'pkt>, &'pkt [u8], usize, &'static [FieldDescriptor]),
) {
    let mut pos = 0;
    while pos + LSA_HEADER_SIZE <= data.len() {
        let abs = base_offset + pos;
        let obj_idx = buf.begin_container(
            &child_fields[0], // use first child descriptor as placeholder
            FieldValue::Object(0..0),
            abs..abs + LSA_HEADER_SIZE,
        );
        parse_fn(buf, &data[pos..pos + LSA_HEADER_SIZE], abs, child_fields);
        buf.end_container(obj_idx);
        pos += LSA_HEADER_SIZE;
    }
}

/// Pushes variable-length LSA entries from a Link State Update body into the buffer.
///
/// The body starts at the `# LSAs` field (4 bytes); this function parses
/// from byte offset 4 onward. Used by LSU (Type 4) in both OSPFv2 and OSPFv3.
pub(crate) fn push_lsu_lsas<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    num_lsas: u32,
    body_offset: usize,
    child_fields: &'static [FieldDescriptor],
    parse_fn: fn(&mut DissectBuffer<'pkt>, &'pkt [u8], usize, &'static [FieldDescriptor]),
) {
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
        let obj_idx = buf.begin_container(
            &child_fields[0],
            FieldValue::Object(0..0),
            abs..abs + lsa_len,
        );
        parse_fn(buf, &body[pos..pos + LSA_HEADER_SIZE], abs, child_fields);
        buf.end_container(obj_idx);
        pos += lsa_len;
    }
}
