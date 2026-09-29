//! Type Bit Maps field shared by NSEC, NSEC3 and CSYNC.
//!
//! ## References
//! - RFC 4034, Section 4.1.2: <https://www.rfc-editor.org/rfc/rfc4034#section-4.1.2>
//! - RFC 5155, Section 3.2.1 (NSEC3 reuses the NSEC encoding): <https://www.rfc-editor.org/rfc/rfc5155#section-3.2.1>
//! - RFC 7477, Section 2.1.1 (CSYNC reuses the NSEC encoding): <https://www.rfc-editor.org/rfc/rfc7477#section-2.1.1>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::dns_type_name;

/// Element descriptor for one RR type in a decoded type bit map.
pub(crate) static FD_BITMAP_TYPE: FieldDescriptor = FieldDescriptor {
    name: "type",
    display_name: "Type",
    field_type: FieldType::U16,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U16(t) => dns_type_name(*t),
        _ => None,
    }),
    format_fn: None,
};

/// Check that `bitmap` is a well-formed Type Bit Maps field.
///
/// RFC 4034, Section 4.1.2 — <https://www.rfc-editor.org/rfc/rfc4034#section-4.1.2>:
/// each block is Window Block # (1 octet), Bitmap Length (1 octet, 1 to 32)
/// and the Bitmap, and "Blocks are present in the NSEC RR RDATA in
/// increasing numerical order."
fn is_well_formed(bitmap: &[u8]) -> bool {
    let mut pos = 0;
    let mut last_window: Option<u8> = None;
    while pos < bitmap.len() {
        if pos + 2 > bitmap.len() {
            return false;
        }
        let window = bitmap[pos];
        let len = bitmap[pos + 1] as usize;
        if !(1..=32).contains(&len) || pos + 2 + len > bitmap.len() {
            return false;
        }
        if last_window.is_some_and(|w| window <= w) {
            return false;
        }
        last_window = Some(window);
        pos += 2 + len;
    }
    true
}

/// Push `array_fd` as an Array of the RR types present in `bitmap`.
///
/// `abs_offset` is the absolute offset of `bitmap`. Each element's range is
/// the bitmap octet that carries its bit. Nothing is pushed if the bit map
/// is malformed; the caller keeps the raw bytes in that case.
pub(crate) fn push_type_bitmap<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array_fd: &'static FieldDescriptor,
    bitmap: &'pkt [u8],
    abs_offset: usize,
) {
    if bitmap.is_empty() || !is_well_formed(bitmap) {
        return;
    }
    let arr = buf.begin_container(
        array_fd,
        FieldValue::Array(0..0),
        abs_offset..abs_offset + bitmap.len(),
    );
    let mut pos = 0;
    while pos + 2 <= bitmap.len() {
        let window = bitmap[pos] as u16;
        let len = bitmap[pos + 1] as usize;
        for (i, &octet) in bitmap[pos + 2..pos + 2 + len].iter().enumerate() {
            for bit in 0..8u16 {
                // "Bits representing pseudo-types MUST be clear, as they do
                // not appear in zone data.  If encountered, they MUST be
                // ignored upon being read." Ignoring them is for resolvers;
                // the dissector reports every set bit as it is on the wire.
                if octet & (0x80 >> bit) != 0 {
                    let rtype = (window << 8) | ((i as u16) << 3) | bit;
                    let at = abs_offset + pos + 2 + i;
                    buf.push_field(&FD_BITMAP_TYPE, FieldValue::U16(rtype), at..at + 1);
                }
            }
        }
        pos += 2 + len;
    }
    buf.end_container(arr);
}
