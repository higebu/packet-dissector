//! ProtocolIE-Container and ProtocolIE-Field decoding.
//!
//! ## References
//! - 3GPP TS 36.413 v19.2.0, Section 9.3.7 (Container Definitions):
//!   <https://www.3gpp.org/ftp/Specs/archive/36_series/36.413/>
//! - ITU-T Rec. X.691 (APER), Sections 11.2 (open types), 11.5.7
//!   (constrained whole numbers), 11.9 (length determinants):
//!   <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_per::ap::{ensure_consumed, skip_sequence_extension_additions};
use packet_dissector_per::{AperReader, Extent, read_extent};

use crate::{criticality_name, ie_id, ie_parsers};

/// Where an IE is decoded.
///
/// E-RAB lists are only decoded in the IE container of a message; inside
/// a list item they are kept raw, which bounds the nesting depth.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IeContext {
    /// The IE container of an S1AP message.
    Message,
    /// A `ProtocolIE-SingleContainer` item of an E-RAB list.
    Item,
}

const CFD_ID: usize = 0;
const CFD_CRITICALITY: usize = 1;
const CFD_LENGTH: usize = 2;
const CFD_VALUE: usize = 3;

/// Descriptor for one ProtocolIE-Field object; its label resolves to the
/// IE name.
static FD_IE: FieldDescriptor = FieldDescriptor {
    name: "ie",
    display_name: "IE",
    field_type: FieldType::Object,
    optional: false,
    children: Some(IE_CHILD_FIELDS),
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("id", FieldValue::U16(id)) => Some(ie_id::ie_id_name(*id)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// The common fields of each ProtocolIE-Field object. Decoded values add
/// the fields of [`ie_parsers::VALUE_FIELDS`] instead of `value`.
///
/// 3GPP TS 36.413, Section 9.3.7 — `ProtocolIE-Field ::= SEQUENCE { id,
/// criticality, value }`.
pub(crate) static IE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("id", "ID", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(id) => Some(ie_id::ie_id_name(*id)),
        _ => None,
    }),
    FieldDescriptor::new("criticality", "Criticality", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => criticality_name(*c),
            _ => None,
        },
    ),
    FieldDescriptor::new("length", "Length", FieldType::U32),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// Reason the IE container of the message could not be decoded completely.
pub(crate) static FD_IE_CONTAINER_ERROR: FieldDescriptor =
    FieldDescriptor::new("ie_container_error", "IE Container Error", FieldType::Str).optional();

/// Octets of the IE container of the message that were not decoded.
pub(crate) static FD_UNDECODED_IES: FieldDescriptor =
    FieldDescriptor::new("undecoded_ies", "Undecoded IEs", FieldType::Bytes).optional();

/// Pushes an IE value as raw octets.
pub(crate) fn push_raw_value<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    buf.push_field(
        &IE_CHILD_FIELDS[CFD_VALUE],
        FieldValue::Bytes(data),
        offset..offset + data.len(),
    );
}

/// Decodes a ProtocolIE-Container starting at the IE count into an array
/// described by `array_desc`, followed by `ie_container_error` and
/// `undecoded_ies` when it is malformed.
///
/// 3GPP TS 36.413, Section 9.3.7 — `ProtocolIE-Container ::= SEQUENCE
/// (SIZE (0..maxProtocolIEs)) OF ProtocolIE-Field`; maxProtocolIEs is
/// 65535 (Section 9.3.6), so the count is a two-octet constrained whole
/// number (ITU-T Rec. X.691, Section 11.5.7.3).
///
/// `extended` is the extension bit of the message SEQUENCE: when set,
/// octets after the last IE are its extension additions (X.691, Section
/// 19.8), which are skipped rather than reported.
///
/// Returns `false` when the IE count itself is missing.
pub(crate) fn push_ie_container<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array_desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
    extended: bool,
) -> bool {
    let Some(&[c0, c1]) = data.get(..2) else {
        return false;
    };
    let count = u16::from_be_bytes([c0, c1]);
    let array_idx = buf.begin_container(
        array_desc,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 2;
    let mut error = None;
    for _ in 0..count {
        match push_ie(buf, data, pos, offset, IeContext::Message) {
            Ok(end) => pos = end,
            Err(reason) => {
                error = Some(reason);
                break;
            }
        }
    }
    if error.is_none() && pos < data.len() && !(extended && is_extension_additions(&data[pos..])) {
        error = Some("octets after the last IE");
    }
    if let Some(field) = buf.field_mut(array_idx as usize) {
        field.range = offset..offset + pos;
    }
    buf.end_container(array_idx);
    if let Some(reason) = error {
        buf.push_field(
            &FD_IE_CONTAINER_ERROR,
            FieldValue::Str(reason),
            offset + pos..offset + data.len(),
        );
        if pos < data.len() {
            buf.push_field(
                &FD_UNDECODED_IES,
                FieldValue::Bytes(&data[pos..]),
                offset + pos..offset + data.len(),
            );
        }
    }
    true
}

/// Returns `true` if `data` is exactly the extension additions of a
/// SEQUENCE (ITU-T Rec. X.691, Section 19.8).
fn is_extension_additions(data: &[u8]) -> bool {
    let mut r = AperReader::new(data);
    skip_sequence_extension_additions(&mut r).is_ok() && ensure_consumed(&r, data).is_ok()
}

/// Decodes one ProtocolIE-Field at `pos` of `data` (whose absolute offset
/// is `offset`); returns the position after it.
///
/// `id` is INTEGER (0..65535), two octets; `criticality` is ENUMERATED
/// {reject, ignore, notify}, two bits followed by padding up to the
/// octet-aligned open type `value` (ITU-T Rec. X.691, Section 11.2).
pub(crate) fn push_ie<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
    ctx: IeContext,
) -> Result<usize, &'static str> {
    let Some(&[i0, i1, crit]) = data.get(pos..pos + 3) else {
        return Err(if pos == data.len() {
            "fewer IEs than the IE count"
        } else {
            "IE header truncated"
        });
    };
    let id = u16::from_be_bytes([i0, i1]);
    let criticality = crit >> 6;
    let len_pos = pos + 3;
    let extent = read_extent(data, len_pos).map_err(|e| match e {
        PacketError::Truncated { .. } => "IE value truncated",
        _ => "IE value length determinant invalid",
    })?;
    // A message value is at most 16383 octets (a larger one is fragmented
    // and not decoded), so an IE value inside it is never fragmented
    // (ITU-T Rec. X.691, Section 11.9.3.8).
    let Extent::Contiguous { len_octets, len } = extent else {
        return Err("IE value length determinant invalid");
    };
    let len_end = len_pos + len_octets;
    let value_end = len_end + len;
    if value_end > data.len() {
        return Err("IE value truncated");
    }

    let at = |r: core::ops::Range<usize>| offset + r.start..offset + r.end;
    let obj = buf.begin_container(&FD_IE, FieldValue::Object(0..0), at(pos..value_end));
    buf.push_field(
        &IE_CHILD_FIELDS[CFD_ID],
        FieldValue::U16(id),
        at(pos..pos + 2),
    );
    buf.push_field(
        &IE_CHILD_FIELDS[CFD_CRITICALITY],
        FieldValue::U8(criticality),
        at(pos + 2..pos + 3),
    );
    buf.push_field(
        &IE_CHILD_FIELDS[CFD_LENGTH],
        FieldValue::U32(len as u32),
        at(len_pos..len_end),
    );
    ie_parsers::push_ie_value(buf, id, &data[len_end..value_end], offset + len_end, ctx);
    buf.end_container(obj);
    Ok(value_end)
}
