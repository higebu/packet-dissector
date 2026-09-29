//! ProtocolIE-Container decoding shared by NGAP messages and the
//! `...Transfer` OCTET STRINGs that carry their own IE container.
//!
//! ## References
//! - 3GPP TS 38.413, Section 9.4.4 (ProtocolIE-Container) and 9.4.5
//!   (Transfer types): <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
//! - ITU-T Rec. X.691 (APER), Sections 11.2 (open types), 11.9 (length
//!   determinants): <https://www.itu.int/rec/T-REC-X.691>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use packet_dissector_core::error::PacketError;

use crate::aper::{AperReader, Extent, read_extent};
use crate::ie_parsers::{ensure_consumed, skip_sequence_extension_additions};
use crate::{criticality_name, ie_id, ie_parsers};

/// Where an IE container is decoded.
///
/// IE values in a `...Transfer` never contain PDU session resource lists
/// in the specification, so list IEs found there are kept raw. This bounds
/// the nesting (message → list → transfer) regardless of the input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IeContext {
    /// The IE container of an NGAP message.
    Message,
    /// The IE container of a `...Transfer`.
    Transfer,
}

// Indices into [`IE_CHILD_FIELDS`] of the fields pushed for each IE.
const CFD_ID: usize = 0;
const CFD_CRITICALITY: usize = 1;
const CFD_LENGTH: usize = 2;
const CFD_FRAGMENTED_VALUE: usize = 4;

/// Descriptor for the ProtocolIE-Field Object container itself.
///
/// `display_fn` is invoked with the container's children, so the outer
/// label resolves to the IE name instead of colliding with the inner `id`.
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

/// Child field descriptors for each IE element of an `ies` array.
///
/// 3GPP TS 38.413, Section 9.4.4 — ProtocolIE-Field structure. `value`
/// is the raw fallback; decoded IEs carry their own fields instead.
pub(crate) static IE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("id", "ID", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(id) => Some(ie_id::ie_id_name(*id)),
        _ => None,
    }),
    FieldDescriptor::new("criticality", "Criticality", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => Some(criticality_name(*c)),
            _ => None,
        },
    ),
    FieldDescriptor::new("length", "Length", FieldType::U32),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("fragmented_value", "Fragmented Value", FieldType::Bytes).optional(),
];

/// Reason the IE container of the message could not be decoded completely.
pub(crate) static FD_IE_CONTAINER_ERROR: FieldDescriptor =
    FieldDescriptor::new("ie_container_error", "IE Container Error", FieldType::Str).optional();

/// Octets of the IE container of the message that were not decoded.
pub(crate) static FD_UNDECODED_IES: FieldDescriptor =
    FieldDescriptor::new("undecoded_ies", "Undecoded IEs", FieldType::Bytes).optional();

/// Reason the IE container of a `...Transfer` could not be decoded
/// completely. Distinct from [`FD_IE_CONTAINER_ERROR`] so that a lookup of
/// the message-level field by name never finds a nested one.
pub(crate) static FD_TRANSFER_IE_CONTAINER_ERROR: FieldDescriptor = FieldDescriptor::new(
    "transfer_ie_container_error",
    "Transfer IE Container Error",
    FieldType::Str,
)
.optional();

/// Octets of the IE container of a `...Transfer` that were not decoded.
pub(crate) static FD_TRANSFER_UNDECODED_IES: FieldDescriptor = FieldDescriptor::new(
    "transfer_undecoded_ies",
    "Transfer Undecoded IEs",
    FieldType::Bytes,
)
.optional();

/// Decodes a ProtocolIE-Container starting at the IE count and pushes the
/// IEs into an array described by `array_desc`, followed by
/// `ie_container_error` and `undecoded_octets` when the container is
/// malformed.
///
/// 3GPP TS 38.413, Section 9.4.4 — `ProtocolIE-Container ::= SEQUENCE
/// (SIZE (0..maxProtocolIEs)) OF ProtocolIE-Field`, each field being `id`
/// (INTEGER (0..65535), two octets), `criticality` (ENUMERATED, two bits
/// then padding up to the octet-aligned open type) and `value` (open type,
/// ITU-T Rec. X.691, Section 11.2). maxProtocolIEs is 65535, so the count
/// is a two-octet constrained whole number (X.691, Section 11.5.7.3).
///
/// `extended` is the extension bit of the enclosing SEQUENCE: when set,
/// octets after the last IE are its extension additions (ITU-T Rec. X.691,
/// Section 19.8), which are skipped rather than reported.
///
/// Returns `false` when the IE count itself is missing.
pub(crate) fn push_ie_container<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array_desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
    ctx: IeContext,
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
        match push_ie(buf, data, pos, offset, ctx) {
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
        let (error_desc, undecoded_desc) = match ctx {
            IeContext::Message => (&FD_IE_CONTAINER_ERROR, &FD_UNDECODED_IES),
            IeContext::Transfer => (&FD_TRANSFER_IE_CONTAINER_ERROR, &FD_TRANSFER_UNDECODED_IES),
        };
        buf.push_field(
            error_desc,
            FieldValue::Str(reason),
            offset + pos..offset + data.len(),
        );
        if pos < data.len() {
            buf.push_field(
                undecoded_desc,
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

/// Decodes one ProtocolIE-Field at `pos`; returns the position after it.
fn push_ie<'pkt>(
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
    let (len, len_end, value_end) = match extent {
        Extent::Contiguous { len_octets, len } => {
            let value_end = len_pos + len_octets + len;
            if value_end > data.len() {
                return Err("IE value truncated");
            }
            (len, len_pos + len_octets, value_end)
        }
        Extent::Fragmented { total, end } => (total, len_pos, end),
    };

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
        at(len_pos..len_end.max(len_pos + 1)),
    );
    match extent {
        Extent::Contiguous { .. } => {
            ie_parsers::push_ie_value_in(buf, id, &data[len_end..value_end], offset + len_end, ctx);
        }
        // ITU-T Rec. X.691, Section 11.9.3.8: the value octets are split by
        // length determinants, so they are not a contiguous slice of the
        // packet; the whole encoding is kept undecoded.
        Extent::Fragmented { .. } => buf.push_field(
            &IE_CHILD_FIELDS[CFD_FRAGMENTED_VALUE],
            FieldValue::Bytes(&data[len_pos..value_end]),
            at(len_pos..value_end),
        ),
    }
    buf.end_container(obj);
    Ok(value_end)
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 38.413 ProtocolIE-Container Coverage
    //!
    //! | Spec Section    | Description                          | Test                               |
    //! |-----------------|--------------------------------------|------------------------------------|
    //! | 9.4.4           | Container with IEs                   | container_decodes_ies              |
    //! | 9.4.4           | Missing IE count                     | container_without_count            |
    //! | 9.4.4           | Fewer IEs than the count             | container_count_exceeds_ies        |
    //! | 9.4.4           | Truncated IE header                  | container_truncated_header         |
    //! | 9.4.4           | Truncated IE value                   | container_truncated_value          |
    //! | 9.4.4           | Octets after the last IE             | container_trailing_octets          |
    //! | X.691 11.9.3.8  | Fragmented IE value                  | container_fragmented_value         |
    //! | 9.4.4           | IE / ID / criticality display names  | display_names                      |
    //! | X.691 11.9.3.8  | Invalid fragment multiplier          | container_invalid_length           |
    //! | X.691 19.8      | Extension additions after the IEs    | container_extension_additions      |
    //! | 9.4.4           | Errors in a transfer container       | container_transfer_error_names     |

    use super::*;

    static FD_TEST_IES: FieldDescriptor =
        FieldDescriptor::new("ies", "IEs", FieldType::Array).with_children(IE_CHILD_FIELDS);

    fn names<'a>(buf: &'a DissectBuffer<'_>) -> Vec<&'a str> {
        buf.fields().iter().map(|f| f.name()).collect()
    }

    fn field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        name: &str,
    ) -> &'a packet_dissector_core::field::Field<'pkt> {
        buf.fields().iter().find(|f| f.name() == name).unwrap()
    }

    #[test]
    fn container_decodes_ies() {
        // Two IEs: RAN-UE-NGAP-ID 42 and an unknown IE.
        let data = [
            0x00, 0x02, 0x00, 0x55, 0x00, 0x02, 0x00, 0x2a, 0x27, 0x0f, 0x40, 0x01, 0xff,
        ];
        let mut buf = DissectBuffer::new();
        assert!(push_ie_container(
            &mut buf,
            &FD_TEST_IES,
            &data,
            10,
            IeContext::Message,
            false
        ));
        assert_eq!(
            names(&buf),
            [
                "ies",
                "ie",
                "id",
                "criticality",
                "length",
                "ran_ue_ngap_id",
                "ie",
                "id",
                "criticality",
                "length",
                "value",
            ]
        );
        assert_eq!(buf.fields()[0].range, 10..23);
        assert_eq!(buf.fields()[5].value, FieldValue::U32(42));
        assert_eq!(buf.fields()[8].value, FieldValue::U8(1));
        assert_eq!(buf.fields()[10].value, FieldValue::Bytes(&[0xff]));
        assert_eq!(buf.fields()[10].range, 22..23);
    }

    #[test]
    fn container_without_count() {
        let mut buf = DissectBuffer::new();
        assert!(!push_ie_container(
            &mut buf,
            &FD_TEST_IES,
            &[0x00],
            0,
            IeContext::Message,
            false
        ));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn container_count_exceeds_ies() {
        let data = [0x00, 0x02, 0x00, 0x55, 0x00, 0x02, 0x00, 0x2a];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, false);
        assert_eq!(
            field(&buf, "ie_container_error").value,
            FieldValue::Str("fewer IEs than the IE count")
        );
        assert!(names(&buf).iter().all(|n| *n != "undecoded_ies"));
    }

    #[test]
    fn container_truncated_header() {
        let data = [0x00, 0x01, 0x00, 0x55];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, false);
        assert_eq!(
            field(&buf, "ie_container_error").value,
            FieldValue::Str("IE header truncated")
        );
        let rest = field(&buf, "undecoded_ies");
        assert_eq!(rest.value, FieldValue::Bytes(&[0x00, 0x55]));
        assert_eq!(rest.range, 2..4);
    }

    #[test]
    fn container_truncated_value() {
        for data in [
            &[0x00, 0x01, 0x00, 0x55, 0x00, 0x05, 0x00][..],
            &[0x00, 0x01, 0x00, 0x55, 0x00][..],
        ] {
            let mut buf = DissectBuffer::new();
            push_ie_container(&mut buf, &FD_TEST_IES, data, 0, IeContext::Message, false);
            assert_eq!(
                field(&buf, "ie_container_error").value,
                FieldValue::Str("IE value truncated")
            );
            assert_eq!(
                field(&buf, "undecoded_ies").value,
                FieldValue::Bytes(&data[2..])
            );
            assert_eq!(buf.fields()[0].value, FieldValue::Array(1..1));
        }
    }

    #[test]
    fn container_trailing_octets() {
        let data = [0x00, 0x00, 0xaa];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, false);
        assert_eq!(
            field(&buf, "ie_container_error").value,
            FieldValue::Str("octets after the last IE")
        );
        assert_eq!(
            field(&buf, "undecoded_ies").value,
            FieldValue::Bytes(&[0xaa])
        );
    }

    #[test]
    fn container_fragmented_value() {
        // One IE whose value is one 16K fragment followed by 2 octets.
        let mut data = vec![0x00, 0x01, 0x00, 0x75, 0x40, 0xc1];
        data.extend(std::iter::repeat_n(0x11u8, 16384));
        data.extend_from_slice(&[0x02, 0x22, 0x33]);
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, false);
        assert_eq!(field(&buf, "length").value, FieldValue::U32(16386));
        let v = field(&buf, "fragmented_value");
        assert_eq!(v.range, 5..data.len());
        assert!(names(&buf).iter().all(|n| *n != "ie_container_error"));
    }

    #[test]
    fn display_names() {
        let id = FieldValue::U16(85);
        let crit = FieldValue::U8(1);
        let f = IE_CHILD_FIELDS[CFD_ID].display_fn.unwrap();
        assert_eq!(f(&id, &[]), Some("RAN-UE-NGAP-ID"));
        assert_eq!(f(&crit, &[]), None);
        let f = IE_CHILD_FIELDS[CFD_CRITICALITY].display_fn.unwrap();
        assert_eq!(f(&crit, &[]), Some("ignore"));
        assert_eq!(f(&id, &[]), None);
        let f = FD_IE.display_fn.unwrap();
        let children = [IE_CHILD_FIELDS[CFD_ID].to_field(id.clone(), 0..2)];
        assert_eq!(
            f(&FieldValue::Object(0..1), &children),
            Some("RAN-UE-NGAP-ID")
        );
        assert_eq!(f(&FieldValue::Object(0..0), &[]), None);
        assert_eq!(f(&crit, &children), None);
    }

    #[test]
    fn container_invalid_length() {
        let data = [0x00, 0x01, 0x00, 0x55, 0x00, 0xc5];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, false);
        assert_eq!(
            field(&buf, "ie_container_error").value,
            FieldValue::Str("IE value length determinant invalid")
        );
    }

    #[test]
    fn container_extension_additions() {
        // No IEs, then one extension addition (one octet 0xaa).
        let data = [0x00, 0x00, 0x01, 0x01, 0xaa];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, true);
        assert_eq!(names(&buf), ["ies"]);
        // Octets that are not valid additions are still reported.
        let data = [0x00, 0x00, 0x01, 0x05, 0xaa];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Message, true);
        assert_eq!(
            field(&buf, "ie_container_error").value,
            FieldValue::Str("octets after the last IE")
        );
    }

    #[test]
    fn container_transfer_error_names() {
        let data = [0x00, 0x01, 0x00, 0x55];
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &FD_TEST_IES, &data, 0, IeContext::Transfer, false);
        assert_eq!(
            field(&buf, "transfer_ie_container_error").value,
            FieldValue::Str("IE header truncated")
        );
        assert_eq!(
            field(&buf, "transfer_undecoded_ies").value,
            FieldValue::Bytes(&[0x00, 0x55])
        );
    }
}
