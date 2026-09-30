//! Generic decoder for the PDU framing shared by the 3GPP RAN application
//! protocols XnAP, F1AP and E1AP.
//!
//! Each protocol defines a top-level CHOICE of `initiatingMessage`,
//! `successfulOutcome` and `unsuccessfulOutcome`, each a SEQUENCE of
//! `procedureCode` (INTEGER (0..255)), `criticality` (ENUMERATED {reject,
//! ignore, notify}) and `value` (an open type holding the message). Every
//! message is `SEQUENCE { protocolIEs ProtocolIE-Container, ... }`, except
//! the Private Message whose `PrivateIE-Container` uses a different IE
//! identifier and is kept undecoded.
//!
//! The protocol-specific parts (names, IE value decoders) are supplied
//! through [`ApSpec`].
//!
//! ## References
//! - 3GPP TS 38.423 (XnAP), Sections 9.3.3 and 9.3.8:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - 3GPP TS 38.473 (F1AP), Sections 9.4.3 and 9.4.8:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - 3GPP TS 37.483 (E1AP), Sections 9.4.3 and 9.4.8:
//!   <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>
//! - ITU-T Rec. X.691 (APER), Sections 11.2 (open types), 11.9 (length
//!   determinants), 19 (SEQUENCE), 20 (SEQUENCE OF), 23 (CHOICE):
//!   <https://www.itu.int/rec/T-REC-X.691>

use core::ops::Range;

use packet_dissector_core::dissector::{DispatchHint, DissectResult};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::helpers::{ensure_consumed, skip_sequence_extension_additions};
use crate::reader::{AperReader, Extent, read_extent};

/// Minimum PDU size: the CHOICE octet, `procedureCode` and the
/// `criticality` octet, before the value length determinant.
pub const MIN_HEADER_SIZE: usize = 3;

/// Maximum nesting depth of IE containers decoded by
/// [`push_ie_container`] and [`push_single_container_list`]. Deeper
/// values are kept raw, which bounds the work done on crafted input.
pub const MAX_DEPTH: u8 = 4;

/// Decodes the value of one IE and pushes its fields.
///
/// Arguments: the buffer, the IE `id`, the value octets (an open type, so
/// decoding starts at its first bit), the absolute offset of the value and
/// the nesting depth of the enclosing container (0 for the message
/// container). Returns `false` when the value is not decoded; the caller
/// then pushes the raw value.
pub type PushValueFn = for<'pkt> fn(&mut DissectBuffer<'pkt>, u16, &'pkt [u8], usize, u8) -> bool;

/// Encoding of the top-level PDU CHOICE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduChoice {
    /// `CHOICE { initiatingMessage, successfulOutcome,
    /// unsuccessfulOutcome, ... }`: an extension bit then a 2-bit index
    /// (XnAP, E1AP). ITU-T Rec. X.691, Section 23.
    Extensible,
    /// `CHOICE { initiatingMessage, successfulOutcome,
    /// unsuccessfulOutcome, choice-extension }`: a 2-bit index, the fourth
    /// alternative being a ProtocolIE-SingleContainer (F1AP). ITU-T Rec.
    /// X.691, Section 23.
    ChoiceExtension,
}

/// The protocol-specific parts of an application protocol.
pub struct ApSpec {
    /// Layer name (the dissector's short name).
    pub short_name: &'static str,
    /// Layer schema passed to [`DissectBuffer::begin_layer`].
    pub field_descriptors: &'static [FieldDescriptor],
    /// Encoding of the PDU CHOICE.
    pub pdu_choice: PduChoice,
    /// Procedure code of the Private Message procedure.
    pub private_message_code: u8,
    /// `procedure_code` descriptor (names the procedure).
    pub procedure_code: &'static FieldDescriptor,
    /// `ies` array descriptor of the message IE container.
    pub ies: &'static FieldDescriptor,
    /// Object descriptor of one IE (see [`IE_OBJECT_NAME`]).
    pub ie: &'static FieldDescriptor,
    /// `id` descriptor of an IE (names the IE).
    pub ie_id: &'static FieldDescriptor,
    /// IE value decoder.
    pub push_value: PushValueFn,
}

/// Name of the Object field pushed for each IE.
pub const IE_OBJECT_NAME: &str = "ie";

/// Returns a human-readable name for the PDU CHOICE index.
pub fn pdu_type_name(pdu_type: u8) -> &'static str {
    match pdu_type {
        0 => "initiatingMessage",
        1 => "successfulOutcome",
        2 => "unsuccessfulOutcome",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a `Criticality` value.
///
/// `Criticality ::= ENUMERATED { reject, ignore, notify }` — e.g. 3GPP TS
/// 38.473, Section 9.4.6.
pub fn criticality_name(criticality: u8) -> &'static str {
    match criticality {
        0 => "reject",
        1 => "ignore",
        2 => "notify",
        _ => "Unknown",
    }
}

/// `pdu_type` — the PDU CHOICE index.
pub const PDU_TYPE: FieldDescriptor = FieldDescriptor::new("pdu_type", "PDU Type", FieldType::U8)
    .with_display_fn(|v, _| match v {
        FieldValue::U8(t) => Some(pdu_type_name(*t)),
        _ => None,
    });

/// `criticality` of the procedure.
pub const CRITICALITY: FieldDescriptor =
    FieldDescriptor::new("criticality", "Criticality", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(c) => Some(criticality_name(*c)),
            _ => None,
        },
    );

/// `value_length` — octets in the message value.
pub const VALUE_LENGTH: FieldDescriptor =
    FieldDescriptor::new("value_length", "Value Length", FieldType::U32);

/// `length` of an IE value.
pub const IE_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U32);

/// Raw IE value, pushed when the value is not decoded.
pub const IE_VALUE: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional();

/// Raw fragmented IE value (ITU-T Rec. X.691, Section 11.9.3.8), with its
/// length determinants.
pub const IE_FRAGMENTED_VALUE: FieldDescriptor =
    FieldDescriptor::new("fragmented_value", "Fragmented Value", FieldType::Bytes).optional();

/// Reason the message IE container could not be decoded completely.
pub const IE_CONTAINER_ERROR: FieldDescriptor =
    FieldDescriptor::new("ie_container_error", "IE Container Error", FieldType::Str).optional();

/// Octets of the message IE container that were not decoded.
pub const UNDECODED_IES: FieldDescriptor =
    FieldDescriptor::new("undecoded_ies", "Undecoded IEs", FieldType::Bytes).optional();

/// The `PrivateIE-Container` of a Private Message, not decoded.
pub const PRIVATE_IES: FieldDescriptor =
    FieldDescriptor::new("private_ies", "Private IEs", FieldType::Bytes).optional();

/// Reason a nested IE container or IE list could not be decoded
/// completely. Distinct from [`IE_CONTAINER_ERROR`] so that a lookup of
/// the message-level field by name never finds a nested one.
pub const NESTED_IE_CONTAINER_ERROR: FieldDescriptor = FieldDescriptor::new(
    "nested_ie_container_error",
    "Nested IE Container Error",
    FieldType::Str,
)
.optional();

/// Octets of a nested IE container or IE list that were not decoded.
pub const NESTED_UNDECODED_IES: FieldDescriptor = FieldDescriptor::new(
    "nested_undecoded_ies",
    "Nested Undecoded IEs",
    FieldType::Bytes,
)
.optional();

/// `criticality` of an IE (same as [`CRITICALITY`]).
pub const IE_CRITICALITY: FieldDescriptor = CRITICALITY;

/// Dissects one PDU of the protocol described by `spec`.
///
/// ITU-T Rec. X.691, Section 23 (the CHOICE index), 11.5.7.2
/// (`procedureCode`, one octet-aligned octet), 14 (`criticality`, two
/// bits) and 11.2 (`value`, an octet-aligned open type).
pub fn dissect_pdu<'pkt>(
    spec: &ApSpec,
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<DissectResult, PacketError> {
    if data.len() < MIN_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: MIN_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let first = data[0];
    let pdu_type = match spec.pdu_choice {
        PduChoice::Extensible => {
            if first & 0x80 != 0 {
                return Err(PacketError::InvalidHeader(
                    "PDU CHOICE extension not supported",
                ));
            }
            (first >> 5) & 0x03
        }
        PduChoice::ChoiceExtension => {
            let index = first >> 6;
            if index == 3 {
                return Err(PacketError::InvalidHeader(
                    "PDU choice-extension not supported",
                ));
            }
            index
        }
    };
    if pdu_type > 2 {
        return Err(PacketError::InvalidFieldValue {
            field: "pdu_type",
            value: u32::from(pdu_type),
        });
    }
    let procedure_code = data[1];
    let criticality = data[2] >> 6;

    let pos = MIN_HEADER_SIZE;
    let (value_length, value_start, end) = match read_extent(data, pos)? {
        Extent::Contiguous { len_octets, len } => (len, pos + len_octets, pos + len_octets + len),
        Extent::Fragmented { total, end } => (total, pos, end),
    };
    if end > data.len() {
        return Err(PacketError::Truncated {
            expected: end,
            actual: data.len(),
        });
    }
    let fragmented = value_start == pos;
    let value = &data[value_start..end];

    buf.begin_layer(
        spec.short_name,
        None,
        spec.field_descriptors,
        offset..offset + end,
    );
    buf.push_field(&PDU_TYPE, FieldValue::U8(pdu_type), offset..offset + 1);
    buf.push_field(
        spec.procedure_code,
        FieldValue::U8(procedure_code),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &CRITICALITY,
        FieldValue::U8(criticality),
        offset + 2..offset + 3,
    );
    // A fragmented value has no single length determinant; the first
    // octet of the first one is reported.
    let len_end = if fragmented { pos + 1 } else { value_start };
    buf.push_field(
        &VALUE_LENGTH,
        FieldValue::U32(value_length as u32),
        offset + pos..offset + len_end,
    );

    let value_offset = offset + value_start;
    if fragmented {
        // ITU-T Rec. X.691, Section 11.9.3.8: the message value is split
        // into fragments separated by length determinants, so the IE
        // container is not contiguous in the packet and is not decoded.
        buf.push_field(
            &IE_CONTAINER_ERROR,
            FieldValue::Str("fragmented message value not decoded"),
            offset + pos..offset + end,
        );
        buf.push_field(
            &UNDECODED_IES,
            FieldValue::Bytes(value),
            offset + pos..offset + end,
        );
    } else if procedure_code == spec.private_message_code {
        buf.push_field(
            &PRIVATE_IES,
            FieldValue::Bytes(value),
            value_offset..value_offset + value.len(),
        );
    } else if let Some((&preamble, container)) = value.split_first() {
        // The message SEQUENCE has an extension bit and no OPTIONAL
        // component, so the container starts at the next octet (ITU-T Rec.
        // X.691, Section 19.1).
        push_ie_container(
            buf,
            spec,
            spec.ies,
            container,
            value_offset + 1,
            0,
            preamble & 0x80 != 0,
        );
    } else {
        buf.push_field(
            &IE_CONTAINER_ERROR,
            FieldValue::Str("message value empty"),
            value_offset..value_offset,
        );
    }

    buf.end_layer();
    Ok(DissectResult::new(end, DispatchHint::End))
}

/// Decodes a `ProtocolIE-Container` starting at its IE count and pushes
/// the IEs into an array described by `array_desc`, followed by an error
/// and the undecoded octets when the container is malformed.
///
/// `ProtocolIE-Container ::= SEQUENCE (SIZE (0..maxProtocolIEs)) OF
/// ProtocolIE-Field` with maxProtocolIEs = 65535, so the count is a
/// two-octet constrained whole number (ITU-T Rec. X.691, Section
/// 11.5.7.3); each field is `id` (two octets), `criticality` (two bits
/// then padding) and `value` (an open type, Section 11.2) — 3GPP TS
/// 38.473, Section 9.4.8.
///
/// `extended` is the extension bit of the enclosing SEQUENCE: when set,
/// octets after the last IE are its extension additions (ITU-T Rec. X.691,
/// Section 19.8), which are skipped rather than reported. `depth` is the
/// nesting depth of this container (0 for the message container).
pub fn push_ie_container<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    spec: &ApSpec,
    array_desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
    depth: u8,
    extended: bool,
) {
    let (count, first) = match data.get(..2) {
        Some(&[c0, c1]) => (u64::from(u16::from_be_bytes([c0, c1])), 2),
        _ => {
            push_error(buf, depth, "IE count truncated", data, 0, offset);
            return;
        }
    };
    push_fields(
        buf, spec, array_desc, data, first, count, offset, depth, extended,
    );
}

/// Decodes a `SEQUENCE (SIZE (1..ub)) OF ProtocolIE-SingleContainer` (a
/// list of items, each carried as a ProtocolIE-Field) and pushes the
/// items as IEs into an array described by `array_desc`.
///
/// ITU-T Rec. X.691, Section 20.6: the count is a constrained length
/// (Section 11.9.4.1, a bit-field when `ub` is below 256); the first
/// ProtocolIE-Field is octet-aligned since its `id` is a two-octet
/// constrained whole number (Section 11.5.7.3). Returns `false` if the
/// count cannot be read.
pub fn push_single_container_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    spec: &ApSpec,
    array_desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
    depth: u8,
    ub: u64,
) -> bool {
    let mut r = AperReader::new(data);
    let Ok(count) = r.read_length(1, Some(ub)) else {
        return false;
    };
    r.align();
    push_fields(
        buf,
        spec,
        array_desc,
        data,
        r.bit_position() / 8,
        count,
        offset,
        depth,
        false,
    );
    true
}

#[allow(clippy::too_many_arguments)]
fn push_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    spec: &ApSpec,
    array_desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    first: usize,
    count: u64,
    offset: usize,
    depth: u8,
    extended: bool,
) {
    let array_idx = buf.begin_container(
        array_desc,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = first;
    let mut error = None;
    for _ in 0..count {
        match push_field(buf, spec, data, pos, offset, depth) {
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
    // The array covers the count and the IEs, not any extension additions
    // or undecoded octets that follow them.
    if let Some(field) = buf.field_mut(array_idx as usize) {
        field.range = offset..offset + pos;
    }
    buf.end_container(array_idx);
    if let Some(reason) = error {
        push_error(buf, depth, reason, data, pos, offset);
    }
}

/// Pushes the container error `reason` and the octets from `pos`.
fn push_error<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    depth: u8,
    reason: &'static str,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
) {
    let (error_desc, undecoded_desc) = if depth == 0 {
        (&IE_CONTAINER_ERROR, &UNDECODED_IES)
    } else {
        (&NESTED_IE_CONTAINER_ERROR, &NESTED_UNDECODED_IES)
    };
    let range = offset + pos..offset + data.len();
    buf.push_field(error_desc, FieldValue::Str(reason), range.clone());
    if pos < data.len() {
        buf.push_field(undecoded_desc, FieldValue::Bytes(&data[pos..]), range);
    }
}

/// Returns `true` if `data` is exactly the extension additions of a
/// SEQUENCE (ITU-T Rec. X.691, Section 19.8).
fn is_extension_additions(data: &[u8]) -> bool {
    let mut r = AperReader::new(data);
    skip_sequence_extension_additions(&mut r).is_ok() && ensure_consumed(&r, data).is_ok()
}

/// Decodes one ProtocolIE-Field at `pos`; returns the position after it.
fn push_field<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    spec: &ApSpec,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
    depth: u8,
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

    let at = |r: Range<usize>| offset + r.start..offset + r.end;
    let obj = buf.begin_container(spec.ie, FieldValue::Object(0..0), at(pos..value_end));
    buf.push_field(spec.ie_id, FieldValue::U16(id), at(pos..pos + 2));
    buf.push_field(
        &IE_CRITICALITY,
        FieldValue::U8(criticality),
        at(pos + 2..pos + 3),
    );
    buf.push_field(
        &IE_LENGTH,
        FieldValue::U32(len as u32),
        at(len_pos..len_end.max(len_pos + 1)),
    );
    match extent {
        Extent::Contiguous { .. } => {
            let value = &data[len_end..value_end];
            let value_offset = offset + len_end;
            if !(spec.push_value)(buf, id, value, value_offset, depth) {
                buf.push_field(
                    &IE_VALUE,
                    FieldValue::Bytes(value),
                    value_offset..value_offset + value.len(),
                );
            }
        }
        // ITU-T Rec. X.691, Section 11.9.3.8: the value octets are split by
        // length determinants, so they are not a contiguous slice of the
        // packet; the whole encoding is kept undecoded.
        Extent::Fragmented { .. } => buf.push_field(
            &IE_FRAGMENTED_VALUE,
            FieldValue::Bytes(&data[len_pos..value_end]),
            at(len_pos..value_end),
        ),
    }
    buf.end_container(obj);
    Ok(value_end)
}

#[cfg(test)]
mod tests {
    //! # 3GPP RAN Application Protocol Framing Coverage
    //!
    //! | Section                    | Description                             | Test                                   |
    //! |----------------------------|-----------------------------------------|----------------------------------------|
    //! | TS 38.423 9.3.3            | Extensible PDU CHOICE                   | extensible_choice_initiating           |
    //! | TS 38.423 9.3.3            | PDU CHOICE extension rejected           | extensible_choice_extension_rejected   |
    //! | TS 38.423 9.3.3            | Index 3 without extension bit rejected  | extensible_choice_index_three_rejected |
    //! | TS 38.473 9.4.3            | choice-extension alternative rejected   | choice_extension_rejected              |
    //! | TS 38.473 9.4.3            | unsuccessfulOutcome (2-bit index)       | choice_extension_unsuccessful          |
    //! | TS 38.473 9.4.3            | Truncated header                        | truncated_header                       |
    //! | X.691 11.9                 | Value longer than the data              | truncated_value                        |
    //! | TS 38.473 9.4.8            | ProtocolIE-Container, decoded value     | container_with_decoded_and_raw_values  |
    //! | TS 38.473 9.4.8            | IE count missing                        | container_count_missing                |
    //! | TS 38.473 9.4.8            | Fewer IEs than the count                | container_fewer_ies                    |
    //! | TS 38.473 9.4.8            | IE header truncated                     | container_ie_header_truncated          |
    //! | TS 38.473 9.4.8            | IE value truncated                      | container_ie_value_truncated           |
    //! | TS 38.473 9.4.8            | Bad IE length determinant               | container_ie_bad_length                |
    //! | X.691 19.8                 | Trailing octets vs extension additions  | container_trailing_octets              |
    //! | X.691 19.8                 | Extension additions after the IEs       | container_extension_additions_skipped  |
    //! | X.691 11.9.3.8             | Fragmented message value                | fragmented_message_value               |
    //! | X.691 11.9.3.8             | Fragmented IE value                     | fragmented_ie_value                    |
    //! | TS 38.473 9.2.1.x          | Private Message kept raw                | private_message_kept_raw               |
    //! | —                          | Empty message value                     | empty_message_value                    |
    //! | X.691 20.6                 | SingleContainer list                    | single_container_list                  |
    //! | X.691 20.6                 | SingleContainer list, bad count         | single_container_list_bad_count        |
    //! | —                          | Nested container error names            | nested_error_names                     |
    //! | —                          | Name tables                             | name_tables                            |

    use super::*;

    static FIELDS: &[FieldDescriptor] = &[
        PDU_TYPE,
        FieldDescriptor::new("procedure_code", "Procedure Code", FieldType::U8),
        CRITICALITY,
        VALUE_LENGTH,
        FieldDescriptor::new("ies", "IEs", FieldType::Array).optional(),
        IE_CONTAINER_ERROR,
        UNDECODED_IES,
        PRIVATE_IES,
    ];
    static FD_IE: FieldDescriptor = FieldDescriptor::new(IE_OBJECT_NAME, "IE", FieldType::Object);
    static FD_IE_ID: FieldDescriptor = FieldDescriptor::new("id", "ID", FieldType::U16);
    static FD_DECODED: FieldDescriptor = FieldDescriptor::new("decoded", "Decoded", FieldType::U8);
    static FD_NESTED: FieldDescriptor = FieldDescriptor::new("nested", "Nested", FieldType::Array);

    /// IE 1 decodes to a single octet; IE 2 holds a nested container; IE 3
    /// holds a SingleContainer list (1..5 items); others are raw.
    fn push_value<'pkt>(
        buf: &mut DissectBuffer<'pkt>,
        id: u16,
        data: &'pkt [u8],
        offset: usize,
        depth: u8,
    ) -> bool {
        match id {
            1 if data.len() == 1 => {
                buf.push_field(&FD_DECODED, FieldValue::U8(data[0]), offset..offset + 1);
                true
            }
            2 if depth < MAX_DEPTH => {
                push_ie_container(buf, &SPEC, &FD_NESTED, data, offset, depth + 1, false);
                true
            }
            3 => push_single_container_list(buf, &SPEC, &FD_NESTED, data, offset, depth + 1, 5),
            _ => false,
        }
    }

    const BASE: ApSpec = ApSpec {
        short_name: "TEST",
        field_descriptors: FIELDS,
        pdu_choice: PduChoice::Extensible,
        private_message_code: 22,
        procedure_code: &FIELDS[1],
        ies: &FIELDS[4],
        ie: &FD_IE,
        ie_id: &FD_IE_ID,
        push_value,
    };
    static SPEC: ApSpec = BASE;
    static SPEC_CE: ApSpec = ApSpec {
        pdu_choice: PduChoice::ChoiceExtension,
        ..BASE
    };

    fn pdu(first: u8, code: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![first, code, 0x40, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    fn names(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
        buf.fields().iter().map(|f| f.name()).collect()
    }

    fn field<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a FieldValue<'a> {
        &buf.fields()
            .iter()
            .find(|f| f.name() == name)
            .unwrap()
            .value
    }

    #[test]
    fn extensible_choice_initiating() {
        let data = pdu(0x00, 17, &[0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        let r = dissect_pdu(&SPEC, &data, &mut buf, 10).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(
            names(&buf),
            [
                "pdu_type",
                "procedure_code",
                "criticality",
                "value_length",
                "ies"
            ]
        );
        assert_eq!(*field(&buf, "procedure_code"), FieldValue::U8(17));
        assert_eq!(*field(&buf, "criticality"), FieldValue::U8(1));
        assert_eq!(*field(&buf, "value_length"), FieldValue::U32(3));
        assert_eq!(buf.fields()[4].range, 15..17);
        assert_eq!(buf.layers()[0].range, 10..17);
    }

    #[test]
    fn extensible_choice_extension_rejected() {
        let data = pdu(0x80, 0, &[0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            dissect_pdu(&SPEC, &data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn extensible_choice_index_three_rejected() {
        let data = pdu(0x60, 0, &[0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        assert_eq!(
            dissect_pdu(&SPEC, &data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "pdu_type",
                value: 3
            })
        );
    }

    #[test]
    fn choice_extension_rejected() {
        let data = pdu(0xC0, 0, &[0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            dissect_pdu(&SPEC_CE, &data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn choice_extension_unsuccessful() {
        let data = pdu(0x80, 1, &[0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC_CE, &data, &mut buf, 0).unwrap();
        assert_eq!(*field(&buf, "pdu_type"), FieldValue::U8(2));
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            dissect_pdu(&SPEC, &[0x00, 0x01], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 3,
                actual: 2
            })
        );
    }

    #[test]
    fn truncated_value() {
        let mut data = pdu(0x00, 1, &[0x00, 0x00, 0x00]);
        data.pop();
        let mut buf = DissectBuffer::new();
        assert_eq!(
            dissect_pdu(&SPEC, &data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 7,
                actual: 6
            })
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn container_with_decoded_and_raw_values() {
        // Two IEs: id 1 (decoded), id 9 (raw).
        let value = [
            0x00, 0x00, 0x02, // preamble, count 2
            0x00, 0x01, 0x00, 0x01, 0x2A, // id 1, reject, len 1, 0x2A
            0x00, 0x09, 0x40, 0x02, 0xAA, 0xBB, // id 9, ignore, len 2
        ];
        let data = pdu(0x20, 5, &value);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(
            names(&buf)[4..],
            [
                "ies",
                "ie",
                "id",
                "criticality",
                "length",
                "decoded",
                "ie",
                "id",
                "criticality",
                "length",
                "value"
            ]
        );
        assert_eq!(*field(&buf, "decoded"), FieldValue::U8(0x2A));
        assert_eq!(*field(&buf, "value"), FieldValue::Bytes(&[0xAA, 0xBB]));
        let ies = &buf.fields()[4];
        assert_eq!(ies.value, FieldValue::Array(5..15));
        assert_eq!(ies.range, 5..data.len());
    }

    #[test]
    fn container_count_missing() {
        let data = pdu(0x00, 5, &[0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(
            *field(&buf, "ie_container_error"),
            FieldValue::Str("IE count truncated")
        );
        assert_eq!(*field(&buf, "undecoded_ies"), FieldValue::Bytes(&[0x00]));
    }

    fn container_error(value: &[u8]) -> (String, Option<Vec<u8>>) {
        let data = pdu(0x00, 5, value);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        let reason = match field(&buf, "ie_container_error") {
            FieldValue::Str(s) => s.to_string(),
            _ => unreachable!(),
        };
        let undecoded = buf
            .fields()
            .iter()
            .find(|f| f.name() == "undecoded_ies")
            .and_then(|f| f.value.as_bytes().map(<[u8]>::to_vec));
        (reason, undecoded)
    }

    #[test]
    fn container_fewer_ies() {
        assert_eq!(
            container_error(&[0x00, 0x00, 0x01]),
            ("fewer IEs than the IE count".to_string(), None)
        );
    }

    #[test]
    fn container_ie_header_truncated() {
        assert_eq!(
            container_error(&[0x00, 0x00, 0x01, 0x00, 0x01]),
            ("IE header truncated".to_string(), Some(vec![0x00, 0x01]))
        );
    }

    #[test]
    fn container_ie_value_truncated() {
        assert_eq!(
            container_error(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x05, 0x01]).0,
            "IE value truncated"
        );
        assert_eq!(
            container_error(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00]).0,
            "IE value truncated"
        );
    }

    #[test]
    fn container_ie_bad_length() {
        assert_eq!(
            container_error(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xC5]).0,
            "IE value length determinant invalid"
        );
    }

    #[test]
    fn container_trailing_octets() {
        assert_eq!(
            container_error(&[0x00, 0x00, 0x00, 0xFF]),
            ("octets after the last IE".to_string(), Some(vec![0xFF]))
        );
    }

    #[test]
    fn container_extension_additions_skipped() {
        // Extension bit set; one addition present (open type of one octet).
        let data = pdu(0x00, 5, &[0x80, 0x00, 0x00, 0x01, 0x01, 0xAA]);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert!(!names(&buf).contains(&"ie_container_error"));
        // The `ies` array ends after the IE count, before the additions.
        assert_eq!(buf.fields()[4].range, 5..7);
    }

    #[test]
    fn fragmented_message_value() {
        let mut data = vec![0x00, 5, 0x00, 0xC1];
        data.extend(core::iter::repeat_n(0u8, 16384));
        data.push(0x00);
        let mut buf = DissectBuffer::new();
        let r = dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, data.len());
        assert_eq!(*field(&buf, "value_length"), FieldValue::U32(16384));
        assert_eq!(buf.fields()[3].range, 3..4);
        assert_eq!(
            *field(&buf, "ie_container_error"),
            FieldValue::Str("fragmented message value not decoded")
        );
    }

    #[test]
    fn fragmented_ie_value() {
        // A container holding one IE whose value uses a fragmented length
        // determinant (16K octets, then a final zero-length part).
        let mut container = vec![0x00, 0x01, 0x00, 0x09, 0x00, 0xC1];
        container.extend(core::iter::repeat_n(0u8, 16384));
        container.push(0x00);
        let mut buf = DissectBuffer::new();
        push_ie_container(&mut buf, &SPEC, &FIELDS[4], &container, 100, 0, false);
        assert_eq!(*field(&buf, "length"), FieldValue::U32(16384));
        let frag = buf
            .fields()
            .iter()
            .find(|f| f.name() == "fragmented_value")
            .unwrap();
        assert_eq!(frag.range, 105..100 + container.len());
        assert!(!names(&buf).contains(&"ie_container_error"));
    }

    #[test]
    fn private_message_kept_raw() {
        let data = pdu(0x00, 22, &[0x00, 0x00, 0x01, 0x00]);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(
            *field(&buf, "private_ies"),
            FieldValue::Bytes(&[0x00, 0x00, 0x01, 0x00])
        );
        assert!(!names(&buf).contains(&"ies"));
    }

    #[test]
    fn empty_message_value() {
        let data = pdu(0x00, 5, &[]);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(
            *field(&buf, "ie_container_error"),
            FieldValue::Str("message value empty")
        );
    }

    #[test]
    fn single_container_list() {
        // IE 3: list of 2 items (count-1 = 1 in three bits: 0b001 then
        // padding), each an IE 1 with one octet.
        let list = [
            0x20, // count 2
            0x00, 0x01, 0x00, 0x01, 0x11, // item 1
            0x00, 0x01, 0x00, 0x01, 0x22, // item 2
        ];
        let mut value = vec![0x00, 0x00, 0x01, 0x00, 0x03, 0x00, list.len() as u8];
        value.extend_from_slice(&list);
        let data = pdu(0x00, 5, &value);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        let decoded: Vec<_> = buf
            .fields()
            .iter()
            .filter(|f| f.name() == "decoded")
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(decoded, [FieldValue::U8(0x11), FieldValue::U8(0x22)]);
        assert!(!names(&buf).contains(&"nested_ie_container_error"));
    }

    #[test]
    fn single_container_list_bad_count() {
        // Count 6 exceeds the upper bound 5 (three-bit field 0b101).
        let value = [0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0xA0];
        let data = pdu(0x00, 5, &value);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(*field(&buf, "value"), FieldValue::Bytes(&[0xA0]));
    }

    #[test]
    fn nested_error_names() {
        // IE 2 holds a nested container with a truncated count.
        let value = [0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00];
        let data = pdu(0x00, 5, &value);
        let mut buf = DissectBuffer::new();
        dissect_pdu(&SPEC, &data, &mut buf, 0).unwrap();
        assert_eq!(
            *field(&buf, "nested_ie_container_error"),
            FieldValue::Str("IE count truncated")
        );
        assert_eq!(
            *field(&buf, "nested_undecoded_ies"),
            FieldValue::Bytes(&[0x00])
        );
        assert!(!names(&buf).contains(&"ie_container_error"));
    }

    #[test]
    fn name_tables() {
        assert_eq!(pdu_type_name(1), "successfulOutcome");
        assert_eq!(pdu_type_name(2), "unsuccessfulOutcome");
        assert_eq!(pdu_type_name(3), "Unknown");
        assert_eq!(criticality_name(0), "reject");
        assert_eq!(criticality_name(2), "notify");
        assert_eq!(criticality_name(3), "Unknown");
    }
}
