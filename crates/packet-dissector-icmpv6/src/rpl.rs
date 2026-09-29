//! RPL Control Message (ICMPv6 Type 155) base objects and options.
//!
//! ## References
//! - RFC 6550, Section 6 (ICMPv6 RPL Control Message): <https://www.rfc-editor.org/rfc/rfc6550#section-6>
//! - RFC 6550, Section 6.7 (RPL Control Message Options): <https://www.rfc-editor.org/rfc/rfc6550#section-6.7>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::{
    FD_DAO_SEQUENCE, FD_DODAG_ID, FD_DTSN, FD_GROUNDED, FD_MOP, FD_PRF, FD_RANK, FD_RPL_FLAGS,
    FD_RPL_INSTANCE_ID, FD_RPL_OPTIONS, FD_RPL_STATUS, FD_VERSION_NUMBER, FIELD_DESCRIPTORS,
    push_raw_body, push_u8, push_u16,
};

/// RFC 6550, Section 6 — "0x00: DODAG Information Solicitation".
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6>
const CODE_DIS: u8 = 0x00;
/// RFC 6550, Section 6 — "0x01: DODAG Information Object".
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6>
const CODE_DIO: u8 = 0x01;
/// RFC 6550, Section 6 — "0x02: Destination Advertisement Object".
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6>
const CODE_DAO: u8 = 0x02;
/// RFC 6550, Section 6 — "0x03: Destination Advertisement Object
/// Acknowledgment".
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6>
const CODE_DAO_ACK: u8 = 0x03;

/// DIS base object size: Flags and Reserved (RFC 6550, Section 6.2.1).
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6.2.1>
const DIS_BASE_SIZE: usize = 2;
/// DIO base object size (RFC 6550, Section 6.3.1).
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6.3.1>
const DIO_BASE_SIZE: usize = 24;
/// Size of the DAO / DAO-ACK base object without DODAGID (RFC 6550,
/// Sections 6.4.1 and 6.5.1).
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6.4.1>
const DAO_BASE_SIZE: usize = 4;
/// Offset of the base object in the ICMPv6 message (after Type, Code and
/// Checksum).
const BASE: usize = 4;

/// Returns the name of an RPL Control Message option type (RFC 6550,
/// Sections 6.7.2-6.7.11).
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6.7>
fn rpl_option_name(t: u8) -> Option<&'static str> {
    match t {
        0x00 => Some("Pad1"),
        0x01 => Some("PadN"),
        0x02 => Some("DAG Metric Container"),
        0x03 => Some("Route Information"),
        0x04 => Some("DODAG Configuration"),
        0x05 => Some("RPL Target"),
        0x06 => Some("Transit Information"),
        0x07 => Some("Solicited Information"),
        0x08 => Some("Prefix Information"),
        0x09 => Some("RPL Target Descriptor"),
        _ => None,
    }
}

/// Container descriptor for one RPL option; its display name resolves to
/// the option name via the nested `type` field.
static FD_RPL_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => rpl_option_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

const RO_TYPE: usize = 0;
const RO_LENGTH: usize = 1;
const RO_AUTHENTICATION: usize = 2;
const RO_PCS: usize = 3;
const RO_DIO_INT_DOUBLINGS: usize = 4;
const RO_DIO_INT_MIN: usize = 5;
const RO_DIO_REDUNDANCY: usize = 6;
const RO_MAX_RANK_INCREASE: usize = 7;
const RO_MIN_HOP_RANK_INCREASE: usize = 8;
const RO_OCP: usize = 9;
const RO_DEFAULT_LIFETIME: usize = 10;
const RO_LIFETIME_UNIT: usize = 11;
const RO_FLAGS: usize = 12;
const RO_PREFIX_LENGTH: usize = 13;
const RO_TARGET_PREFIX: usize = 14;
const RO_VALUE: usize = 15;
const RO_MALFORMED: usize = 16;

/// Child descriptors of an RPL option object (union over all option types).
pub(crate) static RPL_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Option Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _| match v {
            FieldValue::U8(t) => rpl_option_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Option Length", FieldType::U8).optional(),
    // RFC 6550, Section 6.7.6 — DODAG Configuration option fields
    // <https://www.rfc-editor.org/rfc/rfc6550#section-6.7.6>
    FieldDescriptor::new("authentication", "Authentication Enabled", FieldType::U8).optional(),
    FieldDescriptor::new("pcs", "Path Control Size", FieldType::U8).optional(),
    FieldDescriptor::new("dio_int_doublings", "DIOIntervalDoublings", FieldType::U8).optional(),
    FieldDescriptor::new("dio_int_min", "DIOIntervalMin", FieldType::U8).optional(),
    FieldDescriptor::new("dio_redundancy", "DIORedundancyConstant", FieldType::U8).optional(),
    FieldDescriptor::new("max_rank_increase", "MaxRankIncrease", FieldType::U16).optional(),
    FieldDescriptor::new(
        "min_hop_rank_increase",
        "MinHopRankIncrease",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("ocp", "Objective Code Point", FieldType::U16).optional(),
    FieldDescriptor::new("default_lifetime", "Default Lifetime", FieldType::U8).optional(),
    FieldDescriptor::new("lifetime_unit", "Lifetime Unit", FieldType::U16).optional(),
    // RFC 6550, Section 6.7.7 — RPL Target option fields
    // <https://www.rfc-editor.org/rfc/rfc6550#section-6.7.7>
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("target_prefix", "Target Prefix", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("malformed", "Malformed Data", FieldType::Bytes).optional(),
];

/// Push the base object and options of an RPL Control Message.
///
/// RFC 6550, Section 6 — "The Code field identifies the type of RPL control
/// message." Secure variants (Section 6.1) carry a Security section before
/// the base object and, like codes this function does not decode, keep the
/// body as raw `data`; so does a body shorter than its base object.
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6>
pub(crate) fn push_rpl_message<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u8,
    data: &'pkt [u8],
    offset: usize,
) {
    let options_at = match code {
        // RFC 6550, Section 6.2.1 — DIS: Flags, Reserved, Option(s).
        // <https://www.rfc-editor.org/rfc/rfc6550#section-6.2.1>
        CODE_DIS if data.len() >= BASE + DIS_BASE_SIZE => {
            push_u8(buf, FD_RPL_FLAGS, data, BASE, offset);
            BASE + DIS_BASE_SIZE
        }
        // RFC 6550, Section 6.3.1 — DIO: RPLInstanceID, Version Number,
        // Rank, G|0|MOP|Prf, DTSN, Flags, Reserved, DODAGID, Option(s).
        // <https://www.rfc-editor.org/rfc/rfc6550#section-6.3.1>
        CODE_DIO if data.len() >= BASE + DIO_BASE_SIZE => {
            let b = data[BASE + 4];
            push_u8(buf, FD_RPL_INSTANCE_ID, data, BASE, offset);
            push_u8(buf, FD_VERSION_NUMBER, data, BASE + 1, offset);
            push_u16(buf, FD_RANK, data, BASE + 2, offset);
            let at = offset + BASE + 4;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_GROUNDED],
                FieldValue::U8(b >> 7),
                at..at + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_MOP],
                FieldValue::U8((b >> 3) & 0x07),
                at..at + 1,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_PRF],
                FieldValue::U8(b & 0x07),
                at..at + 1,
            );
            push_u8(buf, FD_DTSN, data, BASE + 5, offset);
            push_u8(buf, FD_RPL_FLAGS, data, BASE + 6, offset);
            push_dodag_id(buf, data, BASE + 8, offset);
            BASE + DIO_BASE_SIZE
        }
        // RFC 6550, Section 6.4.1 — DAO: RPLInstanceID, K|D|Flags,
        // Reserved, DAOSequence, DODAGID (present when D is set), Option(s).
        // <https://www.rfc-editor.org/rfc/rfc6550#section-6.4.1>
        CODE_DAO if data.len() >= BASE + DAO_BASE_SIZE => {
            let with_dodag_id = data[BASE + 1] & 0x40 != 0;
            if with_dodag_id && data.len() < BASE + DAO_BASE_SIZE + 16 {
                push_raw_body(buf, data, offset);
                return;
            }
            push_u8(buf, FD_RPL_INSTANCE_ID, data, BASE, offset);
            push_u8(buf, FD_RPL_FLAGS, data, BASE + 1, offset);
            push_u8(buf, FD_DAO_SEQUENCE, data, BASE + 3, offset);
            dodag_id_and_options(buf, data, offset, with_dodag_id)
        }
        // RFC 6550, Section 6.5.1 — DAO-ACK: RPLInstanceID, D|Reserved,
        // DAOSequence, Status, DODAGID (present when D is set), Option(s).
        // <https://www.rfc-editor.org/rfc/rfc6550#section-6.5.1>
        CODE_DAO_ACK if data.len() >= BASE + DAO_BASE_SIZE => {
            let with_dodag_id = data[BASE + 1] & 0x80 != 0;
            if with_dodag_id && data.len() < BASE + DAO_BASE_SIZE + 16 {
                push_raw_body(buf, data, offset);
                return;
            }
            push_u8(buf, FD_RPL_INSTANCE_ID, data, BASE, offset);
            push_u8(buf, FD_RPL_FLAGS, data, BASE + 1, offset);
            push_u8(buf, FD_DAO_SEQUENCE, data, BASE + 2, offset);
            push_u8(buf, FD_RPL_STATUS, data, BASE + 3, offset);
            dodag_id_and_options(buf, data, offset, with_dodag_id)
        }
        _ => {
            push_raw_body(buf, data, offset);
            return;
        }
    };

    if data.len() > options_at {
        let idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_RPL_OPTIONS],
            FieldValue::Array(0..0),
            offset + options_at..offset + data.len(),
        );
        push_rpl_options(buf, &data[options_at..], offset + options_at);
        buf.end_container(idx);
    }
}

/// Push the optional DODAGID of a DAO / DAO-ACK and return where the
/// options start.
fn dodag_id_and_options(
    buf: &mut DissectBuffer<'_>,
    data: &[u8],
    offset: usize,
    with_dodag_id: bool,
) -> usize {
    let at = BASE + DAO_BASE_SIZE;
    if with_dodag_id {
        push_dodag_id(buf, data, at, offset);
        at + 16
    } else {
        at
    }
}

fn push_dodag_id(buf: &mut DissectBuffer<'_>, data: &[u8], at: usize, offset: usize) {
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&data[at..at + 16]);
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_DODAG_ID],
        FieldValue::Ipv6Addr(addr),
        offset + at..offset + at + 16,
    );
}

/// Walk RPL Control Message options.
///
/// RFC 6550, Section 6.7.1 — "Option Length: 8-bit unsigned integer,
/// representing the length in octets of the option, not including the
/// Option Type and Length fields". Section 6.7.2 — "The format of the Pad1
/// option is a special case -- it has neither Option Length nor Option Data
/// fields." An option whose length runs past
/// the message ends the walk and is reported with its remaining octets as
/// `malformed`.
/// <https://www.rfc-editor.org/rfc/rfc6550#section-6.7.1>
fn push_rpl_options<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let mut pos = 0;
    let end = offset + data.len();
    while pos < data.len() {
        let opt_type = data[pos];
        let start = offset + pos;
        if opt_type == 0x00 {
            let idx = begin_option(buf, opt_type, start..start + 1);
            buf.end_container(idx);
            pos += 1;
            continue;
        }
        let Some(&len) = data.get(pos + 1) else {
            let idx = begin_option(buf, opt_type, start..end);
            buf.push_field(
                &RPL_OPTION_CHILDREN[RO_MALFORMED],
                FieldValue::Bytes(&[]),
                end..end,
            );
            buf.end_container(idx);
            return;
        };
        let body_start = pos + 2;
        let body_end = body_start + len as usize;
        if body_end > data.len() {
            let idx = begin_option(buf, opt_type, start..end);
            push_length(buf, len, start);
            buf.push_field(
                &RPL_OPTION_CHILDREN[RO_MALFORMED],
                FieldValue::Bytes(&data[body_start..]),
                start + 2..end,
            );
            buf.end_container(idx);
            return;
        }
        let idx = begin_option(buf, opt_type, start..offset + body_end);
        push_length(buf, len, start);
        push_option_body(buf, opt_type, &data[body_start..body_end], start + 2);
        buf.end_container(idx);
        pos = body_end;
    }
}

fn begin_option(buf: &mut DissectBuffer<'_>, opt_type: u8, range: core::ops::Range<usize>) -> u32 {
    let start = range.start;
    let idx = buf.begin_container(&FD_RPL_OPTION, FieldValue::Object(0..0), range);
    buf.push_field(
        &RPL_OPTION_CHILDREN[RO_TYPE],
        FieldValue::U8(opt_type),
        start..start + 1,
    );
    idx
}

fn push_length(buf: &mut DissectBuffer<'_>, len: u8, start: usize) {
    buf.push_field(
        &RPL_OPTION_CHILDREN[RO_LENGTH],
        FieldValue::U8(len),
        start + 1..start + 2,
    );
}

fn opt_u8(buf: &mut DissectBuffer<'_>, fd: usize, v: u8, at: usize) {
    buf.push_field(&RPL_OPTION_CHILDREN[fd], FieldValue::U8(v), at..at + 1);
}

fn opt_u16(buf: &mut DissectBuffer<'_>, fd: usize, b: &[u8], at: usize) {
    buf.push_field(
        &RPL_OPTION_CHILDREN[fd],
        FieldValue::U16(u16::from_be_bytes([b[0], b[1]])),
        at..at + 2,
    );
}

/// Push the data of one RPL option. Options without a decoder here, or
/// with an unexpected length, keep their data as `value`.
fn push_option_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_type: u8,
    body: &'pkt [u8],
    offset: usize,
) {
    match (opt_type, body.len()) {
        // RFC 6550, Section 6.7.6 — DODAG Configuration: "Option Length:
        // 14". Flags (4 bits), A, PCS (3 bits), DIOIntDoubl., DIOIntMin.,
        // DIORedun., MaxRankIncrease, MinHopRankIncrease, OCP, Reserved,
        // Def. Lifetime, Lifetime Unit.
        // <https://www.rfc-editor.org/rfc/rfc6550#section-6.7.6>
        (0x04, 14) => {
            opt_u8(buf, RO_AUTHENTICATION, (body[0] >> 3) & 0x01, offset);
            opt_u8(buf, RO_PCS, body[0] & 0x07, offset);
            opt_u8(buf, RO_DIO_INT_DOUBLINGS, body[1], offset + 1);
            opt_u8(buf, RO_DIO_INT_MIN, body[2], offset + 2);
            opt_u8(buf, RO_DIO_REDUNDANCY, body[3], offset + 3);
            opt_u16(buf, RO_MAX_RANK_INCREASE, &body[4..], offset + 4);
            opt_u16(buf, RO_MIN_HOP_RANK_INCREASE, &body[6..], offset + 6);
            opt_u16(buf, RO_OCP, &body[8..], offset + 8);
            opt_u8(buf, RO_DEFAULT_LIFETIME, body[11], offset + 11);
            opt_u16(buf, RO_LIFETIME_UNIT, &body[12..], offset + 12);
        }
        // RFC 6550, Section 6.7.7 — RPL Target: Flags, Prefix Length,
        // Target Prefix (variable length).
        // <https://www.rfc-editor.org/rfc/rfc6550#section-6.7.7>
        (0x05, 2..) => {
            opt_u8(buf, RO_FLAGS, body[0], offset);
            opt_u8(buf, RO_PREFIX_LENGTH, body[1], offset + 1);
            if body.len() > 2 {
                buf.push_field(
                    &RPL_OPTION_CHILDREN[RO_TARGET_PREFIX],
                    FieldValue::Bytes(&body[2..]),
                    offset + 2..offset + body.len(),
                );
            }
        }
        (_, 1..) => {
            buf.push_field(
                &RPL_OPTION_CHILDREN[RO_VALUE],
                FieldValue::Bytes(body),
                offset..offset + body.len(),
            );
        }
        _ => {}
    }
}
