//! Mobility Header message bodies and mobility options.
//!
//! ## References
//! - RFC 6275, Section 6.1 (Mobility Header): <https://www.rfc-editor.org/rfc/rfc6275#section-6.1>
//! - RFC 6275, Section 6.2 (Mobility Options): <https://www.rfc-editor.org/rfc/rfc6275#section-6.2>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::ext::{
    MH_FD_ACK_FLAGS, MH_FD_FLAGS, MH_FD_HOME_ADDRESS, MH_FD_INIT_COOKIE, MH_FD_KEYGEN_TOKEN,
    MH_FD_LIFETIME, MH_FD_MOBILITY_OPTIONS, MH_FD_NONCE_INDEX, MH_FD_SEQUENCE_NUMBER, MH_FD_STATUS,
    MOBILITY_DESCRIPTORS,
};

/// RFC 6275, Section 6.1.2 — Binding Refresh Request.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.2>
const MH_BRR: u8 = 0;
/// RFC 6275, Section 6.1.3 — Home Test Init.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.3>
const MH_HOTI: u8 = 1;
/// RFC 6275, Section 6.1.4 — Care-of Test Init.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.4>
const MH_COTI: u8 = 2;
/// RFC 6275, Section 6.1.5 — Home Test.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.5>
const MH_HOT: u8 = 3;
/// RFC 6275, Section 6.1.6 — Care-of Test.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.6>
const MH_COT: u8 = 4;
/// RFC 6275, Section 6.1.7 — Binding Update.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.7>
const MH_BU: u8 = 5;
/// RFC 6275, Section 6.1.8 — Binding Acknowledgement.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.8>
const MH_BA: u8 = 6;
/// RFC 6275, Section 6.1.9 — Binding Error.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.9>
const MH_BE: u8 = 7;

/// Returns the name of a Mobility Header type (RFC 6275, Sections
/// 6.1.2-6.1.9).
/// <https://www.rfc-editor.org/rfc/rfc6275>
pub(crate) fn mh_type_name(t: u8) -> Option<&'static str> {
    match t {
        MH_BRR => Some("Binding Refresh Request"),
        MH_HOTI => Some("Home Test Init"),
        MH_COTI => Some("Care-of Test Init"),
        MH_HOT => Some("Home Test"),
        MH_COT => Some("Care-of Test"),
        MH_BU => Some("Binding Update"),
        MH_BA => Some("Binding Acknowledgement"),
        MH_BE => Some("Binding Error"),
        _ => None,
    }
}

/// RFC 6275, Section 6.2.2 — Pad1.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.2>
const MO_PAD1: u8 = 0;
/// RFC 6275, Section 6.2.3 — PadN.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.3>
const MO_PADN: u8 = 1;
/// RFC 6275, Section 6.2.4 — Binding Refresh Advice.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.4>
const MO_BRA: u8 = 2;
/// RFC 6275, Section 6.2.5 — Alternate Care-of Address.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.5>
const MO_ALT_COA: u8 = 3;
/// RFC 6275, Section 6.2.6 — Nonce Indices.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.6>
const MO_NONCE_INDICES: u8 = 4;
/// RFC 6275, Section 6.2.7 — Binding Authorization Data.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.7>
const MO_AUTH_DATA: u8 = 5;

/// Returns the name of a mobility option type (RFC 6275, Sections
/// 6.2.2-6.2.7).
/// <https://www.rfc-editor.org/rfc/rfc6275>
fn mobility_option_name(t: u8) -> Option<&'static str> {
    match t {
        MO_PAD1 => Some("Pad1"),
        MO_PADN => Some("PadN"),
        MO_BRA => Some("Binding Refresh Advice"),
        MO_ALT_COA => Some("Alternate Care-of Address"),
        MO_NONCE_INDICES => Some("Nonce Indices"),
        MO_AUTH_DATA => Some("Binding Authorization Data"),
        _ => None,
    }
}

/// Container descriptor for one mobility option. The display name resolves
/// to the option name via the nested `type` field.
static FD_MOBILITY_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => mobility_option_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

const MOC_TYPE: usize = 0;
const MOC_LENGTH: usize = 1;
const MOC_REFRESH_INTERVAL: usize = 2;
const MOC_ALT_COA: usize = 3;
const MOC_HOME_NONCE_INDEX: usize = 4;
const MOC_CARE_OF_NONCE_INDEX: usize = 5;
const MOC_AUTHENTICATOR: usize = 6;
const MOC_VALUE: usize = 7;
const MOC_MALFORMED: usize = 8;

/// Child descriptors of a mobility option object (union over all types).
pub(crate) static MOBILITY_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Option Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _| match v {
            FieldValue::U8(t) => mobility_option_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Option Length", FieldType::U8).optional(),
    FieldDescriptor::new("refresh_interval", "Refresh Interval", FieldType::U16).optional(),
    FieldDescriptor::new(
        "alternate_care_of_address",
        "Alternate Care-of Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("home_nonce_index", "Home Nonce Index", FieldType::U16).optional(),
    FieldDescriptor::new("care_of_nonce_index", "Care-of Nonce Index", FieldType::U16).optional(),
    FieldDescriptor::new("authenticator", "Authenticator", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("malformed", "Malformed Data", FieldType::Bytes).optional(),
];

fn push_u16(buf: &mut DissectBuffer<'_>, fd: &'static FieldDescriptor, b: &[u8], at: usize) {
    buf.push_field(
        fd,
        FieldValue::U16(u16::from_be_bytes([b[0], b[1]])),
        at..at + 2,
    );
}

fn read_addr(b: &[u8]) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&b[..16]);
    addr
}

/// Push the Message Data of a Mobility Header.
///
/// `body` is the Message Data (after the 6 fixed octets) and `offset` its
/// absolute position. Returns `false` when the MH Type has no decoder or the
/// body is shorter than the message's fixed fields, in which case the
/// caller keeps the body as raw `message_data`.
pub(crate) fn push_message<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    mh_type: u8,
    body: &'pkt [u8],
    offset: usize,
) -> bool {
    let fd = |i: usize| &MOBILITY_DESCRIPTORS[i];
    let fixed = match mh_type {
        // RFC 6275, Section 6.1.2 — Binding Refresh Request: Reserved (16
        // bits), Mobility Options.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.2>
        MH_BRR => 2,
        // RFC 6275, Sections 6.1.3 / 6.1.4 — Home / Care-of Test Init:
        // Reserved (16 bits), Init Cookie (64 bits), Mobility Options.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.3>
        MH_HOTI | MH_COTI => 10,
        // RFC 6275, Sections 6.1.5 / 6.1.6 — Home / Care-of Test: Nonce
        // Index (16 bits), Init Cookie (64 bits), Keygen Token (64 bits),
        // Mobility Options.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.5>
        MH_HOT | MH_COT => 18,
        // RFC 6275, Section 6.1.7 — Binding Update: Sequence # (16 bits),
        // A|H|L|K|Reserved (16 bits), Lifetime (16 bits), Mobility Options.
        // RFC 6275, Section 6.1.8 — Binding Acknowledgement: Status (8
        // bits), K|Reserved (8 bits), Sequence # (16 bits), Lifetime (16
        // bits), Mobility Options.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.7>
        MH_BU | MH_BA => 6,
        // RFC 6275, Section 6.1.9 — Binding Error: Status (8 bits),
        // Reserved (8 bits), Home Address (128 bits), Mobility Options.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.1.9>
        MH_BE => 18,
        _ => return false,
    };
    if body.len() < fixed {
        return false;
    }

    match mh_type {
        MH_HOTI | MH_COTI => {
            buf.push_field(
                fd(MH_FD_INIT_COOKIE),
                FieldValue::Bytes(&body[2..10]),
                offset + 2..offset + 10,
            );
        }
        MH_HOT | MH_COT => {
            push_u16(buf, fd(MH_FD_NONCE_INDEX), body, offset);
            buf.push_field(
                fd(MH_FD_INIT_COOKIE),
                FieldValue::Bytes(&body[2..10]),
                offset + 2..offset + 10,
            );
            buf.push_field(
                fd(MH_FD_KEYGEN_TOKEN),
                FieldValue::Bytes(&body[10..18]),
                offset + 10..offset + 18,
            );
        }
        MH_BU => {
            push_u16(buf, fd(MH_FD_SEQUENCE_NUMBER), body, offset);
            push_u16(buf, fd(MH_FD_FLAGS), &body[2..], offset + 2);
            push_u16(buf, fd(MH_FD_LIFETIME), &body[4..], offset + 4);
        }
        MH_BA => {
            buf.push_field(
                fd(MH_FD_STATUS),
                FieldValue::U8(body[0]),
                offset..offset + 1,
            );
            buf.push_field(
                fd(MH_FD_ACK_FLAGS),
                FieldValue::U8(body[1]),
                offset + 1..offset + 2,
            );
            push_u16(buf, fd(MH_FD_SEQUENCE_NUMBER), &body[2..], offset + 2);
            push_u16(buf, fd(MH_FD_LIFETIME), &body[4..], offset + 4);
        }
        MH_BE => {
            buf.push_field(
                fd(MH_FD_STATUS),
                FieldValue::U8(body[0]),
                offset..offset + 1,
            );
            buf.push_field(
                fd(MH_FD_HOME_ADDRESS),
                FieldValue::Ipv6Addr(read_addr(&body[2..])),
                offset + 2..offset + 18,
            );
        }
        _ => {}
    }

    let options = &body[fixed..];
    if !options.is_empty() {
        let opt_offset = offset + fixed;
        let idx = buf.begin_container(
            fd(MH_FD_MOBILITY_OPTIONS),
            FieldValue::Array(0..0),
            opt_offset..opt_offset + options.len(),
        );
        push_mobility_options(buf, options, opt_offset);
        buf.end_container(idx);
    }
    true
}

/// Walk the mobility options of a Mobility Header message.
///
/// RFC 6275, Section 6.2.1 — options use a TLV format; Option Length is
/// the "length in octets of the mobility option, not including the Option
/// Type and Option Length fields." Section 6.2.2 — "the format of the Pad1
/// option is a special case -- it has neither Option Length nor Option Data
/// fields." Section 6.2.1 — "When processing a
/// Mobility Header containing an option for which the Option Type value is
/// not recognized by the receiver, the receiver MUST quietly ignore and
/// skip over the option".
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.1>
///
/// An option whose length runs past the header ends the walk: its type and
/// length are pushed together with the remaining octets as `malformed`.
fn push_mobility_options<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let mut pos = 0;
    let end = offset + data.len();
    while pos < data.len() {
        let opt_type = data[pos];
        let start = offset + pos;
        if opt_type == MO_PAD1 {
            let idx = begin_option(buf, opt_type, start..start + 1);
            buf.end_container(idx);
            pos += 1;
            continue;
        }
        let Some(&len) = data.get(pos + 1) else {
            let idx = begin_option(buf, opt_type, start..end);
            buf.push_field(
                &MOBILITY_OPTION_CHILDREN[MOC_MALFORMED],
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
                &MOBILITY_OPTION_CHILDREN[MOC_MALFORMED],
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
    let idx = buf.begin_container(&FD_MOBILITY_OPTION, FieldValue::Object(0..0), range);
    buf.push_field(
        &MOBILITY_OPTION_CHILDREN[MOC_TYPE],
        FieldValue::U8(opt_type),
        start..start + 1,
    );
    idx
}

fn push_length(buf: &mut DissectBuffer<'_>, len: u8, start: usize) {
    buf.push_field(
        &MOBILITY_OPTION_CHILDREN[MOC_LENGTH],
        FieldValue::U8(len),
        start + 1..start + 2,
    );
}

/// Push the data of one mobility option. Options with an unexpected length
/// keep their data as `value`.
fn push_option_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_type: u8,
    body: &'pkt [u8],
    offset: usize,
) {
    let fd = |i: usize| &MOBILITY_OPTION_CHILDREN[i];
    match (opt_type, body.len()) {
        // RFC 6275, Section 6.2.4 — Binding Refresh Advice: Length 2,
        // Refresh Interval (16 bits, units of 4 seconds).
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.4>
        (MO_BRA, 2) => push_u16(buf, fd(MOC_REFRESH_INTERVAL), body, offset),
        // RFC 6275, Section 6.2.5 — Alternate Care-of Address: Length 16.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.5>
        (MO_ALT_COA, 16) => {
            buf.push_field(
                fd(MOC_ALT_COA),
                FieldValue::Ipv6Addr(read_addr(body)),
                offset..offset + 16,
            );
        }
        // RFC 6275, Section 6.2.6 — Nonce Indices: Length 4, Home Nonce
        // Index (16 bits), Care-of Nonce Index (16 bits).
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.6>
        (MO_NONCE_INDICES, 4) => {
            push_u16(buf, fd(MOC_HOME_NONCE_INDEX), body, offset);
            push_u16(buf, fd(MOC_CARE_OF_NONCE_INDEX), &body[2..], offset + 2);
        }
        // RFC 6275, Section 6.2.7 — Binding Authorization Data: variable
        // length Authenticator.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.2.7>
        (MO_AUTH_DATA, 1..) => {
            buf.push_field(
                fd(MOC_AUTHENTICATOR),
                FieldValue::Bytes(body),
                offset..offset + body.len(),
            );
        }
        (_, 1..) => {
            buf.push_field(
                fd(MOC_VALUE),
                FieldValue::Bytes(body),
                offset..offset + body.len(),
            );
        }
        _ => {}
    }
}
