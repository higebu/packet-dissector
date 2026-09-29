//! IPv4 option parsing.
//!
//! ## References
//! - RFC 791, Section 3.1 (Options): <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
//! - RFC 1108, Section 2 (DoD Basic Security option): <https://www.rfc-editor.org/rfc/rfc1108#section-2>
//! - RFC 2113, Section 2.1 (Router Alert option): <https://www.rfc-editor.org/rfc/rfc2113#section-2.1>
//! - RFC 4782, Section 3.1 (Quick-Start option for IPv4): <https://www.rfc-editor.org/rfc/rfc4782#section-3.1>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// RFC 791, Section 3.1 — End of Option List (type 0, single octet).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_EOL: u8 = 0;
/// RFC 791, Section 3.1 — No Operation (type 1, single octet).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_NOP: u8 = 1;
/// RFC 791, Section 3.1 — Record Route (type 7).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_RR: u8 = 7;
/// RFC 4782, Section 3.1 — Quick-Start (type 25).
/// <https://www.rfc-editor.org/rfc/rfc4782#section-3.1>
const OPT_QUICK_START: u8 = 25;
/// RFC 791, Section 3.1 — Internet Timestamp (type 68).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_TIMESTAMP: u8 = 68;
/// RFC 1108, Section 2 — DoD Basic Security (type 130).
/// <https://www.rfc-editor.org/rfc/rfc1108#section-2>
const OPT_BASIC_SECURITY: u8 = 130;
/// RFC 791, Section 3.1 — Loose Source and Record Route (type 131).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_LSRR: u8 = 131;
/// RFC 791, Section 3.1 — Stream Identifier (type 136).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_STREAM_ID: u8 = 136;
/// RFC 791, Section 3.1 — Strict Source and Record Route (type 137).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const OPT_SSRR: u8 = 137;
/// RFC 2113, Section 2.1 — Router Alert (type 148).
/// <https://www.rfc-editor.org/rfc/rfc2113#section-2.1>
const OPT_ROUTER_ALERT: u8 = 148;

/// Returns the name of an IPv4 option type.
///
/// Names follow the IANA "IP Option Numbers" registry
/// (<https://www.iana.org/assignments/ip-parameters>) for the options this
/// module decodes.
pub(crate) fn ipv4_option_name(t: u8) -> Option<&'static str> {
    match t {
        OPT_EOL => Some("End of Option List"),
        OPT_NOP => Some("No Operation"),
        OPT_RR => Some("Record Route"),
        OPT_QUICK_START => Some("Quick-Start"),
        OPT_TIMESTAMP => Some("Internet Timestamp"),
        OPT_BASIC_SECURITY => Some("Basic Security"),
        OPT_LSRR => Some("Loose Source and Record Route"),
        OPT_STREAM_ID => Some("Stream Identifier"),
        OPT_SSRR => Some("Strict Source and Record Route"),
        OPT_ROUTER_ALERT => Some("Router Alert"),
        _ => None,
    }
}

/// Container descriptor for one option. The display name resolves to the
/// option name via the nested `type` field.
static FD_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => ipv4_option_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Container descriptor for one Internet Timestamp entry.
static FD_TIMESTAMP_ENTRY: FieldDescriptor =
    FieldDescriptor::new("entry", "Entry", FieldType::Object)
        .with_children(TIMESTAMP_ENTRY_CHILDREN);

const TE_ADDRESS: usize = 0;
const TE_TIMESTAMP: usize = 1;

/// Child descriptors of an Internet Timestamp entry (RFC 791, Section 3.1).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
static TIMESTAMP_ENTRY_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("address", "Internet Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U32),
];

const OC_TYPE: usize = 0;
const OC_COPIED: usize = 1;
const OC_CLASS: usize = 2;
const OC_NUMBER: usize = 3;
const OC_LENGTH: usize = 4;
const OC_POINTER: usize = 5;
const OC_ROUTE: usize = 6;
const OC_OVERFLOW: usize = 7;
const OC_FLAG: usize = 8;
const OC_ENTRIES: usize = 9;
const OC_STREAM_ID: usize = 10;
const OC_CLASSIFICATION_LEVEL: usize = 11;
const OC_PROTECTION_AUTHORITY: usize = 12;
const OC_ROUTER_ALERT: usize = 13;
const OC_QS_FUNCTION: usize = 14;
const OC_QS_RATE: usize = 15;
const OC_QS_TTL: usize = 16;
const OC_QS_NONCE: usize = 17;
const OC_VALUE: usize = 18;
const OC_MALFORMED: usize = 19;

/// Child descriptors of an option object (union over all option types).
pub(crate) static OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _| match v {
            FieldValue::U8(t) => ipv4_option_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("copied", "Copied", FieldType::U8),
    FieldDescriptor::new("class", "Class", FieldType::U8),
    FieldDescriptor::new("number", "Number", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new("pointer", "Pointer", FieldType::U8).optional(),
    FieldDescriptor::new("route", "Route Data", FieldType::Array).optional(),
    FieldDescriptor::new("overflow", "Overflow", FieldType::U8).optional(),
    FieldDescriptor::new("flag", "Flag", FieldType::U8).optional(),
    FieldDescriptor::new("entries", "Timestamp Entries", FieldType::Array)
        .optional()
        .with_children(TIMESTAMP_ENTRY_CHILDREN),
    FieldDescriptor::new("stream_id", "Stream ID", FieldType::U16).optional(),
    FieldDescriptor::new(
        "classification_level",
        "Classification Level",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "protection_authority",
        "Protection Authority Flags",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("router_alert", "Router Alert Value", FieldType::U16).optional(),
    FieldDescriptor::new("qs_function", "Quick-Start Function", FieldType::U8).optional(),
    FieldDescriptor::new("qs_rate", "Quick-Start Rate", FieldType::U8).optional(),
    FieldDescriptor::new("qs_ttl", "Quick-Start TTL", FieldType::U8).optional(),
    FieldDescriptor::new("qs_nonce", "Quick-Start Nonce", FieldType::U32).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("malformed", "Malformed Data", FieldType::Bytes).optional(),
];

/// Walk the IPv4 options area and push one `option` object per option into
/// the currently open `options` array.
///
/// `data` is the options area (`IHL * 4 - 20` octets) and `offset` is its
/// absolute position in the packet.
///
/// RFC 791, Section 3.1 — "There are two cases for the format of an option:
/// Case 1: A single octet of option-type. Case 2: An option-type octet, an
/// option-length octet, and the actual option-data octets."
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
///
/// An option whose length is below 2 or runs past the header ends the walk:
/// its type (and length, when present) are pushed together with the rest of
/// the options area as `malformed` bytes.
pub(crate) fn push_options<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let mut pos = 0;
    while pos < data.len() {
        let opt_type = data[pos];
        let start = offset + pos;

        // RFC 791, Section 3.1 — End of Option List and No Operation occupy
        // a single octet and have no length octet.
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        if opt_type == OPT_EOL || opt_type == OPT_NOP {
            let idx = begin_option(buf, opt_type, start..start + 1);
            buf.end_container(idx);
            // RFC 791, Section 3.1 — End of Option List "is used at the end
            // of all options"; octets after it are header padding.
            // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
            if opt_type == OPT_EOL {
                return;
            }
            pos += 1;
            continue;
        }

        let end = offset + data.len();
        let Some(&len) = data.get(pos + 1) else {
            let idx = begin_option(buf, opt_type, start..end);
            buf.push_field(
                &OPTION_CHILDREN[OC_MALFORMED],
                FieldValue::Bytes(&[]),
                end..end,
            );
            buf.end_container(idx);
            return;
        };
        let len = len as usize;
        // RFC 791, Section 3.1 — "The option-length octet counts the
        // option-type octet and the option-length octet as well as the
        // option-data octets."
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        if len < 2 || pos + len > data.len() {
            let idx = begin_option(buf, opt_type, start..end);
            push_length(buf, len as u8, start);
            buf.push_field(
                &OPTION_CHILDREN[OC_MALFORMED],
                FieldValue::Bytes(&data[pos + 2..]),
                start + 2..end,
            );
            buf.end_container(idx);
            return;
        }

        let idx = begin_option(buf, opt_type, start..start + len);
        push_length(buf, len as u8, start);
        push_option_body(buf, opt_type, &data[pos + 2..pos + len], start + 2);
        buf.end_container(idx);
        pos += len;
    }
}

/// Open an `option` object and push the option-type octet and its three
/// sub-fields.
///
/// RFC 791, Section 3.1 — "The option-type octet is viewed as having 3
/// fields: 1 bit copied flag, 2 bits option class, 5 bits option number."
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
fn begin_option(buf: &mut DissectBuffer<'_>, opt_type: u8, range: core::ops::Range<usize>) -> u32 {
    let start = range.start;
    let idx = buf.begin_container(&FD_OPTION, FieldValue::Object(0..0), range);
    let octet = start..start + 1;
    buf.push_field(
        &OPTION_CHILDREN[OC_TYPE],
        FieldValue::U8(opt_type),
        octet.clone(),
    );
    buf.push_field(
        &OPTION_CHILDREN[OC_COPIED],
        FieldValue::U8(opt_type >> 7),
        octet.clone(),
    );
    buf.push_field(
        &OPTION_CHILDREN[OC_CLASS],
        FieldValue::U8((opt_type >> 5) & 0x03),
        octet.clone(),
    );
    buf.push_field(
        &OPTION_CHILDREN[OC_NUMBER],
        FieldValue::U8(opt_type & 0x1F),
        octet,
    );
    idx
}

fn push_length(buf: &mut DissectBuffer<'_>, len: u8, start: usize) {
    buf.push_field(
        &OPTION_CHILDREN[OC_LENGTH],
        FieldValue::U8(len),
        start + 1..start + 2,
    );
}

/// Push the decoded option data. `body` is the option-data (after the type
/// and length octets) and `offset` its absolute position.
fn push_option_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_type: u8,
    body: &'pkt [u8],
    offset: usize,
) {
    match (opt_type, body.len()) {
        // RFC 791, Section 3.1 — Record Route / Loose Source and Record
        // Route / Strict Source and Record Route: "the pointer octet, and
        // length-3 octets of route data". "A route data is composed of a
        // series of internet addresses. Each internet address is 32 bits or
        // 4 octets."
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        (OPT_RR | OPT_LSRR | OPT_SSRR, 1..) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_POINTER],
                FieldValue::U8(body[0]),
                offset..offset + 1,
            );
            push_route(buf, &body[1..], offset + 1);
        }
        // RFC 791, Section 3.1 — Internet Timestamp: pointer, overflow (4
        // bits) and flag (4 bits), then timestamps (flag 0) or address +
        // timestamp pairs (flags 1 and 3).
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        (OPT_TIMESTAMP, 2..) => {
            let flag = body[1] & 0x0F;
            buf.push_field(
                &OPTION_CHILDREN[OC_POINTER],
                FieldValue::U8(body[0]),
                offset..offset + 1,
            );
            buf.push_field(
                &OPTION_CHILDREN[OC_OVERFLOW],
                FieldValue::U8(body[1] >> 4),
                offset + 1..offset + 2,
            );
            buf.push_field(
                &OPTION_CHILDREN[OC_FLAG],
                FieldValue::U8(flag),
                offset + 1..offset + 2,
            );
            push_timestamps(buf, &body[2..], offset + 2, flag);
        }
        // RFC 791, Section 3.1 — Stream Identifier: "Type=136 Length=4",
        // carrying a 16-bit stream identifier.
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        (OPT_STREAM_ID, 2) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_STREAM_ID],
                FieldValue::U16(u16::from_be_bytes([body[0], body[1]])),
                offset..offset + 2,
            );
        }
        // RFC 1108, Section 2 — DoD Basic Security: classification level
        // (one octet) followed by protection authority flags (variable).
        // <https://www.rfc-editor.org/rfc/rfc1108#section-2>
        (OPT_BASIC_SECURITY, 1..) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_CLASSIFICATION_LEVEL],
                FieldValue::U8(body[0]),
                offset..offset + 1,
            );
            if body.len() > 1 {
                buf.push_field(
                    &OPTION_CHILDREN[OC_PROTECTION_AUTHORITY],
                    FieldValue::Bytes(&body[1..]),
                    offset + 1..offset + body.len(),
                );
            }
        }
        // RFC 2113, Section 2.1 — Router Alert: "Length: 4", "Value: A two
        // octet code".
        // <https://www.rfc-editor.org/rfc/rfc2113#section-2.1>
        (OPT_ROUTER_ALERT, 2) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_ROUTER_ALERT],
                FieldValue::U16(u16::from_be_bytes([body[0], body[1]])),
                offset..offset + 2,
            );
        }
        // RFC 4782, Section 3.1 — Quick-Start option for IPv4, Length=8.
        // <https://www.rfc-editor.org/rfc/rfc4782#section-3.1>
        (OPT_QUICK_START, 6) => push_quick_start(buf, body, offset),
        _ => {
            if !body.is_empty() {
                buf.push_field(
                    &OPTION_CHILDREN[OC_VALUE],
                    FieldValue::Bytes(body),
                    offset..offset + body.len(),
                );
            }
        }
    }
}

/// Push a route data area as an array of IPv4 addresses. Trailing octets
/// that do not form a whole address are left out.
fn push_route<'pkt>(buf: &mut DissectBuffer<'pkt>, route: &'pkt [u8], offset: usize) {
    let idx = buf.begin_container(
        &OPTION_CHILDREN[OC_ROUTE],
        FieldValue::Array(0..0),
        offset..offset + route.len(),
    );
    for (i, addr) in route.chunks_exact(4).enumerate() {
        let start = offset + i * 4;
        buf.push_field(
            &OPTION_CHILDREN[OC_ROUTE],
            FieldValue::Ipv4Addr([addr[0], addr[1], addr[2], addr[3]]),
            start..start + 4,
        );
    }
    buf.end_container(idx);
}

/// Push the Internet Timestamp data area.
///
/// RFC 791, Section 3.1 — flag 0: "time stamps only, stored in consecutive
/// 32-bit words"; flag 1: "each timestamp is preceded with internet address
/// of the registering entity"; flag 3: "the internet address fields are
/// prespecified". Other flag values have no defined layout, so the area is
/// kept as raw bytes.
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
fn push_timestamps<'pkt>(buf: &mut DissectBuffer<'pkt>, area: &'pkt [u8], offset: usize, flag: u8) {
    let entry_len = match flag {
        0 => 4,
        1 | 3 => 8,
        _ => {
            if !area.is_empty() {
                buf.push_field(
                    &OPTION_CHILDREN[OC_VALUE],
                    FieldValue::Bytes(area),
                    offset..offset + area.len(),
                );
            }
            return;
        }
    };
    let idx = buf.begin_container(
        &OPTION_CHILDREN[OC_ENTRIES],
        FieldValue::Array(0..0),
        offset..offset + area.len(),
    );
    for (i, entry) in area.chunks_exact(entry_len).enumerate() {
        let start = offset + i * entry_len;
        let obj = buf.begin_container(
            &FD_TIMESTAMP_ENTRY,
            FieldValue::Object(0..0),
            start..start + entry_len,
        );
        let ts = &entry[entry_len - 4..];
        if entry_len == 8 {
            buf.push_field(
                &TIMESTAMP_ENTRY_CHILDREN[TE_ADDRESS],
                FieldValue::Ipv4Addr([entry[0], entry[1], entry[2], entry[3]]),
                start..start + 4,
            );
        }
        buf.push_field(
            &TIMESTAMP_ENTRY_CHILDREN[TE_TIMESTAMP],
            FieldValue::U32(u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]])),
            start + entry_len - 4..start + entry_len,
        );
        buf.end_container(obj);
    }
    buf.end_container(idx);
}

/// Push the Quick-Start option data (6 octets after type and length).
///
/// RFC 4782, Section 3.1 — "The third byte includes a four-bit Function
/// field." With Function "0000" (Rate Request) the rest of the byte is the
/// Rate Request and "the fourth byte contains the Quick-Start TTL"; with
/// "1000" (Report of Approved Rate) it is the Rate Report and "the fourth
/// byte of the Quick-Start Option is not used". "Bytes 5-8 contain a 30-bit
/// QS Nonce and a 2-bit Reserved field."
/// <https://www.rfc-editor.org/rfc/rfc4782#section-3.1>
///
/// The same layout is used by the IPv6 Quick-Start option (RFC 4782,
/// Section 3.2), which the IPv6 crate decodes separately.
fn push_quick_start<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], offset: usize) {
    let function = body[0] >> 4;
    buf.push_field(
        &OPTION_CHILDREN[OC_QS_FUNCTION],
        FieldValue::U8(function),
        offset..offset + 1,
    );
    buf.push_field(
        &OPTION_CHILDREN[OC_QS_RATE],
        FieldValue::U8(body[0] & 0x0F),
        offset..offset + 1,
    );
    if function == 0 {
        buf.push_field(
            &OPTION_CHILDREN[OC_QS_TTL],
            FieldValue::U8(body[1]),
            offset + 1..offset + 2,
        );
    }
    let word = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
    buf.push_field(
        &OPTION_CHILDREN[OC_QS_NONCE],
        FieldValue::U32(word >> 2),
        offset + 2..offset + 6,
    );
}
