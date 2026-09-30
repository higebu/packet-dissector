//! IPv6 Hop-by-Hop and Destination option parsing.
//!
//! ## References
//! - RFC 8200, Section 4.2 (Extension Header Options): <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
//! - RFC 2711, Section 2.1 (Router Alert): <https://www.rfc-editor.org/rfc/rfc2711#section-2.1>
//! - RFC 2675, Section 2 (Jumbo Payload): <https://www.rfc-editor.org/rfc/rfc2675#section-2>
//! - RFC 2473, Section 5.1 (Tunnel Encapsulation Limit): <https://www.rfc-editor.org/rfc/rfc2473#section-5.1>
//! - RFC 6275, Section 6.3 (Home Address): <https://www.rfc-editor.org/rfc/rfc6275#section-6.3>
//! - RFC 5570, Section 5.1 (CALIPSO): <https://www.rfc-editor.org/rfc/rfc5570#section-5.1>
//! - RFC 6553, Section 3 (RPL Option): <https://www.rfc-editor.org/rfc/rfc6553#section-3>
//! - RFC 9008, Section 11.1 (RPL Option type 0x23): <https://www.rfc-editor.org/rfc/rfc9008#section-11.1>
//! - RFC 7731, Section 6.1 (MPL Option): <https://www.rfc-editor.org/rfc/rfc7731#section-6.1>
//! - RFC 9486, Section 3 (IOAM): <https://www.rfc-editor.org/rfc/rfc9486#section-3>
//! - RFC 8250, Section 3.2.1 (PDM): <https://www.rfc-editor.org/rfc/rfc8250#section-3.2.1>
//! - RFC 4782, Section 3.2 (Quick-Start for IPv6): <https://www.rfc-editor.org/rfc/rfc4782#section-3.2>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// RFC 8200, Section 4.2 — Pad1 (single octet, no length).
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
const OPT_PAD1: u8 = 0x00;
/// RFC 8200, Section 4.2 — PadN.
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
const OPT_PADN: u8 = 0x01;
/// RFC 2473, Section 5.1 — Tunnel Encapsulation Limit.
/// <https://www.rfc-editor.org/rfc/rfc2473#section-5.1>
const OPT_TUNNEL_ENCAP_LIMIT: u8 = 0x04;
/// RFC 2711, Section 2.1 — Router Alert.
/// <https://www.rfc-editor.org/rfc/rfc2711#section-2.1>
const OPT_ROUTER_ALERT: u8 = 0x05;
/// RFC 5570, Section 5.1 — CALIPSO.
/// <https://www.rfc-editor.org/rfc/rfc5570#section-5.1>
const OPT_CALIPSO: u8 = 0x07;
/// RFC 8250, Section 3.2.1 — Performance and Diagnostic Metrics.
/// <https://www.rfc-editor.org/rfc/rfc8250#section-3.2.1>
const OPT_PDM: u8 = 0x0F;
/// RFC 9486, Section 3 — IOAM (destination option).
/// <https://www.rfc-editor.org/rfc/rfc9486#section-3>
const OPT_IOAM_DEST: u8 = 0x11;
/// RFC 9008, Section 11.1 — RPL Option (current type).
/// <https://www.rfc-editor.org/rfc/rfc9008#section-11.1>
const OPT_RPL: u8 = 0x23;
/// RFC 4782, Section 3.2 — Quick-Start.
/// <https://www.rfc-editor.org/rfc/rfc4782#section-3.2>
const OPT_QUICK_START: u8 = 0x26;
/// RFC 9486, Section 3 — IOAM (hop-by-hop option).
/// <https://www.rfc-editor.org/rfc/rfc9486#section-3>
const OPT_IOAM_HBH: u8 = 0x31;
/// RFC 6553, Section 3 — RPL Option (original type).
/// <https://www.rfc-editor.org/rfc/rfc6553#section-3>
const OPT_RPL_LEGACY: u8 = 0x63;
/// RFC 7731, Section 6.1 — MPL Option.
/// <https://www.rfc-editor.org/rfc/rfc7731#section-6.1>
const OPT_MPL: u8 = 0x6D;
/// RFC 2675, Section 2 — Jumbo Payload.
/// <https://www.rfc-editor.org/rfc/rfc2675#section-2>
const OPT_JUMBO: u8 = 0xC2;
/// RFC 6275, Section 6.3 — Home Address.
/// <https://www.rfc-editor.org/rfc/rfc6275#section-6.3>
const OPT_HOME_ADDRESS: u8 = 0xC9;

/// Returns the name of an IPv6 Hop-by-Hop / Destination option type.
///
/// Names follow the IANA "Destination Options and Hop-by-Hop Options"
/// registry (<https://www.iana.org/assignments/ipv6-parameters>) for the
/// options this module decodes.
fn ipv6_option_name(t: u8) -> Option<&'static str> {
    match t {
        OPT_PAD1 => Some("Pad1"),
        OPT_PADN => Some("PadN"),
        OPT_TUNNEL_ENCAP_LIMIT => Some("Tunnel Encapsulation Limit"),
        OPT_ROUTER_ALERT => Some("Router Alert"),
        OPT_CALIPSO => Some("CALIPSO"),
        OPT_PDM => Some("Performance and Diagnostic Metrics"),
        OPT_IOAM_DEST | OPT_IOAM_HBH => Some("IOAM"),
        OPT_RPL => Some("RPL Option"),
        // RFC 9008, Section 11.1 — 0x63 is "RPL Option (DEPRECATED)".
        // <https://www.rfc-editor.org/rfc/rfc9008#section-11.1>
        OPT_RPL_LEGACY => Some("RPL Option (deprecated)"),
        OPT_QUICK_START => Some("Quick-Start"),
        OPT_MPL => Some("MPL Option"),
        OPT_JUMBO => Some("Jumbo Payload"),
        OPT_HOME_ADDRESS => Some("Home Address"),
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
            ("type", FieldValue::U8(t)) => ipv6_option_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

const OC_TYPE: usize = 0;
const OC_ACTION: usize = 1;
const OC_CHANGE: usize = 2;
const OC_LENGTH: usize = 3;
const OC_ROUTER_ALERT: usize = 4;
const OC_JUMBO: usize = 5;
const OC_TUNNEL_ENCAP_LIMIT: usize = 6;
const OC_HOME_ADDRESS: usize = 7;
const OC_CALIPSO_DOI: usize = 8;
const OC_CMPT_LENGTH: usize = 9;
const OC_SENS_LEVEL: usize = 10;
const OC_CHECKSUM: usize = 11;
const OC_COMPARTMENT_BITMAP: usize = 12;
const OC_RPL_DOWN: usize = 13;
const OC_RPL_RANK_ERROR: usize = 14;
const OC_RPL_FORWARDING_ERROR: usize = 15;
const OC_RPL_INSTANCE_ID: usize = 16;
const OC_SENDER_RANK: usize = 17;
const OC_SUB_TLVS: usize = 18;
const OC_MPL_SEED_ID_LENGTH: usize = 19;
const OC_MPL_MAX: usize = 20;
const OC_MPL_VERSION: usize = 21;
const OC_MPL_SEQUENCE: usize = 22;
const OC_MPL_SEED_ID: usize = 23;
const OC_IOAM_RESERVED: usize = 24;
const OC_IOAM_TYPE: usize = 25;
const OC_IOAM_DATA: usize = 26;
const OC_SCALE_DTLR: usize = 27;
const OC_SCALE_DTLS: usize = 28;
const OC_PSN_THIS_PACKET: usize = 29;
const OC_PSN_LAST_RECEIVED: usize = 30;
const OC_DELTA_TIME_LAST_RECEIVED: usize = 31;
const OC_DELTA_TIME_LAST_SENT: usize = 32;
const OC_QS_FUNCTION: usize = 33;
const OC_QS_RATE: usize = 34;
const OC_QS_TTL: usize = 35;
const OC_QS_NONCE: usize = 36;
const OC_VALUE: usize = 37;
const OC_MALFORMED: usize = 38;

/// Child descriptors of an option object (union over all option types).
pub(crate) static OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _| match v {
            FieldValue::U8(t) => ipv6_option_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("action", "Action", FieldType::U8),
    FieldDescriptor::new("change", "May Change En Route", FieldType::U8),
    FieldDescriptor::new("length", "Opt Data Len", FieldType::U8).optional(),
    FieldDescriptor::new("router_alert", "Router Alert Value", FieldType::U16).optional(),
    FieldDescriptor::new(
        "jumbo_payload_length",
        "Jumbo Payload Length",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "tunnel_encap_limit",
        "Tunnel Encapsulation Limit",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("home_address", "Home Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new(
        "calipso_doi",
        "CALIPSO Domain of Interpretation",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("cmpt_length", "Compartment Length", FieldType::U8).optional(),
    FieldDescriptor::new("sens_level", "Sensitivity Level", FieldType::U8).optional(),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16).optional(),
    FieldDescriptor::new("compartment_bitmap", "Compartment Bitmap", FieldType::Bytes).optional(),
    FieldDescriptor::new("rpl_down", "Down", FieldType::U8).optional(),
    FieldDescriptor::new("rpl_rank_error", "Rank-Error", FieldType::U8).optional(),
    FieldDescriptor::new("rpl_forwarding_error", "Forwarding-Error", FieldType::U8).optional(),
    FieldDescriptor::new("rpl_instance_id", "RPLInstanceID", FieldType::U8).optional(),
    FieldDescriptor::new("sender_rank", "SenderRank", FieldType::U16).optional(),
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Bytes).optional(),
    FieldDescriptor::new("mpl_seed_id_length", "Seed-ID Length (S)", FieldType::U8).optional(),
    FieldDescriptor::new("mpl_max", "Max Sequence (M)", FieldType::U8).optional(),
    FieldDescriptor::new("mpl_version", "Version (V)", FieldType::U8).optional(),
    FieldDescriptor::new("mpl_sequence", "Sequence", FieldType::U8).optional(),
    FieldDescriptor::new("mpl_seed_id", "Seed-ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("ioam_reserved", "Reserved", FieldType::U8).optional(),
    FieldDescriptor::new("ioam_type", "IOAM Option-Type", FieldType::U8).optional(),
    FieldDescriptor::new("ioam_data", "IOAM Option Data", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "scale_dtlr",
        "Scale Delta Time Last Received",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("scale_dtls", "Scale Delta Time Last Sent", FieldType::U8).optional(),
    FieldDescriptor::new(
        "psn_this_packet",
        "Packet Sequence Number This Packet",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "psn_last_received",
        "Packet Sequence Number Last Received",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "delta_time_last_received",
        "Delta Time Last Received",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "delta_time_last_sent",
        "Delta Time Last Sent",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("qs_function", "Quick-Start Function", FieldType::U8).optional(),
    FieldDescriptor::new("qs_rate", "Quick-Start Rate", FieldType::U8).optional(),
    FieldDescriptor::new("qs_ttl", "Quick-Start TTL", FieldType::U8).optional(),
    FieldDescriptor::new("qs_nonce", "Quick-Start Nonce", FieldType::U32).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("malformed", "Malformed Data", FieldType::Bytes).optional(),
];

/// Walk the Options area of a Hop-by-Hop or Destination Options header and
/// push one `option` object per option into the currently open `options`
/// array.
///
/// `data` is the Options area (after Next Header and Hdr Ext Len) and
/// `offset` its absolute position. Returns the Jumbo Payload Length when a
/// well-formed Jumbo Payload option is present.
///
/// RFC 8200, Section 4.2 — options are TLV-encoded: an 8-bit Option Type,
/// an 8-bit Opt Data Len ("Length of the Option Data field of this option,
/// in octets") and the Option Data. "the format of the Pad1 option is a
/// special case -- it does not have length and value fields."
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
///
/// An option whose Opt Data Len runs past the header ends the walk: its
/// type (and length, when present) are pushed together with the remaining
/// octets as `malformed` bytes.
pub(crate) fn push_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> Option<u32> {
    let mut jumbo = None;
    let mut pos = 0;
    let end = offset + data.len();
    while pos < data.len() {
        let opt_type = data[pos];
        let start = offset + pos;

        if opt_type == OPT_PAD1 {
            let idx = begin_option(buf, opt_type, start..start + 1);
            buf.end_container(idx);
            pos += 1;
            continue;
        }

        let Some(&len) = data.get(pos + 1) else {
            let idx = begin_option(buf, opt_type, start..end);
            buf.push_field(
                &OPTION_CHILDREN[OC_MALFORMED],
                FieldValue::Bytes(&[]),
                end..end,
            );
            buf.end_container(idx);
            break;
        };
        let body_start = pos + 2;
        let body_end = body_start + len as usize;
        if body_end > data.len() {
            let idx = begin_option(buf, opt_type, start..end);
            push_length(buf, len, start);
            buf.push_field(
                &OPTION_CHILDREN[OC_MALFORMED],
                FieldValue::Bytes(&data[body_start..]),
                start + 2..end,
            );
            buf.end_container(idx);
            break;
        }

        let idx = begin_option(buf, opt_type, start..offset + body_end);
        push_length(buf, len, start);
        let body = &data[body_start..body_end];
        if let Some(j) = push_option_body(buf, opt_type, body, start + 2) {
            jumbo = Some(j);
        }
        buf.end_container(idx);
        pos = body_end;
    }
    jumbo
}

/// Open an `option` object and push the Option Type and its action and
/// change bits.
///
/// RFC 8200, Section 4.2 — "The Option Type identifiers are internally
/// encoded such that their highest-order 2 bits specify the action that
/// must be taken if the processing IPv6 node does not recognize the Option
/// Type" and "The third-highest-order bit of the Option Type specifies
/// whether or not the Option Data of that option can change en route".
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.2>
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
        &OPTION_CHILDREN[OC_ACTION],
        FieldValue::U8(opt_type >> 6),
        octet.clone(),
    );
    buf.push_field(
        &OPTION_CHILDREN[OC_CHANGE],
        FieldValue::U8((opt_type >> 5) & 0x01),
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

fn push_u8(buf: &mut DissectBuffer<'_>, fd: usize, v: u8, at: usize) {
    buf.push_field(&OPTION_CHILDREN[fd], FieldValue::U8(v), at..at + 1);
}

fn push_u16(buf: &mut DissectBuffer<'_>, fd: usize, b: &[u8], at: usize) {
    buf.push_field(
        &OPTION_CHILDREN[fd],
        FieldValue::U16(u16::from_be_bytes([b[0], b[1]])),
        at..at + 2,
    );
}

fn push_bytes<'pkt>(buf: &mut DissectBuffer<'pkt>, fd: usize, b: &'pkt [u8], at: usize) {
    if !b.is_empty() {
        buf.push_field(&OPTION_CHILDREN[fd], FieldValue::Bytes(b), at..at + b.len());
    }
}

/// Push the decoded Option Data. `body` is the Option Data and `offset` its
/// absolute position. Returns the Jumbo Payload Length for a Jumbo Payload
/// option. Options with an unexpected length keep their data as `value`,
/// which also holds option data this module does not decode; CALIPSO octets
/// that disagree with its Cmpt Length are pushed as `malformed`.
fn push_option_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_type: u8,
    body: &'pkt [u8],
    offset: usize,
) -> Option<u32> {
    match (opt_type, body.len()) {
        // RFC 2711, Section 2.1 — Router Alert: "length = 2", "Value:  A 2
        // octet code in network byte order".
        // <https://www.rfc-editor.org/rfc/rfc2711#section-2.1>
        (OPT_ROUTER_ALERT, 2) => push_u16(buf, OC_ROUTER_ALERT, body, offset),
        // RFC 2675, Section 2 — Jumbo Payload: "Opt Data Len 8-bit value 4",
        // a 32-bit Jumbo Payload Length.
        // <https://www.rfc-editor.org/rfc/rfc2675#section-2>
        (OPT_JUMBO, 4) => {
            let len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            buf.push_field(
                &OPTION_CHILDREN[OC_JUMBO],
                FieldValue::U32(len),
                offset..offset + 4,
            );
            return Some(len);
        }
        // RFC 2473, Section 5.1 — Tunnel Encapsulation Limit: "Opt Data Len
        // value 1 - the data portion of the Option is one octet long."
        // <https://www.rfc-editor.org/rfc/rfc2473#section-5.1>
        (OPT_TUNNEL_ENCAP_LIMIT, 1) => push_u8(buf, OC_TUNNEL_ENCAP_LIMIT, body[0], offset),
        // RFC 6275, Section 6.3 — Home Address: Option Length "MUST be set
        // to 16", followed by the home address.
        // <https://www.rfc-editor.org/rfc/rfc6275#section-6.3>
        (OPT_HOME_ADDRESS, 16) => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(body);
            buf.push_field(
                &OPTION_CHILDREN[OC_HOME_ADDRESS],
                FieldValue::Ipv6Addr(addr),
                offset..offset + 16,
            );
        }
        // RFC 5570, Section 5.1 — CALIPSO: Domain of Interpretation (32
        // bits), Cmpt Length (8 bits, in 32-bit words), Sens Level (8 bits),
        // Checksum (16 bits), Compartment Bitmap (optional).
        // <https://www.rfc-editor.org/rfc/rfc5570#section-5.1>
        // RFC 5570, Section 5.1.3 — Cmpt Length "specifies the size of the
        // Compartment Bitmap field in 32-bit words". Octets that disagree
        // with it (a short bitmap or trailing data) are pushed as
        // `malformed`.
        // <https://www.rfc-editor.org/rfc/rfc5570#section-5.1.3>
        (OPT_CALIPSO, 8..) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_CALIPSO_DOI],
                FieldValue::U32(u32::from_be_bytes([body[0], body[1], body[2], body[3]])),
                offset..offset + 4,
            );
            push_u8(buf, OC_CMPT_LENGTH, body[4], offset + 4);
            push_u8(buf, OC_SENS_LEVEL, body[5], offset + 5);
            push_u16(buf, OC_CHECKSUM, &body[6..8], offset + 6);
            let bitmap_end = 8 + 4 * usize::from(body[4]);
            if bitmap_end <= body.len() {
                push_bytes(buf, OC_COMPARTMENT_BITMAP, &body[8..bitmap_end], offset + 8);
                push_bytes(buf, OC_MALFORMED, &body[bitmap_end..], offset + bitmap_end);
            } else {
                push_bytes(buf, OC_MALFORMED, &body[8..], offset + 8);
            }
        }
        // RFC 6553, Section 3 — RPL Option: O|R|F|00000, RPLInstanceID,
        // SenderRank, optional sub-TLVs. RFC 9008, Section 11.1 assigns 0x23
        // as the RPL Option type with the same format.
        // <https://www.rfc-editor.org/rfc/rfc6553#section-3>
        (OPT_RPL | OPT_RPL_LEGACY, 4..) => {
            push_u8(buf, OC_RPL_DOWN, body[0] >> 7, offset);
            push_u8(buf, OC_RPL_RANK_ERROR, (body[0] >> 6) & 0x01, offset);
            push_u8(buf, OC_RPL_FORWARDING_ERROR, (body[0] >> 5) & 0x01, offset);
            push_u8(buf, OC_RPL_INSTANCE_ID, body[1], offset + 1);
            push_u16(buf, OC_SENDER_RANK, &body[2..4], offset + 2);
            push_bytes(buf, OC_SUB_TLVS, &body[4..], offset + 4);
        }
        // RFC 7731, Section 6.1 — MPL Option: S (2 bits), M, V, rsv (4
        // bits), sequence, seed-id whose size S selects (0, 2, 8 or 16
        // octets). "Future updates to this specification may define
        // additional fields following the seed-id field"; such octets are
        // kept undecoded as `value`.
        // <https://www.rfc-editor.org/rfc/rfc7731#section-6.1>
        (OPT_MPL, 2..) => {
            let s = body[0] >> 6;
            let seed_len = match s {
                0 => 0,
                1 => 2,
                2 => 8,
                _ => 16,
            };
            if body.len() < 2 + seed_len {
                push_bytes(buf, OC_VALUE, body, offset);
                return None;
            }
            push_u8(buf, OC_MPL_SEED_ID_LENGTH, s, offset);
            push_u8(buf, OC_MPL_MAX, (body[0] >> 5) & 0x01, offset);
            push_u8(buf, OC_MPL_VERSION, (body[0] >> 4) & 0x01, offset);
            push_u8(buf, OC_MPL_SEQUENCE, body[1], offset + 1);
            push_bytes(buf, OC_MPL_SEED_ID, &body[2..2 + seed_len], offset + 2);
            push_bytes(buf, OC_VALUE, &body[2 + seed_len..], offset + 2 + seed_len);
        }
        // RFC 9486, Section 3 — IOAM: Reserved (8 bits), IOAM Option-Type
        // (8 bits), Option Data.
        // <https://www.rfc-editor.org/rfc/rfc9486#section-3>
        (OPT_IOAM_DEST | OPT_IOAM_HBH, 2..) => {
            push_u8(buf, OC_IOAM_RESERVED, body[0], offset);
            push_u8(buf, OC_IOAM_TYPE, body[1], offset + 1);
            push_bytes(buf, OC_IOAM_DATA, &body[2..], offset + 2);
        }
        // RFC 8250, Section 3.2.1 — PDM: "Option Length 8-bit unsigned
        // integer. Length of the option, in octets, excluding the Option
        // Type and Option Length fields. This field MUST be set to 10."
        // <https://www.rfc-editor.org/rfc/rfc8250#section-3.2.1>
        (OPT_PDM, 10) => {
            push_u8(buf, OC_SCALE_DTLR, body[0], offset);
            push_u8(buf, OC_SCALE_DTLS, body[1], offset + 1);
            push_u16(buf, OC_PSN_THIS_PACKET, &body[2..4], offset + 2);
            push_u16(buf, OC_PSN_LAST_RECEIVED, &body[4..6], offset + 4);
            push_u16(buf, OC_DELTA_TIME_LAST_RECEIVED, &body[6..8], offset + 6);
            push_u16(buf, OC_DELTA_TIME_LAST_SENT, &body[8..10], offset + 8);
        }
        // RFC 4782, Section 3.2 — the IPv6 Quick-Start option uses the same
        // data layout as the IPv4 option (Section 3.1): Function (4 bits),
        // Rate Request / Report (4 bits), QS TTL (Rate Request only), 30-bit
        // QS Nonce and 2-bit Reserved.
        // <https://www.rfc-editor.org/rfc/rfc4782#section-3.2>
        (OPT_QUICK_START, 6) => {
            let function = body[0] >> 4;
            push_u8(buf, OC_QS_FUNCTION, function, offset);
            push_u8(buf, OC_QS_RATE, body[0] & 0x0F, offset);
            if function == 0 {
                push_u8(buf, OC_QS_TTL, body[1], offset + 1);
            }
            let word = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
            buf.push_field(
                &OPTION_CHILDREN[OC_QS_NONCE],
                FieldValue::U32(word >> 2),
                offset + 2..offset + 6,
            );
        }
        _ => push_bytes(buf, OC_VALUE, body, offset),
    }
    None
}
