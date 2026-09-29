//! TCP option parsing.
//!
//! ## References
//! - RFC 9293, Section 3.1 (Options) / 3.2 (EOL, NOP, MSS):
//!   <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
//! - RFC 7323, Section 2.2 (Window Scale) / 3.2 (Timestamps):
//!   <https://www.rfc-editor.org/rfc/rfc7323>
//! - RFC 2018, Sections 2 and 3 (SACK-Permitted, SACK):
//!   <https://www.rfc-editor.org/rfc/rfc2018>
//! - RFC 2385, Section 3.0 (MD5 Signature):
//!   <https://www.rfc-editor.org/rfc/rfc2385#section-3.0>
//! - RFC 5925, Section 2.2 (TCP-AO): <https://www.rfc-editor.org/rfc/rfc5925#section-2.2>
//! - RFC 8684, Sections 3 and 7.2 (MPTCP): <https://www.rfc-editor.org/rfc/rfc8684>
//! - RFC 7413, Section 4.1.1 (Fast Open): <https://www.rfc-editor.org/rfc/rfc7413#section-4.1.1>
//! - RFC 9768, Section 3.2.3 (AccECN Option): <https://www.rfc-editor.org/rfc/rfc9768#section-3.2.3>
//! - RFC 6994, Section 3 (Experimental option ExIDs):
//!   <https://www.rfc-editor.org/rfc/rfc6994#section-3>
//! - IANA TCP Option Kind Numbers:
//!   <https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// RFC 9293, Section 3.2 — End of Option List.
const KIND_EOL: u8 = 0;
/// RFC 9293, Section 3.2 — No-Operation.
const KIND_NOP: u8 = 1;
/// RFC 9293, Section 3.2 — Maximum Segment Size.
const KIND_MSS: u8 = 2;
/// RFC 7323, Section 2.2 — Window Scale.
const KIND_WINDOW_SCALE: u8 = 3;
/// RFC 2018, Section 2 — SACK-Permitted.
const KIND_SACK_PERMITTED: u8 = 4;
/// RFC 2018, Section 3 — SACK.
const KIND_SACK: u8 = 5;
/// RFC 7323, Section 3.2 — Timestamps.
const KIND_TIMESTAMPS: u8 = 8;
/// RFC 2385, Section 3.0 — MD5 Signature.
const KIND_MD5: u8 = 19;
/// RFC 5925, Section 2.2 — TCP Authentication Option.
const KIND_TCP_AO: u8 = 29;
/// RFC 8684, Section 3 — Multipath TCP.
const KIND_MPTCP: u8 = 30;
/// RFC 7413, Section 4.1.1 — TCP Fast Open Cookie.
const KIND_FAST_OPEN: u8 = 34;
/// RFC 9768, Section 3.2.3 — AccECN Order 0.
const KIND_ACCECN0: u8 = 172;
/// RFC 9768, Section 3.2.3 — AccECN Order 1.
const KIND_ACCECN1: u8 = 174;
/// RFC 6994, Section 3 — RFC3692-style Experiment 1.
const KIND_EXP1: u8 = 253;
/// RFC 6994, Section 3 — RFC3692-style Experiment 2.
const KIND_EXP2: u8 = 254;

/// Returns the IANA "TCP Option Kind Numbers" meaning for `kind`.
///
/// IANA — <https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1>
pub(crate) fn option_kind_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0 => "End of Option List",
        1 => "No-Operation",
        2 => "Maximum Segment Size",
        3 => "Window Scale",
        4 => "SACK Permitted",
        5 => "SACK",
        6 => "Echo (obsoleted by option 8)",
        7 => "Echo Reply (obsoleted by option 8)",
        8 => "Timestamps",
        9 => "Partial Order Connection Permitted (obsolete)",
        10 => "Partial Order Service Profile (obsolete)",
        11 => "CC (obsolete)",
        12 => "CC.NEW (obsolete)",
        13 => "CC.ECHO (obsolete)",
        14 => "TCP Alternate Checksum Request (obsolete)",
        15 => "TCP Alternate Checksum Data (obsolete)",
        16 => "Skeeter",
        17 => "Bubba",
        18 => "Trailer Checksum Option",
        19 => "MD5 Signature Option",
        20 => "SCPS Capabilities",
        21 => "Selective Negative Acknowledgements",
        22 => "Record Boundaries",
        23 => "Corruption experienced",
        24 => "SNAP",
        26 => "TCP Compression Filter",
        27 => "Quick-Start Response",
        28 => "User Timeout Option",
        29 => "TCP Authentication Option (TCP-AO)",
        30 => "Multipath TCP (MPTCP)",
        34 => "TCP Fast Open Cookie",
        69 => "Encryption Negotiation (TCP-ENO)",
        172 => "Accurate ECN Order 0 (AccECN0)",
        174 => "Accurate ECN Order 1 (AccECN1)",
        253 => "RFC3692-style Experiment 1",
        254 => "RFC3692-style Experiment 2",
        _ => return None,
    })
}

/// Returns the RFC 8684 MPTCP option subtype symbol.
///
/// RFC 8684, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc8684#section-7.2>
fn mptcp_subtype_name(subtype: u8) -> Option<&'static str> {
    Some(match subtype {
        0x0 => "MP_CAPABLE",
        0x1 => "MP_JOIN",
        0x2 => "DSS",
        0x3 => "ADD_ADDR",
        0x4 => "REMOVE_ADDR",
        0x5 => "MP_PRIO",
        0x6 => "MP_FAIL",
        0x7 => "MP_FASTCLOSE",
        0x8 => "MP_TCPRST",
        0xf => "MP_EXPERIMENTAL",
        _ => return None,
    })
}

/// Child descriptor indices for [`OPTION_CHILDREN`].
const OC_KIND: usize = 0;
const OC_LENGTH: usize = 1;
const OC_MSS: usize = 2;
const OC_SHIFT_COUNT: usize = 3;
const OC_SACK_BLOCKS: usize = 4;
const OC_TS_VAL: usize = 5;
const OC_TS_ECR: usize = 6;
const OC_DIGEST: usize = 7;
const OC_KEY_ID: usize = 8;
const OC_RNEXT_KEY_ID: usize = 9;
const OC_MAC: usize = 10;
const OC_SUBTYPE: usize = 11;
const OC_COOKIE: usize = 12;
const OC_EE0B: usize = 13;
const OC_ECEB: usize = 14;
const OC_EE1B: usize = 15;
const OC_EXID: usize = 16;
const OC_DATA: usize = 17;

/// Child descriptor indices for [`SACK_BLOCK_CHILDREN`].
const SB_LEFT_EDGE: usize = 0;
const SB_RIGHT_EDGE: usize = 1;

/// Container descriptor for one TCP option.
///
/// `display_fn` resolves the container label to the option kind name.
pub(crate) static FD_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("kind", FieldValue::U8(k)) => option_kind_name(*k),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Container descriptor for one SACK block.
static FD_SACK_BLOCK: FieldDescriptor =
    FieldDescriptor::new("sack_block", "SACK Block", FieldType::Object);

/// Child descriptors of a SACK block.
///
/// RFC 2018, Section 3 — <https://www.rfc-editor.org/rfc/rfc2018#section-3>
static SACK_BLOCK_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("left_edge", "Left Edge", FieldType::U32),
    FieldDescriptor::new("right_edge", "Right Edge", FieldType::U32),
];

/// Child descriptors of a TCP option object within the `options` array.
pub(crate) static OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "kind",
        display_name: "Kind",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(k) => option_kind_name(*k),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new("mss", "Maximum Segment Size", FieldType::U16).optional(),
    FieldDescriptor::new("shift_count", "Shift Count", FieldType::U8).optional(),
    FieldDescriptor::new("sack_blocks", "SACK Blocks", FieldType::Array)
        .optional()
        .with_children(SACK_BLOCK_CHILDREN),
    FieldDescriptor::new("ts_val", "Timestamp Value", FieldType::U32).optional(),
    FieldDescriptor::new("ts_ecr", "Timestamp Echo Reply", FieldType::U32).optional(),
    FieldDescriptor::new("digest", "MD5 Digest", FieldType::Bytes).optional(),
    FieldDescriptor::new("key_id", "Key ID", FieldType::U8).optional(),
    FieldDescriptor::new("rnext_key_id", "RNext Key ID", FieldType::U8).optional(),
    FieldDescriptor::new("mac", "MAC", FieldType::Bytes).optional(),
    FieldDescriptor {
        name: "subtype",
        display_name: "MPTCP Subtype",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => mptcp_subtype_name(*s),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("cookie", "Fast Open Cookie", FieldType::Bytes).optional(),
    FieldDescriptor::new("ee0b", "ECT(0) Bytes Echo", FieldType::U32).optional(),
    FieldDescriptor::new("eceb", "CE Bytes Echo", FieldType::U32).optional(),
    FieldDescriptor::new("ee1b", "ECT(1) Bytes Echo", FieldType::U32).optional(),
    FieldDescriptor::new("exid", "Experiment ID", FieldType::U16).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Parse the TCP Options area into a sequence of option objects.
///
/// `opts` is the Options area (`data[20..header_len]`) and `base` is its
/// absolute offset in the packet. Malformed options never fail the packet
/// because the header length is already known from Data Offset: parsing
/// stops at the first option whose length is invalid or runs past the
/// header, and that option's remaining bytes are exposed as `data`.
///
/// RFC 9293, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
pub(crate) fn parse_options<'pkt>(buf: &mut DissectBuffer<'pkt>, opts: &'pkt [u8], base: usize) {
    let mut pos = 0;
    while pos < opts.len() {
        let kind = opts[pos];
        let start = base + pos;

        // RFC 9293, Section 3.1 — "Case 1:  A single octet of option-kind."
        if kind == KIND_EOL || kind == KIND_NOP {
            let idx = buf.begin_container(&FD_OPTION, FieldValue::Object(0..0), start..start + 1);
            push_kind(buf, kind, start);
            buf.end_container(idx);
            // RFC 9293, Section 3.1 — "The content of the header beyond the
            // End of Option List Option MUST be header padding of zeros
            // (MUST-69)."
            if kind == KIND_EOL {
                return;
            }
            pos += 1;
            continue;
        }

        // RFC 9293, Section 3.1 — "Case 2:  An octet of option-kind (Kind),
        // an octet of option-length, and the actual option-data octets."
        let Some(&len) = opts.get(pos + 1) else {
            // Kind byte with no room for the length byte.
            let idx = buf.begin_container(&FD_OPTION, FieldValue::Object(0..0), start..start + 1);
            push_kind(buf, kind, start);
            buf.end_container(idx);
            return;
        };
        let len_usize = len as usize;

        // RFC 9293, Section 3.1 — "The option-length counts the two octets of
        // option-kind and option-length as well as the option-data octets."
        // A length below 2 or past the header cannot be delimited, so the rest
        // of the Options area is reported as this option's data.
        if len_usize < 2 || pos + len_usize > opts.len() {
            let end = base + opts.len();
            let idx = buf.begin_container(&FD_OPTION, FieldValue::Object(0..0), start..end);
            push_kind(buf, kind, start);
            push_length(buf, len, start);
            if pos + 2 < opts.len() {
                buf.push_field(
                    &OPTION_CHILDREN[OC_DATA],
                    FieldValue::Bytes(&opts[pos + 2..]),
                    start + 2..end,
                );
            }
            buf.end_container(idx);
            return;
        }

        let end = start + len_usize;
        let body = &opts[pos + 2..pos + len_usize];
        let body_start = start + 2;
        let idx = buf.begin_container(&FD_OPTION, FieldValue::Object(0..0), start..end);
        push_kind(buf, kind, start);
        push_length(buf, len, start);
        if !decode_body(buf, kind, body, body_start) && !body.is_empty() {
            buf.push_field(
                &OPTION_CHILDREN[OC_DATA],
                FieldValue::Bytes(body),
                body_start..end,
            );
        }
        buf.end_container(idx);
        pos += len_usize;
    }
}

fn push_kind(buf: &mut DissectBuffer<'_>, kind: u8, start: usize) {
    buf.push_field(
        &OPTION_CHILDREN[OC_KIND],
        FieldValue::U8(kind),
        start..start + 1,
    );
}

fn push_length(buf: &mut DissectBuffer<'_>, len: u8, start: usize) {
    buf.push_field(
        &OPTION_CHILDREN[OC_LENGTH],
        FieldValue::U8(len),
        start + 1..start + 2,
    );
}

fn push_u32(buf: &mut DissectBuffer<'_>, child: usize, bytes: &[u8], start: usize) {
    let mut v = 0u32;
    for &b in bytes {
        v = (v << 8) | u32::from(b);
    }
    buf.push_field(
        &OPTION_CHILDREN[child],
        FieldValue::U32(v),
        start..start + bytes.len(),
    );
}

/// Decode the option-data of a well-formed option (length already checked
/// against the Options area).
///
/// Returns `false` when `kind` is not decoded or its length does not match
/// the option definition; the caller then exposes `body` as `data`.
fn decode_body<'pkt>(buf: &mut DissectBuffer<'pkt>, kind: u8, body: &'pkt [u8], at: usize) -> bool {
    match (kind, body.len()) {
        // RFC 9293, Section 3.2 — "Length:  1 byte; Length == 4."
        (KIND_MSS, 2) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_MSS],
                FieldValue::U16(u16::from_be_bytes([body[0], body[1]])),
                at..at + 2,
            );
            true
        }
        // RFC 7323, Section 2.2 — Kind: 3, Length: 3 bytes, shift.cnt.
        (KIND_WINDOW_SCALE, 1) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_SHIFT_COUNT],
                FieldValue::U8(body[0]),
                at..at + 1,
            );
            true
        }
        // RFC 2018, Section 2 — Kind: 4, Length: 2.
        (KIND_SACK_PERMITTED, 0) => true,
        // RFC 2018, Section 3 — "Each contiguous block of data queued at the
        // data receiver is defined in the SACK option by two 32-bit unsigned
        // integers in network byte order".
        (KIND_SACK, n) if n > 0 && n % 8 == 0 => {
            let arr = buf.begin_container(
                &OPTION_CHILDREN[OC_SACK_BLOCKS],
                FieldValue::Array(0..0),
                at..at + n,
            );
            for (i, block) in body.chunks_exact(8).enumerate() {
                let bs = at + i * 8;
                let obj = buf.begin_container(&FD_SACK_BLOCK, FieldValue::Object(0..0), bs..bs + 8);
                buf.push_field(
                    &SACK_BLOCK_CHILDREN[SB_LEFT_EDGE],
                    FieldValue::U32(u32::from_be_bytes([block[0], block[1], block[2], block[3]])),
                    bs..bs + 4,
                );
                buf.push_field(
                    &SACK_BLOCK_CHILDREN[SB_RIGHT_EDGE],
                    FieldValue::U32(u32::from_be_bytes([block[4], block[5], block[6], block[7]])),
                    bs + 4..bs + 8,
                );
                buf.end_container(obj);
            }
            buf.end_container(arr);
            true
        }
        // RFC 7323, Section 3.2 — Kind: 8, Length: 10 bytes, TSval, TSecr.
        (KIND_TIMESTAMPS, 8) => {
            push_u32(buf, OC_TS_VAL, &body[0..4], at);
            push_u32(buf, OC_TS_ECR, &body[4..8], at + 4);
            true
        }
        // RFC 2385, Section 3.0 — "The MD5 digest is always 16 bytes in length".
        (KIND_MD5, 16) => {
            buf.push_field(
                &OPTION_CHILDREN[OC_DIGEST],
                FieldValue::Bytes(body),
                at..at + 16,
            );
            true
        }
        // RFC 5925, Section 2.2 — "The Length value MUST be greater than or
        // equal to 4."
        (KIND_TCP_AO, n) if n >= 2 => {
            buf.push_field(
                &OPTION_CHILDREN[OC_KEY_ID],
                FieldValue::U8(body[0]),
                at..at + 1,
            );
            buf.push_field(
                &OPTION_CHILDREN[OC_RNEXT_KEY_ID],
                FieldValue::U8(body[1]),
                at + 1..at + 2,
            );
            if n > 2 {
                buf.push_field(
                    &OPTION_CHILDREN[OC_MAC],
                    FieldValue::Bytes(&body[2..]),
                    at + 2..at + n,
                );
            }
            true
        }
        // RFC 8684, Section 3 — "This subtype is a 4-bit field -- the first 4
        // bits of the option payload". The low 4 bits of that octet are
        // subtype-specific, so `data` starts at the subtype octet.
        (KIND_MPTCP, n) if n >= 1 => {
            buf.push_field(
                &OPTION_CHILDREN[OC_SUBTYPE],
                FieldValue::U8(body[0] >> 4),
                at..at + 1,
            );
            buf.push_field(
                &OPTION_CHILDREN[OC_DATA],
                FieldValue::Bytes(body),
                at..at + n,
            );
            true
        }
        // RFC 7413, Section 4.1.1 — "Cookie          0, or 4 to 16 bytes
        // (Length - 2)"; "The number MUST be even."
        // "When a cookie is not present or is empty, the option is used by
        // the client to request a cookie from the server." A cookie request
        // (Length 2) therefore has no `cookie` field.
        (KIND_FAST_OPEN, 0) => true,
        (KIND_FAST_OPEN, n) if (4..=16).contains(&n) && n % 2 == 0 => {
            buf.push_field(
                &OPTION_CHILDREN[OC_COOKIE],
                FieldValue::Bytes(body),
                at..at + n,
            );
            true
        }
        // RFC 9768, Section 3.2.3 — "if the AccECN Option is of any other
        // length, implementations MUST use those whole 3-octet fields that
        // fit within the length and ignore the remainder of the option,
        // treating it as padding."
        (KIND_ACCECN0 | KIND_ACCECN1, _) => {
            let order: [usize; 3] = if kind == KIND_ACCECN0 {
                [OC_EE0B, OC_ECEB, OC_EE1B]
            } else {
                [OC_EE1B, OC_ECEB, OC_EE0B]
            };
            let fields = (body.len() / 3).min(3);
            for (i, field) in body.chunks_exact(3).take(fields).enumerate() {
                push_u32(buf, order[i], field, at + i * 3);
            }
            // Keep the ignored remainder visible rather than dropping it.
            let used = fields * 3;
            if used < body.len() {
                buf.push_field(
                    &OPTION_CHILDREN[OC_DATA],
                    FieldValue::Bytes(&body[used..]),
                    at + used..at + body.len(),
                );
            }
            true
        }
        // RFC 6994, Section 3.1 — "ExIDs are registered with IANA using
        // "first come, first served" (FCFS) priority based on the first two
        // bytes.  Those two bytes are thus sufficient to interpret which
        // experimental option is contained in the option field."
        (KIND_EXP1 | KIND_EXP2, n) if n >= 2 => {
            buf.push_field(
                &OPTION_CHILDREN[OC_EXID],
                FieldValue::U16(u16::from_be_bytes([body[0], body[1]])),
                at..at + 2,
            );
            if n > 2 {
                buf.push_field(
                    &OPTION_CHILDREN[OC_DATA],
                    FieldValue::Bytes(&body[2..]),
                    at + 2..at + n,
                );
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_kind_names_follow_iana_registry() {
        let named = [
            0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 26, 27, 28, 29, 30, 34, 69, 172, 174, 253, 254,
        ];
        for kind in 0u8..=255 {
            assert_eq!(
                option_kind_name(kind).is_some(),
                named.contains(&kind),
                "kind {kind}"
            );
        }
        assert_eq!(option_kind_name(25), None); // Unassigned
        assert_eq!(option_kind_name(173), None); // Reserved
    }

    #[test]
    fn mptcp_subtype_names_follow_rfc8684() {
        let expected = [
            "MP_CAPABLE",
            "MP_JOIN",
            "DSS",
            "ADD_ADDR",
            "REMOVE_ADDR",
            "MP_PRIO",
            "MP_FAIL",
            "MP_FASTCLOSE",
            "MP_TCPRST",
        ];
        for (i, name) in expected.iter().enumerate() {
            assert_eq!(mptcp_subtype_name(i as u8), Some(*name));
        }
        for unassigned in 0x9..=0xe {
            assert_eq!(mptcp_subtype_name(unassigned), None);
        }
        assert_eq!(mptcp_subtype_name(0xf), Some("MP_EXPERIMENTAL"));
    }
}
