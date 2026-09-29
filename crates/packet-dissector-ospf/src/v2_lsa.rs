//! OSPFv2 LSA header and body decoding.
//!
//! ## References
//! - RFC 2328, Appendix A.4 (LSA formats): <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4>
//! - RFC 3101, Appendix C (NSSA-LSA): <https://www.rfc-editor.org/rfc/rfc3101#appendix-C>
//! - RFC 5250 (Opaque LSAs): <https://www.rfc-editor.org/rfc/rfc5250>
//! - IANA OSPFv2 parameters: <https://www.iana.org/assignments/ospfv2-parameters>
//! - IANA Opaque LSA option types: <https://www.iana.org/assignments/ospf-opaque-types>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32, read_ipv4_addr};

use crate::common::LSA_HEADER_SIZE;
use crate::tlv::{
    TLVS_DESCRIPTOR, TlvContext, UNPARSED_DESCRIPTOR, push_tlvs, push_unparsed, set_range_end,
};

/// Returns a human-readable name for OSPFv2 LS types.
///
/// RFC 2328, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.1>
/// and the IANA "OSPFv2 Link State (LS) Type" registry —
/// <https://www.iana.org/assignments/ospfv2-parameters>
pub(crate) fn lsa_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Router-LSA"),
        2 => Some("Network-LSA"),
        3 => Some("Summary-LSA (IP network)"),
        4 => Some("Summary-LSA (ASBR)"),
        5 => Some("AS-external-LSA"),
        6 => Some("Group-membership-LSA"),
        // RFC 3101, Appendix C — <https://www.rfc-editor.org/rfc/rfc3101#appendix-C>
        7 => Some("NSSA AS-external LSA"),
        // RFC 5250, Section 3 — <https://www.rfc-editor.org/rfc/rfc5250#section-3>
        9 => Some("Link-scoped Opaque LSA"),
        10 => Some("Area-scoped Opaque LSA"),
        11 => Some("AS-scoped Opaque LSA"),
        _ => None,
    }
}

/// Returns a human-readable name for Opaque LSA option types.
///
/// IANA "Opaque Link-State Advertisements (LSA) Option Types" —
/// <https://www.iana.org/assignments/ospf-opaque-types>
fn opaque_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Traffic Engineering LSA"),
        2 => Some("Sycamore Optical Topology Descriptions"),
        3 => Some("grace-LSA"),
        4 => Some("Router Information (RI)"),
        5 => Some("L1VPN LSA"),
        6 => Some("Inter-AS-TE-v2 LSA"),
        7 => Some("OSPFv2 Extended Prefix Opaque LSA"),
        8 => Some("OSPFv2 Extended Link Opaque LSA"),
        9 => Some("TTZ LSA"),
        10 => Some("OSPFv2 Dynamic Flooding Opaque LSA"),
        11 => Some("OSPFv2 Extended Inter-Area ASBR (EIA-ASBR) LSA"),
        _ => None,
    }
}

/// Returns a human-readable name for Router-LSA link types.
///
/// RFC 2328, Appendix A.4.2 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.2>
fn router_link_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Point-to-point"),
        2 => Some("Transit network"),
        3 => Some("Stub network"),
        4 => Some("Virtual link"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Field descriptor indices for [`LSA_FIELDS`].
const FD_LS_AGE: usize = 0;
const FD_OPTIONS: usize = 1;
const FD_LS_TYPE: usize = 2;
const FD_LINK_STATE_ID: usize = 3;
const FD_ADVERTISING_ROUTER: usize = 4;
const FD_LS_SEQUENCE_NUMBER: usize = 5;
const FD_LS_CHECKSUM: usize = 6;
const FD_LENGTH: usize = 7;
const FD_OPAQUE_TYPE: usize = 8;
const FD_OPAQUE_ID: usize = 9;
const FD_FLAGS: usize = 10;
const FD_FLAG_NT: usize = 11;
const FD_FLAG_V: usize = 12;
const FD_FLAG_E: usize = 13;
const FD_FLAG_B: usize = 14;
const FD_NUM_LINKS: usize = 15;
const FD_LINKS: usize = 16;
const FD_NETWORK_MASK: usize = 17;
const FD_ATTACHED_ROUTERS: usize = 18;
const FD_METRIC: usize = 19;
const FD_TOS_METRICS: usize = 20;
const FD_FORWARDING_ADDRESS: usize = 21;
const FD_EXTERNAL_ROUTE_TAG: usize = 22;
const FD_BODY: usize = 23;

/// Number of LSA header fields at the start of [`LSA_FIELDS`].
const HEADER_FIELD_COUNT: usize = 10;

/// Child fields of an LSA object: the 20-byte header, then the union of
/// the type-specific body fields (all optional).
static LSA_FIELDS: [FieldDescriptor; 26] = [
    FieldDescriptor::new("ls_age", "LS Age", FieldType::U16),
    FieldDescriptor::new("options", "Options", FieldType::U8),
    FieldDescriptor::new("ls_type", "LS Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => lsa_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("link_state_id", "Link State ID", FieldType::Ipv4Addr),
    FieldDescriptor::new(
        "advertising_router",
        "Advertising Router",
        FieldType::Ipv4Addr,
    ),
    FieldDescriptor::new("ls_sequence_number", "LS Sequence Number", FieldType::U32),
    FieldDescriptor::new("ls_checksum", "LS Checksum", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    // RFC 5250, Section 3 — Link State ID = Opaque Type (8 bits) + Opaque ID (24 bits)
    // <https://www.rfc-editor.org/rfc/rfc5250#section-3>
    FieldDescriptor::new("opaque_type", "Opaque Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => opaque_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("opaque_id", "Opaque ID", FieldType::U32).optional(),
    // Router-LSA — RFC 2328, Appendix A.4.2
    // <https://www.rfc-editor.org/rfc/rfc2328>
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("flag_nt", "Nt-bit (NSSA Translator)", FieldType::U8).optional(),
    FieldDescriptor::new("flag_v", "V-bit (Virtual Link Endpoint)", FieldType::U8).optional(),
    FieldDescriptor::new("flag_e", "E-bit", FieldType::U8).optional(),
    FieldDescriptor::new("flag_b", "B-bit (Area Border Router)", FieldType::U8).optional(),
    FieldDescriptor::new("num_links", "Number of Links", FieldType::U16).optional(),
    FieldDescriptor::new("links", "Links", FieldType::Array)
        .optional()
        .with_children(&LINK_FIELDS),
    // Network-LSA, Summary-LSA, AS-external-LSA
    FieldDescriptor::new("network_mask", "Network Mask", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("attached_routers", "Attached Routers", FieldType::Array).optional(),
    FieldDescriptor::new("metric", "Metric", FieldType::U32).optional(),
    FieldDescriptor::new("tos_metrics", "TOS Metrics", FieldType::Array)
        .optional()
        .with_children(&TOS_FIELDS),
    FieldDescriptor::new(
        "forwarding_address",
        "Forwarding Address",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new("external_route_tag", "External Route Tag", FieldType::U32).optional(),
    FieldDescriptor::new("body", "LSA Body", FieldType::Bytes).optional(),
    TLVS_DESCRIPTOR,
    UNPARSED_DESCRIPTOR,
];

/// Field descriptor indices for [`LINK_FIELDS`].
const FD_LINK_ID: usize = 0;
const FD_LINK_DATA: usize = 1;
const FD_LINK_TYPE: usize = 2;
const FD_NUM_TOS: usize = 3;
const FD_LINK_METRIC: usize = 4;
const FD_LINK_TOS_METRICS: usize = 5;

/// Child fields of a Router-LSA link.
///
/// RFC 2328, Appendix A.4.2 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.2>
static LINK_FIELDS: [FieldDescriptor; 6] = [
    FieldDescriptor::new("link_id", "Link ID", FieldType::Ipv4Addr),
    FieldDescriptor::new("link_data", "Link Data", FieldType::Ipv4Addr),
    FieldDescriptor::new("link_type", "Link Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => router_link_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("num_tos", "Number of TOS", FieldType::U8),
    FieldDescriptor::new("metric", "Metric", FieldType::U16),
    FieldDescriptor::new("tos_metrics", "TOS Metrics", FieldType::Array)
        .optional()
        .with_children(&TOS_FIELDS),
];

/// Field descriptor indices for [`TOS_FIELDS`].
const FD_TOS_FLAG_E: usize = 0;
const FD_TOS: usize = 1;
const FD_TOS_METRIC: usize = 2;
const FD_TOS_FORWARDING_ADDRESS: usize = 3;
const FD_TOS_EXTERNAL_ROUTE_TAG: usize = 4;

/// Child fields of a TOS metric entry.
static TOS_FIELDS: [FieldDescriptor; 5] = [
    FieldDescriptor::new("flag_e", "E-bit", FieldType::U8).optional(),
    FieldDescriptor::new("tos", "TOS", FieldType::U8),
    FieldDescriptor::new("metric", "Metric", FieldType::U32),
    FieldDescriptor::new(
        "forwarding_address",
        "Forwarding Address",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new("external_route_tag", "External Route Tag", FieldType::U32).optional(),
];

/// Resolves an LSA container's label from its `ls_type` child.
fn lsa_container_name(
    v: &FieldValue<'_>,
    children: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("ls_type", FieldValue::U8(t)) => lsa_type_name(*t),
            _ => None,
        }),
        _ => None,
    }
}

/// Child fields of an LSA header entry (DD and LSAck packets).
pub(crate) static LSA_HEADER_FIELDS: &[FieldDescriptor] = LSA_FIELDS.split_at(HEADER_FIELD_COUNT).0;

/// Child fields of a full LSA (LSU packets).
pub(crate) static LSA_CHILD_FIELDS: &[FieldDescriptor] = &LSA_FIELDS;

/// Container for an LSA header in DD and LSAck packets, labeled with the
/// LS type name.
pub(crate) static FD_LSA_HEADER: FieldDescriptor =
    FieldDescriptor::new("lsa_header", "LSA Header", FieldType::Object)
        .with_children(LSA_HEADER_FIELDS)
        .with_display_fn(lsa_container_name);

/// Container for a full LSA in LSU packets, labeled with the LS type name.
pub(crate) static FD_LSA: FieldDescriptor = FieldDescriptor::new("lsa", "LSA", FieldType::Object)
    .with_children(LSA_CHILD_FIELDS)
    .with_display_fn(lsa_container_name);

static FD_LINK: FieldDescriptor = FieldDescriptor::new("link", "Link", FieldType::Object)
    .with_children(&LINK_FIELDS)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("link_type", FieldValue::U8(t)) => router_link_type_name(*t),
            _ => None,
        }),
        _ => None,
    });

/// Element of the Network-LSA `attached_routers` array.
static FD_ATTACHED_ROUTER: FieldDescriptor =
    FieldDescriptor::new("attached_router", "Attached Router", FieldType::Ipv4Addr);

static FD_TOS_ENTRY: FieldDescriptor =
    FieldDescriptor::new("tos_metric", "TOS Metric", FieldType::Object).with_children(&TOS_FIELDS);

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Pushes the fields of an LSA header. `data` must hold at least 20 bytes.
///
/// RFC 2328, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.1>
pub(crate) fn push_lsa_header_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) {
    let ls_type = data[3];
    buf.push_field(
        &LSA_FIELDS[FD_LS_AGE],
        FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        offset..offset + 2,
    );
    buf.push_field(
        &LSA_FIELDS[FD_OPTIONS],
        FieldValue::U8(data[2]),
        offset + 2..offset + 3,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LS_TYPE],
        FieldValue::U8(ls_type),
        offset + 3..offset + 4,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LINK_STATE_ID],
        FieldValue::Ipv4Addr(read_ipv4_addr(data, 4).unwrap_or_default()),
        offset + 4..offset + 8,
    );
    buf.push_field(
        &LSA_FIELDS[FD_ADVERTISING_ROUTER],
        FieldValue::Ipv4Addr(read_ipv4_addr(data, 8).unwrap_or_default()),
        offset + 8..offset + 12,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LS_SEQUENCE_NUMBER],
        FieldValue::U32(read_be_u32(data, 12).unwrap_or_default()),
        offset + 12..offset + 16,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LS_CHECKSUM],
        FieldValue::U16(read_be_u16(data, 16).unwrap_or_default()),
        offset + 16..offset + 18,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LENGTH],
        FieldValue::U16(read_be_u16(data, 18).unwrap_or_default()),
        offset + 18..offset + 20,
    );
    // RFC 5250, Section 3 — <https://www.rfc-editor.org/rfc/rfc5250#section-3>
    // "The link-state ID of the Opaque LSA is divided into an Opaque type
    // field (the first 8 bits) and an Opaque ID (the remaining 24 bits)."
    if (9..=11).contains(&ls_type) {
        buf.push_field(
            &LSA_FIELDS[FD_OPAQUE_TYPE],
            FieldValue::U8(data[4]),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &LSA_FIELDS[FD_OPAQUE_ID],
            FieldValue::U32(read_be_u24(data, 5).unwrap_or_default()),
            offset + 5..offset + 8,
        );
    }
}

/// Pushes the fields of a complete LSA (header and body).
///
/// `data` is the whole LSA, as delimited by its `length` field.
pub(crate) fn push_lsa<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    push_lsa_header_fields(buf, data, offset);
    let body = &data[LSA_HEADER_SIZE..];
    let o = offset + LSA_HEADER_SIZE;
    let consumed = match data[3] {
        1 => push_router_lsa(buf, body, o),
        2 => push_network_lsa(buf, body, o),
        3 | 4 => push_summary_lsa(buf, body, o),
        5 | 7 => push_external_lsa(buf, body, o),
        9..=11 => push_opaque_lsa(buf, data[4], body, o),
        _ => None,
    };
    match consumed {
        Some(n) => push_unparsed(buf, &body[n..], o + n),
        None if body.is_empty() => {}
        None => buf.push_field(
            &LSA_FIELDS[FD_BODY],
            FieldValue::Bytes(body),
            o..o + body.len(),
        ),
    }
}

/// Pushes a U8 flag bit extracted from `byte`.
fn push_bit(buf: &mut DissectBuffer<'_>, f: usize, byte: u8, mask: u8, at: usize) {
    buf.push_field(
        &LSA_FIELDS[f],
        FieldValue::U8(u8::from(byte & mask != 0)),
        at..at + 1,
    );
}

/// Router-LSA body. Returns the number of octets decoded.
///
/// RFC 2328, Appendix A.4.2 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.2>
/// "0 |V|E|B| 0 | # links", followed by one entry per link.
/// RFC 3101, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc3101#section-2.1>
/// adds the Nt-bit (0x10).
fn push_router_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 4 {
        return None;
    }
    let flags = body[0];
    buf.push_field(&LSA_FIELDS[FD_FLAGS], FieldValue::U8(flags), o..o + 1);
    push_bit(buf, FD_FLAG_NT, flags, 0x10, o);
    push_bit(buf, FD_FLAG_V, flags, 0x04, o);
    push_bit(buf, FD_FLAG_E, flags, 0x02, o);
    push_bit(buf, FD_FLAG_B, flags, 0x01, o);
    let num_links = read_be_u16(body, 2).unwrap_or_default();
    buf.push_field(
        &LSA_FIELDS[FD_NUM_LINKS],
        FieldValue::U16(num_links),
        o + 2..o + 4,
    );

    let links_idx = buf.begin_container(
        &LSA_FIELDS[FD_LINKS],
        FieldValue::Array(0..0),
        o + 4..o + body.len(),
    );
    let mut pos = 4;
    for _ in 0..num_links {
        // Link ID, Link Data, Type, # TOS, metric (12 octets) + 4 per TOS.
        if pos + 12 > body.len() {
            break;
        }
        let num_tos = body[pos + 9] as usize;
        let end = pos + 12 + num_tos * 4;
        if end > body.len() {
            break;
        }
        let abs = o + pos;
        let link_idx = buf.begin_container(&FD_LINK, FieldValue::Object(0..0), abs..o + end);
        buf.push_field(
            &LINK_FIELDS[FD_LINK_ID],
            FieldValue::Ipv4Addr(read_ipv4_addr(body, pos).unwrap_or_default()),
            abs..abs + 4,
        );
        buf.push_field(
            &LINK_FIELDS[FD_LINK_DATA],
            FieldValue::Ipv4Addr(read_ipv4_addr(body, pos + 4).unwrap_or_default()),
            abs + 4..abs + 8,
        );
        buf.push_field(
            &LINK_FIELDS[FD_LINK_TYPE],
            FieldValue::U8(body[pos + 8]),
            abs + 8..abs + 9,
        );
        buf.push_field(
            &LINK_FIELDS[FD_NUM_TOS],
            FieldValue::U8(body[pos + 9]),
            abs + 9..abs + 10,
        );
        buf.push_field(
            &LINK_FIELDS[FD_LINK_METRIC],
            FieldValue::U16(read_be_u16(body, pos + 10).unwrap_or_default()),
            abs + 10..abs + 12,
        );
        if num_tos > 0 {
            // TOS | 0 | TOS metric (16 bits)
            let tos_idx = buf.begin_container(
                &LINK_FIELDS[FD_LINK_TOS_METRICS],
                FieldValue::Array(0..0),
                abs + 12..o + end,
            );
            for at in (pos + 12..end).step_by(4) {
                let metric = u32::from(read_be_u16(body, at + 2).unwrap_or_default());
                push_tos_entry(buf, body[at], metric, o + at, 2);
            }
            buf.end_container(tos_idx);
        }
        buf.end_container(link_idx);
        pos = end;
    }
    buf.end_container(links_idx);
    set_range_end(buf, links_idx, o + pos);
    Some(pos)
}

/// Pushes a 4-octet `tos_metric` object whose metric starts at `metric_at`.
fn push_tos_entry(buf: &mut DissectBuffer<'_>, tos: u8, metric: u32, abs: usize, metric_at: usize) {
    let idx = buf.begin_container(&FD_TOS_ENTRY, FieldValue::Object(0..0), abs..abs + 4);
    buf.push_field(&TOS_FIELDS[FD_TOS], FieldValue::U8(tos), abs..abs + 1);
    buf.push_field(
        &TOS_FIELDS[FD_TOS_METRIC],
        FieldValue::U32(metric),
        abs + metric_at..abs + 4,
    );
    buf.end_container(idx);
}

/// Pushes the leading `network_mask` shared by Network, Summary and
/// AS-external LSAs.
fn push_network_mask(buf: &mut DissectBuffer<'_>, body: &[u8], o: usize) -> Option<()> {
    let mask = read_ipv4_addr(body, 0).ok()?;
    buf.push_field(
        &LSA_FIELDS[FD_NETWORK_MASK],
        FieldValue::Ipv4Addr(mask),
        o..o + 4,
    );
    Some(())
}

/// Network-LSA body.
///
/// RFC 2328, Appendix A.4.3 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.3>
fn push_network_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    push_network_mask(buf, body, o)?;
    let end = 4 + (body.len() - 4) / 4 * 4;
    let idx = buf.begin_container(
        &LSA_FIELDS[FD_ATTACHED_ROUTERS],
        FieldValue::Array(0..0),
        o + 4..o + end,
    );
    for at in (4..end).step_by(4) {
        buf.push_field(
            &FD_ATTACHED_ROUTER,
            FieldValue::Ipv4Addr(read_ipv4_addr(body, at).unwrap_or_default()),
            o + at..o + at + 4,
        );
    }
    buf.end_container(idx);
    Some(end)
}

/// Summary-LSA body (types 3 and 4).
///
/// RFC 2328, Appendix A.4.4 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.4>
/// "Network Mask | 0 | metric (24 bits)", then "TOS | TOS metric" entries.
fn push_summary_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 8 {
        return None;
    }
    push_network_mask(buf, body, o)?;
    buf.push_field(
        &LSA_FIELDS[FD_METRIC],
        FieldValue::U32(read_be_u24(body, 5).unwrap_or_default()),
        o + 5..o + 8,
    );
    let end = 8 + (body.len() - 8) / 4 * 4;
    if end > 8 {
        let idx = buf.begin_container(
            &LSA_FIELDS[FD_TOS_METRICS],
            FieldValue::Array(0..0),
            o + 8..o + end,
        );
        for at in (8..end).step_by(4) {
            push_tos_entry(
                buf,
                body[at],
                read_be_u24(body, at + 1).unwrap_or_default(),
                o + at,
                1,
            );
        }
        buf.end_container(idx);
    }
    Some(end)
}

/// AS-external-LSA (type 5) and NSSA-LSA (type 7) body.
///
/// RFC 2328, Appendix A.4.5 — <https://www.rfc-editor.org/rfc/rfc2328#appendix-A.4.5>
/// "Network Mask", then 12-octet entries "E | TOS | metric | Forwarding
/// address | External Route Tag"; the first entry is for TOS 0.
/// RFC 3101, Appendix C — <https://www.rfc-editor.org/rfc/rfc3101#appendix-C>
/// uses the same format for the NSSA-LSA.
fn push_external_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 16 {
        return None;
    }
    push_network_mask(buf, body, o)?;
    push_bit(buf, FD_FLAG_E, body[4], 0x80, o + 4);
    buf.push_field(
        &LSA_FIELDS[FD_METRIC],
        FieldValue::U32(read_be_u24(body, 5).unwrap_or_default()),
        o + 5..o + 8,
    );
    buf.push_field(
        &LSA_FIELDS[FD_FORWARDING_ADDRESS],
        FieldValue::Ipv4Addr(read_ipv4_addr(body, 8).unwrap_or_default()),
        o + 8..o + 12,
    );
    buf.push_field(
        &LSA_FIELDS[FD_EXTERNAL_ROUTE_TAG],
        FieldValue::U32(read_be_u32(body, 12).unwrap_or_default()),
        o + 12..o + 16,
    );
    let end = 16 + (body.len() - 16) / 12 * 12;
    if end > 16 {
        let idx = buf.begin_container(
            &LSA_FIELDS[FD_TOS_METRICS],
            FieldValue::Array(0..0),
            o + 16..o + end,
        );
        for at in (16..end).step_by(12) {
            let abs = o + at;
            let entry = buf.begin_container(&FD_TOS_ENTRY, FieldValue::Object(0..0), abs..abs + 12);
            buf.push_field(
                &TOS_FIELDS[FD_TOS_FLAG_E],
                FieldValue::U8(body[at] >> 7),
                abs..abs + 1,
            );
            buf.push_field(
                &TOS_FIELDS[FD_TOS],
                FieldValue::U8(body[at] & 0x7F),
                abs..abs + 1,
            );
            buf.push_field(
                &TOS_FIELDS[FD_TOS_METRIC],
                FieldValue::U32(read_be_u24(body, at + 1).unwrap_or_default()),
                abs + 1..abs + 4,
            );
            buf.push_field(
                &TOS_FIELDS[FD_TOS_FORWARDING_ADDRESS],
                FieldValue::Ipv4Addr(read_ipv4_addr(body, at + 4).unwrap_or_default()),
                abs + 4..abs + 8,
            );
            buf.push_field(
                &TOS_FIELDS[FD_TOS_EXTERNAL_ROUTE_TAG],
                FieldValue::U32(read_be_u32(body, at + 8).unwrap_or_default()),
                abs + 8..abs + 12,
            );
            buf.end_container(entry);
        }
        buf.end_container(idx);
    }
    Some(end)
}

/// Opaque LSA body (types 9, 10, 11), decoded by Opaque Type.
///
/// RFC 5250, Section 3 — <https://www.rfc-editor.org/rfc/rfc5250#section-3>
fn push_opaque_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opaque_type: u8,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    let ctx = match opaque_type {
        // Traffic Engineering LSA — RFC 3630, Section 2
        // <https://www.rfc-editor.org/rfc/rfc3630#section-2>
        1 => TlvContext::Te,
        // Router Information LSA — RFC 7770, Section 2.1
        // <https://www.rfc-editor.org/rfc/rfc7770#section-2.1>
        4 => TlvContext::RouterInfo,
        // OSPFv2 Extended Prefix / Extended Link Opaque LSAs — RFC 7684
        // <https://www.rfc-editor.org/rfc/rfc7684>
        7 => TlvContext::ExtPrefix,
        8 => TlvContext::ExtLink,
        _ => return None,
    };
    push_tlvs(buf, body, o, ctx);
    Some(body.len())
}
