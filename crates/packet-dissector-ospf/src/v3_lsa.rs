//! OSPFv3 LSA header and body decoding.
//!
//! ## References
//! - RFC 5340, Appendix A.4 (LSA formats): <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4>
//! - RFC 7770, Section 2.2 (Router Information LSA): <https://www.rfc-editor.org/rfc/rfc7770#section-2.2>
//! - RFC 8362, Section 4 (Extended LSAs): <https://www.rfc-editor.org/rfc/rfc8362#section-4>
//! - RFC 9513, Section 7 (SRv6 Locator LSA): <https://www.rfc-editor.org/rfc/rfc9513#section-7>
//! - IANA OSPFv3 parameters: <https://www.iana.org/assignments/ospfv3-parameters>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv4_addr};

use crate::common::LSA_HEADER_SIZE;
use crate::tlv::{
    TLVS_DESCRIPTOR, TlvContext, UNPARSED_DESCRIPTOR, prefix_octets, prefix_to_ipv6, push_ipv4_at,
    push_ipv6_at, push_tlvs, push_u8_at, push_u24_at, push_unparsed, set_range_end,
};

/// Returns a human-readable name for OSPFv3 LSA function codes.
///
/// RFC 5340, Appendix A.4.2.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.2.1>
/// and the IANA "OSPFv3 LSA Function Codes" registry —
/// <https://www.iana.org/assignments/ospfv3-parameters>
///
/// The LS Type field is 16 bits. The high-order three bits encode the U-bit
/// (bit 15) and the S1/S2 flooding-scope bits (bits 13-14); the low-order
/// 13 bits are the LSA function code. Function code 6 is explicitly marked
/// "Deprecated (may be reassigned)" and has no name.
pub(crate) fn lsa_type_name(ls_type: u16) -> Option<&'static str> {
    // Function code is in the lower 13 bits; U/S2/S1 bits are in the upper 3 bits.
    let function_code = ls_type & 0x1FFF;
    match function_code {
        1 => Some("Router-LSA"),
        2 => Some("Network-LSA"),
        3 => Some("Inter-Area-Prefix-LSA"),
        4 => Some("Inter-Area-Router-LSA"),
        5 => Some("AS-External-LSA"),
        // 6: Deprecated (may be reassigned) — intentionally not named.
        7 => Some("NSSA-LSA"),
        8 => Some("Link-LSA"),
        9 => Some("Intra-Area-Prefix-LSA"),
        10 => Some("Intra-Area-TE-LSA"),
        11 => Some("GRACE-LSA"),
        // RFC 7770, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc7770#section-2.2>
        12 => Some("OSPFv3 Router Information (RI) LSA"),
        13 => Some("Inter-AS-TE-v3 LSA"),
        14 => Some("OSPFv3 L1VPN LSA"),
        15 => Some("OSPFv3 Autoconfiguration (AC) LSA"),
        16 => Some("OSPFv3 Dynamic Flooding LSA"),
        // RFC 8362, Section 4 — <https://www.rfc-editor.org/rfc/rfc8362#section-4>
        33 => Some("E-Router-LSA"),
        34 => Some("E-Network-LSA"),
        35 => Some("E-Inter-Area-Prefix-LSA"),
        36 => Some("E-Inter-Area-Router-LSA"),
        37 => Some("E-AS-External-LSA"),
        // 38: "Unused (Not to be allocated)" — intentionally not named.
        39 => Some("E-Type-7-LSA"),
        40 => Some("E-Link-LSA"),
        41 => Some("E-Intra-Area-Prefix-LSA"),
        // RFC 9513, Section 7 — <https://www.rfc-editor.org/rfc/rfc9513#section-7>
        42 => Some("SRv6 Locator LSA"),
        _ => None,
    }
}

/// Returns a human-readable name for OSPFv3 Router-LSA interface types.
///
/// RFC 5340, Appendix A.4.3 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.3>
fn router_link_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Point-to-point"),
        2 => Some("Transit network"),
        4 => Some("Virtual link"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Field descriptor indices for [`LSA_FIELDS`].
const FD_LS_AGE: usize = 0;
const FD_LS_TYPE: usize = 1;
const FD_LINK_STATE_ID: usize = 2;
const FD_ADVERTISING_ROUTER: usize = 3;
const FD_LS_SEQUENCE_NUMBER: usize = 4;
const FD_LS_CHECKSUM: usize = 5;
const FD_LENGTH: usize = 6;
const FD_FLAGS: usize = 7;
const FD_FLAG_NT: usize = 8;
const FD_FLAG_V: usize = 9;
const FD_FLAG_E: usize = 10;
const FD_FLAG_B: usize = 11;
const FD_FLAG_F: usize = 12;
const FD_FLAG_T: usize = 13;
const FD_OPTIONS: usize = 14;
const FD_LINKS: usize = 15;
const FD_ATTACHED_ROUTERS: usize = 16;
const FD_METRIC: usize = 17;
const FD_PREFIX_LENGTH: usize = 18;
const FD_PREFIX_OPTIONS: usize = 19;
const FD_PREFIX: usize = 20;
const FD_DESTINATION_ROUTER_ID: usize = 21;
const FD_REFERENCED_LS_TYPE: usize = 22;
const FD_FORWARDING_ADDRESS: usize = 23;
const FD_EXTERNAL_ROUTE_TAG: usize = 24;
const FD_REFERENCED_LINK_STATE_ID: usize = 25;
const FD_ROUTER_PRIORITY: usize = 26;
const FD_LINK_LOCAL_ADDRESS: usize = 27;
const FD_NUM_PREFIXES: usize = 28;
const FD_PREFIXES: usize = 29;
const FD_REFERENCED_ADVERTISING_ROUTER: usize = 30;
const FD_BODY: usize = 31;

/// Number of LSA header fields at the start of [`LSA_FIELDS`].
const HEADER_FIELD_COUNT: usize = 7;

/// Child fields of an LSA object: the 20-byte header, then the union of
/// the type-specific body fields (all optional).
static LSA_FIELDS: [FieldDescriptor; 34] = [
    FieldDescriptor::new("ls_age", "LS Age", FieldType::U16),
    FieldDescriptor::new("ls_type", "LS Type", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => lsa_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("link_state_id", "Link State ID", FieldType::U32),
    FieldDescriptor::new(
        "advertising_router",
        "Advertising Router",
        FieldType::Ipv4Addr,
    ),
    FieldDescriptor::new("ls_sequence_number", "LS Sequence Number", FieldType::U32),
    FieldDescriptor::new("ls_checksum", "LS Checksum", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("flag_nt", "Nt-bit (NSSA Translator)", FieldType::U8).optional(),
    FieldDescriptor::new("flag_v", "V-bit (Virtual Link Endpoint)", FieldType::U8).optional(),
    FieldDescriptor::new("flag_e", "E-bit", FieldType::U8).optional(),
    FieldDescriptor::new("flag_b", "B-bit (Area Border Router)", FieldType::U8).optional(),
    FieldDescriptor::new("flag_f", "F-bit (Forwarding Address)", FieldType::U8).optional(),
    FieldDescriptor::new("flag_t", "T-bit (External Route Tag)", FieldType::U8).optional(),
    FieldDescriptor::new("options", "Options", FieldType::U32).optional(),
    FieldDescriptor::new("links", "Interfaces", FieldType::Array)
        .optional()
        .with_children(&LINK_FIELDS),
    FieldDescriptor::new("attached_routers", "Attached Routers", FieldType::Array).optional(),
    FieldDescriptor::new("metric", "Metric", FieldType::U32).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("prefix_options", "Prefix Options", FieldType::U8).optional(),
    FieldDescriptor::new("prefix", "Address Prefix", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new(
        "destination_router_id",
        "Destination Router ID",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new("referenced_ls_type", "Referenced LS Type", FieldType::U16).optional(),
    FieldDescriptor::new(
        "forwarding_address",
        "Forwarding Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("external_route_tag", "External Route Tag", FieldType::U32).optional(),
    FieldDescriptor::new(
        "referenced_link_state_id",
        "Referenced Link State ID",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("router_priority", "Router Priority", FieldType::U8).optional(),
    FieldDescriptor::new(
        "link_local_address",
        "Link-local Interface Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("num_prefixes", "Number of Prefixes", FieldType::U32).optional(),
    FieldDescriptor::new("prefixes", "Prefixes", FieldType::Array)
        .optional()
        .with_children(&PREFIX_FIELDS),
    FieldDescriptor::new(
        "referenced_advertising_router",
        "Referenced Advertising Router",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new("body", "LSA Body", FieldType::Bytes).optional(),
    TLVS_DESCRIPTOR,
    UNPARSED_DESCRIPTOR,
];

/// Field descriptor indices for [`LINK_FIELDS`].
const FD_LINK_TYPE: usize = 0;
const FD_LINK_METRIC: usize = 1;
const FD_INTERFACE_ID: usize = 2;
const FD_NEIGHBOR_INTERFACE_ID: usize = 3;
const FD_NEIGHBOR_ROUTER_ID: usize = 4;

/// Child fields of a Router-LSA interface entry.
///
/// RFC 5340, Appendix A.4.3 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.3>
static LINK_FIELDS: [FieldDescriptor; 5] = [
    FieldDescriptor::new("link_type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => router_link_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("metric", "Metric", FieldType::U16),
    FieldDescriptor::new("interface_id", "Interface ID", FieldType::U32),
    FieldDescriptor::new(
        "neighbor_interface_id",
        "Neighbor Interface ID",
        FieldType::U32,
    ),
    FieldDescriptor::new(
        "neighbor_router_id",
        "Neighbor Router ID",
        FieldType::Ipv4Addr,
    ),
];

/// Field descriptor indices for [`PREFIX_FIELDS`].
const FD_P_PREFIX_LENGTH: usize = 0;
const FD_P_PREFIX_OPTIONS: usize = 1;
const FD_P_METRIC: usize = 2;
const FD_P_PREFIX: usize = 3;

/// Child fields of a prefix entry in Link-LSAs and Intra-Area-Prefix-LSAs.
///
/// RFC 5340, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.1>
static PREFIX_FIELDS: [FieldDescriptor; 4] = [
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8),
    FieldDescriptor::new("prefix_options", "Prefix Options", FieldType::U8),
    FieldDescriptor::new("metric", "Metric", FieldType::U16).optional(),
    FieldDescriptor::new("prefix", "Address Prefix", FieldType::Ipv6Addr),
];

/// Resolves an LSA container's label from its `ls_type` child.
fn lsa_container_name(
    v: &FieldValue<'_>,
    children: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("ls_type", FieldValue::U16(t)) => lsa_type_name(*t),
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

static FD_LINK: FieldDescriptor = FieldDescriptor::new("link", "Interface", FieldType::Object)
    .with_children(&LINK_FIELDS)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("link_type", FieldValue::U8(t)) => router_link_type_name(*t),
            _ => None,
        }),
        _ => None,
    });

static FD_PREFIX_ENTRY: FieldDescriptor =
    FieldDescriptor::new("prefix_entry", "Prefix", FieldType::Object).with_children(&PREFIX_FIELDS);

/// Element of the Network-LSA `attached_routers` array.
static FD_ATTACHED_ROUTER: FieldDescriptor =
    FieldDescriptor::new("attached_router", "Attached Router", FieldType::Ipv4Addr);

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Pushes the fields of an LSA header. `data` must hold at least 20 bytes.
///
/// RFC 5340, Appendix A.4.2 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.2>
pub(crate) fn push_lsa_header_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) {
    buf.push_field(
        &LSA_FIELDS[FD_LS_AGE],
        FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        offset..offset + 2,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LS_TYPE],
        FieldValue::U16(read_be_u16(data, 2).unwrap_or_default()),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &LSA_FIELDS[FD_LINK_STATE_ID],
        FieldValue::U32(read_be_u32(data, 4).unwrap_or_default()),
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
}

/// Pushes the fields of a complete LSA (header and body).
///
/// `data` is the whole LSA, as delimited by its `length` field.
pub(crate) fn push_lsa<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    push_lsa_header_fields(buf, data, offset);
    let body = &data[LSA_HEADER_SIZE..];
    let o = offset + LSA_HEADER_SIZE;
    let function_code = read_be_u16(data, 2).unwrap_or_default() & 0x1FFF;
    let consumed = match function_code {
        1 => push_router_lsa(buf, body, o),
        2 => push_network_lsa(buf, body, o),
        3 => push_inter_area_prefix_lsa(buf, body, o),
        4 => push_inter_area_router_lsa(buf, body, o),
        5 | 7 => push_external_lsa(buf, body, o),
        8 => push_link_lsa(buf, body, o),
        9 => push_intra_area_prefix_lsa(buf, body, o),
        // Router Information LSA — RFC 7770, Section 2.2
        // <https://www.rfc-editor.org/rfc/rfc7770#section-2.2>
        12 => push_tlv_body(buf, body, 0, o, TlvContext::RouterInfo),
        // E-Router-LSA — RFC 8362, Section 4.1: "0 |Nt|x|V|E|B| Options"
        // <https://www.rfc-editor.org/rfc/rfc8362#section-4.1>
        33 if body.len() >= 4 => {
            push_router_flags(buf, body[0], o);
            push_options(buf, body, o);
            push_tlv_body(buf, body, 4, o, TlvContext::V3ExtLsa)
        }
        // E-Network-LSA — RFC 8362, Section 4.2: "0 | Options"
        // <https://www.rfc-editor.org/rfc/rfc8362#section-4.2>
        34 if body.len() >= 4 => {
            push_options(buf, body, o);
            push_tlv_body(buf, body, 4, o, TlvContext::V3ExtLsa)
        }
        // E-Inter-Area-Prefix, E-Inter-Area-Router, E-AS-External and
        // E-NSSA LSAs — RFC 8362, Sections 4.3-4.6: TLVs only
        // <https://www.rfc-editor.org/rfc/rfc8362#section-4.3>
        35 | 36 | 37 | 39 => push_tlv_body(buf, body, 0, o, TlvContext::V3ExtLsa),
        // E-Link-LSA — RFC 8362, Section 4.7: "Rtr Priority | Options"
        // <https://www.rfc-editor.org/rfc/rfc8362#section-4.7>
        40 if body.len() >= 4 => {
            push_u8(buf, FD_ROUTER_PRIORITY, body, 0, o);
            push_options(buf, body, o);
            push_tlv_body(buf, body, 4, o, TlvContext::V3ExtLsa)
        }
        // E-Intra-Area-Prefix-LSA — RFC 8362, Section 4.8
        // <https://www.rfc-editor.org/rfc/rfc8362#section-4.8>
        41 if body.len() >= 12 => {
            push_references(buf, body, o);
            push_tlv_body(buf, body, 12, o, TlvContext::V3ExtLsa)
        }
        // SRv6 Locator LSA — RFC 9513, Section 7
        // <https://www.rfc-editor.org/rfc/rfc9513#section-7>
        42 => push_tlv_body(buf, body, 0, o, TlvContext::Srv6Locator),
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

fn push_u8(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_u8_at(buf, &LSA_FIELDS[f], v, at, o);
}

fn push_u24(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_u24_at(buf, &LSA_FIELDS[f], v, at, o);
}

fn push_ipv4(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_ipv4_at(buf, &LSA_FIELDS[f], v, at, o);
}

fn push_ipv6(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, len: usize, o: usize) {
    push_ipv6_at(buf, &LSA_FIELDS[f], v, at, len, o);
}

/// Pushes the 24-bit Options field at octets 1-3.
///
/// RFC 5340, Appendix A.2 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.2>
fn push_options(buf: &mut DissectBuffer<'_>, v: &[u8], o: usize) {
    push_u24(buf, FD_OPTIONS, v, 1, o);
}

/// Pushes the Router-LSA flags octet and its Nt/V/E/B bits.
///
/// RFC 5340, Appendix A.4.3 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.3>
/// "0 |Nt|x|V|E|B| Options"
fn push_router_flags(buf: &mut DissectBuffer<'_>, flags: u8, o: usize) {
    buf.push_field(&LSA_FIELDS[FD_FLAGS], FieldValue::U8(flags), o..o + 1);
    for (f, mask) in [
        (FD_FLAG_NT, 0x10),
        (FD_FLAG_V, 0x04),
        (FD_FLAG_E, 0x02),
        (FD_FLAG_B, 0x01),
    ] {
        buf.push_field(
            &LSA_FIELDS[f],
            FieldValue::U8(u8::from(flags & mask != 0)),
            o..o + 1,
        );
    }
}

/// Pushes the TLVs of `body[start..]`.
fn push_tlv_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    start: usize,
    o: usize,
    ctx: TlvContext,
) -> Option<usize> {
    push_tlvs(buf, &body[start..], o + start, ctx);
    Some(body.len())
}

/// Pushes Referenced LS Type (octets 2-3), Referenced Link State ID and
/// Referenced Advertising Router (octets 4-11).
///
/// RFC 5340, Appendix A.4.10 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.10>
fn push_references(buf: &mut DissectBuffer<'_>, v: &[u8], o: usize) {
    buf.push_field(
        &LSA_FIELDS[FD_REFERENCED_LS_TYPE],
        FieldValue::U16(read_be_u16(v, 2).unwrap_or_default()),
        o + 2..o + 4,
    );
    buf.push_field(
        &LSA_FIELDS[FD_REFERENCED_LINK_STATE_ID],
        FieldValue::U32(read_be_u32(v, 4).unwrap_or_default()),
        o + 4..o + 8,
    );
    push_ipv4(buf, FD_REFERENCED_ADVERTISING_ROUTER, v, 8, o);
}

/// Router-LSA body.
///
/// RFC 5340, Appendix A.4.3 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.3>
/// Each interface is "Type | 0 | Metric | Interface ID | Neighbor Interface
/// ID | Neighbor Router ID" (16 octets).
fn push_router_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 4 {
        return None;
    }
    push_router_flags(buf, body[0], o);
    push_options(buf, body, o);
    let end = 4 + (body.len() - 4) / 16 * 16;
    let idx = buf.begin_container(
        &LSA_FIELDS[FD_LINKS],
        FieldValue::Array(0..0),
        o + 4..o + end,
    );
    for at in (4..end).step_by(16) {
        let abs = o + at;
        let link = buf.begin_container(&FD_LINK, FieldValue::Object(0..0), abs..abs + 16);
        buf.push_field(
            &LINK_FIELDS[FD_LINK_TYPE],
            FieldValue::U8(body[at]),
            abs..abs + 1,
        );
        buf.push_field(
            &LINK_FIELDS[FD_LINK_METRIC],
            FieldValue::U16(read_be_u16(body, at + 2).unwrap_or_default()),
            abs + 2..abs + 4,
        );
        buf.push_field(
            &LINK_FIELDS[FD_INTERFACE_ID],
            FieldValue::U32(read_be_u32(body, at + 4).unwrap_or_default()),
            abs + 4..abs + 8,
        );
        buf.push_field(
            &LINK_FIELDS[FD_NEIGHBOR_INTERFACE_ID],
            FieldValue::U32(read_be_u32(body, at + 8).unwrap_or_default()),
            abs + 8..abs + 12,
        );
        buf.push_field(
            &LINK_FIELDS[FD_NEIGHBOR_ROUTER_ID],
            FieldValue::Ipv4Addr(read_ipv4_addr(body, at + 12).unwrap_or_default()),
            abs + 12..abs + 16,
        );
        buf.end_container(link);
    }
    buf.end_container(idx);
    Some(end)
}

/// Network-LSA body.
///
/// RFC 5340, Appendix A.4.4 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.4>
fn push_network_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 4 {
        return None;
    }
    push_options(buf, body, o);
    let end = 4 + (body.len() - 4) / 4 * 4;
    let idx = buf.begin_container(
        &LSA_FIELDS[FD_ATTACHED_ROUTERS],
        FieldValue::Array(0..0),
        o + 4..o + end,
    );
    for at in (4..end).step_by(4) {
        push_ipv4_at(buf, &FD_ATTACHED_ROUTER, body, at, o);
    }
    buf.end_container(idx);
    Some(end)
}

/// Returns the number of octets of the address prefix announced by
/// `prefix_length` if it fits in `body` at `at`.
fn prefix_fits(body: &[u8], prefix_length: u8, at: usize) -> Option<usize> {
    let n = prefix_octets(prefix_length)?;
    (at + n <= body.len()).then_some(n)
}

/// Inter-Area-Prefix-LSA body.
///
/// RFC 5340, Appendix A.4.5 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.5>
/// "0 | Metric | PrefixLength | PrefixOptions | 0 | Address Prefix"
fn push_inter_area_prefix_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    let n = prefix_fits(body, *body.get(4)?, 8)?;
    push_u24(buf, FD_METRIC, body, 1, o);
    push_u8(buf, FD_PREFIX_LENGTH, body, 4, o);
    push_u8(buf, FD_PREFIX_OPTIONS, body, 5, o);
    push_ipv6(buf, FD_PREFIX, body, 8, n, o);
    Some(8 + n)
}

/// Inter-Area-Router-LSA body.
///
/// RFC 5340, Appendix A.4.6 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.6>
/// "0 | Options | 0 | Metric | Destination Router ID"
fn push_inter_area_router_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 12 {
        return None;
    }
    push_options(buf, body, o);
    push_u24(buf, FD_METRIC, body, 5, o);
    push_ipv4(buf, FD_DESTINATION_ROUTER_ID, body, 8, o);
    Some(12)
}

/// AS-External-LSA and NSSA-LSA body.
///
/// RFC 5340, Appendix A.4.7 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.7>
/// "|E|F|T| Metric | PrefixLength | PrefixOptions | Referenced LS Type |
/// Address Prefix | Forwarding Address (opt.) | External Route Tag (opt.)
/// | Referenced Link State ID (opt.)"
/// RFC 5340, Appendix A.4.8 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.8>
/// uses the same format for the NSSA-LSA.
fn push_external_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    let n = prefix_fits(body, *body.get(4)?, 8)?;
    let flags = body[0];
    let referenced_ls_type = read_be_u16(body, 6).ok()?;
    let has_fwd = flags & 0x02 != 0;
    let has_tag = flags & 0x01 != 0;
    let has_ref = referenced_ls_type != 0;
    let end = 8
        + n
        + if has_fwd { 16 } else { 0 }
        + if has_tag { 4 } else { 0 }
        + if has_ref { 4 } else { 0 };
    if end > body.len() {
        return None;
    }

    buf.push_field(&LSA_FIELDS[FD_FLAGS], FieldValue::U8(flags), o..o + 1);
    for (f, mask) in [(FD_FLAG_E, 0x04), (FD_FLAG_F, 0x02), (FD_FLAG_T, 0x01)] {
        buf.push_field(
            &LSA_FIELDS[f],
            FieldValue::U8(u8::from(flags & mask != 0)),
            o..o + 1,
        );
    }
    push_u24(buf, FD_METRIC, body, 1, o);
    push_u8(buf, FD_PREFIX_LENGTH, body, 4, o);
    push_u8(buf, FD_PREFIX_OPTIONS, body, 5, o);
    buf.push_field(
        &LSA_FIELDS[FD_REFERENCED_LS_TYPE],
        FieldValue::U16(referenced_ls_type),
        o + 6..o + 8,
    );
    push_ipv6(buf, FD_PREFIX, body, 8, n, o);
    let mut at = 8 + n;
    if has_fwd {
        push_ipv6(buf, FD_FORWARDING_ADDRESS, body, at, 16, o);
        at += 16;
    }
    if has_tag {
        buf.push_field(
            &LSA_FIELDS[FD_EXTERNAL_ROUTE_TAG],
            FieldValue::U32(read_be_u32(body, at).unwrap_or_default()),
            o + at..o + at + 4,
        );
        at += 4;
    }
    if has_ref {
        buf.push_field(
            &LSA_FIELDS[FD_REFERENCED_LINK_STATE_ID],
            FieldValue::U32(read_be_u32(body, at).unwrap_or_default()),
            o + at..o + at + 4,
        );
        at += 4;
    }
    Some(at)
}

/// Pushes a `prefixes` array of `count` entries starting at `start`.
///
/// Each entry is "PrefixLength | PrefixOptions | 16-bit field | Address
/// Prefix"; the 16-bit field is a Metric when `with_metric` is set and
/// reserved otherwise. Returns the offset after the last complete entry.
///
/// RFC 5340, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.1>
fn push_prefixes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    start: usize,
    count: u32,
    with_metric: bool,
    o: usize,
) -> usize {
    let idx = buf.begin_container(
        &LSA_FIELDS[FD_PREFIXES],
        FieldValue::Array(0..0),
        o + start..o + body.len(),
    );
    let mut at = start;
    for _ in 0..count {
        let Some(&prefix_length) = body.get(at) else {
            break;
        };
        let Some(n) = prefix_fits(body, prefix_length, at + 4) else {
            break;
        };
        let abs = o + at;
        let entry =
            buf.begin_container(&FD_PREFIX_ENTRY, FieldValue::Object(0..0), abs..abs + 4 + n);
        buf.push_field(
            &PREFIX_FIELDS[FD_P_PREFIX_LENGTH],
            FieldValue::U8(prefix_length),
            abs..abs + 1,
        );
        buf.push_field(
            &PREFIX_FIELDS[FD_P_PREFIX_OPTIONS],
            FieldValue::U8(body[at + 1]),
            abs + 1..abs + 2,
        );
        if with_metric {
            buf.push_field(
                &PREFIX_FIELDS[FD_P_METRIC],
                FieldValue::U16(read_be_u16(body, at + 2).unwrap_or_default()),
                abs + 2..abs + 4,
            );
        }
        buf.push_field(
            &PREFIX_FIELDS[FD_P_PREFIX],
            FieldValue::Ipv6Addr(prefix_to_ipv6(&body[at + 4..at + 4 + n])),
            abs + 4..abs + 4 + n,
        );
        buf.end_container(entry);
        at += 4 + n;
    }
    buf.end_container(idx);
    set_range_end(buf, idx, o + at);
    at
}

/// Link-LSA body.
///
/// RFC 5340, Appendix A.4.9 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.9>
/// "Rtr Priority | Options | Link-local Interface Address | # prefixes |
/// PrefixLength | PrefixOptions | 0 | Address Prefix ..."
fn push_link_lsa<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], o: usize) -> Option<usize> {
    if body.len() < 24 {
        return None;
    }
    push_u8(buf, FD_ROUTER_PRIORITY, body, 0, o);
    push_options(buf, body, o);
    push_ipv6(buf, FD_LINK_LOCAL_ADDRESS, body, 4, 16, o);
    let count = read_be_u32(body, 20).unwrap_or_default();
    buf.push_field(
        &LSA_FIELDS[FD_NUM_PREFIXES],
        FieldValue::U32(count),
        o + 20..o + 24,
    );
    Some(push_prefixes(buf, body, 24, count, false, o))
}

/// Intra-Area-Prefix-LSA body.
///
/// RFC 5340, Appendix A.4.10 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.10>
/// "# Prefixes | Referenced LS Type | Referenced Link State ID | Referenced
/// Advertising Router | PrefixLength | PrefixOptions | Metric | Address
/// Prefix ..."
fn push_intra_area_prefix_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if body.len() < 12 {
        return None;
    }
    let count = u32::from(read_be_u16(body, 0).unwrap_or_default());
    buf.push_field(
        &LSA_FIELDS[FD_NUM_PREFIXES],
        FieldValue::U32(count),
        o..o + 2,
    );
    push_references(buf, body, o);
    Some(push_prefixes(buf, body, 12, count, true, o))
}
