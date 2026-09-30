//! IS-IS sub-TLV and sub-sub-TLV decoding.
//!
//! Sub-TLVs use the IS-IS TLV encoding (1-octet type, 1-octet length, no
//! padding) and appear inside the Extended IS / IP reachability entries,
//! the Router Capability TLV, the SRv6 Locator TLV and the SID/Label
//! Binding TLVs.
//!
//! ## References
//! - RFC 5305 (TE extensions): <https://www.rfc-editor.org/rfc/rfc5305>
//! - RFC 5307 (GMPLS extensions): <https://www.rfc-editor.org/rfc/rfc5307>
//! - RFC 5130 (Admin tags): <https://www.rfc-editor.org/rfc/rfc5130>
//! - RFC 6119 (IPv6 TE): <https://www.rfc-editor.org/rfc/rfc6119>
//! - RFC 7794 (Prefix attributes): <https://www.rfc-editor.org/rfc/rfc7794>
//! - RFC 8491 (MSD): <https://www.rfc-editor.org/rfc/rfc8491>
//! - RFC 8570 (TE metric extensions): <https://www.rfc-editor.org/rfc/rfc8570>
//! - RFC 8667 (Segment Routing): <https://www.rfc-editor.org/rfc/rfc8667>
//! - RFC 9346 (Inter-AS TE): <https://www.rfc-editor.org/rfc/rfc9346>
//! - RFC 9352 (SRv6): <https://www.rfc-editor.org/rfc/rfc9352>
//! - IANA IS-IS TLV Codepoints:
//!   <https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml>

use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_u16, read_be_u24, read_be_u32, read_be_u64, read_ipv6_addr,
};

use super::format_isis_id;

/// Sub-TLV header size (Type + Length).
const SUB_TLV_HEADER_SIZE: usize = 2;

/// IS-IS System ID length; the dissector only accepts ID Length 0 / 6.
///
/// ISO/IEC 10589:2002, Section 9.5.
pub(crate) const SYSTEM_ID_LEN: usize = 6;

/// SRv6 SID length.
///
/// RFC 9352, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc9352#section-7.2>
/// "SID:  16 octets."
const SRV6_SID_LEN: usize = 16;

/// Formats a `U32` holding IEEE 754 single-precision bits as a JSON number.
///
/// RFC 5305, Section 3.4 — <https://www.rfc-editor.org/rfc/rfc5305#section-3.4>
/// "The maximum link bandwidth is encoded in 32 bits in IEEE floating
/// point format.  The units are bytes (not bits!) per second."
pub(crate) fn format_ieee_float(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    match value {
        FieldValue::U32(bits) => {
            let f = f32::from_bits(*bits);
            if f.is_finite() {
                write!(w, "{f}")
            } else {
                w.write_all(b"null")
            }
        }
        _ => w.write_all(b"null"),
    }
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Field descriptor indices for [`SUB_TLV_FIELDS`] and [`SUB_SUB_TLV_FIELDS`].
const F_LENGTH: usize = 1;
const F_VALUE: usize = 2;
const F_RAW: usize = 3;
const F_ADMIN_GROUP: usize = 5;
const F_LOCAL_IDENTIFIER: usize = 6;
const F_REMOTE_IDENTIFIER: usize = 7;
const F_IPV4_INTERFACE_ADDRESS: usize = 8;
const F_IPV4_NEIGHBOR_ADDRESS: usize = 9;
const F_IPV6_INTERFACE_ADDRESS: usize = 10;
const F_IPV6_NEIGHBOR_ADDRESS: usize = 11;
const F_MAX_BANDWIDTH: usize = 12;
const F_MAX_RESERVABLE_BANDWIDTH: usize = 13;
const F_UNRESERVED_BANDWIDTH: usize = 14;
const F_TE_DEFAULT_METRIC: usize = 15;
const F_FLAGS: usize = 16;
const F_WEIGHT: usize = 17;
const F_ALGORITHM: usize = 18;
const F_SID: usize = 19;
const F_NEIGHBOR_SYSTEM_ID: usize = 20;
const F_ANOMALOUS: usize = 21;
const F_DELAY: usize = 22;
const F_MIN_DELAY: usize = 23;
const F_MAX_DELAY: usize = 24;
const F_DELAY_VARIATION: usize = 25;
const F_LINK_LOSS: usize = 26;
const F_BANDWIDTH: usize = 27;
const F_ENDPOINT_BEHAVIOR: usize = 28;
const F_SRV6_SID: usize = 29;
const F_LOCATOR_BLOCK_LENGTH: usize = 30;
const F_LOCATOR_NODE_LENGTH: usize = 31;
const F_FUNCTION_LENGTH: usize = 32;
const F_ARGUMENT_LENGTH: usize = 33;
const F_TAGS: usize = 34;
const F_FLAG_X: usize = 35;
const F_FLAG_R: usize = 36;
const F_FLAG_N: usize = 37;
const F_IPV4_SOURCE_ROUTER_ID: usize = 38;
const F_IPV6_SOURCE_ROUTER_ID: usize = 39;
const F_RANGES: usize = 40;
const F_ALGORITHMS: usize = 41;
const F_MSDS: usize = 42;
const F_PREFERENCE: usize = 43;
const F_SRV6_FLAGS: usize = 44;
const F_IPV4_TE_ROUTER_ID: usize = 45;
const F_IPV6_TE_ROUTER_ID: usize = 46;

/// Number of fields in a sub-TLV object schema.
const SUB_TLV_FIELD_COUNT: usize = 47;

/// Builds the union of the fields that can appear inside a sub-TLV
/// object. Every field except `type` and `length` depends on the sub-TLV
/// type, so they are all marked optional.
const fn sub_tlv_fields(sub_tlvs: FieldDescriptor) -> [FieldDescriptor; SUB_TLV_FIELD_COUNT] {
    [
        FieldDescriptor::new("type", "Type", FieldType::U8),
        FieldDescriptor::new("length", "Length", FieldType::U8),
        FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
        RAW_DESCRIPTOR,
        sub_tlvs,
        FieldDescriptor::new("admin_group", "Administrative Group", FieldType::U32).optional(),
        FieldDescriptor::new("local_identifier", "Link Local Identifier", FieldType::U32)
            .optional(),
        FieldDescriptor::new(
            "remote_identifier",
            "Link Remote Identifier",
            FieldType::U32,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv4_interface_address",
            "IPv4 Interface Address",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv4_neighbor_address",
            "IPv4 Neighbor Address",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv6_interface_address",
            "IPv6 Interface Address",
            FieldType::Ipv6Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv6_neighbor_address",
            "IPv6 Neighbor Address",
            FieldType::Ipv6Addr,
        )
        .optional(),
        FieldDescriptor::new("max_bandwidth", "Maximum Link Bandwidth", FieldType::U32)
            .optional()
            .with_format_fn(format_ieee_float),
        FieldDescriptor::new(
            "max_reservable_bandwidth",
            "Maximum Reservable Link Bandwidth",
            FieldType::U32,
        )
        .optional()
        .with_format_fn(format_ieee_float),
        FieldDescriptor::new(
            "unreserved_bandwidth",
            "Unreserved Bandwidth",
            FieldType::Array,
        )
        .optional(),
        FieldDescriptor::new("te_default_metric", "TE Default Metric", FieldType::U32).optional(),
        FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
        FieldDescriptor::new("weight", "Weight", FieldType::U8).optional(),
        FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8).optional(),
        FieldDescriptor::new("sid", "SID/Index/Label", FieldType::U32).optional(),
        FieldDescriptor::new("neighbor_system_id", "Neighbor System-ID", FieldType::Bytes)
            .optional()
            .with_format_fn(format_isis_id),
        FieldDescriptor::new("anomalous", "A-bit (Anomalous)", FieldType::U8).optional(),
        FieldDescriptor::new("delay", "Delay (us)", FieldType::U32).optional(),
        FieldDescriptor::new("min_delay", "Min Delay (us)", FieldType::U32).optional(),
        FieldDescriptor::new("max_delay", "Max Delay (us)", FieldType::U32).optional(),
        FieldDescriptor::new("delay_variation", "Delay Variation (us)", FieldType::U32).optional(),
        FieldDescriptor::new("link_loss", "Link Loss", FieldType::U32).optional(),
        FieldDescriptor::new("bandwidth", "Bandwidth", FieldType::U32)
            .optional()
            .with_format_fn(format_ieee_float),
        FieldDescriptor::new("endpoint_behavior", "Endpoint Behavior", FieldType::U16).optional(),
        FieldDescriptor::new("srv6_sid", "SRv6 SID", FieldType::Ipv6Addr).optional(),
        FieldDescriptor::new(
            "locator_block_length",
            "Locator Block Length",
            FieldType::U8,
        )
        .optional(),
        FieldDescriptor::new("locator_node_length", "Locator Node Length", FieldType::U8)
            .optional(),
        FieldDescriptor::new("function_length", "Function Length", FieldType::U8).optional(),
        FieldDescriptor::new("argument_length", "Argument Length", FieldType::U8).optional(),
        FieldDescriptor::new("tags", "Administrative Tags", FieldType::Array).optional(),
        FieldDescriptor::new("flag_x", "X-Flag (External Prefix)", FieldType::U8).optional(),
        FieldDescriptor::new("flag_r", "R-Flag (Re-advertisement)", FieldType::U8).optional(),
        FieldDescriptor::new("flag_n", "N-Flag (Node)", FieldType::U8).optional(),
        FieldDescriptor::new(
            "ipv4_source_router_id",
            "IPv4 Source Router ID",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv6_source_router_id",
            "IPv6 Source Router ID",
            FieldType::Ipv6Addr,
        )
        .optional(),
        FieldDescriptor::new("ranges", "SRGB / SRLB Ranges", FieldType::Array)
            .optional()
            .with_children(&RANGE_FIELDS),
        FieldDescriptor::new("algorithms", "Algorithms", FieldType::Array).optional(),
        FieldDescriptor::new("msds", "MSDs", FieldType::Array)
            .optional()
            .with_children(&MSD_FIELDS),
        FieldDescriptor::new("preference", "Preference", FieldType::U8).optional(),
        FieldDescriptor::new("srv6_flags", "SRv6 Capability Flags", FieldType::U16).optional(),
        FieldDescriptor::new(
            "ipv4_te_router_id",
            "IPv4 TE Router ID",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv6_te_router_id",
            "IPv6 TE Router ID",
            FieldType::Ipv6Addr,
        )
        .optional(),
    ]
}

/// Descriptor for octets that follow the last structure that could be
/// decoded; named like the TLV-level `raw` field.
pub(crate) const RAW_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("raw", "Raw", FieldType::Bytes).optional();

/// Child fields of a sub-TLV object.
static SUB_TLV_FIELDS: [FieldDescriptor; SUB_TLV_FIELD_COUNT] = sub_tlv_fields(
    FieldDescriptor::new("sub_tlvs", "Sub-sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&SUB_SUB_TLV_FIELDS),
);

/// Child fields of a sub-sub-TLV object; nested `sub_tlvs` carry no further
/// schema, which keeps the descriptor graph acyclic.
static SUB_SUB_TLV_FIELDS: [FieldDescriptor; SUB_TLV_FIELD_COUNT] =
    sub_tlv_fields(FieldDescriptor::new("sub_tlvs", "Sub-sub-TLVs", FieldType::Array).optional());

/// Field descriptor indices for [`RANGE_FIELDS`].
const FR_RANGE_SIZE: usize = 0;
const FR_SID: usize = 1;

/// Child fields of an SRGB / SRLB range descriptor.
///
/// RFC 8667, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc8667#section-3.1>
static RANGE_FIELDS: [FieldDescriptor; 2] = [
    FieldDescriptor::new("range_size", "Range", FieldType::U32),
    FieldDescriptor::new("sid", "First SID/Label", FieldType::U32).optional(),
];

/// Field descriptor indices for [`MSD_FIELDS`].
const FM_TYPE: usize = 0;
const FM_VALUE: usize = 1;

/// Child fields of a Node MSD entry.
///
/// RFC 8491, Section 2 — <https://www.rfc-editor.org/rfc/rfc8491#section-2>
static MSD_FIELDS: [FieldDescriptor; 2] = [
    FieldDescriptor::new("msd_type", "MSD-Type", FieldType::U8),
    FieldDescriptor::new("msd_value", "MSD-Value", FieldType::U8),
];

static FD_RANGE: FieldDescriptor =
    FieldDescriptor::new("range", "Range", FieldType::Object).with_children(&RANGE_FIELDS);
static FD_MSD: FieldDescriptor =
    FieldDescriptor::new("msd", "MSD", FieldType::Object).with_children(&MSD_FIELDS);
static FD_BANDWIDTH_ELEM: FieldDescriptor =
    FieldDescriptor::new("bandwidth", "Bandwidth", FieldType::U32)
        .with_format_fn(format_ieee_float);
static FD_TAG32: FieldDescriptor = FieldDescriptor::new("tag", "Tag", FieldType::U32);
static FD_TAG64: FieldDescriptor = FieldDescriptor::new("tag", "Tag", FieldType::U64);
static FD_ALGORITHM_ELEM: FieldDescriptor =
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8);

/// Resolves a sub-TLV container's label from its `type` child.
fn container_name(v: &FieldValue<'_>, children: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::Object(_) => {
            let t = children.iter().find(|f| f.name() == "type")?;
            (t.descriptor.display_fn?)(&t.value, children)
        }
        _ => None,
    }
}

/// Descriptor for a `sub_tlvs` array inside a TLV or TLV entry. Shared with
/// the TLV schemas in the crate root.
pub(crate) const SUB_TLVS_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&SUB_TLV_FIELDS);

static FD_SUB_TLVS: FieldDescriptor = SUB_TLVS_DESCRIPTOR;
static FD_SUB_TLV: FieldDescriptor = FieldDescriptor::new("sub_tlv", "Sub-TLV", FieldType::Object)
    .with_children(&SUB_TLV_FIELDS)
    .with_display_fn(container_name);
static FD_SUB_SUB_TLVS: FieldDescriptor =
    FieldDescriptor::new("sub_tlvs", "Sub-sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&SUB_SUB_TLV_FIELDS);
static FD_SUB_SUB_TLV: FieldDescriptor =
    FieldDescriptor::new("sub_tlv", "Sub-sub-TLV", FieldType::Object)
        .with_children(&SUB_SUB_TLV_FIELDS)
        .with_display_fn(container_name);

// ---------------------------------------------------------------------------
// Name tables
// ---------------------------------------------------------------------------

/// IANA "IS-IS Sub-TLVs for TLVs Advertising Neighbor Information".
fn neighbor_sub_tlv_name(t: u8) -> Option<&'static str> {
    match t {
        3 => Some("Administrative group (color)"),
        4 => Some("Link Local/Remote Identifiers"),
        6 => Some("IPv4 interface address"),
        8 => Some("IPv4 neighbor address"),
        9 => Some("Maximum link bandwidth"),
        10 => Some("Maximum reservable link bandwidth"),
        11 => Some("Unreserved bandwidth"),
        12 => Some("IPv6 Interface Address"),
        13 => Some("IPv6 Neighbor Address"),
        14 => Some("Extended Administrative Group"),
        15 => Some("Link MSD"),
        16 => Some("Application-Specific Link Attributes"),
        17 => Some("Generic Metric"),
        18 => Some("TE Default metric"),
        19 => Some("Link-attributes"),
        20 => Some("Link Protection Type"),
        21 => Some("Interface Switching Capability Descriptor"),
        22 => Some("Bandwidth Constraints"),
        23 => Some("Unconstrained TE LSP Count"),
        24 => Some("Remote AS Number"),
        25 => Some("IPv4 Remote ASBR Identifier"),
        26 => Some("IPv6 Remote ASBR Identifier"),
        27 => Some("Interface Adjustment Capability Descriptor (IACD)"),
        28 => Some("MTU"),
        29 => Some("SPB-Metric"),
        30 => Some("SPB-A-OALG"),
        31 => Some("Adjacency Segment Identifier"),
        32 => Some("LAN Adjacency Segment Identifier"),
        33 => Some("Unidirectional Link Delay"),
        34 => Some("Min/Max Unidirectional Link Delay"),
        35 => Some("Unidirectional Delay Variation"),
        36 => Some("Unidirectional Link Loss"),
        37 => Some("Unidirectional Residual Bandwidth"),
        38 => Some("Unidirectional Available Bandwidth"),
        39 => Some("Unidirectional Utilized Bandwidth"),
        40 => Some("RTM Capability"),
        41 => Some("L2 Bundle Member Adj-SID"),
        42 => Some("L2 Bundle Member LAN Adj-SID"),
        43 => Some("SRv6 End.X SID"),
        44 => Some("SRv6 LAN End.X SID"),
        45 => Some("IPv6 Local ASBR Identifier"),
        161 => Some("Flood Reflector Adjacency"),
        _ => None,
    }
}

/// IANA "IS-IS Sub-TLVs for TLVs Advertising Prefix Reachability".
fn prefix_sub_tlv_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("32-bit Administrative Tag"),
        2 => Some("64-bit Administrative Tag"),
        3 => Some("Prefix Segment Identifier"),
        4 => Some("Prefix Attribute Flags"),
        5 => Some("SRv6 End SID"),
        6 => Some("Flexible Algorithm Prefix Metric (FAPM)"),
        11 => Some("IPv4 Source Router ID"),
        12 => Some("IPv6 Source Router ID"),
        32 => Some("BIER Info"),
        _ => None,
    }
}

/// IANA "IS-IS Sub-TLVs for IS-IS Router CAPABILITY TLV".
fn router_capability_sub_tlv_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("TE Node Capability Descriptor"),
        2 => Some("Segment Routing Capability"),
        3 => Some("TE-MESH-GROUP TLV (IPv4)"),
        4 => Some("TE-MESH-GROUP TLV (IPv6)"),
        5 => Some("PCED"),
        6 => Some("NICKNAME"),
        7 => Some("TREES"),
        8 => Some("TREE-RT-IDs"),
        9 => Some("TREE-USE-IDs"),
        10 => Some("INT-VLAN"),
        11 => Some("IPv4 TE Router ID"),
        12 => Some("IPv6 TE Router ID"),
        13 => Some("TRILL-VER"),
        14 => Some("VLAN-GROUP"),
        15 => Some("INT-LABEL"),
        16 => Some("RBCHANNELS"),
        17 => Some("AFFINITY"),
        18 => Some("LABEL-GROUP"),
        19 => Some("Segment Routing Algorithm"),
        20 => Some("S-BFD Discriminators"),
        21 => Some("Node-Admin-Tag"),
        22 => Some("Segment Routing Local Block (SRLB)"),
        23 => Some("Node MSD"),
        24 => Some("Segment Routing Mapping Server Preference (SRMS Preference)"),
        25 => Some("SRv6 Capabilities"),
        26 => Some("Flexible Algorithm Definition (FAD)"),
        27 => Some("IS-IS Area Leader"),
        28 => Some("IS-IS Dynamic Flooding"),
        29 => Some("IP Algorithm"),
        30 => Some("MP-TLV Support for TLVs with Implicit Support"),
        161 => Some("Flood Reflection Discovery"),
        _ => None,
    }
}

/// IANA "IS-IS Sub-TLVs for Segment Identifier/Label Binding TLVs".
fn binding_sub_tlv_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("SID/Label"),
        3 => Some("Prefix Segment Identifier"),
        _ => None,
    }
}

/// IANA "IS-IS Sub-Sub-TLVs for SRv6 SID Sub-TLVs".
fn srv6_sid_sub_sub_tlv_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("SRv6 SID Structure"),
        _ => None,
    }
}

/// Sub-sub-TLVs of the SRv6 Capabilities sub-TLV; none are registered.
///
/// RFC 9352, Section 2 — <https://www.rfc-editor.org/rfc/rfc9352#section-2>
/// "No sub-sub-TLVs are currently defined."
fn no_name(_t: u8) -> Option<&'static str> {
    None
}

/// Builds a `type` descriptor whose display function names the sub-TLV.
macro_rules! type_descriptor {
    ($name_fn:path) => {
        FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
            FieldValue::U8(t) => $name_fn(*t),
            _ => None,
        })
    };
}

static TYPE_NEIGHBOR: FieldDescriptor = type_descriptor!(neighbor_sub_tlv_name);
static TYPE_PREFIX: FieldDescriptor = type_descriptor!(prefix_sub_tlv_name);
static TYPE_ROUTER_CAPABILITY: FieldDescriptor = type_descriptor!(router_capability_sub_tlv_name);
static TYPE_BINDING: FieldDescriptor = type_descriptor!(binding_sub_tlv_name);
static TYPE_SRV6_SID: FieldDescriptor = type_descriptor!(srv6_sid_sub_sub_tlv_name);
static TYPE_NONE: FieldDescriptor = type_descriptor!(no_name);

/// Which sub-TLV registry a sequence belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubTlvContext {
    /// Sub-TLVs of TLVs 22, 222 (neighbor information).
    Neighbor,
    /// Sub-TLVs of TLVs 135, 235, 236, 237 and 27 (prefix reachability).
    Prefix,
    /// Sub-TLVs of TLV 242 (Router Capability).
    RouterCapability,
    /// Sub-TLVs of TLVs 149 / 150 (SID/Label Binding).
    Binding,
    /// Sub-sub-TLVs of the SRv6 SID sub-TLVs.
    Srv6Sid,
    /// Sub-sub-TLVs without a registry (SRv6 Capabilities).
    Unregistered,
}

impl SubTlvContext {
    fn type_descriptor(self) -> &'static FieldDescriptor {
        match self {
            Self::Neighbor => &TYPE_NEIGHBOR,
            Self::Prefix => &TYPE_PREFIX,
            Self::RouterCapability => &TYPE_ROUTER_CAPABILITY,
            Self::Binding => &TYPE_BINDING,
            Self::Srv6Sid => &TYPE_SRV6_SID,
            Self::Unregistered => &TYPE_NONE,
        }
    }

    /// Decodes a sub-TLV value; returns the octets decoded, or `None` when
    /// the type is unknown or the value is shorter than its fixed part.
    fn decode<'pkt>(
        self,
        buf: &mut DissectBuffer<'pkt>,
        t: u8,
        v: &'pkt [u8],
        o: usize,
    ) -> Option<usize> {
        match self {
            Self::Neighbor => decode_neighbor(buf, t, v, o),
            Self::Prefix => decode_prefix(buf, t, v, o),
            Self::RouterCapability => decode_router_capability(buf, t, v, o),
            Self::Binding => match t {
                1 => push_sid(buf, v, 0, o),
                3 => decode_prefix(buf, t, v, o),
                _ => None,
            },
            Self::Srv6Sid => decode_srv6_sid_structure(buf, t, v, o),
            Self::Unregistered => None,
        }
    }

    /// Whether this context holds sub-sub-TLVs (nested one level deeper).
    fn nested(self) -> bool {
        matches!(self, Self::Srv6Sid | Self::Unregistered)
    }
}

// ---------------------------------------------------------------------------
// Walker
// ---------------------------------------------------------------------------

/// Pushes a `sub_tlvs` array for `data`, or nothing when it is empty.
///
/// Walking stops at the first sub-TLV whose length overruns `data`; the
/// remaining octets are pushed as `raw` after the array.
///
/// RFC 5305, Section 3 — <https://www.rfc-editor.org/rfc/rfc5305#section-3>
pub(crate) fn push_sub_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ctx: SubTlvContext,
) {
    let pos = walk_sub_tlvs(buf, data, offset, ctx);
    let raw = if ctx.nested() {
        &SUB_SUB_TLV_FIELDS[F_RAW]
    } else {
        &SUB_TLV_FIELDS[F_RAW]
    };
    push_raw(buf, raw, &data[pos..], offset + pos);
}

/// Pushes a `sub_tlvs` array for `data`, or nothing when it is empty, and
/// returns the number of octets its complete sub-TLVs cover. Unlike
/// [`push_sub_tlvs`], the remaining octets are left to the caller.
fn walk_sub_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ctx: SubTlvContext,
) -> usize {
    if data.is_empty() {
        return 0;
    }
    let (array, element, fields) = if ctx.nested() {
        (&FD_SUB_SUB_TLVS, &FD_SUB_SUB_TLV, &SUB_SUB_TLV_FIELDS)
    } else {
        (&FD_SUB_TLVS, &FD_SUB_TLV, &SUB_TLV_FIELDS)
    };
    let array_idx =
        buf.begin_container(array, FieldValue::Array(0..0), offset..offset + data.len());
    let mut pos = 0;
    while pos + SUB_TLV_HEADER_SIZE <= data.len() {
        let t = data[pos];
        let len = data[pos + 1] as usize;
        let value_start = pos + SUB_TLV_HEADER_SIZE;
        let value_end = value_start + len;
        if value_end > data.len() {
            break;
        }
        let abs = offset + pos;
        let obj = buf.begin_container(element, FieldValue::Object(0..0), abs..offset + value_end);
        buf.push_field(ctx.type_descriptor(), FieldValue::U8(t), abs..abs + 1);
        buf.push_field(
            &fields[F_LENGTH],
            FieldValue::U8(len as u8),
            abs + 1..abs + 2,
        );
        let v = &data[value_start..value_end];
        let vo = offset + value_start;
        match ctx.decode(buf, t, v, vo) {
            Some(n) => push_raw(buf, &fields[F_RAW], &v[n.min(v.len())..], vo + n),
            None => buf.push_field(&fields[F_VALUE], FieldValue::Bytes(v), vo..vo + len),
        }
        buf.end_container(obj);
        pos = value_end;
    }
    buf.end_container(array_idx);
    set_range_end(buf, array_idx, offset + pos);
    pos
}

/// Pushes `rest` with descriptor `d` unless it is empty.
fn push_raw<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    d: &'static FieldDescriptor,
    rest: &'pkt [u8],
    o: usize,
) {
    if !rest.is_empty() {
        buf.push_field(d, FieldValue::Bytes(rest), o..o + rest.len());
    }
}

/// Shrinks the byte range of the container at `idx` to end at `end`, so
/// that it covers only the entries that were decoded.
pub(crate) fn set_range_end(buf: &mut DissectBuffer<'_>, idx: u32, end: usize) {
    if let Some(field) = buf.field_mut(idx as usize) {
        field.range.end = end;
    }
}

/// Pushes a single-bit flag from `byte` as a `U8` (0 or 1).
pub(crate) fn push_flag(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    byte: u8,
    mask: u8,
    at: usize,
) {
    buf.push_field(d, FieldValue::U8(u8::from(byte & mask != 0)), at..at + 1);
}

/// Clears the bits of `prefix` after the first `bits` bits.
///
/// RFC 5305, Section 4 — <https://www.rfc-editor.org/rfc/rfc5305#section-4>
/// "The remaining bits of prefix are transmitted as zero and ignored upon
/// receipt."
pub(crate) fn mask_prefix(prefix: &mut [u8], bits: usize) {
    for (i, byte) in prefix.iter_mut().enumerate() {
        let start = i * 8;
        if start >= bits {
            *byte = 0;
        } else if bits - start < 8 {
            *byte &= 0xFFu8 << (8 - (bits - start));
        }
    }
}

// ---------------------------------------------------------------------------
// Push helpers
// ---------------------------------------------------------------------------

fn push_u8(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    buf.push_field(
        &SUB_TLV_FIELDS[f],
        FieldValue::U8(v[at]),
        o + at..o + at + 1,
    );
}

fn push_bit(buf: &mut DissectBuffer<'_>, f: usize, byte: u8, mask: u8, at: usize) {
    push_flag(buf, &SUB_TLV_FIELDS[f], byte, mask, at);
}

fn push_u16(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    let x = read_be_u16(v, at).unwrap_or_default();
    buf.push_field(&SUB_TLV_FIELDS[f], FieldValue::U16(x), o + at..o + at + 2);
}

fn push_u24(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    let x = read_be_u24(v, at).unwrap_or_default();
    buf.push_field(&SUB_TLV_FIELDS[f], FieldValue::U32(x), o + at..o + at + 3);
}

fn push_u32(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    let x = read_be_u32(v, at).unwrap_or_default();
    buf.push_field(&SUB_TLV_FIELDS[f], FieldValue::U32(x), o + at..o + at + 4);
}

fn push_ipv4(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    let x = [v[at], v[at + 1], v[at + 2], v[at + 3]];
    buf.push_field(
        &SUB_TLV_FIELDS[f],
        FieldValue::Ipv4Addr(x),
        o + at..o + at + 4,
    );
}

fn push_ipv6(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    let x = read_ipv6_addr(v, at).unwrap_or_default();
    buf.push_field(
        &SUB_TLV_FIELDS[f],
        FieldValue::Ipv6Addr(x),
        o + at..o + at + 16,
    );
}

fn push_bytes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    f: usize,
    v: &'pkt [u8],
    at: usize,
    len: usize,
    o: usize,
) {
    buf.push_field(
        &SUB_TLV_FIELDS[f],
        FieldValue::Bytes(&v[at..at + len]),
        o + at..o + at + len,
    );
}

/// Pushes an array of consecutive `size`-octet elements; returns the octets
/// covered.
fn push_array(
    buf: &mut DissectBuffer<'_>,
    array: usize,
    element: &'static FieldDescriptor,
    v: &[u8],
    size: usize,
    o: usize,
) -> usize {
    let n = v.len() / size * size;
    let idx = buf.begin_container(&SUB_TLV_FIELDS[array], FieldValue::Array(0..0), o..o + n);
    for at in (0..n).step_by(size) {
        let value = match size {
            1 => FieldValue::U8(v[at]),
            8 => FieldValue::U64(read_be_u64(v, at).unwrap_or_default()),
            _ => FieldValue::U32(read_be_u32(v, at).unwrap_or_default()),
        };
        buf.push_field(element, value, o + at..o + at + size);
    }
    buf.end_container(idx);
    n
}

/// Pushes a SID/Index/Label at `at`: 3 octets carry a label in the 20
/// rightmost bits, 4 octets an index or SID.
///
/// RFC 8667, Section 2.1.1.1 — <https://www.rfc-editor.org/rfc/rfc8667#section-2.1.1.1>
fn push_sid(buf: &mut DissectBuffer<'_>, v: &[u8], at: usize, o: usize) -> Option<usize> {
    match v.len().checked_sub(at)? {
        0..=2 => None,
        3 => {
            let label = read_be_u24(v, at).ok()? & 0x000F_FFFF;
            buf.push_field(
                &SUB_TLV_FIELDS[F_SID],
                FieldValue::U32(label),
                o + at..o + at + 3,
            );
            Some(at + 3)
        }
        _ => {
            push_u32(buf, F_SID, v, at, o);
            Some(at + 4)
        }
    }
}

/// Pushes the SRv6 SID at `at`, then the length-prefixed sub-sub-TLVs;
/// returns the offset after the last complete sub-sub-TLV, so that the
/// caller pushes any octets left inside and after the Sub-sub-TLV area as a
/// single `raw` field.
///
/// RFC 9352, Sections 7.2 and 8 — <https://www.rfc-editor.org/rfc/rfc9352#section-7.2>
fn push_srv6_sid_and_sub_sub_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    v: &'pkt [u8],
    at: usize,
    o: usize,
) -> usize {
    push_ipv6(buf, F_SRV6_SID, v, at, o);
    let len_at = at + SRV6_SID_LEN;
    let Some(&sub_len) = v.get(len_at) else {
        return len_at;
    };
    let end = len_at + 1 + sub_len as usize;
    if end > v.len() {
        return len_at;
    }
    let start = len_at + 1;
    start + walk_sub_tlvs(buf, &v[start..end], o + start, SubTlvContext::Srv6Sid)
}

/// Pushes SRGB / SRLB range descriptors ("Range" + SID/Label sub-TLV);
/// returns the offset after the last complete descriptor.
///
/// RFC 8667, Sections 3.1 and 3.3 — <https://www.rfc-editor.org/rfc/rfc8667#section-3.1>
fn push_ranges(buf: &mut DissectBuffer<'_>, v: &[u8], start: usize, o: usize) -> usize {
    let idx = buf.begin_container(
        &SUB_TLV_FIELDS[F_RANGES],
        FieldValue::Array(0..0),
        o + start..o + v.len(),
    );
    let mut at = start;
    // Range (3) + SID/Label sub-TLV header (2) + value (3 or 4)
    while at + 5 <= v.len() {
        let sub_type = v[at + 3];
        let sub_len = v[at + 4] as usize;
        let end = at + 5 + sub_len;
        if sub_type != 1 || !(3..=4).contains(&sub_len) || end > v.len() {
            break;
        }
        let entry = buf.begin_container(&FD_RANGE, FieldValue::Object(0..0), o + at..o + end);
        buf.push_field(
            &RANGE_FIELDS[FR_RANGE_SIZE],
            FieldValue::U32(read_be_u24(v, at).unwrap_or_default()),
            o + at..o + at + 3,
        );
        let sid = match sub_len {
            3 => read_be_u24(v, at + 5).unwrap_or_default() & 0x000F_FFFF,
            _ => read_be_u32(v, at + 5).unwrap_or_default(),
        };
        buf.push_field(
            &RANGE_FIELDS[FR_SID],
            FieldValue::U32(sid),
            o + at + 5..o + end,
        );
        buf.end_container(entry);
        at = end;
    }
    buf.end_container(idx);
    set_range_end(buf, idx, o + at);
    at
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

/// Neighbor sub-TLVs (TLVs 22 / 222).
fn decode_neighbor<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u8,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // Administrative group — RFC 5305, Section 3.1
        // <https://www.rfc-editor.org/rfc/rfc5305#section-3.1>
        3 if v.len() >= 4 => {
            push_u32(buf, F_ADMIN_GROUP, v, 0, o);
            Some(4)
        }
        // Link Local/Remote Identifiers — RFC 5307, Section 1.1
        // <https://www.rfc-editor.org/rfc/rfc5307#section-1.1>
        4 if v.len() >= 8 => {
            push_u32(buf, F_LOCAL_IDENTIFIER, v, 0, o);
            push_u32(buf, F_REMOTE_IDENTIFIER, v, 4, o);
            Some(8)
        }
        // IPv4 interface / neighbor address — RFC 5305, Sections 3.2-3.3
        // <https://www.rfc-editor.org/rfc/rfc5305#section-3.2>
        6 if v.len() >= 4 => {
            push_ipv4(buf, F_IPV4_INTERFACE_ADDRESS, v, 0, o);
            Some(4)
        }
        8 if v.len() >= 4 => {
            push_ipv4(buf, F_IPV4_NEIGHBOR_ADDRESS, v, 0, o);
            Some(4)
        }
        // Maximum (reservable) link bandwidth, unreserved bandwidth —
        // RFC 5305, Sections 3.4-3.6
        // <https://www.rfc-editor.org/rfc/rfc5305#section-3.4>
        9 if v.len() >= 4 => {
            push_u32(buf, F_MAX_BANDWIDTH, v, 0, o);
            Some(4)
        }
        10 if v.len() >= 4 => {
            push_u32(buf, F_MAX_RESERVABLE_BANDWIDTH, v, 0, o);
            Some(4)
        }
        11 if v.len() >= 32 => Some(push_array(
            buf,
            F_UNRESERVED_BANDWIDTH,
            &FD_BANDWIDTH_ELEM,
            &v[..32],
            4,
            o,
        )),
        // IPv6 interface / neighbor address — RFC 6119, Sections 4.2-4.3
        // <https://www.rfc-editor.org/rfc/rfc6119#section-4.2>
        12 if v.len() >= 16 => {
            push_ipv6(buf, F_IPV6_INTERFACE_ADDRESS, v, 0, o);
            Some(16)
        }
        13 if v.len() >= 16 => {
            push_ipv6(buf, F_IPV6_NEIGHBOR_ADDRESS, v, 0, o);
            Some(16)
        }
        // TE Default metric (24 bits) — RFC 5305, Section 3.7
        // <https://www.rfc-editor.org/rfc/rfc5305#section-3.7>
        18 if v.len() >= 3 => {
            push_u24(buf, F_TE_DEFAULT_METRIC, v, 0, o);
            Some(3)
        }
        // Adj-SID — RFC 8667, Section 2.2.1: Flags | Weight | SID/Label/Index
        // <https://www.rfc-editor.org/rfc/rfc8667#section-2.2.1>
        31 if v.len() >= 5 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_WEIGHT, v, 1, o);
            push_sid(buf, v, 2, o)
        }
        // LAN-Adj-SID — RFC 8667, Section 2.2.2:
        // Flags | Weight | Neighbor System-ID | SID/Label/Index
        // <https://www.rfc-editor.org/rfc/rfc8667#section-2.2.2>
        32 if v.len() >= 2 + SYSTEM_ID_LEN + 3 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_WEIGHT, v, 1, o);
            push_bytes(buf, F_NEIGHBOR_SYSTEM_ID, v, 2, SYSTEM_ID_LEN, o);
            push_sid(buf, v, 2 + SYSTEM_ID_LEN, o)
        }
        // Unidirectional Link Delay — RFC 8570, Section 4.1: |A| RESERVED | Delay
        // <https://www.rfc-editor.org/rfc/rfc8570#section-4.1>
        33 if v.len() >= 4 => {
            push_bit(buf, F_ANOMALOUS, v[0], 0x80, o);
            push_u24(buf, F_DELAY, v, 1, o);
            Some(4)
        }
        // Min/Max Unidirectional Link Delay — RFC 8570, Section 4.2
        // <https://www.rfc-editor.org/rfc/rfc8570#section-4.2>
        34 if v.len() >= 8 => {
            push_bit(buf, F_ANOMALOUS, v[0], 0x80, o);
            push_u24(buf, F_MIN_DELAY, v, 1, o);
            push_u24(buf, F_MAX_DELAY, v, 5, o);
            Some(8)
        }
        // Unidirectional Delay Variation — RFC 8570, Section 4.3
        // <https://www.rfc-editor.org/rfc/rfc8570#section-4.3>
        35 if v.len() >= 4 => {
            push_u24(buf, F_DELAY_VARIATION, v, 1, o);
            Some(4)
        }
        // Unidirectional Link Loss — RFC 8570, Section 4.4
        // <https://www.rfc-editor.org/rfc/rfc8570#section-4.4>
        36 if v.len() >= 4 => {
            push_bit(buf, F_ANOMALOUS, v[0], 0x80, o);
            push_u24(buf, F_LINK_LOSS, v, 1, o);
            Some(4)
        }
        // Residual / Available / Utilized Bandwidth — RFC 8570, Sections 4.5-4.7
        // <https://www.rfc-editor.org/rfc/rfc8570#section-4.5>
        37..=39 if v.len() >= 4 => {
            push_u32(buf, F_BANDWIDTH, v, 0, o);
            Some(4)
        }
        // SRv6 End.X SID — RFC 9352, Section 8.1:
        // Flags | Algorithm | Weight | Endpoint Behavior | SID | Sub-sub-TLV-len
        // <https://www.rfc-editor.org/rfc/rfc9352#section-8.1>
        43 if v.len() >= 5 + SRV6_SID_LEN => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_ALGORITHM, v, 1, o);
            push_u8(buf, F_WEIGHT, v, 2, o);
            push_u16(buf, F_ENDPOINT_BEHAVIOR, v, 3, o);
            Some(push_srv6_sid_and_sub_sub_tlvs(buf, v, 5, o))
        }
        // SRv6 LAN End.X SID — RFC 9352, Section 8.2:
        // Neighbor System-ID | Flags | Algorithm | Weight | Endpoint Behavior | SID
        // <https://www.rfc-editor.org/rfc/rfc9352#section-8.2>
        44 if v.len() >= SYSTEM_ID_LEN + 5 + SRV6_SID_LEN => {
            let at = SYSTEM_ID_LEN;
            push_bytes(buf, F_NEIGHBOR_SYSTEM_ID, v, 0, SYSTEM_ID_LEN, o);
            push_u8(buf, F_FLAGS, v, at, o);
            push_u8(buf, F_ALGORITHM, v, at + 1, o);
            push_u8(buf, F_WEIGHT, v, at + 2, o);
            push_u16(buf, F_ENDPOINT_BEHAVIOR, v, at + 3, o);
            Some(push_srv6_sid_and_sub_sub_tlvs(buf, v, at + 5, o))
        }
        _ => None,
    }
}

/// Prefix reachability sub-TLVs (TLVs 135, 235, 236, 237, 27).
fn decode_prefix<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u8,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // 32-bit / 64-bit Administrative Tags — RFC 5130, Sections 3.1-3.2
        // <https://www.rfc-editor.org/rfc/rfc5130#section-3.1>
        1 if v.len() >= 4 => Some(push_array(buf, F_TAGS, &FD_TAG32, v, 4, o)),
        2 if v.len() >= 8 => Some(push_array(buf, F_TAGS, &FD_TAG64, v, 8, o)),
        // Prefix-SID — RFC 8667, Section 2.1: Flags | Algorithm | SID/Index/Label
        // <https://www.rfc-editor.org/rfc/rfc8667#section-2.1>
        3 if v.len() >= 5 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_ALGORITHM, v, 1, o);
            push_sid(buf, v, 2, o)
        }
        // Prefix Attribute Flags — RFC 7794, Section 2.1: |X|R|N| ...
        // <https://www.rfc-editor.org/rfc/rfc7794#section-2.1>
        4 if !v.is_empty() => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_bit(buf, F_FLAG_X, v[0], 0x80, o);
            push_bit(buf, F_FLAG_R, v[0], 0x40, o);
            push_bit(buf, F_FLAG_N, v[0], 0x20, o);
            Some(1)
        }
        // SRv6 End SID — RFC 9352, Section 7.2:
        // Flags | Endpoint Behavior | SID | Sub-sub-TLV-len
        // <https://www.rfc-editor.org/rfc/rfc9352#section-7.2>
        5 if v.len() >= 3 + SRV6_SID_LEN => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u16(buf, F_ENDPOINT_BEHAVIOR, v, 1, o);
            Some(push_srv6_sid_and_sub_sub_tlvs(buf, v, 3, o))
        }
        // IPv4 / IPv6 Source Router ID — RFC 7794, Section 2.2
        // <https://www.rfc-editor.org/rfc/rfc7794#section-2.2>
        11 if v.len() >= 4 => {
            push_ipv4(buf, F_IPV4_SOURCE_ROUTER_ID, v, 0, o);
            Some(4)
        }
        12 if v.len() >= 16 => {
            push_ipv6(buf, F_IPV6_SOURCE_ROUTER_ID, v, 0, o);
            Some(16)
        }
        _ => None,
    }
}

/// Router Capability sub-TLVs (TLV 242).
fn decode_router_capability<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u8,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // SR-Capabilities (2) and SR Local Block (22) — RFC 8667, Sections
        // 3.1 and 3.3: Flags, then Range + SID/Label sub-TLV descriptors
        // <https://www.rfc-editor.org/rfc/rfc8667#section-3.1>
        // <https://www.rfc-editor.org/rfc/rfc8667#section-3.3>
        2 | 22 if !v.is_empty() => {
            push_u8(buf, F_FLAGS, v, 0, o);
            Some(push_ranges(buf, v, 1, o))
        }
        // IPv4 / IPv6 TE Router ID — RFC 9346, Section 4.1
        // <https://www.rfc-editor.org/rfc/rfc9346#section-4.1>
        11 if v.len() >= 4 => {
            push_ipv4(buf, F_IPV4_TE_ROUTER_ID, v, 0, o);
            Some(4)
        }
        12 if v.len() >= 16 => {
            push_ipv6(buf, F_IPV6_TE_ROUTER_ID, v, 0, o);
            Some(16)
        }
        // SR-Algorithm — RFC 8667, Section 3.2
        // <https://www.rfc-editor.org/rfc/rfc8667#section-3.2>
        19 => Some(push_array(buf, F_ALGORITHMS, &FD_ALGORITHM_ELEM, v, 1, o)),
        // Node MSD — RFC 8491, Section 2: MSD-Type | MSD-Value pairs
        // <https://www.rfc-editor.org/rfc/rfc8491#section-2>
        23 => {
            let n = v.len() / 2 * 2;
            let idx =
                buf.begin_container(&SUB_TLV_FIELDS[F_MSDS], FieldValue::Array(0..0), o..o + n);
            for at in (0..n).step_by(2) {
                let e = buf.begin_container(&FD_MSD, FieldValue::Object(0..0), o + at..o + at + 2);
                buf.push_field(
                    &MSD_FIELDS[FM_TYPE],
                    FieldValue::U8(v[at]),
                    o + at..o + at + 1,
                );
                buf.push_field(
                    &MSD_FIELDS[FM_VALUE],
                    FieldValue::U8(v[at + 1]),
                    o + at + 1..o + at + 2,
                );
                buf.end_container(e);
            }
            buf.end_container(idx);
            Some(n)
        }
        // SRMS Preference — RFC 8667, Section 3.4
        // <https://www.rfc-editor.org/rfc/rfc8667#section-3.4>
        24 if !v.is_empty() => {
            push_u8(buf, F_PREFERENCE, v, 0, o);
            Some(1)
        }
        // SRv6 Capabilities — RFC 9352, Section 2: Flags (2) | sub-sub-TLVs
        // <https://www.rfc-editor.org/rfc/rfc9352#section-2>
        25 if v.len() >= 2 => {
            push_u16(buf, F_SRV6_FLAGS, v, 0, o);
            push_sub_tlvs(buf, &v[2..], o + 2, SubTlvContext::Unregistered);
            Some(v.len())
        }
        _ => None,
    }
}

/// SRv6 SID Structure sub-sub-TLV.
///
/// RFC 9352, Section 9 — <https://www.rfc-editor.org/rfc/rfc9352#section-9>
/// Layout: LB Length, LN Length, Fun. Length, Arg. Length (1 octet each).
fn decode_srv6_sid_structure(
    buf: &mut DissectBuffer<'_>,
    t: u8,
    v: &[u8],
    o: usize,
) -> Option<usize> {
    match t {
        1 if v.len() >= 4 => {
            let fields = [
                F_LOCATOR_BLOCK_LENGTH,
                F_LOCATOR_NODE_LENGTH,
                F_FUNCTION_LENGTH,
                F_ARGUMENT_LENGTH,
            ];
            for (at, f) in fields.into_iter().enumerate() {
                buf.push_field(
                    &SUB_SUB_TLV_FIELDS[f],
                    FieldValue::U8(v[at]),
                    o + at..o + at + 1,
                );
            }
            Some(4)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # Sub-TLV helper coverage
    //
    // | RFC Section        | Description                         | Test                      |
    // |--------------------|-------------------------------------|---------------------------|
    // | RFC 5305 §3.4      | IEEE float bandwidth formatting     | ieee_float_formats        |
    // | RFC 8667 §2.1.1.1  | SID/Label 3- or 4-octet encodings   | sid_label_lengths         |
    // | RFC 8667 §3.1      | Malformed SRGB range descriptors    | ranges_stop_on_bad_sub_tlv |
    // | RFC 5305 §4        | Trailing prefix bits ignored        | mask_prefix_clears_trailing_bits |
    // | IANA registries    | Sub-TLV name tables                 | name_tables_cover_registries |
    // | —                  | Sub-TLV schema layout               | schema_builder_layout     |
    // | RFC 6119, RFC 9346, RFC 9352 §2, §7.2, RFC 8667 §2.4 | Remaining sub-TLV decoders | decode_remaining_sub_tlvs |

    #[test]
    fn ieee_float_formats() {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        format_ieee_float(&FieldValue::U32(1.25e8f32.to_bits()), &ctx, &mut out).unwrap();
        assert_eq!(out, b"125000000");
        out.clear();
        format_ieee_float(&FieldValue::U32(f32::INFINITY.to_bits()), &ctx, &mut out).unwrap();
        assert_eq!(out, b"null");
        out.clear();
        format_ieee_float(&FieldValue::U8(1), &ctx, &mut out).unwrap();
        assert_eq!(out, b"null");
    }

    #[test]
    fn sid_label_lengths() {
        let mut buf = DissectBuffer::new();
        assert_eq!(push_sid(&mut buf, &[0x0f, 0xff, 0xff], 0, 0), Some(3));
        assert_eq!(buf.fields()[0].value, FieldValue::U32(0xF_FFFF));
        assert_eq!(push_sid(&mut buf, &[0, 0, 0, 1], 0, 0), Some(4));
        assert_eq!(push_sid(&mut buf, &[0, 0], 0, 0), None);
        assert_eq!(push_sid(&mut buf, &[0], 4, 0), None);
    }

    #[test]
    fn mask_prefix_clears_trailing_bits() {
        let mut p = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0xff];
        mask_prefix(&mut p, 60);
        assert_eq!(p, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0xf0]);
        let mut p = [0xff, 0xff];
        mask_prefix(&mut p, 0);
        assert_eq!(p, [0, 0]);
        let mut p = [0xff];
        mask_prefix(&mut p, 8);
        assert_eq!(p, [0xff]);
    }

    #[test]
    fn ranges_stop_on_bad_sub_tlv() {
        let mut buf = DissectBuffer::new();
        // Flags, then a range whose SID/Label sub-TLV has type 9.
        let v = [0x80, 0, 0, 1, 9, 3, 0, 0, 1];
        assert_eq!(push_ranges(&mut buf, &v, 1, 0), 1);
        assert_eq!(buf.fields()[0].range, 1..1);
    }

    /// Every registered name is reachable, and unknown codes have none.
    #[test]
    fn name_tables_cover_registries() {
        let count =
            |f: fn(u8) -> Option<&'static str>| (0..=255u8).filter(|t| f(*t).is_some()).count();
        assert_eq!(count(neighbor_sub_tlv_name), 42);
        assert_eq!(count(prefix_sub_tlv_name), 9);
        assert_eq!(count(router_capability_sub_tlv_name), 31);
        assert_eq!(count(binding_sub_tlv_name), 2);
        assert_eq!(count(srv6_sid_sub_sub_tlv_name), 1);
        assert_eq!(count(no_name), 0);
        for ctx in [
            SubTlvContext::Neighbor,
            SubTlvContext::Prefix,
            SubTlvContext::RouterCapability,
            SubTlvContext::Binding,
            SubTlvContext::Srv6Sid,
            SubTlvContext::Unregistered,
        ] {
            let d = ctx.type_descriptor();
            assert_eq!((d.display_fn.unwrap())(&FieldValue::U16(1), &[]), None);
        }
        assert_eq!(container_name(&FieldValue::U8(0), &[]), None);
    }

    /// The schema builder yields the documented field order.
    #[test]
    fn schema_builder_layout() {
        let fields = sub_tlv_fields(RAW_DESCRIPTOR);
        assert_eq!(fields[F_LENGTH].name, "length");
        assert_eq!(fields[F_VALUE].name, "value");
        assert_eq!(fields[F_RAW].name, "raw");
        assert_eq!(fields[F_IPV6_TE_ROUTER_ID].name, "ipv6_te_router_id");
        assert_eq!(SUB_TLV_FIELDS.len(), SUB_TLV_FIELD_COUNT);
    }

    fn named<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Vec<&'a Field<'pkt>> {
        buf.fields().iter().filter(|f| f.name() == name).collect()
    }

    /// IPv6 addresses (RFC 6119, RFC 9346), SRv6 Capabilities sub-sub-TLVs,
    /// Binding Prefix-SID, and malformed SRv6 SID sub-sub-TLV blocks.
    #[test]
    fn decode_remaining_sub_tlvs() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut data = vec![12, 16];
        data.extend_from_slice(&addr);
        data.extend_from_slice(&[13, 16]);
        data.extend_from_slice(&addr);
        let mut buf = DissectBuffer::new();
        push_sub_tlvs(&mut buf, &data, 0, SubTlvContext::Neighbor);
        assert_eq!(named(&buf, "ipv6_interface_address").len(), 1);
        assert_eq!(named(&buf, "ipv6_neighbor_address").len(), 1);

        let mut data = vec![12, 16];
        data.extend_from_slice(&addr);
        data.extend_from_slice(&[25, 5, 0x40, 0, 9, 1, 7]); // SRv6 Caps + sub-sub
        let mut buf = DissectBuffer::new();
        push_sub_tlvs(&mut buf, &data, 0, SubTlvContext::RouterCapability);
        assert_eq!(named(&buf, "ipv6_te_router_id").len(), 1);
        assert_eq!(named(&buf, "value")[0].value, FieldValue::Bytes(&[7]));

        let mut buf = DissectBuffer::new();
        push_sub_tlvs(
            &mut buf,
            &[3, 6, 0, 0, 0, 0, 0, 5],
            0,
            SubTlvContext::Binding,
        );
        assert_eq!(named(&buf, "sid")[0].value, FieldValue::U32(5));

        // End SID without the Sub-sub-TLV-len octet, then with an overrun.
        let mut end = vec![5, 19, 0, 0, 1];
        end.extend_from_slice(&addr);
        let mut buf = DissectBuffer::new();
        push_sub_tlvs(&mut buf, &end, 0, SubTlvContext::Prefix);
        assert_eq!(named(&buf, "srv6_sid").len(), 1);
        assert!(named(&buf, "raw").is_empty());
        let mut end = vec![5, 21, 0, 0, 1];
        end.extend_from_slice(&addr);
        end.extend_from_slice(&[9, 1]);
        let mut buf = DissectBuffer::new();
        push_sub_tlvs(&mut buf, &end, 0, SubTlvContext::Prefix);
        assert_eq!(named(&buf, "raw")[0].value, FieldValue::Bytes(&[9, 1]));

        // Unknown SRv6 SID sub-sub-TLV stays raw.
        let mut buf = DissectBuffer::new();
        push_sub_tlvs(&mut buf, &[2, 1, 0], 0, SubTlvContext::Srv6Sid);
        assert_eq!(named(&buf, "value")[0].value, FieldValue::Bytes(&[0]));
    }

    /// RFC 9352, Section 7.2 — octets left over inside the Sub-sub-TLV area
    /// and after it are one `raw` field of the SRv6 End SID sub-TLV, not two
    /// `raw` keys in the same object.
    /// <https://www.rfc-editor.org/rfc/rfc9352#section-7.2>
    #[test]
    fn srv6_sid_leftovers_are_one_raw_field() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        // Flags | Endpoint Behavior | SID | Sub-sub-TLV-len = 3, a
        // sub-sub-TLV whose length overruns it, then one trailing octet.
        let mut end = vec![5, 24, 0, 0, 1];
        end.extend_from_slice(&addr);
        end.extend_from_slice(&[3, 1, 5, 9, 7]);
        let mut buf = DissectBuffer::new();
        push_sub_tlvs(&mut buf, &end, 0, SubTlvContext::Prefix);
        let raw = named(&buf, "raw");
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].value, FieldValue::Bytes(&[1, 5, 9, 7]));
        assert_eq!(raw[0].range, 22..26);
        // The empty sub-sub-TLV array covers none of the leftover octets.
        let arrays = named(&buf, "sub_tlvs");
        assert_eq!(arrays.len(), 2);
        assert_eq!(arrays[1].range, 22..22);
    }
}
