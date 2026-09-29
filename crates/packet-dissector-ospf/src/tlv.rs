//! TLV decoding shared by OSPFv2 Opaque LSAs, OSPFv3 Extended LSAs, the
//! Router Information LSA, the SRv6 Locator LSA and the LLS data block.
//!
//! All of these use the same TLV encoding: a 2-octet Type, a 2-octet Length
//! covering the value only, and a value padded to a 4-octet boundary.
//!
//! ## References
//! - RFC 3630 (TE extensions): <https://www.rfc-editor.org/rfc/rfc3630>
//! - RFC 5613 (LLS): <https://www.rfc-editor.org/rfc/rfc5613>
//! - RFC 5642 (Dynamic Hostname): <https://www.rfc-editor.org/rfc/rfc5642>
//! - RFC 7684 (OSPFv2 Prefix/Link Attribute Advertisement): <https://www.rfc-editor.org/rfc/rfc7684>
//! - RFC 7770 (Router Information): <https://www.rfc-editor.org/rfc/rfc7770>
//! - RFC 8362 (OSPFv3 LSA Extendibility): <https://www.rfc-editor.org/rfc/rfc8362>
//! - RFC 8665 (OSPFv2 Segment Routing): <https://www.rfc-editor.org/rfc/rfc8665>
//! - RFC 8666 (OSPFv3 Segment Routing): <https://www.rfc-editor.org/rfc/rfc8666>
//! - RFC 9513 (OSPFv3 SRv6): <https://www.rfc-editor.org/rfc/rfc9513>
//! - IANA OSPF parameters: <https://www.iana.org/assignments/ospf-parameters>,
//!   <https://www.iana.org/assignments/ospfv2-parameters>,
//!   <https://www.iana.org/assignments/ospfv3-parameters>,
//!   <https://www.iana.org/assignments/ospf-traffic-eng-tlvs>

use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32, read_ipv4_addr};

/// TLV header size (Type + Length).
///
/// RFC 3630, Section 2.3.2 — <https://www.rfc-editor.org/rfc/rfc3630#section-2.3.2>
const TLV_HEADER_SIZE: usize = 4;

/// Returns the number of octets used by an OSPFv3 address prefix of
/// `prefix_length` bits, or `None` if the length exceeds 128 bits.
///
/// RFC 5340, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.1>
/// "Address Prefix is an encoding of the prefix itself as an even multiple
/// of 32-bit words, padding with zero bits as necessary."
pub(crate) fn prefix_octets(prefix_length: u8) -> Option<usize> {
    if prefix_length > 128 {
        return None;
    }
    Some(prefix_length.div_ceil(32) as usize * 4)
}

/// Copies an address prefix (at most 16 octets) into a zero-padded IPv6 address.
pub(crate) fn prefix_to_ipv6(bytes: &[u8]) -> [u8; 16] {
    let mut addr = [0u8; 16];
    let n = bytes.len().min(16);
    addr[..n].copy_from_slice(&bytes[..n]);
    addr
}

/// Formats a `U32` holding IEEE 754 single-precision bits as a JSON number.
///
/// RFC 3630, Section 2.5.6 — <https://www.rfc-editor.org/rfc/rfc3630#section-2.5.6>
/// "The Maximum Bandwidth sub-TLV specifies the maximum bandwidth that can
/// be used on this link, in this direction (from the system originating
/// the LSA to its neighbor), in IEEE floating point format."
fn format_ieee_float(
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

/// Field descriptor indices for [`TLV_FIELDS`] and [`SUB_TLV_FIELDS`].
const F_LENGTH: usize = 1;
const F_VALUE: usize = 2;
const F_ROUTER_ADDRESS: usize = 5;
const F_LINK_TYPE: usize = 6;
const F_LINK_ID: usize = 7;
const F_LINK_DATA: usize = 8;
const F_LOCAL_ADDRESSES: usize = 9;
const F_REMOTE_ADDRESSES: usize = 10;
const F_TE_METRIC: usize = 11;
const F_MAX_BANDWIDTH: usize = 12;
const F_MAX_RESERVABLE_BANDWIDTH: usize = 13;
const F_UNRESERVED_BANDWIDTH: usize = 14;
const F_ADMIN_GROUP: usize = 15;
const F_INFORMATIONAL_CAPABILITIES: usize = 16;
const F_FUNCTIONAL_CAPABILITIES: usize = 17;
const F_HOSTNAME: usize = 18;
const F_ALGORITHMS: usize = 19;
const F_ALGORITHM: usize = 20;
const F_RANGE_SIZE: usize = 21;
const F_SID: usize = 22;
const F_PREFERENCE: usize = 23;
const F_FLAGS: usize = 24;
const F_MT_ID: usize = 25;
const F_WEIGHT: usize = 26;
const F_NEIGHBOR_ID: usize = 27;
const F_ROUTE_TYPE: usize = 28;
const F_PREFIX_LENGTH: usize = 29;
const F_ADDRESS_FAMILY: usize = 30;
const F_PREFIX: usize = 31;
const F_PREFIX_OPTIONS: usize = 32;
const F_METRIC: usize = 33;
const F_INTERFACE_ID: usize = 34;
const F_NEIGHBOR_INTERFACE_ID: usize = 35;
const F_NEIGHBOR_ROUTER_ID: usize = 36;
const F_ATTACHED_ROUTERS: usize = 37;
const F_OPTIONS: usize = 38;
const F_DESTINATION_ROUTER_ID: usize = 39;
const F_FLAG_E: usize = 40;
const F_LINK_LOCAL_ADDRESS: usize = 41;
const F_IPV4_LINK_LOCAL_ADDRESS: usize = 42;
const F_FORWARDING_ADDRESS: usize = 43;
const F_IPV4_FORWARDING_ADDRESS: usize = 44;
const F_ROUTE_TAG: usize = 45;
const F_ENDPOINT_BEHAVIOR: usize = 46;
const F_SRV6_SID: usize = 47;
const F_LOCATOR: usize = 48;
const F_EXTENDED_OPTIONS: usize = 49;
const F_SEQUENCE_NUMBER: usize = 50;
const F_AUTH_DATA: usize = 51;

/// Number of fields in a TLV object schema.
const TLV_FIELD_COUNT: usize = 52;

/// `flags` differs in width by TLV type: one octet in the SR sub-TLVs,
/// two octets in the SRv6 Capabilities TLV (RFC 9513, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc9513#section-2>).
const FLAGS_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("flags", "Flags", FieldType::Any).optional();

/// `prefix` is an IPv4 address in the OSPFv2 Extended Prefix TLVs and an
/// OSPFv3 address prefix (RFC 5340, Appendix A.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.1>) elsewhere.
const PREFIX_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("prefix", "Address Prefix", FieldType::Any).optional();

/// Builds the union of the fields that can appear inside a TLV or sub-TLV
/// object. Every field except `type` and `length` depends on the TLV type,
/// so they are all marked optional.
const fn tlv_fields(sub_tlvs: FieldDescriptor) -> [FieldDescriptor; TLV_FIELD_COUNT] {
    [
        FieldDescriptor::new("type", "Type", FieldType::U16),
        FieldDescriptor::new("length", "Length", FieldType::U16),
        FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
        UNPARSED_DESCRIPTOR,
        sub_tlvs,
        FieldDescriptor::new("router_address", "Router Address", FieldType::Ipv4Addr).optional(),
        FieldDescriptor::new("link_type", "Link Type", FieldType::U8).optional(),
        FieldDescriptor::new("link_id", "Link ID", FieldType::Ipv4Addr).optional(),
        FieldDescriptor::new("link_data", "Link Data", FieldType::Ipv4Addr).optional(),
        FieldDescriptor::new(
            "local_addresses",
            "Local Interface IP Addresses",
            FieldType::Array,
        )
        .optional(),
        FieldDescriptor::new(
            "remote_addresses",
            "Remote Interface IP Addresses",
            FieldType::Array,
        )
        .optional(),
        FieldDescriptor::new("te_metric", "TE Metric", FieldType::U32).optional(),
        FieldDescriptor::new("max_bandwidth", "Maximum Bandwidth", FieldType::U32)
            .optional()
            .with_format_fn(format_ieee_float),
        FieldDescriptor::new(
            "max_reservable_bandwidth",
            "Maximum Reservable Bandwidth",
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
        FieldDescriptor::new("admin_group", "Administrative Group", FieldType::U32).optional(),
        FieldDescriptor::new(
            "informational_capabilities",
            "Informational Capabilities",
            FieldType::U32,
        )
        .optional(),
        FieldDescriptor::new(
            "functional_capabilities",
            "Functional Capabilities",
            FieldType::U32,
        )
        .optional(),
        FieldDescriptor::new("hostname", "Hostname", FieldType::Bytes)
            .optional()
            .with_format_fn(format_utf8_lossy),
        FieldDescriptor::new("algorithms", "Algorithms", FieldType::Array).optional(),
        FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8).optional(),
        FieldDescriptor::new("range_size", "Range Size", FieldType::U32).optional(),
        FieldDescriptor::new("sid", "SID/Label/Index", FieldType::U32).optional(),
        FieldDescriptor::new("preference", "Preference", FieldType::U8).optional(),
        FLAGS_DESCRIPTOR,
        FieldDescriptor::new("mt_id", "MT-ID", FieldType::U8).optional(),
        FieldDescriptor::new("weight", "Weight", FieldType::U8).optional(),
        FieldDescriptor::new("neighbor_id", "Neighbor ID", FieldType::Ipv4Addr).optional(),
        FieldDescriptor::new("route_type", "Route Type", FieldType::U8).optional(),
        FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
        FieldDescriptor::new("address_family", "Address Family", FieldType::U8).optional(),
        PREFIX_DESCRIPTOR,
        FieldDescriptor::new("prefix_options", "Prefix Options", FieldType::U8).optional(),
        FieldDescriptor::new("metric", "Metric", FieldType::U32).optional(),
        FieldDescriptor::new("interface_id", "Interface ID", FieldType::U32).optional(),
        FieldDescriptor::new(
            "neighbor_interface_id",
            "Neighbor Interface ID",
            FieldType::U32,
        )
        .optional(),
        FieldDescriptor::new(
            "neighbor_router_id",
            "Neighbor Router ID",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new("attached_routers", "Attached Routers", FieldType::Array).optional(),
        FieldDescriptor::new("options", "Options", FieldType::U32).optional(),
        FieldDescriptor::new(
            "destination_router_id",
            "Destination Router ID",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new("flag_e", "E-bit (External Metric Type 2)", FieldType::U8).optional(),
        FieldDescriptor::new(
            "link_local_address",
            "IPv6 Link-Local Interface Address",
            FieldType::Ipv6Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv4_link_local_address",
            "IPv4 Link-Local Interface Address",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "forwarding_address",
            "Forwarding Address",
            FieldType::Ipv6Addr,
        )
        .optional(),
        FieldDescriptor::new(
            "ipv4_forwarding_address",
            "IPv4 Forwarding Address",
            FieldType::Ipv4Addr,
        )
        .optional(),
        FieldDescriptor::new("route_tag", "Route Tag", FieldType::U32).optional(),
        FieldDescriptor::new("endpoint_behavior", "Endpoint Behavior", FieldType::U16).optional(),
        FieldDescriptor::new("srv6_sid", "SRv6 SID", FieldType::Ipv6Addr).optional(),
        FieldDescriptor::new("locator", "SRv6 Locator", FieldType::Ipv6Addr).optional(),
        FieldDescriptor::new(
            "extended_options",
            "Extended Options and Flags",
            FieldType::U32,
        )
        .optional(),
        FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32).optional(),
        FieldDescriptor::new("auth_data", "Authentication Data", FieldType::Bytes).optional(),
    ]
}

/// Child fields of a top-level TLV object.
static TLV_FIELDS: [FieldDescriptor; TLV_FIELD_COUNT] = tlv_fields(
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&SUB_TLV_FIELDS),
);

/// Child fields of a sub-TLV object.
///
/// Identical to [`TLV_FIELDS`] except that nested `sub_tlvs` carry no
/// further schema, which keeps the descriptor graph acyclic.
static SUB_TLV_FIELDS: [FieldDescriptor; TLV_FIELD_COUNT] =
    tlv_fields(FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array).optional());

/// Element of the `local_addresses` and `remote_addresses` arrays.
static FD_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("address", "Address", FieldType::Ipv4Addr);

/// Element of the `unreserved_bandwidth` array.
static FD_BANDWIDTH: FieldDescriptor =
    FieldDescriptor::new("bandwidth", "Bandwidth", FieldType::U32)
        .with_format_fn(format_ieee_float);

/// Element of the `algorithms` array.
static FD_ALGORITHM: FieldDescriptor =
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8);

/// Element of the `attached_routers` array.
static FD_ATTACHED_ROUTER: FieldDescriptor =
    FieldDescriptor::new("attached_router", "Attached Router", FieldType::Ipv4Addr);

/// Resolves a TLV container's label from its `type` child.
fn tlv_container_name(
    v: &FieldValue<'_>,
    children: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    match v {
        FieldValue::Object(_) => {
            let t = children.iter().find(|f| f.name() == "type")?;
            (t.descriptor.display_fn?)(&t.value, children)
        }
        _ => None,
    }
}

/// Descriptor for bytes left over after the last structure that could be
/// decoded. Shared with the LSA body decoders.
pub(crate) const UNPARSED_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("unparsed", "Unparsed Data", FieldType::Bytes).optional();

/// Descriptor for an array of top-level TLVs. Shared with the LSA schemas.
pub(crate) const TLVS_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(&TLV_FIELDS);

/// Array of top-level TLVs.
static FD_TLVS: FieldDescriptor = TLVS_DESCRIPTOR;

/// Object for one top-level TLV; labeled with the TLV type name.
static FD_TLV: FieldDescriptor = FieldDescriptor::new("tlv", "TLV", FieldType::Object)
    .with_children(&TLV_FIELDS)
    .with_display_fn(tlv_container_name);

/// Array of sub-TLVs.
static FD_SUB_TLVS: FieldDescriptor =
    FieldDescriptor::new("sub_tlvs", "Sub-TLVs", FieldType::Array)
        .optional()
        .with_children(&SUB_TLV_FIELDS);

/// Object for one sub-TLV; labeled with the sub-TLV type name.
static FD_SUB_TLV: FieldDescriptor = FieldDescriptor::new("sub_tlv", "Sub-TLV", FieldType::Object)
    .with_children(&SUB_TLV_FIELDS)
    .with_display_fn(tlv_container_name);

static FD_UNPARSED: FieldDescriptor = UNPARSED_DESCRIPTOR;

// ---------------------------------------------------------------------------
// Type name tables
// ---------------------------------------------------------------------------

/// Top-level TLVs of the Traffic Engineering LSA.
///
/// IANA "Top Level Types in TE LSAs" — <https://www.iana.org/assignments/ospf-traffic-eng-tlvs>
fn te_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("Router Address"),
        2 => Some("Link"),
        3 => Some("Router IPv6 Address"),
        4 => Some("Link Local"),
        5 => Some("Node Attribute"),
        6 => Some("Optical Node Property"),
        _ => None,
    }
}

/// Sub-TLVs of the TE Link TLV.
///
/// IANA "Types for sub-TLVs of TE Link TLV (Value 2)" — <https://www.iana.org/assignments/ospf-traffic-eng-tlvs>
fn te_link_sub_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("Link type"),
        2 => Some("Link ID"),
        3 => Some("Local interface IP address"),
        4 => Some("Remote interface IP address"),
        5 => Some("Traffic engineering metric"),
        6 => Some("Maximum bandwidth"),
        7 => Some("Maximum reservable bandwidth"),
        8 => Some("Unreserved bandwidth"),
        9 => Some("Administrative group"),
        10 => Some("Local and Remote TE Router ID"),
        11 => Some("Link Local/Remote Identifiers"),
        14 => Some("Link Protection Type"),
        15 => Some("Interface Switching Capability Descriptor"),
        16 => Some("Shared Risk Link Group"),
        17 => Some("Bandwidth Constraints"),
        18 => Some("Neighbor ID"),
        19 => Some("Local Interface IPv6 Address"),
        20 => Some("Remote Interface IPv6 Address"),
        21 => Some("Remote AS Number"),
        22 => Some("IPv4 Remote ASBR ID"),
        24 => Some("IPv6 Remote ASBR ID"),
        26 => Some("Extended Administrative Group"),
        27 => Some("Unidirectional Link Delay"),
        28 => Some("Min/Max Unidirectional Link Delay"),
        29 => Some("Unidirectional Delay Variation"),
        30 => Some("Unidirectional Link Loss"),
        31 => Some("Unidirectional Residual Bandwidth"),
        32 => Some("Unidirectional Available Bandwidth"),
        33 => Some("Unidirectional Utilized Bandwidth"),
        _ => None,
    }
}

/// Router Information LSA TLVs (OSPFv2 and OSPFv3).
///
/// IANA "OSPF Router Information (RI) TLVs" — <https://www.iana.org/assignments/ospf-parameters>
fn ri_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("Router Informational Capabilities"),
        2 => Some("Router Functional Capabilities"),
        3 => Some("TE-MESH-GROUP (IPv4)"),
        4 => Some("TE-MESH-GROUP (IPv6)"),
        5 => Some("TE Node Capability Descriptor"),
        6 => Some("PCED"),
        7 => Some("OSPF Dynamic Hostname"),
        8 => Some("SR-Algorithm"),
        9 => Some("SID/Label Range"),
        10 => Some("Node Admin Tag"),
        11 => Some("S-BFD Discriminator"),
        12 => Some("Node MSD"),
        13 => Some("Tunnel Encapsulations"),
        14 => Some("SR Local Block"),
        15 => Some("SRMS Preference"),
        16 => Some("Flexible Algorithm Definition"),
        17 => Some("OSPF Area Leader"),
        18 => Some("OSPF Dynamic Flooding"),
        20 => Some("SRv6 Capabilities"),
        21 => Some("IP Algorithm"),
        _ => None,
    }
}

/// Sub-TLVs of the SID/Label Range and SR Local Block TLVs.
///
/// RFC 8665, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8665#section-2.1>
fn sid_label_sub_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("SID/Label"),
        _ => None,
    }
}

/// Sub-TLVs without a registered name table (e.g. of the SRv6
/// Capabilities TLV, for which RFC 9513 defines none).
/// <https://www.rfc-editor.org/rfc/rfc9513>
fn no_name(_t: u16) -> Option<&'static str> {
    None
}

/// OSPFv2 Extended Prefix Opaque LSA TLVs.
///
/// IANA "OSPFv2 Extended Prefix Opaque LSA TLVs" — <https://www.iana.org/assignments/ospfv2-parameters>
fn ext_prefix_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("OSPFv2 Extended Prefix"),
        2 => Some("OSPF Extended Prefix Range"),
        _ => None,
    }
}

/// OSPFv2 Extended Prefix TLV sub-TLVs.
///
/// IANA "OSPFv2 Extended Prefix TLV Sub-TLVs" — <https://www.iana.org/assignments/ospfv2-parameters>
fn ext_prefix_sub_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("SID/Label"),
        2 => Some("Prefix-SID"),
        3 => Some("Flexible Algorithm Prefix Metric"),
        4 => Some("Prefix Source OSPF Router-ID"),
        5 => Some("Prefix Source Router Address"),
        6 => Some("OSPFv2 IP Algorithm Prefix Reachability"),
        7 => Some("OSPFv2 IP Forwarding Address"),
        9 => Some("BIER"),
        10 => Some("BIER MPLS Encapsulation"),
        11 => Some("OSPFv2 Prefix Extended Flags"),
        12 => Some("BIER PHP Request"),
        13 => Some("Administrative Tag"),
        _ => None,
    }
}

/// OSPFv2 Extended Link Opaque LSA TLVs.
///
/// IANA "OSPFv2 Extended Link Opaque LSA TLVs" — <https://www.iana.org/assignments/ospfv2-parameters>
fn ext_link_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("OSPFv2 Extended Link"),
        _ => None,
    }
}

/// OSPFv2 Extended Link TLV sub-TLVs.
///
/// IANA "OSPFv2 Extended Link TLV Sub-TLVs" — <https://www.iana.org/assignments/ospfv2-parameters>
fn ext_link_sub_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("SID/Label"),
        2 => Some("Adj-SID"),
        3 => Some("LAN Adj-SID/Label"),
        4 => Some("Network-to-Router Metric"),
        5 => Some("RTM Capability"),
        6 => Some("OSPFv2 Link MSD"),
        7 => Some("Graceful-Link-Shutdown"),
        8 => Some("Remote IPv4 Address"),
        9 => Some("Local/Remote Interface ID"),
        10 => Some("Application-Specific Link Attributes"),
        11 => Some("Shared Risk Link Group"),
        12 => Some("Unidirectional Link Delay"),
        13 => Some("Min/Max Unidirectional Link Delay"),
        14 => Some("Unidirectional Delay Variation"),
        15 => Some("Unidirectional Link Loss"),
        16 => Some("Unidirectional Residual Bandwidth"),
        17 => Some("Unidirectional Available Bandwidth"),
        18 => Some("Unidirectional Utilized Bandwidth"),
        19 => Some("Administrative Group"),
        20 => Some("Extended Administrative Group"),
        21 => Some("OSPFv2 Link Attributes Bits"),
        22 => Some("TE Metric"),
        23 => Some("Maximum link bandwidth"),
        24 => Some("L2 Bundle Member Attributes"),
        25 => Some("Generic Metric"),
        _ => None,
    }
}

/// OSPFv3 Extended-LSA TLVs.
///
/// IANA "OSPFv3 Extended-LSA TLVs" — <https://www.iana.org/assignments/ospfv3-parameters>
fn v3_ext_lsa_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("Router-Link"),
        2 => Some("Attached-Routers"),
        3 => Some("Inter-Area-Prefix"),
        4 => Some("Inter-Area-Router"),
        5 => Some("External-Prefix"),
        6 => Some("Intra-Area-Prefix"),
        7 => Some("IPv6 Link-Local Address"),
        8 => Some("IPv4 Link-Local Address"),
        9 => Some("OSPFv3 Extended Prefix Range"),
        _ => None,
    }
}

/// OSPFv3 Extended-LSA sub-TLVs.
///
/// IANA "OSPFv3 Extended-LSA Sub-TLVs" — <https://www.iana.org/assignments/ospfv3-parameters>
fn v3_ext_lsa_sub_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("IPv6-Forwarding-Address"),
        2 => Some("IPv4-Forwarding-Address"),
        3 => Some("Route-Tag"),
        4 => Some("Prefix-SID"),
        5 => Some("Adj-SID"),
        6 => Some("LAN Adj-SID"),
        7 => Some("SID/Label"),
        8 => Some("Graceful-Link-Shutdown"),
        9 => Some("OSPFv3 Link MSD"),
        10 => Some("OSPFv3 Link Attributes Bits"),
        11 => Some("Application-Specific Link Attributes"),
        12 => Some("Shared Risk Link Group"),
        13 => Some("Unidirectional Link Delay"),
        14 => Some("Min/Max Unidirectional Link Delay"),
        15 => Some("Unidirectional Delay Variation"),
        16 => Some("Unidirectional Link Loss"),
        17 => Some("Unidirectional Residual Bandwidth"),
        18 => Some("Unidirectional Available Bandwidth"),
        19 => Some("Unidirectional Utilized Bandwidth"),
        20 => Some("Administrative Group"),
        21 => Some("Extended Administrative Group"),
        22 => Some("TE Metric"),
        23 => Some("Maximum link bandwidth"),
        24 => Some("Local Interface IPv6 Address"),
        25 => Some("Remote Interface IPv6 Address"),
        26 => Some("Flexible Algorithm Prefix Metric"),
        27 => Some("Prefix Source OSPF Router-ID"),
        28 => Some("Prefix Source Router Address"),
        29 => Some("L2 Bundle Member Attributes"),
        30 => Some("SRv6 SID Structure"),
        31 => Some("SRv6 End.X SID"),
        32 => Some("SRv6 LAN End.X SID"),
        33 => Some("OSPF Flexible Algorithm ASBR Metric"),
        34 => Some("Generic Metric"),
        35 => Some("OSPFv3 IP Algorithm Prefix Reachability"),
        36 => Some("OSPFv3 IP Flexible Algorithm ASBR Metric"),
        37 => Some("OSPFv3 Prefix Extended Flags"),
        38 => Some("BIER PHP Request"),
        39 => Some("Administrative Tag"),
        _ => None,
    }
}

/// OSPFv3 SRv6 Locator LSA TLVs.
///
/// RFC 9513, Section 13.8 — <https://www.rfc-editor.org/rfc/rfc9513#section-13.8>
fn srv6_locator_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("SRv6 Locator"),
        _ => None,
    }
}

/// OSPFv3 SRv6 Locator LSA sub-TLVs.
///
/// IANA "OSPFv3 SRv6 Locator LSA Sub-TLVs" — <https://www.iana.org/assignments/ospfv3-parameters>
fn srv6_locator_sub_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("SRv6 End SID"),
        2 => Some("IPv6-Forwarding-Address"),
        3 => Some("Route-Tag"),
        4 => Some("Prefix Source OSPF Router-ID"),
        5 => Some("Prefix Source Router Address"),
        6 => Some("Administrative Tag"),
        10 => Some("SRv6 SID Structure"),
        _ => None,
    }
}

/// LLS TLVs.
///
/// RFC 5613, Sections 2.4-2.5 — <https://www.rfc-editor.org/rfc/rfc5613#section-2.4>
fn lls_tlv_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("Extended Options and Flags"),
        2 => Some("Cryptographic Authentication"),
        _ => None,
    }
}

/// Builds a `type` descriptor whose display function names the TLV type.
macro_rules! type_descriptor {
    ($name_fn:path) => {
        FieldDescriptor::new("type", "Type", FieldType::U16).with_display_fn(|v, _| match v {
            FieldValue::U16(t) => $name_fn(*t),
            _ => None,
        })
    };
}

// ---------------------------------------------------------------------------
// Contexts
// ---------------------------------------------------------------------------

/// Which TLV registry a TLV sequence belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlvContext {
    /// Top-level TLVs of the OSPFv2 TE LSA (RFC 3630).
    /// <https://www.rfc-editor.org/rfc/rfc3630>
    Te,
    /// Sub-TLVs of the TE Link TLV (RFC 3630).
    /// <https://www.rfc-editor.org/rfc/rfc3630>
    TeLink,
    /// Router Information LSA TLVs (RFC 7770).
    /// <https://www.rfc-editor.org/rfc/rfc7770>
    RouterInfo,
    /// Sub-TLVs of the SID/Label Range and SRLB TLVs (RFC 8665).
    /// <https://www.rfc-editor.org/rfc/rfc8665>
    SidLabelRange,
    /// Sub-TLVs of a TLV with no defined sub-TLVs.
    Opaque,
    /// OSPFv2 Extended Prefix Opaque LSA TLVs (RFC 7684).
    /// <https://www.rfc-editor.org/rfc/rfc7684>
    ExtPrefix,
    /// Sub-TLVs of the OSPFv2 Extended Prefix (Range) TLV.
    ExtPrefixSub,
    /// OSPFv2 Extended Link Opaque LSA TLVs (RFC 7684).
    /// <https://www.rfc-editor.org/rfc/rfc7684>
    ExtLink,
    /// Sub-TLVs of the OSPFv2 Extended Link TLV.
    ExtLinkSub,
    /// OSPFv3 Extended-LSA TLVs (RFC 8362).
    /// <https://www.rfc-editor.org/rfc/rfc8362>
    V3ExtLsa,
    /// OSPFv3 Extended-LSA sub-TLVs (RFC 8362, RFC 8666, RFC 9513).
    /// <https://www.rfc-editor.org/rfc/rfc8362>
    /// <https://www.rfc-editor.org/rfc/rfc8666>
    /// <https://www.rfc-editor.org/rfc/rfc9513>
    V3ExtLsaSub,
    /// OSPFv3 SRv6 Locator LSA TLVs (RFC 9513).
    /// <https://www.rfc-editor.org/rfc/rfc9513>
    Srv6Locator,
    /// OSPFv3 SRv6 Locator LSA sub-TLVs (RFC 9513).
    /// <https://www.rfc-editor.org/rfc/rfc9513>
    Srv6LocatorSub,
    /// LLS data block TLVs (RFC 5613).
    /// <https://www.rfc-editor.org/rfc/rfc5613>
    Lls,
}

static TYPE_TE: FieldDescriptor = type_descriptor!(te_tlv_name);
static TYPE_TE_LINK: FieldDescriptor = type_descriptor!(te_link_sub_tlv_name);
static TYPE_RI: FieldDescriptor = type_descriptor!(ri_tlv_name);
static TYPE_SID_LABEL_RANGE: FieldDescriptor = type_descriptor!(sid_label_sub_tlv_name);
static TYPE_OPAQUE: FieldDescriptor = type_descriptor!(no_name);
static TYPE_EXT_PREFIX: FieldDescriptor = type_descriptor!(ext_prefix_tlv_name);
static TYPE_EXT_PREFIX_SUB: FieldDescriptor = type_descriptor!(ext_prefix_sub_tlv_name);
static TYPE_EXT_LINK: FieldDescriptor = type_descriptor!(ext_link_tlv_name);
static TYPE_EXT_LINK_SUB: FieldDescriptor = type_descriptor!(ext_link_sub_tlv_name);
static TYPE_V3_EXT_LSA: FieldDescriptor = type_descriptor!(v3_ext_lsa_tlv_name);
static TYPE_V3_EXT_LSA_SUB: FieldDescriptor = type_descriptor!(v3_ext_lsa_sub_tlv_name);
static TYPE_SRV6_LOCATOR: FieldDescriptor = type_descriptor!(srv6_locator_tlv_name);
static TYPE_SRV6_LOCATOR_SUB: FieldDescriptor = type_descriptor!(srv6_locator_sub_tlv_name);
static TYPE_LLS: FieldDescriptor = type_descriptor!(lls_tlv_name);

impl TlvContext {
    /// Descriptor for the `type` field, carrying this registry's name table.
    fn type_descriptor(self) -> &'static FieldDescriptor {
        match self {
            Self::Te => &TYPE_TE,
            Self::TeLink => &TYPE_TE_LINK,
            Self::RouterInfo => &TYPE_RI,
            Self::SidLabelRange => &TYPE_SID_LABEL_RANGE,
            Self::Opaque => &TYPE_OPAQUE,
            Self::ExtPrefix => &TYPE_EXT_PREFIX,
            Self::ExtPrefixSub => &TYPE_EXT_PREFIX_SUB,
            Self::ExtLink => &TYPE_EXT_LINK,
            Self::ExtLinkSub => &TYPE_EXT_LINK_SUB,
            Self::V3ExtLsa => &TYPE_V3_EXT_LSA,
            Self::V3ExtLsaSub => &TYPE_V3_EXT_LSA_SUB,
            Self::Srv6Locator => &TYPE_SRV6_LOCATOR,
            Self::Srv6LocatorSub => &TYPE_SRV6_LOCATOR_SUB,
            Self::Lls => &TYPE_LLS,
        }
    }

    /// Decodes a TLV value into typed fields.
    ///
    /// Returns the number of value octets decoded, or `None` when the type is
    /// unknown or the value is too short for its fixed part (nothing is
    /// pushed in that case).
    fn decode<'pkt>(
        self,
        buf: &mut DissectBuffer<'pkt>,
        t: u16,
        v: &'pkt [u8],
        o: usize,
    ) -> Option<usize> {
        match self {
            Self::Te => decode_te(buf, t, v, o),
            Self::TeLink => decode_te_link(buf, t, v, o),
            Self::RouterInfo => decode_router_info(buf, t, v, o),
            Self::SidLabelRange => match t {
                1 => push_sid(buf, v, 0, o),
                _ => None,
            },
            Self::Opaque => None,
            Self::ExtPrefix => decode_ext_prefix(buf, t, v, o),
            Self::ExtPrefixSub => decode_ext_prefix_sub(buf, t, v, o),
            Self::ExtLink => decode_ext_link(buf, t, v, o),
            Self::ExtLinkSub => decode_ext_link_sub(buf, t, v, o),
            Self::V3ExtLsa => decode_v3_ext_lsa(buf, t, v, o),
            Self::V3ExtLsaSub => decode_v3_ext_lsa_sub(buf, t, v, o),
            Self::Srv6Locator => decode_srv6_locator(buf, t, v, o),
            Self::Srv6LocatorSub => decode_srv6_locator_sub(buf, t, v, o),
            Self::Lls => decode_lls(buf, t, v, o),
        }
    }
}

// ---------------------------------------------------------------------------
// Walkers
// ---------------------------------------------------------------------------

/// Pushes a `tlvs` array for the TLV sequence in `data`.
///
/// Walking stops at the first TLV whose declared length overruns `data`; the
/// remaining octets are pushed as `unparsed` after the array.
///
/// RFC 3630, Section 2.3.2 — <https://www.rfc-editor.org/rfc/rfc3630#section-2.3.2>
pub(crate) fn push_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ctx: TlvContext,
) {
    walk(buf, data, offset, ctx, &FD_TLVS, &FD_TLV);
}

/// Pushes a `sub_tlvs` array, or nothing when `data` is empty.
fn push_sub_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ctx: TlvContext,
) {
    if !data.is_empty() {
        walk(buf, data, offset, ctx, &FD_SUB_TLVS, &FD_SUB_TLV);
    }
}

fn walk<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    ctx: TlvContext,
    array: &'static FieldDescriptor,
    element: &'static FieldDescriptor,
) {
    let array_idx =
        buf.begin_container(array, FieldValue::Array(0..0), offset..offset + data.len());
    let mut pos = 0;
    while pos + TLV_HEADER_SIZE <= data.len() {
        let t = read_be_u16(data, pos).unwrap_or_default();
        let len = read_be_u16(data, pos + 2).unwrap_or_default() as usize;
        let value_start = pos + TLV_HEADER_SIZE;
        let value_end = value_start + len;
        if value_end > data.len() {
            break;
        }
        let abs = offset + pos;
        let obj_idx =
            buf.begin_container(element, FieldValue::Object(0..0), abs..offset + value_end);
        buf.push_field(ctx.type_descriptor(), FieldValue::U16(t), abs..abs + 2);
        buf.push_field(
            &TLV_FIELDS[F_LENGTH],
            FieldValue::U16(len as u16),
            abs + 2..abs + 4,
        );
        push_value(
            buf,
            ctx,
            t,
            &data[value_start..value_end],
            offset + value_start,
        );
        buf.end_container(obj_idx);
        // RFC 3630, Section 2.3.2: "The TLV is padded to four-octet alignment"
        // <https://www.rfc-editor.org/rfc/rfc3630#section-2.3.2>
        pos = (value_start + len.div_ceil(4) * 4).min(data.len());
    }
    buf.end_container(array_idx);
    set_range_end(buf, array_idx, offset + pos);
    push_unparsed(buf, &data[pos..], offset + pos);
}

/// Decodes one TLV value, falling back to raw `value` bytes.
fn push_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    ctx: TlvContext,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) {
    match ctx.decode(buf, t, v, o) {
        Some(n) => push_unparsed(buf, &v[n.min(v.len())..], o + n),
        None => buf.push_field(&TLV_FIELDS[F_VALUE], FieldValue::Bytes(v), o..o + v.len()),
    }
}

/// Pushes `rest` as `unparsed` unless it is empty.
pub(crate) fn push_unparsed<'pkt>(buf: &mut DissectBuffer<'pkt>, rest: &'pkt [u8], o: usize) {
    if !rest.is_empty() {
        buf.push_field(&FD_UNPARSED, FieldValue::Bytes(rest), o..o + rest.len());
    }
}

// ---------------------------------------------------------------------------
// Small push helpers
// ---------------------------------------------------------------------------

/// Pushes the octet at `at` as a `U8`.
pub(crate) fn push_u8_at(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    v: &[u8],
    at: usize,
    o: usize,
) {
    buf.push_field(d, FieldValue::U8(v[at]), o + at..o + at + 1);
}

/// Pushes the 16-bit value at `at` as a `U16`.
pub(crate) fn push_u16_at(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    v: &[u8],
    at: usize,
    o: usize,
) {
    let x = read_be_u16(v, at).unwrap_or_default();
    buf.push_field(d, FieldValue::U16(x), o + at..o + at + 2);
}

/// Pushes the 24-bit value at `at` as a `U32`.
pub(crate) fn push_u24_at(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    v: &[u8],
    at: usize,
    o: usize,
) {
    let x = read_be_u24(v, at).unwrap_or_default();
    buf.push_field(d, FieldValue::U32(x), o + at..o + at + 3);
}

/// Pushes the 32-bit value at `at` as a `U32`.
pub(crate) fn push_u32_at(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    v: &[u8],
    at: usize,
    o: usize,
) {
    let x = read_be_u32(v, at).unwrap_or_default();
    buf.push_field(d, FieldValue::U32(x), o + at..o + at + 4);
}

/// Pushes the four octets at `at` as an `Ipv4Addr`.
pub(crate) fn push_ipv4_at(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    v: &[u8],
    at: usize,
    o: usize,
) {
    let x = read_ipv4_addr(v, at).unwrap_or_default();
    buf.push_field(d, FieldValue::Ipv4Addr(x), o + at..o + at + 4);
}

/// Pushes `len` (at most 16) octets at `at` as a zero-padded `Ipv6Addr`.
pub(crate) fn push_ipv6_at(
    buf: &mut DissectBuffer<'_>,
    d: &'static FieldDescriptor,
    v: &[u8],
    at: usize,
    len: usize,
    o: usize,
) {
    let x = prefix_to_ipv6(&v[at..at + len]);
    buf.push_field(d, FieldValue::Ipv6Addr(x), o + at..o + at + len);
}

/// Shrinks the byte range of the container at `idx` to end at `end`, so
/// that it covers only the entries that were decoded.
pub(crate) fn set_range_end(buf: &mut DissectBuffer<'_>, idx: u32, end: usize) {
    if let Some(field) = buf.field_mut(idx as usize) {
        field.range.end = end;
    }
}

fn push_u8(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_u8_at(buf, &TLV_FIELDS[f], v, at, o);
}

fn push_u16(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_u16_at(buf, &TLV_FIELDS[f], v, at, o);
}

fn push_u24(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_u24_at(buf, &TLV_FIELDS[f], v, at, o);
}

fn push_u32(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_u32_at(buf, &TLV_FIELDS[f], v, at, o);
}

fn push_ipv4(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_ipv4_at(buf, &TLV_FIELDS[f], v, at, o);
}

fn push_ipv6(buf: &mut DissectBuffer<'_>, f: usize, v: &[u8], at: usize, o: usize) {
    push_ipv6_at(buf, &TLV_FIELDS[f], v, at, 16, o);
}

/// Pushes an array of consecutive fixed-size elements (1-octet `U8`, or
/// 4-octet `Ipv4Addr` / `U32` according to the element's type).
fn push_array<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array: usize,
    element: &'static FieldDescriptor,
    v: &'pkt [u8],
    size: usize,
    o: usize,
) -> usize {
    let n = v.len() / size * size;
    let idx = buf.begin_container(&TLV_FIELDS[array], FieldValue::Array(0..0), o..o + n);
    for at in (0..n).step_by(size) {
        match (size, element.field_type) {
            (1, _) => push_u8_at(buf, element, v, at, o),
            (_, FieldType::Ipv4Addr) => push_ipv4_at(buf, element, v, at, o),
            _ => push_u32_at(buf, element, v, at, o),
        }
    }
    buf.end_container(idx);
    n
}

/// Pushes a SID/Label/Index field starting at `at`.
///
/// RFC 8665, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8665#section-2.1>
/// "If the length is set to 3, then the 20 rightmost bits represent a
/// label. If the length is set to 4, then the value represents a 32-bit
/// SID."
fn push_sid(buf: &mut DissectBuffer<'_>, v: &[u8], at: usize, o: usize) -> Option<usize> {
    match v.len().checked_sub(at)? {
        0..=2 => None,
        3 => {
            let label = read_be_u24(v, at).ok()? & 0x000F_FFFF;
            buf.push_field(
                &TLV_FIELDS[F_SID],
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

/// Pushes an OSPFv3 address prefix of `prefix_length` bits at `at`.
///
/// RFC 5340, Appendix A.4.1 — <https://www.rfc-editor.org/rfc/rfc5340#appendix-A.4.1>
fn push_v3_prefix(
    buf: &mut DissectBuffer<'_>,
    f: usize,
    prefix_length: u8,
    v: &[u8],
    at: usize,
    o: usize,
) -> Option<usize> {
    let n = prefix_octets(prefix_length)?;
    let bytes = v.get(at..at + n)?;
    buf.push_field(
        &TLV_FIELDS[f],
        FieldValue::Ipv6Addr(prefix_to_ipv6(bytes)),
        o + at..o + at + n,
    );
    Some(at + n)
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

/// RFC 3630, Section 2.4 — <https://www.rfc-editor.org/rfc/rfc3630#section-2.4>
fn decode_te<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // Router Address TLV — RFC 3630, Section 2.4.1
        // <https://www.rfc-editor.org/rfc/rfc3630#section-2.4.1>
        1 if v.len() >= 4 => {
            push_ipv4(buf, F_ROUTER_ADDRESS, v, 0, o);
            Some(4)
        }
        // Link TLV — RFC 3630, Section 2.4.2
        // <https://www.rfc-editor.org/rfc/rfc3630#section-2.4.2>
        2 => {
            push_sub_tlvs(buf, v, o, TlvContext::TeLink);
            Some(v.len())
        }
        _ => None,
    }
}

/// RFC 3630, Section 2.5 — <https://www.rfc-editor.org/rfc/rfc3630#section-2.5>
fn decode_te_link<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        1 if !v.is_empty() => {
            push_u8(buf, F_LINK_TYPE, v, 0, o);
            Some(1)
        }
        2 if v.len() >= 4 => {
            push_ipv4(buf, F_LINK_ID, v, 0, o);
            Some(4)
        }
        3 if v.len() >= 4 => Some(push_array(buf, F_LOCAL_ADDRESSES, &FD_ADDRESS, v, 4, o)),
        4 if v.len() >= 4 => Some(push_array(buf, F_REMOTE_ADDRESSES, &FD_ADDRESS, v, 4, o)),
        5 if v.len() >= 4 => {
            push_u32(buf, F_TE_METRIC, v, 0, o);
            Some(4)
        }
        6 if v.len() >= 4 => {
            push_u32(buf, F_MAX_BANDWIDTH, v, 0, o);
            Some(4)
        }
        7 if v.len() >= 4 => {
            push_u32(buf, F_MAX_RESERVABLE_BANDWIDTH, v, 0, o);
            Some(4)
        }
        // RFC 3630, Section 2.5.8: "is 32 octets in length"
        // <https://www.rfc-editor.org/rfc/rfc3630#section-2.5.8>
        8 if v.len() >= 32 => Some(push_array(
            buf,
            F_UNRESERVED_BANDWIDTH,
            &FD_BANDWIDTH,
            &v[..32],
            4,
            o,
        )),
        9 if v.len() >= 4 => {
            push_u32(buf, F_ADMIN_GROUP, v, 0, o);
            Some(4)
        }
        _ => None,
    }
}

/// RFC 7770, Sections 2.4 and 2.6; RFC 8665, Section 3; RFC 5642, Section 3.1;
/// RFC 9513, Section 2.
/// <https://www.rfc-editor.org/rfc/rfc7770#section-2.4>
/// <https://www.rfc-editor.org/rfc/rfc8665#section-3>
/// <https://www.rfc-editor.org/rfc/rfc5642#section-3.1>
/// <https://www.rfc-editor.org/rfc/rfc9513#section-2>
fn decode_router_info<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // Router Informational Capabilities — RFC 7770, Section 2.4
        // <https://www.rfc-editor.org/rfc/rfc7770#section-2.4>
        1 if v.len() >= 4 => {
            push_u32(buf, F_INFORMATIONAL_CAPABILITIES, v, 0, o);
            Some(4)
        }
        // Router Functional Capabilities — RFC 7770, Section 2.6
        // <https://www.rfc-editor.org/rfc/rfc7770#section-2.6>
        2 if v.len() >= 4 => {
            push_u32(buf, F_FUNCTIONAL_CAPABILITIES, v, 0, o);
            Some(4)
        }
        // Dynamic Hostname — RFC 5642, Section 3.1
        // <https://www.rfc-editor.org/rfc/rfc5642#section-3.1>
        7 => {
            buf.push_field(
                &TLV_FIELDS[F_HOSTNAME],
                FieldValue::Bytes(v),
                o..o + v.len(),
            );
            Some(v.len())
        }
        // SR-Algorithm — RFC 8665, Section 3.1
        // <https://www.rfc-editor.org/rfc/rfc8665#section-3.1>
        8 => Some(push_array(buf, F_ALGORITHMS, &FD_ALGORITHM, v, 1, o)),
        // SID/Label Range (9) and SR Local Block (14) — RFC 8665, Sections 3.2-3.3
        // <https://www.rfc-editor.org/rfc/rfc8665#section-3.2>
        9 | 14 if v.len() >= 4 => {
            push_u24(buf, F_RANGE_SIZE, v, 0, o);
            push_sub_tlvs(buf, &v[4..], o + 4, TlvContext::SidLabelRange);
            Some(v.len())
        }
        // SRMS Preference — RFC 8665, Section 3.4
        // <https://www.rfc-editor.org/rfc/rfc8665#section-3.4>
        15 if !v.is_empty() => {
            push_u8(buf, F_PREFERENCE, v, 0, o);
            Some(v.len().min(4))
        }
        // SRv6 Capabilities — RFC 9513, Section 2
        // <https://www.rfc-editor.org/rfc/rfc9513#section-2>
        20 if v.len() >= 4 => {
            push_u16(buf, F_FLAGS, v, 0, o);
            push_sub_tlvs(buf, &v[4..], o + 4, TlvContext::Opaque);
            Some(v.len())
        }
        _ => None,
    }
}

/// RFC 7684, Section 2.1 and RFC 8665, Section 4.
/// <https://www.rfc-editor.org/rfc/rfc7684#section-2.1>
/// <https://www.rfc-editor.org/rfc/rfc8665#section-4>
fn decode_ext_prefix<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // OSPFv2 Extended Prefix TLV — RFC 7684, Section 2.1
        // <https://www.rfc-editor.org/rfc/rfc7684#section-2.1>
        // "For the address family IPv4 unicast, the prefix itself is encoded
        // as a 32-bit value."
        1 if v.len() >= 8 => {
            push_u8(buf, F_ROUTE_TYPE, v, 0, o);
            push_u8(buf, F_PREFIX_LENGTH, v, 1, o);
            push_u8(buf, F_ADDRESS_FAMILY, v, 2, o);
            push_u8(buf, F_FLAGS, v, 3, o);
            push_ipv4(buf, F_PREFIX, v, 4, o);
            push_sub_tlvs(buf, &v[8..], o + 8, TlvContext::ExtPrefixSub);
            Some(v.len())
        }
        // OSPF Extended Prefix Range TLV — RFC 8665, Section 4
        // <https://www.rfc-editor.org/rfc/rfc8665#section-4>
        2 if v.len() >= 12 => {
            push_u8(buf, F_PREFIX_LENGTH, v, 0, o);
            push_u8(buf, F_ADDRESS_FAMILY, v, 1, o);
            let range_size = u32::from(read_be_u16(v, 2).unwrap_or_default());
            buf.push_field(
                &TLV_FIELDS[F_RANGE_SIZE],
                FieldValue::U32(range_size),
                o + 2..o + 4,
            );
            push_u8(buf, F_FLAGS, v, 4, o);
            push_ipv4(buf, F_PREFIX, v, 8, o);
            push_sub_tlvs(buf, &v[12..], o + 12, TlvContext::ExtPrefixSub);
            Some(v.len())
        }
        _ => None,
    }
}

/// RFC 8665, Sections 2.1 and 5.
/// <https://www.rfc-editor.org/rfc/rfc8665#section-2.1>
fn decode_ext_prefix_sub<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        1 => push_sid(buf, v, 0, o),
        // Prefix-SID — RFC 8665, Section 5
        // <https://www.rfc-editor.org/rfc/rfc8665#section-5>
        // Flags | Reserved | MT-ID | Algorithm | SID/Index/Label
        2 if v.len() >= 7 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_MT_ID, v, 2, o);
            push_u8(buf, F_ALGORITHM, v, 3, o);
            push_sid(buf, v, 4, o)
        }
        _ => None,
    }
}

/// RFC 7684, Section 3.1.
/// <https://www.rfc-editor.org/rfc/rfc7684#section-3.1>
fn decode_ext_link<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // OSPFv2 Extended Link TLV — RFC 7684, Section 3.1
        // <https://www.rfc-editor.org/rfc/rfc7684#section-3.1>
        1 if v.len() >= 12 => {
            push_u8(buf, F_LINK_TYPE, v, 0, o);
            push_ipv4(buf, F_LINK_ID, v, 4, o);
            push_ipv4(buf, F_LINK_DATA, v, 8, o);
            push_sub_tlvs(buf, &v[12..], o + 12, TlvContext::ExtLinkSub);
            Some(v.len())
        }
        _ => None,
    }
}

/// RFC 8665, Sections 2.1 and 6.
/// <https://www.rfc-editor.org/rfc/rfc8665#section-2.1>
fn decode_ext_link_sub<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        1 => push_sid(buf, v, 0, o),
        // Adj-SID — RFC 8665, Section 6.1
        // <https://www.rfc-editor.org/rfc/rfc8665#section-6.1>
        // Flags | Reserved | MT-ID | Weight | SID/Label/Index
        2 if v.len() >= 7 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_MT_ID, v, 2, o);
            push_u8(buf, F_WEIGHT, v, 3, o);
            push_sid(buf, v, 4, o)
        }
        // LAN Adj-SID — RFC 8665, Section 6.2
        // <https://www.rfc-editor.org/rfc/rfc8665#section-6.2>
        3 if v.len() >= 11 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_MT_ID, v, 2, o);
            push_u8(buf, F_WEIGHT, v, 3, o);
            push_ipv4(buf, F_NEIGHBOR_ID, v, 4, o);
            push_sid(buf, v, 8, o)
        }
        _ => None,
    }
}

/// Pushes `metric` (24 bits at 1), `prefix_length`, `prefix_options`, the
/// address prefix at 8, and the sub-TLVs that follow it.
///
/// RFC 8362, Sections 3.4, 3.6 and 3.7 — <https://www.rfc-editor.org/rfc/rfc8362#section-3.4>
fn decode_v3_prefix_tlv<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    if v.len() < 8 {
        return None;
    }
    let n = prefix_octets(v[4])?;
    if v.len() < 8 + n {
        return None;
    }
    push_u24(buf, F_METRIC, v, 1, o);
    push_u8(buf, F_PREFIX_LENGTH, v, 4, o);
    push_u8(buf, F_PREFIX_OPTIONS, v, 5, o);
    let end = push_v3_prefix(buf, F_PREFIX, v[4], v, 8, o)?;
    push_sub_tlvs(buf, &v[end..], o + end, TlvContext::V3ExtLsaSub);
    Some(v.len())
}

/// RFC 8362, Section 3.
/// <https://www.rfc-editor.org/rfc/rfc8362#section-3>
fn decode_v3_ext_lsa<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // Router-Link TLV — RFC 8362, Section 3.2
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.2>
        1 if v.len() >= 16 => {
            push_u8(buf, F_LINK_TYPE, v, 0, o);
            let metric = u32::from(read_be_u16(v, 2).unwrap_or_default());
            buf.push_field(&TLV_FIELDS[F_METRIC], FieldValue::U32(metric), o + 2..o + 4);
            push_u32(buf, F_INTERFACE_ID, v, 4, o);
            push_u32(buf, F_NEIGHBOR_INTERFACE_ID, v, 8, o);
            push_ipv4(buf, F_NEIGHBOR_ROUTER_ID, v, 12, o);
            push_sub_tlvs(buf, &v[16..], o + 16, TlvContext::V3ExtLsaSub);
            Some(v.len())
        }
        // Attached-Routers TLV — RFC 8362, Section 3.3
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.3>
        2 if v.len() >= 4 => Some(push_array(
            buf,
            F_ATTACHED_ROUTERS,
            &FD_ATTACHED_ROUTER,
            v,
            4,
            o,
        )),
        // Inter-Area-Prefix (3) and Intra-Area-Prefix (6) TLVs —
        // RFC 8362, Sections 3.4 and 3.7
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.4>
        3 | 6 => decode_v3_prefix_tlv(buf, v, o),
        // Inter-Area-Router TLV — RFC 8362, Section 3.5
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.5>
        4 if v.len() >= 12 => {
            push_u24(buf, F_OPTIONS, v, 1, o);
            push_u24(buf, F_METRIC, v, 5, o);
            push_ipv4(buf, F_DESTINATION_ROUTER_ID, v, 8, o);
            push_sub_tlvs(buf, &v[12..], o + 12, TlvContext::V3ExtLsaSub);
            Some(v.len())
        }
        // External-Prefix TLV — RFC 8362, Section 3.6
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.6>
        5 if v.len() >= 8 => {
            // Validate before pushing so a bad prefix length leaves no fields.
            let n = prefix_octets(v[4])?;
            if v.len() < 8 + n {
                return None;
            }
            push_u8(buf, F_FLAGS, v, 0, o);
            buf.push_field(
                &TLV_FIELDS[F_FLAG_E],
                FieldValue::U8((v[0] >> 2) & 1),
                o..o + 1,
            );
            decode_v3_prefix_tlv(buf, v, o)
        }
        // IPv6 Link-Local Address TLV — RFC 8362, Section 3.8
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.8>
        7 if v.len() >= 16 => {
            push_ipv6(buf, F_LINK_LOCAL_ADDRESS, v, 0, o);
            push_sub_tlvs(buf, &v[16..], o + 16, TlvContext::V3ExtLsaSub);
            Some(v.len())
        }
        // IPv4 Link-Local Address TLV — RFC 8362, Section 3.9
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.9>
        8 if v.len() >= 4 => {
            push_ipv4(buf, F_IPV4_LINK_LOCAL_ADDRESS, v, 0, o);
            push_sub_tlvs(buf, &v[4..], o + 4, TlvContext::V3ExtLsaSub);
            Some(v.len())
        }
        _ => None,
    }
}

/// SRv6 End.X (31) and LAN End.X (32) SID sub-TLVs.
///
/// RFC 9513, Sections 9.1-9.2 — <https://www.rfc-editor.org/rfc/rfc9513#section-9.1>
fn decode_srv6_end_x<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    lan: bool,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    let sid_at = if lan { 12 } else { 8 };
    if v.len() < sid_at + 16 {
        return None;
    }
    push_u16(buf, F_ENDPOINT_BEHAVIOR, v, 0, o);
    push_u8(buf, F_FLAGS, v, 2, o);
    push_u8(buf, F_ALGORITHM, v, 4, o);
    push_u8(buf, F_WEIGHT, v, 5, o);
    if lan {
        push_ipv4(buf, F_NEIGHBOR_ID, v, 8, o);
    }
    push_ipv6(buf, F_SRV6_SID, v, sid_at, o);
    let end = sid_at + 16;
    push_sub_tlvs(buf, &v[end..], o + end, TlvContext::V3ExtLsaSub);
    Some(v.len())
}

/// RFC 8362, Sections 3.10-3.12; RFC 8666, Sections 3.1, 6, 7; RFC 9513, Section 9.
/// <https://www.rfc-editor.org/rfc/rfc8362#section-3.10>
/// <https://www.rfc-editor.org/rfc/rfc8666#section-3.1>
/// <https://www.rfc-editor.org/rfc/rfc9513#section-9>
fn decode_v3_ext_lsa_sub<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // IPv6-Forwarding-Address — RFC 8362, Section 3.10
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.10>
        1 if v.len() >= 16 => {
            push_ipv6(buf, F_FORWARDING_ADDRESS, v, 0, o);
            Some(16)
        }
        // IPv4-Forwarding-Address — RFC 8362, Section 3.11
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.11>
        2 if v.len() >= 4 => {
            push_ipv4(buf, F_IPV4_FORWARDING_ADDRESS, v, 0, o);
            Some(4)
        }
        // Route-Tag — RFC 8362, Section 3.12
        // <https://www.rfc-editor.org/rfc/rfc8362#section-3.12>
        3 if v.len() >= 4 => {
            push_u32(buf, F_ROUTE_TAG, v, 0, o);
            Some(4)
        }
        // Prefix-SID — RFC 8666, Section 6
        // <https://www.rfc-editor.org/rfc/rfc8666#section-6>
        // Flags | Algorithm | Reserved (2) | SID/Index/Label
        4 if v.len() >= 7 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_ALGORITHM, v, 1, o);
            push_sid(buf, v, 4, o)
        }
        // Adj-SID — RFC 8666, Section 7.1
        // <https://www.rfc-editor.org/rfc/rfc8666#section-7.1>
        // Flags | Weight | Reserved (2) | SID/Label/Index
        5 if v.len() >= 7 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_WEIGHT, v, 1, o);
            push_sid(buf, v, 4, o)
        }
        // LAN Adj-SID — RFC 8666, Section 7.2
        // <https://www.rfc-editor.org/rfc/rfc8666#section-7.2>
        6 if v.len() >= 11 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u8(buf, F_WEIGHT, v, 1, o);
            push_ipv4(buf, F_NEIGHBOR_ID, v, 4, o);
            push_sid(buf, v, 8, o)
        }
        // SID/Label — RFC 8666, Section 3.1
        // <https://www.rfc-editor.org/rfc/rfc8666#section-3.1>
        7 => push_sid(buf, v, 0, o),
        31 => decode_srv6_end_x(buf, false, v, o),
        32 => decode_srv6_end_x(buf, true, v, o),
        _ => None,
    }
}

/// RFC 9513, Section 7.1.
/// <https://www.rfc-editor.org/rfc/rfc9513#section-7.1>
fn decode_srv6_locator<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // SRv6 Locator TLV — RFC 9513, Section 7.1
        // <https://www.rfc-editor.org/rfc/rfc9513#section-7.1>
        1 if v.len() >= 8 => {
            let n = prefix_octets(v[2])?;
            if v.len() < 8 + n {
                return None;
            }
            push_u8(buf, F_ROUTE_TYPE, v, 0, o);
            push_u8(buf, F_ALGORITHM, v, 1, o);
            push_u8(buf, F_PREFIX_LENGTH, v, 2, o);
            push_u8(buf, F_PREFIX_OPTIONS, v, 3, o);
            push_u32(buf, F_METRIC, v, 4, o);
            let end = push_v3_prefix(buf, F_LOCATOR, v[2], v, 8, o)?;
            push_sub_tlvs(buf, &v[end..], o + end, TlvContext::Srv6LocatorSub);
            Some(v.len())
        }
        _ => None,
    }
}

/// RFC 9513, Sections 7.2 and 8.
/// <https://www.rfc-editor.org/rfc/rfc9513#section-7.2>
fn decode_srv6_locator_sub<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // SRv6 End SID — RFC 9513, Section 8
        // <https://www.rfc-editor.org/rfc/rfc9513#section-8>
        // Flags | Reserved | Endpoint Behavior | SID (128 bits)
        1 if v.len() >= 20 => {
            push_u8(buf, F_FLAGS, v, 0, o);
            push_u16(buf, F_ENDPOINT_BEHAVIOR, v, 2, o);
            push_ipv6(buf, F_SRV6_SID, v, 4, o);
            push_sub_tlvs(buf, &v[20..], o + 20, TlvContext::Srv6LocatorSub);
            Some(v.len())
        }
        // IPv6-Forwarding-Address and Route-Tag — RFC 9513, Section 7.2
        // <https://www.rfc-editor.org/rfc/rfc9513#section-7.2>
        2 if v.len() >= 16 => {
            push_ipv6(buf, F_FORWARDING_ADDRESS, v, 0, o);
            Some(16)
        }
        3 if v.len() >= 4 => {
            push_u32(buf, F_ROUTE_TAG, v, 0, o);
            Some(4)
        }
        _ => None,
    }
}

/// RFC 5613, Sections 2.4-2.5.
/// <https://www.rfc-editor.org/rfc/rfc5613#section-2.4>
fn decode_lls<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    v: &'pkt [u8],
    o: usize,
) -> Option<usize> {
    match t {
        // Extended Options and Flags TLV — RFC 5613, Section 2.4
        // <https://www.rfc-editor.org/rfc/rfc5613#section-2.4>
        1 if v.len() >= 4 => {
            push_u32(buf, F_EXTENDED_OPTIONS, v, 0, o);
            Some(4)
        }
        // Cryptographic Authentication TLV — RFC 5613, Section 2.5
        // <https://www.rfc-editor.org/rfc/rfc5613#section-2.5>
        2 if v.len() >= 4 => {
            push_u32(buf, F_SEQUENCE_NUMBER, v, 0, o);
            let data = &v[4..];
            buf.push_field(
                &TLV_FIELDS[F_AUTH_DATA],
                FieldValue::Bytes(data),
                o + 4..o + v.len(),
            );
            Some(v.len())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # TLV decoding coverage
    //
    // | RFC Section         | Description                       | Test                           |
    // |---------------------|-----------------------------------|--------------------------------|
    // | RFC 5340 A.4.1      | Address prefix length             | prefix_octets_rounds_to_words  |
    // | RFC 3630 2.5.6      | IEEE float bandwidth formatting   | ieee_float_formats_as_number   |
    // | RFC 8665 2.1        | SID/Label 3- or 4-octet encodings | sid_label_lengths              |

    #[test]
    fn prefix_octets_rounds_to_words() {
        assert_eq!(prefix_octets(0), Some(0));
        assert_eq!(prefix_octets(1), Some(4));
        assert_eq!(prefix_octets(64), Some(8));
        assert_eq!(prefix_octets(65), Some(12));
        assert_eq!(prefix_octets(128), Some(16));
        assert_eq!(prefix_octets(129), None);
    }

    #[test]
    fn ieee_float_formats_as_number() {
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
        format_ieee_float(&FieldValue::U32(f32::NAN.to_bits()), &ctx, &mut out).unwrap();
        assert_eq!(out, b"null");
        out.clear();
        format_ieee_float(&FieldValue::U8(0), &ctx, &mut out).unwrap();
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

    /// Every IANA name table entry is reachable and unknown codes have none.
    #[test]
    fn name_tables_cover_registries() {
        let count =
            |f: fn(u16) -> Option<&'static str>| (0..=u16::MAX).filter(|t| f(*t).is_some()).count();
        assert_eq!(count(te_tlv_name), 6);
        assert_eq!(count(te_link_sub_tlv_name), 29);
        assert_eq!(count(ri_tlv_name), 20);
        assert_eq!(count(sid_label_sub_tlv_name), 1);
        assert_eq!(count(no_name), 0);
        assert_eq!(count(ext_prefix_tlv_name), 2);
        assert_eq!(count(ext_prefix_sub_tlv_name), 12);
        assert_eq!(count(ext_link_tlv_name), 1);
        assert_eq!(count(ext_link_sub_tlv_name), 25);
        assert_eq!(count(v3_ext_lsa_tlv_name), 9);
        assert_eq!(count(v3_ext_lsa_sub_tlv_name), 39);
        assert_eq!(count(srv6_locator_tlv_name), 1);
        assert_eq!(count(srv6_locator_sub_tlv_name), 7);
        assert_eq!(count(lls_tlv_name), 2);
    }

    const ALL_CONTEXTS: [TlvContext; 14] = [
        TlvContext::Te,
        TlvContext::TeLink,
        TlvContext::RouterInfo,
        TlvContext::SidLabelRange,
        TlvContext::Opaque,
        TlvContext::ExtPrefix,
        TlvContext::ExtPrefixSub,
        TlvContext::ExtLink,
        TlvContext::ExtLinkSub,
        TlvContext::V3ExtLsa,
        TlvContext::V3ExtLsaSub,
        TlvContext::Srv6Locator,
        TlvContext::Srv6LocatorSub,
        TlvContext::Lls,
    ];

    /// Type display functions ignore non-`U16` values, and containers that
    /// are not objects have no label.
    #[test]
    fn display_fns_ignore_other_values() {
        for ctx in ALL_CONTEXTS {
            let d = ctx.type_descriptor();
            assert_eq!((d.display_fn.unwrap())(&FieldValue::U8(1), &[]), None);
        }
        assert_eq!(tlv_container_name(&FieldValue::U8(0), &[]), None);
    }

    /// The schema builder yields the documented field order.
    #[test]
    fn schema_builder_layout() {
        let fields = tlv_fields(UNPARSED_DESCRIPTOR);
        assert_eq!(fields[F_LENGTH].name, "length");
        assert_eq!(fields[F_VALUE].name, "value");
        assert_eq!(fields[F_AUTH_DATA].name, "auth_data");
        assert_eq!(TLV_FIELDS.len(), TLV_FIELD_COUNT);
    }

    fn named<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> usize {
        buf.fields().iter().filter(|f| f.name() == name).count()
    }

    fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
        let mut out = t.to_be_bytes().to_vec();
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    /// Unknown types and values shorter than their fixed part stay raw in
    /// every context.
    #[test]
    fn unknown_and_short_values_are_raw() {
        for ctx in ALL_CONTEXTS {
            let mut buf = DissectBuffer::new();
            let data = tlv(0x7fff, &[1, 2, 3]);
            push_tlvs(&mut buf, &data, 0, ctx);
            assert_eq!(named(&buf, "value"), 1, "{ctx:?}");
        }
        // Short / malformed fixed parts.
        let cases: [(TlvContext, Vec<u8>); 9] = [
            (TlvContext::V3ExtLsa, tlv(3, &[0, 0, 0, 1])),
            (TlvContext::V3ExtLsa, tlv(3, &[0, 0, 0, 1, 64, 0, 0, 0])),
            (TlvContext::V3ExtLsa, tlv(5, &[0, 0, 0, 1, 64, 0, 0, 0])),
            (TlvContext::V3ExtLsa, tlv(1, &[0; 8])),
            (TlvContext::V3ExtLsaSub, tlv(31, &[0; 8])),
            (TlvContext::V3ExtLsaSub, tlv(32, &[0; 20])),
            (TlvContext::Srv6Locator, tlv(1, &[1, 0, 64, 0, 0, 0, 0, 1])),
            (TlvContext::Srv6Locator, tlv(1, &[1, 0, 200, 0, 0, 0, 0, 1])),
            (TlvContext::ExtPrefix, tlv(2, &[0; 8])),
        ];
        for (ctx, data) in cases {
            let mut buf = DissectBuffer::new();
            push_tlvs(&mut buf, &data, 0, ctx);
            assert_eq!(named(&buf, "value"), 1, "{ctx:?} {data:?}");
        }
    }

    /// Functional Capabilities (RFC 7770, Section 2.6), a SID/Label sub-TLV
    /// of an Extended Prefix TLV (RFC 8665, Section 2.1) and a sub-TLV of the
    /// SRv6 Capabilities TLV (no registered types, RFC 9513, Section 2).
    /// <https://www.rfc-editor.org/rfc/rfc7770#section-2.6>
    /// <https://www.rfc-editor.org/rfc/rfc8665#section-2.1>
    /// <https://www.rfc-editor.org/rfc/rfc9513#section-2>
    #[test]
    fn decode_remaining_tlvs() {
        let mut data = tlv(2, &[0x80, 0, 0, 0]);
        let mut caps = vec![0, 0, 0, 0];
        caps.extend(tlv(1, &[9]));
        data.extend(tlv(20, &caps));
        let mut buf = DissectBuffer::new();
        push_tlvs(&mut buf, &data, 0, TlvContext::RouterInfo);
        assert_eq!(named(&buf, "functional_capabilities"), 1);
        assert_eq!(named(&buf, "value"), 1);

        let mut prefix = vec![1, 32, 0, 0, 10, 0, 0, 1];
        prefix.extend(tlv(1, &[0, 0, 0, 5]));
        let data = tlv(1, &prefix);
        let mut buf = DissectBuffer::new();
        push_tlvs(&mut buf, &data, 0, TlvContext::ExtPrefix);
        assert_eq!(named(&buf, "sid"), 1);
    }
}
