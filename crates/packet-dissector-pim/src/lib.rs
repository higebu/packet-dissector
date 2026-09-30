//! PIM (Protocol Independent Multicast) version 2 dissector.
//!
//! Decodes the PIMv2 messages of PIM Sparse Mode, Dense Mode and the
//! Bootstrap Router mechanism: Hello, Register, Register-Stop, Join/Prune,
//! Bootstrap, Assert, Graft, Graft-Ack, Candidate-RP-Advertisement and State
//! Refresh. The multicast data packet of a Register is handed to the IPv4 or
//! IPv6 dissector. Other message types keep their body as raw bytes.
//!
//! PIM messages are carried directly in IP with protocol number 103.
//!
//! ## References
//! - RFC 7761 (PIM-SM): <https://www.rfc-editor.org/rfc/rfc7761>
//! - RFC 3973 (PIM-DM): <https://www.rfc-editor.org/rfc/rfc3973>
//! - RFC 5059 (Bootstrap Router Mechanism for PIM): <https://www.rfc-editor.org/rfc/rfc5059>
//! - RFC 5384 (PIM Join Attribute Format): <https://www.rfc-editor.org/rfc/rfc5384>
//! - RFC 9436 (PIM Message Type Space Extension and Reserved Bits): <https://www.rfc-editor.org/rfc/rfc9436>
//! - IANA PIM Parameters: <https://www.iana.org/assignments/pim-parameters/pim-parameters.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// PIM common header size: PIM Ver / Type (1), Flag Bits (1), Checksum (2).
/// RFC 7761, Section 4.9 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9>
const HEADER_SIZE: usize = 4;

/// "PIM Version number is 2." RFC 7761, Section 4.9 —
/// <https://www.rfc-editor.org/rfc/rfc7761#section-4.9>
const VERSION_2: u8 = 2;

/// Message types. RFC 7761, Section 4.9 —
/// <https://www.rfc-editor.org/rfc/rfc7761#section-4.9>; RFC 3973,
/// Section 4.7.1 — <https://www.rfc-editor.org/rfc/rfc3973#section-4.7.1>
const TYPE_HELLO: u8 = 0;
const TYPE_REGISTER: u8 = 1;
const TYPE_REGISTER_STOP: u8 = 2;
const TYPE_JOIN_PRUNE: u8 = 3;
const TYPE_BOOTSTRAP: u8 = 4;
const TYPE_ASSERT: u8 = 5;
const TYPE_GRAFT: u8 = 6;
const TYPE_GRAFT_ACK: u8 = 7;
const TYPE_CANDIDATE_RP_ADV: u8 = 8;
const TYPE_STATE_REFRESH: u8 = 9;
const TYPE_DF_ELECTION: u8 = 10;
const TYPE_PFM: u8 = 12;

/// Hello option types. RFC 7761, Section 4.9.2 —
/// <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.2>; RFC 3973,
/// Section 4.7.5.4 — <https://www.rfc-editor.org/rfc/rfc3973#section-4.7.5.4>
const OPTION_HOLDTIME: u16 = 1;
const OPTION_LAN_PRUNE_DELAY: u16 = 2;
const OPTION_DR_PRIORITY: u16 = 19;
const OPTION_GENERATION_ID: u16 = 20;
const OPTION_STATE_REFRESH: u16 = 21;
const OPTION_ADDRESS_LIST: u16 = 24;

/// Address families of encoded addresses: IANA Address Family Numbers
/// (RFC 7761, Section 4.9.1 —
/// <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.1>).
const AF_IPV4: u8 = 1;
const AF_IPV6: u8 = 2;

/// Encoding types: 0 is the native encoding (RFC 7761, Section 4.9.1 —
/// <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.1>), 1 the native
/// encoding followed by Join Attributes (RFC 5384, Section 3.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5384#section-3.4.1>).
const ENCODING_NATIVE: u8 = 0;
const ENCODING_JOIN_ATTRIBUTES: u8 = 1;

/// Returns the name of a PIM message type.
///
/// IANA PIM Message Types —
/// <https://www.iana.org/assignments/pim-parameters/pim-parameters.xhtml#message-types>
fn message_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Hello"),
        1 => Some("Register"),
        2 => Some("Register-Stop"),
        3 => Some("Join/Prune"),
        4 => Some("Bootstrap"),
        5 => Some("Assert"),
        6 => Some("Graft"),
        7 => Some("Graft-Ack"),
        8 => Some("Candidate-RP-Advertisement"),
        9 => Some("State Refresh"),
        10 => Some("DF Election"),
        11 => Some("ECMP Redirect"),
        12 => Some("PIM Flooding Mechanism"),
        _ => None,
    }
}

/// Returns the name of an extended message type (`type.subtype`).
///
/// RFC 9436, Section 5 — <https://www.rfc-editor.org/rfc/rfc9436#section-5>;
/// IANA PIM Message Types.
fn extended_type_name(t: u8, subtype: u8) -> Option<&'static str> {
    match (t, subtype) {
        (13, 0) => Some("PIM Packed Null-Register"),
        (13, 1) => Some("PIM Packed Register-Stop"),
        (15, 15) => Some("Reserved"),
        _ => None,
    }
}

/// Returns the name of a Hello option type.
///
/// IANA PIM-Hello Options —
/// <https://www.iana.org/assignments/pim-parameters/pim-parameters.xhtml#pim-parameters-1>
fn hello_option_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Hold Time"),
        2 => Some("LAN Prune Delay"),
        17 => Some("Label Parameters"),
        18 => Some("Deprecated"),
        19 => Some("DR Priority"),
        20 => Some("Generation ID"),
        21 => Some("State-Refresh"),
        22 => Some("Bidirectional Capable"),
        23 => Some("VCI Capability"),
        24 => Some("Address List"),
        25 => Some("Neighbor List TLV"),
        26 => Some("Join Attribute"),
        27 => Some("PIM-over-TCP-Capable"),
        28 => Some("PIM-over-SCTP-Capable"),
        29 => Some("Pop-Count"),
        30 => Some("PIM MT-ID"),
        31 => Some("Interface ID"),
        32 => Some("PIM ECMP Redirect Hello Option"),
        33 => Some("vPC Peer ID"),
        34 => Some("DR Load-Balancing Capability (DRLB-Cap)"),
        35 => Some("DR Load-Balancing List (DRLB-List)"),
        36 => Some("Hierarchical Join/Prune Attribute"),
        37 => Some("DR Address Option"),
        38 => Some("BDR Address Option"),
        39 => Some("BFD Discriminator Option"),
        40 => Some("Packed Assert Capability"),
        41 => Some("GSI TLV support"),
        42 => Some("PFM Optimization"),
        65001..=65535 => Some("Private Use"),
        _ => None,
    }
}

/// Returns the name of a Join Attribute type.
///
/// IANA PIM Join Attribute Types —
/// <https://www.iana.org/assignments/pim-parameters/pim-parameters.xhtml#pim-parameters-2>
fn join_attribute_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("RPF Vector TLV"),
        1 => Some("MVPN Join Attribute"),
        2 => Some("MT-ID Join Attribute"),
        3 => Some("Pop-Count"),
        4 => Some("Explicit RPF Vector"),
        5 => Some("Transport Attribute"),
        6 => Some("Receiver RLOC Attribute"),
        _ => None,
    }
}

/// Returns the name of an address family of an encoded address.
///
/// IANA Address Family Numbers —
/// <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
fn address_family_name(v: u8) -> Option<&'static str> {
    match v {
        AF_IPV4 => Some("IPv4"),
        AF_IPV6 => Some("IPv6"),
        251..=255 => Some("Private Use"),
        _ => None,
    }
}

/// Descriptor of a single-bit flag.
const fn flag(name: &'static str, display: &'static str) -> FieldDescriptor {
    FieldDescriptor::new(name, display, FieldType::U8).optional()
}

/// Child field indices of an encoded address object.
const EA_ADDRESS_FAMILY: usize = 0;
const EA_ENCODING_TYPE: usize = 1;
const EA_B_BIT: usize = 2;
const EA_Z_BIT: usize = 3;
const EA_S_BIT: usize = 4;
const EA_W_BIT: usize = 5;
const EA_R_BIT: usize = 6;
const EA_MASK_LEN: usize = 7;
const EA_ADDRESS: usize = 8;
const EA_JOIN_ATTRIBUTES: usize = 9;

/// Child field indices of a Join Attribute.
const JA_F_BIT: usize = 0;
const JA_E_BIT: usize = 1;
const JA_TYPE: usize = 2;
const JA_LENGTH: usize = 3;
const JA_VALUE: usize = 4;

/// Child descriptors of a Join Attribute. RFC 5384, Section 3.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5384#section-3.4.1>
static JOIN_ATTRIBUTE_CHILDREN: [FieldDescriptor; 5] = [
    FieldDescriptor::new("f_bit", "Transitive (F)", FieldType::U8),
    FieldDescriptor::new("e_bit", "End of Attributes (E)", FieldType::U8),
    FieldDescriptor::new("type", "Attr Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => join_attribute_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static JOIN_ATTRIBUTE: FieldDescriptor =
    FieldDescriptor::new("join_attribute", "Join Attribute", FieldType::Object)
        .with_children(&JOIN_ATTRIBUTE_CHILDREN);

/// Child descriptors of an encoded address: the union of the Encoded-Unicast,
/// Encoded-Group and Encoded-Source formats.
///
/// RFC 7761, Section 4.9.1 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.1>
static ENCODED_ADDRESS_CHILDREN: [FieldDescriptor; 10] = [
    FieldDescriptor::new("address_family", "Addr Family", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(f) => address_family_name(*f),
            _ => None,
        }
    }),
    FieldDescriptor::new("encoding_type", "Encoding Type", FieldType::U8),
    flag("b_bit", "Bidirectional (B)"),
    flag("z_bit", "Admin Scope Zone (Z)"),
    flag("s_bit", "Sparse (S)"),
    flag("w_bit", "WildCard (W)"),
    flag("r_bit", "RPT (R)"),
    FieldDescriptor::new("mask_len", "Mask Len", FieldType::U8).optional(),
    // Ipv4Addr or Ipv6Addr per the address family; raw bytes otherwise.
    FieldDescriptor::new("address", "Address", FieldType::Any),
    FieldDescriptor::new("join_attributes", "Join Attributes", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&JOIN_ATTRIBUTE)),
];

/// Declares an encoded address object descriptor.
macro_rules! encoded_address {
    ($name:literal, $display:literal) => {
        FieldDescriptor::new($name, $display, FieldType::Object)
            .optional()
            .with_children(&ENCODED_ADDRESS_CHILDREN)
    };
}

/// Encoded address objects used as array elements.
static SECONDARY_ADDRESS: FieldDescriptor = encoded_address!("address", "Secondary Address");
static SOURCE_ADDRESS: FieldDescriptor = encoded_address!("source", "Source Address");
static GROUP_ADDRESS: FieldDescriptor = encoded_address!("group", "Group Address");

/// Child field indices of a Hello option.
const HO_TYPE: usize = 0;
const HO_LENGTH: usize = 1;
const HO_HOLDTIME: usize = 2;
const HO_T_BIT: usize = 3;
const HO_PROPAGATION_DELAY: usize = 4;
const HO_OVERRIDE_INTERVAL: usize = 5;
const HO_DR_PRIORITY: usize = 6;
const HO_GENERATION_ID: usize = 7;
const HO_STATE_REFRESH_VERSION: usize = 8;
const HO_STATE_REFRESH_INTERVAL: usize = 9;
const HO_ADDRESSES: usize = 10;
const HO_VALUE: usize = 11;

/// Child descriptors of a Hello option.
///
/// RFC 7761, Section 4.9.2 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.2>;
/// RFC 3973, Section 4.7.5 — <https://www.rfc-editor.org/rfc/rfc3973#section-4.7.5>
static HELLO_OPTION_CHILDREN: [FieldDescriptor; 12] = [
    FieldDescriptor::new("type", "OptionType", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => hello_option_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "OptionLength", FieldType::U16),
    FieldDescriptor::new("holdtime", "Holdtime", FieldType::U16).optional(),
    flag("t_bit", "Join Suppression Disable (T)"),
    FieldDescriptor::new("propagation_delay", "Propagation Delay", FieldType::U16).optional(),
    FieldDescriptor::new("override_interval", "Override Interval", FieldType::U16).optional(),
    FieldDescriptor::new("dr_priority", "DR Priority", FieldType::U32).optional(),
    FieldDescriptor::new("generation_id", "Generation ID", FieldType::U32).optional(),
    FieldDescriptor::new("state_refresh_version", "Version", FieldType::U8).optional(),
    FieldDescriptor::new("state_refresh_interval", "Interval", FieldType::U8).optional(),
    FieldDescriptor::new("addresses", "Secondary Addresses", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&SECONDARY_ADDRESS)),
    FieldDescriptor::new("value", "OptionValue", FieldType::Bytes).optional(),
];

static HELLO_OPTION: FieldDescriptor = FieldDescriptor::new("option", "Option", FieldType::Object)
    .with_children(&HELLO_OPTION_CHILDREN)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => hello_option_name(*t),
            _ => None,
        }),
        _ => None,
    });

/// Child field indices of a Join/Prune group set.
const GS_GROUP: usize = 0;
const GS_NUM_JOINED: usize = 1;
const GS_NUM_PRUNED: usize = 2;
const GS_JOINED: usize = 3;
const GS_PRUNED: usize = 4;

/// Child descriptors of a Join/Prune group set.
/// RFC 7761, Section 4.9.5 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.5>
static GROUP_SET_CHILDREN: [FieldDescriptor; 5] = [
    encoded_address!("group", "Multicast Group Address"),
    FieldDescriptor::new(
        "num_joined_sources",
        "Number of Joined Sources",
        FieldType::U16,
    ),
    FieldDescriptor::new(
        "num_pruned_sources",
        "Number of Pruned Sources",
        FieldType::U16,
    ),
    FieldDescriptor::new("joined_sources", "Joined Sources", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&SOURCE_ADDRESS)),
    FieldDescriptor::new("pruned_sources", "Pruned Sources", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&SOURCE_ADDRESS)),
];

static GROUP_SET: FieldDescriptor =
    FieldDescriptor::new("group_set", "Group Set", FieldType::Object)
        .with_children(&GROUP_SET_CHILDREN);

/// Child field indices of a Bootstrap RP entry.
const RP_ADDRESS: usize = 0;
const RP_HOLDTIME: usize = 1;
const RP_PRIORITY: usize = 2;

/// Child descriptors of a Bootstrap RP entry.
/// RFC 5059, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5059#section-4.1>
static RP_CHILDREN: [FieldDescriptor; 3] = [
    encoded_address!("address", "RP Address"),
    FieldDescriptor::new("holdtime", "RP Holdtime", FieldType::U16),
    FieldDescriptor::new("priority", "RP Priority", FieldType::U8),
];

static RP: FieldDescriptor =
    FieldDescriptor::new("rp", "RP", FieldType::Object).with_children(&RP_CHILDREN);

/// Child field indices of a Bootstrap group range.
const GR_GROUP: usize = 0;
const GR_RP_COUNT: usize = 1;
const GR_FRAG_RP_COUNT: usize = 2;
const GR_RPS: usize = 3;

/// Child descriptors of a Bootstrap group range.
/// RFC 5059, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5059#section-4.1>
static GROUP_RANGE_CHILDREN: [FieldDescriptor; 4] = [
    encoded_address!("group", "Group Address"),
    FieldDescriptor::new("rp_count", "RP Count", FieldType::U8),
    FieldDescriptor::new("frag_rp_count", "Frag RP Cnt", FieldType::U8),
    FieldDescriptor::new("rps", "RPs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&RP)),
];

static GROUP_RANGE: FieldDescriptor =
    FieldDescriptor::new("group_range", "Group Range", FieldType::Object)
        .with_children(&GROUP_RANGE_CHILDREN);

/// Field descriptor indices into [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_TYPE: usize = 1;
const FD_FLAGS: usize = 2;
const FD_SUBTYPE: usize = 3;
const FD_NO_FORWARD: usize = 4;
const FD_CHECKSUM: usize = 5;
const FD_OPTIONS: usize = 6;
const FD_BORDER: usize = 7;
const FD_NULL_REGISTER: usize = 8;
const FD_UPSTREAM_NEIGHBOR: usize = 9;
const FD_NUM_GROUPS: usize = 10;
const FD_HOLDTIME: usize = 11;
const FD_GROUP_SETS: usize = 12;
const FD_FRAGMENT_TAG: usize = 13;
const FD_HASH_MASK_LEN: usize = 14;
const FD_BSR_PRIORITY: usize = 15;
const FD_BSR_ADDRESS: usize = 16;
const FD_GROUP_RANGES: usize = 17;
const FD_GROUP: usize = 18;
const FD_SOURCE: usize = 19;
const FD_ORIGINATOR: usize = 20;
const FD_RPT_BIT: usize = 21;
const FD_METRIC_PREFERENCE: usize = 22;
const FD_METRIC: usize = 23;
const FD_PREFIX_COUNT: usize = 24;
const FD_PRIORITY: usize = 25;
const FD_RP_ADDRESS: usize = 26;
const FD_GROUPS: usize = 27;
const FD_MASKLEN: usize = 28;
const FD_TTL: usize = 29;
const FD_PRUNE_INDICATOR: usize = 30;
const FD_PRUNE_NOW: usize = 31;
const FD_ASSERT_OVERRIDE: usize = 32;
const FD_INTERVAL: usize = 33;
const FD_DATA: usize = 34;

/// Field descriptors for the PIM dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 7761, Section 4.9 — common header; RFC 9436, Section 3 — Flag Bits
    //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9
    //   https://www.rfc-editor.org/rfc/rfc9436#section-3
    FieldDescriptor::new("version", "PIM Ver", FieldType::U8),
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, siblings| {
        let FieldValue::U8(t) = v else {
            return None;
        };
        let subtype = siblings
            .iter()
            .find(|f| f.name() == "subtype")
            .and_then(|f| f.value.as_u8());
        match (t, subtype) {
            (13..=15, Some(s)) => extended_type_name(*t, s),
            _ => message_type_name(*t),
        }
    }),
    FieldDescriptor::new("flags", "Flag Bits", FieldType::U8),
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8).optional(),
    flag("no_forward", "No-Forward (N)"),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    // RFC 7761, Section 4.9.2 — Hello
    //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9.2
    FieldDescriptor::new("options", "Options", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&HELLO_OPTION)),
    // RFC 7761, Section 4.9.3 — Register
    //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9.3
    flag("border", "Border (B)"),
    flag("null_register", "Null-Register (N)"),
    // RFC 7761, Section 4.9.5 — Join/Prune (also Graft and Graft-Ack,
    // RFC 3973, Sections 4.7.8 and 4.7.9)
    //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9.5
    //   https://www.rfc-editor.org/rfc/rfc3973#section-4.7.8
    encoded_address!("upstream_neighbor", "Upstream Neighbor Address"),
    FieldDescriptor::new("num_groups", "Num Groups", FieldType::U8).optional(),
    FieldDescriptor::new("holdtime", "Holdtime", FieldType::U16).optional(),
    FieldDescriptor::new("group_sets", "Group Sets", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&GROUP_SET)),
    // RFC 5059, Section 4.1 — Bootstrap
    //   https://www.rfc-editor.org/rfc/rfc5059#section-4.1
    FieldDescriptor::new("fragment_tag", "Fragment Tag", FieldType::U16).optional(),
    FieldDescriptor::new("hash_mask_len", "Hash Mask Len", FieldType::U8).optional(),
    FieldDescriptor::new("bsr_priority", "BSR Priority", FieldType::U8).optional(),
    encoded_address!("bsr_address", "BSR Address"),
    FieldDescriptor::new("group_ranges", "Group Ranges", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&GROUP_RANGE)),
    // RFC 7761, Sections 4.9.4 and 4.9.6 — Register-Stop and Assert; RFC
    // 3973, Section 4.7.10 — State Refresh
    //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9.4
    //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9.6
    //   https://www.rfc-editor.org/rfc/rfc3973#section-4.7.10
    encoded_address!("group", "Group Address"),
    encoded_address!("source", "Source Address"),
    encoded_address!("originator", "Originator Address"),
    flag("rpt_bit", "RPTbit (R)"),
    FieldDescriptor::new("metric_preference", "Metric Preference", FieldType::U32).optional(),
    FieldDescriptor::new("metric", "Metric", FieldType::U32).optional(),
    // RFC 5059, Section 4.2 — Candidate-RP-Advertisement
    //   https://www.rfc-editor.org/rfc/rfc5059#section-4.2
    FieldDescriptor::new("prefix_count", "Prefix Count", FieldType::U8).optional(),
    FieldDescriptor::new("priority", "Priority", FieldType::U8).optional(),
    encoded_address!("rp_address", "RP Address"),
    FieldDescriptor::new("groups", "Group Addresses", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&GROUP_ADDRESS)),
    // RFC 3973, Section 4.7.10 — State Refresh
    //   https://www.rfc-editor.org/rfc/rfc3973#section-4.7.10
    FieldDescriptor::new("masklen", "Masklen", FieldType::U8).optional(),
    FieldDescriptor::new("ttl", "TTL", FieldType::U8).optional(),
    flag("prune_indicator", "Prune Indicator (P)"),
    flag("prune_now", "Prune Now (N)"),
    flag("assert_override", "Assert Override (O)"),
    FieldDescriptor::new("interval", "Interval", FieldType::U8).optional(),
    // Octets of the message that are not decoded.
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Specification references for the PIM dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 7761",
        "Protocol Independent Multicast - Sparse Mode (PIM-SM): Protocol Specification (Revised)",
        "https://www.rfc-editor.org/rfc/rfc7761",
    ),
    SpecReference::new(
        "RFC 3973",
        "Protocol Independent Multicast - Dense Mode (PIM-DM): Protocol Specification (Revised)",
        "https://www.rfc-editor.org/rfc/rfc3973",
    ),
    SpecReference::new(
        "RFC 5059",
        "Bootstrap Router (BSR) Mechanism for Protocol Independent Multicast (PIM)",
        "https://www.rfc-editor.org/rfc/rfc5059",
    ),
    SpecReference::new(
        "RFC 5384",
        "The Protocol Independent Multicast (PIM) Join Attribute Format",
        "https://www.rfc-editor.org/rfc/rfc5384",
    ),
    SpecReference::new(
        "RFC 9436",
        "PIM Message Type Space Extension and Reserved Bits",
        "https://www.rfc-editor.org/rfc/rfc9436",
    ),
    SpecReference::new(
        "IANA PIM Parameters",
        "Protocol Independent Multicast (PIM) Parameters",
        "https://www.iana.org/assignments/pim-parameters/pim-parameters.xhtml",
    ),
];

/// The three encoded address formats.
///
/// RFC 7761, Section 4.9.1 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.1>
#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// Encoded-Unicast: family, encoding type, address.
    Unicast,
    /// Encoded-Group: family, encoding type, B/Z flags, mask length, address.
    Group,
    /// Encoded-Source: family, encoding type, S/W/R flags, mask length,
    /// address, and Join Attributes for encoding type 1.
    Source,
}

/// Returns the length of the address of `family` in its native encoding.
fn address_len(family: u8) -> Option<usize> {
    match family {
        AF_IPV4 => Some(4),
        AF_IPV6 => Some(16),
        _ => None,
    }
}

/// Returns the length of the Join Attributes at the start of `data`: TLVs
/// until the one with the E bit set (RFC 5384, Section 3.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5384#section-3.4.1>).
fn join_attributes_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let flags = *data.get(pos)?;
        let len = usize::from(*data.get(pos + 1)?);
        pos += 2 + len;
        if pos > data.len() {
            return None;
        }
        if flags & 0x40 != 0 {
            return Some(pos);
        }
    }
}

/// Returns the length of the encoded address of `kind` at `data[pos..]`, or
/// `None` when it is truncated or its family / encoding type is unknown.
fn encoded_len(data: &[u8], pos: usize, kind: Encoding) -> Option<usize> {
    let family = *data.get(pos)?;
    let encoding = *data.get(pos + 1)?;
    let header = if kind == Encoding::Unicast { 2 } else { 4 };
    let fixed = header + address_len(family)?;
    if pos + fixed > data.len() {
        return None;
    }
    match (kind, encoding) {
        (_, ENCODING_NATIVE) => Some(fixed),
        (Encoding::Source, ENCODING_JOIN_ATTRIBUTES) => {
            join_attributes_len(&data[pos + fixed..]).map(|n| fixed + n)
        }
        _ => None,
    }
}

/// Pushes the encoded address of `kind` at `data[pos..]` as an object
/// described by `descriptor` and returns the position after it, or `None`
/// (pushing nothing) when it cannot be decoded.
fn push_encoded_address<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
    kind: Encoding,
) -> Option<usize> {
    let len = encoded_len(data, pos, kind)?;
    push_encoded_address_of_len(buf, descriptor, data, pos, offset, kind, len);
    Some(pos + len)
}

/// Pushes the encoded address of `kind` at `data[pos..pos + len]`, where
/// `len` was returned by [`encoded_len`].
fn push_encoded_address_of_len<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
    kind: Encoding,
    len: usize,
) {
    let abs = offset + pos;
    let c = &ENCODED_ADDRESS_CHILDREN;
    let family = data[pos];
    let obj = buf.begin_container(descriptor, FieldValue::Object(0..0), abs..abs + len);
    buf.push_field(&c[EA_ADDRESS_FAMILY], FieldValue::U8(family), abs..abs + 1);
    buf.push_field(
        &c[EA_ENCODING_TYPE],
        FieldValue::U8(data[pos + 1]),
        abs + 1..abs + 2,
    );
    let mut addr = pos + 2;
    if kind != Encoding::Unicast {
        let flags = data[pos + 2];
        let bits: &[(usize, u8)] = if kind == Encoding::Group {
            // |B| Reserved  |Z|
            &[(EA_B_BIT, 0x80), (EA_Z_BIT, 0x01)]
        } else {
            // | Rsrvd   |S|W|R|
            &[(EA_S_BIT, 0x04), (EA_W_BIT, 0x02), (EA_R_BIT, 0x01)]
        };
        for &(fd, mask) in bits {
            buf.push_field(
                &c[fd],
                FieldValue::U8(u8::from(flags & mask != 0)),
                abs + 2..abs + 3,
            );
        }
        buf.push_field(
            &c[EA_MASK_LEN],
            FieldValue::U8(data[pos + 3]),
            abs + 3..abs + 4,
        );
        addr = pos + 4;
    }
    let (value, addr_end) = if family == AF_IPV4 {
        let a = [data[addr], data[addr + 1], data[addr + 2], data[addr + 3]];
        (FieldValue::Ipv4Addr(a), addr + 4)
    } else {
        let mut a = [0u8; 16];
        a.copy_from_slice(&data[addr..addr + 16]);
        (FieldValue::Ipv6Addr(a), addr + 16)
    };
    buf.push_field(&c[EA_ADDRESS], value, offset + addr..offset + addr_end);
    if addr_end < pos + len {
        push_join_attributes(buf, &data[addr_end..pos + len], offset + addr_end);
    }
    buf.end_container(obj);
}

/// Scans up to `max` consecutive elements starting at `start`, where
/// `element_len(pos)` is the length of a complete element at `pos` or
/// `None`. Returns the end of the complete elements and their number.
fn scan(start: usize, max: usize, element_len: impl Fn(usize) -> Option<usize>) -> (usize, usize) {
    let mut pos = start;
    let mut n = 0;
    while n < max {
        let Some(len) = element_len(pos) else {
            break;
        };
        pos += len;
        n += 1;
    }
    (pos, n)
}

/// Pushes up to `max` encoded addresses of `kind` at `data[start..]` as the
/// array `array` of `element` objects. Only complete addresses are pushed,
/// and no array when there is none. Returns the position after them and
/// whether all `max` were decoded.
#[allow(clippy::too_many_arguments)]
fn push_address_array<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    array: &'static FieldDescriptor,
    element: &'static FieldDescriptor,
    data: &'pkt [u8],
    start: usize,
    offset: usize,
    kind: Encoding,
    max: usize,
) -> (usize, bool) {
    let (end, n) = scan(start, max, |p| encoded_len(data, p, kind));
    if n > 0 {
        let idx = buf.begin_container(array, FieldValue::Array(0..0), offset + start..offset + end);
        let mut pos = start;
        while pos < end {
            let Some(len) = encoded_len(data, pos, kind) else {
                break;
            };
            push_encoded_address_of_len(buf, element, data, pos, offset, kind, len);
            pos += len;
        }
        buf.end_container(idx);
    }
    (end, n == max)
}

/// Pushes Join Attributes already validated by [`join_attributes_len`].
///
/// RFC 5384, Section 3.4.1 — <https://www.rfc-editor.org/rfc/rfc5384#section-3.4.1>
fn push_join_attributes<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let array = buf.begin_container(
        &ENCODED_ADDRESS_CHILDREN[EA_JOIN_ATTRIBUTES],
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let c = &JOIN_ATTRIBUTE_CHILDREN;
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let flags = data[pos];
        let len = usize::from(data[pos + 1]);
        let end = pos + 2 + len;
        let abs = offset + pos;
        let obj = buf.begin_container(&JOIN_ATTRIBUTE, FieldValue::Object(0..0), abs..offset + end);
        buf.push_field(&c[JA_F_BIT], FieldValue::U8(flags >> 7), abs..abs + 1);
        buf.push_field(&c[JA_E_BIT], FieldValue::U8((flags >> 6) & 1), abs..abs + 1);
        buf.push_field(&c[JA_TYPE], FieldValue::U8(flags & 0x3F), abs..abs + 1);
        buf.push_field(
            &c[JA_LENGTH],
            FieldValue::U8(data[pos + 1]),
            abs + 1..abs + 2,
        );
        if end > pos + 2 {
            buf.push_field(
                &c[JA_VALUE],
                FieldValue::Bytes(&data[pos + 2..end]),
                abs + 2..offset + end,
            );
        }
        buf.end_container(obj);
        pos = end;
    }
    buf.end_container(array);
}

/// Pushes the undecoded octets `data[pos..]` as `data`, if any.
fn push_rest<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], pos: usize, offset: usize) {
    if pos < data.len() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA],
            FieldValue::Bytes(&data[pos..]),
            offset + pos..offset + data.len(),
        );
    }
}

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    read_be_u16(data, pos).ok()
}

fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    read_be_u32(data, pos).ok()
}

/// Pushes the value of one Hello option.
///
/// RFC 7761, Section 4.9.2 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.2>
fn push_hello_option_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    t: u16,
    value: &'pkt [u8],
    offset: usize,
) {
    let c = &HELLO_OPTION_CHILDREN;
    let r = |from: usize, to: usize| offset + from..offset + to;
    match (t, value.len()) {
        (OPTION_HOLDTIME, 2) => {
            buf.push_field(
                &c[HO_HOLDTIME],
                FieldValue::U16(u16::from_be_bytes([value[0], value[1]])),
                r(0, 2),
            );
        }
        // |T|      Propagation_Delay      |      Override_Interval        |
        (OPTION_LAN_PRUNE_DELAY, 4) => {
            let delay = u16::from_be_bytes([value[0], value[1]]);
            buf.push_field(&c[HO_T_BIT], FieldValue::U8((value[0] >> 7) & 1), r(0, 1));
            buf.push_field(
                &c[HO_PROPAGATION_DELAY],
                FieldValue::U16(delay & 0x7FFF),
                r(0, 2),
            );
            buf.push_field(
                &c[HO_OVERRIDE_INTERVAL],
                FieldValue::U16(u16::from_be_bytes([value[2], value[3]])),
                r(2, 4),
            );
        }
        (OPTION_DR_PRIORITY, 4) | (OPTION_GENERATION_ID, 4) => {
            let fd = if t == OPTION_DR_PRIORITY {
                HO_DR_PRIORITY
            } else {
                HO_GENERATION_ID
            };
            buf.push_field(
                &c[fd],
                FieldValue::U32(u32::from_be_bytes([value[0], value[1], value[2], value[3]])),
                r(0, 4),
            );
        }
        // |  Version = 1  |   Interval    |            Reserved           |
        // (RFC 3973, Section 4.7.5.4 —
        // https://www.rfc-editor.org/rfc/rfc3973#section-4.7.5.4)
        (OPTION_STATE_REFRESH, 4) => {
            buf.push_field(
                &c[HO_STATE_REFRESH_VERSION],
                FieldValue::U8(value[0]),
                r(0, 1),
            );
            buf.push_field(
                &c[HO_STATE_REFRESH_INTERVAL],
                FieldValue::U8(value[1]),
                r(1, 2),
            );
        }
        // "Secondary Address 1 (Encoded-Unicast format)" ...
        (OPTION_ADDRESS_LIST, _) if !value.is_empty() => {
            let (pos, _) = push_address_array(
                buf,
                &c[HO_ADDRESSES],
                &SECONDARY_ADDRESS,
                value,
                0,
                offset,
                Encoding::Unicast,
                usize::MAX,
            );
            if pos < value.len() {
                buf.push_field(
                    &c[HO_VALUE],
                    FieldValue::Bytes(&value[pos..]),
                    r(pos, value.len()),
                );
            }
        }
        (_, 0) => {}
        _ => buf.push_field(&c[HO_VALUE], FieldValue::Bytes(value), r(0, value.len())),
    }
}

/// Pushes the Hello options at `data[pos..]` and returns the position after
/// the last complete option.
///
/// RFC 7761, Section 4.9.2 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.2>
fn push_hello<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> usize {
    let mut end = HEADER_SIZE;
    while end + 4 <= data.len() {
        let len = usize::from(u16::from_be_bytes([data[end + 2], data[end + 3]]));
        if end + 4 + len > data.len() {
            break;
        }
        end += 4 + len;
    }
    if end == HEADER_SIZE {
        return end;
    }
    let c = &HELLO_OPTION_CHILDREN;
    let array = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_OPTIONS],
        FieldValue::Array(0..0),
        offset + HEADER_SIZE..offset + end,
    );
    let mut pos = HEADER_SIZE;
    while pos < end {
        let t = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([data[pos + 2], data[pos + 3]]));
        let abs = offset + pos;
        let obj = buf.begin_container(&HELLO_OPTION, FieldValue::Object(0..0), abs..abs + 4 + len);
        buf.push_field(&c[HO_TYPE], FieldValue::U16(t), abs..abs + 2);
        buf.push_field(&c[HO_LENGTH], FieldValue::U16(len as u16), abs + 2..abs + 4);
        push_hello_option_value(buf, t, &data[pos + 4..pos + 4 + len], abs + 4);
        buf.end_container(obj);
        pos += 4 + len;
    }
    buf.end_container(array);
    end
}

/// Returns the length of the Join/Prune group set at `data[pos..]`: the
/// group, the two counts and every joined and pruned source, or `None` when
/// it is incomplete.
///
/// RFC 7761, Section 4.9.5 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.5>
fn group_set_len(data: &[u8], pos: usize) -> Option<usize> {
    let group = encoded_len(data, pos, Encoding::Group)?;
    let joined = usize::from(read_u16(data, pos + group)?);
    let pruned = usize::from(read_u16(data, pos + group + 2)?);
    let start = pos + group + 4;
    let (end, n) = scan(start, joined + pruned, |p| {
        encoded_len(data, p, Encoding::Source)
    });
    (n == joined + pruned).then_some(end - pos)
}

/// Pushes the body of a Join/Prune, Graft or Graft-Ack message and returns
/// the position where decoding stopped. Only complete group sets are
/// decoded.
///
/// RFC 7761, Section 4.9.5 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.5>;
/// RFC 3973, Sections 4.7.8 and 4.7.9 —
/// <https://www.rfc-editor.org/rfc/rfc3973#section-4.7.8>
fn push_join_prune<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> usize {
    let Some(pos) = push_encoded_address(
        buf,
        &FIELD_DESCRIPTORS[FD_UPSTREAM_NEIGHBOR],
        data,
        HEADER_SIZE,
        offset,
        Encoding::Unicast,
    ) else {
        return HEADER_SIZE;
    };
    // |  Reserved     | Num groups    |          Holdtime             |
    let Some(holdtime) = read_u16(data, pos + 2) else {
        return pos;
    };
    let num_groups = data[pos + 1];
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_NUM_GROUPS],
        FieldValue::U8(num_groups),
        offset + pos + 1..offset + pos + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HOLDTIME],
        FieldValue::U16(holdtime),
        offset + pos + 2..offset + pos + 4,
    );
    let start = pos + 4;
    let (end, n) = scan(start, usize::from(num_groups), |p| group_set_len(data, p));
    if n == 0 {
        return start;
    }
    let c = &GROUP_SET_CHILDREN;
    let array = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_GROUP_SETS],
        FieldValue::Array(0..0),
        offset + start..offset + end,
    );
    let mut pos = start;
    while pos < end {
        let (Some(set_len), Some(group_len)) = (
            group_set_len(data, pos),
            encoded_len(data, pos, Encoding::Group),
        ) else {
            break;
        };
        let obj = buf.begin_container(
            &GROUP_SET,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + set_len,
        );
        push_encoded_address_of_len(
            buf,
            &c[GS_GROUP],
            data,
            pos,
            offset,
            Encoding::Group,
            group_len,
        );
        let counts = pos + group_len;
        let joined = read_u16(data, counts).unwrap_or_default();
        let pruned = read_u16(data, counts + 2).unwrap_or_default();
        buf.push_field(
            &c[GS_NUM_JOINED],
            FieldValue::U16(joined),
            offset + counts..offset + counts + 2,
        );
        buf.push_field(
            &c[GS_NUM_PRUNED],
            FieldValue::U16(pruned),
            offset + counts + 2..offset + counts + 4,
        );
        let (after_joined, _) = push_address_array(
            buf,
            &c[GS_JOINED],
            &SOURCE_ADDRESS,
            data,
            counts + 4,
            offset,
            Encoding::Source,
            usize::from(joined),
        );
        push_address_array(
            buf,
            &c[GS_PRUNED],
            &SOURCE_ADDRESS,
            data,
            after_joined,
            offset,
            Encoding::Source,
            usize::from(pruned),
        );
        buf.end_container(obj);
        pos += set_len;
    }
    buf.end_container(array);
    end
}

/// Returns the length of the Bootstrap RP entry at `data[pos..]`: an
/// Encoded-Unicast RP Address, then RP Holdtime, RP Priority and Reserved.
///
/// RFC 5059, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5059#section-4.1>
fn rp_len(data: &[u8], pos: usize) -> Option<usize> {
    let addr = encoded_len(data, pos, Encoding::Unicast)?;
    (pos + addr + 4 <= data.len()).then_some(addr + 4)
}

/// Returns the length of the Bootstrap group range at `data[pos..]`: the
/// group, RP Count, Frag RP Cnt, Reserved and Frag RP Cnt RP entries.
///
/// RFC 5059, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5059#section-4.1>
fn group_range_len(data: &[u8], pos: usize) -> Option<usize> {
    let group = encoded_len(data, pos, Encoding::Group)?;
    let frag_rp_count = usize::from(*data.get(pos + group + 1)?);
    let start = pos + group + 4;
    if start > data.len() {
        return None;
    }
    let (end, n) = scan(start, frag_rp_count, |p| rp_len(data, p));
    (n == frag_rp_count).then_some(end - pos)
}

/// Pushes the body of a Bootstrap message and returns the position where
/// decoding stopped. Only complete group ranges are decoded.
///
/// RFC 5059, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc5059#section-4.1>
fn push_bootstrap<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> usize {
    // |         Fragment Tag          | Hash Mask Len | BSR Priority  |
    let Some(fixed) = data.get(HEADER_SIZE..HEADER_SIZE + 4) else {
        return HEADER_SIZE;
    };
    let abs = offset + HEADER_SIZE;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_FRAGMENT_TAG],
        FieldValue::U16(u16::from_be_bytes([fixed[0], fixed[1]])),
        abs..abs + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HASH_MASK_LEN],
        FieldValue::U8(fixed[2]),
        abs + 2..abs + 3,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_BSR_PRIORITY],
        FieldValue::U8(fixed[3]),
        abs + 3..abs + 4,
    );
    let Some(start) = push_encoded_address(
        buf,
        &FIELD_DESCRIPTORS[FD_BSR_ADDRESS],
        data,
        HEADER_SIZE + 4,
        offset,
        Encoding::Unicast,
    ) else {
        return HEADER_SIZE + 4;
    };
    // Group ranges until the end of the message.
    let (end, n) = scan(start, usize::MAX, |p| group_range_len(data, p));
    if n == 0 {
        return start;
    }
    let c = &GROUP_RANGE_CHILDREN;
    let r = &RP_CHILDREN;
    let array = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_GROUP_RANGES],
        FieldValue::Array(0..0),
        offset + start..offset + end,
    );
    let mut pos = start;
    while pos < end {
        let (Some(range_len), Some(group_len)) = (
            group_range_len(data, pos),
            encoded_len(data, pos, Encoding::Group),
        ) else {
            break;
        };
        let obj = buf.begin_container(
            &GROUP_RANGE,
            FieldValue::Object(0..0),
            offset + pos..offset + pos + range_len,
        );
        push_encoded_address_of_len(
            buf,
            &c[GR_GROUP],
            data,
            pos,
            offset,
            Encoding::Group,
            group_len,
        );
        // | RP Count 1    | Frag RP Cnt 1 |         Reserved              |
        let counts = pos + group_len;
        buf.push_field(
            &c[GR_RP_COUNT],
            FieldValue::U8(data[counts]),
            offset + counts..offset + counts + 1,
        );
        buf.push_field(
            &c[GR_FRAG_RP_COUNT],
            FieldValue::U8(data[counts + 1]),
            offset + counts + 1..offset + counts + 2,
        );
        let rps_start = counts + 4;
        let rps_end = pos + range_len;
        if rps_start < rps_end {
            let rps = buf.begin_container(
                &c[GR_RPS],
                FieldValue::Array(0..0),
                offset + rps_start..offset + rps_end,
            );
            let mut p = rps_start;
            while p < rps_end {
                let (Some(len), Some(addr_len)) =
                    (rp_len(data, p), encoded_len(data, p, Encoding::Unicast))
                else {
                    break;
                };
                let rp = buf.begin_container(
                    &RP,
                    FieldValue::Object(0..0),
                    offset + p..offset + p + len,
                );
                push_encoded_address_of_len(
                    buf,
                    &r[RP_ADDRESS],
                    data,
                    p,
                    offset,
                    Encoding::Unicast,
                    addr_len,
                );
                // |          RP1 Holdtime         | RP1 Priority  |   Reserved    |
                let h = p + addr_len;
                buf.push_field(
                    &r[RP_HOLDTIME],
                    FieldValue::U16(u16::from_be_bytes([data[h], data[h + 1]])),
                    offset + h..offset + h + 2,
                );
                buf.push_field(
                    &r[RP_PRIORITY],
                    FieldValue::U8(data[h + 2]),
                    offset + h + 2..offset + h + 3,
                );
                buf.end_container(rp);
                p += len;
            }
            buf.end_container(rps);
        }
        buf.end_container(obj);
        pos += range_len;
    }
    buf.end_container(array);
    end
}

/// Pushes the `|R| Metric Preference |` and `Metric` words at `data[pos..]`
/// and returns the position after them.
///
/// RFC 7761, Section 4.9.6 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.6>
fn push_metrics<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    offset: usize,
) -> Option<usize> {
    let pref = read_u32(data, pos)?;
    let metric = read_u32(data, pos + 4)?;
    let abs = offset + pos;
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_RPT_BIT],
        FieldValue::U8((pref >> 31) as u8),
        abs..abs + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_METRIC_PREFERENCE],
        FieldValue::U32(pref & 0x7FFF_FFFF),
        abs..abs + 4,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_METRIC],
        FieldValue::U32(metric),
        abs + 4..abs + 8,
    );
    Some(pos + 8)
}

/// Pushes the encoded addresses `fields` (descriptor index and format) in
/// order and returns the position after them, or where decoding stopped.
fn push_addresses<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    mut pos: usize,
    offset: usize,
    fields: &[(usize, Encoding)],
) -> Result<usize, usize> {
    for &(fd, kind) in fields {
        pos = push_encoded_address(buf, &FIELD_DESCRIPTORS[fd], data, pos, offset, kind)
            .ok_or(pos)?;
    }
    Ok(pos)
}

/// Pushes the body of an Assert message.
///
/// RFC 7761, Section 4.9.6 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.6>
fn push_assert<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> usize {
    let fields = [(FD_GROUP, Encoding::Group), (FD_SOURCE, Encoding::Unicast)];
    match push_addresses(buf, data, HEADER_SIZE, offset, &fields) {
        Ok(pos) => push_metrics(buf, data, pos, offset).unwrap_or(pos),
        Err(pos) => pos,
    }
}

/// Pushes the body of a State Refresh message.
///
/// RFC 3973, Section 4.7.10 — <https://www.rfc-editor.org/rfc/rfc3973#section-4.7.10>
fn push_state_refresh<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> usize {
    let fields = [
        (FD_GROUP, Encoding::Group),
        (FD_SOURCE, Encoding::Unicast),
        (FD_ORIGINATOR, Encoding::Unicast),
    ];
    let pos = match push_addresses(buf, data, HEADER_SIZE, offset, &fields) {
        Ok(pos) => pos,
        Err(pos) => return pos,
    };
    let Some(pos) = push_metrics(buf, data, pos, offset) else {
        return pos;
    };
    // |    Masklen    |    TTL        |P|N|O|Reserved |   Interval    |
    let Some(word) = data.get(pos..pos + 4) else {
        return pos;
    };
    let abs = offset + pos;
    let d = FIELD_DESCRIPTORS;
    buf.push_field(&d[FD_MASKLEN], FieldValue::U8(word[0]), abs..abs + 1);
    buf.push_field(&d[FD_TTL], FieldValue::U8(word[1]), abs + 1..abs + 2);
    for (fd, mask) in [
        (FD_PRUNE_INDICATOR, 0x80),
        (FD_PRUNE_NOW, 0x40),
        (FD_ASSERT_OVERRIDE, 0x20),
    ] {
        buf.push_field(
            &d[fd],
            FieldValue::U8(u8::from(word[2] & mask != 0)),
            abs + 2..abs + 3,
        );
    }
    buf.push_field(&d[FD_INTERVAL], FieldValue::U8(word[3]), abs + 3..abs + 4);
    pos + 4
}

/// Pushes the body of a Candidate-RP-Advertisement message.
///
/// RFC 5059, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc5059#section-4.2>
fn push_candidate_rp_adv<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> usize {
    // | Prefix Count  |   Priority    |           Holdtime            |
    let Some(holdtime) = read_u16(data, HEADER_SIZE + 2) else {
        return HEADER_SIZE;
    };
    let prefix_count = data[HEADER_SIZE];
    let abs = offset + HEADER_SIZE;
    let d = FIELD_DESCRIPTORS;
    buf.push_field(
        &d[FD_PREFIX_COUNT],
        FieldValue::U8(prefix_count),
        abs..abs + 1,
    );
    buf.push_field(
        &d[FD_PRIORITY],
        FieldValue::U8(data[HEADER_SIZE + 1]),
        abs + 1..abs + 2,
    );
    buf.push_field(&d[FD_HOLDTIME], FieldValue::U16(holdtime), abs + 2..abs + 4);
    let Some(pos) = push_encoded_address(
        buf,
        &d[FD_RP_ADDRESS],
        data,
        HEADER_SIZE + 4,
        offset,
        Encoding::Unicast,
    ) else {
        return HEADER_SIZE + 4;
    };
    let (end, _) = push_address_array(
        buf,
        &d[FD_GROUPS],
        &GROUP_ADDRESS,
        data,
        pos,
        offset,
        Encoding::Group,
        usize::from(prefix_count),
    );
    end
}

/// Returns the dispatch hint for the multicast data packet of a Register:
/// an IPv4 packet with a valid IHL or an IPv6 packet with a complete fixed
/// header, or `None` when the octets are neither.
///
/// RFC 7761, Section 4.9.3 — "This packet must be of the same address
/// family as the encapsulating PIM packet" —
/// <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.3>; RFC 791,
/// Section 3.1 — <https://www.rfc-editor.org/rfc/rfc791#section-3.1>; RFC
/// 8200, Section 3 — <https://www.rfc-editor.org/rfc/rfc8200#section-3>
fn inner_packet_hint(packet: &[u8]) -> Option<DispatchHint> {
    let first = *packet.first()?;
    match first >> 4 {
        // Version 4 and an IHL of at least 5 words that fits the packet.
        4 if (first & 0x0F) >= 5 && packet.len() >= usize::from(first & 0x0F) * 4 => {
            Some(DispatchHint::ByEtherType(0x0800))
        }
        6 if packet.len() >= 40 => Some(DispatchHint::ByEtherType(0x86DD)),
        _ => None,
    }
}

/// Whether the layers before this one are a PIM Register followed by an
/// IPv6 header, i.e. this is the dummy PIM header of an IPv6 Null-Register.
///
/// RFC 7761, Section 4.9.3 — <https://www.rfc-editor.org/rfc/rfc7761#section-4.9.3>
fn in_ipv6_null_register(buf: &DissectBuffer<'_>) -> bool {
    let mut layers = buf.layers().iter().rev();
    matches!(
        (layers.next(), layers.next()),
        (Some(ip), Some(pim)) if ip.name == "IPv6" && pim.name == "PIM"
    )
}

/// PIM version 2 dissector.
///
/// A message whose body cannot be decoded completely keeps the undecoded
/// octets as `data`. A Register hands its multicast data packet to the
/// IPv4 or IPv6 dissector.
pub struct PimDissector;

impl Dissector for PimDissector {
    fn name(&self) -> &'static str {
        "Protocol Independent Multicast"
    }

    fn short_name(&self) -> &'static str {
        "PIM"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }
        // RFC 7761, Section 4.9 — |PIM Ver| Type  | Flag Bits | Checksum |
        //   https://www.rfc-editor.org/rfc/rfc7761#section-4.9
        let version = data[0] >> 4;
        let msg_type = data[0] & 0x0F;
        let flags = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        // An IPv6 Null-Register carries a dummy IPv6 header followed by a
        // dummy PIM header whose PIM Version, Type and Reserved fields are 0
        // (table in RFC 7761, Section 4.9.3 —
        // https://www.rfc-editor.org/rfc/rfc7761#section-4.9.3).
        let dummy_header = version == 0
            && msg_type == TYPE_HELLO
            && data.len() == HEADER_SIZE
            && in_ipv6_null_register(buf);
        if version != VERSION_2 && !dummy_header {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }

        let d = FIELD_DESCRIPTORS;
        buf.begin_layer(self.short_name(), None, d, offset..offset + data.len());
        buf.push_field(&d[FD_VERSION], FieldValue::U8(version), offset..offset + 1);
        // The dummy header's Type 0 does not make it a Hello.
        if !dummy_header {
            buf.push_field(&d[FD_TYPE], FieldValue::U8(msg_type), offset..offset + 1);
        }
        buf.push_field(&d[FD_FLAGS], FieldValue::U8(flags), offset + 1..offset + 2);
        match msg_type {
            // "defines flag bit 7 as No-Forward" (RFC 9436, Sections 4.1 and
            // 4.3 — https://www.rfc-editor.org/rfc/rfc9436#section-4.1)
            TYPE_BOOTSTRAP | TYPE_PFM => buf.push_field(
                &d[FD_NO_FORWARD],
                FieldValue::U8(flags >> 7),
                offset + 1..offset + 2,
            ),
            // "the four most significant flag bits (bits 4-7) are to be used
            // as a subtype" (RFC 9436, Sections 4.2 and 5 —
            // https://www.rfc-editor.org/rfc/rfc9436#section-5)
            TYPE_DF_ELECTION | 13..=15 => buf.push_field(
                &d[FD_SUBTYPE],
                FieldValue::U8(flags >> 4),
                offset + 1..offset + 2,
            ),
            _ => {}
        }
        buf.push_field(
            &d[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 2..offset + 4,
        );

        if dummy_header {
            buf.end_layer();
            return Ok(DissectResult::new(HEADER_SIZE, DispatchHint::End));
        }

        let end = match msg_type {
            TYPE_HELLO => push_hello(buf, data, offset),
            TYPE_REGISTER => {
                // |B|N|                       Reserved2                           |
                if data.len() < HEADER_SIZE + 4 {
                    HEADER_SIZE
                } else {
                    let word = data[HEADER_SIZE];
                    let abs = offset + HEADER_SIZE;
                    buf.push_field(&d[FD_BORDER], FieldValue::U8(word >> 7), abs..abs + 1);
                    buf.push_field(
                        &d[FD_NULL_REGISTER],
                        FieldValue::U8((word >> 6) & 1),
                        abs..abs + 1,
                    );
                    // "Multicast data packet": the original IPv4 or IPv6
                    // packet, dispatched by its version nibble.
                    let inner = HEADER_SIZE + 4;
                    let next = inner_packet_hint(&data[inner..]);
                    if let Some(next) = next {
                        if let Some(layer) = buf.last_layer_mut() {
                            layer.range = offset..offset + inner;
                        }
                        buf.end_layer();
                        return Ok(DissectResult::new(inner, next));
                    }
                    inner
                }
            }
            TYPE_REGISTER_STOP => {
                let fields = [(FD_GROUP, Encoding::Group), (FD_SOURCE, Encoding::Unicast)];
                push_addresses(buf, data, HEADER_SIZE, offset, &fields).unwrap_or_else(|p| p)
            }
            TYPE_JOIN_PRUNE | TYPE_GRAFT | TYPE_GRAFT_ACK => push_join_prune(buf, data, offset),
            TYPE_BOOTSTRAP => push_bootstrap(buf, data, offset),
            TYPE_ASSERT => push_assert(buf, data, offset),
            TYPE_CANDIDATE_RP_ADV => push_candidate_rp_adv(buf, data, offset),
            TYPE_STATE_REFRESH => push_state_refresh(buf, data, offset),
            _ => HEADER_SIZE,
        };
        push_rest(buf, data, end, offset);
        buf.end_layer();
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 7761 (PIM-SM) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.9 | Common header (version, type, checksum) | `parse_hello_ipv4` |
    //! | 4.9 | Version other than 2 rejected | `reject_unsupported_version` |
    //! | 4.9 | Header shorter than 4 octets is Truncated | `truncated_header` |
    //! | 4.9 | Unknown message type kept as data | `unknown_type_kept_as_data` |
    //! | 4.9.1 | Encoded-Unicast / Group / Source (IPv4) | `parse_join_prune_ipv4` |
    //! | 4.9.1 | Encoded addresses (IPv6) | `parse_join_prune_ipv6` |
    //! | 4.9.1 | Unknown address family stops decoding | `unknown_address_family_kept_as_data` |
    //! | 4.9.2 | Hello Holdtime, LAN Prune Delay, DR Priority, Generation ID, Address List | `parse_hello_ipv4` |
    //! | 4.9.2 | Hello Address List (IPv6) | `parse_hello_ipv6_address_list` |
    //! | 4.9.2 | Unknown / private Hello options kept as value | `parse_hello_ipv4` |
    //! | 4.9.2 | Hello option overrunning the message kept as data | `hello_option_overrun` |
    //! | 4.9.3 | Register with an inner IPv4 packet | `parse_register_ipv4` |
    //! | 4.9.3 | Register with an inner IPv6 packet | `parse_register_ipv6` |
    //! | 4.9.3 | Null-Register (N bit) | `parse_null_register` |
    //! | 4.9.3 | IPv6 Null-Register dummy PIM header | `parse_null_register_dummy_pim_header` |
    //! | 4.9.3 | Register without a recognizable inner packet (bad version, IHL, short header) | `register_unknown_inner_packet` |
    //! | 4.9.4 | Register-Stop | `parse_register_stop` |
    //! | 4.9.5 | Join/Prune with (*,G) join and (S,G,rpt) prune | `parse_join_prune_ipv4` |
    //! | 4.9.5 | Join/Prune with a truncated source list | `join_prune_truncated_source` |
    //! | 4.9.6 | Assert | `parse_assert` |
    //!
    //! # RFC 3973 (PIM-DM) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.7.5.4 | State Refresh Capable Hello option | `parse_hello_ipv4` |
    //! | 4.7.8 | Graft | `parse_graft` |
    //! | 4.7.10 | State Refresh | `parse_state_refresh` |
    //!
    //! # RFC 5059 (BSR) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.1 | Bootstrap with No-Forward bit, group range and RP | `parse_bootstrap` |
    //! | 4.1 | Bootstrap with a truncated RP entry | `bootstrap_truncated_rp` |
    //! | 4.2 | Candidate-RP-Advertisement | `parse_candidate_rp_adv` |
    //!
    //! # RFC 5384 (Join Attributes) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 3.4.1 | Encoded-Source with Join Attributes (encoding type 1) | `parse_join_prune_join_attributes` |
    //!
    //! # RFC 9436 (Type Space Extension and Flag Bits) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.2, 5 | Subtype of DF Election and extended types | `extended_type_subtype` |
    //! | 4.1 | Bootstrap No-Forward flag bit | `parse_bootstrap` |

    use super::*;
    use packet_dissector_core::field::Field;
    use packet_dissector_core::packet::Layer;

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = PimDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    /// The last PIM layer.
    fn layer<'a>(buf: &'a DissectBuffer<'_>) -> &'a Layer {
        buf.layers().iter().rev().find(|l| l.name == "PIM").unwrap()
    }

    /// Direct children of the container `field`.
    fn children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        field: &Field<'pkt>,
    ) -> Vec<&'a Field<'pkt>> {
        let (FieldValue::Array(r) | FieldValue::Object(r)) = &field.value else {
            panic!("{} is not a container", field.name());
        };
        let mut out = Vec::new();
        let mut i = r.start;
        while i < r.end {
            let f = &buf.fields()[i as usize];
            out.push(f);
            i = match &f.value {
                FieldValue::Array(c) | FieldValue::Object(c) => c.end.max(i + 1),
                _ => i + 1,
            };
        }
        out
    }

    fn top<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> &'a Field<'pkt> {
        children_of_layer(buf)
            .into_iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} missing"))
    }

    fn has_top(buf: &DissectBuffer<'_>, name: &str) -> bool {
        children_of_layer(buf).iter().any(|f| f.name() == name)
    }

    /// Direct fields of the PIM layer.
    fn children_of_layer<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<&'a Field<'pkt>> {
        let l = layer(buf);
        let mut out = Vec::new();
        let mut i = l.field_range.start;
        while i < l.field_range.end {
            let f = &buf.fields()[i as usize];
            out.push(f);
            i = match &f.value {
                FieldValue::Array(c) | FieldValue::Object(c) => c.end.max(i + 1),
                _ => i + 1,
            };
        }
        out
    }

    fn child<'a, 'pkt>(fields: &[&'a Field<'pkt>], name: &str) -> &'a Field<'pkt> {
        fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("child {name} missing"))
    }

    fn display(buf: &DissectBuffer<'_>, field: &Field<'_>) -> Option<&'static str> {
        let siblings = match &field.value {
            FieldValue::Array(r) | FieldValue::Object(r) => buf.nested_fields(r),
            _ => buf.layer_fields(layer(buf)),
        };
        (field.descriptor.display_fn?)(&field.value, siblings)
    }

    /// Encoded-Unicast IPv4 address.
    fn eu4(a: [u8; 4]) -> Vec<u8> {
        let mut v = vec![1, 0];
        v.extend_from_slice(&a);
        v
    }

    /// Encoded-Group IPv4 address with flags and mask length.
    fn eg4(flags: u8, mask: u8, a: [u8; 4]) -> Vec<u8> {
        let mut v = vec![1, 0, flags, mask];
        v.extend_from_slice(&a);
        v
    }

    /// Encoded-Source IPv4 address with S/W/R flags.
    fn es4(flags: u8, a: [u8; 4]) -> Vec<u8> {
        let mut v = vec![1, 0, flags, 32];
        v.extend_from_slice(&a);
        v
    }

    fn pim(msg_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x20 | msg_type, flags, 0xAB, 0xCD];
        v.extend_from_slice(body);
        v
    }

    fn option(t: u16, value: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn parse_hello_ipv4() {
        let mut body = option(1, &105u16.to_be_bytes());
        body.extend(option(2, &[0x81, 0xF4, 0x09, 0xC4])); // T=1, 500 ms, 2500 ms
        body.extend(option(19, &1u32.to_be_bytes()));
        body.extend(option(20, &0xDEAD_BEEFu32.to_be_bytes()));
        body.extend(option(21, &[1, 60, 0, 0]));
        body.extend(option(24, &eu4([10, 0, 1, 1])));
        body.extend(option(26, &[]));
        body.extend(option(65001, &[9, 9]));
        let data = pim(TYPE_HELLO, 0, &body);
        let (buf, result) = dissect(&data);

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        let l = layer(&buf);
        assert_eq!(l.range, 0..data.len());
        assert_eq!(
            buf.field_by_name(l, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(buf.resolve_display_name(l, "type_name"), Some("Hello"));
        assert_eq!(top(&buf, "checksum").value, FieldValue::U16(0xABCD));
        assert!(!has_top(&buf, "data"));

        let options = children(&buf, top(&buf, "options"));
        assert_eq!(options.len(), 8);
        let o: Vec<_> = options.iter().map(|o| children(&buf, o)).collect();
        assert_eq!(display(&buf, options[0]), Some("Hold Time"));
        assert_eq!(child(&o[0], "holdtime").value, FieldValue::U16(105));
        assert_eq!(child(&o[1], "t_bit").value, FieldValue::U8(1));
        assert_eq!(
            child(&o[1], "propagation_delay").value,
            FieldValue::U16(500)
        );
        assert_eq!(
            child(&o[1], "override_interval").value,
            FieldValue::U16(2500)
        );
        assert_eq!(child(&o[2], "dr_priority").value, FieldValue::U32(1));
        assert_eq!(
            child(&o[3], "generation_id").value,
            FieldValue::U32(0xDEAD_BEEF)
        );
        assert_eq!(
            child(&o[4], "state_refresh_version").value,
            FieldValue::U8(1)
        );
        assert_eq!(
            child(&o[4], "state_refresh_interval").value,
            FieldValue::U8(60)
        );
        let addrs = children(&buf, child(&o[5], "addresses"));
        assert_eq!(addrs.len(), 1);
        let a = children(&buf, addrs[0]);
        assert_eq!(
            child(&a, "address").value,
            FieldValue::Ipv4Addr([10, 0, 1, 1])
        );
        assert_eq!(display(&buf, child(&a, "address_family")), Some("IPv4"));
        assert_eq!(display(&buf, options[6]), Some("Join Attribute"));
        assert_eq!(o[6].len(), 2);
        assert_eq!(display(&buf, options[7]), Some("Private Use"));
        assert_eq!(child(&o[7], "value").value, FieldValue::Bytes(&[9, 9]));
    }

    #[test]
    fn parse_hello_ipv6_address_list() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let mut value = vec![2, 0];
        value.extend_from_slice(&addr);
        value.extend_from_slice(&[9, 9, 9]); // trailing garbage
        let data = pim(TYPE_HELLO, 0, &option(24, &value));
        let (buf, _) = dissect(&data);
        let options = children(&buf, top(&buf, "options"));
        let o = children(&buf, options[0]);
        let addrs = children(&buf, child(&o, "addresses"));
        let a = children(&buf, addrs[0]);
        assert_eq!(child(&a, "address").value, FieldValue::Ipv6Addr(addr));
        assert_eq!(child(&o, "value").value, FieldValue::Bytes(&[9, 9, 9]));
        assert_eq!(child(&o, "value").range, 26..29);
    }

    #[test]
    fn hello_option_overrun() {
        let mut body = option(1, &[0, 30]);
        body.extend_from_slice(&[0, 19, 0, 8, 1]);
        let data = pim(TYPE_HELLO, 0, &body);
        let (buf, _) = dissect(&data);
        let options = top(&buf, "options");
        assert_eq!(children(&buf, options).len(), 1);
        assert_eq!(options.range, 4..10);
        assert_eq!(
            top(&buf, "data").value,
            FieldValue::Bytes(&[0, 19, 0, 8, 1])
        );

        // A Hello whose only option overruns has no options array.
        let data = pim(TYPE_HELLO, 0, &[0, 1, 0, 2]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "options"));
        assert_eq!(top(&buf, "data").range, 4..8);
    }

    /// A dummy IPv4 header of a Null-Register (RFC 7761, Section 4.9.3).
    const IPV4_HEADER: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 103, 0, 0, 192, 0, 2, 1, 239, 1, 1, 1,
    ];

    #[test]
    fn parse_register_ipv4() {
        let mut body = vec![0x80, 0, 0, 0]; // B=1, N=0
        body.extend_from_slice(&IPV4_HEADER);
        let data = pim(TYPE_REGISTER, 0, &body);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        assert_eq!(layer(&buf).range, 0..8);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("Register")
        );
        assert_eq!(top(&buf, "border").value, FieldValue::U8(1));
        assert_eq!(top(&buf, "null_register").value, FieldValue::U8(0));
    }

    #[test]
    fn parse_register_ipv6() {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&[0x60; 40]);
        let data = pim(TYPE_REGISTER, 0, &body);
        let (_, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn parse_null_register() {
        let mut body = vec![0x40, 0, 0, 0];
        body.extend_from_slice(&IPV4_HEADER);
        let data = pim(TYPE_REGISTER, 0, &body);
        let (buf, result) = dissect(&data);
        assert_eq!(top(&buf, "null_register").value, FieldValue::U8(1));
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn parse_null_register_dummy_pim_header() {
        // PIM Version 0 and Type 0 after the dummy IPv6 header of a
        // Register.
        let data = [0x00, 0x00, 0x12, 0x34];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("PIM", None, &[], 0..8);
        buf.end_layer();
        buf.begin_layer("IPv6", None, &[], 8..48);
        buf.end_layer();
        let result = PimDissector.dissect(&data, &mut buf, 48).unwrap();
        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(top(&buf, "version").value, FieldValue::U8(0));
        assert_eq!(top(&buf, "checksum").value, FieldValue::U16(0x1234));
        assert!(!has_top(&buf, "type"));

        // Outside a Register it is an unsupported version.
        let mut buf = DissectBuffer::new();
        assert!(PimDissector.dissect(&data, &mut buf, 0).is_err());
    }

    #[test]
    fn register_unknown_inner_packet() {
        let data = pim(TYPE_REGISTER, 0, &[0, 0, 0, 0, 0x10, 1]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(top(&buf, "data").value, FieldValue::Bytes(&[0x10, 1]));

        // An IPv4 header with an IHL below 5 words, and a short IPv6 header.
        let data = pim(TYPE_REGISTER, 0, &[0, 0, 0, 0, 0x41, 0, 0, 20]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(top(&buf, "data").range, 8..12);
        let data = pim(TYPE_REGISTER, 0, &[0, 0, 0, 0, 0x60, 0, 0, 0]);
        let (_, result) = dissect(&data);
        assert_eq!(result.next, DispatchHint::End);

        // Too short for the B/N word.
        let data = pim(TYPE_REGISTER, 0, &[0, 0]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "border"));
        assert_eq!(top(&buf, "data").value, FieldValue::Bytes(&[0, 0]));
    }

    #[test]
    fn parse_register_stop() {
        let mut body = eg4(0, 32, [239, 1, 1, 1]);
        body.extend(eu4([192, 0, 2, 1]));
        let data = pim(TYPE_REGISTER_STOP, 0, &body);
        let (buf, _) = dissect(&data);
        let g = children(&buf, top(&buf, "group"));
        assert_eq!(
            child(&g, "address").value,
            FieldValue::Ipv4Addr([239, 1, 1, 1])
        );
        assert_eq!(child(&g, "mask_len").value, FieldValue::U8(32));
        assert_eq!(child(&g, "b_bit").value, FieldValue::U8(0));
        let s = children(&buf, top(&buf, "source"));
        assert_eq!(
            child(&s, "address").value,
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert_eq!(top(&buf, "source").range, 12..18);
        assert!(!has_top(&buf, "data"));
    }

    fn join_prune_body() -> Vec<u8> {
        let mut body = eu4([10, 0, 0, 2]);
        body.extend_from_slice(&[0, 1, 0, 210]);
        body.extend(eg4(0, 32, [239, 1, 1, 1]));
        body.extend_from_slice(&[0, 1, 0, 1]);
        body.extend(es4(0x07, [10, 0, 0, 100])); // (*,G): S, WC, RPT
        body.extend(es4(0x05, [192, 0, 2, 1])); // (S,G,rpt): S, RPT
        body
    }

    #[test]
    fn parse_join_prune_ipv4() {
        let data = pim(TYPE_JOIN_PRUNE, 0, &join_prune_body());
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("Join/Prune")
        );
        let up = children(&buf, top(&buf, "upstream_neighbor"));
        assert_eq!(
            child(&up, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
        assert_eq!(top(&buf, "num_groups").value, FieldValue::U8(1));
        assert_eq!(top(&buf, "holdtime").value, FieldValue::U16(210));
        let sets = children(&buf, top(&buf, "group_sets"));
        assert_eq!(sets.len(), 1);
        assert_eq!(top(&buf, "group_sets").range, 14..data.len());
        assert_eq!(sets[0].range, 14..data.len());
        let set = children(&buf, sets[0]);
        let g = children(&buf, child(&set, "group"));
        assert_eq!(
            child(&g, "address").value,
            FieldValue::Ipv4Addr([239, 1, 1, 1])
        );
        assert_eq!(child(&set, "num_joined_sources").value, FieldValue::U16(1));
        let joined = children(&buf, child(&set, "joined_sources"));
        let j = children(&buf, joined[0]);
        assert_eq!(child(&j, "s_bit").value, FieldValue::U8(1));
        assert_eq!(child(&j, "w_bit").value, FieldValue::U8(1));
        assert_eq!(child(&j, "r_bit").value, FieldValue::U8(1));
        assert_eq!(
            child(&j, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 100])
        );
        let pruned = children(&buf, child(&set, "pruned_sources"));
        let p = children(&buf, pruned[0]);
        assert_eq!(child(&p, "w_bit").value, FieldValue::U8(0));
        assert_eq!(child(&p, "r_bit").value, FieldValue::U8(1));
        assert_eq!(child(&set, "pruned_sources").range, 34..42);
    }

    #[test]
    fn parse_join_prune_ipv6() {
        let up = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let group = [0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut body = vec![2, 0];
        body.extend_from_slice(&up);
        body.extend_from_slice(&[0, 1, 0, 210]);
        body.extend_from_slice(&[2, 0, 0, 128]);
        body.extend_from_slice(&group);
        body.extend_from_slice(&[0, 0, 0, 0]);
        let data = pim(TYPE_JOIN_PRUNE, 0, &body);
        let (buf, _) = dissect(&data);
        let u = children(&buf, top(&buf, "upstream_neighbor"));
        assert_eq!(child(&u, "address").value, FieldValue::Ipv6Addr(up));
        let sets = children(&buf, top(&buf, "group_sets"));
        let set = children(&buf, sets[0]);
        assert!(set.iter().all(|f| f.name() != "joined_sources"));
        let g = children(&buf, child(&set, "group"));
        assert_eq!(child(&g, "address").value, FieldValue::Ipv6Addr(group));
        assert!(!has_top(&buf, "data"));
    }

    #[test]
    fn parse_join_prune_join_attributes() {
        let mut body = eu4([10, 0, 0, 2]);
        body.extend_from_slice(&[0, 1, 0, 210]);
        body.extend(eg4(0, 32, [232, 1, 1, 1]));
        body.extend_from_slice(&[0, 1, 0, 0]);
        // Encoding type 1: source then an RPF Vector attribute (F=1, E=0)
        // and an MT-ID attribute (F=0, E=1).
        body.extend_from_slice(&[1, 1, 4, 32, 192, 0, 2, 1]);
        body.extend_from_slice(&[0x80, 4, 10, 9, 9, 9]);
        body.extend_from_slice(&[0x42, 2, 0, 5]);
        let data = pim(TYPE_JOIN_PRUNE, 0, &body);
        let (buf, _) = dissect(&data);
        let sets = children(&buf, top(&buf, "group_sets"));
        let set = children(&buf, sets[0]);
        let joined = children(&buf, child(&set, "joined_sources"));
        let j = children(&buf, joined[0]);
        assert_eq!(child(&j, "encoding_type").value, FieldValue::U8(1));
        let attrs = children(&buf, child(&j, "join_attributes"));
        assert_eq!(attrs.len(), 2);
        let a0 = children(&buf, attrs[0]);
        assert_eq!(child(&a0, "f_bit").value, FieldValue::U8(1));
        assert_eq!(child(&a0, "e_bit").value, FieldValue::U8(0));
        assert_eq!(display(&buf, child(&a0, "type")), Some("RPF Vector TLV"));
        assert_eq!(child(&a0, "value").value, FieldValue::Bytes(&[10, 9, 9, 9]));
        let a1 = children(&buf, attrs[1]);
        assert_eq!(child(&a1, "e_bit").value, FieldValue::U8(1));
        assert_eq!(
            display(&buf, child(&a1, "type")),
            Some("MT-ID Join Attribute")
        );
        assert!(!has_top(&buf, "data"));
    }

    #[test]
    fn join_prune_truncated_source() {
        let mut body = join_prune_body();
        body.truncate(body.len() - 3);
        let data = pim(TYPE_JOIN_PRUNE, 0, &body);
        let (buf, _) = dissect(&data);
        // Only complete group sets are decoded.
        assert!(!has_top(&buf, "group_sets"));
        assert_eq!(top(&buf, "holdtime").value, FieldValue::U16(210));
        assert_eq!(top(&buf, "data").range, 14..data.len());

        // Truncated in the holdtime word and in the group set counts.
        let data = pim(TYPE_JOIN_PRUNE, 0, &[1, 0, 10, 0, 0, 2, 0, 1]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "holdtime"));
        assert_eq!(top(&buf, "data").range, 10..12);
        let mut body = eu4([10, 0, 0, 2]);
        body.extend_from_slice(&[0, 1, 0, 210]);
        body.extend(eg4(0, 32, [239, 1, 1, 1]));
        let data = pim(TYPE_JOIN_PRUNE, 0, &body);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "group_sets"));
        assert_eq!(top(&buf, "data").range, 14..22);
    }

    #[test]
    fn unknown_address_family_kept_as_data() {
        let data = pim(TYPE_JOIN_PRUNE, 0, &[99, 0, 1, 2, 3, 4]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "upstream_neighbor"));
        assert_eq!(top(&buf, "data").range, 4..10);
        // Unknown encoding type.
        let data = pim(TYPE_REGISTER_STOP, 0, &[1, 7, 0, 32, 239, 1, 1, 1]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "group"));
    }

    #[test]
    fn parse_graft() {
        let data = pim(TYPE_GRAFT, 0, &join_prune_body());
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("Graft")
        );
        assert_eq!(children(&buf, top(&buf, "group_sets")).len(), 1);
    }

    #[test]
    fn parse_bootstrap() {
        let mut body = vec![0x12, 0x34, 30, 64];
        body.extend(eu4([10, 0, 0, 9]));
        body.extend(eg4(0x01, 4, [239, 0, 0, 0])); // Z bit, 239.0.0.0/4
        body.extend_from_slice(&[1, 1, 0, 0]);
        body.extend(eu4([10, 0, 0, 100]));
        body.extend_from_slice(&[0, 150, 192, 0]);
        let data = pim(TYPE_BOOTSTRAP, 0x80, &body);
        let (buf, _) = dissect(&data);
        assert_eq!(top(&buf, "no_forward").value, FieldValue::U8(1));
        assert_eq!(top(&buf, "fragment_tag").value, FieldValue::U16(0x1234));
        assert_eq!(top(&buf, "hash_mask_len").value, FieldValue::U8(30));
        assert_eq!(top(&buf, "bsr_priority").value, FieldValue::U8(64));
        let bsr = children(&buf, top(&buf, "bsr_address"));
        assert_eq!(
            child(&bsr, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 9])
        );
        let ranges = children(&buf, top(&buf, "group_ranges"));
        assert_eq!(ranges.len(), 1);
        let r = children(&buf, ranges[0]);
        let g = children(&buf, child(&r, "group"));
        assert_eq!(child(&g, "z_bit").value, FieldValue::U8(1));
        assert_eq!(child(&g, "mask_len").value, FieldValue::U8(4));
        assert_eq!(child(&r, "rp_count").value, FieldValue::U8(1));
        assert_eq!(child(&r, "frag_rp_count").value, FieldValue::U8(1));
        let rps = children(&buf, child(&r, "rps"));
        let rp = children(&buf, rps[0]);
        assert_eq!(child(&rp, "holdtime").value, FieldValue::U16(150));
        assert_eq!(child(&rp, "priority").value, FieldValue::U8(192));
        let a = children(&buf, child(&rp, "address"));
        assert_eq!(
            child(&a, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 100])
        );
        assert_eq!(ranges[0].range, 14..data.len());
        assert!(!has_top(&buf, "data"));
    }

    #[test]
    fn bootstrap_truncated_rp() {
        let mut body = vec![0, 1, 30, 64];
        body.extend(eu4([10, 0, 0, 9]));
        body.extend(eg4(0, 4, [224, 0, 0, 0]));
        body.extend_from_slice(&[2, 2, 0, 0]);
        body.extend(eu4([10, 0, 0, 100]));
        body.extend_from_slice(&[0, 150, 0, 0]);
        body.extend(eu4([10, 0, 0, 101]));
        body.extend_from_slice(&[0, 150]);
        let data = pim(TYPE_BOOTSTRAP, 0, &body);
        let (buf, _) = dissect(&data);
        // Only complete group ranges are decoded.
        assert!(!has_top(&buf, "group_ranges"));
        assert_eq!(top(&buf, "data").range, 14..data.len());

        // Bootstrap truncated in its fixed part and in the BSR address.
        let data = pim(TYPE_BOOTSTRAP, 0, &[0, 1, 30]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "fragment_tag"));
        let data = pim(TYPE_BOOTSTRAP, 0, &[0, 1, 30, 64, 1, 0, 10]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "bsr_address"));
        assert_eq!(top(&buf, "data").range, 8..11);
    }

    #[test]
    fn parse_assert() {
        let mut body = eg4(0, 32, [239, 1, 1, 1]);
        body.extend(eu4([0, 0, 0, 0]));
        body.extend_from_slice(&0x8000_0065u32.to_be_bytes());
        body.extend_from_slice(&20u32.to_be_bytes());
        let data = pim(TYPE_ASSERT, 0, &body);
        let (buf, _) = dissect(&data);
        assert_eq!(top(&buf, "rpt_bit").value, FieldValue::U8(1));
        assert_eq!(top(&buf, "metric_preference").value, FieldValue::U32(101));
        assert_eq!(top(&buf, "metric").value, FieldValue::U32(20));
        assert!(!has_top(&buf, "data"));

        let data = pim(TYPE_ASSERT, 0, &eg4(0, 32, [239, 1, 1, 1]));
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "metric"));
    }

    #[test]
    fn parse_candidate_rp_adv() {
        let mut body = vec![2, 0, 0, 150];
        body.extend(eu4([10, 0, 0, 100]));
        body.extend(eg4(0, 4, [224, 0, 0, 0]));
        body.extend(eg4(0x80, 8, [239, 0, 0, 0]));
        let data = pim(TYPE_CANDIDATE_RP_ADV, 0, &body);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("Candidate-RP-Advertisement")
        );
        assert_eq!(top(&buf, "prefix_count").value, FieldValue::U8(2));
        assert_eq!(top(&buf, "priority").value, FieldValue::U8(0));
        assert_eq!(top(&buf, "holdtime").value, FieldValue::U16(150));
        let groups = children(&buf, top(&buf, "groups"));
        assert_eq!(groups.len(), 2);
        let g = children(&buf, groups[1]);
        assert_eq!(child(&g, "b_bit").value, FieldValue::U8(1));
        assert!(!has_top(&buf, "data"));

        let data = pim(
            TYPE_CANDIDATE_RP_ADV,
            0,
            &[0, 0, 0, 150, 1, 0, 10, 0, 0, 100],
        );
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "groups"));
        let data = pim(TYPE_CANDIDATE_RP_ADV, 0, &[1, 0]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "prefix_count"));
        let data = pim(TYPE_CANDIDATE_RP_ADV, 0, &[1, 0, 0, 150, 1]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "rp_address"));
    }

    #[test]
    fn parse_state_refresh() {
        let mut body = eg4(0, 32, [239, 1, 1, 1]);
        body.extend(eu4([192, 0, 2, 1]));
        body.extend(eu4([10, 0, 0, 1]));
        body.extend_from_slice(&110u32.to_be_bytes());
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(&[24, 16, 0xA0, 60]); // P=1, N=0, O=1
        let data = pim(TYPE_STATE_REFRESH, 0, &body);
        let (buf, _) = dissect(&data);
        let o = children(&buf, top(&buf, "originator"));
        assert_eq!(
            child(&o, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(top(&buf, "rpt_bit").value, FieldValue::U8(0));
        assert_eq!(top(&buf, "metric_preference").value, FieldValue::U32(110));
        assert_eq!(top(&buf, "masklen").value, FieldValue::U8(24));
        assert_eq!(top(&buf, "ttl").value, FieldValue::U8(16));
        assert_eq!(top(&buf, "prune_indicator").value, FieldValue::U8(1));
        assert_eq!(top(&buf, "prune_now").value, FieldValue::U8(0));
        assert_eq!(top(&buf, "assert_override").value, FieldValue::U8(1));
        assert_eq!(top(&buf, "interval").value, FieldValue::U8(60));
        assert!(!has_top(&buf, "data"));

        // Truncated after the addresses, after the metrics, and in them.
        let data = pim(TYPE_STATE_REFRESH, 0, &body[..20]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "metric"));
        let data = pim(TYPE_STATE_REFRESH, 0, &body[..28]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "ttl"));
        let data = pim(TYPE_STATE_REFRESH, 0, &body[..12]);
        let (buf, _) = dissect(&data);
        assert!(!has_top(&buf, "originator"));
    }

    #[test]
    fn extended_type_subtype() {
        let data = pim(TYPE_DF_ELECTION, 0x20, &[1, 2]);
        let (buf, _) = dissect(&data);
        assert_eq!(top(&buf, "subtype").value, FieldValue::U8(2));
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("DF Election")
        );
        assert_eq!(top(&buf, "data").value, FieldValue::Bytes(&[1, 2]));

        let data = pim(13, 0x10, &[]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("PIM Packed Register-Stop")
        );
        let data = pim(15, 0xF0, &[]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("Reserved")
        );
        let data = pim(14, 0x00, &[]);
        let (buf, _) = dissect(&data);
        assert_eq!(buf.resolve_display_name(layer(&buf), "type_name"), None);
        let data = pim(TYPE_PFM, 0x80, &[]);
        let (buf, _) = dissect(&data);
        assert_eq!(top(&buf, "no_forward").value, FieldValue::U8(1));
    }

    #[test]
    fn unknown_type_kept_as_data() {
        let data = pim(11, 0, &[1, 2, 3]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(layer(&buf), "type_name"),
            Some("ECMP Redirect")
        );
        assert_eq!(top(&buf, "data").value, FieldValue::Bytes(&[1, 2, 3]));
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            PimDissector.dissect(&[0x20, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn reject_unsupported_version() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            PimDissector.dissect(&[0x13, 0, 0, 0], &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            })
        );
        // Version 0 is only the 4-octet dummy header.
        assert!(
            PimDissector
                .dissect(&[0x00, 0, 0, 0, 0], &mut buf, 0)
                .is_err()
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn offsets_are_absolute() {
        let data = pim(TYPE_REGISTER_STOP, 0, &{
            let mut b = eg4(0, 32, [239, 1, 1, 1]);
            b.extend(eu4([192, 0, 2, 1]));
            b
        });
        let mut buf = DissectBuffer::new();
        PimDissector.dissect(&data, &mut buf, 34).unwrap();
        assert_eq!(buf.layers()[0].range, 34..34 + data.len());
        let src = buf.field_by_name(&buf.layers()[0], "source").unwrap();
        assert_eq!(src.range, 46..52);
    }

    #[test]
    fn registry_names() {
        assert!((0..=12).all(|t| message_type_name(t).is_some()));
        assert_eq!(message_type_name(13), None);
        assert_eq!(extended_type_name(13, 0), Some("PIM Packed Null-Register"));
        assert!((17..=42).all(|t| hello_option_name(t).is_some()));
        assert_eq!(hello_option_name(3), None);
        assert!((0..=6).all(|t| join_attribute_name(t).is_some()));
        assert_eq!(join_attribute_name(7), None);
        assert_eq!(address_family_name(2), Some("IPv6"));
        assert_eq!(address_family_name(251), Some("Private Use"));
        assert_eq!(address_family_name(3), None);
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(PimDissector.name(), "Protocol Independent Multicast");
        assert_eq!(PimDissector.short_name(), "PIM");
        assert_eq!(PimDissector.layer(), Some(ProtocolLayer::Network));
        assert_eq!(PimDissector.references()[0].id, "RFC 7761");
        assert_eq!(PimDissector.field_descriptors().len(), FD_DATA + 1);
        let mut names: Vec<_> = FIELD_DESCRIPTORS.iter().map(|d| d.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FIELD_DESCRIPTORS.len());
    }
}
