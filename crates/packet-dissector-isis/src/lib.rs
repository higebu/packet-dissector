//! IS-IS (Intermediate System to Intermediate System) dissector.
//!
//! ## References
//! - ISO/IEC 10589:2002 (base IS-IS protocol)
//! - RFC 1195: <https://www.rfc-editor.org/rfc/rfc1195>
//! - RFC 5302: <https://www.rfc-editor.org/rfc/rfc5302>
//! - RFC 5304: <https://www.rfc-editor.org/rfc/rfc5304>
//! - RFC 5305: <https://www.rfc-editor.org/rfc/rfc5305>
//! - RFC 5308: <https://www.rfc-editor.org/rfc/rfc5308>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, MacAddr, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32};

// ---------------------------------------------------------------------------
// Constants — ISO/IEC 10589:2002, Section 9
// ---------------------------------------------------------------------------

/// IS-IS NLPID (Intra-domain Routing Protocol Discriminator).
/// ISO/IEC 10589:2002, Section 8.
const NLPID_ISIS: u8 = 0x83;

/// Common fixed header size in bytes.
/// ISO/IEC 10589:2002, Section 9.5.
const COMMON_HEADER_SIZE: usize = 8;

/// PDU type: L1 LAN IS-IS Hello.
/// ISO/IEC 10589:2002, Section 9.7.
const PDU_TYPE_L1_LAN_IIH: u8 = 15;

/// PDU type: L2 LAN IS-IS Hello.
/// ISO/IEC 10589:2002, Section 9.8.
const PDU_TYPE_L2_LAN_IIH: u8 = 16;

/// PDU type: Point-to-Point IS-IS Hello.
/// ISO/IEC 10589:2002, Section 9.9.
const PDU_TYPE_P2P_IIH: u8 = 17;

/// PDU type: L1 Link State PDU.
/// ISO/IEC 10589:2002, Section 9.10.
const PDU_TYPE_L1_LSP: u8 = 18;

/// PDU type: L2 Link State PDU.
/// ISO/IEC 10589:2002, Section 9.11.
const PDU_TYPE_L2_LSP: u8 = 20;

/// PDU type: L1 Complete Sequence Numbers PDU.
/// ISO/IEC 10589:2002, Section 9.12.
const PDU_TYPE_L1_CSNP: u8 = 24;

/// PDU type: L2 Complete Sequence Numbers PDU.
/// ISO/IEC 10589:2002, Section 9.13.
const PDU_TYPE_L2_CSNP: u8 = 25;

/// PDU type: L1 Partial Sequence Numbers PDU.
/// ISO/IEC 10589:2002, Section 9.14.
const PDU_TYPE_L1_PSNP: u8 = 26;

/// PDU type: L2 Partial Sequence Numbers PDU.
/// ISO/IEC 10589:2002, Section 9.15.
const PDU_TYPE_L2_PSNP: u8 = 27;

// ---------------------------------------------------------------------------
// TLV type codes
// ---------------------------------------------------------------------------

/// TLV type: Area Addresses — ISO/IEC 10589:2002.
const TLV_AREA_ADDRESSES: u8 = 1;

/// TLV type: IS Neighbors (IIH) — ISO/IEC 10589:2002.
const TLV_IS_NEIGHBORS_IIH: u8 = 6;

/// TLV type: Padding — ISO/IEC 10589:2002.
const TLV_PADDING: u8 = 8;

/// TLV type: LSP Entries — ISO/IEC 10589:2002.
const TLV_LSP_ENTRIES: u8 = 9;

/// TLV type: Authentication — ISO/IEC 10589:2002, RFC 5304.
const TLV_AUTHENTICATION: u8 = 10;

/// TLV type: Extended IS Reachability — RFC 5305, Section 3.
const TLV_EXTENDED_IS_REACHABILITY: u8 = 22;

/// TLV type: IP Internal Reachability — RFC 1195.
const TLV_IP_INTERNAL_REACHABILITY: u8 = 128;

/// TLV type: Protocols Supported — RFC 1195.
const TLV_PROTOCOLS_SUPPORTED: u8 = 129;

/// TLV type: IP External Reachability — RFC 1195.
const TLV_IP_EXTERNAL_REACHABILITY: u8 = 130;

/// TLV type: IP Interface Address — RFC 1195.
const TLV_IP_INTERFACE_ADDRESS: u8 = 132;

/// TLV type: TE Router ID — RFC 5305, Section 4.3.
const TLV_TE_ROUTER_ID: u8 = 134;

/// TLV type: Extended IP Reachability — RFC 5305, Section 4.
const TLV_EXTENDED_IP_REACHABILITY: u8 = 135;

/// TLV type: Dynamic Hostname — RFC 5301.
const TLV_DYNAMIC_HOSTNAME: u8 = 137;

/// TLV type: Restart — RFC 8706.
const TLV_RESTART: u8 = 211;

/// TLV type: MT IS Neighbors — RFC 5120.
const TLV_MT_IS_NEIGHBORS: u8 = 222;

/// TLV type: IPv6 Interface Address — RFC 5308, Section 2.
const TLV_IPV6_INTERFACE_ADDRESS: u8 = 232;

/// TLV type: MT IP Reachability — RFC 5120.
const TLV_MT_IP_REACHABILITY: u8 = 235;

/// TLV type: IPv6 Reachability — RFC 5308, Section 5.
const TLV_IPV6_REACHABILITY: u8 = 236;

/// TLV type: MT IPv6 Reachability — RFC 5120.
const TLV_MT_IPV6_REACHABILITY: u8 = 237;

/// TLV type: P2P Three-Way Adjacency — RFC 5303.
const TLV_P2P_THREE_WAY_ADJ: u8 = 240;

/// TLV type: Router Capability — RFC 7981.
const TLV_ROUTER_CAPABILITY: u8 = 242;

// ---------------------------------------------------------------------------
// Name lookup helpers
// ---------------------------------------------------------------------------

/// Returns a human-readable name for IS-IS PDU type values.
fn pdu_type_name(v: u8) -> Option<&'static str> {
    match v {
        PDU_TYPE_L1_LAN_IIH => Some("L1 LAN IIH"),
        PDU_TYPE_L2_LAN_IIH => Some("L2 LAN IIH"),
        PDU_TYPE_P2P_IIH => Some("P2P IIH"),
        PDU_TYPE_L1_LSP => Some("L1 LSP"),
        PDU_TYPE_L2_LSP => Some("L2 LSP"),
        PDU_TYPE_L1_CSNP => Some("L1 CSNP"),
        PDU_TYPE_L2_CSNP => Some("L2 CSNP"),
        PDU_TYPE_L1_PSNP => Some("L1 PSNP"),
        PDU_TYPE_L2_PSNP => Some("L2 PSNP"),
        _ => None,
    }
}

/// Returns a human-readable name for IS-IS TLV type codes.
///
/// Covers all IANA-assigned IS-IS TLV codepoints commonly seen in real deployments.
/// <https://www.iana.org/assignments/isis-tlv-codepoints/>
fn tlv_type_name(v: u8) -> Option<&'static str> {
    match v {
        TLV_AREA_ADDRESSES => Some("Area Addresses"), // 1, ISO 10589
        2 => Some("IS Neighbors (LSP)"),              // ISO 10589
        3 => Some("ES Neighbors"),                    // ISO 10589
        4 => Some("Partition Designated L2 IS"),      // ISO 10589
        5 => Some("Prefix Neighbors"),                // ISO 10589
        TLV_IS_NEIGHBORS_IIH => Some("IS Neighbors"), // 6, ISO 10589
        7 => Some("Instance Identifier"),             // RFC 8202
        TLV_PADDING => Some("Padding"),               // 8, ISO 10589
        TLV_LSP_ENTRIES => Some("LSP Entries"),       // 9, ISO 10589
        TLV_AUTHENTICATION => Some("Authentication"), // 10, RFC 5304
        11 => Some("ESN"),                            // RFC 7602
        12 => Some("Optional Checksum"),              // RFC 3358
        13 => Some("Purge Originator Identification"), // RFC 6232
        14 => Some("LSP Buffer Size"),                // ISO 10589
        15 => Some("Router-Fingerprint"),             // RFC 8196
        16 => Some("Reverse Metric"),                 // RFC 8500
        TLV_EXTENDED_IS_REACHABILITY => Some("Extended IS Reachability"), // 22, RFC 5305
        23 => Some("IS Neighbor Attribute"),          // RFC 5311
        24 => Some("IS Alias ID"),                    // RFC 5311
        25 => Some("L2 Bundle Member Attributes"),    // RFC 8668
        27 => Some("SRv6 Locator"),                   // RFC 9352
        TLV_IP_INTERNAL_REACHABILITY => Some("IP Internal Reachability"), // 128, RFC 1195
        TLV_PROTOCOLS_SUPPORTED => Some("Protocols Supported"), // 129, RFC 1195
        TLV_IP_EXTERNAL_REACHABILITY => Some("IP External Reachability"), // 130, RFC 1195
        131 => Some("Inter-Domain Routing Protocol Info"), // RFC 1195
        TLV_IP_INTERFACE_ADDRESS => Some("IP Interface Address"), // 132, RFC 1195
        TLV_TE_ROUTER_ID => Some("TE Router ID"),     // 134, RFC 5305
        TLV_EXTENDED_IP_REACHABILITY => Some("Extended IP Reachability"), // 135, RFC 5305
        TLV_DYNAMIC_HOSTNAME => Some("Dynamic Hostname"), // 137, RFC 5301
        138 => Some("GMPLS SRLG"),                    // RFC 5307
        139 => Some("IPv6 SRLG"),                     // RFC 6119
        140 => Some("IPv6 TE Router ID"),             // RFC 6119
        141 => Some("Inter-AS Reachability Information"), // RFC 9346
        143 => Some("MT Port Capability"),            // RFC 6165
        144 => Some("MT Capability"),                 // RFC 6329
        148 => Some("BFD Enabled"),                   // RFC 6213
        149 => Some("Segment Identifier / Label Binding"), // RFC 8667
        150 => Some("MT Segment Identifier / Label Binding"), // RFC 8667
        161 => Some("Flood Reflection"),              // RFC 9377
        TLV_RESTART => Some("Restart"),               // 211, RFC 8706
        TLV_MT_IS_NEIGHBORS => Some("MT IS Neighbors"), // 222, RFC 5120
        223 => Some("MT IS Neighbor Attribute"),      // RFC 5311
        229 => Some("Multi-Topology"),                // RFC 5120
        TLV_IPV6_INTERFACE_ADDRESS => Some("IPv6 Interface Address"), // 232, RFC 5308
        233 => Some("IPv6 Global Interface Address"), // RFC 6119
        TLV_MT_IP_REACHABILITY => Some("MT IP Reachability"), // 235, RFC 5120
        TLV_IPV6_REACHABILITY => Some("IPv6 Reachability"), // 236, RFC 5308
        TLV_MT_IPV6_REACHABILITY => Some("MT IPv6 Reachability"), // 237, RFC 5120
        TLV_P2P_THREE_WAY_ADJ => Some("P2P Three-Way Adjacency"), // 240, RFC 5303
        TLV_ROUTER_CAPABILITY => Some("Router Capability"), // 242, RFC 7981
        243 => Some("Scope Flooding Support"),        // RFC 7356
        _ => None,
    }
}

/// Returns a human-readable name for NLPID values.
/// RFC 1195, Section 1.3.
fn nlpid_name(v: u8) -> Option<&'static str> {
    match v {
        0xCC => Some("IPv4"),
        0x8E => Some("IPv6"),
        0x81 => Some("ISO 8473 (CLNP)"),
        0x82 => Some("ISO 9542 (ES-IS)"),
        0x83 => Some("ISO 10589 (IS-IS)"),
        _ => None,
    }
}

/// Returns a human-readable name for IS-IS restart flags (5 bits).
///
/// RFC 8706, Section 3.
fn restart_flags_name(flags: u8) -> &'static str {
    /// Pre-computed flag names for all 32 combinations of the 5-bit restart flags.
    static TABLE: [&str; 32] = [
        "none",           // 0b00000
        "RR",             // 0b00001
        "RA",             // 0b00010
        "RR|RA",          // 0b00011
        "SA",             // 0b00100
        "RR|SA",          // 0b00101
        "RA|SA",          // 0b00110
        "RR|RA|SA",       // 0b00111
        "PR",             // 0b01000
        "RR|PR",          // 0b01001
        "RA|PR",          // 0b01010
        "RR|RA|PR",       // 0b01011
        "SA|PR",          // 0b01100
        "RR|SA|PR",       // 0b01101
        "RA|SA|PR",       // 0b01110
        "RR|RA|SA|PR",    // 0b01111
        "PA",             // 0b10000
        "RR|PA",          // 0b10001
        "RA|PA",          // 0b10010
        "RR|RA|PA",       // 0b10011
        "SA|PA",          // 0b10100
        "RR|SA|PA",       // 0b10101
        "RA|SA|PA",       // 0b10110
        "RR|RA|SA|PA",    // 0b10111
        "PR|PA",          // 0b11000
        "RR|PR|PA",       // 0b11001
        "RA|PR|PA",       // 0b11010
        "RR|RA|PR|PA",    // 0b11011
        "SA|PR|PA",       // 0b11100
        "RR|SA|PR|PA",    // 0b11101
        "RA|SA|PR|PA",    // 0b11110
        "RR|RA|SA|PR|PA", // 0b11111
    ];
    TABLE[(flags & 0x1F) as usize]
}

// System ID (6 bytes), LSP ID (8 bytes), Node ID (7 bytes), and Area
// Addresses are stored as raw `FieldValue::Bytes` slices into the packet
// data.  String formatting (e.g., "0102.0304.0506") is deferred to
// serialization time via `FormatFn` if needed.

// ---------------------------------------------------------------------------
// Field descriptor indices for [`FIELD_DESCRIPTORS`].
// ---------------------------------------------------------------------------

const FD_NLPID: usize = 0;
const FD_HEADER_LENGTH: usize = 1;
const FD_VERSION: usize = 2;
const FD_ID_LENGTH: usize = 3;
const FD_PDU_TYPE: usize = 4;
const FD_MAX_AREA_ADDRESSES: usize = 5;
const FD_CIRCUIT_TYPE: usize = 6;
const FD_SOURCE_ID: usize = 7;
const FD_HOLDING_TIME: usize = 8;
const FD_PDU_LENGTH: usize = 9;
const FD_PRIORITY: usize = 10;
const FD_LAN_ID: usize = 11;
const FD_LOCAL_CIRCUIT_ID: usize = 12;
const FD_REMAINING_LIFETIME: usize = 13;
const FD_LSP_ID: usize = 14;
const FD_SEQUENCE_NUMBER: usize = 15;
const FD_CHECKSUM: usize = 16;
const FD_TYPE_BLOCK: usize = 17;
const FD_START_LSP_ID: usize = 18;
const FD_END_LSP_ID: usize = 19;
const FD_TLVS: usize = 20;

// ---------------------------------------------------------------------------
// TLV child field descriptor indices for [`TLV_CHILD_FIELDS`].
// ---------------------------------------------------------------------------

const FD_TLV_TYPE: usize = 0;
const FD_TLV_LENGTH: usize = 1;
const FD_TLV_AREAS: usize = 2;
const FD_TLV_PROTOCOLS: usize = 3;
const FD_TLV_ADDRESSES: usize = 4;
const FD_TLV_ROUTER_ID: usize = 5;
const FD_TLV_HOSTNAME: usize = 6;
const FD_TLV_NEIGHBORS: usize = 7;
const FD_TLV_PREFIXES: usize = 8;
const FD_TLV_ENTRIES: usize = 9;
const FD_TLV_STATE: usize = 10;
const FD_TLV_AUTH_TYPE: usize = 11;
const FD_TLV_FLAGS: usize = 12;
const FD_TLV_REMAINING_TIME: usize = 13;
const FD_TLV_RAW: usize = 14;

// ---------------------------------------------------------------------------
// Nested child field descriptors for TLV-specific objects.
// ---------------------------------------------------------------------------

/// Field descriptor indices for [`PROTOCOL_CHILD_FIELDS`].
const FD_PROTO_NLPID: usize = 0;

/// Child fields for Protocol Supported entries (TLV 129).
static PROTOCOL_CHILD_FIELDS: &[FieldDescriptor] = &[FieldDescriptor {
    name: "nlpid",
    display_name: "NLPID",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(n) => nlpid_name(*n),
        _ => None,
    }),
    format_fn: None,
}];

/// Field descriptor indices for [`EXT_IS_REACH_CHILD_FIELDS`].
const FD_EIR_NEIGHBOR_ID: usize = 0;
const FD_EIR_METRIC: usize = 1;

/// Child fields for Extended IS Reachability entries (TLV 22).
static EXT_IS_REACH_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("neighbor_id", "Neighbor ID", FieldType::Bytes),
    FieldDescriptor::new("metric", "Metric", FieldType::U32),
];

/// Field descriptor indices for [`EXT_IP_REACH_CHILD_FIELDS`].
const FD_EIPR_PREFIX: usize = 0;
const FD_EIPR_PREFIX_LENGTH: usize = 1;
const FD_EIPR_METRIC: usize = 2;

/// Child fields for Extended IP Reachability entries (TLV 135).
static EXT_IP_REACH_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("prefix", "Prefix", FieldType::Ipv4Addr),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8),
    FieldDescriptor::new("metric", "Metric", FieldType::U32),
];

/// Field descriptor indices for [`IPV6_REACH_CHILD_FIELDS`].
const FD_IP6R_PREFIX: usize = 0;
const FD_IP6R_PREFIX_LENGTH: usize = 1;
const FD_IP6R_METRIC: usize = 2;

/// Child fields for IPv6 Reachability entries (TLV 236).
static IPV6_REACH_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("prefix", "Prefix", FieldType::Ipv6Addr),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8),
    FieldDescriptor::new("metric", "Metric", FieldType::U32),
];

/// Field descriptor indices for [`IP_REACH_CHILD_FIELDS`].
const FD_IPR_IP_ADDRESS: usize = 0;
const FD_IPR_SUBNET_MASK: usize = 1;
const FD_IPR_METRIC: usize = 2;

/// Child fields for IP Internal/External Reachability entries (TLV 128/130).
static IP_REACH_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ip_address", "IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("subnet_mask", "Subnet Mask", FieldType::Ipv4Addr),
    FieldDescriptor::new("metric", "Metric", FieldType::U8),
];

/// Field descriptor indices for [`LSP_ENTRY_CHILD_FIELDS`].
const FD_LSPE_LSP_ID: usize = 0;
const FD_LSPE_SEQUENCE_NUMBER: usize = 1;
const FD_LSPE_REMAINING_LIFETIME: usize = 2;
const FD_LSPE_CHECKSUM: usize = 3;

/// Child fields for LSP Entries (TLV 9).
static LSP_ENTRY_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("lsp_id", "LSP ID", FieldType::Bytes),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    FieldDescriptor::new("remaining_lifetime", "Remaining Lifetime", FieldType::U16),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
];

// ---------------------------------------------------------------------------
// TLV child field descriptors
// ---------------------------------------------------------------------------

/// Child fields for a parsed TLV entry.
/// All TLV-specific fields are optional since each TLV type produces different fields.
static TLV_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => tlv_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U8),
    // TLV-specific typed fields (all optional)
    FieldDescriptor::new("areas", "Areas", FieldType::Array).optional(),
    FieldDescriptor::new("protocols", "Protocols", FieldType::Array).optional(),
    FieldDescriptor::new("addresses", "Addresses", FieldType::Array).optional(),
    FieldDescriptor::new("router_id", "Router ID", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("hostname", "Hostname", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("neighbors", "Neighbors", FieldType::Array).optional(),
    FieldDescriptor::new("prefixes", "Prefixes", FieldType::Array).optional(),
    FieldDescriptor::new("entries", "Entries", FieldType::Array).optional(),
    FieldDescriptor {
        name: "state",
        display_name: "State",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(0) => Some("Up"),
            FieldValue::U8(1) => Some("Initializing"),
            FieldValue::U8(2) => Some("Down"),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "auth_type",
        display_name: "Auth Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(0) => Some("Reserved"),
            FieldValue::U8(1) => Some("Cleartext Password"),
            FieldValue::U8(54) => Some("HMAC-MD5"),
            FieldValue::U8(255) => Some("Routing Domain Private"),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "flags",
        display_name: "Flags",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(f) => Some(restart_flags_name(*f)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("remaining_time", "Remaining Time", FieldType::U16).optional(),
    FieldDescriptor::new("raw", "Raw", FieldType::Bytes).optional(),
];

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // Common header fields
    FieldDescriptor::new("nlpid", "NLPID", FieldType::U8),
    FieldDescriptor::new("header_length", "Header Length", FieldType::U8),
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("id_length", "ID Length", FieldType::U8),
    FieldDescriptor {
        name: "pdu_type",
        display_name: "PDU Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => pdu_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("max_area_addresses", "Max Area Addresses", FieldType::U8),
    // IIH-specific fields
    FieldDescriptor::new("circuit_type", "Circuit Type", FieldType::U8).optional(),
    FieldDescriptor::new("source_id", "Source ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("holding_time", "Holding Time", FieldType::U16).optional(),
    FieldDescriptor::new("pdu_length", "PDU Length", FieldType::U16).optional(),
    FieldDescriptor::new("priority", "Priority", FieldType::U8).optional(),
    FieldDescriptor::new("lan_id", "LAN ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("local_circuit_id", "Local Circuit ID", FieldType::U8).optional(),
    // LSP-specific fields
    FieldDescriptor::new("remaining_lifetime", "Remaining Lifetime", FieldType::U16).optional(),
    FieldDescriptor::new("lsp_id", "LSP ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32).optional(),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16).optional(),
    FieldDescriptor::new("type_block", "Type Block", FieldType::U8).optional(),
    // CSNP/PSNP-specific fields
    FieldDescriptor::new("start_lsp_id", "Start LSP ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("end_lsp_id", "End LSP ID", FieldType::Bytes).optional(),
    // TLVs
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(TLV_CHILD_FIELDS),
];

// ---------------------------------------------------------------------------
// TLV value parsing
// ---------------------------------------------------------------------------

/// Parses TLV-type-specific fields and pushes them into the buffer.
/// Returns `true` if typed fields were pushed, `false` for unknown/padding TLVs.
fn parse_tlv_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    tlv_type: u8,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    match tlv_type {
        TLV_AREA_ADDRESSES => parse_area_addresses_fields(buf, value, offset),
        TLV_PROTOCOLS_SUPPORTED => parse_protocols_supported_fields(buf, value, offset),
        TLV_IP_INTERFACE_ADDRESS => parse_ip_address_fields(buf, value, offset),
        TLV_TE_ROUTER_ID => parse_te_router_id_fields(buf, value, offset),
        TLV_DYNAMIC_HOSTNAME => parse_hostname_fields(buf, value, offset),
        TLV_IPV6_INTERFACE_ADDRESS => parse_ipv6_address_fields(buf, value, offset),
        TLV_IS_NEIGHBORS_IIH => parse_is_neighbors_iih_fields(buf, value, offset),
        TLV_EXTENDED_IS_REACHABILITY => parse_extended_is_reach_fields(buf, value, offset),
        TLV_EXTENDED_IP_REACHABILITY => parse_extended_ip_reach_fields(buf, value, offset),
        TLV_IPV6_REACHABILITY => parse_ipv6_reach_fields(buf, value, offset),
        TLV_IP_INTERNAL_REACHABILITY | TLV_IP_EXTERNAL_REACHABILITY => {
            parse_ip_reach_fields(buf, value, offset)
        }
        TLV_LSP_ENTRIES => parse_lsp_entries_fields(buf, value, offset),
        TLV_P2P_THREE_WAY_ADJ => parse_p2p_adj_fields(buf, value, offset),
        TLV_AUTHENTICATION => parse_authentication_fields(buf, value, offset),
        TLV_RESTART => parse_restart_fields(buf, value, offset),
        TLV_PADDING => false,
        _ => false,
    }
}

/// TLV 1: Area Addresses — ISO/IEC 10589:2002.
fn parse_area_addresses_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_AREAS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut i = 0;
    while i < value.len() {
        let addr_len = value[i] as usize;
        i += 1;
        if i + addr_len > value.len() {
            break;
        }
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_AREAS],
            FieldValue::Bytes(&value[i..i + addr_len]),
            offset + i - 1..offset + i + addr_len,
        );
        i += addr_len;
    }
    buf.end_container(array_idx);
    true
}

/// TLV 129: Protocols Supported — RFC 1195.
fn parse_protocols_supported_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_PROTOCOLS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    for (i, &v) in value.iter().enumerate() {
        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_PROTOCOLS],
            FieldValue::Object(0..0),
            offset + i..offset + i + 1,
        );
        buf.push_field(
            &PROTOCOL_CHILD_FIELDS[FD_PROTO_NLPID],
            FieldValue::U8(v),
            offset + i..offset + i + 1,
        );
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
    true
}

/// TLV 132: IP Interface Address — RFC 1195.
fn parse_ip_address_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.len() < 4 || value.len() % 4 != 0 {
        return false;
    }
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_ADDRESSES],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    for (i, c) in value.chunks_exact(4).enumerate() {
        let start = offset + i * 4;
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_ADDRESSES],
            FieldValue::Ipv4Addr([c[0], c[1], c[2], c[3]]),
            start..start + 4,
        );
    }
    buf.end_container(array_idx);
    true
}

/// TLV 134: TE Router ID — RFC 5305, Section 4.3.
fn parse_te_router_id_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.len() < 4 {
        return false;
    }
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_ROUTER_ID],
        FieldValue::Ipv4Addr([value[0], value[1], value[2], value[3]]),
        offset..offset + 4,
    );
    true
}

/// TLV 137: Dynamic Hostname — RFC 5301.
fn parse_hostname_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_HOSTNAME],
        FieldValue::Bytes(value),
        offset..offset + value.len(),
    );
    true
}

/// TLV 232: IPv6 Interface Address — RFC 5308, Section 2.
fn parse_ipv6_address_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.len() < 16 || value.len() % 16 != 0 {
        return false;
    }
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_ADDRESSES],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    for (i, c) in value.chunks_exact(16).enumerate() {
        let start = offset + i * 16;
        let addr: [u8; 16] = c.try_into().unwrap_or([0; 16]);
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_ADDRESSES],
            FieldValue::Ipv6Addr(addr),
            start..start + 16,
        );
    }
    buf.end_container(array_idx);
    true
}

/// TLV 6: IS Neighbors (IIH) — ISO/IEC 10589:2002.
fn parse_is_neighbors_iih_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.is_empty() || value.len() % 6 != 0 {
        return false;
    }
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_NEIGHBORS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    for (i, c) in value.chunks_exact(6).enumerate() {
        let start = offset + i * 6;
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_NEIGHBORS],
            FieldValue::MacAddr(MacAddr([c[0], c[1], c[2], c[3], c[4], c[5]])),
            start..start + 6,
        );
    }
    buf.end_container(array_idx);
    true
}

/// TLV 22: Extended IS Reachability — RFC 5305, Section 3.
fn parse_extended_is_reach_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_NEIGHBORS],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut i = 0;
    while i + 11 <= value.len() {
        let metric = read_be_u24(value, i + 7).unwrap_or_default();
        let sub_tlv_len = value[i + 10] as usize;
        let entry_end = i + 11 + sub_tlv_len;
        if entry_end > value.len() {
            break;
        }
        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_NEIGHBORS],
            FieldValue::Object(0..0),
            offset + i..offset + entry_end,
        );
        buf.push_field(
            &EXT_IS_REACH_CHILD_FIELDS[FD_EIR_NEIGHBOR_ID],
            FieldValue::Bytes(&value[i..i + 7]),
            offset + i..offset + i + 7,
        );
        buf.push_field(
            &EXT_IS_REACH_CHILD_FIELDS[FD_EIR_METRIC],
            FieldValue::U32(metric),
            offset + i + 7..offset + i + 10,
        );
        buf.end_container(obj_idx);
        i = entry_end;
    }
    buf.end_container(array_idx);
    true
}

/// TLV 135: Extended IP Reachability — RFC 5305, Section 4.
fn parse_extended_ip_reach_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_PREFIXES],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut i = 0;
    while i + 5 <= value.len() {
        let metric = read_be_u32(value, i).unwrap_or_default();
        let control = value[i + 4];
        let prefix_len = control & 0x3F;
        if prefix_len > 32 {
            break;
        }
        let prefix_bytes = (prefix_len as usize).div_ceil(8);
        let entry_start = i;
        i += 5;
        if i + prefix_bytes > value.len() {
            break;
        }
        let mut addr = [0u8; 4];
        addr[..prefix_bytes].copy_from_slice(&value[i..i + prefix_bytes]);
        i += prefix_bytes;
        let has_sub_tlvs = (control & 0x40) != 0;
        if has_sub_tlvs {
            if i >= value.len() {
                break;
            }
            let sub_len = value[i] as usize;
            if i + 1 + sub_len > value.len() {
                break;
            }
            i += 1 + sub_len;
        }
        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_PREFIXES],
            FieldValue::Object(0..0),
            offset + entry_start..offset + i,
        );
        buf.push_field(
            &EXT_IP_REACH_CHILD_FIELDS[FD_EIPR_PREFIX],
            FieldValue::Ipv4Addr(addr),
            offset + entry_start + 5..offset + entry_start + 5 + prefix_bytes,
        );
        buf.push_field(
            &EXT_IP_REACH_CHILD_FIELDS[FD_EIPR_PREFIX_LENGTH],
            FieldValue::U8(prefix_len),
            offset + entry_start + 4..offset + entry_start + 5,
        );
        buf.push_field(
            &EXT_IP_REACH_CHILD_FIELDS[FD_EIPR_METRIC],
            FieldValue::U32(metric),
            offset + entry_start..offset + entry_start + 4,
        );
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
    true
}

/// TLV 236: IPv6 Reachability — RFC 5308, Section 5.
fn parse_ipv6_reach_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_PREFIXES],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut i = 0;
    while i + 6 <= value.len() {
        let metric = read_be_u32(value, i).unwrap_or_default();
        let control = value[i + 4];
        let prefix_len = value[i + 5];
        if prefix_len > 128 {
            break;
        }
        let prefix_bytes = (prefix_len as usize).div_ceil(8);
        let entry_start = i;
        i += 6;
        if i + prefix_bytes > value.len() {
            break;
        }
        let mut addr = [0u8; 16];
        addr[..prefix_bytes].copy_from_slice(&value[i..i + prefix_bytes]);
        i += prefix_bytes;
        let has_sub_tlvs = (control & 0x20) != 0;
        if has_sub_tlvs {
            if i >= value.len() {
                break;
            }
            let sub_len = value[i] as usize;
            if i + 1 + sub_len > value.len() {
                break;
            }
            i += 1 + sub_len;
        }
        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_PREFIXES],
            FieldValue::Object(0..0),
            offset + entry_start..offset + i,
        );
        buf.push_field(
            &IPV6_REACH_CHILD_FIELDS[FD_IP6R_PREFIX],
            FieldValue::Ipv6Addr(addr),
            offset + entry_start + 6..offset + entry_start + 6 + prefix_bytes,
        );
        buf.push_field(
            &IPV6_REACH_CHILD_FIELDS[FD_IP6R_PREFIX_LENGTH],
            FieldValue::U8(prefix_len),
            offset + entry_start + 5..offset + entry_start + 6,
        );
        buf.push_field(
            &IPV6_REACH_CHILD_FIELDS[FD_IP6R_METRIC],
            FieldValue::U32(metric),
            offset + entry_start..offset + entry_start + 4,
        );
        buf.end_container(obj_idx);
    }
    buf.end_container(array_idx);
    true
}

/// TLV 128/130: IP Internal/External Reachability — RFC 1195.
fn parse_ip_reach_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_ENTRIES],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut i = 0;
    while i + 12 <= value.len() {
        let metric = value[i] & 0x3F;
        let ip = [value[i + 4], value[i + 5], value[i + 6], value[i + 7]];
        let mask = [value[i + 8], value[i + 9], value[i + 10], value[i + 11]];
        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_ENTRIES],
            FieldValue::Object(0..0),
            offset + i..offset + i + 12,
        );
        buf.push_field(
            &IP_REACH_CHILD_FIELDS[FD_IPR_IP_ADDRESS],
            FieldValue::Ipv4Addr(ip),
            offset + i + 4..offset + i + 8,
        );
        buf.push_field(
            &IP_REACH_CHILD_FIELDS[FD_IPR_SUBNET_MASK],
            FieldValue::Ipv4Addr(mask),
            offset + i + 8..offset + i + 12,
        );
        buf.push_field(
            &IP_REACH_CHILD_FIELDS[FD_IPR_METRIC],
            FieldValue::U8(metric),
            offset + i..offset + i + 1,
        );
        buf.end_container(obj_idx);
        i += 12;
    }
    buf.end_container(array_idx);
    true
}

/// TLV 9: LSP Entries — ISO/IEC 10589:2002.
fn parse_lsp_entries_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_ENTRIES],
        FieldValue::Array(0..0),
        offset..offset + value.len(),
    );
    let mut i = 0;
    while i + 16 <= value.len() {
        let remaining_lifetime = read_be_u16(value, i).unwrap_or_default();
        let seq = read_be_u32(value, i + 10).unwrap_or_default();
        let checksum = read_be_u16(value, i + 14).unwrap_or_default();
        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_ENTRIES],
            FieldValue::Object(0..0),
            offset + i..offset + i + 16,
        );
        buf.push_field(
            &LSP_ENTRY_CHILD_FIELDS[FD_LSPE_LSP_ID],
            FieldValue::Bytes(&value[i + 2..i + 10]),
            offset + i + 2..offset + i + 10,
        );
        buf.push_field(
            &LSP_ENTRY_CHILD_FIELDS[FD_LSPE_SEQUENCE_NUMBER],
            FieldValue::U32(seq),
            offset + i + 10..offset + i + 14,
        );
        buf.push_field(
            &LSP_ENTRY_CHILD_FIELDS[FD_LSPE_REMAINING_LIFETIME],
            FieldValue::U16(remaining_lifetime),
            offset + i..offset + i + 2,
        );
        buf.push_field(
            &LSP_ENTRY_CHILD_FIELDS[FD_LSPE_CHECKSUM],
            FieldValue::U16(checksum),
            offset + i + 14..offset + i + 16,
        );
        buf.end_container(obj_idx);
        i += 16;
    }
    buf.end_container(array_idx);
    true
}

/// TLV 240: P2P Three-Way Adjacency — RFC 5303.
fn parse_p2p_adj_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.is_empty() {
        return false;
    }
    let state = value[0];
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_STATE],
        FieldValue::U8(state),
        offset..offset + 1,
    );
    true
}

/// TLV 10: Authentication — ISO/IEC 10589:2002, RFC 5304.
fn parse_authentication_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.is_empty() {
        return false;
    }
    let auth_type = value[0];
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_AUTH_TYPE],
        FieldValue::U8(auth_type),
        offset..offset + 1,
    );
    true
}

/// TLV 211: Restart — RFC 8706.
fn parse_restart_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    offset: usize,
) -> bool {
    if value.is_empty() {
        return false;
    }
    let flags = value[0];
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_FLAGS],
        FieldValue::U8(flags),
        offset..offset + 1,
    );
    if value.len() >= 3 {
        let remaining_time = read_be_u16(value, 1).unwrap_or_default();
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_REMAINING_TIME],
            FieldValue::U16(remaining_time),
            offset + 1..offset + 3,
        );
    }
    true
}

/// Parses the TLV area starting at `data[tlv_start..]` up to `pdu_end`.
/// Returns `true` if any TLVs were parsed.
fn parse_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    tlv_start: usize,
    pdu_end: usize,
) -> bool {
    let mut pos = tlv_start;
    let mut any = false;

    while pos + 2 <= pdu_end && pos + 2 <= data.len() {
        let tlv_type = data[pos];
        let tlv_len = data[pos + 1] as usize;
        let value_start = pos + 2;
        let value_end = value_start + tlv_len;

        if value_end > pdu_end || value_end > data.len() {
            break;
        }

        any = true;
        let tlv_value = &data[value_start..value_end];

        let obj_idx = buf.begin_container(
            &TLV_CHILD_FIELDS[FD_TLV_TYPE],
            FieldValue::Object(0..0),
            offset + pos..offset + value_end,
        );

        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_TYPE],
            FieldValue::U8(tlv_type),
            offset + pos..offset + pos + 1,
        );
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_LENGTH],
            FieldValue::U8(tlv_len as u8),
            offset + pos + 1..offset + value_start,
        );

        let has_typed = parse_tlv_fields(buf, tlv_type, tlv_value, offset + value_start);
        if !has_typed && tlv_type != TLV_PADDING {
            buf.push_field(
                &TLV_CHILD_FIELDS[FD_TLV_RAW],
                FieldValue::Bytes(tlv_value),
                offset + value_start..offset + value_end,
            );
        }

        buf.end_container(obj_idx);

        pos = value_end;
    }

    any
}

// ---------------------------------------------------------------------------
// Dissector implementation
// ---------------------------------------------------------------------------

/// IS-IS dissector.
///
/// Parses IS-IS PDUs carried over IEEE 802.2 LLC (DSAP 0xFE).
/// Supports all PDU types defined in ISO/IEC 10589:2002.
pub struct IsisDissector;

impl Dissector for IsisDissector {
    fn name(&self) -> &'static str {
        "Intermediate System to Intermediate System"
    }

    fn short_name(&self) -> &'static str {
        "ISIS"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < COMMON_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: COMMON_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let nlpid = data[0];
        if nlpid != NLPID_ISIS {
            return Err(PacketError::InvalidFieldValue {
                field: "nlpid",
                value: nlpid as u32,
            });
        }

        let header_length = data[1] as usize;
        let version = data[2];
        let id_length = data[3];
        let pdu_type_raw = data[4] & 0x1F;
        let version2 = data[5];
        let max_area_addresses = data[7];

        if version != 1 || version2 != 1 {
            return Err(PacketError::InvalidHeader("IS-IS version must be 1"));
        }

        // id_length 0 means default (6); only 0 and 6 are valid for standard IS-IS.
        if id_length != 0 && id_length != 6 {
            return Err(PacketError::InvalidFieldValue {
                field: "id_length",
                value: id_length as u32,
            });
        }

        // We begin the layer early so header parsers can push fields directly.
        buf.begin_layer("ISIS", None, FIELD_DESCRIPTORS, offset..offset + data.len());

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NLPID],
            FieldValue::U8(nlpid),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HEADER_LENGTH],
            FieldValue::U8(header_length as u8),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ID_LENGTH],
            FieldValue::U8(id_length),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PDU_TYPE],
            FieldValue::U8(pdu_type_raw),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAX_AREA_ADDRESSES],
            FieldValue::U8(max_area_addresses),
            offset + 7..offset + 8,
        );

        let (pdu_length, tlv_start) = match pdu_type_raw {
            PDU_TYPE_L1_LAN_IIH | PDU_TYPE_L2_LAN_IIH => parse_lan_iih_header(data, offset, buf)?,
            PDU_TYPE_P2P_IIH => parse_p2p_iih_header(data, offset, buf)?,
            PDU_TYPE_L1_LSP | PDU_TYPE_L2_LSP => parse_lsp_header(data, offset, buf)?,
            PDU_TYPE_L1_CSNP | PDU_TYPE_L2_CSNP => parse_csnp_header(data, offset, buf)?,
            PDU_TYPE_L1_PSNP | PDU_TYPE_L2_PSNP => parse_psnp_header(data, offset, buf)?,
            _ => {
                // Remove the partially-built layer before returning error.
                buf.pop_layer();
                return Err(PacketError::InvalidFieldValue {
                    field: "pdu_type",
                    value: pdu_type_raw as u32,
                });
            }
        };

        // header_length must match the expected fixed header size for this PDU type.
        if header_length != tlv_start {
            buf.pop_layer();
            return Err(PacketError::InvalidHeader("IS-IS header length mismatch"));
        }

        // Validate declared PDU length:
        // - it must be at least as large as the fixed header/TLV start
        // - it must not exceed the available buffer length
        if pdu_length < tlv_start {
            buf.pop_layer();
            return Err(PacketError::InvalidHeader(
                "IS-IS PDU length smaller than header size",
            ));
        }

        if pdu_length > data.len() {
            buf.pop_layer();
            return Err(PacketError::Truncated {
                expected: pdu_length,
                actual: data.len(),
            });
        }

        let pdu_end = pdu_length;

        // Parse TLVs into a container array.
        if tlv_start < pdu_end {
            let tlv_range = offset + tlv_start..offset + pdu_end;
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_TLVS],
                FieldValue::Array(0..0),
                tlv_range,
            );
            parse_tlvs(buf, data, offset, tlv_start, pdu_end);
            buf.end_container(array_idx);
        }

        // Fix the layer range to the actual PDU size.
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + pdu_end;
        }
        buf.end_layer();

        Ok(DissectResult::new(pdu_end, DispatchHint::End))
    }
}

// ---------------------------------------------------------------------------
// PDU-specific header parsers
// ---------------------------------------------------------------------------

/// Parses LAN IIH specific header (types 15, 16).
/// ISO/IEC 10589:2002, Sections 9.7–9.8.
/// Returns `(pdu_length, tlv_start_offset)`.
fn parse_lan_iih_header<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(usize, usize), PacketError> {
    // Common header (8) + Circuit Type (1) + Source ID (6) + Holding Time (2) +
    // PDU Length (2) + Priority (1) + LAN ID (7) = 27 bytes minimum
    let min_size = 27;
    if data.len() < min_size {
        return Err(PacketError::Truncated {
            expected: min_size,
            actual: data.len(),
        });
    }

    let circuit_type = data[8] & 0x03;
    let holding_time = read_be_u16(data, 15)?;
    let pdu_length = read_be_u16(data, 17)? as usize;
    let priority = data[19] & 0x7F;

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIRCUIT_TYPE],
        FieldValue::U8(circuit_type),
        offset + 8..offset + 9,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SOURCE_ID],
        FieldValue::Bytes(&data[9..15]),
        offset + 9..offset + 15,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HOLDING_TIME],
        FieldValue::U16(holding_time),
        offset + 15..offset + 17,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PDU_LENGTH],
        FieldValue::U16(pdu_length as u16),
        offset + 17..offset + 19,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PRIORITY],
        FieldValue::U8(priority),
        offset + 19..offset + 20,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LAN_ID],
        FieldValue::Bytes(&data[20..27]),
        offset + 20..offset + 27,
    );

    // TLVs start after byte 27 (header length indicator should confirm)
    Ok((pdu_length, 27))
}

/// Parses Point-to-Point IIH specific header (type 17).
/// ISO/IEC 10589:2002, Section 9.9.
fn parse_p2p_iih_header<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(usize, usize), PacketError> {
    let min_size = 20;
    if data.len() < min_size {
        return Err(PacketError::Truncated {
            expected: min_size,
            actual: data.len(),
        });
    }

    let circuit_type = data[8] & 0x03;
    let holding_time = read_be_u16(data, 15)?;
    let pdu_length = read_be_u16(data, 17)? as usize;
    let local_circuit_id = data[19];

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CIRCUIT_TYPE],
        FieldValue::U8(circuit_type),
        offset + 8..offset + 9,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SOURCE_ID],
        FieldValue::Bytes(&data[9..15]),
        offset + 9..offset + 15,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HOLDING_TIME],
        FieldValue::U16(holding_time),
        offset + 15..offset + 17,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PDU_LENGTH],
        FieldValue::U16(pdu_length as u16),
        offset + 17..offset + 19,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LOCAL_CIRCUIT_ID],
        FieldValue::U8(local_circuit_id),
        offset + 19..offset + 20,
    );

    Ok((pdu_length, 20))
}

/// Parses LSP specific header (types 18, 20).
/// ISO/IEC 10589:2002, Sections 9.10–9.11.
fn parse_lsp_header<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(usize, usize), PacketError> {
    let min_size = 27;
    if data.len() < min_size {
        return Err(PacketError::Truncated {
            expected: min_size,
            actual: data.len(),
        });
    }

    let pdu_length = read_be_u16(data, 8)? as usize;
    let remaining_lifetime = read_be_u16(data, 10)?;
    let sequence_number = read_be_u32(data, 20)?;
    let checksum = read_be_u16(data, 24)?;
    let type_block = data[26];

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PDU_LENGTH],
        FieldValue::U16(pdu_length as u16),
        offset + 8..offset + 10,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_REMAINING_LIFETIME],
        FieldValue::U16(remaining_lifetime),
        offset + 10..offset + 12,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LSP_ID],
        FieldValue::Bytes(&data[12..20]),
        offset + 12..offset + 20,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
        FieldValue::U32(sequence_number),
        offset + 20..offset + 24,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CHECKSUM],
        FieldValue::U16(checksum),
        offset + 24..offset + 26,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TYPE_BLOCK],
        FieldValue::U8(type_block),
        offset + 26..offset + 27,
    );

    Ok((pdu_length, 27))
}

/// Parses CSNP specific header (types 24, 25).
/// ISO/IEC 10589:2002, Sections 9.12–9.13.
fn parse_csnp_header<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(usize, usize), PacketError> {
    let min_size = 33;
    if data.len() < min_size {
        return Err(PacketError::Truncated {
            expected: min_size,
            actual: data.len(),
        });
    }

    let pdu_length = read_be_u16(data, 8)? as usize;

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PDU_LENGTH],
        FieldValue::U16(pdu_length as u16),
        offset + 8..offset + 10,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SOURCE_ID],
        FieldValue::Bytes(&data[10..17]),
        offset + 10..offset + 17,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_START_LSP_ID],
        FieldValue::Bytes(&data[17..25]),
        offset + 17..offset + 25,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_END_LSP_ID],
        FieldValue::Bytes(&data[25..33]),
        offset + 25..offset + 33,
    );

    Ok((pdu_length, 33))
}

/// Parses PSNP specific header (types 26, 27).
/// ISO/IEC 10589:2002, Sections 9.14–9.15.
fn parse_psnp_header<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(usize, usize), PacketError> {
    let min_size = 17;
    if data.len() < min_size {
        return Err(PacketError::Truncated {
            expected: min_size,
            actual: data.len(),
        });
    }

    let pdu_length = read_be_u16(data, 8)? as usize;

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PDU_LENGTH],
        FieldValue::U16(pdu_length as u16),
        offset + 8..offset + 10,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SOURCE_ID],
        FieldValue::Bytes(&data[10..17]),
        offset + 10..offset + 17,
    );

    Ok((pdu_length, 17))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Range;
    use packet_dissector_core::field::Field;

    /// Count the number of top-level TLV objects in the "tlvs" Array.
    ///
    /// In the flat buffer, each TLV is an Object that was pushed via
    /// `begin_container` inside `parse_tlvs`.  Top-level TLV objects
    /// are identified by scanning `tlvs_range` and skipping over each
    /// Object's children (using its inner range) to find the next one.
    fn count_tlv_objects(buf: &DissectBuffer<'_>, range: &Range<u32>) -> usize {
        let fields = buf.nested_fields(range);
        let mut count = 0;
        let mut i = 0;
        while i < fields.len() {
            if let Some(r) = fields[i].value.as_container_range() {
                count += 1;
                // Skip past all children of this object.
                i = (r.end - range.start) as usize;
            } else {
                i += 1;
            }
        }
        count
    }

    /// Get the Nth TLV object's field range from the "tlvs" array.
    fn nth_tlv_range(buf: &DissectBuffer<'_>, tlvs_range: &Range<u32>, n: usize) -> Range<u32> {
        let fields = buf.nested_fields(tlvs_range);
        let mut count = 0;
        let mut i = 0;
        while i < fields.len() {
            if let Some(r) = fields[i].value.as_container_range() {
                if count == n {
                    return r.clone();
                }
                count += 1;
                i = (r.end - tlvs_range.start) as usize;
            } else {
                i += 1;
            }
        }
        panic!("TLV object {n} not found")
    }

    /// Find a named field within a container range.
    fn nested_field_by_name<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        range: &Range<u32>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    /// Get a named field's value from a TLV object range.
    fn tlv_field_value<'pkt>(
        buf: &DissectBuffer<'pkt>,
        tlv_range: &Range<u32>,
        name: &str,
    ) -> Option<FieldValue<'pkt>> {
        nested_field_by_name(buf, tlv_range, name).map(|f| f.value.clone())
    }

    // # IS-IS Coverage
    //
    // | Spec Section               | Description                    | Test                                   |
    // |----------------------------|--------------------------------|----------------------------------------|
    // | ISO 10589 §9.5             | Common fixed header            | parse_common_header                    |
    // | ISO 10589 §9.5             | Invalid NLPID                  | reject_invalid_nlpid                   |
    // | ISO 10589 §9.5             | Invalid version                | reject_invalid_version                 |
    // | ISO 10589 §9.5             | Invalid version2               | reject_invalid_version2                |
    // | ISO 10589 §9.5             | Truncated common header        | reject_truncated_common_header         |
    // | ISO 10589 §9.5             | Unsupported ID length          | reject_unsupported_id_length           |
    // | ISO 10589 §9.5             | Header length mismatch         | reject_header_length_mismatch          |
    // | ISO 10589 §9.5             | PDU length < header size       | reject_pdu_length_smaller_than_header  |
    // | ISO 10589 §9.5             | PDU length > buffer            | reject_pdu_length_exceeds_buffer       |
    // | ISO 10589 §9.7             | L1 LAN IIH                    | parse_l1_lan_iih                       |
    // | ISO 10589 §9.8             | L2 LAN IIH                    | parse_l2_lan_iih                       |
    // | ISO 10589 §9.9             | P2P IIH                        | parse_p2p_iih                          |
    // | ISO 10589 §9.9             | Truncated P2P IIH              | reject_truncated_p2p_iih               |
    // | ISO 10589 §9.10            | L1 LSP                         | parse_l1_lsp                           |
    // | ISO 10589 §9.11            | L2 LSP                         | parse_l2_lsp                           |
    // | ISO 10589 §9.11            | Truncated LSP                  | reject_truncated_lsp                   |
    // | ISO 10589 §9.12            | L1 CSNP                        | parse_l1_csnp                          |
    // | ISO 10589 §9.13            | L2 CSNP                        | parse_l2_csnp                          |
    // | ISO 10589 §9.13            | Truncated CSNP                 | reject_truncated_csnp                  |
    // | ISO 10589 §9.14            | L1 PSNP                        | parse_l1_psnp                          |
    // | ISO 10589 §9.15            | L2 PSNP                        | parse_l2_psnp                          |
    // | ISO 10589 §9.15            | Truncated PSNP                 | reject_truncated_psnp                  |
    // | ISO 10589                  | IS Neighbors IIH TLV (6)       | parse_tlv_is_neighbors_iih             |
    // | ISO 10589                  | LSP Entries TLV (9)            | parse_tlv_lsp_entries                  |
    // | RFC 1195                   | Protocols Supported TLV        | parse_tlv_protocols_supported          |
    // | RFC 1195                   | IP Interface Address TLV       | parse_tlv_ip_interface_address         |
    // | RFC 1195                   | IP Internal Reachability (128)  | parse_tlv_ip_internal_reachability     |
    // | RFC 1195                   | IP External Reachability (130)  | parse_tlv_ip_external_reachability     |
    // | RFC 5301                   | Dynamic Hostname TLV           | parse_tlv_dynamic_hostname             |
    // | RFC 5303                   | P2P Three-Way Adjacency (240)  | parse_tlv_p2p_three_way_adj            |
    // | RFC 5305 §3                | Extended IS Reachability (22)   | parse_tlv_extended_is_reachability     |
    // | RFC 5305 §4                | Extended IP Reachability TLV   | parse_tlv_extended_ip_reachability     |
    // | RFC 5305 §4.3              | TE Router ID TLV (134)         | parse_tlv_te_router_id                 |
    // | RFC 5304                   | Authentication TLV (10)        | parse_tlv_authentication               |
    // | RFC 5308 §2                | IPv6 Interface Address TLV     | parse_tlv_ipv6_interface_address       |
    // | RFC 5308 §5                | IPv6 Reachability TLV (236)    | parse_tlv_ipv6_reachability            |
    // | RFC 5120                   | MT IS Neighbors (222) raw      | parse_tlv_mt_is_neighbors_raw          |
    // | ISO 10589                  | Area Addresses TLV             | parse_tlv_area_addresses               |
    // | ISO 10589                  | Unknown PDU type               | reject_unknown_pdu_type                |
    // | ISO 10589                  | Truncated LAN IIH              | reject_truncated_lan_iih               |
    // | ISO 10589                  | Unknown TLV produces raw       | parse_unknown_tlv_raw                  |

    /// Helper: build a minimal L1 LAN IIH PDU (27 bytes header + TLVs).
    fn build_l1_lan_iih(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 27 + tlvs.len();
        let mut pdu = Vec::with_capacity(pdu_len);
        pdu.extend_from_slice(&[
            0x83,
            27,
            0x01,
            0x00,
            PDU_TYPE_L1_LAN_IIH,
            0x01,
            0x00,
            0x00,
            0x01, // Circuit Type: L1
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06, // Source ID
        ]);
        pdu.extend_from_slice(&30u16.to_be_bytes()); // Holding Time
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes()); // PDU Length
        pdu.push(0x40); // Priority
        pdu.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01]); // LAN ID
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal P2P IIH PDU.
    fn build_p2p_iih(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 20 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[
            0x83,             // [0] NLPID
            20,               // [1] Header Length
            0x01,             // [2] Version
            0x00,             // [3] ID Length
            PDU_TYPE_P2P_IIH, // [4] PDU Type
            0x01,             // [5] Version
            0x00,             // [6] Reserved
            0x00,             // [7] Max Area Addresses
            0x03,             // [8] Circuit Type: L1L2
            // [9..15] Source ID
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
        ]);
        pdu.extend_from_slice(&60u16.to_be_bytes()); // [15..17] Holding Time
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes()); // [17..19] PDU Length
        pdu.push(0x01); // [19] Local Circuit ID
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal L1 LSP.
    fn build_l1_lsp(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 27 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x83, 27, 0x01, 0x00, PDU_TYPE_L1_LSP, 0x01, 0x00, 0x00]);
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes()); // [8..10] PDU Length
        pdu.extend_from_slice(&1200u16.to_be_bytes()); // [10..12] Remaining Lifetime
        // [12..20] LSP ID (8 bytes)
        pdu.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00]);
        pdu.extend_from_slice(&0x00000001u32.to_be_bytes()); // [20..24] Sequence Number
        pdu.extend_from_slice(&0xABCDu16.to_be_bytes()); // [24..26] Checksum
        pdu.push(0x03); // [26] Type Block (L1+L2)
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal L1 CSNP.
    fn build_l1_csnp(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 33 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x83, 33, 0x01, 0x00, PDU_TYPE_L1_CSNP, 0x01, 0x00, 0x00]);
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes()); // PDU Length
        // Source ID (7 bytes)
        pdu.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00]);
        // Start LSP ID (8 bytes)
        pdu.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // End LSP ID (8 bytes)
        pdu.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal L1 PSNP.
    fn build_l1_psnp(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 17 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x83, 17, 0x01, 0x00, PDU_TYPE_L1_PSNP, 0x01, 0x00, 0x00]);
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes());
        pdu.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00]);
        pdu.extend_from_slice(tlvs);
        pdu
    }

    #[test]
    fn parse_common_header() {
        let data = build_l1_lan_iih(&[]);
        let mut buf = DissectBuffer::new();
        let result = IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 27);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "nlpid").unwrap().value,
            FieldValue::U8(0x83)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "id_length").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "pdu_type").unwrap().value,
            FieldValue::U8(PDU_TYPE_L1_LAN_IIH)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L1 LAN IIH")
        );
        assert_eq!(
            buf.field_by_name(layer, "max_area_addresses")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn reject_invalid_nlpid() {
        let mut data = build_l1_lan_iih(&[]);
        data[0] = 0x84; // Wrong NLPID
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue {
                field: "nlpid",
                value: 0x84,
            } => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_version() {
        let mut data = build_l1_lan_iih(&[]);
        data[2] = 0x02; // Wrong version
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidHeader(_) => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_truncated_common_header() {
        let data = [0x83, 27, 0x01]; // Only 3 bytes
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 8);
                assert_eq!(actual, 3);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_l1_lan_iih() {
        let data = build_l1_lan_iih(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "circuit_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            buf.field_by_name(layer, "holding_time").unwrap().value,
            FieldValue::U16(30)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(64)
        );
        assert_eq!(
            buf.field_by_name(layer, "lan_id").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01])
        );
    }

    #[test]
    fn parse_p2p_iih() {
        let data = build_p2p_iih(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("P2P IIH")
        );
        assert_eq!(
            buf.field_by_name(layer, "circuit_type").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
        assert_eq!(
            buf.field_by_name(layer, "holding_time").unwrap().value,
            FieldValue::U16(60)
        );
        assert_eq!(
            buf.field_by_name(layer, "local_circuit_id").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_l1_lsp() {
        let data = build_l1_lsp(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L1 LSP")
        );
        assert_eq!(
            buf.field_by_name(layer, "remaining_lifetime")
                .unwrap()
                .value,
            FieldValue::U16(1200)
        );
        assert_eq!(
            buf.field_by_name(layer, "lsp_id").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00])
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xABCD)
        );
        assert_eq!(
            buf.field_by_name(layer, "type_block").unwrap().value,
            FieldValue::U8(0x03)
        );
    }

    #[test]
    fn parse_l1_csnp() {
        let data = build_l1_csnp(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L1 CSNP")
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00])
        );
        assert!(buf.field_by_name(layer, "start_lsp_id").is_some());
        assert!(buf.field_by_name(layer, "end_lsp_id").is_some());
    }

    #[test]
    fn parse_l1_psnp() {
        let data = build_l1_psnp(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L1 PSNP")
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00])
        );
    }

    #[test]
    fn parse_tlv_protocols_supported() {
        let data = build_l1_lan_iih(&[TLV_PROTOCOLS_SUPPORTED, 0x02, 0xCC, 0x8E]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert_eq!(count_tlv_objects(&buf, &tlvs_range), 1);
        // "protocols" is an Array of Objects with nlpid + name
        let protocols =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "protocols").unwrap();
        {
            let r = protocols.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, r), 2);
        }
    }

    #[test]
    fn parse_tlv_ip_interface_address() {
        let data = build_l1_lan_iih(&[TLV_IP_INTERFACE_ADDRESS, 0x04, 10, 0, 0, 1]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let addrs =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "addresses").unwrap();
        {
            let r = addrs.as_container_range().unwrap();
            let children = buf.nested_fields(r);
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        }
    }

    #[test]
    fn parse_tlv_dynamic_hostname() {
        let hostname = b"router1";
        let mut tlvs = vec![TLV_DYNAMIC_HOSTNAME, hostname.len() as u8];
        tlvs.extend_from_slice(hostname);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "hostname").unwrap(),
            FieldValue::Bytes(b"router1")
        );
    }

    #[test]
    fn parse_tlv_extended_ip_reachability() {
        let mut tlvs = vec![TLV_EXTENDED_IP_REACHABILITY, 8];
        tlvs.extend_from_slice(&10u32.to_be_bytes());
        tlvs.push(24);
        tlvs.extend_from_slice(&[10, 0, 0]);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let prefixes =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "prefixes").unwrap();
        {
            let p = prefixes.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, p), 1);
            {
                let child = &buf.nested_fields(p)[0];
                let fields = child.value.as_container_range().unwrap();
                let prefix = nested_field_by_name(&buf, fields, "prefix").unwrap();
                assert_eq!(prefix.value, FieldValue::Ipv4Addr([10, 0, 0, 0]));
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U32(10));
            }
        }
    }

    #[test]
    fn parse_tlv_ipv6_interface_address() {
        let mut tlvs = vec![TLV_IPV6_INTERFACE_ADDRESS, 16];
        tlvs.extend_from_slice(&[
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let addrs =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "addresses").unwrap();
        {
            let a = addrs.as_container_range().unwrap();
            assert_eq!(buf.nested_fields(a).len(), 1);
            assert_eq!(
                buf.nested_fields(a)[0].value,
                FieldValue::Ipv6Addr([
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ])
            );
        }
    }

    #[test]
    fn parse_tlv_area_addresses() {
        let data = build_l1_lan_iih(&[TLV_AREA_ADDRESSES, 0x04, 0x03, 0x49, 0x00, 0x01]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let areas = tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "areas").unwrap();
        {
            let r = areas.as_container_range().unwrap();
            let children = buf.nested_fields(r);
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].value, FieldValue::Bytes(&[0x49, 0x00, 0x01]));
        }
    }

    #[test]
    fn reject_unknown_pdu_type() {
        let mut data = build_l1_lan_iih(&[]);
        data[4] = 0x1F; // Unknown PDU type
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue {
                field: "pdu_type",
                value: 31,
            } => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_truncated_lan_iih() {
        // Only 20 bytes (need 27 for LAN IIH)
        let data = [
            0x83,
            27,
            0x01,
            0x00,
            PDU_TYPE_L1_LAN_IIH,
            0x01,
            0x00,
            0x00,
            0x01,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x00,
            0x1E,
            0x00,
            0x1C,
            0x40,
        ];
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected: 27, .. } => {}
            other => panic!("expected Truncated with expected=27, got {other:?}"),
        }
    }

    #[test]
    fn parse_with_offset() {
        let prefix = [0xDE, 0xAD]; // 2 bytes before the PDU
        let pdu = build_l1_lan_iih(&[]);
        let mut data = Vec::new();
        data.extend_from_slice(&prefix);
        data.extend_from_slice(&pdu);

        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data[2..], &mut buf, 2).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(layer.range.start, 2);
    }

    #[test]
    fn parse_multiple_tlvs() {
        let mut tlvs = Vec::new();
        tlvs.extend_from_slice(&[TLV_PROTOCOLS_SUPPORTED, 0x01, 0xCC]);
        tlvs.extend_from_slice(&[TLV_IP_INTERFACE_ADDRESS, 0x04, 192, 168, 1, 1]);
        tlvs.extend_from_slice(&[TLV_AREA_ADDRESSES, 0x04, 0x03, 0x49, 0x00, 0x01]);
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        {
            let layer = buf.layer_by_name("ISIS").unwrap();
            let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
            let tlvs_range = tlvs_field.value.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, tlvs_range), 3);
        }
    }

    #[test]
    fn parse_padding_tlv_no_value() {
        let data = build_l1_lan_iih(&[TLV_PADDING, 0x04, 0x00, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert_eq!(count_tlv_objects(&buf, &tlvs_range), 1);
        assert!(
            buf.nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .all(|f: &Field<'_>| f.name() != "value" && f.name() != "raw")
        );
    }

    #[test]
    fn parse_tlv_restart() {
        let data = build_p2p_iih(&[TLV_RESTART, 0x03, 0x01, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Restart")
            );
        }
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "flags").unwrap(),
            FieldValue::U8(0x01)
        );
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "flags")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("RR")
            );
        }
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "remaining_time").unwrap(),
            FieldValue::U16(0)
        );
    }

    #[test]
    fn parse_tlv_restart_no_flags() {
        let data = build_p2p_iih(&[TLV_RESTART, 0x03, 0x00, 0x00, 0x00]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "flags").unwrap(),
            FieldValue::U8(0)
        );
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "flags")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("none")
            );
        }
    }

    #[test]
    fn parse_tlv_restart_multiple_flags() {
        let data = build_p2p_iih(&[TLV_RESTART, 0x03, 0x0D, 0x00, 0x1E]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "flags")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("RR|SA|PR")
            );
        }
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "remaining_time").unwrap(),
            FieldValue::U16(30)
        );
    }

    // -----------------------------------------------------------------------
    // L2 PDU type helpers and tests
    // -----------------------------------------------------------------------

    /// Helper: build a minimal L2 LAN IIH PDU.
    fn build_l2_lan_iih(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 27 + tlvs.len();
        let mut pdu = Vec::with_capacity(pdu_len);
        pdu.extend_from_slice(&[
            0x83,
            27,
            0x01,
            0x00,
            PDU_TYPE_L2_LAN_IIH,
            0x01,
            0x00,
            0x00,
            0x02, // Circuit Type: L2
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F, // Source ID
        ]);
        pdu.extend_from_slice(&45u16.to_be_bytes()); // Holding Time
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes()); // PDU Length
        pdu.push(0x40); // Priority
        pdu.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x02]); // LAN ID
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal L2 LSP.
    fn build_l2_lsp(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 27 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x83, 27, 0x01, 0x00, PDU_TYPE_L2_LSP, 0x01, 0x00, 0x00]);
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes());
        pdu.extend_from_slice(&900u16.to_be_bytes()); // Remaining Lifetime
        pdu.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00]); // LSP ID
        pdu.extend_from_slice(&0x00000005u32.to_be_bytes()); // Sequence Number
        pdu.extend_from_slice(&0x1234u16.to_be_bytes()); // Checksum
        pdu.push(0x03); // Type Block
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal L2 CSNP.
    fn build_l2_csnp(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 33 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x83, 33, 0x01, 0x00, PDU_TYPE_L2_CSNP, 0x01, 0x00, 0x00]);
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes());
        pdu.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00]); // Source ID
        pdu.extend_from_slice(&[0x00; 8]); // Start LSP ID
        pdu.extend_from_slice(&[0xFF; 8]); // End LSP ID
        pdu.extend_from_slice(tlvs);
        pdu
    }

    /// Helper: build a minimal L2 PSNP.
    fn build_l2_psnp(tlvs: &[u8]) -> Vec<u8> {
        let pdu_len = 17 + tlvs.len();
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[0x83, 17, 0x01, 0x00, PDU_TYPE_L2_PSNP, 0x01, 0x00, 0x00]);
        pdu.extend_from_slice(&(pdu_len as u16).to_be_bytes());
        pdu.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00]);
        pdu.extend_from_slice(tlvs);
        pdu
    }

    #[test]
    fn parse_l2_lan_iih() {
        let data = build_l2_lan_iih(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L2 LAN IIH")
        );
        assert_eq!(
            buf.field_by_name(layer, "circuit_type").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        );
        assert_eq!(
            buf.field_by_name(layer, "holding_time").unwrap().value,
            FieldValue::U16(45)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(64)
        );
        assert_eq!(
            buf.field_by_name(layer, "lan_id").unwrap().value,
            FieldValue::Bytes(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x02])
        );
    }

    #[test]
    fn parse_l2_lsp() {
        let data = build_l2_lsp(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L2 LSP")
        );
        assert_eq!(
            buf.field_by_name(layer, "remaining_lifetime")
                .unwrap()
                .value,
            FieldValue::U16(900)
        );
        assert_eq!(
            buf.field_by_name(layer, "lsp_id").unwrap().value,
            FieldValue::Bytes(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00])
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(5)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0x1234)
        );
    }

    #[test]
    fn parse_l2_csnp() {
        let data = build_l2_csnp(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L2 CSNP")
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00])
        );
        assert!(buf.field_by_name(layer, "start_lsp_id").is_some());
        assert!(buf.field_by_name(layer, "end_lsp_id").is_some());
    }

    #[test]
    fn parse_l2_psnp() {
        let data = build_l2_psnp(&[]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "pdu_type_name"),
            Some("L2 PSNP")
        );
        assert_eq!(
            buf.field_by_name(layer, "source_id").unwrap().value,
            FieldValue::Bytes(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00])
        );
    }

    // -----------------------------------------------------------------------
    // Untested TLV parsers
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tlv_is_neighbors_iih() {
        // TLV 6: one IS neighbor MAC address (6 bytes each).
        let mut tlvs = vec![TLV_IS_NEIGHBORS_IIH, 6];
        tlvs.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert_eq!(count_tlv_objects(&buf, &tlvs_range), 1);
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("IS Neighbors")
            );
        }
        let neighbors =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "neighbors").unwrap();
        {
            let n = neighbors.as_container_range().unwrap();
            assert_eq!(buf.nested_fields(n).len(), 1);
            assert_eq!(
                buf.nested_fields(n)[0].value,
                FieldValue::MacAddr(MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
            );
        }
    }

    #[test]
    fn parse_tlv_is_neighbors_iih_multiple() {
        // Two IS neighbor MAC addresses.
        let mut tlvs = vec![TLV_IS_NEIGHBORS_IIH, 12];
        tlvs.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        tlvs.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let neighbors =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "neighbors").unwrap();
        {
            let r = neighbors.as_container_range().unwrap();
            assert_eq!(buf.nested_fields(r).len(), 2);
        }
    }

    #[test]
    fn parse_tlv_is_neighbors_iih_empty() {
        // Empty value — should return empty vec (no "neighbors" field).
        let tlvs = [TLV_IS_NEIGHBORS_IIH, 0];
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        // Empty TLV with 0 length produces no typed fields; raw fallback is skipped
        // because parse_is_neighbors_iih_fields returns empty vec for empty/odd value.
        // The TLV still appears with type/length, but no "neighbors" field.
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "neighbors").is_none());
    }

    #[test]
    fn parse_tlv_is_neighbors_iih_odd_length() {
        // Non-multiple-of-6 length — treated as invalid, returns empty.
        let tlvs = [TLV_IS_NEIGHBORS_IIH, 5, 0x01, 0x02, 0x03, 0x04, 0x05];
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        // Returns empty vec from parser, so "raw" fallback is used.
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_extended_is_reachability() {
        // TLV 22: one neighbor with 7-byte node ID, 3-byte metric, 1-byte sub-TLV len (0).
        let mut tlvs = vec![TLV_EXTENDED_IS_REACHABILITY, 11];
        // Neighbor ID (7 bytes)
        tlvs.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00]);
        // Metric (3 bytes, big-endian 24-bit) = 10
        tlvs.extend_from_slice(&[0x00, 0x00, 0x0A]);
        // Sub-TLV length = 0
        tlvs.push(0x00);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Extended IS Reachability")
            );
        }
        let neighbors =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "neighbors").unwrap();
        {
            let n = neighbors.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, n), 1);
            {
                let child = &buf.nested_fields(n)[0];
                let fields = child.value.as_container_range().unwrap();
                let nid = nested_field_by_name(&buf, fields, "neighbor_id").unwrap();
                assert_eq!(
                    nid.value,
                    FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00])
                );
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U32(10));
            }
        }
    }

    #[test]
    fn parse_tlv_extended_is_reachability_with_sub_tlvs() {
        // TLV 22: one neighbor with sub-TLVs (sub-TLV data is skipped).
        let sub_tlv_data = [0x06, 0x04, 0x0A, 0x00, 0x00, 0x01]; // sub-TLV type 6, len 4
        let entry_len = 11 + sub_tlv_data.len();
        let mut tlvs = vec![TLV_EXTENDED_IS_REACHABILITY, entry_len as u8];
        tlvs.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01]); // Neighbor ID
        tlvs.extend_from_slice(&[0x00, 0x01, 0x00]); // Metric = 256
        tlvs.push(sub_tlv_data.len() as u8); // Sub-TLV length
        tlvs.extend_from_slice(&sub_tlv_data);
        let data = build_l2_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let neighbors =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "neighbors").unwrap();
        {
            let n = neighbors.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, n), 1);
            {
                let child = &buf.nested_fields(n)[0];
                let fields = child.value.as_container_range().unwrap();
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U32(256));
            }
        }
    }

    #[test]
    fn parse_tlv_ip_internal_reachability() {
        // TLV 128: one IP reachability entry (12 bytes each).
        // Layout: metric_byte(1) + 3 padding bytes + IP(4) + Mask(4) = 12.
        let mut tlvs = vec![TLV_IP_INTERNAL_REACHABILITY, 12];
        tlvs.push(10); // default metric (low 6 bits = 10)
        tlvs.extend_from_slice(&[0x00, 0x00, 0x00]); // delay/expense/error metrics
        tlvs.extend_from_slice(&[10, 0, 0, 0]); // IP address
        tlvs.extend_from_slice(&[255, 255, 255, 0]); // Subnet mask
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("IP Internal Reachability")
            );
        }
        let entries =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "entries").unwrap();
        {
            let e = entries.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, e), 1);
            {
                let child = &buf.nested_fields(e)[0];
                let fields = child.value.as_container_range().unwrap();
                let ip = nested_field_by_name(&buf, fields, "ip_address").unwrap();
                assert_eq!(ip.value, FieldValue::Ipv4Addr([10, 0, 0, 0]));
                let mask = nested_field_by_name(&buf, fields, "subnet_mask").unwrap();
                assert_eq!(mask.value, FieldValue::Ipv4Addr([255, 255, 255, 0]));
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U8(10));
            }
        }
    }

    #[test]
    fn parse_tlv_ip_external_reachability() {
        // TLV 130: same format as 128 but different type code.
        let mut tlvs = vec![TLV_IP_EXTERNAL_REACHABILITY, 12];
        tlvs.push(20); // metric = 20
        tlvs.extend_from_slice(&[0x00, 0x00, 0x00]);
        tlvs.extend_from_slice(&[172, 16, 0, 0]); // IP
        tlvs.extend_from_slice(&[255, 255, 0, 0]); // Mask
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("IP External Reachability")
            );
        }
        let entries =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "entries").unwrap();
        {
            let e = entries.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, e), 1);
            {
                let child = &buf.nested_fields(e)[0];
                let fields = child.value.as_container_range().unwrap();
                let ip = nested_field_by_name(&buf, fields, "ip_address").unwrap();
                assert_eq!(ip.value, FieldValue::Ipv4Addr([172, 16, 0, 0]));
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U8(20));
            }
        }
    }

    #[test]
    fn parse_tlv_lsp_entries() {
        // TLV 9: one LSP entry (16 bytes each).
        // Layout: remaining_lifetime(2) + LSP ID(8) + seq(4) + checksum(2) = 16.
        let mut tlvs = vec![TLV_LSP_ENTRIES, 16];
        tlvs.extend_from_slice(&600u16.to_be_bytes()); // remaining_lifetime
        // LSP ID (8 bytes)
        tlvs.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00]);
        tlvs.extend_from_slice(&0x00000003u32.to_be_bytes()); // sequence number
        tlvs.extend_from_slice(&0xBEEFu16.to_be_bytes()); // checksum
        let data = build_l1_csnp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("LSP Entries")
            );
        }
        let entries =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "entries").unwrap();
        {
            let e = entries.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, e), 1);
            {
                let child = &buf.nested_fields(e)[0];
                let fields = child.value.as_container_range().unwrap();
                let lsp_id = nested_field_by_name(&buf, fields, "lsp_id").unwrap();
                assert_eq!(
                    lsp_id.value,
                    FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00])
                );
                let seq = nested_field_by_name(&buf, fields, "sequence_number").unwrap();
                assert_eq!(seq.value, FieldValue::U32(3));
                let lifetime = nested_field_by_name(&buf, fields, "remaining_lifetime").unwrap();
                assert_eq!(lifetime.value, FieldValue::U16(600));
                let cksum = nested_field_by_name(&buf, fields, "checksum").unwrap();
                assert_eq!(cksum.value, FieldValue::U16(0xBEEF));
            }
        }
    }

    #[test]
    fn parse_tlv_p2p_three_way_adj() {
        // TLV 240: state = 0 (Up).
        let tlvs = [TLV_P2P_THREE_WAY_ADJ, 1, 0x00];
        let data = build_p2p_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("P2P Three-Way Adjacency")
            );
        }
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "state").unwrap(),
            FieldValue::U8(0)
        );
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "state")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Up")
            );
        }
    }

    #[test]
    fn parse_tlv_p2p_three_way_adj_initializing() {
        let tlvs = [TLV_P2P_THREE_WAY_ADJ, 1, 0x01];
        let data = build_p2p_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "state")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Initializing")
            );
        }
    }

    #[test]
    fn parse_tlv_p2p_three_way_adj_down() {
        let tlvs = [TLV_P2P_THREE_WAY_ADJ, 1, 0x02];
        let data = build_p2p_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "state")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Down")
            );
        }
    }

    #[test]
    fn parse_tlv_p2p_three_way_adj_unknown_state() {
        let tlvs = [TLV_P2P_THREE_WAY_ADJ, 1, 0xFF];
        let data = build_p2p_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "state")
                .unwrap();
            assert_eq!(base.descriptor.display_fn.unwrap()(&base.value, &[]), None);
        }
    }

    #[test]
    fn parse_tlv_p2p_three_way_adj_empty() {
        // Empty P2P adjacency TLV — returns empty fields, raw fallback.
        let tlvs = [TLV_P2P_THREE_WAY_ADJ, 0];
        let data = build_p2p_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "state").is_none());
    }

    #[test]
    fn parse_tlv_authentication() {
        // TLV 10: auth type 1 (Cleartext Password).
        let tlvs = [TLV_AUTHENTICATION, 5, 0x01, b'p', b'a', b's', b's'];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Authentication")
            );
        }
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "auth_type").unwrap(),
            FieldValue::U8(1)
        );
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "auth_type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Cleartext Password")
            );
        }
    }

    #[test]
    fn parse_tlv_authentication_hmac_md5() {
        let tlvs = [TLV_AUTHENTICATION, 1, 54]; // auth type 54 = HMAC-MD5
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "auth_type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("HMAC-MD5")
            );
        }
    }

    #[test]
    fn parse_tlv_authentication_reserved() {
        let tlvs = [TLV_AUTHENTICATION, 1, 0]; // auth type 0 = Reserved
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "auth_type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Reserved")
            );
        }
    }

    #[test]
    fn parse_tlv_authentication_routing_domain_private() {
        let tlvs = [TLV_AUTHENTICATION, 1, 255]; // auth type 255
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "auth_type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Routing Domain Private")
            );
        }
    }

    #[test]
    fn parse_tlv_authentication_unknown_type() {
        let tlvs = [TLV_AUTHENTICATION, 1, 99]; // auth type 99 = Unknown
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "auth_type")
                .unwrap();
            assert_eq!(base.descriptor.display_fn.unwrap()(&base.value, &[]), None);
        }
    }

    #[test]
    fn parse_tlv_authentication_empty() {
        // Empty auth TLV — returns empty fields, raw fallback.
        let tlvs = [TLV_AUTHENTICATION, 0];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "auth_type").is_none());
    }

    #[test]
    fn parse_tlv_te_router_id() {
        // TLV 134: 4-byte router ID.
        let tlvs = [TLV_TE_ROUTER_ID, 4, 10, 0, 0, 1];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("TE Router ID")
            );
        }
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "router_id").unwrap(),
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_tlv_te_router_id_too_short() {
        // TLV 134 with only 3 bytes — returns empty, raw fallback.
        let tlvs = [TLV_TE_ROUTER_ID, 3, 10, 0, 0];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "router_id").is_none());
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_ipv6_reachability() {
        // TLV 236: one IPv6 prefix entry.
        // Layout: metric(4) + control(1) + prefix_len(1) + prefix_bytes.
        let prefix_len: u8 = 64;
        let prefix_bytes = (prefix_len as usize).div_ceil(8); // 8
        let entry_len = 4 + 1 + 1 + prefix_bytes; // 14
        let mut tlvs = vec![TLV_IPV6_REACHABILITY, entry_len as u8];
        tlvs.extend_from_slice(&100u32.to_be_bytes()); // metric = 100
        tlvs.push(0x00); // control (no sub-TLVs, up, internal)
        tlvs.push(prefix_len);
        // Prefix: 2001:db8:: (first 8 bytes)
        tlvs.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("IPv6 Reachability")
            );
        }
        let prefixes =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "prefixes").unwrap();
        {
            let p = prefixes.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, p), 1);
            {
                let child = &buf.nested_fields(p)[0];
                let fields = child.value.as_container_range().unwrap();
                let pl = nested_field_by_name(&buf, fields, "prefix_length").unwrap();
                assert_eq!(pl.value, FieldValue::U8(64));
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U32(100));
            }
        }
    }

    #[test]
    fn parse_tlv_ipv6_reachability_with_sub_tlvs() {
        // TLV 236 with sub-TLVs present (control bit 0x20).
        let prefix_len: u8 = 48;
        let prefix_bytes = (prefix_len as usize).div_ceil(8); // 6
        let sub_tlv_data = [0x01, 0x02, 0xAA, 0xBB]; // 4 bytes of sub-TLV
        let entry_len = 4 + 1 + 1 + prefix_bytes + 1 + sub_tlv_data.len(); // 17
        let mut tlvs = vec![TLV_IPV6_REACHABILITY, entry_len as u8];
        tlvs.extend_from_slice(&50u32.to_be_bytes()); // metric
        tlvs.push(0x20); // control: sub-TLVs present
        tlvs.push(prefix_len);
        tlvs.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]); // prefix bytes
        tlvs.push(sub_tlv_data.len() as u8); // sub-TLV length
        tlvs.extend_from_slice(&sub_tlv_data);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let prefixes =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "prefixes").unwrap();
        {
            let r = prefixes.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, r), 1);
        }
    }

    #[test]
    fn parse_tlv_extended_ip_reachability_with_sub_tlvs() {
        // TLV 135 with sub-TLVs present (control bit 0x40).
        let prefix_len: u8 = 24;
        let prefix_bytes = 3;
        let sub_tlv_data = [0x01, 0x01, 0xFF]; // 3 bytes of sub-TLV
        // Total entry: metric(4) + control(1) + prefix(3) + sub_len(1) + sub_data(3) = 12
        let entry_len = 4 + 1 + prefix_bytes + 1 + sub_tlv_data.len();
        let mut tlvs = vec![TLV_EXTENDED_IP_REACHABILITY, entry_len as u8];
        tlvs.extend_from_slice(&20u32.to_be_bytes()); // metric
        tlvs.push(prefix_len | 0x40); // control: prefix_len=24, sub-TLVs present
        tlvs.extend_from_slice(&[192, 168, 1]); // prefix bytes
        tlvs.push(sub_tlv_data.len() as u8);
        tlvs.extend_from_slice(&sub_tlv_data);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let prefixes =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "prefixes").unwrap();
        {
            let p = prefixes.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, p), 1);
            {
                let child = &buf.nested_fields(p)[0];
                let fields = child.value.as_container_range().unwrap();
                let metric = nested_field_by_name(&buf, fields, "metric").unwrap();
                assert_eq!(metric.value, FieldValue::U32(20));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Multi-topology TLV tests (raw fallback for unsupported MT TLVs)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tlv_mt_is_neighbors_raw() {
        // TLV 222: MT IS Neighbors — not fully parsed, falls through to raw.
        let tlvs = [TLV_MT_IS_NEIGHBORS, 4, 0x01, 0x02, 0x03, 0x04];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("MT IS Neighbors")
            );
        }
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_mt_ip_reachability_raw() {
        // TLV 235: MT IP Reachability — not fully parsed, raw fallback.
        let tlvs = [TLV_MT_IP_REACHABILITY, 4, 0x01, 0x02, 0x03, 0x04];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("MT IP Reachability")
            );
        }
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_mt_ipv6_reachability_raw() {
        // TLV 237: MT IPv6 Reachability — not fully parsed, raw fallback.
        let tlvs = [TLV_MT_IPV6_REACHABILITY, 4, 0x01, 0x02, 0x03, 0x04];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("MT IPv6 Reachability")
            );
        }
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_router_capability_raw() {
        // TLV 242: Router Capability — not fully parsed, raw fallback.
        let tlvs = [TLV_ROUTER_CAPABILITY, 2, 0x01, 0x02];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("Router Capability")
            );
        }
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_unknown_tlv_raw() {
        // Unknown TLV type 250 — should produce "raw" field.
        let tlvs = [250, 2, 0xDE, 0xAD];
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "type")
                .unwrap();
            assert!(base.descriptor.display_fn.unwrap()(&base.value, &[]).is_none());
        };
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").unwrap(),
            FieldValue::Bytes(&[0xDE, 0xAD])
        );
    }

    // -----------------------------------------------------------------------
    // Error path tests
    // -----------------------------------------------------------------------

    #[test]
    fn reject_unsupported_id_length() {
        let mut data = build_l1_lan_iih(&[]);
        data[3] = 8; // ID length = 8 (unsupported)
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidFieldValue {
                field: "id_length",
                value: 8,
            } => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_invalid_version2() {
        let mut data = build_l1_lan_iih(&[]);
        data[5] = 0x02; // version2 = 2 (invalid)
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidHeader(_) => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_header_length_mismatch() {
        let mut data = build_l1_lan_iih(&[]);
        data[1] = 20; // Header length says 20 but LAN IIH expects 27
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidHeader("IS-IS header length mismatch") => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_pdu_length_smaller_than_header() {
        let mut data = build_l1_lan_iih(&[]);
        // Set PDU length to 10 (smaller than header size 27)
        let pdu_len_bytes = 10u16.to_be_bytes();
        data[17] = pdu_len_bytes[0];
        data[18] = pdu_len_bytes[1];
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::InvalidHeader("IS-IS PDU length smaller than header size") => {}
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn reject_pdu_length_exceeds_buffer() {
        let mut data = build_l1_lan_iih(&[]);
        // Set PDU length to 1000 (exceeds 27 byte buffer)
        let pdu_len_bytes = 1000u16.to_be_bytes();
        data[17] = pdu_len_bytes[0];
        data[18] = pdu_len_bytes[1];
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated {
                expected: 1000,
                actual: 27,
            } => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn reject_truncated_p2p_iih() {
        // Only 15 bytes (need 20 for P2P IIH).
        let data = [
            0x83,
            20,
            0x01,
            0x00,
            PDU_TYPE_P2P_IIH,
            0x01,
            0x00,
            0x00,
            0x03,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
        ];
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected: 20, .. } => {}
            other => panic!("expected Truncated with expected=20, got {other:?}"),
        }
    }

    #[test]
    fn reject_truncated_lsp() {
        // Only 20 bytes (need 27 for LSP).
        let mut data = vec![0x83, 27, 0x01, 0x00, PDU_TYPE_L1_LSP, 0x01, 0x00, 0x00];
        data.extend_from_slice(&27u16.to_be_bytes());
        data.extend_from_slice(&[0x00; 10]); // total = 20
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected: 27, .. } => {}
            other => panic!("expected Truncated with expected=27, got {other:?}"),
        }
    }

    #[test]
    fn reject_truncated_csnp() {
        // Only 25 bytes (need 33 for CSNP).
        let mut data = vec![0x83, 33, 0x01, 0x00, PDU_TYPE_L1_CSNP, 0x01, 0x00, 0x00];
        data.extend_from_slice(&33u16.to_be_bytes());
        data.extend_from_slice(&[0x00; 15]); // total = 25
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected: 33, .. } => {}
            other => panic!("expected Truncated with expected=33, got {other:?}"),
        }
    }

    #[test]
    fn reject_truncated_psnp() {
        // Only 12 bytes (need 17 for PSNP).
        let mut data = vec![0x83, 17, 0x01, 0x00, PDU_TYPE_L1_PSNP, 0x01, 0x00, 0x00];
        data.extend_from_slice(&17u16.to_be_bytes());
        data.extend_from_slice(&[0x00; 2]); // total = 12
        let mut buf = DissectBuffer::new();
        let err = IsisDissector.dissect(&data, &mut buf, 0).unwrap_err();
        match err {
            PacketError::Truncated { expected: 17, .. } => {}
            other => panic!("expected Truncated with expected=17, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases for TLV parsers
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tlv_ip_address_odd_length() {
        // IP address TLV with 5 bytes (not a multiple of 4) — returns empty.
        let tlvs = [TLV_IP_INTERFACE_ADDRESS, 5, 10, 0, 0, 1, 0xFF];
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "addresses").is_none());
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_ipv6_address_odd_length() {
        // IPv6 address TLV with 15 bytes (not a multiple of 16) — returns empty.
        let mut tlvs = vec![TLV_IPV6_INTERFACE_ADDRESS, 15];
        tlvs.extend_from_slice(&[0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        tlvs.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let data = build_l1_lan_iih(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "addresses").is_none());
        assert!(tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "raw").is_some());
    }

    #[test]
    fn parse_tlv_restart_flags_all() {
        // All 5 flags set: RR|RA|SA|PR|PA = 0x1F.
        let data = build_p2p_iih(&[TLV_RESTART, 0x03, 0x1F, 0x01, 0x00]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "flags")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("RR|RA|SA|PR|PA")
            );
        }
    }

    #[test]
    fn parse_tlv_restart_short_no_remaining_time() {
        // Only 1 byte (flags only, no remaining_time).
        let data = build_p2p_iih(&[TLV_RESTART, 0x01, 0x02]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        assert_eq!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "flags").unwrap(),
            FieldValue::U8(0x02)
        );
        {
            let base = buf
                .nested_fields(&nth_tlv_range(&buf, &tlvs_range, 0))
                .iter()
                .find(|f: &&Field<'_>| f.name() == "flags")
                .unwrap();
            assert_eq!(
                base.descriptor.display_fn.unwrap()(&base.value, &[]),
                Some("RA")
            );
        }
        // remaining_time not present since value.len() < 3.
        assert!(
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "remaining_time").is_none()
        );
    }

    #[test]
    fn parse_l1_lan_iih_with_id_length_6() {
        // id_length = 6 is valid (same as 0, which means default 6).
        let mut data = build_l1_lan_iih(&[]);
        data[3] = 6; // id_length = 6
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "id_length").unwrap().value,
            FieldValue::U8(6)
        );
    }

    #[test]
    fn parse_lsp_entries_in_psnp() {
        // LSP Entries TLV (9) inside a PSNP, testing through L2 path.
        let mut tlvs = vec![TLV_LSP_ENTRIES, 16];
        tlvs.extend_from_slice(&300u16.to_be_bytes());
        tlvs.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x00]);
        tlvs.extend_from_slice(&0x0000000Au32.to_be_bytes());
        tlvs.extend_from_slice(&0xCAFEu16.to_be_bytes());
        let data = build_l2_psnp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let entries =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "entries").unwrap();
        {
            let e = entries.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, e), 1);
            {
                let child = &buf.nested_fields(e)[0];
                let fields = child.value.as_container_range().unwrap();
                let lsp_id = nested_field_by_name(&buf, fields, "lsp_id").unwrap();
                assert_eq!(
                    lsp_id.value,
                    FieldValue::Bytes(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x00])
                );
            }
        }
    }

    #[test]
    fn parse_tlv_lsp_entries_multiple() {
        // Two LSP entries in a single TLV.
        let mut tlvs = vec![TLV_LSP_ENTRIES, 32]; // 2 * 16
        // Entry 1
        tlvs.extend_from_slice(&500u16.to_be_bytes());
        tlvs.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00]);
        tlvs.extend_from_slice(&1u32.to_be_bytes());
        tlvs.extend_from_slice(&0xAAAAu16.to_be_bytes());
        // Entry 2
        tlvs.extend_from_slice(&400u16.to_be_bytes());
        tlvs.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x00]);
        tlvs.extend_from_slice(&2u32.to_be_bytes());
        tlvs.extend_from_slice(&0xBBBBu16.to_be_bytes());
        let data = build_l2_csnp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let entries =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "entries").unwrap();
        {
            let r = entries.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, r), 2);
        }
    }

    #[test]
    fn dissector_name_and_short_name() {
        assert_eq!(
            IsisDissector.name(),
            "Intermediate System to Intermediate System"
        );
        assert_eq!(IsisDissector.short_name(), "ISIS");
    }

    #[test]
    fn field_descriptors_not_empty() {
        let fds = IsisDissector.field_descriptors();
        assert!(!fds.is_empty());
        assert_eq!(fds[FD_NLPID].name, "nlpid");
        assert_eq!(fds[FD_TLVS].name, "tlvs");
    }

    #[test]
    fn parse_tlv_ip_internal_reachability_multiple() {
        // Two IP reachability entries (24 bytes total).
        let mut tlvs = vec![TLV_IP_INTERNAL_REACHABILITY, 24];
        // Entry 1
        tlvs.push(5); // metric
        tlvs.extend_from_slice(&[0x00, 0x00, 0x00]);
        tlvs.extend_from_slice(&[10, 1, 0, 0]);
        tlvs.extend_from_slice(&[255, 255, 255, 0]);
        // Entry 2
        tlvs.push(15); // metric
        tlvs.extend_from_slice(&[0x00, 0x00, 0x00]);
        tlvs.extend_from_slice(&[192, 168, 0, 0]);
        tlvs.extend_from_slice(&[255, 255, 0, 0]);
        let data = build_l1_lsp(&tlvs);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let entries =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "entries").unwrap();
        {
            let r = entries.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, r), 2);
        }
    }

    #[test]
    fn parse_nlpid_name_coverage() {
        // Exercise nlpid_name for various NLPID values through Protocols Supported TLV.
        let data = build_l1_lan_iih(&[
            TLV_PROTOCOLS_SUPPORTED,
            5,
            0xCC, // IPv4
            0x8E, // IPv6
            0x81, // CLNP
            0x82, // ES-IS
            0x83, // IS-IS
        ]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let protocols =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "protocols").unwrap();
        {
            let r = protocols.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, r), 5);
        }
    }

    #[test]
    fn parse_nlpid_unknown() {
        // Unknown NLPID value in Protocols Supported.
        let data = build_l1_lan_iih(&[TLV_PROTOCOLS_SUPPORTED, 1, 0x42]);
        let mut buf = DissectBuffer::new();
        IsisDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("ISIS").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs_range = tlvs_field.value.as_container_range().unwrap().clone();
        let protocols =
            tlv_field_value(&buf, &nth_tlv_range(&buf, &tlvs_range, 0), "protocols").unwrap();
        {
            let protos = protocols.as_container_range().unwrap();
            assert_eq!(count_tlv_objects(&buf, protos), 1);
            {
                let child = &buf.nested_fields(protos)[0];
                let fields = child.value.as_container_range().unwrap();
                let nlpid = nested_field_by_name(&buf, fields, "nlpid").unwrap();
                // Unknown NLPID has no display name
                assert!(nlpid.descriptor.display_fn.unwrap()(&nlpid.value, &[]).is_none());
            }
        }
    }
}
