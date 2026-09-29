//! ICMPv6 (Internet Control Message Protocol for IPv6) dissector.
//!
//! ## References
//! - RFC 4443: <https://www.rfc-editor.org/rfc/rfc4443>
//! - RFC 4861 (Neighbor Discovery — defines types 133-137): <https://www.rfc-editor.org/rfc/rfc4861>
//! - RFC 2710 (MLDv1 — defines types 130-132): <https://www.rfc-editor.org/rfc/rfc2710>
//! - RFC 3810 (MLDv2 — defines type 143 and extended query): <https://www.rfc-editor.org/rfc/rfc3810>
//! - RFC 9777 (MLDv2, obsoletes RFC 3810 — Maximum Response Code / QQIC encoding): <https://www.rfc-editor.org/rfc/rfc9777>
//! - RFC 4286 (Multicast Router Discovery — types 151-153): <https://www.rfc-editor.org/rfc/rfc4286>
//! - RFC 6275 (Mobile IPv6 — types 144-145): <https://www.rfc-editor.org/rfc/rfc6275>
//! - RFC 4191 (Default Router Preferences — Route Information option): <https://www.rfc-editor.org/rfc/rfc4191>
//! - RFC 8106 (IPv6 RA DNS options — RDNSS/DNSSL): <https://www.rfc-editor.org/rfc/rfc8106>
//! - RFC 8781 (PREF64 — NAT64 prefix in RA): <https://www.rfc-editor.org/rfc/rfc8781>
//! - RFC 8335 (Extended Echo — types 160-161): <https://www.rfc-editor.org/rfc/rfc8335>
//! - RFC 4884 (Extended ICMP Multi-Part Messages — updates RFC 4443, adds Length field
//!   to Types 1 and 3): <https://www.rfc-editor.org/rfc/rfc4884>

#![deny(missing_docs)]

mod rpl;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_fqdn_labels};
use packet_dissector_core::icmp_extension;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv6_addr};

/// Specification references for the ICMPv6 dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 4443",
        "Internet Control Message Protocol (ICMPv6) for the Internet Protocol \
         Version 6 (IPv6) Specification",
        "https://www.rfc-editor.org/rfc/rfc4443",
    ),
    SpecReference::new(
        "RFC 4861",
        "Neighbor Discovery for IP version 6 (IPv6)",
        "https://www.rfc-editor.org/rfc/rfc4861",
    ),
    SpecReference::new(
        "RFC 2710",
        "Multicast Listener Discovery (MLD) for IPv6",
        "https://www.rfc-editor.org/rfc/rfc2710",
    ),
    SpecReference::new(
        "RFC 3810",
        "Multicast Listener Discovery Version 2 (MLDv2) for IPv6",
        "https://www.rfc-editor.org/rfc/rfc3810",
    ),
    SpecReference::new(
        "RFC 9777",
        "Multicast Listener Discovery Version 2 (MLDv2) for IPv6",
        "https://www.rfc-editor.org/rfc/rfc9777",
    ),
    SpecReference::new(
        "RFC 4286",
        "Multicast Router Discovery",
        "https://www.rfc-editor.org/rfc/rfc4286",
    ),
    SpecReference::new(
        "RFC 6275",
        "Mobility Support in IPv6",
        "https://www.rfc-editor.org/rfc/rfc6275",
    ),
    SpecReference::new(
        "RFC 4191",
        "Default Router Preferences and More-Specific Routes",
        "https://www.rfc-editor.org/rfc/rfc4191",
    ),
    SpecReference::new(
        "RFC 8106",
        "IPv6 Router Advertisement Options for DNS Configuration",
        "https://www.rfc-editor.org/rfc/rfc8106",
    ),
    SpecReference::new(
        "RFC 8781",
        "Discovering PREF64 in Router Advertisements",
        "https://www.rfc-editor.org/rfc/rfc8781",
    ),
    SpecReference::new(
        "RFC 8335",
        "PROBE: A Utility for Probing Interfaces",
        "https://www.rfc-editor.org/rfc/rfc8335",
    ),
    SpecReference::new(
        "RFC 4884",
        "Extended ICMP to Support Multi-Part Messages",
        "https://www.rfc-editor.org/rfc/rfc4884",
    ),
];

/// Returns a human-readable name for ICMPv6 type values.
fn icmpv6_type_name(v: u8) -> Option<&'static str> {
    // IANA "ICMPv6 'type' Numbers" registry
    // <https://www.iana.org/assignments/icmpv6-parameters>
    match v {
        1 => Some("Destination Unreachable"),
        2 => Some("Packet Too Big"),
        3 => Some("Time Exceeded"),
        4 => Some("Parameter Problem"),
        128 => Some("Echo Request"),
        129 => Some("Echo Reply"),
        130 => Some("Multicast Listener Query"),
        131 => Some("Multicast Listener Report"),
        132 => Some("Multicast Listener Done"),
        133 => Some("Router Solicitation"),
        134 => Some("Router Advertisement"),
        135 => Some("Neighbor Solicitation"),
        136 => Some("Neighbor Advertisement"),
        137 => Some("Redirect Message"),
        138 => Some("Router Renumbering"),
        139 => Some("ICMP Node Information Query"),
        140 => Some("ICMP Node Information Response"),
        141 => Some("Inverse Neighbor Discovery Solicitation Message"),
        142 => Some("Inverse Neighbor Discovery Advertisement Message"),
        143 => Some("Version 2 Multicast Listener Report"),
        144 => Some("Home Agent Address Discovery Request Message"),
        145 => Some("Home Agent Address Discovery Reply Message"),
        146 => Some("Mobile Prefix Solicitation"),
        147 => Some("Mobile Prefix Advertisement"),
        148 => Some("Certification Path Solicitation Message"),
        149 => Some("Certification Path Advertisement Message"),
        150 => Some("Experimental Mobility Protocols"),
        151 => Some("Multicast Router Advertisement"),
        152 => Some("Multicast Router Solicitation"),
        153 => Some("Multicast Router Termination"),
        154 => Some("FMIPv6 Messages"),
        155 => Some("RPL Control Message"),
        156 => Some("ILNPv6 Locator Update Message"),
        157 => Some("Duplicate Address Request"),
        158 => Some("Duplicate Address Confirmation"),
        159 => Some("MPL Control Message"),
        160 => Some("Extended Echo Request"),
        161 => Some("Extended Echo Reply"),
        _ => None,
    }
}

fn ndp_option_type_name(v: u8) -> Option<&'static str> {
    // IANA "IPv6 Neighbor Discovery Option Formats" registry
    // <https://www.iana.org/assignments/icmpv6-parameters>
    match v {
        // RFC 4861, Section 4.6
        1 => Some("Source Link-Layer Address"),
        2 => Some("Target Link-Layer Address"),
        3 => Some("Prefix Information"),
        4 => Some("Redirected Header"),
        5 => Some("MTU"),
        // RFC 6275, Sections 7.3 and 7.4
        7 => Some("Advertisement Interval"),
        8 => Some("Home Agent Information"),
        // RFC 3122, Section 3.1
        9 => Some("Source Address List"),
        10 => Some("Target Address List"),
        // RFC 3971, Sections 5.1-5.3 and 6.4
        11 => Some("CGA"),
        12 => Some("RSA Signature"),
        13 => Some("Timestamp"),
        14 => Some("Nonce"),
        15 => Some("Trust Anchor"),
        16 => Some("Certificate"),
        // RFC 8801, Section 3.1
        21 => Some("PvD ID Router Advertisement"),
        // RFC 4191, Section 2.3
        24 => Some("Route Information"),
        // RFC 8106
        25 => Some("Recursive DNS Server"),
        // RFC 5175, Section 4
        26 => Some("RA Flags Extension"),
        // RFC 8106
        31 => Some("DNS Search List"),
        // RFC 6775, Sections 4.1-4.3 (Address Registration extended by
        // RFC 8505, Section 4.1)
        33 => Some("Address Registration"),
        34 => Some("6LoWPAN Context"),
        35 => Some("Authoritative Border Router"),
        // RFC 8910, Section 2.3
        37 => Some("Captive-Portal"),
        // RFC 8781
        38 => Some("PREF64"),
        _ => None,
    }
}

/// Minimum ICMPv6 header size (Type + Code + Checksum + 4 bytes type-specific).
/// RFC 4443, Section 2.1.
const HEADER_SIZE: usize = 8;

/// Minimum header size for Router Advertisement (RFC 4861, Section 4.2).
const RA_HEADER_SIZE: usize = 16;

/// Minimum header size for Neighbor Solicitation / Neighbor Advertisement
/// (RFC 4861, Sections 4.3 and 4.4).
const NS_NA_HEADER_SIZE: usize = 24;

/// Minimum header size for Redirect (RFC 4861, Section 4.5).
const REDIRECT_HEADER_SIZE: usize = 40;

/// Minimum header size for MLD messages (RFC 2710, Section 3).
const MLD_HEADER_SIZE: usize = 24;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_TYPE: usize = 0;
const FD_CODE: usize = 1;
const FD_CHECKSUM: usize = 2;
const FD_MTU: usize = 3;
const FD_POINTER: usize = 4;
const FD_IDENTIFIER: usize = 5;
const FD_SEQUENCE_NUMBER: usize = 6;
const FD_DATA: usize = 7;
const FD_LENGTH: usize = 8;
const FD_MAX_RESPONSE_DELAY: usize = 9;
const FD_MULTICAST_ADDRESS: usize = 10;
const FD_S_FLAG: usize = 11;
const FD_QRV: usize = 12;
const FD_QQIC: usize = 13;
const FD_NUM_SOURCES: usize = 14;
const FD_SOURCES: usize = 15;
const FD_CUR_HOP_LIMIT: usize = 16;
const FD_FLAGS: usize = 17;
const FD_ROUTER_LIFETIME: usize = 18;
const FD_REACHABLE_TIME: usize = 19;
const FD_RETRANS_TIMER: usize = 20;
const FD_TARGET_ADDRESS: usize = 21;
const FD_DESTINATION_ADDRESS: usize = 22;
const FD_OPTIONS: usize = 23;
const FD_NUM_RECORDS: usize = 24;
const FD_RECORDS: usize = 25;
const FD_HOME_AGENT_ADDRESSES: usize = 26;
const FD_QUERY_INTERVAL: usize = 27;
const FD_ROBUSTNESS_VARIABLE: usize = 28;
const FD_INVOKING_PACKET: usize = 29;
/// RFC 8335, Section 2 — the Sequence Number in Extended Echo messages is
/// an 8-bit field, unlike the 16-bit field in classic Echo (RFC 4443, §4.1).
const FD_SEQUENCE_NUMBER_U8: usize = 30;
const FD_EXTENSIONS: usize = 31;
const FD_MAX_RESPONSE_DELAY_MS: usize = 32;
const FD_QQI: usize = 33;
const FD_RR_SEQUENCE_NUMBER: usize = 34;
const FD_SEGMENT_NUMBER: usize = 35;
const FD_MAX_DELAY: usize = 36;
const FD_QTYPE: usize = 37;
const FD_NI_FLAGS: usize = 38;
const FD_NONCE: usize = 39;
const FD_COMPONENT: usize = 40;
const FD_ALL_COMPONENTS: usize = 41;
const FD_STATUS: usize = 42;
const FD_TID: usize = 43;
const FD_REGISTRATION_LIFETIME: usize = 44;
const FD_ROVR: usize = 45;
const FD_REGISTERED_ADDRESS: usize = 46;
pub(crate) const FD_RPL_INSTANCE_ID: usize = 47;
pub(crate) const FD_VERSION_NUMBER: usize = 48;
pub(crate) const FD_RANK: usize = 49;
pub(crate) const FD_GROUNDED: usize = 50;
pub(crate) const FD_MOP: usize = 51;
pub(crate) const FD_PRF: usize = 52;
pub(crate) const FD_DTSN: usize = 53;
pub(crate) const FD_RPL_FLAGS: usize = 54;
pub(crate) const FD_DODAG_ID: usize = 55;
pub(crate) const FD_DAO_SEQUENCE: usize = 56;
pub(crate) const FD_RPL_OPTIONS: usize = 57;
pub(crate) const FD_RPL_STATUS: usize = FD_STATUS;

/// Minimum IPv6 header size (RFC 8200, Section 3).
const IPV6_MIN_HEADER: usize = 40;

/// Child field descriptor indices for [`INVOKING_PACKET_CHILDREN`].
const IPC_VERSION: usize = 0;
const IPC_NEXT_HEADER: usize = 1;
const IPC_SRC: usize = 2;
const IPC_DST: usize = 3;
const IPC_SRC_PORT: usize = 4;
const IPC_DST_PORT: usize = 5;
const IPC_TRANSPORT_DATA: usize = 6;

/// Child field descriptor indices for [`NDP_OPTION_CHILDREN`].
const NOC_TYPE: usize = 0;
const NOC_LENGTH: usize = 1;
const NOC_LINK_LAYER_ADDRESS: usize = 2;
const NOC_PREFIX_LENGTH: usize = 3;
const NOC_FLAGS: usize = 4;
const NOC_VALID_LIFETIME: usize = 5;
const NOC_PREFERRED_LIFETIME: usize = 6;
const NOC_PREFIX: usize = 7;
const NOC_ROUTE_LIFETIME: usize = 8;
const NOC_LIFETIME: usize = 9;
const NOC_ADDRESSES: usize = 10;
const NOC_DOMAIN_NAMES: usize = 11;
const NOC_SCALED_LIFETIME: usize = 12;
const NOC_PLC: usize = 13;
const NOC_VALUE: usize = 14;
const NOC_MTU: usize = 15;
const NOC_ADVERTISEMENT_INTERVAL: usize = 16;
const NOC_HOME_AGENT_PREFERENCE: usize = 17;
const NOC_HOME_AGENT_LIFETIME: usize = 18;
const NOC_PAD_LENGTH: usize = 19;
const NOC_CGA_PARAMETERS: usize = 20;
const NOC_KEY_HASH: usize = 21;
const NOC_DIGITAL_SIGNATURE: usize = 22;
const NOC_TIMESTAMP: usize = 23;
const NOC_NONCE: usize = 24;
const NOC_NAME_TYPE: usize = 25;
const NOC_NAME: usize = 26;
const NOC_CERT_TYPE: usize = 27;
const NOC_CERTIFICATE: usize = 28;
const NOC_PVD_FLAGS: usize = 29;
const NOC_DELAY: usize = 30;
const NOC_SEQUENCE_NUMBER: usize = 31;
const NOC_PVD_ID: usize = 32;
const NOC_RA_FLAGS: usize = 33;
const NOC_STATUS: usize = 34;
const NOC_OPAQUE: usize = 35;
const NOC_ARO_FLAGS: usize = 36;
const NOC_TID: usize = 37;
const NOC_REGISTRATION_LIFETIME: usize = 38;
const NOC_ROVR: usize = 39;
const NOC_CONTEXT_LENGTH: usize = 40;
const NOC_COMPRESSION_FLAG: usize = 41;
const NOC_CID: usize = 42;
const NOC_VALID_LIFETIME_MINUTES: usize = 43;
const NOC_CONTEXT_PREFIX: usize = 44;
const NOC_VERSION_LOW: usize = 45;
const NOC_VERSION_HIGH: usize = 46;
const NOC_BORDER_ROUTER_ADDRESS: usize = 47;
const NOC_URI: usize = 48;

/// Container descriptor for an NDP option entry.
///
/// `display_fn` resolves the outer container's label to the option kind name
/// (e.g. "Source Link-Layer Address") by looking up the inner `type` field.
static FD_NDP_OPTION: FieldDescriptor = FieldDescriptor {
    name: "option",
    display_name: "Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => ndp_option_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for NDP option entries within the `options` array.
static NDP_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("link_layer_address", "Link-Layer Address", FieldType::Bytes).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("valid_lifetime", "Valid Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("preferred_lifetime", "Preferred Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("prefix", "Prefix", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("route_lifetime", "Route Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("lifetime", "Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("addresses", "Addresses", FieldType::Array).optional(),
    FieldDescriptor::new("domain_names", "Domain Names", FieldType::Array).optional(),
    FieldDescriptor::new("scaled_lifetime", "Scaled Lifetime", FieldType::U16).optional(),
    FieldDescriptor::new("plc", "Prefix Length Code", FieldType::U8).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("mtu", "MTU", FieldType::U32).optional(),
    // RFC 6275, Section 7.3 — Advertisement Interval (milliseconds)
    // <https://www.rfc-editor.org/rfc/rfc6275#section-7.3>
    FieldDescriptor::new(
        "advertisement_interval",
        "Advertisement Interval",
        FieldType::U32,
    )
    .optional(),
    // RFC 6275, Section 7.4 — Home Agent Preference (16-bit signed) and
    // Home Agent Lifetime (seconds)
    // <https://www.rfc-editor.org/rfc/rfc6275#section-7.4>
    FieldDescriptor::new(
        "home_agent_preference",
        "Home Agent Preference",
        FieldType::I32,
    )
    .optional(),
    FieldDescriptor::new("home_agent_lifetime", "Home Agent Lifetime", FieldType::U16).optional(),
    // RFC 3971, Sections 5.1 / 6.4.3 — Pad Length
    // <https://www.rfc-editor.org/rfc/rfc3971#section-5.1>
    FieldDescriptor::new("pad_length", "Pad Length", FieldType::U8).optional(),
    // RFC 3971, Section 5.1 — CGA Parameters
    FieldDescriptor::new("cga_parameters", "CGA Parameters", FieldType::Bytes).optional(),
    // RFC 3971, Section 5.2 — Key Hash and Digital Signature (with padding)
    // <https://www.rfc-editor.org/rfc/rfc3971#section-5.2>
    FieldDescriptor::new("key_hash", "Key Hash", FieldType::Bytes).optional(),
    FieldDescriptor::new("digital_signature", "Digital Signature", FieldType::Bytes).optional(),
    // RFC 3971, Section 5.3.1 — Timestamp (64 bits)
    // <https://www.rfc-editor.org/rfc/rfc3971#section-5.3.1>
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U64).optional(),
    // RFC 3971, Section 5.3.2 — Nonce
    // <https://www.rfc-editor.org/rfc/rfc3971#section-5.3.2>
    FieldDescriptor::new("nonce", "Nonce", FieldType::Bytes).optional(),
    // RFC 3971, Section 6.4.3 — Trust Anchor Name Type and Name
    // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.3>
    FieldDescriptor::new("name_type", "Name Type", FieldType::U8).optional(),
    FieldDescriptor::new("name", "Name", FieldType::Bytes).optional(),
    // RFC 3971, Section 6.4.4 — Cert Type and Certificate (with padding)
    // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.4>
    FieldDescriptor::new("cert_type", "Cert Type", FieldType::U8).optional(),
    FieldDescriptor::new("certificate", "Certificate", FieldType::Bytes).optional(),
    // RFC 8801, Section 3.1 — H|L|R|Reserved|Delay, Sequence Number, PvD ID
    // FQDN
    // <https://www.rfc-editor.org/rfc/rfc8801#section-3.1>
    FieldDescriptor::new("pvd_flags", "PvD Flags", FieldType::U16).optional(),
    FieldDescriptor::new("delay", "Delay", FieldType::U8).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("pvd_id", "PvD ID FQDN", FieldType::Bytes)
        .optional()
        .with_format_fn(format_fqdn_labels),
    // RFC 5175, Section 4 — Router Advertisement flag bits (48 bits)
    // <https://www.rfc-editor.org/rfc/rfc5175#section-4>
    FieldDescriptor::new("ra_flags", "RA Flags", FieldType::Bytes).optional(),
    // RFC 8505, Section 4.1 — (Extended) Address Registration Option:
    // Status, Opaque, Rsvd|I|R|T, TID, Registration Lifetime, ROVR (EUI-64
    // in the RFC 6775 ARO)
    // <https://www.rfc-editor.org/rfc/rfc8505#section-4.1>
    FieldDescriptor::new("status", "Status", FieldType::U8).optional(),
    FieldDescriptor::new("opaque", "Opaque", FieldType::U8).optional(),
    FieldDescriptor::new("aro_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("tid", "Transaction ID", FieldType::U8).optional(),
    FieldDescriptor::new(
        "registration_lifetime",
        "Registration Lifetime",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("rovr", "Registration Ownership Verifier", FieldType::Bytes).optional(),
    // RFC 6775, Section 4.2 — 6LoWPAN Context Option
    // <https://www.rfc-editor.org/rfc/rfc6775#section-4.2>
    FieldDescriptor::new("context_length", "Context Length", FieldType::U8).optional(),
    FieldDescriptor::new("compression_flag", "Compression Flag", FieldType::U8).optional(),
    FieldDescriptor::new("cid", "Context Identifier", FieldType::U8).optional(),
    // RFC 6775, Sections 4.2 / 4.3 — Valid Lifetime in units of 60 seconds
    FieldDescriptor::new(
        "valid_lifetime_minutes",
        "Valid Lifetime (minutes)",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("context_prefix", "Context Prefix", FieldType::Ipv6Addr).optional(),
    // RFC 6775, Section 4.3 — Authoritative Border Router Option
    // <https://www.rfc-editor.org/rfc/rfc6775#section-4.3>
    FieldDescriptor::new("version_low", "Version Low", FieldType::U16).optional(),
    FieldDescriptor::new("version_high", "Version High", FieldType::U16).optional(),
    FieldDescriptor::new("border_router_address", "6LBR Address", FieldType::Ipv6Addr).optional(),
    // RFC 8910, Section 2.3 — Captive-Portal URI
    // <https://www.rfc-editor.org/rfc/rfc8910#section-2.3>
    FieldDescriptor::new("uri", "URI", FieldType::Str).optional(),
];

/// Child field descriptor indices for [`MLDV2_RECORD_CHILDREN`].
const MRC_RECORD_TYPE: usize = 0;
const MRC_AUX_DATA_LEN: usize = 1;
const MRC_NUM_SOURCES: usize = 2;
const MRC_MULTICAST_ADDRESS: usize = 3;
const MRC_SOURCES: usize = 4;

/// Child field descriptors for the invoking IPv6 packet embedded in error messages
/// (RFC 4443, Sections 3.1 and 3.3).
static INVOKING_PACKET_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    FieldDescriptor::new("src", "Source Address", FieldType::Ipv6Addr),
    FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv6Addr),
    FieldDescriptor::new("src_port", "Source Port", FieldType::U16).optional(),
    FieldDescriptor::new("dst_port", "Destination Port", FieldType::U16).optional(),
    FieldDescriptor::new("transport_data", "Transport Data", FieldType::Bytes).optional(),
];

/// Child field descriptors for MLDv2 multicast address record entries.
static MLDV2_RECORD_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("record_type", "Record Type", FieldType::U8),
    FieldDescriptor::new("aux_data_len", "Auxiliary Data Length", FieldType::U8),
    FieldDescriptor::new("num_sources", "Number of Sources", FieldType::U16),
    FieldDescriptor::new(
        "multicast_address",
        "Multicast Address",
        FieldType::Ipv6Addr,
    ),
    FieldDescriptor::new("sources", "Source Addresses", FieldType::Array).optional(),
];

pub(crate) static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => icmpv6_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("code", "Code", FieldType::U8),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("mtu", "MTU", FieldType::U32).optional(),
    FieldDescriptor::new("pointer", "Pointer", FieldType::U32).optional(),
    FieldDescriptor::new("identifier", "Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new(
        "max_response_delay",
        "Maximum Response Delay",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "multicast_address",
        "Multicast Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("s_flag", "Suppress Router-Side Processing", FieldType::U8).optional(),
    FieldDescriptor::new("qrv", "Querier's Robustness Variable", FieldType::U8).optional(),
    FieldDescriptor::new("qqic", "Querier's Query Interval Code", FieldType::U8).optional(),
    FieldDescriptor::new("num_sources", "Number of Sources", FieldType::U16).optional(),
    FieldDescriptor::new("sources", "Source Addresses", FieldType::Array).optional(),
    FieldDescriptor::new("cur_hop_limit", "Current Hop Limit", FieldType::U8).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("router_lifetime", "Router Lifetime", FieldType::U16).optional(),
    FieldDescriptor::new("reachable_time", "Reachable Time", FieldType::U32).optional(),
    FieldDescriptor::new("retrans_timer", "Retransmit Timer", FieldType::U32).optional(),
    FieldDescriptor::new("target_address", "Target Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new(
        "destination_address",
        "Destination Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("options", "Options", FieldType::Array)
        .optional()
        .with_children(NDP_OPTION_CHILDREN),
    FieldDescriptor::new(
        "num_records",
        "Number of Multicast Address Records",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("records", "Multicast Address Records", FieldType::Array)
        .optional()
        .with_children(MLDV2_RECORD_CHILDREN),
    FieldDescriptor::new(
        "home_agent_addresses",
        "Home Agent Addresses",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("query_interval", "Query Interval", FieldType::U16).optional(),
    FieldDescriptor::new("robustness_variable", "Robustness Variable", FieldType::U16).optional(),
    // RFC 4443, Sections 3.1/3.3 — invoking packet in error messages
    FieldDescriptor::new("invoking_packet", "Invoking Packet", FieldType::Object)
        .optional()
        .with_children(INVOKING_PACKET_CHILDREN),
    // RFC 8335, Section 2 — Extended Echo Sequence Number is an 8-bit field.
    // A separate descriptor is needed because the classic Echo (RFC 4443, §4.1)
    // uses a 16-bit Sequence Number (see FD_SEQUENCE_NUMBER above).
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U8).optional(),
    // RFC 4884, Section 7 — ICMP Extension Structure (Types 1 and 3 after the
    // original datagram; Type 160 right after the header per RFC 8335,
    // Section 2).
    // <https://www.rfc-editor.org/rfc/rfc4884#section-7>
    FieldDescriptor::new("extensions", "ICMP Extension Structure", FieldType::Object)
        .optional()
        .with_children(icmp_extension::EXTENSION_CHILDREN),
    // RFC 9777, Section 5.1.3 — Maximum Response Delay (milliseconds) derived
    // from the Maximum Response Code of an MLDv2 Query.
    // <https://www.rfc-editor.org/rfc/rfc9777#section-5.1.3>
    FieldDescriptor::new(
        "max_response_delay_ms",
        "Maximum Response Delay (ms)",
        FieldType::U32,
    )
    .optional(),
    // RFC 9777, Section 5.1.9 — Querier's Query Interval (seconds) derived
    // from QQIC.
    // <https://www.rfc-editor.org/rfc/rfc9777#section-5.1.9>
    FieldDescriptor::new("qqi", "Querier's Query Interval", FieldType::U16).optional(),
    // RFC 2894, Section 3.1 — Router Renumbering SequenceNumber (32 bits),
    // SegmentNumber and MaxDelay (milliseconds)
    // <https://www.rfc-editor.org/rfc/rfc2894#section-3.1>
    FieldDescriptor::new("rr_sequence_number", "Sequence Number", FieldType::U32).optional(),
    FieldDescriptor::new("segment_number", "Segment Number", FieldType::U8).optional(),
    FieldDescriptor::new("max_delay", "Maximum Delay", FieldType::U16).optional(),
    // RFC 4620, Section 4 — Node Information Qtype, Flags and Nonce
    // <https://www.rfc-editor.org/rfc/rfc4620#section-4>
    FieldDescriptor::new("qtype", "Qtype", FieldType::U16).optional(),
    FieldDescriptor::new("ni_flags", "Flags", FieldType::U16).optional(),
    FieldDescriptor::new("nonce", "Nonce", FieldType::Bytes).optional(),
    // RFC 3971, Sections 6.4.1 / 6.4.2 — Certification Path Component and
    // All Components
    // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.1>
    FieldDescriptor::new("component", "Component", FieldType::U16).optional(),
    FieldDescriptor::new("all_components", "All Components", FieldType::U16).optional(),
    // RFC 6775, Section 4.4 / RFC 8505, Section 4.2 — Duplicate Address
    // Request / Confirmation fields; `status` is also the RPL DAO-ACK Status
    // (RFC 6550, Section 6.5.1)
    // <https://www.rfc-editor.org/rfc/rfc8505#section-4.2>
    FieldDescriptor::new("status", "Status", FieldType::U8).optional(),
    FieldDescriptor::new("tid", "Transaction ID", FieldType::U8).optional(),
    FieldDescriptor::new(
        "registration_lifetime",
        "Registration Lifetime",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("rovr", "Registration Ownership Verifier", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "registered_address",
        "Registered Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    // RFC 6550, Sections 6.2-6.5 — RPL control message base objects
    // <https://www.rfc-editor.org/rfc/rfc6550#section-6>
    FieldDescriptor::new("rpl_instance_id", "RPLInstanceID", FieldType::U8).optional(),
    FieldDescriptor::new("version_number", "Version Number", FieldType::U8).optional(),
    FieldDescriptor::new("rank", "Rank", FieldType::U16).optional(),
    FieldDescriptor::new("grounded", "Grounded", FieldType::U8).optional(),
    FieldDescriptor::new("mop", "Mode of Operation", FieldType::U8).optional(),
    FieldDescriptor::new("prf", "DODAG Preference", FieldType::U8).optional(),
    FieldDescriptor::new(
        "dtsn",
        "Destination Advertisement Trigger Sequence Number",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("rpl_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("dodag_id", "DODAGID", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("dao_sequence", "DAOSequence", FieldType::U8).optional(),
    // RFC 6550, Section 6.7 — RPL Control Message Options
    // <https://www.rfc-editor.org/rfc/rfc6550#section-6.7>
    FieldDescriptor::new("rpl_options", "RPL Options", FieldType::Array)
        .optional()
        .with_children(rpl::RPL_OPTION_CHILDREN),
];

/// ICMPv6 dissector.
pub struct Icmpv6Dissector;

/// Router Renumbering header size (RFC 2894, Section 3.1).
const RR_HEADER_SIZE: usize = 16;
/// Node Information header size (RFC 4620, Section 4).
const NI_HEADER_SIZE: usize = 16;
/// Certification Path Advertisement header size (RFC 3971, Section 6.4.2).
const CPA_HEADER_SIZE: usize = 12;

pub(crate) fn push_u8(
    buf: &mut DissectBuffer<'_>,
    fd: usize,
    data: &[u8],
    at: usize,
    offset: usize,
) {
    buf.push_field(
        &FIELD_DESCRIPTORS[fd],
        FieldValue::U8(data[at]),
        offset + at..offset + at + 1,
    );
}

pub(crate) fn push_u16(
    buf: &mut DissectBuffer<'_>,
    fd: usize,
    data: &[u8],
    at: usize,
    offset: usize,
) {
    buf.push_field(
        &FIELD_DESCRIPTORS[fd],
        FieldValue::U16(u16::from_be_bytes([data[at], data[at + 1]])),
        offset + at..offset + at + 2,
    );
}

fn push_u32(buf: &mut DissectBuffer<'_>, fd: usize, data: &[u8], at: usize, offset: usize) {
    buf.push_field(
        &FIELD_DESCRIPTORS[fd],
        FieldValue::U32(u32::from_be_bytes([
            data[at],
            data[at + 1],
            data[at + 2],
            data[at + 3],
        ])),
        offset + at..offset + at + 4,
    );
}

/// Push `data[from..]` as `fd` when it is not empty.
pub(crate) fn push_bytes_from<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: usize,
    data: &'pkt [u8],
    from: usize,
    offset: usize,
) {
    if data.len() > from {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            FieldValue::Bytes(&data[from..]),
            offset + from..offset + data.len(),
        );
    }
}

/// Keep a message body that is shorter than its fixed fields (or has an
/// undecoded layout) as raw `data` after the 4-octet common header.
pub(crate) fn push_raw_body<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    push_bytes_from(buf, FD_DATA, data, 4, offset);
}

/// Decode an MLDv2 Maximum Response Code into milliseconds.
///
/// RFC 9777, Section 5.1.3 — "If Maximum Response Code < 32768, Maximum
/// Response Delay = Maximum Response Code." Otherwise it "represents a
/// floating-point value" `|1| exp | mant |` and "Maximum Response Delay =
/// (mant | 0x1000) << (exp+3)".
/// <https://www.rfc-editor.org/rfc/rfc9777#section-5.1.3>
fn mldv2_max_response_delay(code: u16) -> u32 {
    if code < 0x8000 {
        return u32::from(code);
    }
    let exp = u32::from((code >> 12) & 0x07);
    let mant = u32::from(code & 0x0FFF);
    (mant | 0x1000) << (exp + 3)
}

/// Decode an MLDv2 QQIC into seconds.
///
/// RFC 9777, Section 5.1.9 — "If QQIC < 128, QQI = QQIC". Otherwise it
/// "represents a floating-point value" `|1| exp | mant |` and "QQI = (mant |
/// 0x10) << (exp + 3)".
/// <https://www.rfc-editor.org/rfc/rfc9777#section-5.1.9>
fn mldv2_qqi(qqic: u8) -> u16 {
    if qqic < 0x80 {
        return u16::from(qqic);
    }
    let exp = u16::from((qqic >> 4) & 0x07);
    let mant = u16::from(qqic & 0x0F);
    (mant | 0x10) << (exp + 3)
}

/// Push invoking packet fields as an Object container into buf.
///
/// RFC 4443, Sections 3.1 and 3.3 — error messages include the original IPv6
/// packet that triggered the error, starting after the 8-byte ICMPv6 header.
fn push_invoking_packet<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data.len() >= IPV6_MIN_HEADER {
        let version = data[0] >> 4;
        let next_header = data[6];
        let mut src = [0u8; 16];
        src.copy_from_slice(&data[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&data[24..40]);

        let obj_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_INVOKING_PACKET],
            FieldValue::Object(0..0),
            offset..offset + data.len(),
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_NEXT_HEADER],
            FieldValue::U8(next_header),
            offset + 6..offset + 7,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_SRC],
            FieldValue::Ipv6Addr(src),
            offset + 8..offset + 24,
        );
        buf.push_field(
            &INVOKING_PACKET_CHILDREN[IPC_DST],
            FieldValue::Ipv6Addr(dst),
            offset + 24..offset + 40,
        );

        // The octets after the IPv6 header. For TCP and UDP the first four
        // are the Source and Destination Ports (RFC 9293, Section 3.1;
        // RFC 768).
        // <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
        // <https://www.rfc-editor.org/rfc/rfc768>
        let transport = &data[IPV6_MIN_HEADER..];
        let t_off = offset + IPV6_MIN_HEADER;
        match next_header {
            6 | 17 if transport.len() >= 4 => {
                buf.push_field(
                    &INVOKING_PACKET_CHILDREN[IPC_SRC_PORT],
                    FieldValue::U16(u16::from_be_bytes([transport[0], transport[1]])),
                    t_off..t_off + 2,
                );
                buf.push_field(
                    &INVOKING_PACKET_CHILDREN[IPC_DST_PORT],
                    FieldValue::U16(u16::from_be_bytes([transport[2], transport[3]])),
                    t_off + 2..t_off + 4,
                );
            }
            _ if !transport.is_empty() => {
                buf.push_field(
                    &INVOKING_PACKET_CHILDREN[IPC_TRANSPORT_DATA],
                    FieldValue::Bytes(transport),
                    t_off..t_off + transport.len(),
                );
            }
            _ => {}
        }
        buf.end_container(obj_idx);
    } else {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_INVOKING_PACKET],
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
    }
}

/// Length of an uncompressed DNS name in wire format (RFC 1035, Section
/// 3.1), including the terminating zero-length label. Returns `None` when
/// the labels run past `data` or no terminating label is found.
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.1>
fn dns_name_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let len = *data.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        // RFC 1035, Section 4.1.4 — a label length with the top two bits set
        // is a compression pointer, which RFC 8801 forbids here.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += len;
    }
}

/// Parse NDP options (RFC 4861, Section 4.6).
///
/// NDP options are Type-Length-Value encoded where Length is in units of
/// 8 octets (including type and length bytes).
fn parse_ndp_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    start: usize,
) -> Result<(), PacketError> {
    let mut cursor = start;

    while cursor + 2 <= data.len() {
        let opt_type = data[cursor];
        let opt_len_units = data[cursor + 1];

        // RFC 4861, Section 4.6 — Length 0 is invalid (prevents infinite loop).
        if opt_len_units == 0 {
            return Err(PacketError::InvalidHeader("NDP option with length 0"));
        }

        let opt_len = opt_len_units as usize * 8;
        if cursor + opt_len > data.len() {
            return Err(PacketError::Truncated {
                expected: cursor + opt_len,
                actual: data.len(),
            });
        }

        let opt_start = offset + cursor;
        let opt_end = offset + cursor + opt_len;
        let value_data = &data[cursor + 2..cursor + opt_len];

        let obj_idx =
            buf.begin_container(&FD_NDP_OPTION, FieldValue::Object(0..0), opt_start..opt_end);

        buf.push_field(
            &NDP_OPTION_CHILDREN[NOC_TYPE],
            FieldValue::U8(opt_type),
            opt_start..opt_start + 1,
        );
        buf.push_field(
            &NDP_OPTION_CHILDREN[NOC_LENGTH],
            FieldValue::U8(opt_len_units),
            opt_start + 1..opt_start + 2,
        );

        match opt_type {
            // RFC 4861, Section 4.6.1 — Source / Target Link-Layer Address
            1 | 2 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_LINK_LAYER_ADDRESS],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }

            // RFC 4861, Section 4.6.2 — Prefix Information
            // Length MUST be 4 (32 bytes total). Value is 30 bytes.
            3 if value_data.len() >= 30 => {
                let prefix_length = value_data[0];
                let flags = value_data[1];
                let valid_lifetime = read_be_u32(value_data, 2)?;
                let preferred_lifetime = read_be_u32(value_data, 6)?;
                // bytes 10-13: reserved
                let prefix = read_ipv6_addr(value_data, 14)?;

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX_LENGTH],
                    FieldValue::U8(prefix_length),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_FLAGS],
                    FieldValue::U8(flags),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALID_LIFETIME],
                    FieldValue::U32(valid_lifetime),
                    opt_start + 4..opt_start + 8,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFERRED_LIFETIME],
                    FieldValue::U32(preferred_lifetime),
                    opt_start + 8..opt_start + 12,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 16..opt_start + 32,
                );
            }

            // RFC 4191, Section 2.3 — Route Information
            // Length is 1, 2, or 3 depending on Prefix Length.
            // value_data layout: prefix_length(1) + flags(1) + route_lifetime(4) + prefix(0..16)
            24 if value_data.len() >= 6 => {
                let prefix_length = value_data[0];
                let flags = value_data[1];
                let route_lifetime = read_be_u32(value_data, 2)?;

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX_LENGTH],
                    FieldValue::U8(prefix_length),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_FLAGS],
                    FieldValue::U8(flags),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_ROUTE_LIFETIME],
                    FieldValue::U32(route_lifetime),
                    opt_start + 4..opt_start + 8,
                );

                // Prefix may be 0, 8, or 16 bytes; zero-pad to 16 bytes.
                let prefix_data = &value_data[6..];
                let mut prefix = [0u8; 16];
                let copy_len = prefix_data.len().min(16);
                prefix[..copy_len].copy_from_slice(&prefix_data[..copy_len]);

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 8..opt_end,
                );
            }

            // RFC 8106, Section 5.1 — Recursive DNS Server (RDNSS)
            // value_data layout: reserved(2) + lifetime(4) + addresses(N*16)
            25 if value_data.len() >= 6 => {
                let lifetime = read_be_u32(value_data, 2)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_LIFETIME],
                    FieldValue::U32(lifetime),
                    opt_start + 4..opt_start + 8,
                );

                // Number of addresses = (Length - 1) / 2
                let addr_data = &value_data[6..];
                if addr_data.len() >= 16 {
                    let array_idx = buf.begin_container(
                        &NDP_OPTION_CHILDREN[NOC_ADDRESSES],
                        FieldValue::Array(0..0),
                        opt_start + 8..opt_end,
                    );
                    let mut pos = 0;
                    while pos + 16 <= addr_data.len() {
                        let addr = read_ipv6_addr(addr_data, pos)?;
                        buf.push_field(
                            &NDP_OPTION_CHILDREN[NOC_ADDRESSES],
                            FieldValue::Ipv6Addr(addr),
                            opt_start + 8 + pos..opt_start + 8 + pos + 16,
                        );
                        pos += 16;
                    }
                    buf.end_container(array_idx);
                }
            }

            // RFC 8106, Section 5.2 — DNS Search List (DNSSL)
            // value_data layout: reserved(2) + lifetime(4) + domain_names(variable)
            31 if value_data.len() >= 6 => {
                let lifetime = read_be_u32(value_data, 2)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_LIFETIME],
                    FieldValue::U32(lifetime),
                    opt_start + 4..opt_start + 8,
                );

                // Parse DNS labels (RFC 1035 format, no compression)
                let name_data = &value_data[6..];
                let mut pos = 0;
                let mut has_domains = false;
                let mut array_idx = 0;
                while pos < name_data.len() {
                    let label_len = name_data[pos] as usize;
                    if label_len == 0 {
                        break; // end of this domain or padding
                    }
                    // Build one domain name from labels
                    let domain_start = pos;
                    let mut cur = pos;
                    while cur < name_data.len() {
                        let len = name_data[cur] as usize;
                        if len == 0 {
                            cur += 1; // skip null terminator
                            break;
                        }
                        if cur + 1 + len > name_data.len() {
                            break;
                        }
                        cur += 1 + len;
                    }
                    if cur > domain_start {
                        if !has_domains {
                            array_idx = buf.begin_container(
                                &NDP_OPTION_CHILDREN[NOC_DOMAIN_NAMES],
                                FieldValue::Array(0..0),
                                opt_start + 8..opt_end,
                            );
                            has_domains = true;
                        }
                        buf.push_field(
                            &NDP_OPTION_CHILDREN[NOC_DOMAIN_NAMES],
                            FieldValue::Bytes(
                                &data[cursor + 2 + 6 + domain_start..cursor + 2 + 6 + cur],
                            ),
                            opt_start + 8 + domain_start..opt_start + 8 + cur,
                        );
                    }
                    pos = cur;
                    // RFC 8106, Section 5.2 — guard against truncated label with no
                    // progress: if the inner loop did not advance past the starting
                    // position, stop to prevent an infinite loop.
                    if pos == domain_start {
                        break;
                    }
                }
                if has_domains {
                    buf.end_container(array_idx);
                }
            }

            // RFC 8781, Section 4 — PREF64 (NAT64 prefix)
            // value_data layout: scaled_lifetime+plc(2) + prefix(12)
            38 if value_data.len() >= 14 => {
                let combined = read_be_u16(value_data, 0)?;
                let scaled_lifetime = combined >> 3;
                let plc = (combined & 0x07) as u8;

                // PLC to prefix length mapping (RFC 8781, Section 4)
                let prefix_length: u8 = match plc {
                    0 => 96,
                    1 => 64,
                    2 => 56,
                    3 => 48,
                    4 => 40,
                    5 => 32,
                    _ => 0, // reserved
                };

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_SCALED_LIFETIME],
                    FieldValue::U16(scaled_lifetime),
                    opt_start + 2..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PLC],
                    FieldValue::U8(plc),
                    opt_start + 2..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX_LENGTH],
                    FieldValue::U8(prefix_length),
                    opt_start + 2..opt_start + 4,
                );

                // 96 bits (12 bytes) of prefix, zero-padded to 16
                let mut prefix = [0u8; 16];
                let copy_len = value_data[2..].len().min(12);
                prefix[..copy_len].copy_from_slice(&value_data[2..2 + copy_len]);

                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 4..opt_end,
                );
            }

            // RFC 4861, Section 4.6.3 — Redirected Header
            4 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALUE],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }

            // RFC 4861, Section 4.6.4 — MTU
            // Length MUST be 1 (8 bytes total). Value: 2 reserved + 4 MTU.
            5 if value_data.len() >= 6 => {
                let mtu = read_be_u32(value_data, 2)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_MTU],
                    FieldValue::U32(mtu),
                    opt_start + 4..opt_start + 8,
                );
            }

            // RFC 6275, Section 7.3 — Advertisement Interval: Reserved (16),
            // Advertisement Interval (32, milliseconds).
            // <https://www.rfc-editor.org/rfc/rfc6275#section-7.3>
            7 if value_data.len() >= 6 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_ADVERTISEMENT_INTERVAL],
                    FieldValue::U32(read_be_u32(value_data, 2)?),
                    opt_start + 4..opt_start + 8,
                );
            }

            // RFC 6275, Section 7.4 — Home Agent Information: Reserved
            // (16), Home Agent Preference (16, signed), Home Agent Lifetime
            // (16).
            // <https://www.rfc-editor.org/rfc/rfc6275#section-7.4>
            8 if value_data.len() >= 6 => {
                let preference = read_be_u16(value_data, 2)? as i16;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_HOME_AGENT_PREFERENCE],
                    FieldValue::I32(i32::from(preference)),
                    opt_start + 4..opt_start + 6,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_HOME_AGENT_LIFETIME],
                    FieldValue::U16(read_be_u16(value_data, 4)?),
                    opt_start + 6..opt_start + 8,
                );
            }

            // RFC 3122, Section 3.1 — Source / Target Address List:
            // Reserved (48 bits), then IPv6 addresses.
            // <https://www.rfc-editor.org/rfc/rfc3122#section-3.1>
            9 | 10 if value_data.len() >= 6 => {
                let array_idx = buf.begin_container(
                    &NDP_OPTION_CHILDREN[NOC_ADDRESSES],
                    FieldValue::Array(0..0),
                    opt_start + 8..opt_end,
                );
                for (i, a) in value_data[6..].chunks_exact(16).enumerate() {
                    let start = opt_start + 8 + i * 16;
                    buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_ADDRESSES],
                        FieldValue::Ipv6Addr(read_ipv6_addr(a, 0)?),
                        start..start + 16,
                    );
                }
                buf.end_container(array_idx);
            }

            // RFC 3971, Section 5.1 — CGA: Pad Length, Reserved, CGA
            // Parameters, Padding ("Pad Length ... The number of padding
            // octets beyond the end of the CGA Parameters field").
            // <https://www.rfc-editor.org/rfc/rfc3971#section-5.1>
            11 if value_data.len() >= 2 => {
                let pad_len = value_data[0];
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PAD_LENGTH],
                    FieldValue::U8(pad_len),
                    opt_start + 2..opt_start + 3,
                );
                let params = &value_data[2..];
                let params = &params[..params.len().saturating_sub(pad_len as usize)];
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_CGA_PARAMETERS],
                    FieldValue::Bytes(params),
                    opt_start + 4..opt_start + 4 + params.len(),
                );
            }

            // RFC 3971, Section 5.2 — RSA Signature: Reserved (16), Key Hash
            // (128), Digital Signature, Padding. The option has no pad
            // length, so the signature is pushed together with the padding.
            // <https://www.rfc-editor.org/rfc/rfc3971#section-5.2>
            12 if value_data.len() >= 18 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_KEY_HASH],
                    FieldValue::Bytes(&value_data[2..18]),
                    opt_start + 4..opt_start + 20,
                );
                if value_data.len() > 18 {
                    buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_DIGITAL_SIGNATURE],
                        FieldValue::Bytes(&value_data[18..]),
                        opt_start + 20..opt_end,
                    );
                }
            }

            // RFC 3971, Section 5.3.1 — Timestamp: Reserved (48), Timestamp
            // (64).
            // <https://www.rfc-editor.org/rfc/rfc3971#section-5.3.1>
            13 if value_data.len() >= 14 => {
                let hi = u64::from(read_be_u32(value_data, 6)?);
                let lo = u64::from(read_be_u32(value_data, 10)?);
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_TIMESTAMP],
                    FieldValue::U64((hi << 32) | lo),
                    opt_start + 8..opt_start + 16,
                );
            }

            // RFC 3971, Section 5.3.2 — Nonce: "A field containing a random
            // number selected by the sender of the solicitation message".
            // <https://www.rfc-editor.org/rfc/rfc3971#section-5.3.2>
            14 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_NONCE],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }

            // RFC 3971, Section 6.4.3 — Trust Anchor: Name Type, Pad
            // Length, Name, Padding.
            // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.3>
            15 if value_data.len() >= 2 => {
                let pad_len = value_data[1];
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_NAME_TYPE],
                    FieldValue::U8(value_data[0]),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PAD_LENGTH],
                    FieldValue::U8(pad_len),
                    opt_start + 3..opt_start + 4,
                );
                let name = &value_data[2..];
                let name = &name[..name.len().saturating_sub(pad_len as usize)];
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_NAME],
                    FieldValue::Bytes(name),
                    opt_start + 4..opt_start + 4 + name.len(),
                );
            }

            // RFC 3971, Section 6.4.4 — Certificate: Cert Type, Reserved,
            // Certificate, Padding (no pad length, so pushed together).
            // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.4>
            16 if value_data.len() >= 2 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_CERT_TYPE],
                    FieldValue::U8(value_data[0]),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_CERTIFICATE],
                    FieldValue::Bytes(&value_data[2..]),
                    opt_start + 4..opt_end,
                );
            }

            // RFC 8801, Section 3.1 — PvD ID: H|L|R|Reserved(9)|Delay(4),
            // Sequence Number, PvD ID FQDN (DNS wire format, no
            // compression), Padding, then an optional RA header and RA
            // options, which stay raw in `value`.
            // <https://www.rfc-editor.org/rfc/rfc8801#section-3.1>
            21 if value_data.len() >= 4 => {
                let flags = read_be_u16(value_data, 0)?;
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_PVD_FLAGS],
                    FieldValue::U16(flags),
                    opt_start + 2..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_DELAY],
                    FieldValue::U8((flags & 0x0F) as u8),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_SEQUENCE_NUMBER],
                    FieldValue::U16(read_be_u16(value_data, 2)?),
                    opt_start + 4..opt_start + 6,
                );
                let name_area = &value_data[4..];
                if let Some(name_len) = dns_name_len(name_area) {
                    buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_PVD_ID],
                        FieldValue::Bytes(&name_area[..name_len]),
                        opt_start + 6..opt_start + 6 + name_len,
                    );
                    // Padding "to the next 8-octet boundary", measured from
                    // the start of the option.
                    let rest_start = (6 + name_len).div_ceil(8) * 8;
                    if rest_start < opt_len {
                        buf.push_field(
                            &NDP_OPTION_CHILDREN[NOC_VALUE],
                            FieldValue::Bytes(&data[cursor + rest_start..cursor + opt_len]),
                            opt_start + rest_start..opt_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_VALUE],
                        FieldValue::Bytes(name_area),
                        opt_start + 6..opt_end,
                    );
                }
            }

            // RFC 5175, Section 4 — RA Flags Extension: "Bit fields
            // available for assignment" (48 bits with Length 1).
            // <https://www.rfc-editor.org/rfc/rfc5175#section-4>
            26 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_RA_FLAGS],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }

            // RFC 8505, Section 4.1 — EARO (the RFC 6775 ARO with Opaque,
            // I/R/T flags and TID in formerly reserved octets, and the
            // EUI-64 renamed ROVR): Status, Opaque, Rsvd|I|R|T, TID,
            // Registration Lifetime, ROVR.
            // <https://www.rfc-editor.org/rfc/rfc8505#section-4.1>
            33 if value_data.len() >= 6 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_STATUS],
                    FieldValue::U8(value_data[0]),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_OPAQUE],
                    FieldValue::U8(value_data[1]),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_ARO_FLAGS],
                    FieldValue::U8(value_data[2]),
                    opt_start + 4..opt_start + 5,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_TID],
                    FieldValue::U8(value_data[3]),
                    opt_start + 5..opt_start + 6,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_REGISTRATION_LIFETIME],
                    FieldValue::U16(read_be_u16(value_data, 4)?),
                    opt_start + 6..opt_start + 8,
                );
                if value_data.len() > 6 {
                    buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_ROVR],
                        FieldValue::Bytes(&value_data[6..]),
                        opt_start + 8..opt_end,
                    );
                }
            }

            // RFC 6775, Section 4.2 — 6LoWPAN Context: Context Length,
            // Res|C|CID, Reserved (16), Valid Lifetime (16, units of 60 s),
            // Context Prefix (8 or 16 octets for Length 2 or 3).
            // <https://www.rfc-editor.org/rfc/rfc6775#section-4.2>
            34 if value_data.len() >= 14 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_CONTEXT_LENGTH],
                    FieldValue::U8(value_data[0]),
                    opt_start + 2..opt_start + 3,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_COMPRESSION_FLAG],
                    FieldValue::U8((value_data[1] >> 4) & 0x01),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_CID],
                    FieldValue::U8(value_data[1] & 0x0F),
                    opt_start + 3..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALID_LIFETIME_MINUTES],
                    FieldValue::U16(read_be_u16(value_data, 4)?),
                    opt_start + 6..opt_start + 8,
                );
                let prefix_bytes = &value_data[6..value_data.len().min(22)];
                let mut prefix = [0u8; 16];
                prefix[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_CONTEXT_PREFIX],
                    FieldValue::Ipv6Addr(prefix),
                    opt_start + 8..opt_start + 8 + prefix_bytes.len(),
                );
            }

            // RFC 6775, Section 4.3 — Authoritative Border Router: Version
            // Low, Version High, Valid Lifetime (units of 60 s), 6LBR
            // Address.
            // <https://www.rfc-editor.org/rfc/rfc6775#section-4.3>
            35 if value_data.len() >= 22 => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VERSION_LOW],
                    FieldValue::U16(read_be_u16(value_data, 0)?),
                    opt_start + 2..opt_start + 4,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VERSION_HIGH],
                    FieldValue::U16(read_be_u16(value_data, 2)?),
                    opt_start + 4..opt_start + 6,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALID_LIFETIME_MINUTES],
                    FieldValue::U16(read_be_u16(value_data, 4)?),
                    opt_start + 6..opt_start + 8,
                );
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_BORDER_ROUTER_ADDRESS],
                    FieldValue::Ipv6Addr(read_ipv6_addr(value_data, 6)?),
                    opt_start + 8..opt_start + 24,
                );
            }

            // RFC 8910, Section 2.3 — Captive-Portal: the URI, "padded with
            // NUL (0x00)". A URI that is not UTF-8 stays raw in `value`.
            // <https://www.rfc-editor.org/rfc/rfc8910#section-2.3>
            37 => {
                let uri_len = value_data
                    .iter()
                    .rposition(|&b| b != 0)
                    .map_or(0, |p| p + 1);
                match core::str::from_utf8(&value_data[..uri_len]) {
                    Ok(uri) => buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_URI],
                        FieldValue::Str(uri),
                        opt_start + 2..opt_start + 2 + uri_len,
                    ),
                    Err(_) => buf.push_field(
                        &NDP_OPTION_CHILDREN[NOC_VALUE],
                        FieldValue::Bytes(value_data),
                        opt_start + 2..opt_end,
                    ),
                }
            }

            // Unknown or insufficient data — store raw value
            _ => {
                buf.push_field(
                    &NDP_OPTION_CHILDREN[NOC_VALUE],
                    FieldValue::Bytes(value_data),
                    opt_start + 2..opt_end,
                );
            }
        }

        buf.end_container(obj_idx);

        cursor += opt_len;
    }

    Ok(())
}

/// Append NDP options as an `"options"` array container if any are present.
fn append_ndp_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    options_start: usize,
) -> Result<(), PacketError> {
    if data.len() > options_start {
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_OPTIONS],
            FieldValue::Array(0..0),
            offset + options_start..offset + data.len(),
        );
        parse_ndp_options(buf, data, offset, options_start)?;
        buf.end_container(array_idx);
    }
    Ok(())
}

/// Parse MLDv2 Report multicast address records (RFC 3810, Section 5.2).
fn parse_mldv2_records<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    start: usize,
    num_records: u16,
) -> Result<(), PacketError> {
    let mut cursor = start;

    for _ in 0..num_records {
        // Each record: record_type(1) + aux_data_len(1) + num_sources(2) +
        //              multicast_address(16) = 20 bytes minimum
        if cursor + 20 > data.len() {
            return Err(PacketError::Truncated {
                expected: cursor + 20,
                actual: data.len(),
            });
        }

        let record_type = data[cursor];
        let aux_data_len = data[cursor + 1];
        let num_sources = read_be_u16(data, cursor + 2)?;
        let multicast_address = read_ipv6_addr(data, cursor + 4)?;

        let sources_start = cursor + 20;
        let sources_end = sources_start + num_sources as usize * 16;
        let aux_end = sources_end + aux_data_len as usize * 4;

        if aux_end > data.len() {
            return Err(PacketError::Truncated {
                expected: aux_end,
                actual: data.len(),
            });
        }

        let rec_start = offset + cursor;
        let rec_end = offset + aux_end;

        let obj_idx = buf.begin_container(
            &MLDV2_RECORD_CHILDREN[MRC_RECORD_TYPE],
            FieldValue::Object(0..0),
            rec_start..rec_end,
        );

        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_RECORD_TYPE],
            FieldValue::U8(record_type),
            rec_start..rec_start + 1,
        );
        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_AUX_DATA_LEN],
            FieldValue::U8(aux_data_len),
            rec_start + 1..rec_start + 2,
        );
        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_NUM_SOURCES],
            FieldValue::U16(num_sources),
            rec_start + 2..rec_start + 4,
        );
        buf.push_field(
            &MLDV2_RECORD_CHILDREN[MRC_MULTICAST_ADDRESS],
            FieldValue::Ipv6Addr(multicast_address),
            rec_start + 4..rec_start + 20,
        );

        // Parse source addresses
        if num_sources > 0 {
            let src_array_idx = buf.begin_container(
                &MLDV2_RECORD_CHILDREN[MRC_SOURCES],
                FieldValue::Array(0..0),
                offset + sources_start..offset + sources_end,
            );
            for i in 0..num_sources as usize {
                let s_start = sources_start + i * 16;
                let addr = read_ipv6_addr(data, s_start)?;
                buf.push_field(
                    &MLDV2_RECORD_CHILDREN[MRC_SOURCES],
                    FieldValue::Ipv6Addr(addr),
                    offset + s_start..offset + s_start + 16,
                );
            }
            buf.end_container(src_array_idx);
        }

        buf.end_container(obj_idx);

        cursor = aux_end;
    }

    Ok(())
}

impl Dissector for Icmpv6Dissector {
    fn name(&self) -> &'static str {
        "Internet Control Message Protocol v6"
    }

    fn short_name(&self) -> &'static str {
        "ICMPv6"
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

        // RFC 4443, Section 2.1 — Common header fields
        let icmpv6_type = data[0];
        let code = data[1];
        let checksum = read_be_u16(data, 2)?;

        let total_len = data.len();

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(icmpv6_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CODE],
            FieldValue::U8(code),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 2..offset + 4,
        );

        match icmpv6_type {
            // RFC 4443, Section 3.1 — Destination Unreachable (Type 1)
            // RFC 4443, Section 3.3 — Time Exceeded (Type 3)
            // RFC 4884, Section 4 — byte 4 carries an optional 8-bit Length field
            // (measured in 64-bit words) indicating the padded length of the
            // 'original datagram' field.  A value of zero means the field is unused.
            // Bytes 5-7 remain unused (must be zero).
            1 | 3 => {
                let length = data[4];
                if length > 0 {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_LENGTH],
                        FieldValue::U8(length),
                        offset + 4..offset + 5,
                    );
                }
                // RFC 4884, Section 4 — "For ICMPv6 messages, the length
                // attribute represents 64-bit words." When it is set and an
                // Extension Structure fits, the invoking packet ends where
                // the structure starts.
                // <https://www.rfc-editor.org/rfc/rfc4884#section-4>
                let ext_start = icmp_extension::extension_structure_start(
                    HEADER_SIZE,
                    length as usize * 8,
                    data.len(),
                );
                let invoking_end = ext_start.unwrap_or(data.len());
                // RFC 4443 — invoking packet follows the 8-byte header
                if invoking_end > HEADER_SIZE {
                    push_invoking_packet(
                        buf,
                        &data[HEADER_SIZE..invoking_end],
                        offset + HEADER_SIZE,
                    );
                }
                if let Some(start) = ext_start {
                    icmp_extension::push_extension_structure(
                        buf,
                        &FIELD_DESCRIPTORS[FD_EXTENSIONS],
                        &data[start..],
                        offset + start,
                    );
                }
            }

            // RFC 4443, Section 3.2 — Packet Too Big (Type 2)
            // <https://www.rfc-editor.org/rfc/rfc4443#section-3.2>
            // The MTU field is followed by "As much of invoking packet as
            // possible" (same rule as other error messages). RFC 4884, §5
            // explicitly notes that Packet Too Big has no Length extension
            // field, so all bytes after MTU belong to the invoking packet.
            2 => {
                let mtu = read_be_u32(data, 4)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MTU],
                    FieldValue::U32(mtu),
                    offset + 4..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }

            // RFC 4443, Section 3.4 — Parameter Problem (Type 4)
            // <https://www.rfc-editor.org/rfc/rfc4443#section-3.4>
            // The Pointer field is followed by "As much of invoking packet as
            // possible". RFC 4884, §5 states no Length extension is defined
            // for this message, so remaining bytes are purely the invoking
            // packet.
            4 => {
                let pointer = read_be_u32(data, 4)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_POINTER],
                    FieldValue::U32(pointer),
                    offset + 4..offset + 8,
                );
                if data.len() > HEADER_SIZE {
                    push_invoking_packet(buf, &data[HEADER_SIZE..], offset + HEADER_SIZE);
                }
            }

            // RFC 4443, Section 4.1 — Echo Request (Type 128)
            // RFC 4443, Section 4.2 — Echo Reply (Type 129)
            128 | 129 => {
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = read_be_u16(data, 6)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U16(sequence_number),
                    offset + 6..offset + 8,
                );

                if data.len() > HEADER_SIZE {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_DATA],
                        FieldValue::Bytes(&data[HEADER_SIZE..]),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                }
            }

            // RFC 2710, Section 3.6 — Multicast Listener Query (Type 130)
            // RFC 2710, Section 3.7 — Multicast Listener Report (Type 131)
            // RFC 2710, Section 3.8 — Multicast Listener Done (Type 132)
            130..=132 => {
                if data.len() < MLD_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: MLD_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                let max_response_delay = read_be_u16(data, 4)?;
                // bytes 6-7: reserved
                let multicast_address = read_ipv6_addr(data, 8)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MAX_RESPONSE_DELAY],
                    FieldValue::U16(max_response_delay),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_MULTICAST_ADDRESS],
                    FieldValue::Ipv6Addr(multicast_address),
                    offset + 8..offset + 24,
                );

                // RFC 3810, Section 5.1 — MLDv2 Query (Type 130 with at least 28 bytes).
                // The MLDv2 extension occupies bytes 24-27 (S+QRV, QQIC, Number of Sources).
                if icmpv6_type == 130 && data.len() >= 28 {
                    let flags_byte = data[24];
                    let s_flag = (flags_byte >> 3) & 1;
                    let qrv = flags_byte & 0x07;
                    let qqic = data[25];
                    let num_sources = read_be_u16(data, 26)?;

                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_S_FLAG],
                        FieldValue::U8(s_flag),
                        offset + 24..offset + 25,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_QRV],
                        FieldValue::U8(qrv),
                        offset + 24..offset + 25,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_MAX_RESPONSE_DELAY_MS],
                        FieldValue::U32(mldv2_max_response_delay(max_response_delay)),
                        offset + 4..offset + 6,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_QQIC],
                        FieldValue::U8(qqic),
                        offset + 25..offset + 26,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_QQI],
                        FieldValue::U16(mldv2_qqi(qqic)),
                        offset + 25..offset + 26,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_NUM_SOURCES],
                        FieldValue::U16(num_sources),
                        offset + 26..offset + 28,
                    );

                    // Parse source addresses
                    if num_sources > 0 {
                        let sources_start = 28;
                        let sources_end = sources_start + num_sources as usize * 16;
                        if sources_end > data.len() {
                            return Err(PacketError::Truncated {
                                expected: sources_end,
                                actual: data.len(),
                            });
                        }
                        let array_idx = buf.begin_container(
                            &FIELD_DESCRIPTORS[FD_SOURCES],
                            FieldValue::Array(0..0),
                            offset + sources_start..offset + sources_end,
                        );
                        for i in 0..num_sources as usize {
                            let s_start = sources_start + i * 16;
                            let addr = read_ipv6_addr(data, s_start)?;
                            buf.push_field(
                                &FIELD_DESCRIPTORS[FD_SOURCES],
                                FieldValue::Ipv6Addr(addr),
                                offset + s_start..offset + s_start + 16,
                            );
                        }
                        buf.end_container(array_idx);
                    }
                }
            }

            // RFC 4861, Section 4.1 — Router Solicitation (Type 133)
            133 => {
                // Bytes 4-7: reserved
                append_ndp_options(buf, data, offset, HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.2 — Router Advertisement (Type 134)
            134 => {
                if data.len() < RA_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: RA_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                let cur_hop_limit = data[4];
                let flags = data[5];
                let router_lifetime = read_be_u16(data, 6)?;
                let reachable_time = read_be_u32(data, 8)?;
                let retrans_timer = read_be_u32(data, 12)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_CUR_HOP_LIMIT],
                    FieldValue::U8(cur_hop_limit),
                    offset + 4..offset + 5,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_FLAGS],
                    FieldValue::U8(flags),
                    offset + 5..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROUTER_LIFETIME],
                    FieldValue::U16(router_lifetime),
                    offset + 6..offset + 8,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_REACHABLE_TIME],
                    FieldValue::U32(reachable_time),
                    offset + 8..offset + 12,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_RETRANS_TIMER],
                    FieldValue::U32(retrans_timer),
                    offset + 12..offset + 16,
                );

                append_ndp_options(buf, data, offset, RA_HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.3 — Neighbor Solicitation (Type 135)
            135 => {
                if data.len() < NS_NA_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: NS_NA_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                // Bytes 4-7: reserved
                let target_address = read_ipv6_addr(data, 8)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TARGET_ADDRESS],
                    FieldValue::Ipv6Addr(target_address),
                    offset + 8..offset + 24,
                );

                append_ndp_options(buf, data, offset, NS_NA_HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.4 — Neighbor Advertisement (Type 136)
            136 => {
                if data.len() < NS_NA_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: NS_NA_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                // Byte 4: R(0x80), S(0x40), O(0x20) flags
                let flags = data[4];
                // Bytes 5-7: reserved
                let target_address = read_ipv6_addr(data, 8)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_FLAGS],
                    FieldValue::U8(flags),
                    offset + 4..offset + 5,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TARGET_ADDRESS],
                    FieldValue::Ipv6Addr(target_address),
                    offset + 8..offset + 24,
                );

                append_ndp_options(buf, data, offset, NS_NA_HEADER_SIZE)?;
            }

            // RFC 4861, Section 4.5 — Redirect (Type 137)
            137 => {
                if data.len() < REDIRECT_HEADER_SIZE {
                    return Err(PacketError::Truncated {
                        expected: REDIRECT_HEADER_SIZE,
                        actual: data.len(),
                    });
                }

                // Bytes 4-7: reserved
                let target_address = read_ipv6_addr(data, 8)?;
                let destination_address = read_ipv6_addr(data, 24)?;

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TARGET_ADDRESS],
                    FieldValue::Ipv6Addr(target_address),
                    offset + 8..offset + 24,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DESTINATION_ADDRESS],
                    FieldValue::Ipv6Addr(destination_address),
                    offset + 24..offset + 40,
                );

                append_ndp_options(buf, data, offset, REDIRECT_HEADER_SIZE)?;
            }

            // RFC 3810, Section 5.2 — MLDv2 Report (Type 143)
            143 => {
                // Bytes 4-5: reserved
                let num_records = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_NUM_RECORDS],
                    FieldValue::U16(num_records),
                    offset + 6..offset + 8,
                );

                if num_records > 0 {
                    let array_idx = buf.begin_container(
                        &FIELD_DESCRIPTORS[FD_RECORDS],
                        FieldValue::Array(0..0),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                    parse_mldv2_records(buf, data, offset, HEADER_SIZE, num_records)?;
                    buf.end_container(array_idx);
                }
            }

            // RFC 6275, Section 6.5 — Home Agent Address Discovery Request (Type 144)
            144 => {
                let identifier = read_be_u16(data, 4)?;
                // Bytes 6-7: reserved
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
            }

            // RFC 6275, Section 6.5 — Home Agent Address Discovery Reply (Type 145)
            145 => {
                let identifier = read_be_u16(data, 4)?;
                // Bytes 6-7: reserved
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );

                // Home agent addresses follow the 8-byte header
                if data.len() > HEADER_SIZE {
                    let array_idx = buf.begin_container(
                        &FIELD_DESCRIPTORS[FD_HOME_AGENT_ADDRESSES],
                        FieldValue::Array(0..0),
                        offset + HEADER_SIZE..offset + data.len(),
                    );
                    let mut cursor = HEADER_SIZE;
                    while cursor + 16 <= data.len() {
                        let addr = read_ipv6_addr(data, cursor)?;
                        buf.push_field(
                            &FIELD_DESCRIPTORS[FD_HOME_AGENT_ADDRESSES],
                            FieldValue::Ipv6Addr(addr),
                            offset + cursor..offset + cursor + 16,
                        );
                        cursor += 16;
                    }
                    buf.end_container(array_idx);
                }
            }

            // RFC 4286, Section 3 — Multicast Router Advertisement (Type 151)
            151 => {
                let query_interval = read_be_u16(data, 4)?;
                let robustness_variable = read_be_u16(data, 6)?;
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_QUERY_INTERVAL],
                    FieldValue::U16(query_interval),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_ROBUSTNESS_VARIABLE],
                    FieldValue::U16(robustness_variable),
                    offset + 6..offset + 8,
                );
            }

            // RFC 4286, Section 3 — Multicast Router Solicitation (Type 152)
            // RFC 4286, Section 3 — Multicast Router Termination (Type 153)
            // Bytes 4-7 are reserved.
            152 | 153 => {}

            // RFC 8335, Section 2 — Extended Echo Request (Type 160) and
            // Extended Echo Reply (Type 161).
            // <https://www.rfc-editor.org/rfc/rfc8335#section-2>
            // Layout (after the 4-byte ICMPv6 common header):
            //   Identifier (16 bits) | Sequence Number (8 bits) | flags (8 bits)
            // For Request: flags = Reserved(7) + L(1).
            // For Reply:   flags = State(3) + Res(2) + A(1) + 4(1) + 6(1).
            // Note: the Sequence Number here is 8 bits wide, whereas the
            // classic Echo Sequence Number in RFC 4443, §4.1 is 16 bits wide;
            // we therefore use a dedicated U8 descriptor.
            160 | 161 => {
                let identifier = read_be_u16(data, 4)?;
                let sequence_number = data[6];
                let flags = data[7];

                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_IDENTIFIER],
                    FieldValue::U16(identifier),
                    offset + 4..offset + 6,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER_U8],
                    FieldValue::U8(sequence_number),
                    offset + 6..offset + 7,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_FLAGS],
                    FieldValue::U8(flags),
                    offset + 7..offset + 8,
                );
                // RFC 8335, Section 2 — the Extended Echo Request carries an
                // ICMP Extension Structure right after the header, which
                // "MUST contain exactly one instance of the Interface
                // Identification Object".
                if icmpv6_type == 160 && data.len() > HEADER_SIZE {
                    icmp_extension::push_extension_structure(
                        buf,
                        &FIELD_DESCRIPTORS[FD_EXTENSIONS],
                        &data[HEADER_SIZE..],
                        offset + HEADER_SIZE,
                    );
                }
            }

            // RFC 2894, Section 3.1 — Router Renumbering header:
            // SequenceNumber (32), SegmentNumber, Flags, MaxDelay, reserved
            // (32), then the message body.
            // <https://www.rfc-editor.org/rfc/rfc2894#section-3.1>
            138 => {
                if data.len() < RR_HEADER_SIZE {
                    push_raw_body(buf, data, offset);
                } else {
                    push_u32(buf, FD_RR_SEQUENCE_NUMBER, data, 4, offset);
                    push_u8(buf, FD_SEGMENT_NUMBER, data, 8, offset);
                    push_u8(buf, FD_FLAGS, data, 9, offset);
                    push_u16(buf, FD_MAX_DELAY, data, 10, offset);
                    push_bytes_from(buf, FD_DATA, data, RR_HEADER_SIZE, offset);
                }
            }

            // RFC 4620, Section 4 — Node Information Query / Reply: Qtype,
            // Flags, Nonce (64 bits), Data.
            // <https://www.rfc-editor.org/rfc/rfc4620#section-4>
            139 | 140 => {
                if data.len() < NI_HEADER_SIZE {
                    push_raw_body(buf, data, offset);
                } else {
                    push_u16(buf, FD_QTYPE, data, 4, offset);
                    push_u16(buf, FD_NI_FLAGS, data, 6, offset);
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_NONCE],
                        FieldValue::Bytes(&data[8..16]),
                        offset + 8..offset + 16,
                    );
                    push_bytes_from(buf, FD_DATA, data, NI_HEADER_SIZE, offset);
                }
            }

            // RFC 3122, Sections 2.1 / 2.2 — Inverse Neighbor Discovery
            // Solicitation / Advertisement: Reserved (32 bits), Options.
            // <https://www.rfc-editor.org/rfc/rfc3122#section-2.1>
            141 | 142 => {
                append_ndp_options(buf, data, offset, HEADER_SIZE)?;
            }

            // RFC 6275, Section 6.7 — Mobile Prefix Solicitation:
            // Identifier, Reserved.
            // <https://www.rfc-editor.org/rfc/rfc6275#section-6.7>
            146 => {
                push_u16(buf, FD_IDENTIFIER, data, 4, offset);
            }

            // RFC 6275, Section 6.8 — Mobile Prefix Advertisement:
            // Identifier, M|O|Reserved (the M and O flags are the top bits
            // of the first octet), Options.
            // <https://www.rfc-editor.org/rfc/rfc6275#section-6.8>
            147 => {
                push_u16(buf, FD_IDENTIFIER, data, 4, offset);
                push_u8(buf, FD_FLAGS, data, 6, offset);
                append_ndp_options(buf, data, offset, HEADER_SIZE)?;
            }

            // RFC 3971, Section 6.4.1 — Certification Path Solicitation:
            // Identifier, Component, Options.
            // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.1>
            148 => {
                push_u16(buf, FD_IDENTIFIER, data, 4, offset);
                push_u16(buf, FD_COMPONENT, data, 6, offset);
                append_ndp_options(buf, data, offset, HEADER_SIZE)?;
            }

            // RFC 3971, Section 6.4.2 — Certification Path Advertisement:
            // Identifier, All Components, Component, Reserved, Options.
            // <https://www.rfc-editor.org/rfc/rfc3971#section-6.4.2>
            149 => {
                if data.len() < CPA_HEADER_SIZE {
                    push_raw_body(buf, data, offset);
                } else {
                    push_u16(buf, FD_IDENTIFIER, data, 4, offset);
                    push_u16(buf, FD_ALL_COMPONENTS, data, 6, offset);
                    push_u16(buf, FD_COMPONENT, data, 8, offset);
                    append_ndp_options(buf, data, offset, CPA_HEADER_SIZE)?;
                }
            }

            // RFC 6550, Section 6 — RPL Control Message.
            // <https://www.rfc-editor.org/rfc/rfc6550#section-6>
            155 => rpl::push_rpl_message(buf, code, data, offset),

            // RFC 6775, Section 4.4 — Duplicate Address Request /
            // Confirmation: Status, Reserved, Registration Lifetime, EUI-64,
            // Registered Address.
            // RFC 8505, Section 4.2 — with a non-zero Code Suffix the
            // Reserved octet is the TID and "The size of the ROVR is known
            // from the ICMP Code Suffix" (1-4 for 64-256 bits).
            // <https://www.rfc-editor.org/rfc/rfc6775#section-4.4>
            // <https://www.rfc-editor.org/rfc/rfc8505#section-4.2>
            157 | 158 => {
                let code_suffix = (code & 0x0F) as usize;
                let rovr_len = code_suffix.max(1) * 8;
                if code_suffix > 4 || data.len() < 8 + rovr_len + 16 {
                    push_raw_body(buf, data, offset);
                } else {
                    push_u8(buf, FD_STATUS, data, 4, offset);
                    if code_suffix != 0 {
                        push_u8(buf, FD_TID, data, 5, offset);
                    }
                    push_u16(buf, FD_REGISTRATION_LIFETIME, data, 6, offset);
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_ROVR],
                        FieldValue::Bytes(&data[8..8 + rovr_len]),
                        offset + 8..offset + 8 + rovr_len,
                    );
                    let addr_at = 8 + rovr_len;
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_REGISTERED_ADDRESS],
                        FieldValue::Ipv6Addr(read_ipv6_addr(data, addr_at)?),
                        offset + addr_at..offset + addr_at + 16,
                    );
                }
            }

            // All other types: no type-specific parsing
            _ => {}
        }

        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # ICMPv6 invoking packet coverage
    //!
    //! | RFC Section                            | Description                        | Test                                           |
    //! |----------------------------------------|------------------------------------|------------------------------------------------|
    //! | RFC 4443 §3.1 Destination Unreachable  | Invoking IPv6 packet parsing       | parse_dest_unreachable_with_invoking_ipv6      |
    //! | RFC 4443 §3.3 Time Exceeded            | Invoking IPv6 packet parsing       | parse_time_exceeded_with_invoking_ipv6         |
    //! | RFC 4443 §3.1 Destination Unreachable  | Truncated invoking packet          | parse_dest_unreachable_truncated_invoking      |
    //! | RFC 4443 §3.1 Destination Unreachable  | No invoking packet data            | parse_dest_unreachable_no_invoking             |
    //! | RFC 4443 §3.2 Packet Too Big           | Invoking IPv6 packet parsing       | parse_packet_too_big_with_invoking_ipv6        |
    //! | RFC 4443 §3.4 Parameter Problem        | Invoking IPv6 packet parsing       | parse_parameter_problem_with_invoking_ipv6     |
    //! | RFC 8335 §2 Extended Echo Request      | Sequence Number is 8-bit           | parse_extended_echo_request_u8_sequence_number |

    use super::*;

    /// Build an ICMPv6 error message with an invoking IPv6 packet.
    ///
    /// `icmpv6_type`: 1 (Dest Unreachable) or 3 (Time Exceeded)
    /// `invoking`: bytes to append after the 8-byte ICMPv6 header
    fn build_icmpv6_error(icmpv6_type: u8, code: u8, invoking: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HEADER_SIZE + invoking.len());
        pkt.push(icmpv6_type);
        pkt.push(code);
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // unused / length=0
        pkt.extend_from_slice(invoking);
        pkt
    }

    /// Build a minimal IPv6 header (40 bytes).
    fn build_ipv6_header(next_header: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut hdr = vec![0u8; 40];
        hdr[0] = 0x60; // version=6, traffic class high nibble=0
        hdr[6] = next_header;
        hdr[8..24].copy_from_slice(&src);
        hdr[24..40].copy_from_slice(&dst);
        hdr
    }

    #[test]
    fn parse_dest_unreachable_with_invoking_ipv6() {
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let invoking = build_ipv6_header(17, src, dst); // next_header=17 (UDP)
        let data = build_icmpv6_error(1, 0, &invoking);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);

        // Find invoking_packet object
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };

        // Check children
        let children = buf.nested_fields(&range);
        assert_eq!(children.len(), 4);
        assert_eq!(children[0].value, FieldValue::U8(6)); // version
        assert_eq!(children[1].value, FieldValue::U8(17)); // next_header
        assert_eq!(children[2].value, FieldValue::Ipv6Addr(src)); // src
        assert_eq!(children[3].value, FieldValue::Ipv6Addr(dst)); // dst
    }

    #[test]
    fn parse_time_exceeded_with_invoking_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let invoking = build_ipv6_header(6, src, dst); // next_header=6 (TCP)
        let data = build_icmpv6_error(3, 0, &invoking);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        assert_eq!(children[0].value, FieldValue::U8(6)); // version
        assert_eq!(children[1].value, FieldValue::U8(6)); // next_header (TCP)
    }

    #[test]
    fn parse_dest_unreachable_truncated_invoking() {
        // Only 10 bytes of invoking data (< 40 byte IPv6 minimum)
        let invoking = &[0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x40, 0xfe, 0x80];
        let data = build_icmpv6_error(1, 3, invoking);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let ip_field = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .unwrap();
        // Should be raw bytes, not a structured Object
        assert!(matches!(ip_field.value, FieldValue::Bytes(_)));
    }

    #[test]
    fn parse_dest_unreachable_no_invoking() {
        // Exactly 8 bytes — no invoking packet data
        let data = build_icmpv6_error(1, 0, &[]);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert!(
            fields
                .iter()
                .all(|f| f.descriptor.name != "invoking_packet")
        );
    }

    /// RFC 4443, Section 3.2 — Packet Too Big (Type 2) carries the invoking
    /// packet after the 32-bit MTU field.
    /// <https://www.rfc-editor.org/rfc/rfc4443#section-3.2>
    #[test]
    fn parse_packet_too_big_with_invoking_ipv6() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let invoking = build_ipv6_header(17, src, dst); // UDP

        let mut pkt = Vec::with_capacity(HEADER_SIZE + invoking.len());
        pkt.push(2); // Packet Too Big
        pkt.push(0); // Code
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00, 0x05, 0xdc]); // MTU = 1500
        pkt.extend_from_slice(&invoking);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);

        // MTU must still be present.
        assert!(
            fields
                .iter()
                .any(|f| f.descriptor.name == "mtu" && f.value == FieldValue::U32(1500))
        );

        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .expect("Packet Too Big must expose the invoking packet");
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        assert_eq!(children[0].value, FieldValue::U8(6)); // version
        assert_eq!(children[1].value, FieldValue::U8(17)); // next_header (UDP)
        assert_eq!(children[2].value, FieldValue::Ipv6Addr(src));
        assert_eq!(children[3].value, FieldValue::Ipv6Addr(dst));
    }

    /// RFC 4443, Section 3.4 — Parameter Problem (Type 4) carries the invoking
    /// packet after the 32-bit Pointer field.
    /// <https://www.rfc-editor.org/rfc/rfc4443#section-3.4>
    #[test]
    fn parse_parameter_problem_with_invoking_ipv6() {
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb];
        let invoking = build_ipv6_header(58, src, dst); // ICMPv6

        let mut pkt = Vec::with_capacity(HEADER_SIZE + invoking.len());
        pkt.push(4); // Parameter Problem
        pkt.push(0); // Code = erroneous header field encountered
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // Pointer = 6
        pkt.extend_from_slice(&invoking);

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);

        // Pointer must still be present.
        assert!(
            fields
                .iter()
                .any(|f| f.descriptor.name == "pointer" && f.value == FieldValue::U32(6))
        );

        let ip_obj = fields
            .iter()
            .find(|f| f.descriptor.name == "invoking_packet")
            .expect("Parameter Problem must expose the invoking packet");
        let range = match &ip_obj.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {other:?}"),
        };
        let children = buf.nested_fields(&range);
        assert_eq!(children[0].value, FieldValue::U8(6));
        assert_eq!(children[1].value, FieldValue::U8(58));
        assert_eq!(children[2].value, FieldValue::Ipv6Addr(src));
        assert_eq!(children[3].value, FieldValue::Ipv6Addr(dst));
    }

    /// RFC 8335, Section 2 — Extended Echo Request (Type 160) Sequence Number
    /// is an 8-bit field, distinct from the 16-bit Sequence Number in the
    /// classic Echo Request/Reply (RFC 4443, Section 4.1).
    /// <https://www.rfc-editor.org/rfc/rfc8335#section-2>
    #[test]
    fn parse_extended_echo_request_u8_sequence_number() {
        let pkt: [u8; 8] = [
            160, // Type: Extended Echo Request
            0,   // Code
            0x00, 0x00, // Checksum
            0x12, 0x34, // Identifier
            0x2a, // Sequence Number (8-bit) = 42
            0x01, // Reserved(7) + L(1)
        ];

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);

        let seq = fields
            .iter()
            .find(|f| f.descriptor.name == "sequence_number")
            .expect("sequence_number field must be present");
        // Per RFC 8335, the Sequence Number for Extended Echo is 8 bits wide,
        // so the descriptor must report U8 and the value must match.
        assert_eq!(seq.value, FieldValue::U8(0x2a));
        assert_eq!(seq.descriptor.field_type, FieldType::U8);
    }

    #[test]
    fn ndp_option_container_resolves_to_option_name() {
        // Router Solicitation (RFC 4861 §4.1) with a Source Link-Layer Address
        // option (type 1, length 1 * 8 bytes).
        let pkt: [u8; 16] = [
            133, 0, 0x00, 0x00, // Type, Code, Checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x01, 0x01, // Option type=1 (Source LLA), length=1
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Link-layer address
        ];

        let mut buf = DissectBuffer::new();
        Icmpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);

        let opts = fields
            .iter()
            .find(|f| f.descriptor.name == "options")
            .expect("options array must be present");
        let opts_range = match &opts.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {other:?}"),
        };

        let opt_children = buf.nested_fields(&opts_range);
        let (opt_offset, option) = opt_children
            .iter()
            .enumerate()
            .find(|(_, f)| matches!(f.value, FieldValue::Object(_)))
            .expect("option Object must be present");
        // Outer container uses the generic descriptor label.
        assert_eq!(option.descriptor.display_name, "Option");
        // Resolved label from the inner `type` field.
        let opt_idx = opts_range.start + opt_offset as u32;
        assert_eq!(
            buf.resolve_container_display_name(opt_idx),
            Some("Source Link-Layer Address"),
        );
    }

    #[test]
    fn test_references_and_layer() {
        let dissector = Icmpv6Dissector;
        let refs = dissector.references();
        assert!(!refs.is_empty());
        for r in refs {
            assert!(!r.id.is_empty());
            assert!(r.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Network));
    }
}
