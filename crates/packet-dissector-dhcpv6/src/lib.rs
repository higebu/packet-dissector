//! DHCPv6 (Dynamic Host Configuration Protocol for IPv6) dissector.
//!
//! ## References
//! - RFC 9915 (DHCPv6, obsoletes RFC 8415):
//!   <https://www.rfc-editor.org/rfc/rfc9915>
//! - RFC 8415 (retained for historical IA_TA and Server Unicast option definitions):
//!   <https://www.rfc-editor.org/rfc/rfc8415>
//! - RFC 3646 (DNS Configuration Options):
//!   <https://www.rfc-editor.org/rfc/rfc3646>
//! - RFC 4704 (Client FQDN Option):
//!   <https://www.rfc-editor.org/rfc/rfc4704>
//! - RFC 6355 (DUID-UUID): <https://www.rfc-editor.org/rfc/rfc6355>
//! - RFC 3319 (SIP Server Options): <https://www.rfc-editor.org/rfc/rfc3319>
//! - RFC 4075 (SNTP Servers Option): <https://www.rfc-editor.org/rfc/rfc4075>
//! - RFC 4649 (Relay Agent Remote-ID Option): <https://www.rfc-editor.org/rfc/rfc4649>
//! - RFC 4580 (Relay Agent Subscriber-ID Option): <https://www.rfc-editor.org/rfc/rfc4580>
//! - RFC 5007 (DHCPv6 Leasequery): <https://www.rfc-editor.org/rfc/rfc5007>
//! - RFC 5460 (DHCPv6 Bulk Leasequery, Relay-ID Option): <https://www.rfc-editor.org/rfc/rfc5460>
//! - RFC 5908 (NTP Server Option): <https://www.rfc-editor.org/rfc/rfc5908>
//! - RFC 5970 (Network Boot Options): <https://www.rfc-editor.org/rfc/rfc5970>
//! - RFC 6334 (AFTR-Name Option): <https://www.rfc-editor.org/rfc/rfc6334>
//! - RFC 6939 (Client Link-Layer Address Option): <https://www.rfc-editor.org/rfc/rfc6939>
//! - RFC 6977 (Reconfigure-request/-reply): <https://www.rfc-editor.org/rfc/rfc6977>
//! - RFC 7341 (DHCPv4-over-DHCPv6): <https://www.rfc-editor.org/rfc/rfc7341>
//! - RFC 7598 (Softwire46 Options): <https://www.rfc-editor.org/rfc/rfc7598>
//! - RFC 7653 (DHCPv6 Active Leasequery): <https://www.rfc-editor.org/rfc/rfc7653>
//! - RFC 8156 (DHCPv6 Failover Protocol): <https://www.rfc-editor.org/rfc/rfc8156>
//! - RFC 8910 (Captive-Portal Option): <https://www.rfc-editor.org/rfc/rfc8910>
//! - RFC 9686 (Address Registration): <https://www.rfc-editor.org/rfc/rfc9686>
//! - IANA DHCPv6 Parameters:
//!   <https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, MacAddr, format_fqdn_labels, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u24, read_be_u32, read_ipv6_addr};

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_MSG_TYPE: usize = 0;
const FD_TRANSACTION_ID: usize = 1;
const FD_HOP_COUNT: usize = 2;
const FD_LINK_ADDRESS: usize = 3;
const FD_PEER_ADDRESS: usize = 4;
const FD_OPTIONS: usize = 5;
const FD_FLAGS: usize = 6;
const FD_UNICAST: usize = 7;

// Client/server and relay messages share msg_type. Other fields
// depend on the message type, so they are marked optional.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "msg_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => dhcpv6_msg_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("transaction_id", "Transaction ID", FieldType::U32).optional(),
    FieldDescriptor::new("hop_count", "Hop Count", FieldType::U8).optional(),
    FieldDescriptor::new("link_address", "Link Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("peer_address", "Peer Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("options", "Options", FieldType::Array)
        .optional()
        .with_children(OPTION_CHILD_FIELDS),
    // RFC 7341, Section 6.2 — DHCPv4-query / DHCPv4-response carry a
    // 3-octet "flags" field in place of the transaction-id.
    // <https://www.rfc-editor.org/rfc/rfc7341#section-6.2>
    FieldDescriptor::new("flags", "Flags", FieldType::U32).optional(),
    // RFC 7341, Section 6.3 — "U:   Unicast flag."
    // <https://www.rfc-editor.org/rfc/rfc7341#section-6.3>
    FieldDescriptor::new("unicast", "Unicast", FieldType::U8).optional(),
];

/// Field descriptor indices for [`OPTION_CHILD_FIELDS`].
const OFD_ADDRESS: usize = 0;
const OFD_ALGORITHM: usize = 1;
const OFD_AUTHENTICATION: usize = 2;
const OFD_CLIENT_ID: usize = 3;
const OFD_CODE: usize = 4;
const OFD_DATA: usize = 5;
const OFD_DNS_SERVERS: usize = 6;
const OFD_DOMAIN_SEARCH: usize = 7;
const OFD_ELAPSED_TIME: usize = 8;
const OFD_ENTERPRISE_NUMBER: usize = 9;
const OFD_FLAGS: usize = 10;
const OFD_FQDN: usize = 11;
const OFD_IA_ADDR: usize = 12;
const OFD_IA_NA: usize = 13;
const OFD_IA_PD: usize = 14;
const OFD_IA_PREFIX: usize = 15;
const OFD_IA_TA: usize = 16;
const OFD_IAID: usize = 17;
const OFD_INFORMATION: usize = 18;
const OFD_INTERFACE_ID: usize = 19;
const OFD_MSG_TYPE: usize = 20;
const OFD_OPTIONS: usize = 21;
const OFD_PREFERENCE: usize = 22;
const OFD_PREFERRED_LIFETIME: usize = 23;
const OFD_PREFIX: usize = 24;
const OFD_PREFIX_LENGTH: usize = 25;
const OFD_PROTOCOL: usize = 26;
const OFD_RDM: usize = 27;
const OFD_RELAY_MESSAGE: usize = 28;
const OFD_REPLAY_DETECTION: usize = 29;
const OFD_REQUESTED_OPTIONS: usize = 30;
const OFD_SERVER_ID: usize = 31;
const OFD_SERVER_UNICAST: usize = 32;
const OFD_STATUS_CODE: usize = 33;
const OFD_STATUS_MESSAGE: usize = 34;
const OFD_T1: usize = 35;
const OFD_T2: usize = 36;
const OFD_USER_CLASS: usize = 37;
const OFD_VALID_LIFETIME: usize = 38;
const OFD_VENDOR_CLASS: usize = 39;
const OFD_VENDOR_INFO: usize = 40;
const OFD_DUID_TYPE: usize = 41;
const OFD_HW_TYPE: usize = 42;
const OFD_LINK_LAYER_ADDRESS: usize = 43;
const OFD_LINK_LAYER_ADDRESS_BYTES: usize = 44;
const OFD_IDENTIFIER: usize = 45;
const OFD_UUID: usize = 46;
const OFD_RELAY_ID: usize = 47;
const OFD_SIP_SERVER_DOMAINS: usize = 48;
const OFD_SIP_SERVER_ADDRESSES: usize = 49;
const OFD_SNTP_SERVERS: usize = 50;
const OFD_INFORMATION_REFRESH_TIME: usize = 51;
const OFD_REMOTE_ID: usize = 52;
const OFD_SUBSCRIBER_ID: usize = 53;
const OFD_NTP_SUBOPTIONS: usize = 54;
const OFD_BOOT_FILE_URL: usize = 55;
const OFD_BOOT_FILE_PARAMETERS: usize = 56;
const OFD_CLIENT_ARCH_TYPES: usize = 57;
const OFD_AFTR_NAME: usize = 58;
const OFD_LINK_LAYER_TYPE: usize = 59;
const OFD_SOL_MAX_RT: usize = 60;
const OFD_INF_MAX_RT: usize = 61;
const OFD_DHCPV4_MESSAGE: usize = 62;
const OFD_DHCP4O6_SERVERS: usize = 63;
const OFD_EA_LEN: usize = 64;
const OFD_PREFIX4_LEN: usize = 65;
const OFD_IPV4_PREFIX: usize = 66;
const OFD_PREFIX6_LEN: usize = 67;
const OFD_IPV6_PREFIX: usize = 68;
const OFD_BR_ADDRESS: usize = 69;
const OFD_IPV4_ADDRESS: usize = 70;
const OFD_PSID_OFFSET: usize = 71;
const OFD_PSID_LEN: usize = 72;
const OFD_PSID: usize = 73;
const OFD_CAPTIVE_PORTAL_URI: usize = 74;
const OFD_VENDOR_OPTIONS: usize = 75;

/// Child field descriptors for DHCPv6 option entries.
static OPTION_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("address", "IPv6 Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8).optional(),
    FieldDescriptor::new("authentication", "Authentication Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("client_id", "Client Identifier", FieldType::Bytes).optional(),
    FieldDescriptor::new("code", "Option Code", FieldType::U16),
    FieldDescriptor::new("data", "Option Data", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "dns_servers",
        "DNS Recursive Name Servers",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("domain_search", "Domain Search List", FieldType::Array).optional(),
    FieldDescriptor::new("elapsed_time", "Elapsed Time", FieldType::U16).optional(),
    FieldDescriptor::new("enterprise_number", "Enterprise Number", FieldType::U32).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    // RFC 4704, Section 4.2 — "The data in the Domain Name field MUST be
    // encoded as described in Section 8 of [5]."
    // <https://www.rfc-editor.org/rfc/rfc4704#section-4.2>
    FieldDescriptor::new("fqdn", "Fully Qualified Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_fqdn_labels),
    FieldDescriptor::new("ia_addr", "IA Address Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_na", "IA_NA Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_pd", "IA_PD Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_prefix", "IA Prefix Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("ia_ta", "IA_TA Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("iaid", "IAID", FieldType::U32).optional(),
    FieldDescriptor::new(
        "information",
        "Authentication Information",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("interface_id", "Interface ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("msg_type", "Message Type", FieldType::U8).optional(),
    FieldDescriptor::new("options", "Options", FieldType::Array).optional(),
    FieldDescriptor::new("preference", "Preference Value", FieldType::U8).optional(),
    FieldDescriptor::new("preferred_lifetime", "Preferred Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("prefix", "Prefix", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8).optional(),
    FieldDescriptor::new("rdm", "Replay Detection Method", FieldType::U8).optional(),
    FieldDescriptor::new("relay_message", "Relay Message", FieldType::Bytes).optional(),
    FieldDescriptor::new("replay_detection", "Replay Detection", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "requested_options",
        "Requested Option Codes",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("server_id", "Server Identifier", FieldType::Bytes).optional(),
    FieldDescriptor::new("server_unicast", "Server Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("status_code", "Status Code", FieldType::U16).optional(),
    FieldDescriptor::new("status_message", "Status Message", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("t1", "T1", FieldType::U32).optional(),
    FieldDescriptor::new("t2", "T2", FieldType::U32).optional(),
    FieldDescriptor::new("user_class", "User Class Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("valid_lifetime", "Valid Lifetime", FieldType::U32).optional(),
    FieldDescriptor::new("vendor_class", "Vendor Class Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("vendor_info", "Vendor Information", FieldType::Bytes).optional(),
    // RFC 9915, Sections 11.1-11.5 — DUID contents.
    // <https://www.rfc-editor.org/rfc/rfc9915#section-11.1>
    FieldDescriptor::new("duid_type", "DUID Type", FieldType::U16).optional(),
    FieldDescriptor::new("hw_type", "Hardware Type", FieldType::U16).optional(),
    FieldDescriptor::new(
        "link_layer_address",
        "Link-Layer Address",
        FieldType::MacAddr,
    )
    .optional(),
    FieldDescriptor::new(
        "link_layer_address_bytes",
        "Link-Layer Address",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("identifier", "Identifier", FieldType::Bytes).optional(),
    FieldDescriptor::new("uuid", "UUID", FieldType::Bytes).optional(),
    // RFC 5460, Section 5.4.1 — <https://www.rfc-editor.org/rfc/rfc5460#section-5.4.1>
    FieldDescriptor::new("relay_id", "Relay-ID", FieldType::Bytes).optional(),
    // RFC 3319, Sections 3.1 and 3.2 — <https://www.rfc-editor.org/rfc/rfc3319#section-3.1>
    FieldDescriptor::new(
        "sip_server_domains",
        "SIP Server Domain Name List",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new(
        "sip_server_addresses",
        "SIP Server IPv6 Address List",
        FieldType::Array,
    )
    .optional(),
    // RFC 4075, Section 4 — <https://www.rfc-editor.org/rfc/rfc4075#section-4>
    FieldDescriptor::new("sntp_servers", "SNTP Servers", FieldType::Array).optional(),
    // RFC 9915, Section 21.23 — <https://www.rfc-editor.org/rfc/rfc9915#section-21.23>
    FieldDescriptor::new(
        "information_refresh_time",
        "Information Refresh Time",
        FieldType::U32,
    )
    .optional(),
    // RFC 4649, Section 3 — <https://www.rfc-editor.org/rfc/rfc4649#section-3>
    FieldDescriptor::new("remote_id", "Remote-ID", FieldType::Bytes).optional(),
    // RFC 4580, Section 2 — <https://www.rfc-editor.org/rfc/rfc4580#section-2>
    FieldDescriptor::new("subscriber_id", "Subscriber-ID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // RFC 5908, Section 4 — <https://www.rfc-editor.org/rfc/rfc5908#section-4>
    FieldDescriptor::new("ntp_suboptions", "NTP Server Suboptions", FieldType::Array)
        .optional()
        .with_children(NTP_SUBOPTION_CHILDREN),
    // RFC 5970, Sections 3.1-3.3 — <https://www.rfc-editor.org/rfc/rfc5970#section-3.1>
    FieldDescriptor::new("boot_file_url", "Boot File URL", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new(
        "boot_file_parameters",
        "Boot File Parameters",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new(
        "client_arch_types",
        "Client System Architecture Types",
        FieldType::Array,
    )
    .optional(),
    // RFC 6334, Section 3 — <https://www.rfc-editor.org/rfc/rfc6334#section-3>
    FieldDescriptor::new("aftr_name", "AFTR-Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_fqdn_labels),
    // RFC 6939, Section 4 — <https://www.rfc-editor.org/rfc/rfc6939#section-4>
    FieldDescriptor::new("link_layer_type", "Link-Layer Type", FieldType::U16).optional(),
    // RFC 9915, Sections 21.24 and 21.25 — <https://www.rfc-editor.org/rfc/rfc9915#section-21.24>
    FieldDescriptor::new("sol_max_rt", "SOL_MAX_RT", FieldType::U32).optional(),
    FieldDescriptor::new("inf_max_rt", "INF_MAX_RT", FieldType::U32).optional(),
    // RFC 7341, Sections 7.1 and 7.2 — <https://www.rfc-editor.org/rfc/rfc7341#section-7.1>
    FieldDescriptor::new("dhcpv4_message", "DHCPv4 Message", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "dhcp4o6_servers",
        "DHCP 4o6 Server Addresses",
        FieldType::Array,
    )
    .optional(),
    // RFC 7598, Sections 4.1-4.5 — <https://www.rfc-editor.org/rfc/rfc7598#section-4.1>
    FieldDescriptor::new("ea_len", "EA Length", FieldType::U8).optional(),
    FieldDescriptor::new("prefix4_len", "IPv4 Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("ipv4_prefix", "IPv4 Prefix", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("prefix6_len", "IPv6 Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("ipv6_prefix", "IPv6 Prefix", FieldType::Bytes).optional(),
    FieldDescriptor::new("br_address", "BR IPv6 Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("offset", "PSID Offset", FieldType::U8).optional(),
    FieldDescriptor::new("psid_len", "PSID Length", FieldType::U8).optional(),
    FieldDescriptor::new("psid", "PSID", FieldType::U16).optional(),
    // RFC 8910, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8910#section-2.2>
    FieldDescriptor::new("captive_portal_uri", "Captive-Portal URI", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // RFC 9915, Section 21.17 — <https://www.rfc-editor.org/rfc/rfc9915#section-21.17>
    FieldDescriptor::new("vendor_options", "Vendor Options", FieldType::Array)
        .optional()
        .with_children(VENDOR_OPTION_CHILDREN),
];

/// Element descriptor for one DNS-encoded domain name in a domain list
/// (options 21 and 24).
///
/// RFC 9915, Section 10 — "a domain name or a list of domain names is encoded
/// using the technique described in Section 3.1 of [RFC1035]."
/// <https://www.rfc-editor.org/rfc/rfc9915#section-10>
static FD_DOMAIN: FieldDescriptor = FieldDescriptor::new("domain", "Domain Name", FieldType::Bytes)
    .with_format_fn(format_fqdn_labels);

/// Element descriptor for one Boot File Parameters entry.
///
/// RFC 5970, Section 3.2 — "These UTF-8 strings are parameters needed for
/// booting, e.g., kernel parameters."
/// <https://www.rfc-editor.org/rfc/rfc5970#section-3.2>
static FD_BOOT_FILE_PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Bytes)
        .with_format_fn(format_utf8_lossy);

/// Child field descriptor indices for [`NTP_SUBOPTION_CHILDREN`].
const NFD_CODE: usize = 0;
const NFD_SERVER_ADDRESS: usize = 1;
const NFD_MULTICAST_ADDRESS: usize = 2;
const NFD_SERVER_FQDN: usize = 3;
const NFD_DATA: usize = 4;

/// Child field descriptors for NTP Server suboptions (RFC 5908, Sections
/// 4.1-4.3).
/// <https://www.rfc-editor.org/rfc/rfc5908#section-4.1>
static NTP_SUBOPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "Suboption Code", FieldType::U16),
    FieldDescriptor::new("server_address", "NTP Server Address", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new(
        "multicast_address",
        "NTP Multicast Address",
        FieldType::Ipv6Addr,
    )
    .optional(),
    FieldDescriptor::new("server_fqdn", "NTP Server FQDN", FieldType::Bytes)
        .optional()
        .with_format_fn(format_fqdn_labels),
    FieldDescriptor::new("data", "Suboption Data", FieldType::Bytes).optional(),
];

/// Object container for one NTP Server suboption.
static FD_NTP_SUBOPTION: FieldDescriptor =
    FieldDescriptor::new("ntp_suboption", "NTP Server Suboption", FieldType::Object)
        .with_children(NTP_SUBOPTION_CHILDREN);

/// Child field descriptors for one Vendor-specific Information suboption
/// (RFC 9915, Section 21.17).
/// <https://www.rfc-editor.org/rfc/rfc9915#section-21.17>
static VENDOR_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "Suboption Code", FieldType::U16),
    FieldDescriptor::new("data", "Suboption Data", FieldType::Bytes),
];

/// Object container for one Vendor-specific Information suboption.
static FD_VENDOR_OPTION: FieldDescriptor =
    FieldDescriptor::new("vendor_option", "Vendor Option", FieldType::Object)
        .with_children(VENDOR_OPTION_CHILDREN);

/// Returns a human-readable name for DHCPv6 option codes.
///
/// RFC 9915, Section 24 — DHCPv6 Option Codes.
/// <https://www.rfc-editor.org/rfc/rfc9915#section-24>
///
/// Codes beyond the base specification follow the IANA "DHCPv6 Parameters"
/// registry, "Option Codes":
/// <https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-2>
fn dhcpv6_option_name(code: u16) -> Option<&'static str> {
    Some(match code {
        1 => "Client Identifier",
        2 => "Server Identifier",
        3 => "IA_NA",
        4 => "IA_TA",
        5 => "IA Address",
        6 => "Option Request",
        7 => "Preference",
        8 => "Elapsed Time",
        9 => "Relay Message",
        11 => "Authentication",
        12 => "Server Unicast",
        13 => "Status Code",
        14 => "Rapid Commit",
        15 => "User Class",
        16 => "Vendor Class",
        17 => "Vendor-Specific Information",
        18 => "Interface-Id",
        19 => "Reconfigure Message",
        20 => "Reconfigure Accept",
        21 => "SIP Server Domain Name List",
        22 => "SIP Server IPv6 Address List",
        23 => "DNS Recursive Name Server",
        24 => "Domain Search List",
        25 => "IA_PD",
        26 => "IA Prefix",
        27 => "NIS Servers",
        28 => "NIS+ Servers",
        29 => "NIS Domain Name",
        30 => "NIS+ Domain Name",
        31 => "SNTP Servers",
        32 => "Information Refresh Time",
        33 => "BCMCS Controller Domain Name List",
        34 => "BCMCS Controller IPv6 Address List",
        36 => "GeoConf Civic",
        37 => "Relay Agent Remote-ID",
        38 => "Relay Agent Subscriber-ID",
        39 => "Client FQDN",
        40 => "PANA Authentication Agent",
        41 => "New POSIX Timezone",
        42 => "New TZDB Timezone",
        43 => "Echo Request",
        44 => "LQ Query",
        45 => "Client Data",
        46 => "CLT Time",
        47 => "LQ Relay Data",
        48 => "LQ Client Link",
        49 => "MIPv6 Home Network ID FQDN",
        50 => "MIPv6 Visited Home Network Information",
        51 => "LoST Server",
        52 => "CAPWAP Access Controller Addresses",
        53 => "Relay-ID",
        54 => "MoS IPv6 Address",
        55 => "MoS FQDN",
        56 => "NTP Server",
        57 => "Access Network Domain Name",
        58 => "SIP UA Configuration Service Domains",
        59 => "Boot File URL",
        60 => "Boot File Parameters",
        61 => "Client System Architecture Type",
        62 => "Client Network Interface Identifier",
        63 => "Geolocation",
        64 => "AFTR-Name",
        65 => "ERP Local Domain Name",
        66 => "Relay-Supplied Options",
        67 => "Prefix Exclude",
        68 => "Virtual Subnet Selection",
        69 => "MIPv6 Identified Home Network Information",
        70 => "MIPv6 Unrestricted Home Network Information",
        71 => "MIPv6 Home Network Prefix",
        72 => "MIPv6 Home Agent Address",
        73 => "MIPv6 Home Agent FQDN",
        74 => "RDNSS Selection",
        75 => "Kerberos Principal Name",
        76 => "Kerberos Realm Name",
        77 => "Kerberos Default Realm Name",
        78 => "Kerberos KDC",
        79 => "Client Link-Layer Address",
        80 => "Link Address",
        81 => "RADIUS",
        82 => "SOL_MAX_RT",
        83 => "INF_MAX_RT",
        84 => "Address Selection",
        85 => "Address Selection Policy Table",
        86 => "PCP Server",
        87 => "DHCPv4 Message",
        88 => "DHCP 4o6 Server Address",
        89 => "S46 Rule",
        90 => "S46 BR",
        91 => "S46 DMR",
        92 => "S46 IPv4/IPv6 Address Binding",
        93 => "S46 Port Parameters",
        94 => "S46 MAP-E Container",
        95 => "S46 MAP-T Container",
        96 => "S46 Lightweight 4over6 Container",
        97 => "4RD",
        98 => "4RD Map Rule",
        99 => "4RD Non-Map Rule",
        100 => "LQ Base Time",
        101 => "LQ Start Time",
        102 => "LQ End Time",
        103 => "Captive-Portal",
        104 => "MPL Parameters",
        105 => "ANI Access-Technology-Type",
        106 => "ANI Network-Name",
        107 => "ANI AP-Name",
        108 => "ANI AP-BSSID",
        109 => "ANI Operator-Identifier",
        110 => "ANI Operator-Realm",
        111 => "S46 Priority",
        112 => "MUD URL",
        113 => "IPv6 Prefix64",
        114 => "Failover Binding Status",
        115 => "Failover Connect Flags",
        116 => "Failover DNS Removal Info",
        117 => "Failover DNS Host Name",
        118 => "Failover DNS Zone Name",
        119 => "Failover DNS Flags",
        120 => "Failover Expiration Time",
        121 => "Failover Max Unacked BNDUPD",
        122 => "Failover MCLT",
        123 => "Failover Partner Lifetime",
        124 => "Failover Partner Lifetime Sent",
        125 => "Failover Partner Down Time",
        126 => "Failover Partner Raw CLT Time",
        127 => "Failover Protocol Version",
        128 => "Failover Keepalive Time",
        129 => "Failover Reconfigure Data",
        130 => "Failover Relationship Name",
        131 => "Failover Server Flags",
        132 => "Failover Server State",
        133 => "Failover Start Time of State",
        134 => "Failover State Expiration Time",
        135 => "Relay Source Port",
        136 => "SZTP Redirect",
        137 => "S46 Bind IPv6 Prefix",
        138 => "IA_LL",
        139 => "LLADDR",
        140 => "SLAP Quad",
        141 => "DOTS Reference Identifier",
        142 => "DOTS Address",
        143 => "ANDSF IPv6 Address",
        144 => "Encrypted DNS Resolver",
        145 => "Registered Domain",
        146 => "Forward Distributed Manager",
        147 => "Reverse Distributed Manager",
        148 => "ADDR-REG-ENABLE",
        149 => "IA SRv6 Locator",
        150 => "IA Locator",
        _ => return None,
    })
}

/// Descriptor for the DHCPv6 option Object container.
///
/// `display_fn` is invoked by
/// [`DissectBuffer::resolve_container_display_name`] with the container's
/// children, so the outer label resolves to the option name (e.g.
/// "Client Identifier") instead of colliding with the inner `Option Code`
/// field.
static FD_DHCPV6_OPTION: FieldDescriptor = FieldDescriptor {
    name: "dhcpv6_option",
    display_name: "DHCPv6 Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("code", FieldValue::U16(c)) => dhcpv6_option_name(*c),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Minimum client/server message size: msg-type (1) + transaction-id (3).
const CLIENT_SERVER_HEADER_SIZE: usize = 4;

/// Relay message header size: msg-type (1) + hop-count (1) + link-address (16) + peer-address (16).
const RELAY_HEADER_SIZE: usize = 34;

/// DHCPv6 option header size: option-code (2) + option-len (2).
const OPTION_HEADER_SIZE: usize = 4;

/// Returns a human-readable name for DHCPv6 message type values.
///
/// RFC 9915, Section 7.3 — DHCP Message Types.
/// <https://www.rfc-editor.org/rfc/rfc9915#section-7.3>
///
/// Later values follow the IANA "DHCPv6 Parameters" registry, "Message
/// Types"; multi-word names use `_` like the base types above:
/// <https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-1>
fn dhcpv6_msg_type_name(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "SOLICIT",
        2 => "ADVERTISE",
        3 => "REQUEST",
        4 => "CONFIRM",
        5 => "RENEW",
        6 => "REBIND",
        7 => "REPLY",
        8 => "RELEASE",
        9 => "DECLINE",
        10 => "RECONFIGURE",
        11 => "INFORMATION_REQUEST",
        12 => "RELAY_FORW",
        13 => "RELAY_REPL",
        // RFC 5007, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc5007#section-4.1.1>
        14 => "LEASEQUERY",
        15 => "LEASEQUERY_REPLY",
        // RFC 5460, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc5460#section-5.2>
        16 => "LEASEQUERY_DONE",
        17 => "LEASEQUERY_DATA",
        // RFC 6977, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc6977#section-6.1>
        18 => "RECONFIGURE_REQUEST",
        19 => "RECONFIGURE_REPLY",
        // RFC 7341, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc7341#section-6.1>
        20 => "DHCPV4_QUERY",
        21 => "DHCPV4_RESPONSE",
        // RFC 7653, Section 6.2 — <https://www.rfc-editor.org/rfc/rfc7653#section-6.2>
        22 => "ACTIVELEASEQUERY",
        23 => "STARTTLS",
        // RFC 8156, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc8156#section-5.3>
        24 => "BNDUPD",
        25 => "BNDREPLY",
        26 => "POOLREQ",
        27 => "POOLRESP",
        28 => "UPDREQ",
        29 => "UPDREQALL",
        30 => "UPDDONE",
        31 => "CONNECT",
        32 => "CONNECTREPLY",
        33 => "DISCONNECT",
        34 => "STATE",
        35 => "CONTACT",
        // RFC 9686, Sections 4.2 and 4.3 — <https://www.rfc-editor.org/rfc/rfc9686#section-4.2>
        36 => "ADDR_REG_INFORM",
        37 => "ADDR_REG_REPLY",
        _ => return None,
    })
}

/// DHCPv6 dissector.
pub struct Dhcpv6Dissector;

/// Specification references for the DHCPv6 dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9915",
        "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)",
        "https://www.rfc-editor.org/rfc/rfc9915",
    ),
    SpecReference::new(
        "RFC 8415",
        "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)",
        "https://www.rfc-editor.org/rfc/rfc8415",
    ),
    SpecReference::new(
        "RFC 3646",
        "DNS Configuration options for Dynamic Host Configuration Protocol for IPv6 (DHCPv6)",
        "https://www.rfc-editor.org/rfc/rfc3646",
    ),
    SpecReference::new(
        "RFC 4704",
        "The Dynamic Host Configuration Protocol for IPv6 (DHCPv6) Client Fully Qualified Domain Name (FQDN) Option",
        "https://www.rfc-editor.org/rfc/rfc4704",
    ),
    SpecReference::new(
        "RFC 6355",
        "Definition of the UUID-Based DHCPv6 Unique Identifier (DUID-UUID)",
        "https://www.rfc-editor.org/rfc/rfc6355",
    ),
    SpecReference::new(
        "RFC 3319",
        "Dynamic Host Configuration Protocol (DHCPv6) Options for Session Initiation Protocol (SIP) Servers",
        "https://www.rfc-editor.org/rfc/rfc3319",
    ),
    SpecReference::new(
        "RFC 4075",
        "Simple Network Time Protocol (SNTP) Configuration Option for DHCPv6",
        "https://www.rfc-editor.org/rfc/rfc4075",
    ),
    SpecReference::new(
        "RFC 4649",
        "Dynamic Host Configuration Protocol for IPv6 (DHCPv6) Relay Agent Remote-ID Option",
        "https://www.rfc-editor.org/rfc/rfc4649",
    ),
    SpecReference::new(
        "RFC 4580",
        "Dynamic Host Configuration Protocol for IPv6 (DHCPv6) Relay Agent Subscriber-ID Option",
        "https://www.rfc-editor.org/rfc/rfc4580",
    ),
    SpecReference::new(
        "RFC 5007",
        "DHCPv6 Leasequery",
        "https://www.rfc-editor.org/rfc/rfc5007",
    ),
    SpecReference::new(
        "RFC 5460",
        "DHCPv6 Bulk Leasequery",
        "https://www.rfc-editor.org/rfc/rfc5460",
    ),
    SpecReference::new(
        "RFC 5908",
        "Network Time Protocol (NTP) Server Option for DHCPv6",
        "https://www.rfc-editor.org/rfc/rfc5908",
    ),
    SpecReference::new(
        "RFC 5970",
        "DHCPv6 Options for Network Boot",
        "https://www.rfc-editor.org/rfc/rfc5970",
    ),
    SpecReference::new(
        "RFC 6334",
        "Dynamic Host Configuration Protocol for IPv6 (DHCPv6) Option for Dual-Stack Lite",
        "https://www.rfc-editor.org/rfc/rfc6334",
    ),
    SpecReference::new(
        "RFC 6939",
        "Client Link-Layer Address Option in DHCPv6",
        "https://www.rfc-editor.org/rfc/rfc6939",
    ),
    SpecReference::new(
        "RFC 6977",
        "Triggering DHCPv6 Reconfiguration from Relay Agents",
        "https://www.rfc-editor.org/rfc/rfc6977",
    ),
    SpecReference::new(
        "RFC 7341",
        "DHCPv4-over-DHCPv6 (DHCP 4o6) Transport",
        "https://www.rfc-editor.org/rfc/rfc7341",
    ),
    SpecReference::new(
        "RFC 7598",
        "DHCPv6 Options for Configuration of Softwire Address and Port-Mapped Clients",
        "https://www.rfc-editor.org/rfc/rfc7598",
    ),
    SpecReference::new(
        "RFC 7653",
        "DHCPv6 Active Leasequery",
        "https://www.rfc-editor.org/rfc/rfc7653",
    ),
    SpecReference::new(
        "RFC 8156",
        "DHCPv6 Failover Protocol",
        "https://www.rfc-editor.org/rfc/rfc8156",
    ),
    SpecReference::new(
        "RFC 8910",
        "Captive-Portal Identification in DHCP and Router Advertisements (RAs)",
        "https://www.rfc-editor.org/rfc/rfc8910",
    ),
    SpecReference::new(
        "RFC 9686",
        "Registering Self-Generated IPv6 Addresses Using DHCPv6",
        "https://www.rfc-editor.org/rfc/rfc9686",
    ),
];

impl Dissector for Dhcpv6Dissector {
    fn name(&self) -> &'static str {
        "Dynamic Host Configuration Protocol for IPv6"
    }

    fn short_name(&self) -> &'static str {
        "DHCPv6"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.is_empty() {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        }

        let msg_type = data[0];

        // RFC 9915, Section 9 — Relay messages have a different header format.
        if msg_type == 12 || msg_type == 13 {
            return dissect_relay(data, buf, offset, 0);
        }

        dissect_client_server(data, buf, offset)
    }
}

/// Parse a client/server message (RFC 9915, Section 8).
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    msg-type   |               transaction-id                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          options ...                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn dissect_client_server<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<DissectResult, PacketError> {
    if data.len() < CLIENT_SERVER_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: CLIENT_SERVER_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let msg_type = data[0];
    // RFC 9915, Section 8 — transaction-id is 3 bytes. RFC 7341, Section 6.2
    // — DHCPv4-query and DHCPv4-response carry a 3-octet "flags" field in the
    // same position.
    // <https://www.rfc-editor.org/rfc/rfc7341#section-6.2>
    let second_word = read_be_u24(data, 1)?;
    let is_dhcp4o6 = matches!(msg_type, MSG_DHCPV4_QUERY | MSG_DHCPV4_RESPONSE);

    buf.begin_layer(
        "DHCPv6",
        None,
        FIELD_DESCRIPTORS,
        offset..offset + data.len(),
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MSG_TYPE],
        FieldValue::U8(msg_type),
        offset..offset + 1,
    );
    if is_dhcp4o6 {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U32(second_word),
            offset + 1..offset + 4,
        );
        // RFC 7341, Section 6.3 — "U:   Unicast flag." is the first bit of
        // the DHCPv4-query flags. Section 6.4 defines no DHCPv4-response
        // flags.
        // <https://www.rfc-editor.org/rfc/rfc7341#section-6.3>
        if msg_type == MSG_DHCPV4_QUERY {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_UNICAST],
                FieldValue::U8((second_word >> 23) as u8),
                offset + 1..offset + 2,
            );
        }
    } else {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TRANSACTION_ID],
            FieldValue::U32(second_word),
            offset + 1..offset + 4,
        );
    }

    // Parse options (RFC 9915, Section 21.1).
    let scan = parse_options(buf, data, offset, CLIENT_SERVER_HEADER_SIZE, 0)?;

    let total_len = data.len();
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..offset + total_len;
    }
    buf.end_layer();

    // Recursively parse Relay Message option (9) if present
    if let Some(range) = scan.relay_message {
        let inner = &data[range.start..range.end];
        let _ = parse_inner_message(inner, buf, offset + range.start, 0);
    }

    // RFC 7341, Section 6.2 — "The DHCPv4 Message Option (described in
    // Section 7.1) MUST be carried by the message." Its DHCPv4 message is
    // handed to the DHCPv4 dissector, which the registry serves on the
    // DHCPv4 UDP ports (RFC 2131, Section 4.1).
    // <https://www.rfc-editor.org/rfc/rfc7341#section-6.2>
    // <https://www.rfc-editor.org/rfc/rfc2131#section-4.1>
    if is_dhcp4o6 {
        if let Some(range) = scan.dhcpv4_message {
            return Ok(DissectResult::with_embedded_payload(
                total_len,
                DispatchHint::ByUdpPort(DHCPV4_SERVER_PORT, DHCPV4_CLIENT_PORT),
                offset + range.start..offset + range.end,
            ));
        }
    }

    Ok(DissectResult::new(total_len, DispatchHint::End))
}

/// DHCPV4-QUERY message type.
///
/// RFC 7341, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc7341#section-6.1>
const MSG_DHCPV4_QUERY: u8 = 20;
/// DHCPV4-RESPONSE message type.
///
/// RFC 7341, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc7341#section-6.1>
const MSG_DHCPV4_RESPONSE: u8 = 21;

/// DHCPv4 server UDP port, used to dispatch an encapsulated DHCPv4 message.
///
/// RFC 2131, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc2131#section-4.1>
const DHCPV4_SERVER_PORT: u16 = 67;
/// DHCPv4 client UDP port.
///
/// RFC 2131, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc2131#section-4.1>
const DHCPV4_CLIENT_PORT: u16 = 68;

/// Parse a relay agent message (RFC 9915, Section 9).
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    msg-type   |   hop-count   |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                         link-address                          |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// |                               |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                         peer-address                          |
/// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
/// |                               |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          options ...                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// Maximum relay nesting depth.
///
/// RFC 9915, Section 7.6 — HOP_COUNT_LIMIT = 8. A relay agent discards any
/// Relay-forward message whose hop-count is greater than or equal to this
/// value (Section 19.1.2). The dissector uses the same value to bound
/// recursion through nested Relay Message (9) options.
const MAX_RELAY_DEPTH: usize = 8;

fn dissect_relay<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    depth: usize,
) -> Result<DissectResult, PacketError> {
    if depth >= MAX_RELAY_DEPTH {
        return Err(PacketError::InvalidHeader(
            "DHCPv6: relay nesting depth exceeds HOP_COUNT_LIMIT (8)",
        ));
    }
    if data.len() < RELAY_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: RELAY_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let msg_type = data[0];
    let hop_count = data[1];

    let mut link_address = [0u8; 16];
    link_address.copy_from_slice(&data[2..18]);

    let mut peer_address = [0u8; 16];
    peer_address.copy_from_slice(&data[18..34]);

    buf.begin_layer(
        "DHCPv6",
        None,
        FIELD_DESCRIPTORS,
        offset..offset + data.len(),
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MSG_TYPE],
        FieldValue::U8(msg_type),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_HOP_COUNT],
        FieldValue::U8(hop_count),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LINK_ADDRESS],
        FieldValue::Ipv6Addr(link_address),
        offset + 2..offset + 18,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_ADDRESS],
        FieldValue::Ipv6Addr(peer_address),
        offset + 18..offset + 34,
    );

    // Parse options (RFC 9915, Section 21.1).
    let scan = parse_options(buf, data, offset, RELAY_HEADER_SIZE, 0)?;

    let total_len = data.len();
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..offset + total_len;
    }
    buf.end_layer();

    // Recursively parse Relay Message option (9) if present
    if let Some(range) = scan.relay_message {
        let inner = &data[range.start..range.end];
        // A relayed DHCPv4-query / DHCPv4-response (RFC 7341, Section 10)
        // still hands its DHCPv4 message on; its range is already absolute.
        // <https://www.rfc-editor.org/rfc/rfc7341#section-10>
        if let Ok(inner_result) = parse_inner_message(inner, buf, offset + range.start, depth) {
            if let Some(payload) = inner_result.embedded_payload {
                return Ok(DissectResult::with_embedded_payload(
                    total_len,
                    inner_result.next,
                    payload,
                ));
            }
        }
    }

    Ok(DissectResult::new(total_len, DispatchHint::End))
}

/// Recursively parse an inner DHCPv6 message from a Relay Message option (9).
///
/// Errors are silently ignored since the outer message is already parsed.
fn parse_inner_message<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    depth: usize,
) -> Result<DissectResult, PacketError> {
    if data.is_empty() {
        return Err(PacketError::Truncated {
            expected: 1,
            actual: 0,
        });
    }
    let msg_type = data[0];
    if msg_type == 12 || msg_type == 13 {
        dissect_relay(data, buf, offset, depth + 1)
    } else {
        dissect_client_server(data, buf, offset)
    }
}

/// Parse DHCPv6 options (RFC 9915, Section 21.1).
///
/// Each option is encoded as:
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          option-code          |           option-len          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          option-data ...                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// The parsed options are pushed as an `options` array. `depth` counts the
/// levels of encapsulating options above this list (0 for a message's
/// top-level options); see [`MAX_OPTION_DEPTH`].
///
/// Returns the ranges (relative to `data`) of the Relay Message (9) and
/// DHCPv4 Message (87) option data found in this list.
fn parse_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    start: usize,
    depth: usize,
) -> Result<OptionScan, PacketError> {
    let mut cursor = start;
    let mut scan = OptionScan::default();
    let options_arr_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_OPTIONS],
        FieldValue::Array(0..0),
        offset + start..offset + data.len(),
    );

    while cursor + OPTION_HEADER_SIZE <= data.len() {
        let option_code = read_be_u16(data, cursor)?;
        let option_len = read_be_u16(data, cursor + 2)? as usize;

        let option_data_start = cursor + OPTION_HEADER_SIZE;
        let option_data_end = option_data_start + option_len;

        if option_data_end > data.len() {
            return Err(PacketError::Truncated {
                expected: option_data_end,
                actual: data.len(),
            });
        }

        let option_data = &data[option_data_start..option_data_end];
        let field_range = offset + cursor..offset + option_data_end;

        match option_code {
            // RFC 9915, Section 21.2 — Client Identifier Option. The DUID
            // (Section 11) is also decoded.
            // <https://www.rfc-editor.org/rfc/rfc9915#section-21.2>
            1 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CLIENT_ID],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                push_duid(buf, option_data, offset + option_data_start);
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.3 — Server Identifier Option.
            // <https://www.rfc-editor.org/rfc/rfc9915#section-21.3>
            2 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_SERVER_ID],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                push_duid(buf, option_data, offset + option_data_start);
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.4 — Identity Association for Non-Temporary
            // Addresses Option (IA_NA).
            3 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 12 {
                    let iaid = read_be_u32(option_data, 0)?;
                    let t1 = read_be_u32(option_data, 4)?;
                    let t2 = read_be_u32(option_data, 8)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IAID],
                        FieldValue::U32(iaid),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T1],
                        FieldValue::U32(t1),
                        offset + option_data_start + 4..offset + option_data_start + 8,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T2],
                        FieldValue::U32(t2),
                        offset + option_data_start + 8..offset + option_data_start + 12,
                    );
                    if option_data.len() > 12 {
                        push_encapsulated_options(
                            buf,
                            option_data,
                            offset + option_data_start,
                            12,
                            depth,
                        )?;
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_NA],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.5 — Identity Association for Temporary
            // Addresses Option (IA_TA). Obsoleted by RFC 9915; retained so the
            // dissector can still decode legacy captures.
            4 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 4 {
                    let iaid = read_be_u32(option_data, 0)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IAID],
                        FieldValue::U32(iaid),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    if option_data.len() > 4 {
                        push_encapsulated_options(
                            buf,
                            option_data,
                            offset + option_data_start,
                            4,
                            depth,
                        )?;
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_TA],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.6 — IA Address Option.
            5 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 24 {
                    let addr = read_ipv6_addr(option_data, 0)?;
                    let preferred_lifetime = read_be_u32(option_data, 16)?;
                    let valid_lifetime = read_be_u32(option_data, 20)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ADDRESS],
                        FieldValue::Ipv6Addr(addr),
                        offset + option_data_start..offset + option_data_start + 16,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFERRED_LIFETIME],
                        FieldValue::U32(preferred_lifetime),
                        offset + option_data_start + 16..offset + option_data_start + 20,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VALID_LIFETIME],
                        FieldValue::U32(valid_lifetime),
                        offset + option_data_start + 20..offset + option_data_start + 24,
                    );
                    if option_data.len() > 24 {
                        push_encapsulated_options(
                            buf,
                            option_data,
                            offset + option_data_start,
                            24,
                            depth,
                        )?;
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_ADDR],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.7 — Option Request Option.
            6 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                let req_arr_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_REQUESTED_OPTIONS],
                    FieldValue::Array(0..0),
                    offset + option_data_start..offset + option_data_end,
                );
                let mut i = 0;
                while i + 2 <= option_data.len() {
                    let code = read_be_u16(option_data, i)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_REQUESTED_OPTIONS],
                        FieldValue::U16(code),
                        offset + option_data_start + i..offset + option_data_start + i + 2,
                    );
                    i += 2;
                }
                buf.end_container(req_arr_idx);
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.8 — Preference Option.
            7 => {
                if !option_data.is_empty() {
                    let obj_idx = buf.begin_container(
                        &FD_DHCPV6_OPTION,
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFERENCE],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 9915, Section 21.9 — Elapsed Time Option.
            8 => {
                if option_data.len() >= 2 {
                    let elapsed = read_be_u16(option_data, 0)?;
                    let obj_idx = buf.begin_container(
                        &FD_DHCPV6_OPTION,
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ELAPSED_TIME],
                        FieldValue::U16(elapsed),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 9915, Section 21.10 — Relay Message Option.
            9 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_RELAY_MESSAGE],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
                scan.relay_message = Some(option_data_start..option_data_end);
            }
            // RFC 9915, Section 21.11 — Authentication Option.
            11 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 11 {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PROTOCOL],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_start + 1,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ALGORITHM],
                        FieldValue::U8(option_data[1]),
                        offset + option_data_start + 1..offset + option_data_start + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_RDM],
                        FieldValue::U8(option_data[2]),
                        offset + option_data_start + 2..offset + option_data_start + 3,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_REPLAY_DETECTION],
                        FieldValue::Bytes(&option_data[3..11]),
                        offset + option_data_start + 3..offset + option_data_start + 11,
                    );
                    if option_data.len() > 11 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_INFORMATION],
                            FieldValue::Bytes(&option_data[11..]),
                            offset + option_data_start + 11..offset + option_data_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_AUTHENTICATION],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.12 — Server Unicast Option. Obsoleted by
            // RFC 9915; retained so the dissector can still decode legacy
            // captures.
            12 => {
                if option_data.len() >= 16 {
                    let addr = read_ipv6_addr(option_data, 0)?;
                    let obj_idx = buf.begin_container(
                        &FD_DHCPV6_OPTION,
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_SERVER_UNICAST],
                        FieldValue::Ipv6Addr(addr),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 9915, Section 21.13 — Status Code Option.
            13 => {
                if option_data.len() >= 2 {
                    let status_code = read_be_u16(option_data, 0)?;
                    let obj_idx = buf.begin_container(
                        &FD_DHCPV6_OPTION,
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_STATUS_CODE],
                        FieldValue::U16(status_code),
                        offset + option_data_start..offset + option_data_start + 2,
                    );
                    if option_data.len() > 2 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_STATUS_MESSAGE],
                            FieldValue::Bytes(&option_data[2..]),
                            offset + option_data_start + 2..offset + option_data_end,
                        );
                    }
                    buf.end_container(obj_idx);
                }
            }
            // RFC 9915, Section 21.14 — Rapid Commit Option.
            14 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.15 — User Class Option.
            15 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_USER_CLASS],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.16 — Vendor Class Option.
            16 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 4 {
                    let enterprise_number = read_be_u32(option_data, 0)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ENTERPRISE_NUMBER],
                        FieldValue::U32(enterprise_number),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    if option_data.len() > 4 {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_DATA],
                            FieldValue::Bytes(&option_data[4..]),
                            offset + option_data_start + 4..offset + option_data_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VENDOR_CLASS],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.17 — Vendor-Specific Information Option.
            17 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 4 {
                    let enterprise_number = read_be_u32(option_data, 0)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_ENTERPRISE_NUMBER],
                        FieldValue::U32(enterprise_number),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    let vendor_data = &option_data[4..];
                    // RFC 9915, Section 21.17 — "The vendor-option-data field
                    // MUST be encoded as a sequence of code/length/value
                    // fields of format identical to the DHCP options (see
                    // Section 21.1)." Data that does not parse exactly stays
                    // raw.
                    // <https://www.rfc-editor.org/rfc/rfc9915#section-21.17>
                    if !vendor_data.is_empty() && options_valid(vendor_data) {
                        push_vendor_options(buf, vendor_data, offset + option_data_start + 4);
                    } else if !vendor_data.is_empty() {
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_DATA],
                            FieldValue::Bytes(vendor_data),
                            offset + option_data_start + 4..offset + option_data_end,
                        );
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VENDOR_INFO],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.18 — Interface-Id Option.
            18 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_INTERFACE_ID],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.19 — Reconfigure Message Option.
            19 => {
                if !option_data.is_empty() {
                    let obj_idx = buf.begin_container(
                        &FD_DHCPV6_OPTION,
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_MSG_TYPE],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_end,
                    );
                    buf.end_container(obj_idx);
                }
            }
            // RFC 9915, Section 21.20 — Reconfigure Accept Option.
            20 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.end_container(obj_idx);
            }
            // RFC 3646, Section 3 — DNS Recursive Name Server
            23 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                let dns_arr_idx = buf.begin_container(
                    &OPTION_CHILD_FIELDS[OFD_DNS_SERVERS],
                    FieldValue::Array(0..0),
                    offset + option_data_start..offset + option_data_end,
                );
                let mut i = 0;
                while i + 16 <= option_data.len() {
                    let addr = read_ipv6_addr(option_data, i)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_DNS_SERVERS],
                        FieldValue::Ipv6Addr(addr),
                        offset + option_data_start + i..offset + option_data_start + i + 16,
                    );
                    i += 16;
                }
                buf.end_container(dns_arr_idx);
                buf.end_container(obj_idx);
            }
            // RFC 3646, Section 4 — Domain Search List
            24 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if domain_list_is_complete(option_data) {
                    push_domain_list(
                        buf,
                        &OPTION_CHILD_FIELDS[OFD_DOMAIN_SEARCH],
                        option_data,
                        offset + option_data_start,
                    );
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_DATA],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.21 — Identity Association for Prefix
            // Delegation Option (IA_PD).
            25 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 12 {
                    let iaid = read_be_u32(option_data, 0)?;
                    let t1 = read_be_u32(option_data, 4)?;
                    let t2 = read_be_u32(option_data, 8)?;
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IAID],
                        FieldValue::U32(iaid),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T1],
                        FieldValue::U32(t1),
                        offset + option_data_start + 4..offset + option_data_start + 8,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_T2],
                        FieldValue::U32(t2),
                        offset + option_data_start + 8..offset + option_data_start + 12,
                    );
                    if option_data.len() > 12 {
                        push_encapsulated_options(
                            buf,
                            option_data,
                            offset + option_data_start,
                            12,
                            depth,
                        )?;
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_PD],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 9915, Section 21.22 — IA Prefix Option.
            26 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if option_data.len() >= 25 {
                    let preferred_lifetime = read_be_u32(option_data, 0)?;
                    let valid_lifetime = read_be_u32(option_data, 4)?;
                    let prefix_length = option_data[8];
                    let mut prefix = [0u8; 16];
                    prefix.copy_from_slice(&option_data[9..25]);
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFERRED_LIFETIME],
                        FieldValue::U32(preferred_lifetime),
                        offset + option_data_start..offset + option_data_start + 4,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_VALID_LIFETIME],
                        FieldValue::U32(valid_lifetime),
                        offset + option_data_start + 4..offset + option_data_start + 8,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFIX_LENGTH],
                        FieldValue::U8(prefix_length),
                        offset + option_data_start + 8..offset + option_data_start + 9,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_PREFIX],
                        FieldValue::Ipv6Addr(prefix),
                        offset + option_data_start + 9..offset + option_data_start + 25,
                    );
                    if option_data.len() > 25 {
                        push_encapsulated_options(
                            buf,
                            option_data,
                            offset + option_data_start,
                            25,
                            depth,
                        )?;
                    }
                } else {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_IA_PREFIX],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
            }
            // RFC 4704, Section 4 — Client FQDN
            39 => {
                if !option_data.is_empty() {
                    let obj_idx = buf.begin_container(
                        &FD_DHCPV6_OPTION,
                        FieldValue::Object(0..0),
                        field_range,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_CODE],
                        FieldValue::U16(option_code),
                        offset + cursor..offset + cursor + 2,
                    );
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_FLAGS],
                        FieldValue::U8(option_data[0]),
                        offset + option_data_start..offset + option_data_start + 1,
                    );
                    if option_data.len() > 1 {
                        // Store raw DNS-encoded FQDN bytes
                        buf.push_field(
                            &OPTION_CHILD_FIELDS[OFD_FQDN],
                            FieldValue::Bytes(&option_data[1..]),
                            offset + option_data_start + 1..offset + option_data_end,
                        );
                    }
                    buf.end_container(obj_idx);
                }
            }
            // Options decoded by `push_extended_option_value`; data that does
            // not match the defined format stays raw.
            21
            | 22
            | 31
            | 32
            | 37
            | 38
            | 53
            | 56
            | 59
            | 60
            | 61
            | 64
            | 79
            | 82
            | 83
            | 87
            | 88..=96
            | 103 => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                if !push_extended_option_value(
                    buf,
                    option_code,
                    option_data,
                    offset + option_data_start,
                    depth,
                ) {
                    buf.push_field(
                        &OPTION_CHILD_FIELDS[OFD_DATA],
                        FieldValue::Bytes(option_data),
                        offset + option_data_start..offset + option_data_end,
                    );
                }
                buf.end_container(obj_idx);
                if option_code == OPTION_DHCPV4_MSG {
                    scan.dhcpv4_message = Some(option_data_start..option_data_end);
                }
            }
            // Unknown option — store as raw bytes
            _ => {
                let obj_idx =
                    buf.begin_container(&FD_DHCPV6_OPTION, FieldValue::Object(0..0), field_range);
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_CODE],
                    FieldValue::U16(option_code),
                    offset + cursor..offset + cursor + 2,
                );
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_DATA],
                    FieldValue::Bytes(option_data),
                    offset + option_data_start..offset + option_data_end,
                );
                buf.end_container(obj_idx);
            }
        }

        cursor = option_data_end;
    }

    buf.end_container(options_arr_idx);
    Ok(scan)
}

/// Ranges (relative to the parsed slice) of option data that the caller
/// processes after the option list.
#[derive(Default)]
struct OptionScan {
    /// Relay Message option (9) data — RFC 9915, Section 21.10.
    /// <https://www.rfc-editor.org/rfc/rfc9915#section-21.10>
    relay_message: Option<core::ops::Range<usize>>,
    /// DHCPv4 Message option (87) data — RFC 7341, Section 7.1.
    /// <https://www.rfc-editor.org/rfc/rfc7341#section-7.1>
    dhcpv4_message: Option<core::ops::Range<usize>>,
}

/// OPTION_DHCPV4_MSG option code.
///
/// RFC 7341, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc7341#section-7.1>
const OPTION_DHCPV4_MSG: u16 = 87;

/// Maximum nesting depth of encapsulated options (e.g. IA Address inside
/// IA_NA, or S46 Rule inside an S46 container).
///
/// RFC 9915 does not bound option encapsulation; this is an implementation
/// limit that keeps recursion bounded on crafted input. Deeper encapsulated
/// options are exposed as raw bytes.
const MAX_OPTION_DEPTH: usize = 16;

/// Parse the options encapsulated in `option_data[start..]` of an IA_NA,
/// IA_TA, IA Address, IA_PD or IA Prefix option into an `options` field.
///
/// RFC 9915, Section 21.1 — <https://www.rfc-editor.org/rfc/rfc9915#section-21.1>
fn push_encapsulated_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    option_data: &'pkt [u8],
    abs: usize,
    start: usize,
    depth: usize,
) -> Result<(), PacketError> {
    let range = abs + start..abs + option_data.len();
    if depth + 1 >= MAX_OPTION_DEPTH {
        buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_DATA],
            FieldValue::Bytes(&option_data[start..]),
            range,
        );
        return Ok(());
    }
    let sub_arr_idx = buf.begin_container(
        &OPTION_CHILD_FIELDS[OFD_OPTIONS],
        FieldValue::Array(0..0),
        range,
    );
    parse_options(buf, option_data, abs, start, depth + 1)?;
    buf.end_container(sub_arr_idx);
    Ok(())
}

/// Whether `data` is a sequence of option-code (2) / option-len (2) /
/// option-data entries that exactly fills it.
///
/// RFC 9915, Section 21.1 — <https://www.rfc-editor.org/rfc/rfc9915#section-21.1>
fn options_valid(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        if i + OPTION_HEADER_SIZE > data.len() {
            return false;
        }
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += OPTION_HEADER_SIZE + len;
        if i > data.len() {
            return false;
        }
    }
    true
}

/// Push the options encapsulated in an S46 option (RFC 7598, Sections 4.1,
/// 4.4 and 5) as an `options` field. Returns `false` (leaving `buf`
/// possibly partially written; the caller rolls back) when the data is not
/// an exact option list, the depth limit is reached, or parsing fails.
/// <https://www.rfc-editor.org/rfc/rfc7598#section-5>
fn push_nested_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    abs: usize,
    depth: usize,
) -> bool {
    if depth + 1 >= MAX_OPTION_DEPTH || !options_valid(data) {
        return false;
    }
    parse_options(buf, data, abs, 0, depth + 1).is_ok()
}

/// Decode a DUID (RFC 9915, Section 11) whose raw bytes the caller has
/// already pushed. `abs` is the absolute offset of `duid`.
///
/// RFC 9915, Section 11.1 — "A DUID consists of a 2-octet type code
/// represented in network byte order, followed by a variable number of
/// octets that make up the actual identifier."
/// <https://www.rfc-editor.org/rfc/rfc9915#section-11.1>
///
/// Unknown types and identifiers too short for their type only yield the
/// type code: RFC 9915, Section 11 — "Clients and servers MUST NOT restrict
/// DUIDs to the types defined in this document, as additional DUID types may
/// be defined in the future."
/// <https://www.rfc-editor.org/rfc/rfc9915#section-11>
fn push_duid<'pkt>(buf: &mut DissectBuffer<'pkt>, duid: &'pkt [u8], abs: usize) {
    let &[t0, t1, ref rest @ ..] = duid else {
        return;
    };
    let duid_type = u16::from_be_bytes([t0, t1]);
    buf.push_field(
        &OPTION_CHILD_FIELDS[OFD_DUID_TYPE],
        FieldValue::U16(duid_type),
        abs..abs + 2,
    );
    let body = abs + 2;
    match (duid_type, rest) {
        // RFC 9915, Section 11.2 — DUID-LLT: hardware type (2), time (4),
        // link-layer address.
        // <https://www.rfc-editor.org/rfc/rfc9915#section-11.2>
        // The time field is left in the raw DUID bytes. An Ethernet address
        // (hardware type 0x0001, the common case) is pushed directly.
        (1, &[0, 1, _, _, _, _, a, b, c, d, e, f]) => {
            push_mac(buf, [a, b, c, d, e, f], body + 6);
        }
        (1, &[h0, h1, _, _, _, _, ref ll @ ..]) => {
            push_duid_link_layer(buf, u16::from_be_bytes([h0, h1]), ll, body, 6);
        }
        // RFC 9915, Section 11.3 — DUID-EN: enterprise-number (4),
        // identifier.
        // <https://www.rfc-editor.org/rfc/rfc9915#section-11.3>
        (2, &[e0, e1, e2, e3, ref id @ ..]) => {
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_ENTERPRISE_NUMBER],
                FieldValue::U32(u32::from_be_bytes([e0, e1, e2, e3])),
                body..body + 4,
            );
            if !id.is_empty() {
                buf.push_field(
                    &OPTION_CHILD_FIELDS[OFD_IDENTIFIER],
                    FieldValue::Bytes(id),
                    body + 4..body + 4 + id.len(),
                );
            }
        }
        // RFC 9915, Section 11.4 — DUID-LL: hardware type (2), link-layer
        // address.
        // <https://www.rfc-editor.org/rfc/rfc9915#section-11.4>
        // An Ethernet address (hardware type 0x0001) is pushed directly.
        (3, &[0, 1, a, b, c, d, e, f]) => push_mac(buf, [a, b, c, d, e, f], body + 2),
        (3, &[h0, h1, ref ll @ ..]) => {
            push_duid_link_layer(buf, u16::from_be_bytes([h0, h1]), ll, body, 2);
        }
        // RFC 9915, Section 11.5 — "This type of DUID consists of 16 octets
        // containing a 128-bit UUID." (RFC 6355, Section 4)
        // <https://www.rfc-editor.org/rfc/rfc9915#section-11.5>
        // <https://www.rfc-editor.org/rfc/rfc6355#section-4>
        (4, uuid) if uuid.len() == 16 => {
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_UUID],
                FieldValue::Bytes(uuid),
                body..body + 16,
            );
        }
        _ => {}
    }
}

/// IANA hardware type for Ethernet (10Mb).
///
/// RFC 9915, Section 11.2 — "The hardware type MUST be a valid hardware type
/// assigned by IANA"; value 1 is Ethernet in the IANA "Hardware Types"
/// registry.
/// <https://www.rfc-editor.org/rfc/rfc9915#section-11.2>
/// <https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2>
const HW_TYPE_ETHERNET: u16 = 1;

/// Push a link-layer address as `link_layer_address` (an Ethernet MAC) or
/// `link_layer_address_bytes` (any other type or length). Empty addresses
/// are omitted.
fn push_link_layer_address<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    hw_type: u16,
    addr: &'pkt [u8],
    abs: usize,
) {
    let range = abs..abs + addr.len();
    match (hw_type, addr) {
        (_, []) => {}
        (HW_TYPE_ETHERNET, &[a, b, c, d, e, f]) => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_LINK_LAYER_ADDRESS],
            FieldValue::MacAddr(MacAddr([a, b, c, d, e, f])),
            range,
        ),
        _ => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_LINK_LAYER_ADDRESS_BYTES],
            FieldValue::Bytes(addr),
            range,
        ),
    }
}

/// Push an Ethernet `link_layer_address` at absolute offset `abs`.
fn push_mac(buf: &mut DissectBuffer<'_>, mac: [u8; 6], abs: usize) {
    buf.push_field(
        &OPTION_CHILD_FIELDS[OFD_LINK_LAYER_ADDRESS],
        FieldValue::MacAddr(MacAddr(mac)),
        abs..abs + 6,
    );
}

/// Push the hardware type and link-layer address of a DUID-LLT or DUID-LL.
///
/// `hw_type` is pushed only when the address is not an Ethernet MAC: a
/// `link_layer_address` value already says that the type is Ethernet, and
/// keeping the common DUID to two fields keeps Solicit/Advertise dissection
/// cheap. `body` is the absolute offset of the hardware type and the address
/// starts `addr_at` octets after it.
fn push_duid_link_layer<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    hw_type: u16,
    addr: &'pkt [u8],
    body: usize,
    addr_at: usize,
) {
    if !(hw_type == HW_TYPE_ETHERNET && addr.len() == 6) {
        buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_HW_TYPE],
            FieldValue::U16(hw_type),
            body..body + 2,
        );
    }
    push_link_layer_address(buf, hw_type, addr, body + addr_at);
}

/// Whether `data` is a sequence of complete DNS-encoded names, each ending
/// at its zero-length label or at a 2-octet compression pointer.
///
/// RFC 3646, Section 4 — <https://www.rfc-editor.org/rfc/rfc3646#section-4>
/// and RFC 3319, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc3319#section-3.1>:
/// the option data is a list of domain names encoded as in RFC 1035,
/// Section 3.1 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.1>.
fn domain_list_is_complete(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        loop {
            let Some(&len) = data.get(i) else {
                return false;
            };
            let len = len as usize;
            if len == 0 {
                i += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                if i + 2 > data.len() {
                    return false;
                }
                i += 2;
                break;
            }
            if len & 0xC0 != 0 || i + 1 + len > data.len() {
                return false;
            }
            i += 1 + len;
        }
    }
    true
}

/// Push a list of DNS-encoded domain names (options 21 and 24) as an array
/// of [`FD_DOMAIN`] elements. A name ends at its zero-length label or at a
/// 2-octet compression pointer. Callers check [`domain_list_is_complete`]
/// first; a truncated trailing name would be dropped.
///
/// RFC 9915, Section 10 — "The message compression scheme in Section 4.1.4
/// of [RFC1035] MUST NOT be used." Pointers are still tolerated so that
/// non-conforming names do not hide the rest of the list.
/// <https://www.rfc-editor.org/rfc/rfc9915#section-10>
fn push_domain_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    data: &'pkt [u8],
    abs: usize,
) {
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), abs..abs + data.len());
    let mut i = 0;
    'names: while i < data.len() {
        let name_start = i;
        let mut has_labels = false;
        // Running out of data without the terminating label leaves a
        // partial name.
        while let Some(&len) = data.get(i) {
            let len = len as usize;
            if len == 0 {
                i += 1;
                break;
            }
            // RFC 1035, Section 4.1.4 — a pointer is "a two octet sequence"
            // whose first two bits are ones.
            // <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4>
            if len & 0xC0 == 0xC0 {
                if i + 2 > data.len() {
                    break 'names;
                }
                i += 2;
                has_labels = true;
                break;
            }
            if i + 1 + len > data.len() {
                break 'names;
            }
            has_labels = true;
            i += 1 + len;
        }
        if has_labels {
            buf.push_field(
                &FD_DOMAIN,
                FieldValue::Bytes(&data[name_start..i]),
                abs + name_start..abs + i,
            );
        }
    }
    buf.end_container(arr_idx);
}

/// Push a list of IPv6 addresses (`data.len()` is a multiple of 16).
fn push_ipv6_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    data: &'pkt [u8],
    abs: usize,
) {
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), abs..abs + data.len());
    for (n, chunk) in data.chunks_exact(16).enumerate() {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(chunk);
        buf.push_field(
            fd,
            FieldValue::Ipv6Addr(addr),
            abs + n * 16..abs + n * 16 + 16,
        );
    }
    buf.end_container(arr_idx);
}

/// Push the Vendor-specific Information suboptions (RFC 9915, Section
/// 21.17). The caller has checked [`options_valid`].
/// <https://www.rfc-editor.org/rfc/rfc9915#section-21.17>
fn push_vendor_options<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], abs: usize) {
    let arr_idx = buf.begin_container(
        &OPTION_CHILD_FIELDS[OFD_VENDOR_OPTIONS],
        FieldValue::Array(0..0),
        abs..abs + data.len(),
    );
    let mut i = 0;
    while i + OPTION_HEADER_SIZE <= data.len() {
        let code = u16::from_be_bytes([data[i], data[i + 1]]);
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let end = i + OPTION_HEADER_SIZE + len;
        if end > data.len() {
            break;
        }
        let obj_idx = buf.begin_container(
            &FD_VENDOR_OPTION,
            FieldValue::Object(0..0),
            abs + i..abs + end,
        );
        buf.push_field(
            &VENDOR_OPTION_CHILDREN[0],
            FieldValue::U16(code),
            abs + i..abs + i + 2,
        );
        buf.push_field(
            &VENDOR_OPTION_CHILDREN[1],
            FieldValue::Bytes(&data[i + OPTION_HEADER_SIZE..end]),
            abs + i + OPTION_HEADER_SIZE..abs + end,
        );
        buf.end_container(obj_idx);
        i = end;
    }
    buf.end_container(arr_idx);
}

/// Push the NTP Server suboptions (RFC 5908, Sections 4.1-4.3). The caller
/// has checked [`options_valid`].
/// <https://www.rfc-editor.org/rfc/rfc5908#section-4>
fn push_ntp_suboptions<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], abs: usize) {
    let arr_idx = buf.begin_container(
        &OPTION_CHILD_FIELDS[OFD_NTP_SUBOPTIONS],
        FieldValue::Array(0..0),
        abs..abs + data.len(),
    );
    let mut i = 0;
    while i + OPTION_HEADER_SIZE <= data.len() {
        let code = u16::from_be_bytes([data[i], data[i + 1]]);
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let end = i + OPTION_HEADER_SIZE + len;
        if end > data.len() {
            break;
        }
        let value = &data[i + OPTION_HEADER_SIZE..end];
        let value_range = abs + i + OPTION_HEADER_SIZE..abs + end;
        let obj_idx = buf.begin_container(
            &FD_NTP_SUBOPTION,
            FieldValue::Object(0..0),
            abs + i..abs + end,
        );
        buf.push_field(
            &NTP_SUBOPTION_CHILDREN[NFD_CODE],
            FieldValue::U16(code),
            abs + i..abs + i + 2,
        );
        match (code, value.len()) {
            // RFC 5908, Section 4.1 — NTP_SUBOPTION_SRV_ADDR (1), and
            // Section 4.2 — NTP_SUBOPTION_MC_ADDR (2); "suboption-len: 16."
            // <https://www.rfc-editor.org/rfc/rfc5908#section-4.1>
            // <https://www.rfc-editor.org/rfc/rfc5908#section-4.2>
            (1, 16) | (2, 16) => {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(value);
                let fd = if code == 1 {
                    NFD_SERVER_ADDRESS
                } else {
                    NFD_MULTICAST_ADDRESS
                };
                buf.push_field(
                    &NTP_SUBOPTION_CHILDREN[fd],
                    FieldValue::Ipv6Addr(addr),
                    value_range,
                );
            }
            // RFC 5908, Section 4.3 — NTP_SUBOPTION_SRV_FQDN (3).
            // <https://www.rfc-editor.org/rfc/rfc5908#section-4.3>
            (3, _) => buf.push_field(
                &NTP_SUBOPTION_CHILDREN[NFD_SERVER_FQDN],
                FieldValue::Bytes(value),
                value_range,
            ),
            _ => buf.push_field(
                &NTP_SUBOPTION_CHILDREN[NFD_DATA],
                FieldValue::Bytes(value),
                value_range,
            ),
        }
        buf.end_container(obj_idx);
        i = end;
    }
    buf.end_container(arr_idx);
}

/// Whether `data` is a non-empty sequence of param-len (2) + parameter
/// entries that exactly fills it.
///
/// RFC 5970, Section 3.2 — "param-len 1...n   This is a 16-bit integer that
/// specifies the length of the following parameter in octets (not
/// including the parameter-length field)."
/// <https://www.rfc-editor.org/rfc/rfc5970#section-3.2>
fn boot_file_parameters_valid(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            return false;
        }
        let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        i += 2 + len;
        if i > data.len() {
            return false;
        }
    }
    true
}

/// Number of octets holding an IPv6 prefix of `prefix_len` bits, or `None`
/// when `prefix_len` exceeds 128.
///
/// RFC 7598, Section 4.1 — "The field is padded on the right with zero bits
/// up to the nearest octet boundary when prefix6-len is not evenly divisible
/// by 8."
/// <https://www.rfc-editor.org/rfc/rfc7598#section-4.1>
fn ipv6_prefix_octets(prefix_len: u8) -> Option<usize> {
    (prefix_len <= 128).then(|| (prefix_len as usize).div_ceil(8))
}

/// Push `prefix6_len` and a non-empty `ipv6_prefix`.
fn push_ipv6_prefix<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    prefix_len: u8,
    prefix: &'pkt [u8],
    abs: usize,
) {
    buf.push_field(
        &OPTION_CHILD_FIELDS[OFD_PREFIX6_LEN],
        FieldValue::U8(prefix_len),
        abs..abs + 1,
    );
    if !prefix.is_empty() {
        buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_IPV6_PREFIX],
            FieldValue::Bytes(prefix),
            abs + 1..abs + 1 + prefix.len(),
        );
    }
}

/// Push a 4-octet unsigned option value.
fn push_u32_value(buf: &mut DissectBuffer<'_>, ofd: usize, value: [u8; 4], abs: usize) {
    buf.push_field(
        &OPTION_CHILD_FIELDS[ofd],
        FieldValue::U32(u32::from_be_bytes(value)),
        abs..abs + 4,
    );
}

/// Push the decoded value of a DHCPv6 option defined outside the base
/// specification's option parser (see the match in [`parse_options`]).
///
/// `abs` is the absolute offset of `data`. Returns `false`, with any partial
/// output rolled back, when the data does not match the option's format;
/// the caller then pushes the raw bytes.
fn push_extended_option_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u16,
    data: &'pkt [u8],
    abs: usize,
    depth: usize,
) -> bool {
    let mark = buf.fields().len();
    let decoded = push_extended_option_fields(buf, code, data, abs, depth);
    if !decoded {
        buf.truncate_fields(mark);
    }
    decoded
}

/// See [`push_extended_option_value`].
fn push_extended_option_fields<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u16,
    data: &'pkt [u8],
    abs: usize,
    depth: usize,
) -> bool {
    let range = abs..abs + data.len();
    match (code, data) {
        // RFC 3319, Section 3.1 — SIP Servers Domain Name List.
        // <https://www.rfc-editor.org/rfc/rfc3319#section-3.1>
        (21, _) if domain_list_is_complete(data) => {
            push_domain_list(buf, &OPTION_CHILD_FIELDS[OFD_SIP_SERVER_DOMAINS], data, abs)
        }
        // RFC 3319, Section 3.2 — SIP Servers IPv6 Address List.
        // <https://www.rfc-editor.org/rfc/rfc3319#section-3.2>
        (22, _) if !data.is_empty() && data.len() % 16 == 0 => push_ipv6_list(
            buf,
            &OPTION_CHILD_FIELDS[OFD_SIP_SERVER_ADDRESSES],
            data,
            abs,
        ),
        // RFC 4075, Section 4 — SNTP Servers.
        // <https://www.rfc-editor.org/rfc/rfc4075#section-4>
        (31, _) if !data.is_empty() && data.len() % 16 == 0 => {
            push_ipv6_list(buf, &OPTION_CHILD_FIELDS[OFD_SNTP_SERVERS], data, abs)
        }
        // RFC 9915, Section 21.23 — "option-len:  4."
        // <https://www.rfc-editor.org/rfc/rfc9915#section-21.23>
        (32, &[a, b, c, d]) => push_u32_value(buf, OFD_INFORMATION_REFRESH_TIME, [a, b, c, d], abs),
        // RFC 4649, Section 3 — enterprise-number (4), remote-id; "The
        // minimum option-len is 5 octets."
        // <https://www.rfc-editor.org/rfc/rfc4649#section-3>
        (37, &[a, b, c, d, ref remote_id @ ..]) if !remote_id.is_empty() => {
            push_u32_value(buf, OFD_ENTERPRISE_NUMBER, [a, b, c, d], abs);
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_REMOTE_ID],
                FieldValue::Bytes(remote_id),
                abs + 4..range.end,
            );
        }
        // RFC 4580, Section 2 — "The minimum length is 1 octet."
        // <https://www.rfc-editor.org/rfc/rfc4580#section-2>
        (38, _) if !data.is_empty() => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_SUBSCRIBER_ID],
            FieldValue::Bytes(data),
            range,
        ),
        // RFC 5460, Section 5.4.1 — "DUID          The DUID for the relay
        // agent."
        // <https://www.rfc-editor.org/rfc/rfc5460#section-5.4.1>
        (53, _) => {
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_RELAY_ID],
                FieldValue::Bytes(data),
                range,
            );
            push_duid(buf, data, abs);
        }
        // RFC 5908, Section 4 — "This option MUST include one, and only
        // one, time source suboption."
        // <https://www.rfc-editor.org/rfc/rfc5908#section-4>
        (56, _) if !data.is_empty() && options_valid(data) => push_ntp_suboptions(buf, data, abs),
        // RFC 5970, Section 3.1 — boot-file-url.
        // <https://www.rfc-editor.org/rfc/rfc5970#section-3.1>
        (59, _) => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_BOOT_FILE_URL],
            FieldValue::Bytes(data),
            range,
        ),
        // RFC 5970, Section 3.2 — Boot File Parameters.
        // <https://www.rfc-editor.org/rfc/rfc5970#section-3.2>
        (60, _) if boot_file_parameters_valid(data) => {
            let fd = &OPTION_CHILD_FIELDS[OFD_BOOT_FILE_PARAMETERS];
            let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), range);
            let mut i = 0;
            while i + 2 <= data.len() {
                let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                if i + 2 + len > data.len() {
                    break;
                }
                buf.push_field(
                    &FD_BOOT_FILE_PARAMETER,
                    FieldValue::Bytes(&data[i + 2..i + 2 + len]),
                    abs + i + 2..abs + i + 2 + len,
                );
                i += 2 + len;
            }
            buf.end_container(arr_idx);
        }
        // RFC 5970, Section 3.3 — "It MUST be an even number greater than
        // zero."
        // <https://www.rfc-editor.org/rfc/rfc5970#section-3.3>
        (61, _) if !data.is_empty() && data.len() % 2 == 0 => {
            let fd = &OPTION_CHILD_FIELDS[OFD_CLIENT_ARCH_TYPES];
            let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), range);
            for (n, pair) in data.chunks_exact(2).enumerate() {
                buf.push_field(
                    fd,
                    FieldValue::U16(u16::from_be_bytes([pair[0], pair[1]])),
                    abs + 2 * n..abs + 2 * n + 2,
                );
            }
            buf.end_container(arr_idx);
        }
        // RFC 6334, Section 3 — "tunnel-endpoint-name: A fully qualified
        // domain name of the AFTR tunnel endpoint."
        // <https://www.rfc-editor.org/rfc/rfc6334#section-3>
        (64, _) if !data.is_empty() => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_AFTR_NAME],
            FieldValue::Bytes(data),
            range,
        ),
        // RFC 6939, Section 4 — link-layer type (16 bits), link-layer
        // address.
        // <https://www.rfc-editor.org/rfc/rfc6939#section-4>
        (79, &[t0, t1, ref addr @ ..]) => {
            let link_type = u16::from_be_bytes([t0, t1]);
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_LINK_LAYER_TYPE],
                FieldValue::U16(link_type),
                abs..abs + 2,
            );
            push_link_layer_address(buf, link_type, addr, abs + 2);
        }
        // RFC 9915, Section 21.24 — SOL_MAX_RT, "option-len:  4."
        // <https://www.rfc-editor.org/rfc/rfc9915#section-21.24>
        (82, &[a, b, c, d]) => push_u32_value(buf, OFD_SOL_MAX_RT, [a, b, c, d], abs),
        // RFC 9915, Section 21.25 — INF_MAX_RT, "option-len:  4."
        // <https://www.rfc-editor.org/rfc/rfc9915#section-21.25>
        (83, &[a, b, c, d]) => push_u32_value(buf, OFD_INF_MAX_RT, [a, b, c, d], abs),
        // RFC 7341, Section 7.1 — "DHCPv4-message:  The DHCPv4 message sent
        // by the client or the server."
        // <https://www.rfc-editor.org/rfc/rfc7341#section-7.1>
        (OPTION_DHCPV4_MSG, _) => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_DHCPV4_MESSAGE],
            FieldValue::Bytes(data),
            range,
        ),
        // RFC 7341, Section 7.2 — "IPv6 Address:  Zero or more IPv6
        // addresses of the DHCP 4o6 server(s)."
        // <https://www.rfc-editor.org/rfc/rfc7341#section-7.2>
        (88, _) if data.len() % 16 == 0 => {
            push_ipv6_list(buf, &OPTION_CHILD_FIELDS[OFD_DHCP4O6_SERVERS], data, abs)
        }
        // RFC 7598, Section 4.1 — S46 Rule: flags, ea-len, prefix4-len,
        // ipv4-prefix, prefix6-len, ipv6-prefix, S46_RULE-options.
        // <https://www.rfc-editor.org/rfc/rfc7598#section-4.1>
        (
            89,
            &[
                flags,
                ea_len,
                prefix4_len,
                a,
                b,
                c,
                d,
                prefix6_len,
                ref tail @ ..,
            ],
        ) => {
            // RFC 7598, Section 4.1 — prefix4-len: "Allowed values range from
            // 0 to 32."
            // <https://www.rfc-editor.org/rfc/rfc7598#section-4.1>
            let Some(octets) = ipv6_prefix_octets(prefix6_len) else {
                return false;
            };
            if prefix4_len > 32 || octets > tail.len() {
                return false;
            }
            let (prefix, options) = tail.split_at(octets);
            let fixed = [
                (OFD_FLAGS, flags),
                (OFD_EA_LEN, ea_len),
                (OFD_PREFIX4_LEN, prefix4_len),
            ];
            for (i, (ofd, v)) in fixed.into_iter().enumerate() {
                buf.push_field(
                    &OPTION_CHILD_FIELDS[ofd],
                    FieldValue::U8(v),
                    abs + i..abs + i + 1,
                );
            }
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_IPV4_PREFIX],
                FieldValue::Ipv4Addr([a, b, c, d]),
                abs + 3..abs + 7,
            );
            push_ipv6_prefix(buf, prefix6_len, prefix, abs + 7);
            if !options.is_empty() {
                return push_nested_options(buf, options, abs + 8 + octets, depth);
            }
        }
        // RFC 7598, Section 4.2 — "option-length: 16"
        // <https://www.rfc-editor.org/rfc/rfc7598#section-4.2>
        (90, _) if data.len() == 16 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(data);
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_BR_ADDRESS],
                FieldValue::Ipv6Addr(addr),
                range,
            );
        }
        // RFC 7598, Section 4.3 — "option-length: 1 + length of
        // dmr-ipv6-prefix specified in octets."
        // <https://www.rfc-editor.org/rfc/rfc7598#section-4.3>
        (91, &[prefix6_len, ref prefix @ ..])
            if ipv6_prefix_octets(prefix6_len) == Some(prefix.len()) =>
        {
            push_ipv6_prefix(buf, prefix6_len, prefix, abs);
        }
        // RFC 7598, Section 4.4 — ipv4-address, bindprefix6-len,
        // bind-ipv6-prefix, S46_V4V6BIND-options.
        // <https://www.rfc-editor.org/rfc/rfc7598#section-4.4>
        (92, &[a, b, c, d, prefix6_len, ref tail @ ..]) => {
            let Some(octets) = ipv6_prefix_octets(prefix6_len) else {
                return false;
            };
            if octets > tail.len() {
                return false;
            }
            let (prefix, options) = tail.split_at(octets);
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_IPV4_ADDRESS],
                FieldValue::Ipv4Addr([a, b, c, d]),
                abs..abs + 4,
            );
            push_ipv6_prefix(buf, prefix6_len, prefix, abs + 4);
            if !options.is_empty() {
                return push_nested_options(buf, options, abs + 5 + octets, depth);
            }
        }
        // RFC 7598, Section 4.5 — offset (8 bits), PSID-len (8 bits), PSID
        // (16 bits); "option-length: 4".
        // <https://www.rfc-editor.org/rfc/rfc7598#section-4.5>
        (93, &[psid_offset, psid_len, p0, p1]) => {
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_PSID_OFFSET],
                FieldValue::U8(psid_offset),
                abs..abs + 1,
            );
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_PSID_LEN],
                FieldValue::U8(psid_len),
                abs + 1..abs + 2,
            );
            buf.push_field(
                &OPTION_CHILD_FIELDS[OFD_PSID],
                FieldValue::U16(u16::from_be_bytes([p0, p1])),
                abs + 2..abs + 4,
            );
        }
        // RFC 7598, Section 5 — OPTION_S46_CONT_MAPE (94), OPTION_S46_CONT_MAPT
        // (95) and OPTION_S46_CONT_LW (96) encapsulate other S46 options.
        // <https://www.rfc-editor.org/rfc/rfc7598#section-5>
        (94..=96, _) => return push_nested_options(buf, data, abs, depth),
        // RFC 8910, Section 2.2 — "URI:  The URI for the captive portal API
        // endpoint to which the user should connect".
        // <https://www.rfc-editor.org/rfc/rfc8910#section-2.2>
        (103, _) => buf.push_field(
            &OPTION_CHILD_FIELDS[OFD_CAPTIVE_PORTAL_URI],
            FieldValue::Bytes(data),
            range,
        ),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use packet_dissector_core::dissector::{DispatchHint, Dissector};
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;

    // # RFC 9915 (DHCPv6, obsoletes RFC 8415) Coverage
    //
    // | RFC Section | Description                              | Test                                                |
    // |-------------|------------------------------------------|-----------------------------------------------------|
    // | 7.3         | Message Type Names                       | dhcpv6_msg_type_display_fn                          |
    // | 7.6 / 19.1.2| HOP_COUNT_LIMIT (8) boundary             | parse_relay_at_hop_count_limit                      |
    // | 7.6 / 19.1.2| HOP_COUNT_LIMIT (8) exceeded             | parse_relay_max_depth_exceeded                      |
    // | 8           | Client/Server Message Format             | parse_solicit_no_options                            |
    // | 8           | Truncated client/server                  | parse_empty_data, parse_truncated_client_server     |
    // | 8           | All client/server types                  | parse_all_client_server_msg_types                   |
    // | 8           | Offset handling                          | parse_request_with_offset                           |
    // | 9           | Relay Message Format                     | parse_relay_forw, parse_relay_repl                  |
    // | 9           | Truncated relay                          | parse_relay_truncated                               |
    // | 9           | Relay with inner client/server           | parse_relay_with_inner_client_server                |
    // | 9           | Nested relay                             | parse_relay_with_nested_relay                       |
    // | 21.1        | Option Encoding                          | parse_multiple_options                              |
    // | 21.1        | Option length overflow                   | parse_option_data_exceeds_packet                    |
    // | 21.2        | Client Identifier (Option 1)             | parse_option_client_id                              |
    // | 21.3        | Server Identifier (Option 2)             | parse_option_server_id                              |
    // | 21.4        | IA_NA (Option 3)                         | parse_option_ia_na_*                                |
    // | 21.5        | IA_TA (Option 4, obsoleted by RFC 9915)  | parse_option_ia_ta_*                                |
    // | 21.6        | IA Address (Option 5)                    | parse_option_ia_addr_*                              |
    // | 21.7        | Option Request (Option 6)                | parse_option_request_*                              |
    // | 21.8        | Preference (Option 7)                    | parse_option_preference*                            |
    // | 21.9        | Elapsed Time (Option 8)                  | parse_option_elapsed_time*                          |
    // | 21.10       | Relay Message (Option 9)                 | parse_option_relay_message                          |
    // | 21.11       | Authentication (Option 11)               | parse_option_auth_*                                 |
    // | 21.12       | Server Unicast (Option 12, obsoleted)    | parse_option_server_unicast*                        |
    // | 21.13       | Status Code (Option 13)                  | parse_option_status_code*                           |
    // | 21.14       | Rapid Commit (Option 14)                 | parse_option_rapid_commit                           |
    // | 21.15       | User Class (Option 15)                   | parse_option_user_class                             |
    // | 21.16       | Vendor Class (Option 16)                 | parse_option_vendor_class_*                         |
    // | 21.17       | Vendor-specific Info (Option 17)         | parse_option_vendor_info_*                          |
    // | 21.18       | Interface-Id (Option 18)                 | parse_option_interface_id                          |
    // | 21.19       | Reconfigure Message (Option 19)          | parse_option_reconfigure_msg*                       |
    // | 21.20       | Reconfigure Accept (Option 20)           | parse_option_reconfigure_accept                     |
    // | 21.21       | IA_PD (Option 25)                        | parse_option_ia_pd_*                                |
    // | 21.22       | IA Prefix (Option 26)                    | parse_option_ia_prefix_*                            |
    // | 7.3         | Message Types 14-37 (IANA)               | dhcpv6_msg_type_names_iana_registrations            |
    // | 10, RFC 3646 §4 | Incomplete domain lists kept raw     | parse_option_domain_list_truncated_is_raw           |
    // | 11.2        | DUID-LLT                                 | parse_option_client_id_duid_llt                     |
    // | 11.3        | DUID-EN                                  | parse_option_server_id_duid_en                      |
    // | 11.4        | DUID-LL                                  | parse_option_client_id_duid_ll                      |
    // | 11.5        | DUID-UUID                                | parse_option_client_id_duid_uuid                    |
    // | 11          | Unknown / malformed DUID stays raw       | parse_option_client_id_duid_unknown_or_malformed    |
    // | 21.1        | Encapsulation depth bounded              | parse_deeply_nested_options_bounded                 |
    // | 21.17       | Vendor-specific suboptions               | parse_option_vendor_info_suboptions                 |
    // | 21.23       | Information Refresh Time (Option 32)     | parse_option_information_refresh_time               |
    // | 21.24/21.25 | SOL_MAX_RT / INF_MAX_RT (Options 82, 83) | parse_option_sol_and_inf_max_rt                     |
    // | 21.23-21.25 | Wrong length stays raw                   | parse_option_u32_bad_length_raw                     |
    // | 24          | Option names (IANA)                      | dhcpv6_option_names_iana_registrations              |
    //
    // # Other DHCPv6 Option / Message RFC Coverage
    //
    // | RFC / Section | Description                            | Test                                              |
    // |---------------|----------------------------------------|---------------------------------------------------|
    // | 6355 §4       | DUID-UUID                              | parse_option_client_id_duid_uuid                  |
    // | 3319 §3.1     | SIP Server Domain Name List (21)       | parse_option_sip_server_domains                   |
    // | 3319 §3.2     | SIP Server IPv6 Address List (22)      | parse_option_sip_server_addresses                 |
    // | 4075 §4       | SNTP Servers (31)                      | parse_option_sntp_servers                         |
    // | 3319/4075/7341| Address list, bad length -> raw        | parse_option_address_list_bad_length_raw          |
    // | 4649 §3       | Relay Agent Remote-ID (37)             | parse_option_remote_id                            |
    // | 4649 §3       | Remote-ID below 5 octets -> raw        | parse_option_remote_id_short_raw                  |
    // | 4580 §2       | Relay Agent Subscriber-ID (38)         | parse_option_subscriber_id                        |
    // | 4704 §4.2     | Client FQDN domain name decoded (39)   | parse_option_client_fqdn_domain_name_decoded      |
    // | 5460 §5.4.1   | Relay-ID DUID (53)                     | parse_option_relay_id_duid                        |
    // | 5908 §4.1-4.3 | NTP Server suboptions (56)             | parse_option_ntp_server                           |
    // | 5908 §4       | Unknown / malformed NTP suboptions     | parse_option_ntp_server_unknown_and_malformed     |
    // | 5970 §3.1     | Boot File URL (59)                     | parse_option_boot_file_url                        |
    // | 5970 §3.2     | Boot File Parameters (60)              | parse_option_boot_file_parameters                 |
    // | 5970 §3.3     | Client Arch Type (61)                  | parse_option_client_arch_type                     |
    // | 6334 §3       | AFTR-Name (64)                         | parse_option_aftr_name                            |
    // | 6939 §4       | Client Link-Layer Address (79)         | parse_option_client_link_layer_address            |
    // | 7341 §6.2/6.3 | DHCPV4-QUERY flags + option 87 dispatch| parse_dhcpv4_query_message                        |
    // | 7341 §6.4     | DHCPV4-RESPONSE                        | parse_dhcpv4_response_message                     |
    // | 7341 §6.2     | No option 87 / truncated               | parse_dhcpv4_query_without_message_and_truncated  |
    // | 7341 §6.2     | Option 87 outside 4o6 not dispatched   | parse_dhcpv4_message_option_in_other_message_not_dispatched |
    // | 7341 §10      | Relayed DHCPV4-QUERY dispatch          | parse_relay_forw_with_dhcpv4_query                |
    // | 7341 §7.2     | DHCP 4o6 Server Address (88)           | parse_option_dhcp4o6_server_address               |
    // | 7598 §4.1/4.5 | S46 Rule (89) + Port Parameters (93)   | parse_option_s46_rule_with_port_params            |
    // | 7598 §4.1     | Malformed S46 Rule -> raw              | parse_option_s46_rule_malformed_raw               |
    // | 7598 §4.2/4.3 | S46 BR (90), S46 DMR (91)              | parse_option_s46_br_and_dmr                       |
    // | 7598 §4.4     | S46 IPv4/IPv6 Address Binding (92)     | parse_option_s46_v4v6bind                         |
    // | 7598 §5       | S46 containers (94-96)                 | parse_option_s46_containers                       |
    // | 8910 §2.2     | Captive-Portal (103)                   | parse_option_captive_portal                       |
    // | (all above)   | Value types match descriptors          | new_option_value_types_match_descriptors          |
    //
    // # RFC 3646 Coverage
    //
    // | RFC Section | Description                              | Test                                           |
    // |-------------|------------------------------------------|-------------------------------------------------|
    // | 3           | DNS Recursive Name Server (Option 23)    | parse_option_dns_servers*                        |
    // | 4           | Domain Search List (Option 24)           | parse_option_domain_search_*                     |
    //
    // # RFC 4704 Coverage
    //
    // | RFC Section | Description                              | Test                                           |
    // |-------------|------------------------------------------|-------------------------------------------------|
    // | 4           | Client FQDN (Option 39)                  | parse_option_client_fqdn*                        |

    // ── Helpers ──────────────────────────────────────────────────────

    /// Build a DHCPv6 client/server message: msg_type(1) + transaction_id(3) + options.
    fn build_dhcpv6(msg_type: u8, txid: u32, options: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(4 + options.len());
        pkt.push(msg_type);
        // transaction-id is 3 bytes (big-endian, lower 24 bits of txid)
        pkt.push((txid >> 16) as u8);
        pkt.push((txid >> 8) as u8);
        pkt.push(txid as u8);
        pkt.extend_from_slice(options);
        pkt
    }

    /// Encode a DHCPv6 option: code(2) + length(2) + data.
    fn dhcpv6_option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut opt = Vec::with_capacity(4 + data.len());
        opt.extend_from_slice(&code.to_be_bytes());
        opt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        opt.extend_from_slice(data);
        opt
    }

    /// Build a DHCPv6 relay message: msg_type(1) + hop_count(1) + link_addr(16) + peer_addr(16) + options.
    fn build_relay(
        msg_type: u8,
        hop_count: u8,
        link_addr: [u8; 16],
        peer_addr: [u8; 16],
        options: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(34 + options.len());
        pkt.push(msg_type);
        pkt.push(hop_count);
        pkt.extend_from_slice(&link_addr);
        pkt.extend_from_slice(&peer_addr);
        pkt.extend_from_slice(options);
        pkt
    }

    /// Find the first option object matching `code` in the options array.
    /// Returns the nested fields of that option object.
    fn find_option_fields<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &'a packet_dissector_core::packet::Layer,
        code: u16,
    ) -> &'a [packet_dissector_core::field::Field<'pkt>] {
        let options = buf.field_by_name(layer, "options").unwrap();
        let opts_range = options.value.as_container_range().unwrap();
        let opt_objects = buf.nested_fields(opts_range);
        for obj in opt_objects {
            let inner_range = obj.value.as_container_range().unwrap();
            let inner_fields = buf.nested_fields(inner_range);
            if let Some(code_field) = inner_fields.iter().find(|f| f.name() == "code") {
                if code_field.value == FieldValue::U16(code) {
                    return inner_fields;
                }
            }
        }
        panic!("option with code {code} not found");
    }

    /// Check whether an option with the given code exists.
    fn has_option(
        buf: &DissectBuffer<'_>,
        layer: &packet_dissector_core::packet::Layer,
        code: u16,
    ) -> bool {
        let options = buf.field_by_name(layer, "options").unwrap();
        let opts_range = options.value.as_container_range().unwrap();
        let opt_objects = buf.nested_fields(opts_range);
        for obj in opt_objects {
            if let Some(inner_range) = obj.value.as_container_range() {
                let inner_fields = buf.nested_fields(inner_range);
                if let Some(code_field) = inner_fields.iter().find(|f| f.name() == "code") {
                    if code_field.value == FieldValue::U16(code) {
                        return true;
                    }
                }
            }
        }
        false
    }

    // ── Group 1: Metadata ────────────────────────────────────────────

    #[test]
    fn dhcpv6_dissector_metadata() {
        let d = Dhcpv6Dissector;
        assert_eq!(d.name(), "Dynamic Host Configuration Protocol for IPv6");
        assert_eq!(d.short_name(), "DHCPv6");
        assert_eq!(d.field_descriptors().len(), FIELD_DESCRIPTORS.len());
    }

    #[test]
    fn dhcpv6_msg_type_display_fn() {
        let display_fn = FIELD_DESCRIPTORS[FD_MSG_TYPE].display_fn.unwrap();
        let siblings: &[packet_dissector_core::field::Field<'_>] = &[];

        // All 13 named types
        assert_eq!(display_fn(&FieldValue::U8(1), siblings), Some("SOLICIT"));
        assert_eq!(display_fn(&FieldValue::U8(2), siblings), Some("ADVERTISE"));
        assert_eq!(display_fn(&FieldValue::U8(3), siblings), Some("REQUEST"));
        assert_eq!(display_fn(&FieldValue::U8(4), siblings), Some("CONFIRM"));
        assert_eq!(display_fn(&FieldValue::U8(5), siblings), Some("RENEW"));
        assert_eq!(display_fn(&FieldValue::U8(6), siblings), Some("REBIND"));
        assert_eq!(display_fn(&FieldValue::U8(7), siblings), Some("REPLY"));
        assert_eq!(display_fn(&FieldValue::U8(8), siblings), Some("RELEASE"));
        assert_eq!(display_fn(&FieldValue::U8(9), siblings), Some("DECLINE"));
        assert_eq!(
            display_fn(&FieldValue::U8(10), siblings),
            Some("RECONFIGURE")
        );
        assert_eq!(
            display_fn(&FieldValue::U8(11), siblings),
            Some("INFORMATION_REQUEST")
        );
        assert_eq!(
            display_fn(&FieldValue::U8(12), siblings),
            Some("RELAY_FORW")
        );
        assert_eq!(
            display_fn(&FieldValue::U8(13), siblings),
            Some("RELAY_REPL")
        );
        // Unknown type
        assert_eq!(display_fn(&FieldValue::U8(255), siblings), None);
        // Non-U8 variant
        assert_eq!(display_fn(&FieldValue::U16(1), siblings), None);
    }

    // ── Group 2: Header parsing ──────────────────────────────────────

    #[test]
    fn parse_empty_data() {
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&[], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn parse_truncated_client_server() {
        let d = Dhcpv6Dissector;
        let data = [1u8, 0, 0]; // 3 bytes, needs 4
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_solicit_no_options() {
        let pkt = build_dhcpv6(1, 0xABCDEF, &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let result = d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "DHCPv6");

        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "transaction_id").unwrap().value,
            FieldValue::U32(0xABCDEF)
        );
    }

    #[test]
    fn parse_request_with_offset() {
        let pkt = build_dhcpv6(3, 0x123456, &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let offset = 42;
        d.dissect(&pkt, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range.start, 42);
        assert_eq!(layer.range.end, 42 + 4);
        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().range.start,
            42
        );
        assert_eq!(
            buf.field_by_name(layer, "transaction_id")
                .unwrap()
                .range
                .start,
            43
        );
    }

    #[test]
    fn parse_all_client_server_msg_types() {
        let d = Dhcpv6Dissector;
        for msg_type in 1..=11u8 {
            let pkt = build_dhcpv6(msg_type, 1, &[]);
            let mut buf = DissectBuffer::new();
            let result = d.dissect(&pkt, &mut buf, 0).unwrap();
            assert_eq!(result.next, DispatchHint::End);
            assert_eq!(
                buf.field_by_name(&buf.layers()[0], "msg_type")
                    .unwrap()
                    .value,
                FieldValue::U8(msg_type)
            );
        }
    }

    // ── Group 3: Relay messages ──────────────────────────────────────

    #[test]
    fn parse_relay_forw() {
        let link: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let peer: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let pkt = build_relay(12, 0, link, peer, &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let result = d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "msg_type").unwrap().value,
            FieldValue::U8(12)
        );
        assert_eq!(
            buf.field_by_name(layer, "hop_count").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "link_address").unwrap().value,
            FieldValue::Ipv6Addr(link)
        );
        assert_eq!(
            buf.field_by_name(layer, "peer_address").unwrap().value,
            FieldValue::Ipv6Addr(peer)
        );
    }

    #[test]
    fn parse_relay_repl() {
        let pkt = build_relay(13, 5, [0; 16], [0; 16], &[]);
        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(13)
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "hop_count")
                .unwrap()
                .value,
            FieldValue::U8(5)
        );
    }

    #[test]
    fn parse_relay_truncated() {
        let d = Dhcpv6Dissector;
        // msg_type=12 but only 33 bytes (needs 34)
        let data = [12u8; 33];
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 34,
                actual: 33
            }
        ));
    }

    #[test]
    fn parse_relay_with_inner_client_server() {
        // Build inner SOLICIT message
        let inner = build_dhcpv6(1, 0x111111, &[]);
        let relay_opt = dhcpv6_option(9, &inner);
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &relay_opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Should produce 2 layers: relay + inner client/server
        assert_eq!(buf.layers().len(), 2);
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(12)
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[1], "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_relay_with_nested_relay() {
        // Inner relay containing a SOLICIT
        let solicit = build_dhcpv6(1, 0x222222, &[]);
        let inner_relay_opt = dhcpv6_option(9, &solicit);
        let inner_relay = build_relay(12, 1, [0; 16], [0; 16], &inner_relay_opt);
        let outer_relay_opt = dhcpv6_option(9, &inner_relay);
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &outer_relay_opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // 3 layers: outer relay + inner relay + SOLICIT
        assert_eq!(buf.layers().len(), 3);
    }

    #[test]
    fn parse_relay_at_hop_count_limit() {
        // RFC 9915, Section 7.6 — HOP_COUNT_LIMIT = 8.
        // Build exactly HOP_COUNT_LIMIT (8) nested relays around a client/server
        // message; all should be dissected. Layers = 8 relays + 1 client/server = 9.
        let inner = build_dhcpv6(1, 1, &[]);
        let mut current = inner;
        for i in 0..MAX_RELAY_DEPTH {
            let opt = dhcpv6_option(9, &current);
            current = build_relay(12, i as u8, [0; 16], [0; 16], &opt);
        }

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&current, &mut buf, 0).unwrap();
        assert_eq!(buf.layers().len(), MAX_RELAY_DEPTH + 1);
    }

    #[test]
    fn parse_relay_max_depth_exceeded() {
        // RFC 9915, Section 7.6 / Section 19.1.2 — HOP_COUNT_LIMIT = 8.
        // Build HOP_COUNT_LIMIT + 1 (9) nested relays: the innermost relay is at
        // depth=8 which hits MAX_RELAY_DEPTH and is rejected. Only the outer 8
        // relay layers should be produced (client/server never reached).
        let inner = build_dhcpv6(1, 1, &[]);
        let mut current = inner;
        for i in 0..=MAX_RELAY_DEPTH {
            let opt = dhcpv6_option(9, &current);
            current = build_relay(12, i as u8, [0; 16], [0; 16], &opt);
        }

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        // The outermost relay dissect succeeds, but deep nesting triggers the error
        // which is silently ignored (let _ = parse_inner_message).
        d.dissect(&current, &mut buf, 0).unwrap();
        assert_eq!(buf.layers().len(), MAX_RELAY_DEPTH);
    }

    #[test]
    fn parse_inner_message_empty() {
        // Relay with an empty Relay Message option (9) — inner parse fails silently
        let relay_opt = dhcpv6_option(9, &[]);
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &relay_opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Only 1 layer (relay), no inner layer created
        assert_eq!(buf.layers().len(), 1);
    }

    // ── Group 4: Option 1 — Client Identifier ────────────────────────

    #[test]
    fn parse_option_client_id() {
        let duid = [0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        let opt = dhcpv6_option(1, &duid);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 1);
        let client_id = fields.iter().find(|f| f.name() == "client_id").unwrap();
        assert_eq!(client_id.value, FieldValue::Bytes(&duid));
    }

    #[test]
    fn option_container_resolves_to_option_name() {
        // Option 1 (Client Identifier): the outer container label should
        // resolve to "Client Identifier" rather than duplicating "Option Code".
        let duid = [0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        let opt = dhcpv6_option(1, &duid);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "dhcpv6_option")
            .expect("DHCPv6 option container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "DHCPv6 Option");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("Client Identifier")
        );
    }

    // ── Group 5: Option 2 — Server Identifier ────────────────────────

    #[test]
    fn parse_option_server_id() {
        let duid = [0x00, 0x02, 0x11, 0x22, 0x33, 0x44];
        let opt = dhcpv6_option(2, &duid);
        let pkt = build_dhcpv6(2, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 2);
        let server_id = fields.iter().find(|f| f.name() == "server_id").unwrap();
        assert_eq!(server_id.value, FieldValue::Bytes(&duid));
    }

    // ── Group 6: Option 3 — IA_NA ────────────────────────────────────

    #[test]
    fn parse_option_ia_na_full() {
        // IAID(4) + T1(4) + T2(4) = 12 bytes
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // IAID = 1
        data.extend_from_slice(&3600u32.to_be_bytes()); // T1 = 3600
        data.extend_from_slice(&5400u32.to_be_bytes()); // T2 = 5400
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        assert_eq!(
            fields.iter().find(|f| f.name() == "iaid").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t1").unwrap().value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t2").unwrap().value,
            FieldValue::U32(5400)
        );
    }

    #[test]
    fn parse_option_ia_na_exact_12() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&1u32.to_be_bytes());
        data[4..8].copy_from_slice(&100u32.to_be_bytes());
        data[8..12].copy_from_slice(&200u32.to_be_bytes());
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        // Should have iaid, t1, t2 but no sub-options
        assert!(fields.iter().any(|f| f.name() == "iaid"));
        assert!(!fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_na_with_suboptions() {
        // IA_NA with IA Address sub-option
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut ia_addr_data = Vec::new();
        ia_addr_data.extend_from_slice(&addr);
        ia_addr_data.extend_from_slice(&7200u32.to_be_bytes()); // preferred
        ia_addr_data.extend_from_slice(&7500u32.to_be_bytes()); // valid
        let sub_opt = dhcpv6_option(5, &ia_addr_data);

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // IAID
        data.extend_from_slice(&3600u32.to_be_bytes()); // T1
        data.extend_from_slice(&5400u32.to_be_bytes()); // T2
        data.extend_from_slice(&sub_opt);
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_na_short() {
        // Less than 12 bytes → falls back to ia_na raw bytes
        let data = [0u8; 8];
        let opt = dhcpv6_option(3, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 3);
        assert!(fields.iter().any(|f| f.name() == "ia_na"));
    }

    // ── Group 7: Option 4 — IA_TA ────────────────────────────────────

    #[test]
    fn parse_option_ia_ta_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_be_bytes()); // IAID
        let opt = dhcpv6_option(4, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 4);
        assert_eq!(
            fields.iter().find(|f| f.name() == "iaid").unwrap().value,
            FieldValue::U32(42)
        );
    }

    #[test]
    fn parse_option_ia_ta_with_suboptions() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // IAID
        // Add a sub-option (IA Address)
        let mut ia_addr_data = vec![0u8; 24];
        ia_addr_data[0..16]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ia_addr_data[16..20].copy_from_slice(&100u32.to_be_bytes());
        ia_addr_data[20..24].copy_from_slice(&200u32.to_be_bytes());
        data.extend_from_slice(&dhcpv6_option(5, &ia_addr_data));
        let opt = dhcpv6_option(4, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 4);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_ta_short() {
        let data = [0u8; 2]; // < 4 bytes
        let opt = dhcpv6_option(4, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 4);
        assert!(fields.iter().any(|f| f.name() == "ia_ta"));
    }

    // ── Group 8: Option 5 — IA Address ───────────────────────────────

    #[test]
    fn parse_option_ia_addr_full() {
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut data = Vec::new();
        data.extend_from_slice(&addr);
        data.extend_from_slice(&3600u32.to_be_bytes()); // preferred
        data.extend_from_slice(&7200u32.to_be_bytes()); // valid

        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert_eq!(
            fields.iter().find(|f| f.name() == "address").unwrap().value,
            FieldValue::Ipv6Addr(addr)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "preferred_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "valid_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(7200)
        );
    }

    #[test]
    fn parse_option_ia_addr_exact_24() {
        let mut data = vec![0u8; 24];
        data[0..16].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[16..20].copy_from_slice(&100u32.to_be_bytes());
        data[20..24].copy_from_slice(&200u32.to_be_bytes());
        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert!(fields.iter().any(|f| f.name() == "address"));
        assert!(!fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_addr_with_suboptions() {
        let mut data = vec![0u8; 24];
        data[0..16].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[16..20].copy_from_slice(&100u32.to_be_bytes());
        data[20..24].copy_from_slice(&200u32.to_be_bytes());
        // Status code sub-option
        let mut status_data = Vec::new();
        status_data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&dhcpv6_option(13, &status_data));
        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_addr_short() {
        let data = [0u8; 16]; // < 24 bytes
        let opt = dhcpv6_option(5, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 5);
        assert!(fields.iter().any(|f| f.name() == "ia_addr"));
    }

    // ── Group 9: Option 6 — Option Request ───────────────────────────

    #[test]
    fn parse_option_request_list() {
        let mut data = Vec::new();
        data.extend_from_slice(&23u16.to_be_bytes()); // DNS
        data.extend_from_slice(&24u16.to_be_bytes()); // Domain search
        data.extend_from_slice(&39u16.to_be_bytes()); // Client FQDN
        let opt = dhcpv6_option(6, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 6);
        let req_opts = fields
            .iter()
            .find(|f| f.name() == "requested_options")
            .unwrap();
        let range = req_opts.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, FieldValue::U16(23));
        assert_eq!(items[1].value, FieldValue::U16(24));
        assert_eq!(items[2].value, FieldValue::U16(39));
    }

    #[test]
    fn parse_option_request_empty() {
        let opt = dhcpv6_option(6, &[]);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 6);
        let req_opts = fields
            .iter()
            .find(|f| f.name() == "requested_options")
            .unwrap();
        let range = req_opts.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 0);
    }

    // ── Group 10: Option 7 — Preference ──────────────────────────────

    #[test]
    fn parse_option_preference() {
        let opt = dhcpv6_option(7, &[255]);
        let pkt = build_dhcpv6(2, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 7);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "preference")
                .unwrap()
                .value,
            FieldValue::U8(255)
        );
    }

    #[test]
    fn parse_option_preference_empty() {
        // Empty preference data — skipped entirely (no container created for code 7)
        let opt = dhcpv6_option(7, &[]);
        let pkt = build_dhcpv6(2, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Option 7 is skipped when data is empty
        assert!(!has_option(&buf, &buf.layers()[0], 7));
    }

    // ── Group 11: Option 8 — Elapsed Time ────────────────────────────

    #[test]
    fn parse_option_elapsed_time() {
        let opt = dhcpv6_option(8, &100u16.to_be_bytes());
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 8);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "elapsed_time")
                .unwrap()
                .value,
            FieldValue::U16(100)
        );
    }

    #[test]
    fn parse_option_elapsed_time_short() {
        let opt = dhcpv6_option(8, &[0x01]); // only 1 byte, needs 2
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Skipped: no option object for code 8
        assert!(!has_option(&buf, &buf.layers()[0], 8));
    }

    // ── Group 12: Option 9 — Relay Message ───────────────────────────

    #[test]
    fn parse_option_relay_message() {
        let inner = build_dhcpv6(1, 0x123456, &[]);
        let opt = dhcpv6_option(9, &inner);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 9);
        let relay_msg = fields.iter().find(|f| f.name() == "relay_message").unwrap();
        assert_eq!(relay_msg.value, FieldValue::Bytes(inner.as_slice()));

        // Inner message is also parsed as a second layer
        assert_eq!(buf.layers().len(), 2);
    }

    // ── Group 13: Option 11 — Authentication ─────────────────────────

    #[test]
    fn parse_option_auth_full() {
        // protocol(1) + algorithm(1) + rdm(1) + replay_detection(8) = 11 bytes
        let data: [u8; 11] = [3, 1, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let opt = dhcpv6_option(11, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 11);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "protocol")
                .unwrap()
                .value,
            FieldValue::U8(3)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "algorithm")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "rdm").unwrap().value,
            FieldValue::U8(0)
        );
        let replay = fields
            .iter()
            .find(|f| f.name() == "replay_detection")
            .unwrap();
        assert_eq!(
            replay.value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
        // No information field when exactly 11 bytes
        assert!(!fields.iter().any(|f| f.name() == "information"));
    }

    #[test]
    fn parse_option_auth_with_info() {
        let mut data = vec![3u8, 1, 0];
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // auth info
        let opt = dhcpv6_option(11, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 11);
        let info = fields.iter().find(|f| f.name() == "information").unwrap();
        assert_eq!(info.value, FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn parse_option_auth_short() {
        let data = [0u8; 5]; // < 11 bytes
        let opt = dhcpv6_option(11, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 11);
        assert!(fields.iter().any(|f| f.name() == "authentication"));
    }

    // ── Group 14: Option 12 — Server Unicast ─────────────────────────

    #[test]
    fn parse_option_server_unicast() {
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let opt = dhcpv6_option(12, &addr);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 12);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "server_unicast")
                .unwrap()
                .value,
            FieldValue::Ipv6Addr(addr)
        );
    }

    #[test]
    fn parse_option_server_unicast_short() {
        let data = [0u8; 8]; // < 16 bytes
        let opt = dhcpv6_option(12, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Skipped: option 12 needs 16 bytes
        assert!(!has_option(&buf, &buf.layers()[0], 12));
    }

    // ── Group 15: Option 13 — Status Code ────────────────────────────

    #[test]
    fn parse_option_status_code() {
        let opt = dhcpv6_option(13, &0u16.to_be_bytes()); // Success
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 13);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "status_code")
                .unwrap()
                .value,
            FieldValue::U16(0)
        );
        assert!(!fields.iter().any(|f| f.name() == "status_message"));
    }

    #[test]
    fn parse_option_status_code_with_message() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(b"Success");
        let opt = dhcpv6_option(13, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 13);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "status_message")
                .unwrap()
                .value,
            FieldValue::Bytes(b"Success")
        );
    }

    #[test]
    fn parse_option_status_code_short() {
        let opt = dhcpv6_option(13, &[0x00]); // only 1 byte, needs 2
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(!has_option(&buf, &buf.layers()[0], 13));
    }

    // ── Group 16: Option 14 — Rapid Commit ───────────────────────────

    #[test]
    fn parse_option_rapid_commit() {
        let opt = dhcpv6_option(14, &[]);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 14);
        assert_eq!(
            fields.iter().find(|f| f.name() == "code").unwrap().value,
            FieldValue::U16(14)
        );
        // Only code, no other fields
        assert_eq!(fields.len(), 1);
    }

    // ── Group 17: Option 15 — User Class ─────────────────────────────

    #[test]
    fn parse_option_user_class() {
        let data = [0x00, 0x04, 0x74, 0x65, 0x73, 0x74]; // len=4 + "test"
        let opt = dhcpv6_option(15, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 15);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "user_class")
                .unwrap()
                .value,
            FieldValue::Bytes(&data)
        );
    }

    // ── Group 18: Option 16 — Vendor Class ───────────────────────────

    #[test]
    fn parse_option_vendor_class_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&9u32.to_be_bytes()); // enterprise number = 9
        let opt = dhcpv6_option(16, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 16);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "enterprise_number")
                .unwrap()
                .value,
            FieldValue::U32(9)
        );
        assert!(!fields.iter().any(|f| f.name() == "data"));
    }

    #[test]
    fn parse_option_vendor_class_with_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&9u32.to_be_bytes());
        data.extend_from_slice(b"class_data");
        let opt = dhcpv6_option(16, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 16);
        assert_eq!(
            fields.iter().find(|f| f.name() == "data").unwrap().value,
            FieldValue::Bytes(b"class_data")
        );
    }

    #[test]
    fn parse_option_vendor_class_short() {
        let data = [0u8; 2]; // < 4 bytes
        let opt = dhcpv6_option(16, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 16);
        assert!(fields.iter().any(|f| f.name() == "vendor_class"));
    }

    // ── Group 19: Option 17 — Vendor-specific Info ───────────────────

    #[test]
    fn parse_option_vendor_info_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&311u32.to_be_bytes());
        let opt = dhcpv6_option(17, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 17);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "enterprise_number")
                .unwrap()
                .value,
            FieldValue::U32(311)
        );
    }

    #[test]
    fn parse_option_vendor_info_with_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&311u32.to_be_bytes());
        data.extend_from_slice(b"vendor_data");
        let opt = dhcpv6_option(17, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 17);
        assert_eq!(
            fields.iter().find(|f| f.name() == "data").unwrap().value,
            FieldValue::Bytes(b"vendor_data")
        );
    }

    #[test]
    fn parse_option_vendor_info_short() {
        let data = [0u8; 3]; // < 4 bytes
        let opt = dhcpv6_option(17, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 17);
        assert!(fields.iter().any(|f| f.name() == "vendor_info"));
    }

    // ── Group 20: Option 18 — Interface-Id ───────────────────────────

    #[test]
    fn parse_option_interface_id() {
        let data = b"eth0";
        let opt = dhcpv6_option(18, data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 18);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "interface_id")
                .unwrap()
                .value,
            FieldValue::Bytes(b"eth0")
        );
    }

    // ── Group 21: Option 19 — Reconfigure Message ────────────────────

    #[test]
    fn parse_option_reconfigure_msg() {
        let opt = dhcpv6_option(19, &[5]); // msg_type = RENEW
        let pkt = build_dhcpv6(10, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 19);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "msg_type")
                .unwrap()
                .value,
            FieldValue::U8(5)
        );
    }

    #[test]
    fn parse_option_reconfigure_msg_empty() {
        let opt = dhcpv6_option(19, &[]);
        let pkt = build_dhcpv6(10, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(!has_option(&buf, &buf.layers()[0], 19));
    }

    // ── Group 22: Option 20 — Reconfigure Accept ─────────────────────

    #[test]
    fn parse_option_reconfigure_accept() {
        let opt = dhcpv6_option(20, &[]);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 20);
        assert_eq!(fields.len(), 1);
        assert_eq!(
            fields.iter().find(|f| f.name() == "code").unwrap().value,
            FieldValue::U16(20)
        );
    }

    // ── Group 23: Option 23 — DNS Recursive Name Servers ─────────────

    #[test]
    fn parse_option_dns_servers() {
        let addr1: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        let addr2: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&addr1);
        data.extend_from_slice(&addr2);
        let opt = dhcpv6_option(23, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 23);
        let dns = fields.iter().find(|f| f.name() == "dns_servers").unwrap();
        let range = dns.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].value, FieldValue::Ipv6Addr(addr1));
        assert_eq!(items[1].value, FieldValue::Ipv6Addr(addr2));
    }

    #[test]
    fn parse_option_dns_servers_empty() {
        let opt = dhcpv6_option(23, &[]);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 23);
        let dns = fields.iter().find(|f| f.name() == "dns_servers").unwrap();
        let range = dns.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 0);
    }

    // ── Group 24: Option 24 — Domain Search List ─────────────────────

    #[test]
    fn parse_option_domain_search_single() {
        // DNS-encoded: \x07example\x03com\x00
        let data = b"\x07example\x03com\x00";
        let opt = dhcpv6_option(24, data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        let items = buf.nested_fields(range);
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn parse_option_domain_search_multiple() {
        // Two DNS-encoded domains
        let mut data = Vec::new();
        data.extend_from_slice(b"\x07example\x03com\x00");
        data.extend_from_slice(b"\x04test\x03org\x00");
        let opt = dhcpv6_option(24, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 2);
    }

    #[test]
    fn parse_option_domain_search_compression_pointer() {
        // Domain with compression pointer: 0xC0 0x00
        let data = [0x03, b'f', b'o', b'o', 0xC0, 0x00];
        let opt = dhcpv6_option(24, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 1);
    }

    #[test]
    fn parse_option_domain_search_empty_label_only() {
        // Root label only — no real labels, has_labels is false
        let data = [0x00];
        let opt = dhcpv6_option(24, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 24);
        let search = fields.iter().find(|f| f.name() == "domain_search").unwrap();
        let range = search.value.as_container_range().unwrap();
        assert_eq!(buf.nested_fields(range).len(), 0);
    }

    // ── Group 25: Option 25 — IA_PD ──────────────────────────────────

    #[test]
    fn parse_option_ia_pd_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_be_bytes()); // IAID
        data.extend_from_slice(&1800u32.to_be_bytes()); // T1
        data.extend_from_slice(&2700u32.to_be_bytes()); // T2
        let opt = dhcpv6_option(25, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 25);
        assert_eq!(
            fields.iter().find(|f| f.name() == "iaid").unwrap().value,
            FieldValue::U32(10)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t1").unwrap().value,
            FieldValue::U32(1800)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "t2").unwrap().value,
            FieldValue::U32(2700)
        );
    }

    #[test]
    fn parse_option_ia_pd_with_suboptions() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(&1800u32.to_be_bytes());
        data.extend_from_slice(&2700u32.to_be_bytes());
        // IA Prefix sub-option
        let mut prefix_data = Vec::new();
        prefix_data.extend_from_slice(&3600u32.to_be_bytes()); // preferred lifetime
        prefix_data.extend_from_slice(&7200u32.to_be_bytes()); // valid lifetime
        prefix_data.push(48); // prefix length
        prefix_data
            .extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        data.extend_from_slice(&dhcpv6_option(26, &prefix_data));
        let opt = dhcpv6_option(25, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 25);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_pd_short() {
        let data = [0u8; 8]; // < 12 bytes
        let opt = dhcpv6_option(25, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 25);
        assert!(fields.iter().any(|f| f.name() == "ia_pd"));
    }

    // ── Group 26: Option 26 — IA Prefix ──────────────────────────────

    #[test]
    fn parse_option_ia_prefix_full() {
        let prefix_addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut data = Vec::new();
        data.extend_from_slice(&3600u32.to_be_bytes()); // preferred lifetime
        data.extend_from_slice(&7200u32.to_be_bytes()); // valid lifetime
        data.push(48); // prefix length
        data.extend_from_slice(&prefix_addr);
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "preferred_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "valid_lifetime")
                .unwrap()
                .value,
            FieldValue::U32(7200)
        );
        assert_eq!(
            fields
                .iter()
                .find(|f| f.name() == "prefix_length")
                .unwrap()
                .value,
            FieldValue::U8(48)
        );
        assert_eq!(
            fields.iter().find(|f| f.name() == "prefix").unwrap().value,
            FieldValue::Ipv6Addr(prefix_addr)
        );
    }

    #[test]
    fn parse_option_ia_prefix_exact_25() {
        let mut data = vec![0u8; 25];
        data[0..4].copy_from_slice(&100u32.to_be_bytes());
        data[4..8].copy_from_slice(&200u32.to_be_bytes());
        data[8] = 64;
        // prefix at 9..25 already zeroed
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert!(fields.iter().any(|f| f.name() == "prefix"));
        assert!(!fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_prefix_with_suboptions() {
        let mut data = vec![0u8; 25];
        data[0..4].copy_from_slice(&100u32.to_be_bytes());
        data[4..8].copy_from_slice(&200u32.to_be_bytes());
        data[8] = 48;
        // Add status code sub-option
        let mut status_data = Vec::new();
        status_data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&dhcpv6_option(13, &status_data));
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert!(fields.iter().any(|f| f.name() == "options"));
    }

    #[test]
    fn parse_option_ia_prefix_short() {
        let data = [0u8; 20]; // < 25 bytes
        let opt = dhcpv6_option(26, &data);
        let pkt = build_dhcpv6(7, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 26);
        assert!(fields.iter().any(|f| f.name() == "ia_prefix"));
    }

    // ── Group 27: Option 39 — Client FQDN ────────────────────────────

    #[test]
    fn parse_option_client_fqdn() {
        let mut data = Vec::new();
        data.push(0x01); // flags
        data.extend_from_slice(b"\x06client\x07example\x03com\x00");
        let opt = dhcpv6_option(39, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 39);
        assert_eq!(
            fields.iter().find(|f| f.name() == "flags").unwrap().value,
            FieldValue::U8(0x01)
        );
        assert!(fields.iter().any(|f| f.name() == "fqdn"));
    }

    #[test]
    fn parse_option_client_fqdn_flags_only() {
        let data = [0x00]; // flags only, no domain
        let opt = dhcpv6_option(39, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 39);
        assert!(fields.iter().any(|f| f.name() == "flags"));
        assert!(!fields.iter().any(|f| f.name() == "fqdn"));
    }

    #[test]
    fn parse_option_client_fqdn_empty() {
        let opt = dhcpv6_option(39, &[]);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(!has_option(&buf, &buf.layers()[0], 39));
    }

    // ── Group 28: Unknown Option ─────────────────────────────────────

    #[test]
    fn parse_option_unknown() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let opt = dhcpv6_option(999, &data);
        let pkt = build_dhcpv6(1, 1, &opt);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let fields = find_option_fields(&buf, &buf.layers()[0], 999);
        assert_eq!(
            fields.iter().find(|f| f.name() == "data").unwrap().value,
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    // ── Group 29: Edge cases ─────────────────────────────────────────

    #[test]
    fn parse_multiple_options() {
        let mut opts = Vec::new();
        opts.extend_from_slice(&dhcpv6_option(1, &[0x00, 0x01, 0xAA, 0xBB]));
        opts.extend_from_slice(&dhcpv6_option(8, &100u16.to_be_bytes()));
        opts.extend_from_slice(&dhcpv6_option(6, &23u16.to_be_bytes()));
        let pkt = build_dhcpv6(1, 1, &opts);

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert!(has_option(&buf, &buf.layers()[0], 1));
        assert!(has_option(&buf, &buf.layers()[0], 8));
        assert!(has_option(&buf, &buf.layers()[0], 6));
    }

    #[test]
    fn parse_option_data_exceeds_packet() {
        // Manually craft an option where option_len exceeds available data
        let mut pkt = build_dhcpv6(1, 1, &[]);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // option code 0
        pkt.extend_from_slice(&100u16.to_be_bytes()); // option len = 100, but no data

        let d = Dhcpv6Dissector;
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    // ── Group 30: DUIDs, later options, RFC 7341 messages ───────────

    type TestField<'pkt> = packet_dissector_core::field::Field<'pkt>;

    /// Direct children of a container field (nested containers are skipped
    /// as a whole).
    fn direct_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        field: &TestField<'pkt>,
    ) -> Vec<&'a TestField<'pkt>> {
        let range = field.value.as_container_range().unwrap().clone();
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let c = &buf.fields()[i as usize];
            out.push(c);
            i = match c.value.as_container_range() {
                Some(r) => r.end,
                None => i + 1,
            };
        }
        out
    }

    /// Children of the option object with `code` in `options_array`.
    fn option_in<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        options_array: &TestField<'pkt>,
        code: u16,
    ) -> Vec<&'a TestField<'pkt>> {
        for opt in direct_children(buf, options_array) {
            let fields = direct_children(buf, opt);
            if fields
                .iter()
                .any(|f| f.name() == "code" && f.value == FieldValue::U16(code))
            {
                return fields;
            }
        }
        panic!("option {code} not found");
    }

    /// Children of the top-level option `code` in layer `layer`.
    fn top_option<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: usize,
        code: u16,
    ) -> Vec<&'a TestField<'pkt>> {
        let options = buf.field_by_name(&buf.layers()[layer], "options").unwrap();
        option_in(buf, options, code)
    }

    fn child<'a, 'pkt>(fields: &[&'a TestField<'pkt>], name: &str) -> &'a TestField<'pkt> {
        fields
            .iter()
            .find(|f| f.name() == name)
            .copied()
            .unwrap_or_else(|| panic!("child {name} not found"))
    }

    fn has_child(fields: &[&TestField<'_>], name: &str) -> bool {
        fields.iter().any(|f| f.name() == name)
    }

    /// Render a field through its descriptor's `format_fn`.
    fn formatted(field: &TestField<'_>) -> String {
        let ctx = packet_dissector_core::field::FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        (field.descriptor.format_fn.expect("format_fn"))(&field.value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// IANA "DHCPv6 Parameters" registry, Message Types 14-37.
    #[test]
    fn dhcpv6_msg_type_names_iana_registrations() {
        let expected = [
            (14, "LEASEQUERY"),
            (15, "LEASEQUERY_REPLY"),
            (16, "LEASEQUERY_DONE"),
            (17, "LEASEQUERY_DATA"),
            (18, "RECONFIGURE_REQUEST"),
            (19, "RECONFIGURE_REPLY"),
            (20, "DHCPV4_QUERY"),
            (21, "DHCPV4_RESPONSE"),
            (22, "ACTIVELEASEQUERY"),
            (23, "STARTTLS"),
            (24, "BNDUPD"),
            (25, "BNDREPLY"),
            (26, "POOLREQ"),
            (27, "POOLRESP"),
            (28, "UPDREQ"),
            (29, "UPDREQALL"),
            (30, "UPDDONE"),
            (31, "CONNECT"),
            (32, "CONNECTREPLY"),
            (33, "DISCONNECT"),
            (34, "STATE"),
            (35, "CONTACT"),
            (36, "ADDR_REG_INFORM"),
            (37, "ADDR_REG_REPLY"),
        ];
        for (v, name) in expected {
            assert_eq!(dhcpv6_msg_type_name(v), Some(name), "type {v}");
        }
        assert_eq!(dhcpv6_msg_type_name(0), None);
        assert_eq!(dhcpv6_msg_type_name(38), None);
    }

    /// IANA "DHCPv6 Parameters" registry, Option Codes (sample of codes
    /// added beyond 39).
    #[test]
    fn dhcpv6_option_names_iana_registrations() {
        let expected = [
            (21, "SIP Server Domain Name List"),
            (22, "SIP Server IPv6 Address List"),
            (31, "SNTP Servers"),
            (32, "Information Refresh Time"),
            (37, "Relay Agent Remote-ID"),
            (38, "Relay Agent Subscriber-ID"),
            (53, "Relay-ID"),
            (56, "NTP Server"),
            (59, "Boot File URL"),
            (60, "Boot File Parameters"),
            (61, "Client System Architecture Type"),
            (64, "AFTR-Name"),
            (79, "Client Link-Layer Address"),
            (82, "SOL_MAX_RT"),
            (83, "INF_MAX_RT"),
            (87, "DHCPv4 Message"),
            (88, "DHCP 4o6 Server Address"),
            (89, "S46 Rule"),
            (90, "S46 BR"),
            (91, "S46 DMR"),
            (92, "S46 IPv4/IPv6 Address Binding"),
            (93, "S46 Port Parameters"),
            (94, "S46 MAP-E Container"),
            (95, "S46 MAP-T Container"),
            (96, "S46 Lightweight 4over6 Container"),
            (103, "Captive-Portal"),
            (148, "ADDR-REG-ENABLE"),
        ];
        for (code, name) in expected {
            assert_eq!(dhcpv6_option_name(code), Some(name), "option {code}");
        }
        assert_eq!(dhcpv6_option_name(10), None);
        assert_eq!(dhcpv6_option_name(35), None);
        assert_eq!(dhcpv6_option_name(151), None);
    }

    /// RFC 9915, Section 11.2 — DUID-LLT in a Client Identifier.
    /// Issue repro: `00 01 00 0e 00 01 00 01 2b 3c 4d 5e 00 11 22 33 44 55`.
    #[test]
    fn parse_option_client_id_duid_llt() {
        let mut pkt = vec![1, 0, 0, 1];
        pkt.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x2b, 0x3c, 0x4d, 0x5e, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55,
        ]);
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 1);
        assert_eq!(child(&f, "client_id").value, FieldValue::Bytes(&pkt[8..]));
        assert_eq!(child(&f, "duid_type").value, FieldValue::U16(1));
        // An Ethernet address is shown as a MAC, so the hardware type is
        // implied; the time stays in the raw `client_id` bytes.
        assert!(!has_child(&f, "hw_type"));
        assert!(!has_child(&f, "time"));
        let ll = child(&f, "link_layer_address");
        assert_eq!(
            ll.value,
            FieldValue::MacAddr(packet_dissector_core::field::MacAddr([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55
            ]))
        );
        assert_eq!(ll.range, 16..22);
    }

    /// RFC 9915, Section 11.3 — DUID-EN (Figure 6 example) in a Server
    /// Identifier.
    #[test]
    fn parse_option_server_id_duid_en() {
        let duid = [0, 2, 0, 0, 126, 217, 12, 192, 132, 211, 3, 0, 9, 18];
        let pkt = build_dhcpv6(2, 1, &dhcpv6_option(2, &duid));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 2);
        assert_eq!(child(&f, "server_id").value, FieldValue::Bytes(&duid));
        assert_eq!(child(&f, "duid_type").value, FieldValue::U16(2));
        assert_eq!(child(&f, "enterprise_number").value, FieldValue::U32(32473));
        assert_eq!(
            child(&f, "identifier").value,
            FieldValue::Bytes(&[0x0C, 0xC0, 0x84, 0xD3, 0x03, 0x00, 0x09, 0x12])
        );
    }

    /// RFC 9915, Section 11.4 — DUID-LL with an Ethernet address and with a
    /// non-Ethernet (8-octet) link-layer address.
    #[test]
    fn parse_option_client_id_duid_ll() {
        let duid = [0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(1, &duid));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 1);
        assert_eq!(child(&f, "duid_type").value, FieldValue::U16(3));
        assert!(!has_child(&f, "hw_type"));
        assert_eq!(
            child(&f, "link_layer_address").value,
            FieldValue::MacAddr(packet_dissector_core::field::MacAddr([2, 0, 0, 0, 0, 1]))
        );

        let duid = [0, 3, 0, 27, 1, 2, 3, 4, 5, 6, 7, 8];
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(1, &duid));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 1);
        assert_eq!(child(&f, "hw_type").value, FieldValue::U16(27));
        assert_eq!(
            child(&f, "link_layer_address_bytes").value,
            FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert!(!has_child(&f, "link_layer_address"));

        // Hardware type 1 with an address that is not 6 octets: not a MAC,
        // so the hardware type is shown.
        let duid = [0, 1, 0, 1, 0x2b, 0x3c, 0x4d, 0x5e, 1, 2, 3, 4, 5, 6, 7, 8];
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(1, &duid));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 1);
        let hw = child(&f, "hw_type");
        assert_eq!(hw.value, FieldValue::U16(1));
        assert_eq!(hw.range, 10..12);
        assert_eq!(
            child(&f, "link_layer_address_bytes").value,
            FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8])
        );
    }

    /// RFC 9915, Section 11.5 / RFC 6355, Section 4 — DUID-UUID.
    #[test]
    fn parse_option_client_id_duid_uuid() {
        let mut duid = vec![0, 4];
        duid.extend_from_slice(&[0xAB; 16]);
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(1, &duid));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 1);
        assert_eq!(child(&f, "duid_type").value, FieldValue::U16(4));
        assert_eq!(child(&f, "uuid").value, FieldValue::Bytes(&[0xAB; 16]));
    }

    /// RFC 9915, Section 11 — "Clients and servers MUST NOT restrict DUIDs
    /// to the types defined in this document". Unknown or malformed DUIDs
    /// keep only the raw bytes and the type code.
    #[test]
    fn parse_option_client_id_duid_unknown_or_malformed() {
        for duid in [
            &[0u8, 9, 0xAA][..],    // unknown type
            &[0, 4, 1, 2, 3],       // DUID-UUID not 16 octets
            &[0, 1, 0, 1, 0, 0, 0], // DUID-LLT without full time
            &[0, 2, 0, 0, 1],       // DUID-EN without full enterprise number
            &[0, 3, 0],             // DUID-LL without full hardware type
        ] {
            let pkt = build_dhcpv6(1, 1, &dhcpv6_option(1, duid));
            let mut buf = DissectBuffer::new();
            Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
            let f = top_option(&buf, 0, 1);
            assert_eq!(child(&f, "client_id").value, FieldValue::Bytes(duid));
            assert_eq!(
                child(&f, "duid_type").value,
                FieldValue::U16(u16::from_be_bytes([duid[0], duid[1]]))
            );
            for name in [
                "hw_type",
                "time",
                "link_layer_address",
                "link_layer_address_bytes",
                "enterprise_number",
                "identifier",
                "uuid",
            ] {
                assert!(!has_child(&f, name), "{duid:?}: {name}");
            }
        }
        // A one-octet DUID has no type code at all.
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(1, &[7]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(!has_child(&top_option(&buf, 0, 1), "duid_type"));
    }

    /// RFC 5460, Section 5.4.1 — Relay-ID option carries the relay agent's
    /// DUID.
    #[test]
    fn parse_option_relay_id_duid() {
        let duid = [0, 3, 0, 1, 2, 0, 0, 0, 0, 9];
        let pkt = build_dhcpv6(14, 1, &dhcpv6_option(53, &duid));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 53);
        assert_eq!(child(&f, "relay_id").value, FieldValue::Bytes(&duid));
        assert_eq!(child(&f, "duid_type").value, FieldValue::U16(3));
    }

    /// RFC 3319, Section 3.1 — SIP Servers Domain Name List.
    #[test]
    fn parse_option_sip_server_domains() {
        let data = b"\x03sip\x07example\x03com\x00\x04sip2\x07example\x03net\x00";
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(21, data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 21);
        let names = direct_children(&buf, child(&f, "sip_server_domains"));
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].name(), "domain");
        assert_eq!(formatted(names[0]), "\"sip.example.com\"");
        assert_eq!(formatted(names[1]), "\"sip2.example.net\"");
    }

    /// A list that does not consist of complete names (a compression
    /// pointer or a label cut off by the end of the option) does not panic
    /// and is kept as the raw `data`.
    #[test]
    fn parse_option_domain_list_truncated_is_raw() {
        let cases: [&[u8]; 3] = [&[1, b'a', 0xC0], b"\x03sip\x07exa", b"\x07example\x03co"];
        for code in [21u16, 24] {
            for data in cases {
                let pkt = build_dhcpv6(7, 1, &dhcpv6_option(code, data));
                let mut buf = DissectBuffer::new();
                Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
                let f = top_option(&buf, 0, code);
                assert!(f.iter().all(|f| !f.value.is_array()), "{code} {data:?}");
                assert_eq!(child(&f, "data").value, FieldValue::Bytes(data));
            }
        }
    }

    /// RFC 3319, Section 3.2 — SIP Servers IPv6 Address List.
    #[test]
    fn parse_option_sip_server_addresses() {
        let mut data = [0u8; 32];
        data[0] = 0x20;
        data[15] = 1;
        data[16] = 0x20;
        data[31] = 2;
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(22, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 22);
        let addrs = direct_children(&buf, child(&f, "sip_server_addresses"));
        assert_eq!(addrs.len(), 2);
        let mut a1 = [0u8; 16];
        a1[0] = 0x20;
        a1[15] = 2;
        assert_eq!(addrs[1].value, FieldValue::Ipv6Addr(a1));
    }

    /// RFC 4075, Section 4 — SNTP Servers option.
    #[test]
    fn parse_option_sntp_servers() {
        let data = [0x11u8; 16];
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(31, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 31);
        let addrs = direct_children(&buf, child(&f, "sntp_servers"));
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].value, FieldValue::Ipv6Addr([0x11; 16]));
    }

    /// Address-list options whose length is not a multiple of 16 stay raw.
    #[test]
    fn parse_option_address_list_bad_length_raw() {
        for code in [22u16, 31, 88] {
            let pkt = build_dhcpv6(7, 1, &dhcpv6_option(code, &[0u8; 17]));
            let mut buf = DissectBuffer::new();
            Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
            let f = top_option(&buf, 0, code);
            assert_eq!(child(&f, "data").value, FieldValue::Bytes(&[0u8; 17]));
        }
    }

    /// RFC 9915, Section 21.23 — Information Refresh Time option.
    #[test]
    fn parse_option_information_refresh_time() {
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(32, &86400u32.to_be_bytes()));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 32);
        assert_eq!(
            child(&f, "information_refresh_time").value,
            FieldValue::U32(86400)
        );
    }

    /// RFC 9915, Sections 21.24 and 21.25 — SOL_MAX_RT and INF_MAX_RT.
    #[test]
    fn parse_option_sol_and_inf_max_rt() {
        let mut opts = dhcpv6_option(82, &3600u32.to_be_bytes());
        opts.extend_from_slice(&dhcpv6_option(83, &7200u32.to_be_bytes()));
        let pkt = build_dhcpv6(7, 1, &opts);
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            child(&top_option(&buf, 0, 82), "sol_max_rt").value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            child(&top_option(&buf, 0, 83), "inf_max_rt").value,
            FieldValue::U32(7200)
        );
    }

    /// Fixed four-octet options with another length stay raw.
    #[test]
    fn parse_option_u32_bad_length_raw() {
        for code in [32u16, 82, 83] {
            let pkt = build_dhcpv6(7, 1, &dhcpv6_option(code, &[0, 1, 2]));
            let mut buf = DissectBuffer::new();
            Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
            let f = top_option(&buf, 0, code);
            assert_eq!(child(&f, "data").value, FieldValue::Bytes(&[0, 1, 2]));
        }
    }

    /// RFC 4649, Section 3 — Relay Agent Remote-ID: enterprise-number and
    /// remote-id.
    #[test]
    fn parse_option_remote_id() {
        let mut data = 3561u32.to_be_bytes().to_vec();
        data.extend_from_slice(b"port-7");
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &dhcpv6_option(37, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 37);
        assert_eq!(child(&f, "enterprise_number").value, FieldValue::U32(3561));
        assert_eq!(child(&f, "remote_id").value, FieldValue::Bytes(b"port-7"));
    }

    /// RFC 4649, Section 3 — "The minimum option-len is 5 octets."
    #[test]
    fn parse_option_remote_id_short_raw() {
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &dhcpv6_option(37, &[0, 0, 0, 9]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 37);
        assert_eq!(child(&f, "data").value, FieldValue::Bytes(&[0, 0, 0, 9]));
    }

    /// RFC 4580, Section 2 — Relay Agent Subscriber-ID.
    #[test]
    fn parse_option_subscriber_id() {
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &dhcpv6_option(38, b"sub-42"));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 38);
        let s = child(&f, "subscriber_id");
        assert_eq!(s.value, FieldValue::Bytes(b"sub-42"));
        assert_eq!(formatted(s), "\"sub-42\"");
    }

    /// RFC 5908, Section 4 — NTP Server option with its three suboptions.
    #[test]
    fn parse_option_ntp_server() {
        let mut data = dhcpv6_option(1, &[0x20; 16]);
        data.extend_from_slice(&dhcpv6_option(2, &[0xFF; 16]));
        data.extend_from_slice(&dhcpv6_option(3, b"\x03ntp\x07example\x00"));
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(56, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 56);
        let subs = direct_children(&buf, child(&f, "ntp_suboptions"));
        assert_eq!(subs.len(), 3);
        let s0 = direct_children(&buf, subs[0]);
        assert_eq!(child(&s0, "code").value, FieldValue::U16(1));
        assert_eq!(
            child(&s0, "server_address").value,
            FieldValue::Ipv6Addr([0x20; 16])
        );
        let s1 = direct_children(&buf, subs[1]);
        assert_eq!(
            child(&s1, "multicast_address").value,
            FieldValue::Ipv6Addr([0xFF; 16])
        );
        let s2 = direct_children(&buf, subs[2]);
        assert_eq!(formatted(child(&s2, "server_fqdn")), "\"ntp.example\"");
    }

    /// NTP suboptions: an unknown code or a wrong address length keeps the
    /// suboption data raw; a list that does not parse exactly keeps the
    /// whole option raw.
    #[test]
    fn parse_option_ntp_server_unknown_and_malformed() {
        let mut data = dhcpv6_option(9, &[1, 2]);
        data.extend_from_slice(&dhcpv6_option(1, &[0; 4]));
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(56, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 56);
        let subs = direct_children(&buf, child(&f, "ntp_suboptions"));
        assert_eq!(
            child(&direct_children(&buf, subs[0]), "data").value,
            FieldValue::Bytes(&[1, 2])
        );
        assert_eq!(
            child(&direct_children(&buf, subs[1]), "data").value,
            FieldValue::Bytes(&[0; 4])
        );

        let bad = [0, 1, 0, 16, 0];
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(56, &bad));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 56);
        assert!(!has_child(&f, "ntp_suboptions"));
        assert_eq!(child(&f, "data").value, FieldValue::Bytes(&bad));
    }

    /// RFC 5970, Section 3.1 — Boot File URL.
    #[test]
    fn parse_option_boot_file_url() {
        let url = b"tftp://[2001:db8::1]/boot.efi";
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(59, url));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 59);
        assert_eq!(child(&f, "boot_file_url").value, FieldValue::Bytes(url));
    }

    /// RFC 5970, Section 3.2 — Boot File Parameters: param-len (2) +
    /// parameter, repeated.
    #[test]
    fn parse_option_boot_file_parameters() {
        let data = [0, 4, b'r', b'o', b'o', b't', 0, 2, b'q', b'1'];
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(60, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 60);
        let params = direct_children(&buf, child(&f, "boot_file_parameters"));
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].value, FieldValue::Bytes(b"root"));
        assert_eq!(params[1].value, FieldValue::Bytes(b"q1"));

        let bad = [0, 9, b'x'];
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(60, &bad));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            child(&top_option(&buf, 0, 60), "data").value,
            FieldValue::Bytes(&bad)
        );
    }

    /// RFC 5970, Section 3.3 — Client System Architecture Type: "It MUST be
    /// an even number greater than zero."
    #[test]
    fn parse_option_client_arch_type() {
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(61, &[0, 7, 0, 16]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 61);
        let types = direct_children(&buf, child(&f, "client_arch_types"));
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].value, FieldValue::U16(7));
        assert_eq!(types[1].value, FieldValue::U16(16));

        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(61, &[0, 7, 1]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            child(&top_option(&buf, 0, 61), "data").value,
            FieldValue::Bytes(&[0, 7, 1])
        );
    }

    /// RFC 6334, Section 3 — AFTR-Name: an FQDN.
    #[test]
    fn parse_option_aftr_name() {
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(64, b"\x04aftr\x07example\x00"));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 64);
        assert_eq!(formatted(child(&f, "aftr_name")), "\"aftr.example\"");
    }

    /// RFC 4704, Section 4.2 — the Client FQDN Domain Name is decoded as
    /// DNS labels.
    #[test]
    fn parse_option_client_fqdn_domain_name_decoded() {
        let mut data = vec![0x01];
        data.extend_from_slice(b"\x06client\x07example\x03com\x00");
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(39, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 39);
        assert_eq!(formatted(child(&f, "fqdn")), "\"client.example.com\"");
    }

    /// RFC 6939, Section 4 — Client Link-Layer Address.
    #[test]
    fn parse_option_client_link_layer_address() {
        let data = [0, 1, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &dhcpv6_option(79, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 79);
        assert_eq!(child(&f, "link_layer_type").value, FieldValue::U16(1));
        assert_eq!(
            child(&f, "link_layer_address").value,
            FieldValue::MacAddr(packet_dissector_core::field::MacAddr([
                0x02, 0x11, 0x22, 0x33, 0x44, 0x55
            ]))
        );

        let pkt = build_relay(12, 0, [0; 16], [0; 16], &dhcpv6_option(79, &[0]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            child(&top_option(&buf, 0, 79), "data").value,
            FieldValue::Bytes(&[0])
        );
    }

    /// RFC 7341, Section 7.2 — DHCP 4o6 Server Address: zero or more IPv6
    /// addresses.
    #[test]
    fn parse_option_dhcp4o6_server_address() {
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(88, &[0x20; 32]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 88);
        let addrs = direct_children(&buf, child(&f, "dhcp4o6_servers"));
        assert_eq!(addrs.len(), 2);

        // "Minimal length of this option is 0."
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(88, &[]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 88);
        assert!(direct_children(&buf, child(&f, "dhcp4o6_servers")).is_empty());
    }

    /// RFC 7598, Section 4.1 — S46 Rule with an encapsulated S46 Port
    /// Parameters option (Section 4.5).
    #[test]
    fn parse_option_s46_rule_with_port_params() {
        let mut data = vec![0x01, 16, 24, 192, 0, 2, 0, 56];
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00]);
        data.extend_from_slice(&dhcpv6_option(93, &[6, 8, 0x00, 0x34]));
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(89, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 89);
        assert_eq!(child(&f, "flags").value, FieldValue::U8(1));
        assert_eq!(child(&f, "ea_len").value, FieldValue::U8(16));
        assert_eq!(child(&f, "prefix4_len").value, FieldValue::U8(24));
        assert_eq!(
            child(&f, "ipv4_prefix").value,
            FieldValue::Ipv4Addr([192, 0, 2, 0])
        );
        assert_eq!(child(&f, "prefix6_len").value, FieldValue::U8(56));
        assert_eq!(
            child(&f, "ipv6_prefix").value,
            FieldValue::Bytes(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00])
        );
        let pp = option_in(&buf, child(&f, "options"), 93);
        assert_eq!(child(&pp, "offset").value, FieldValue::U8(6));
        assert_eq!(child(&pp, "psid_len").value, FieldValue::U8(8));
        assert_eq!(child(&pp, "psid").value, FieldValue::U16(0x34));
    }

    /// S46 Rule whose prefix6-len does not fit the option stays raw.
    #[test]
    fn parse_option_s46_rule_malformed_raw() {
        let data = [0x00, 0, 24, 192, 0, 2, 0, 200];
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(89, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 89);
        assert_eq!(child(&f, "data").value, FieldValue::Bytes(&data));
    }

    /// RFC 7598, Sections 4.2 and 4.3 — S46 BR and S46 DMR.
    #[test]
    fn parse_option_s46_br_and_dmr() {
        let mut opts = dhcpv6_option(90, &[0x20; 16]);
        opts.extend_from_slice(&dhcpv6_option(
            91,
            &[64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
        ));
        let pkt = build_dhcpv6(7, 1, &opts);
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            child(&top_option(&buf, 0, 90), "br_address").value,
            FieldValue::Ipv6Addr([0x20; 16])
        );
        let dmr = top_option(&buf, 0, 91);
        assert_eq!(child(&dmr, "prefix6_len").value, FieldValue::U8(64));
        assert_eq!(
            child(&dmr, "ipv6_prefix").value,
            FieldValue::Bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0])
        );
    }

    /// RFC 7598, Section 4.4 — S46 IPv4/IPv6 Address Binding.
    #[test]
    fn parse_option_s46_v4v6bind() {
        let data = [198, 51, 100, 7, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1];
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(92, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 92);
        assert_eq!(
            child(&f, "ipv4_address").value,
            FieldValue::Ipv4Addr([198, 51, 100, 7])
        );
        assert_eq!(child(&f, "prefix6_len").value, FieldValue::U8(64));
        assert!(!has_child(&f, "options"));
    }

    /// RFC 7598, Section 5 — the MAP-E, MAP-T and Lightweight 4over6
    /// containers (94-96) encapsulate S46 options.
    #[test]
    fn parse_option_s46_containers() {
        for code in [94u16, 95, 96] {
            let mut inner = dhcpv6_option(90, &[0x20; 16]);
            inner.extend_from_slice(&dhcpv6_option(91, &[0]));
            let pkt = build_dhcpv6(7, 1, &dhcpv6_option(code, &inner));
            let mut buf = DissectBuffer::new();
            Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
            let f = top_option(&buf, 0, code);
            let options = child(&f, "options");
            assert_eq!(
                child(&option_in(&buf, options, 90), "br_address").value,
                FieldValue::Ipv6Addr([0x20; 16])
            );
            assert_eq!(
                child(&option_in(&buf, options, 91), "prefix6_len").value,
                FieldValue::U8(0)
            );
        }
        // Encapsulated options that do not parse exactly stay raw.
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(94, &[0, 90, 0, 16]));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            child(&top_option(&buf, 0, 94), "data").value,
            FieldValue::Bytes(&[0, 90, 0, 16])
        );
    }

    /// RFC 8910, Section 2.2 — Captive-Portal URI.
    #[test]
    fn parse_option_captive_portal() {
        let uri = b"https://cp.example/api";
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(103, uri));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 103);
        let u = child(&f, "captive_portal_uri");
        assert_eq!(u.value, FieldValue::Bytes(uri));
        assert_eq!(formatted(u), "\"https://cp.example/api\"");
    }

    /// RFC 9915, Section 21.17 — "The vendor-option-data field MUST be
    /// encoded as a sequence of code/length/value fields".
    #[test]
    fn parse_option_vendor_info_suboptions() {
        let mut data = 4491u32.to_be_bytes().to_vec();
        data.extend_from_slice(&dhcpv6_option(1, b"ab"));
        data.extend_from_slice(&dhcpv6_option(2, &[]));
        let pkt = build_dhcpv6(7, 1, &dhcpv6_option(17, &data));
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_option(&buf, 0, 17);
        assert_eq!(child(&f, "enterprise_number").value, FieldValue::U32(4491));
        assert!(!has_child(&f, "data"));
        let subs = direct_children(&buf, child(&f, "vendor_options"));
        assert_eq!(subs.len(), 2);
        let s0 = direct_children(&buf, subs[0]);
        assert_eq!(child(&s0, "code").value, FieldValue::U16(1));
        assert_eq!(child(&s0, "data").value, FieldValue::Bytes(b"ab"));
        let s1 = direct_children(&buf, subs[1]);
        assert_eq!(child(&s1, "code").value, FieldValue::U16(2));
        assert_eq!(child(&s1, "data").value, FieldValue::Bytes(&[]));
    }

    /// RFC 7341, Section 6.2 / 6.3 — DHCPv4-query carries a 3-octet flags
    /// field (U bit) instead of a transaction-id, and the DHCPv4 Message
    /// option (Section 7.1) is handed to the DHCPv4 dissector.
    #[test]
    fn parse_dhcpv4_query_message() {
        let dhcpv4 = [0xAAu8; 20];
        let mut pkt = vec![20, 0x80, 0x00, 0x00];
        pkt.extend_from_slice(&dhcpv6_option(87, &dhcpv4));
        let mut buf = DissectBuffer::new();
        let result = Dhcpv6Dissector.dissect(&pkt, &mut buf, 100).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "msg_type_name"),
            Some("DHCPV4_QUERY")
        );
        assert_eq!(buf.field_u32(layer, "flags"), Some(0x80_0000));
        assert_eq!(buf.field_u8(layer, "unicast"), Some(1));
        assert!(buf.field_by_name(layer, "transaction_id").is_none());
        let f = top_option(&buf, 0, 87);
        let msg = child(&f, "dhcpv4_message");
        assert_eq!(msg.value, FieldValue::Bytes(&dhcpv4));
        assert_eq!(msg.range, 108..128);
        assert_eq!(result.bytes_consumed, pkt.len());
        assert_eq!(result.next, DispatchHint::ByUdpPort(67, 68));
        assert_eq!(result.embedded_payload, Some(108..128));
    }

    /// RFC 7341, Section 6.4 — DHCPv4-response flags carry no defined bits.
    #[test]
    fn parse_dhcpv4_response_message() {
        let mut pkt = vec![21, 0x00, 0x00, 0x00];
        pkt.extend_from_slice(&dhcpv6_option(87, &[0xBB; 8]));
        let mut buf = DissectBuffer::new();
        let result = Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(buf.field_u32(layer, "flags"), Some(0));
        assert!(buf.field_by_name(layer, "unicast").is_none());
        assert_eq!(result.embedded_payload, Some(8..16));
    }

    /// A DHCPv4-query without the DHCPv4 Message option does not dispatch;
    /// a truncated one is an error.
    #[test]
    fn parse_dhcpv4_query_without_message_and_truncated() {
        let pkt = [20, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::End);
        assert!(result.embedded_payload.is_none());

        let mut buf = DissectBuffer::new();
        let err = Dhcpv6Dissector.dissect(&[20, 0], &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    /// The DHCPv4 Message option is only dispatched from DHCPv4-query and
    /// DHCPv4-response messages.
    #[test]
    fn parse_dhcpv4_message_option_in_other_message_not_dispatched() {
        let pkt = build_dhcpv6(1, 1, &dhcpv6_option(87, &[1, 2, 3]));
        let mut buf = DissectBuffer::new();
        let result = Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::End);
        assert!(result.embedded_payload.is_none());
        assert_eq!(
            child(&top_option(&buf, 0, 87), "dhcpv4_message").value,
            FieldValue::Bytes(&[1, 2, 3])
        );
    }

    /// RFC 7341, Section 10 — a relayed DHCPv4-query still hands its DHCPv4
    /// message to the next dissector.
    #[test]
    fn parse_relay_forw_with_dhcpv4_query() {
        let mut inner = vec![20, 0, 0, 0];
        inner.extend_from_slice(&dhcpv6_option(87, &[0xCC; 12]));
        let pkt = build_relay(12, 0, [0; 16], [0; 16], &dhcpv6_option(9, &inner));
        let mut buf = DissectBuffer::new();
        let result = Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(buf.layers().len(), 2);
        // relay header (34) + option 9 header (4) + inner header (4) +
        // option 87 header (4)
        assert_eq!(result.embedded_payload, Some(46..58));
        assert_eq!(result.next, DispatchHint::ByUdpPort(67, 68));
        assert_eq!(result.bytes_consumed, pkt.len());
    }

    /// Encapsulated options nest recursively (e.g. IA_NA inside IA_NA);
    /// nesting beyond the depth limit is kept raw instead of recursing.
    #[test]
    fn parse_deeply_nested_options_bounded() {
        let mut opt = dhcpv6_option(14, &[]);
        for _ in 0..200 {
            let mut data = vec![0u8; 12];
            data.extend_from_slice(&opt);
            opt = dhcpv6_option(3, &data);
        }
        let pkt = build_dhcpv6(7, 1, &opt);
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(buf.fields().len() < 200 * 6);
        assert!(buf.fields().iter().any(|f| f.name() == "data"));
    }

    /// Every emitted field (at any nesting depth) matches its descriptor's
    /// type for the newly decoded options.
    #[test]
    fn new_option_value_types_match_descriptors() {
        let mut opts = Vec::new();
        for (code, data) in [
            (1u16, vec![0, 1, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6]),
            (2, vec![0, 2, 0, 0, 0, 9, 1]),
            (53, vec![0, 3, 0, 27, 1]),
            (21, b"\x01a\x00".to_vec()),
            (22, vec![0; 16]),
            (31, vec![0; 16]),
            (32, vec![0, 0, 0, 1]),
            (37, vec![0, 0, 0, 1, 1]),
            (38, vec![1]),
            (56, dhcpv6_option(1, &[0; 16])),
            (59, b"u".to_vec()),
            (60, vec![0, 1, b'p']),
            (61, vec![0, 7]),
            (64, b"\x01a\x00".to_vec()),
            (79, vec![0, 1, 1, 2, 3, 4, 5, 6]),
            (82, vec![0, 0, 0, 60]),
            (83, vec![0, 0, 0, 60]),
            (87, vec![1]),
            (88, vec![0; 16]),
            (89, vec![0, 0, 0, 0, 0, 0, 0, 0]),
            (90, vec![0; 16]),
            (91, vec![8, 0x20]),
            (92, vec![0, 0, 0, 0, 0]),
            (93, vec![0, 0, 0, 0]),
            (94, dhcpv6_option(90, &[0; 16])),
            (103, b"urn:x".to_vec()),
        ] {
            opts.extend_from_slice(&dhcpv6_option(code, &data));
        }
        let mut vendor = 1u32.to_be_bytes().to_vec();
        vendor.extend_from_slice(&dhcpv6_option(1, &[1]));
        opts.extend_from_slice(&dhcpv6_option(17, &vendor));
        let pkt = build_dhcpv6(7, 1, &opts);
        let mut buf = DissectBuffer::new();
        Dhcpv6Dissector.dissect(&pkt, &mut buf, 0).unwrap();
        for f in buf.layer_fields(&buf.layers()[0]) {
            // Scalar array elements reuse the array's descriptor (crate
            // convention, see option 23).
            if f.descriptor.field_type == FieldType::Array && !f.value.is_array() {
                continue;
            }
            assert_eq!(
                f.value.field_type(),
                f.descriptor.field_type,
                "field {}",
                f.name()
            );
        }
    }

    /// Every dissector in this crate must cite the specifications it
    /// implements and declare where it sits in the dissection stack.
    #[test]
    fn references_and_layer_are_populated() {
        fn assert_layer_and_references(dissector: &dyn Dissector) {
            let references = dissector.references();
            assert!(!references.is_empty());
            for reference in references {
                assert!(!reference.id.is_empty());
                assert!(!reference.title.is_empty());
                assert!(
                    reference.url.starts_with("https://"),
                    "{} url must start with https://",
                    reference.id
                );
            }
            assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
        }

        assert_layer_and_references(&Dhcpv6Dissector);
    }
}
