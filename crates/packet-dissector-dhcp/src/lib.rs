//! DHCP (Dynamic Host Configuration Protocol) dissector.
//!
//! ## References
//! - RFC 2131: <https://www.rfc-editor.org/rfc/rfc2131>
//! - RFC 2132 (DHCP Options): <https://www.rfc-editor.org/rfc/rfc2132>
//! - RFC 3396 (Long Options): <https://www.rfc-editor.org/rfc/rfc3396>
//! - RFC 4361 (Client Identifier): <https://www.rfc-editor.org/rfc/rfc4361>
//! - RFC 3046 (Relay Agent Information): <https://www.rfc-editor.org/rfc/rfc3046>
//! - RFC 3397 (Domain Search List): <https://www.rfc-editor.org/rfc/rfc3397>
//! - RFC 3442 (Classless Static Route): <https://www.rfc-editor.org/rfc/rfc3442>
//! - RFC 6842 (Client Identifier in Responses): <https://www.rfc-editor.org/rfc/rfc6842>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, MacAddr, format_utf8_lossy,
};

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_OP: usize = 0;
const FD_HTYPE: usize = 1;
const FD_HLEN: usize = 2;
const FD_HOPS: usize = 3;
const FD_XID: usize = 4;
const FD_SECS: usize = 5;
const FD_BROADCAST: usize = 6;
const FD_CIADDR: usize = 7;
const FD_YIADDR: usize = 8;
const FD_SIADDR: usize = 9;
const FD_GIADDR: usize = 10;
const FD_CHADDR: usize = 11;
const FD_SNAME: usize = 12;
const FD_FILE: usize = 13;
const FD_DHCP_MESSAGE_TYPE: usize = 14;
const FD_ALL_SUBNETS_LOCAL: usize = 15;
const FD_ARP_CACHE_TIMEOUT: usize = 16;
const FD_BOOT_FILE_SIZE: usize = 17;
const FD_BOOTFILE_NAME: usize = 18;
const FD_BROADCAST_ADDRESS: usize = 19;
const FD_CLASSLESS_STATIC_ROUTE: usize = 20;
const FD_CLIENT_IDENTIFIER: usize = 21;
const FD_COOKIE_SERVER: usize = 22;
const FD_DEFAULT_IP_TTL: usize = 23;
const FD_DNS_SERVER: usize = 24;
const FD_DOMAIN_NAME: usize = 25;
const FD_DOMAIN_SEARCH: usize = 26;
const FD_ETHERNET_ENCAPSULATION: usize = 27;
const FD_EXTENSIONS_PATH: usize = 28;
const FD_HOSTNAME: usize = 29;
const FD_IMPRESS_SERVER: usize = 30;
const FD_INTERFACE_MTU: usize = 31;
const FD_IP_FORWARDING: usize = 32;
const FD_LEASE_TIME: usize = 33;
const FD_LOG_SERVER: usize = 34;
const FD_LPR_SERVER: usize = 35;
const FD_MASK_SUPPLIER: usize = 36;
const FD_MAX_DATAGRAM_REASSEMBLY_SIZE: usize = 37;
const FD_MAX_DHCP_MESSAGE_SIZE: usize = 38;
const FD_MERIT_DUMP_FILE: usize = 39;
const FD_MESSAGE: usize = 40;
const FD_NAME_SERVER: usize = 41;
const FD_NETBIOS_DD_SERVER: usize = 42;
const FD_NETBIOS_NAME_SERVER: usize = 43;
const FD_NETBIOS_NODE_TYPE: usize = 44;
const FD_NETBIOS_SCOPE: usize = 45;
const FD_NIS_DOMAIN: usize = 46;
const FD_NIS_SERVERS: usize = 47;
const FD_NISPLUS_DOMAIN: usize = 48;
const FD_NISPLUS_SERVERS: usize = 49;
const FD_NON_LOCAL_SOURCE_ROUTING: usize = 50;
const FD_NTP_SERVERS: usize = 51;
const FD_OPTION_OVERLOAD: usize = 52;
const FD_PARAMETER_REQUEST_LIST: usize = 53;
const FD_PATH_MTU_AGING_TIMEOUT: usize = 54;
const FD_PATH_MTU_PLATEAU_TABLE: usize = 55;
const FD_PERFORM_MASK_DISCOVERY: usize = 56;
const FD_PERFORM_ROUTER_DISCOVERY: usize = 57;
const FD_POLICY_FILTER: usize = 58;
const FD_REBINDING_TIME: usize = 59;
const FD_RELAY_AGENT_INFO: usize = 60;
const FD_RENEWAL_TIME: usize = 61;
const FD_REQUESTED_IP: usize = 62;
const FD_RESOURCE_LOCATION_SERVER: usize = 63;
const FD_ROOT_PATH: usize = 64;
const FD_ROUTER: usize = 65;
const FD_ROUTER_SOLICITATION_ADDRESS: usize = 66;
const FD_SERVER_IDENTIFIER: usize = 67;
const FD_STATIC_ROUTE: usize = 68;
const FD_SUBNET_MASK: usize = 69;
const FD_SWAP_SERVER: usize = 70;
const FD_TCP_DEFAULT_TTL: usize = 71;
const FD_TCP_KEEPALIVE_GARBAGE: usize = 72;
const FD_TCP_KEEPALIVE_INTERVAL: usize = 73;
const FD_TFTP_SERVER_NAME: usize = 74;
const FD_TIME_OFFSET: usize = 75;
const FD_TIME_SERVER: usize = 76;
const FD_TRAILER_ENCAPSULATION: usize = 77;
const FD_UNKNOWN_OPTION: usize = 78;
const FD_VENDOR_CLASS_IDENTIFIER: usize = 79;
const FD_VENDOR_SPECIFIC_INFO: usize = 80;
const FD_X_WINDOW_DISPLAY_MANAGER: usize = 81;
const FD_X_WINDOW_FONT_SERVER: usize = 82;

// Fixed header fields are always present; DHCP options are dynamic
// and represented as individual option fields at the top level.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("op", "Message Type", FieldType::U8),
    FieldDescriptor::new("htype", "Hardware Type", FieldType::U8),
    FieldDescriptor::new("hlen", "Hardware Address Length", FieldType::U8),
    FieldDescriptor::new("hops", "Hops", FieldType::U8),
    FieldDescriptor::new("xid", "Transaction ID", FieldType::U32),
    FieldDescriptor::new("secs", "Seconds Elapsed", FieldType::U16),
    FieldDescriptor::new("broadcast", "Broadcast Flag", FieldType::U8),
    FieldDescriptor::new("ciaddr", "Client IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("yiaddr", "Your IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("siaddr", "Server IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("giaddr", "Gateway IP Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("chaddr", "Client Hardware Address", FieldType::MacAddr),
    FieldDescriptor::new("sname", "Server Host Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("file", "Boot File Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor {
        name: "dhcp_message_type",
        display_name: "DHCP Message Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => dhcp_message_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("all_subnets_local", "All Subnets Local", FieldType::U8).optional(),
    FieldDescriptor::new("arp_cache_timeout", "ARP Cache Timeout", FieldType::U32).optional(),
    FieldDescriptor::new("boot_file_size", "Boot File Size", FieldType::U16).optional(),
    FieldDescriptor::new("bootfile_name", "Bootfile Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new(
        "broadcast_address",
        "Broadcast Address",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new(
        "classless_static_route",
        "Classless Static Route",
        FieldType::Array,
    )
    .optional()
    .with_children(CLASSLESS_ROUTE_CHILDREN),
    FieldDescriptor::new("client_identifier", "Client Identifier", FieldType::Object)
        .optional()
        .with_children(CLIENT_ID_CHILDREN),
    FieldDescriptor::new("cookie_server", "Cookie Server", FieldType::Array).optional(),
    FieldDescriptor::new("default_ip_ttl", "Default IP TTL", FieldType::U8).optional(),
    FieldDescriptor::new("dns_server", "Domain Name Server", FieldType::Array).optional(),
    FieldDescriptor::new("domain_name", "Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("domain_search", "Domain Search List", FieldType::Array).optional(),
    FieldDescriptor::new(
        "ethernet_encapsulation",
        "Ethernet Encapsulation",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("extensions_path", "Extensions Path", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("hostname", "Host Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("impress_server", "Impress Server", FieldType::Array).optional(),
    FieldDescriptor::new("interface_mtu", "Interface MTU", FieldType::U16).optional(),
    FieldDescriptor::new("ip_forwarding", "IP Forwarding", FieldType::U8).optional(),
    FieldDescriptor::new("lease_time", "IP Address Lease Time", FieldType::U32).optional(),
    FieldDescriptor::new("log_server", "Log Server", FieldType::Array).optional(),
    FieldDescriptor::new("lpr_server", "LPR Server", FieldType::Array).optional(),
    FieldDescriptor::new("mask_supplier", "Mask Supplier", FieldType::U8).optional(),
    FieldDescriptor::new(
        "max_datagram_reassembly_size",
        "Maximum Datagram Reassembly Size",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "max_dhcp_message_size",
        "Maximum DHCP Message Size",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("merit_dump_file", "Merit Dump File", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("message", "Message", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("name_server", "Name Server", FieldType::Array).optional(),
    FieldDescriptor::new("netbios_dd_server", "NetBIOS DD Server", FieldType::Array).optional(),
    FieldDescriptor::new(
        "netbios_name_server",
        "NetBIOS Name Server",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("netbios_node_type", "NetBIOS Node Type", FieldType::U8).optional(),
    FieldDescriptor::new("netbios_scope", "NetBIOS Scope", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("nis_domain", "NIS Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("nis_servers", "NIS Servers", FieldType::Array).optional(),
    FieldDescriptor::new("nisplus_domain", "NIS+ Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("nisplus_servers", "NIS+ Servers", FieldType::Array).optional(),
    FieldDescriptor::new(
        "non_local_source_routing",
        "Non-Local Source Routing",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("ntp_servers", "NTP Servers", FieldType::Array).optional(),
    FieldDescriptor::new("option_overload", "Option Overload", FieldType::U8).optional(),
    FieldDescriptor::new(
        "parameter_request_list",
        "Parameter Request List",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new(
        "path_mtu_aging_timeout",
        "Path MTU Aging Timeout",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "path_mtu_plateau_table",
        "Path MTU Plateau Table",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new(
        "perform_mask_discovery",
        "Perform Mask Discovery",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "perform_router_discovery",
        "Perform Router Discovery",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("policy_filter", "Policy Filter", FieldType::Array)
        .optional()
        .with_children(POLICY_FILTER_CHILD_FIELDS),
    FieldDescriptor::new("rebinding_time", "Rebinding Time", FieldType::U32).optional(),
    FieldDescriptor::new(
        "relay_agent_info",
        "Relay Agent Information",
        FieldType::Array,
    )
    .optional()
    .with_children(RELAY_AGENT_CHILDREN),
    FieldDescriptor::new("renewal_time", "Renewal Time", FieldType::U32).optional(),
    FieldDescriptor::new("requested_ip", "Requested IP Address", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new(
        "resource_location_server",
        "Resource Location Server",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("root_path", "Root Path", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("router", "Router", FieldType::Array).optional(),
    FieldDescriptor::new(
        "router_solicitation_address",
        "Router Solicitation Address",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new(
        "server_identifier",
        "Server Identifier",
        FieldType::Ipv4Addr,
    )
    .optional(),
    FieldDescriptor::new("static_route", "Static Route", FieldType::Array)
        .optional()
        .with_children(STATIC_ROUTE_CHILD_FIELDS),
    FieldDescriptor::new("subnet_mask", "Subnet Mask", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("swap_server", "Swap Server", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("tcp_default_ttl", "TCP Default TTL", FieldType::U8).optional(),
    FieldDescriptor::new(
        "tcp_keepalive_garbage",
        "TCP Keepalive Garbage",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "tcp_keepalive_interval",
        "TCP Keepalive Interval",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("tftp_server_name", "TFTP Server Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("time_offset", "Time Offset", FieldType::I32).optional(),
    FieldDescriptor::new("time_server", "Time Server", FieldType::Array).optional(),
    FieldDescriptor::new(
        "trailer_encapsulation",
        "Trailer Encapsulation",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("unknown_option", "Unknown Option", FieldType::Object)
        .optional()
        .with_children(UNKNOWN_OPTION_CHILDREN),
    FieldDescriptor::new(
        "vendor_class_identifier",
        "Vendor Class Identifier",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new(
        "vendor_specific_info",
        "Vendor Specific Information",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new(
        "x_window_display_manager",
        "X Window Display Manager",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new(
        "x_window_font_server",
        "X Window Font Server",
        FieldType::Array,
    )
    .optional(),
];

/// Child field descriptor indices for [`CLIENT_ID_CHILDREN`].
const CFD_CLIENT_ID_TYPE: usize = 0;
const CFD_CLIENT_ID_ID: usize = 1;

/// Child field descriptors for the Client Identifier option (option 61).
static CLIENT_ID_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Hardware Type", FieldType::U8),
    FieldDescriptor::new("id", "Client ID", FieldType::Bytes),
];

/// Child field descriptor indices for [`UNKNOWN_OPTION_CHILDREN`].
const CFD_UNKNOWN_CODE: usize = 0;
const CFD_UNKNOWN_DATA: usize = 1;

/// Child field descriptors for unknown/unrecognised DHCP options.
static UNKNOWN_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "Code", FieldType::U8),
    FieldDescriptor::new("data", "Data", FieldType::Bytes),
];

/// Child field descriptor indices for [`RELAY_AGENT_CHILDREN`].
const CFD_RELAY_SUB_OPTION: usize = 0;
const CFD_RELAY_CIRCUIT_ID: usize = 1;
const CFD_RELAY_REMOTE_ID: usize = 2;
const CFD_RELAY_DATA: usize = 3;

/// Child field descriptors for Relay Agent Information sub-options (RFC 3046).
static RELAY_AGENT_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("sub_option", "Sub-Option", FieldType::U8),
    FieldDescriptor::new("circuit_id", "Circuit ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("remote_id", "Remote ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Child field descriptor indices for [`CLASSLESS_ROUTE_CHILDREN`].
const CFD_ROUTE_PREFIX_LENGTH: usize = 0;
const CFD_ROUTE_DESTINATION: usize = 1;
const CFD_ROUTE_ROUTER: usize = 2;

/// Child field descriptors for Classless Static Route entries (RFC 3442).
static CLASSLESS_ROUTE_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8),
    FieldDescriptor::new("destination", "Destination", FieldType::Bytes),
    FieldDescriptor::new("router", "Router", FieldType::Ipv4Addr),
];

use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_i32, read_be_u16, read_be_u32};

/// Child field descriptors for Policy Filter address/mask pairs (option 21).
static POLICY_FILTER_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("address", "Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("mask", "Mask", FieldType::Ipv4Addr),
];

/// Child field descriptors for Static Route destination/router pairs (option 33).
static STATIC_ROUTE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("destination", "Destination", FieldType::Ipv4Addr),
    FieldDescriptor::new("router", "Router", FieldType::Ipv4Addr),
];

/// Minimum DHCP message size: fixed header (236) + magic cookie (4).
const MIN_MSG_SIZE: usize = 240;

/// DHCP magic cookie: 99.130.83.99 (RFC 2131, Section 3).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Returns a human-readable name for DHCP message type option values.
///
/// RFC 2132, Section 9.6 — DHCP Message Type option (option 53).
fn dhcp_message_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("DISCOVER"),
        2 => Some("OFFER"),
        3 => Some("REQUEST"),
        4 => Some("DECLINE"),
        5 => Some("ACK"),
        6 => Some("NAK"),
        7 => Some("RELEASE"),
        8 => Some("INFORM"),
        _ => None,
    }
}

/// DHCP dissector.
pub struct DhcpDissector;

/// Byte offset of the `sname` field within the fixed DHCP header.
const SNAME_OFFSET: usize = 44;
/// Byte offset just past the `sname` field (start of `file`).
const FILE_OFFSET: usize = 108;
/// Byte offset just past the `file` field (start of magic cookie).
const OPTIONS_FIXED_END: usize = 236;

/// Parse a list of IPv4 addresses from option data.
///
/// Returns `FieldValue::Array` with one `ArrayElement` per address.
fn push_ipv4_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    opt_data: &'pkt [u8],
    opt_offset: usize,
    opt_range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), opt_range);
    let mut i = 0;
    while i + 4 <= opt_data.len() {
        buf.push_field(
            fd,
            FieldValue::Ipv4Addr([
                opt_data[i],
                opt_data[i + 1],
                opt_data[i + 2],
                opt_data[i + 3],
            ]),
            (opt_offset + 2 + i)..(opt_offset + 2 + i + 4),
        );
        i += 4;
    }
    buf.end_container(arr_idx);
}

/// Parse a list of `u16` values from option data.
///
/// Returns `FieldValue::Array` with one `ArrayElement` per value.
fn push_u16_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    opt_data: &'pkt [u8],
    opt_offset: usize,
    opt_range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), opt_range);
    let mut i = 0;
    while i + 2 <= opt_data.len() {
        let val = read_be_u16(opt_data, i).unwrap_or_default();
        buf.push_field(
            fd,
            FieldValue::U16(val),
            (opt_offset + 2 + i)..(opt_offset + 2 + i + 2),
        );
        i += 2;
    }
    buf.end_container(arr_idx);
}

/// Parse pairs of IPv4 addresses from option data (e.g. policy-filter, static-route).
///
/// Each pair consists of two consecutive 4-byte addresses.  The first is named
/// `first_name` and the second `second_name` within an [`FieldValue::Object`].
fn push_ipv4_pairs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    opt_data: &'pkt [u8],
    opt_offset: usize,
    child_fields: &'static [FieldDescriptor],
    opt_range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), opt_range);
    let mut i = 0;
    while i + 8 <= opt_data.len() {
        let base = opt_offset + 2 + i;
        let obj_idx =
            buf.begin_container(&child_fields[0], FieldValue::Object(0..0), base..base + 8);
        buf.push_field(
            &child_fields[0],
            FieldValue::Ipv4Addr([
                opt_data[i],
                opt_data[i + 1],
                opt_data[i + 2],
                opt_data[i + 3],
            ]),
            base..base + 4,
        );
        buf.push_field(
            &child_fields[1],
            FieldValue::Ipv4Addr([
                opt_data[i + 4],
                opt_data[i + 5],
                opt_data[i + 6],
                opt_data[i + 7],
            ]),
            base + 4..base + 8,
        );
        buf.end_container(obj_idx);
        i += 8;
    }
    buf.end_container(arr_idx);
}

/// Single IPv4 address options: (code, FD index).
const IPV4_OPTIONS: &[(u8, usize)] = &[
    (1, FD_SUBNET_MASK),                  // RFC 2132, Section 3.3
    (16, FD_SWAP_SERVER),                 // RFC 2132, Section 3.18
    (28, FD_BROADCAST_ADDRESS),           // RFC 2132, Section 5.3
    (32, FD_ROUTER_SOLICITATION_ADDRESS), // RFC 2132, Section 5.7
    (50, FD_REQUESTED_IP),                // RFC 2132, Section 9.1
    (54, FD_SERVER_IDENTIFIER),           // RFC 2132, Section 9.7
];

/// IPv4 address list options: (code, FD index).
const IPV4_LIST_OPTIONS: &[(u8, usize)] = &[
    (3, FD_ROUTER),                    // RFC 2132, Section 3.5
    (4, FD_TIME_SERVER),               // RFC 2132, Section 3.6
    (5, FD_NAME_SERVER),               // RFC 2132, Section 3.7
    (6, FD_DNS_SERVER),                // RFC 2132, Section 3.8
    (7, FD_LOG_SERVER),                // RFC 2132, Section 3.9
    (8, FD_COOKIE_SERVER),             // RFC 2132, Section 3.10
    (9, FD_LPR_SERVER),                // RFC 2132, Section 3.11
    (10, FD_IMPRESS_SERVER),           // RFC 2132, Section 3.12
    (11, FD_RESOURCE_LOCATION_SERVER), // RFC 2132, Section 3.13
    (41, FD_NIS_SERVERS),              // RFC 2132, Section 8.2
    (42, FD_NTP_SERVERS),              // RFC 2132, Section 8.3
    (44, FD_NETBIOS_NAME_SERVER),      // RFC 2132, Section 8.5
    (45, FD_NETBIOS_DD_SERVER),        // RFC 2132, Section 8.6
    (48, FD_X_WINDOW_FONT_SERVER),     // RFC 2132, Section 8.9
    (49, FD_X_WINDOW_DISPLAY_MANAGER), // RFC 2132, Section 8.10
    (65, FD_NISPLUS_SERVERS),          // RFC 2132, Section 8.12
];

/// Single U8 options: (code, FD index).
/// Note: options 52 and 53 are handled separately (overload side-effect / message type).
const U8_OPTIONS: &[(u8, usize)] = &[
    (19, FD_IP_FORWARDING),            // RFC 2132, Section 4.1
    (20, FD_NON_LOCAL_SOURCE_ROUTING), // RFC 2132, Section 4.2
    (23, FD_DEFAULT_IP_TTL),           // RFC 2132, Section 4.5
    (27, FD_ALL_SUBNETS_LOCAL),        // RFC 2132, Section 5.2
    (29, FD_PERFORM_MASK_DISCOVERY),   // RFC 2132, Section 5.4
    (30, FD_MASK_SUPPLIER),            // RFC 2132, Section 5.5
    (31, FD_PERFORM_ROUTER_DISCOVERY), // RFC 2132, Section 5.6
    (34, FD_TRAILER_ENCAPSULATION),    // RFC 2132, Section 5.9
    (36, FD_ETHERNET_ENCAPSULATION),   // RFC 2132, Section 5.11
    (37, FD_TCP_DEFAULT_TTL),          // RFC 2132, Section 6.1
    (39, FD_TCP_KEEPALIVE_GARBAGE),    // RFC 2132, Section 6.3
    (46, FD_NETBIOS_NODE_TYPE),        // RFC 2132, Section 8.7
];

/// Single U16 options: (code, FD index).
const U16_OPTIONS: &[(u8, usize)] = &[
    (13, FD_BOOT_FILE_SIZE),               // RFC 2132, Section 3.15
    (22, FD_MAX_DATAGRAM_REASSEMBLY_SIZE), // RFC 2132, Section 4.4
    (26, FD_INTERFACE_MTU),                // RFC 2132, Section 5.1
    (57, FD_MAX_DHCP_MESSAGE_SIZE),        // RFC 2132, Section 9.10
];

/// Single U32 options: (code, FD index).
/// Note: option 2 (Time Offset) is I32 and handled separately.
const U32_OPTIONS: &[(u8, usize)] = &[
    (24, FD_PATH_MTU_AGING_TIMEOUT), // RFC 2132, Section 4.6
    (35, FD_ARP_CACHE_TIMEOUT),      // RFC 2132, Section 5.10
    (38, FD_TCP_KEEPALIVE_INTERVAL), // RFC 2132, Section 6.2
    (51, FD_LEASE_TIME),             // RFC 2132, Section 9.2
    (58, FD_RENEWAL_TIME),           // RFC 2132, Section 9.11
    (59, FD_REBINDING_TIME),         // RFC 2132, Section 9.12
];

/// String options: (code, FD index).
const STRING_OPTIONS: &[(u8, usize)] = &[
    (12, FD_HOSTNAME),         // RFC 2132, Section 3.14
    (14, FD_MERIT_DUMP_FILE),  // RFC 2132, Section 3.16
    (15, FD_DOMAIN_NAME),      // RFC 2132, Section 3.17
    (17, FD_ROOT_PATH),        // RFC 2132, Section 3.19
    (18, FD_EXTENSIONS_PATH),  // RFC 2132, Section 3.20
    (40, FD_NIS_DOMAIN),       // RFC 2132, Section 8.1
    (47, FD_NETBIOS_SCOPE),    // RFC 2132, Section 8.8
    (56, FD_MESSAGE),          // RFC 2132, Section 9.9
    (64, FD_NISPLUS_DOMAIN),   // RFC 2132, Section 8.11
    (66, FD_TFTP_SERVER_NAME), // RFC 2132, Section 9.4
    (67, FD_BOOTFILE_NAME),    // RFC 2132, Section 9.5
];

/// Look up option `code` in a table of `(code, FD_index)` tuples.
fn lookup_option(table: &[(u8, usize)], code: u8) -> Option<usize> {
    table.iter().find(|&&(c, _)| c == code).map(|&(_, fd)| fd)
}

/// Parse Relay Agent Information sub-options (RFC 3046).
///
/// Each sub-option is TLV-encoded: 1-byte type, 1-byte length, N bytes data.
fn push_relay_agent_info<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_data: &'pkt [u8],
    opt_offset: usize,
    opt_range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_RELAY_AGENT_INFO],
        FieldValue::Array(0..0),
        opt_range,
    );
    let mut i = 0;
    while i + 2 <= opt_data.len() {
        let sub_type = opt_data[i];
        let sub_len = opt_data[i + 1] as usize;
        if i + 2 + sub_len > opt_data.len() {
            break;
        }
        let sub_data = &opt_data[i + 2..i + 2 + sub_len];
        let base = opt_offset + 2 + i;
        let data_fd = match sub_type {
            1 => CFD_RELAY_CIRCUIT_ID,
            2 => CFD_RELAY_REMOTE_ID,
            _ => CFD_RELAY_DATA,
        };
        let obj_idx = buf.begin_container(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_SUB_OPTION],
            FieldValue::Object(0..0),
            base..base + 2 + sub_len,
        );
        buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_SUB_OPTION],
            FieldValue::U8(sub_type),
            base..base + 1,
        );
        buf.push_field(
            &RELAY_AGENT_CHILDREN[data_fd],
            FieldValue::Bytes(sub_data),
            base + 2..base + 2 + sub_len,
        );
        buf.end_container(obj_idx);
        i += 2 + sub_len;
    }
    buf.end_container(arr_idx);
}

/// Parse Classless Static Routes (RFC 3442).
///
/// Each route entry: 1-byte prefix length, ceil(prefix_len/8) bytes of
/// destination subnet, then 4 bytes of router address.
fn push_classless_static_routes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_data: &'pkt [u8],
    opt_offset: usize,
    opt_range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_CLASSLESS_STATIC_ROUTE],
        FieldValue::Array(0..0),
        opt_range,
    );
    let mut i = 0;
    while i < opt_data.len() {
        let prefix_len = opt_data[i];
        if prefix_len > 32 {
            break;
        }
        let octets = (prefix_len as usize).div_ceil(8);
        if i + 1 + octets + 4 > opt_data.len() {
            break;
        }
        let dest = &opt_data[i + 1..i + 1 + octets];
        let router_start = i + 1 + octets;
        let router = [
            opt_data[router_start],
            opt_data[router_start + 1],
            opt_data[router_start + 2],
            opt_data[router_start + 3],
        ];
        let base = opt_offset + 2 + i;
        let entry_len = 1 + octets + 4;
        let obj_idx = buf.begin_container(
            &CLASSLESS_ROUTE_CHILDREN[CFD_ROUTE_PREFIX_LENGTH],
            FieldValue::Object(0..0),
            base..base + entry_len,
        );
        buf.push_field(
            &CLASSLESS_ROUTE_CHILDREN[CFD_ROUTE_PREFIX_LENGTH],
            FieldValue::U8(prefix_len),
            base..base + 1,
        );
        buf.push_field(
            &CLASSLESS_ROUTE_CHILDREN[CFD_ROUTE_DESTINATION],
            FieldValue::Bytes(dest),
            base + 1..base + 1 + octets,
        );
        buf.push_field(
            &CLASSLESS_ROUTE_CHILDREN[CFD_ROUTE_ROUTER],
            FieldValue::Ipv4Addr(router),
            base + 1 + octets..base + entry_len,
        );
        buf.end_container(obj_idx);
        i += entry_len;
    }
    buf.end_container(arr_idx);
}

/// Parse a Domain Search List (RFC 3397).
///
/// The data contains DNS-encoded domain names (label-length sequences
/// terminated by a zero-length label).  Compression pointers are not valid
/// in this option and cause parsing to stop for the current domain.
fn push_domain_search_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    opt_data: &'pkt [u8],
    opt_offset: usize,
    opt_range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_DOMAIN_SEARCH],
        FieldValue::Array(0..0),
        opt_range,
    );
    let mut i = 0;
    while i < opt_data.len() {
        let domain_start = i;
        let mut has_labels = false;
        loop {
            if i >= opt_data.len() {
                break;
            }
            let label_len = opt_data[i] as usize;
            if label_len == 0 {
                i += 1;
                break;
            }
            if label_len >= 0xC0 {
                i = opt_data.len();
                break;
            }
            if i + 1 + label_len > opt_data.len() {
                i = opt_data.len();
                break;
            }
            has_labels = true;
            i += 1 + label_len;
        }
        if has_labels {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_DOMAIN_SEARCH],
                FieldValue::Bytes(&opt_data[domain_start..i]),
                (opt_offset + 2 + domain_start)..(opt_offset + 2 + i),
            );
        }
    }
    buf.end_container(arr_idx);
}

/// Parse DHCP options (RFC 2132) starting from the given position.
///
/// Returns fields extracted from options, the total bytes consumed, and an
/// optional Option Overload value (option 52).
fn parse_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    pos: usize,
) -> Result<(usize, Option<u8>), PacketError> {
    let mut overload: Option<u8> = None;
    let mut cursor = pos;

    loop {
        if cursor >= data.len() {
            break;
        }

        let code = data[cursor];

        // RFC 2132, Section 3.1 — Pad Option
        if code == 0 {
            cursor += 1;
            continue;
        }

        // RFC 2132, Section 3.2 — End Option
        if code == 255 {
            cursor += 1;
            break;
        }

        // All other options: code (1) + len (1) + data (len)
        if cursor + 1 >= data.len() {
            return Err(PacketError::Truncated {
                expected: cursor + 2,
                actual: data.len(),
            });
        }

        let len = data[cursor + 1] as usize;
        if cursor + 2 + len > data.len() {
            return Err(PacketError::Truncated {
                expected: cursor + 2 + len,
                actual: data.len(),
            });
        }

        let opt_data = &data[cursor + 2..cursor + 2 + len];
        let opt_offset = offset + cursor;
        let opt_range = opt_offset..opt_offset + 2 + len;

        // --- Table-driven parsing for common patterns ---

        // Single IPv4 address (len == 4)
        if len == 4 {
            if let Some(fd) = lookup_option(IPV4_OPTIONS, code) {
                buf.push_field(
                    &FIELD_DESCRIPTORS[fd],
                    FieldValue::Ipv4Addr([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]),
                    opt_range,
                );
                cursor += 2 + len;
                continue;
            }
        }

        // IPv4 address list (len >= 4, len % 4 == 0)
        if len >= 4 && len % 4 == 0 {
            if let Some(fd) = lookup_option(IPV4_LIST_OPTIONS, code) {
                push_ipv4_list(buf, &FIELD_DESCRIPTORS[fd], opt_data, opt_offset, opt_range);
                cursor += 2 + len;
                continue;
            }
        }

        // Single U8 (len == 1)
        if len == 1 {
            if let Some(fd) = lookup_option(U8_OPTIONS, code) {
                buf.push_field(
                    &FIELD_DESCRIPTORS[fd],
                    FieldValue::U8(opt_data[0]),
                    opt_range,
                );
                cursor += 2 + len;
                continue;
            }
        }

        // Single U16 (len == 2)
        if len == 2 {
            if let Some(fd) = lookup_option(U16_OPTIONS, code) {
                buf.push_field(
                    &FIELD_DESCRIPTORS[fd],
                    FieldValue::U16(read_be_u16(opt_data, 0)?),
                    opt_range,
                );
                cursor += 2 + len;
                continue;
            }
        }

        // Single U32 (len == 4)
        if len == 4 {
            if let Some(fd) = lookup_option(U32_OPTIONS, code) {
                buf.push_field(
                    &FIELD_DESCRIPTORS[fd],
                    FieldValue::U32(read_be_u32(opt_data, 0)?),
                    opt_range,
                );
                cursor += 2 + len;
                continue;
            }
        }

        // String options
        if let Some(fd) = lookup_option(STRING_OPTIONS, code) {
            buf.push_field(
                &FIELD_DESCRIPTORS[fd],
                FieldValue::Bytes(opt_data),
                opt_range,
            );
            cursor += 2 + len;
            continue;
        }

        // --- Special-case options not covered by tables ---
        match code {
            // RFC 2132, Section 9.3 — Option Overload
            52 if len == 1 => {
                overload = Some(opt_data[0]);
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_OPTION_OVERLOAD],
                    FieldValue::U8(opt_data[0]),
                    opt_range,
                );
            }
            // RFC 2132, Section 9.6 — DHCP Message Type
            53 if len == 1 => {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_DHCP_MESSAGE_TYPE],
                    FieldValue::U8(opt_data[0]),
                    opt_range,
                );
            }

            // RFC 2132, Section 3.4 — Time Offset (signed I32)
            2 if len == 4 => {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_TIME_OFFSET],
                    FieldValue::I32(read_be_i32(opt_data, 0)?),
                    opt_range,
                );
            }

            // RFC 2132, Section 4.7 — Path MTU Plateau Table
            25 if len >= 2 && len % 2 == 0 => {
                push_u16_list(
                    buf,
                    &FIELD_DESCRIPTORS[FD_PATH_MTU_PLATEAU_TABLE],
                    opt_data,
                    opt_offset,
                    opt_range,
                );
            }

            // RFC 2132, Section 4.3 — Policy Filter
            21 if len >= 8 && len % 8 == 0 => {
                push_ipv4_pairs(
                    buf,
                    &FIELD_DESCRIPTORS[FD_POLICY_FILTER],
                    opt_data,
                    opt_offset,
                    POLICY_FILTER_CHILD_FIELDS,
                    opt_range,
                );
            }
            // RFC 2132, Section 5.8 — Static Route
            33 if len >= 8 && len % 8 == 0 => {
                push_ipv4_pairs(
                    buf,
                    &FIELD_DESCRIPTORS[FD_STATIC_ROUTE],
                    opt_data,
                    opt_offset,
                    STATIC_ROUTE_CHILD_FIELDS,
                    opt_range,
                );
            }

            // RFC 2132, Section 8.4 — Vendor Specific Information
            43 => {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VENDOR_SPECIFIC_INFO],
                    FieldValue::Bytes(opt_data),
                    opt_range,
                );
            }
            // RFC 2132, Section 9.8 — Parameter Request List
            55 => {
                let arr_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_PARAMETER_REQUEST_LIST],
                    FieldValue::Array(0..0),
                    opt_range.clone(),
                );
                for (i, &b) in opt_data.iter().enumerate() {
                    buf.push_field(
                        &FIELD_DESCRIPTORS[FD_PARAMETER_REQUEST_LIST],
                        FieldValue::U8(b),
                        (opt_offset + 2 + i)..(opt_offset + 2 + i + 1),
                    );
                }
                buf.end_container(arr_idx);
            }
            // RFC 2132, Section 9.13 — Vendor Class Identifier
            60 => {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VENDOR_CLASS_IDENTIFIER],
                    FieldValue::Bytes(opt_data),
                    opt_range,
                );
            }
            // RFC 2132, Section 9.14 — Client Identifier
            61 if len >= 2 => {
                let hw_type = opt_data[0];
                let id_value = if hw_type == 1 && len == 7 {
                    FieldValue::MacAddr(MacAddr([
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                        opt_data[4],
                        opt_data[5],
                        opt_data[6],
                    ]))
                } else {
                    FieldValue::Bytes(&opt_data[1..])
                };
                let obj_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_CLIENT_IDENTIFIER],
                    FieldValue::Object(0..0),
                    opt_range,
                );
                buf.push_field(
                    &CLIENT_ID_CHILDREN[CFD_CLIENT_ID_TYPE],
                    FieldValue::U8(hw_type),
                    opt_offset + 2..opt_offset + 3,
                );
                buf.push_field(
                    &CLIENT_ID_CHILDREN[CFD_CLIENT_ID_ID],
                    id_value,
                    opt_offset + 3..opt_offset + 2 + len,
                );
                buf.end_container(obj_idx);
            }

            // RFC 3046 — Relay Agent Information
            82 => {
                push_relay_agent_info(buf, opt_data, opt_offset, opt_range);
            }

            // RFC 3397 — Domain Search List
            119 => {
                push_domain_search_list(buf, opt_data, opt_offset, opt_range);
            }

            // RFC 3442 — Classless Static Route
            121 => {
                push_classless_static_routes(buf, opt_data, opt_offset, opt_range);
            }

            // Generic: store as raw bytes
            _ => {
                let obj_idx = buf.begin_container(
                    &FIELD_DESCRIPTORS[FD_UNKNOWN_OPTION],
                    FieldValue::Object(0..0),
                    opt_range.clone(),
                );
                buf.push_field(
                    &UNKNOWN_OPTION_CHILDREN[CFD_UNKNOWN_CODE],
                    FieldValue::U8(code),
                    opt_range.start..opt_range.start + 1,
                );
                buf.push_field(
                    &UNKNOWN_OPTION_CHILDREN[CFD_UNKNOWN_DATA],
                    FieldValue::Bytes(opt_data),
                    opt_range.start + 2..opt_range.end,
                );
                buf.end_container(obj_idx);
            }
        }

        cursor += 2 + len;
    }

    Ok((cursor - pos, overload))
}

impl Dissector for DhcpDissector {
    fn name(&self) -> &'static str {
        "Dynamic Host Configuration Protocol"
    }

    fn short_name(&self) -> &'static str {
        "DHCP"
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
        if data.len() < MIN_MSG_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_MSG_SIZE,
                actual: data.len(),
            });
        }

        // RFC 2131, Section 2 — Verify magic cookie
        if data[236..240] != MAGIC_COOKIE {
            return Err(PacketError::InvalidHeader("DHCP magic cookie not found"));
        }

        // RFC 2131, Section 2 — Fixed header fields
        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];
        let xid = read_be_u32(data, 4)?;
        let secs = read_be_u16(data, 8)?;
        let flags = read_be_u16(data, 10)?;
        let broadcast = ((flags >> 15) & 1) as u8;

        let ciaddr: [u8; 4] = [data[12], data[13], data[14], data[15]];
        let yiaddr: [u8; 4] = [data[16], data[17], data[18], data[19]];
        let siaddr: [u8; 4] = [data[20], data[21], data[22], data[23]];
        let giaddr: [u8; 4] = [data[24], data[25], data[26], data[27]];

        // chaddr: first `hlen` bytes of the 16-byte field
        let mut chaddr_bytes = [0u8; 6];
        if hlen >= 6 {
            chaddr_bytes.copy_from_slice(&data[28..34]);
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );

        // Actually push each field to the buffer
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OP],
            FieldValue::U8(op),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HTYPE],
            FieldValue::U8(htype),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HLEN],
            FieldValue::U8(hlen),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HOPS],
            FieldValue::U8(hops),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_XID],
            FieldValue::U32(xid),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SECS],
            FieldValue::U16(secs),
            offset + 8..offset + 10,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BROADCAST],
            FieldValue::U8(broadcast),
            offset + 10..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CIADDR],
            FieldValue::Ipv4Addr(ciaddr),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_YIADDR],
            FieldValue::Ipv4Addr(yiaddr),
            offset + 16..offset + 20,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SIADDR],
            FieldValue::Ipv4Addr(siaddr),
            offset + 20..offset + 24,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_GIADDR],
            FieldValue::Ipv4Addr(giaddr),
            offset + 24..offset + 28,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHADDR],
            FieldValue::MacAddr(MacAddr(chaddr_bytes)),
            offset + 28..offset + 44,
        );

        // Parse options (after magic cookie at offset 240)
        let options_start = 240;
        let mut total_consumed = options_start;
        let mut overload_value: Option<u8> = None;

        if data.len() > options_start {
            let (opt_consumed, overload) = parse_options(buf, data, offset, options_start)?;
            total_consumed = options_start + opt_consumed;
            overload_value = overload;

            // RFC 2132, Section 9.3 — Option Overload
            // If present, the `file` and/or `sname` fields carry additional options.
            if let Some(ov) = overload {
                // Value 1 or 3: `file` field (bytes 108..236) carries options.
                if ov == 1 || ov == 3 {
                    let (_, _) =
                        parse_options(buf, &data[..OPTIONS_FIXED_END], offset, FILE_OFFSET)?;
                }
                // Value 2 or 3: `sname` field (bytes 44..108) carries options.
                if ov == 2 || ov == 3 {
                    let (_, _) = parse_options(buf, &data[..FILE_OFFSET], offset, SNAME_OFFSET)?;
                }
            }
        }

        // RFC 2131, Section 2 — sname: optional server host name, null-terminated string.
        // Only expose as a string field when the sname field is not overloaded (option 52 != 2/3).
        let sname_overloaded = matches!(overload_value, Some(2) | Some(3));
        if !sname_overloaded {
            let sname_raw = &data[SNAME_OFFSET..FILE_OFFSET];
            let sname_str = sname_raw
                .iter()
                .position(|&b| b == 0)
                .map_or(sname_raw, |n| &sname_raw[..n]);
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SNAME],
                FieldValue::Bytes(sname_str),
                offset + SNAME_OFFSET..offset + FILE_OFFSET,
            );
        }

        // RFC 2131, Section 2 — file: boot file name, null-terminated string.
        // Only expose as a string field when the file field is not overloaded (option 52 != 1/3).
        let file_overloaded = matches!(overload_value, Some(1) | Some(3));
        if !file_overloaded {
            let file_raw = &data[FILE_OFFSET..OPTIONS_FIXED_END];
            let file_str = file_raw
                .iter()
                .position(|&b| b == 0)
                .map_or(file_raw, |n| &file_raw[..n]);
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FILE],
                FieldValue::Bytes(file_str),
                offset + FILE_OFFSET..offset + OPTIONS_FIXED_END,
            );
        }

        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + total_consumed;
        }
        buf.end_layer();

        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 2131 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 2           | Protocol Summary                    | parse_dhcp_discover                         |
    // | 2           | Fixed header layout                 | parse_dhcp_discover                         |
    // | 2           | Magic cookie                        | parse_dhcp_invalid_magic_cookie             |
    // | 2           | Truncated message                   | parse_dhcp_truncated                        |
    // | 2           | All fixed fields                    | parse_dhcp_offer                            |
    // | 2           | sname field (string, not overloaded)| parse_dhcp_sname_field_exposed_when_not_overloaded |
    // | 2           | sname field (empty/zeroed)          | parse_dhcp_sname_empty_when_zeroed          |
    // | 2           | file field (string, not overloaded) | parse_dhcp_file_field_exposed_when_not_overloaded |
    // | 2           | sname suppressed when overloaded    | parse_dhcp_sname_not_exposed_when_overloaded_sname |
    // | 2           | file suppressed when overloaded     | parse_dhcp_file_not_exposed_when_overloaded_file |
    //
    // # RFC 2132 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 3.1         | Pad Option                          | parse_dhcp_discover                         |
    // | 3.2         | End Option                          | parse_dhcp_discover                         |
    // | 3.3         | Subnet Mask                         | parse_dhcp_offer                            |
    // | 3.4         | Time Offset (signed int32)          | parse_dhcp_time_offset                      |
    // | 3.4         | Time Offset (negative value)        | parse_dhcp_time_offset_negative             |
    // | 3.5         | Router                              | parse_dhcp_offer                            |
    // | 3.5         | Router (multiple)                   | parse_dhcp_multiple_routers                 |
    // | 3.6         | Time Server                         | parse_dhcp_time_server                      |
    // | 3.7         | Name Server                         | parse_dhcp_name_server                      |
    // | 3.8         | Domain Name Server                  | parse_dhcp_offer                            |
    // | 3.8         | Domain Name Server (multiple)       | parse_dhcp_multiple_dns_servers             |
    // | 3.9         | Log Server                          | parse_dhcp_log_server                       |
    // | 3.10        | Cookie Server                       | parse_dhcp_cookie_server                    |
    // | 3.11        | LPR Server                          | parse_dhcp_lpr_server                       |
    // | 3.12        | Impress Server                      | parse_dhcp_impress_server                   |
    // | 3.13        | Resource Location Server            | parse_dhcp_resource_location_server         |
    // | 3.14        | Host Name                           | parse_dhcp_hostname                         |
    // | 3.15        | Boot File Size                      | parse_dhcp_boot_file_size                   |
    // | 3.16        | Merit Dump File                     | parse_dhcp_merit_dump_file                  |
    // | 3.17        | Domain Name                         | parse_dhcp_domain_name                      |
    // | 3.18        | Swap Server                         | parse_dhcp_swap_server                      |
    // | 3.19        | Root Path                           | parse_dhcp_root_path                        |
    // | 3.20        | Extensions Path                     | parse_dhcp_extensions_path                  |
    // | 4.1         | IP Forwarding                       | parse_dhcp_ip_forwarding                    |
    // | 4.2         | Non-Local Source Routing            | parse_dhcp_non_local_source_routing         |
    // | 4.3         | Policy Filter                       | parse_dhcp_policy_filter                    |
    // | 4.4         | Max Datagram Reassembly Size        | parse_dhcp_max_datagram_reassembly_size     |
    // | 4.5         | Default IP TTL                      | parse_dhcp_default_ip_ttl                   |
    // | 4.6         | Path MTU Aging Timeout              | parse_dhcp_path_mtu_aging_timeout           |
    // | 4.7         | Path MTU Plateau Table              | parse_dhcp_path_mtu_plateau_table           |
    // | 5.1         | Interface MTU                       | parse_dhcp_interface_mtu                    |
    // | 5.2         | All Subnets Local                   | parse_dhcp_all_subnets_local                |
    // | 5.3         | Broadcast Address                   | parse_dhcp_broadcast_address                |
    // | 5.4         | Perform Mask Discovery              | parse_dhcp_perform_mask_discovery           |
    // | 5.5         | Mask Supplier                       | parse_dhcp_mask_supplier                    |
    // | 5.6         | Perform Router Discovery            | parse_dhcp_perform_router_discovery         |
    // | 5.7         | Router Solicitation Address         | parse_dhcp_router_solicitation_address      |
    // | 5.8         | Static Route                        | parse_dhcp_static_route                     |
    // | 5.9         | Trailer Encapsulation               | parse_dhcp_trailer_encapsulation            |
    // | 5.10        | ARP Cache Timeout                   | parse_dhcp_arp_cache_timeout                |
    // | 5.11        | Ethernet Encapsulation              | parse_dhcp_ethernet_encapsulation           |
    // | 6.1         | TCP Default TTL                     | parse_dhcp_tcp_default_ttl                  |
    // | 6.2         | TCP Keepalive Interval              | parse_dhcp_tcp_keepalive_interval           |
    // | 6.3         | TCP Keepalive Garbage               | parse_dhcp_tcp_keepalive_garbage            |
    // | 8.1         | NIS Domain Name                     | parse_dhcp_nis_domain                       |
    // | 8.2         | NIS Servers                         | parse_dhcp_nis_servers                      |
    // | 8.3         | NTP Servers                         | parse_dhcp_ntp_servers                      |
    // | 8.4         | Vendor Specific Information         | parse_dhcp_vendor_specific_info             |
    // | 8.5         | NetBIOS Name Server                 | parse_dhcp_netbios_name_server              |
    // | 8.6         | NetBIOS DD Server                   | parse_dhcp_netbios_dd_server                |
    // | 8.7         | NetBIOS Node Type                   | parse_dhcp_netbios_node_type                |
    // | 8.8         | NetBIOS Scope                       | parse_dhcp_netbios_scope                    |
    // | 8.9         | X Window Font Server                | parse_dhcp_x_window_font_server             |
    // | 8.10        | X Window Display Manager            | parse_dhcp_x_window_display_manager         |
    // | 8.11        | NIS+ Domain Name                    | parse_dhcp_nisplus_domain                   |
    // | 8.12        | NIS+ Servers                        | parse_dhcp_nisplus_servers                  |
    // | 9.1         | Requested IP Address                | parse_dhcp_discover                         |
    // | 9.2         | IP Address Lease Time               | parse_dhcp_offer                            |
    // | 9.3         | Option Overload                     | parse_dhcp_option_overload_*                |
    // | 9.4         | TFTP Server Name                    | parse_dhcp_tftp_server_name                 |
    // | 9.5         | Bootfile Name                       | parse_dhcp_bootfile_name                    |
    // | 9.6         | DHCP Message Type                   | parse_dhcp_discover                         |
    // | 9.7         | Server Identifier                   | parse_dhcp_offer                            |
    // | 9.8         | Parameter Request List              | parse_dhcp_parameter_request_list           |
    // | 9.9         | Message                             | parse_dhcp_message_option                   |
    // | 9.10        | Max DHCP Message Size               | parse_dhcp_max_dhcp_message_size            |
    // | 9.11        | Renewal (T1) Time                   | parse_dhcp_renewal_time                     |
    // | 9.12        | Rebinding (T2) Time                 | parse_dhcp_rebinding_time                   |
    // | 9.13        | Vendor Class Identifier             | parse_dhcp_vendor_class_identifier          |
    // | 9.14        | Client Identifier                   | parse_dhcp_client_identifier                |
    //
    // # RFC 3046 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 3.1         | Circuit ID Sub-option               | parse_dhcp_relay_agent_info                 |
    // | 3.2         | Remote ID Sub-option                | parse_dhcp_relay_agent_info                 |
    //
    // # RFC 3397 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 2           | Domain Search List encoding         | parse_dhcp_domain_search_single             |
    // | 2           | Multiple domains                    | parse_dhcp_domain_search_multiple           |
    //
    // # RFC 3442 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 3           | Classless Static Route              | parse_dhcp_classless_static_route_single     |
    // | 3           | Default + /25 routes                | parse_dhcp_classless_static_route_default_and_prefix |

    /// Build a minimal DHCP fixed header (236 bytes) + magic cookie (4 bytes).
    fn build_dhcp_base(op: u8, xid: u32, chaddr: [u8; 6], yiaddr: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 236];
        pkt[0] = op;
        pkt[1] = 1; // htype: Ethernet
        pkt[2] = 6; // hlen: 6
        // hops = 0
        pkt[4..8].copy_from_slice(&xid.to_be_bytes());
        // secs = 0, flags = 0
        // ciaddr = 0.0.0.0
        pkt[16..20].copy_from_slice(&yiaddr); // yiaddr
        // siaddr = 0.0.0.0, giaddr = 0.0.0.0
        pkt[28..34].copy_from_slice(&chaddr);
        // sname, file = zeros
        // Magic cookie
        pkt.extend_from_slice(&MAGIC_COOKIE);
        pkt
    }

    fn push_option(pkt: &mut Vec<u8>, code: u8, data: &[u8]) {
        pkt.push(code);
        pkt.push(data.len() as u8);
        pkt.extend_from_slice(data);
    }

    #[test]
    fn dhcp_dissector_metadata() {
        let d = DhcpDissector;
        assert_eq!(d.name(), "Dynamic Host Configuration Protocol");
        assert_eq!(d.short_name(), "DHCP");
    }

    #[test]
    fn parse_dhcp_discover() {
        let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut pkt = build_dhcp_base(1, 0x12345678, chaddr, [0; 4]);

        // Option 53: DHCP Discover (type=1)
        push_option(&mut pkt, 53, &[1]);
        // Option 50: Requested IP 192.168.1.100
        push_option(&mut pkt, 50, &[192, 168, 1, 100]);
        // End
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        let result = d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "DHCP");

        // Fixed header fields
        assert_eq!(
            buf.field_by_name(layer, "op").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "htype").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "hlen").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "xid").unwrap().value,
            FieldValue::U32(0x12345678)
        );
        assert_eq!(
            buf.field_by_name(layer, "chaddr").unwrap().value,
            FieldValue::MacAddr(MacAddr(chaddr))
        );

        // Options
        assert_eq!(
            buf.field_by_name(layer, "dhcp_message_type").unwrap().value,
            FieldValue::U8(1) // Discover
        );
        assert_eq!(
            buf.field_by_name(layer, "requested_ip").unwrap().value,
            FieldValue::Ipv4Addr([192, 168, 1, 100])
        );
    }

    #[test]
    fn parse_dhcp_offer() {
        let chaddr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let yiaddr = [192, 168, 1, 50];
        let mut pkt = build_dhcp_base(2, 0xAABBCCDD, chaddr, yiaddr);

        // Option 53: DHCP Offer (type=2)
        push_option(&mut pkt, 53, &[2]);
        // Option 54: Server Identifier
        push_option(&mut pkt, 54, &[192, 168, 1, 1]);
        // Option 51: Lease Time (86400 seconds = 1 day)
        push_option(&mut pkt, 51, &86400u32.to_be_bytes());
        // Option 1: Subnet Mask
        push_option(&mut pkt, 1, &[255, 255, 255, 0]);
        // Option 3: Router
        push_option(&mut pkt, 3, &[192, 168, 1, 1]);
        // Option 6: DNS Server
        push_option(&mut pkt, 6, &[8, 8, 8, 8]);
        // End
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];

        // Fixed header
        assert_eq!(
            buf.field_by_name(layer, "op").unwrap().value,
            FieldValue::U8(2)
        ); // BOOTREPLY
        assert_eq!(
            buf.field_by_name(layer, "yiaddr").unwrap().value,
            FieldValue::Ipv4Addr(yiaddr)
        );
        assert_eq!(
            buf.field_by_name(layer, "broadcast").unwrap().value,
            FieldValue::U8(0)
        );

        // Options
        assert_eq!(
            buf.field_by_name(layer, "dhcp_message_type").unwrap().value,
            FieldValue::U8(2) // Offer
        );
        assert_eq!(
            buf.field_by_name(layer, "server_identifier").unwrap().value,
            FieldValue::Ipv4Addr([192, 168, 1, 1])
        );
        assert_eq!(
            buf.field_by_name(layer, "lease_time").unwrap().value,
            FieldValue::U32(86400)
        );
        assert_eq!(
            buf.field_by_name(layer, "subnet_mask").unwrap().value,
            FieldValue::Ipv4Addr([255, 255, 255, 0])
        );
        // Router and DNS are now arrays
        let routers = buf
            .field_by_name(layer, "router")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(routers).len(), 1);
        assert_eq!(
            buf.nested_fields(routers)[0].value,
            FieldValue::Ipv4Addr([192, 168, 1, 1])
        );

        let dns = buf
            .field_by_name(layer, "dns_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(dns).len(), 1);
        assert_eq!(
            buf.nested_fields(dns)[0].value,
            FieldValue::Ipv4Addr([8, 8, 8, 8])
        );
    }

    #[test]
    fn parse_dhcp_truncated() {
        let d = DhcpDissector;
        let data = vec![0u8; 100]; // Too short
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_dhcp_invalid_magic_cookie() {
        let d = DhcpDissector;
        let mut data = vec![0u8; 240];
        let mut buf = DissectBuffer::new();
        // Wrong magic cookie
        data[236..240].copy_from_slice(&[0, 0, 0, 0]);
        let err = d.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_dhcp_no_options() {
        let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let pkt = build_dhcp_base(1, 0x11111111, chaddr, [0; 4]);
        // No options after magic cookie

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        let result = d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 240);
        assert_eq!(buf.layers()[0].name, "DHCP");
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "xid").unwrap().value,
            FieldValue::U32(0x11111111)
        );
    }

    #[test]
    fn parse_dhcp_with_offset() {
        let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut pkt = build_dhcp_base(1, 0xDEADBEEF, chaddr, [0; 4]);
        pkt.push(255); // End option

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        let offset = 42;
        d.dissect(&pkt, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range.start, 42);
        // op field should start at offset
        assert_eq!(buf.field_by_name(layer, "op").unwrap().range.start, 42);
        // xid should be at offset + 4
        assert_eq!(buf.field_by_name(layer, "xid").unwrap().range.start, 46);
    }

    #[test]
    fn parse_dhcp_unknown_option_stored_as_bytes() {
        let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut pkt = build_dhcp_base(1, 0x12345678, chaddr, [0; 4]);

        // Option 252 (unknown): some data
        push_option(&mut pkt, 252, &[0x01, 0x02, 0x03]);
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let unknown = buf.field_by_name(layer, "unknown_option").unwrap();
        let obj = unknown.value.as_container_range().unwrap();
        assert_eq!(
            buf.nested_fields(obj)
                .iter()
                .find(|f| f.name() == "code")
                .unwrap()
                .value,
            FieldValue::U8(252)
        );
        assert_eq!(
            buf.nested_fields(obj)
                .iter()
                .find(|f| f.name() == "data")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn parse_dhcp_broadcast_flag() {
        let mut pkt = build_dhcp_base(1, 0x12345678, [0; 6], [0; 4]);
        // Set broadcast flag
        pkt[10] = 0x80;
        pkt[11] = 0x00;
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "broadcast")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_dhcp_truncated_option() {
        let mut pkt = build_dhcp_base(1, 0x12345678, [0; 6], [0; 4]);
        // Option 53 with len=1 but no data byte
        pkt.push(53);
        pkt.push(1);
        // Missing the actual data byte

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        let err = d.dissect(&pkt, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    // -----------------------------------------------------------------------
    // Pattern A: Single IPv4Addr options
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_swap_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 16, &[10, 0, 0, 1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "swap_server")
                .unwrap()
                .value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_dhcp_broadcast_address() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 28, &[192, 168, 1, 255]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "broadcast_address")
                .unwrap()
                .value,
            FieldValue::Ipv4Addr([192, 168, 1, 255])
        );
    }

    #[test]
    fn parse_dhcp_router_solicitation_address() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 32, &[224, 0, 0, 2]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "router_solicitation_address")
                .unwrap()
                .value,
            FieldValue::Ipv4Addr([224, 0, 0, 2])
        );
    }

    // -----------------------------------------------------------------------
    // Pattern B: Array<IPv4Addr> options
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_multiple_routers() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 3, &[192, 168, 1, 1, 192, 168, 1, 2]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "router")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 2);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([192, 168, 1, 1])
        );
        assert_eq!(
            buf.nested_fields(arr)[1].value,
            FieldValue::Ipv4Addr([192, 168, 1, 2])
        );
    }

    #[test]
    fn parse_dhcp_multiple_dns_servers() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 6, &[8, 8, 8, 8, 8, 8, 4, 4]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "dns_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 2);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([8, 8, 8, 8])
        );
        assert_eq!(
            buf.nested_fields(arr)[1].value,
            FieldValue::Ipv4Addr([8, 8, 4, 4])
        );
    }

    #[test]
    fn parse_dhcp_time_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 4, &[10, 0, 0, 1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "time_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
    }

    #[test]
    fn parse_dhcp_name_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 5, &[10, 0, 0, 5]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "name_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 5])
        );
    }

    #[test]
    fn parse_dhcp_log_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 7, &[10, 0, 0, 7]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "log_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 7])
        );
    }

    #[test]
    fn parse_dhcp_cookie_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 8, &[10, 0, 0, 8]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "cookie_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 8])
        );
    }

    #[test]
    fn parse_dhcp_lpr_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 9, &[10, 0, 0, 9]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "lpr_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 9])
        );
    }

    #[test]
    fn parse_dhcp_impress_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 10, &[10, 0, 0, 10]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "impress_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 10])
        );
    }

    #[test]
    fn parse_dhcp_resource_location_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 11, &[10, 0, 0, 11]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "resource_location_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 11])
        );
    }

    #[test]
    fn parse_dhcp_nis_servers() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 41, &[10, 0, 0, 41]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "nis_servers")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 41])
        );
    }

    #[test]
    fn parse_dhcp_ntp_servers() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 42, &[10, 0, 0, 42, 10, 0, 0, 43]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "ntp_servers")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 2);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 42])
        );
        assert_eq!(
            buf.nested_fields(arr)[1].value,
            FieldValue::Ipv4Addr([10, 0, 0, 43])
        );
    }

    #[test]
    fn parse_dhcp_nisplus_domain() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 64, b"example.com");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "nisplus_domain")
                .unwrap()
                .value,
            FieldValue::Bytes(b"example.com")
        );
    }

    #[test]
    fn parse_dhcp_nisplus_servers() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 65, &[10, 0, 0, 64, 10, 0, 0, 65]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "nisplus_servers")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 2);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 64])
        );
        assert_eq!(
            buf.nested_fields(arr)[1].value,
            FieldValue::Ipv4Addr([10, 0, 0, 65])
        );
    }

    #[test]
    fn parse_dhcp_netbios_name_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 44, &[10, 0, 0, 44]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "netbios_name_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 44])
        );
    }

    #[test]
    fn parse_dhcp_netbios_dd_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 45, &[10, 0, 0, 45]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "netbios_dd_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 45])
        );
    }

    #[test]
    fn parse_dhcp_x_window_font_server() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 48, &[10, 0, 0, 48]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "x_window_font_server")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 48])
        );
    }

    #[test]
    fn parse_dhcp_x_window_display_manager() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 49, &[10, 0, 0, 49]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "x_window_display_manager")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 1);
        assert_eq!(
            buf.nested_fields(arr)[0].value,
            FieldValue::Ipv4Addr([10, 0, 0, 49])
        );
    }

    // -----------------------------------------------------------------------
    // Pattern C: Single U8 options
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_ip_forwarding() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 19, &[1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "ip_forwarding")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_dhcp_non_local_source_routing() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 20, &[0]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "non_local_source_routing")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_dhcp_default_ip_ttl() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 23, &[64]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "default_ip_ttl")
                .unwrap()
                .value,
            FieldValue::U8(64)
        );
    }

    #[test]
    fn parse_dhcp_all_subnets_local() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 27, &[1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "all_subnets_local")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_dhcp_perform_mask_discovery() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 29, &[0]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "perform_mask_discovery")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_dhcp_mask_supplier() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 30, &[0]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "mask_supplier")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_dhcp_perform_router_discovery() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 31, &[1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "perform_router_discovery")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_dhcp_trailer_encapsulation() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 34, &[0]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "trailer_encapsulation")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_dhcp_ethernet_encapsulation() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 36, &[0]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "ethernet_encapsulation")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_dhcp_tcp_default_ttl() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 37, &[64]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "tcp_default_ttl")
                .unwrap()
                .value,
            FieldValue::U8(64)
        );
    }

    #[test]
    fn parse_dhcp_tcp_keepalive_garbage() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 39, &[1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "tcp_keepalive_garbage")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_dhcp_netbios_node_type() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 46, &[0x08]); // H-node
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "netbios_node_type")
                .unwrap()
                .value,
            FieldValue::U8(0x08)
        );
    }

    // -----------------------------------------------------------------------
    // Pattern D: Single U16 options
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_boot_file_size() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 13, &512u16.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "boot_file_size")
                .unwrap()
                .value,
            FieldValue::U16(512)
        );
    }

    #[test]
    fn parse_dhcp_max_datagram_reassembly_size() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 22, &576u16.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "max_datagram_reassembly_size")
                .unwrap()
                .value,
            FieldValue::U16(576)
        );
    }

    #[test]
    fn parse_dhcp_interface_mtu() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 26, &1500u16.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "interface_mtu")
                .unwrap()
                .value,
            FieldValue::U16(1500)
        );
    }

    #[test]
    fn parse_dhcp_max_dhcp_message_size() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 57, &1500u16.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "max_dhcp_message_size")
                .unwrap()
                .value,
            FieldValue::U16(1500)
        );
    }

    // -----------------------------------------------------------------------
    // Pattern E: Single U32 options
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_time_offset() {
        // RFC 2132, Section 3.4 — Time Offset is a signed 32-bit integer.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 2, &3600i32.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "time_offset")
                .unwrap()
                .value,
            FieldValue::I32(3600)
        );
    }

    #[test]
    fn parse_dhcp_time_offset_negative() {
        // RFC 2132, Section 3.4 — Value is signed (2's complement); negative offsets must parse
        // correctly.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 2, &(-18000i32).to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "time_offset")
                .unwrap()
                .value,
            FieldValue::I32(-18000)
        );
    }

    #[test]
    fn parse_dhcp_path_mtu_aging_timeout() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 24, &600u32.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "path_mtu_aging_timeout")
                .unwrap()
                .value,
            FieldValue::U32(600)
        );
    }

    #[test]
    fn parse_dhcp_arp_cache_timeout() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 35, &900u32.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "arp_cache_timeout")
                .unwrap()
                .value,
            FieldValue::U32(900)
        );
    }

    #[test]
    fn parse_dhcp_tcp_keepalive_interval() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 38, &7200u32.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "tcp_keepalive_interval")
                .unwrap()
                .value,
            FieldValue::U32(7200)
        );
    }

    #[test]
    fn parse_dhcp_renewal_time() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 58, &43200u32.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "renewal_time")
                .unwrap()
                .value,
            FieldValue::U32(43200)
        );
    }

    #[test]
    fn parse_dhcp_rebinding_time() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 59, &75600u32.to_be_bytes());
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "rebinding_time")
                .unwrap()
                .value,
            FieldValue::U32(75600)
        );
    }

    // -----------------------------------------------------------------------
    // Pattern F: String options
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_hostname() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 12, b"myhost");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "hostname")
                .unwrap()
                .value,
            FieldValue::Bytes(b"myhost")
        );
    }

    #[test]
    fn parse_dhcp_merit_dump_file() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 14, b"/var/dump");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "merit_dump_file")
                .unwrap()
                .value,
            FieldValue::Bytes(b"/var/dump")
        );
    }

    #[test]
    fn parse_dhcp_domain_name() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 15, b"example.com");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "domain_name")
                .unwrap()
                .value,
            FieldValue::Bytes(b"example.com")
        );
    }

    #[test]
    fn parse_dhcp_root_path() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 17, b"/tftpboot");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "root_path")
                .unwrap()
                .value,
            FieldValue::Bytes(b"/tftpboot")
        );
    }

    #[test]
    fn parse_dhcp_extensions_path() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 18, b"/ext");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "extensions_path")
                .unwrap()
                .value,
            FieldValue::Bytes(b"/ext")
        );
    }

    #[test]
    fn parse_dhcp_nis_domain() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 40, b"nis.example");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "nis_domain")
                .unwrap()
                .value,
            FieldValue::Bytes(b"nis.example")
        );
    }

    #[test]
    fn parse_dhcp_netbios_scope() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 47, b"scope");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "netbios_scope")
                .unwrap()
                .value,
            FieldValue::Bytes(b"scope")
        );
    }

    #[test]
    fn parse_dhcp_message_option() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 56, b"NAK reason");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "message")
                .unwrap()
                .value,
            FieldValue::Bytes(b"NAK reason")
        );
    }

    // -----------------------------------------------------------------------
    // Pattern G: Array<U16>
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_path_mtu_plateau_table() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let mut opt_data = Vec::new();
        opt_data.extend_from_slice(&68u16.to_be_bytes());
        opt_data.extend_from_slice(&296u16.to_be_bytes());
        opt_data.extend_from_slice(&508u16.to_be_bytes());
        push_option(&mut pkt, 25, &opt_data);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = buf
            .field_by_name(&buf.layers()[0], "path_mtu_plateau_table")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        assert_eq!(buf.nested_fields(arr).len(), 3);
        assert_eq!(buf.nested_fields(arr)[0].value, FieldValue::U16(68));
        assert_eq!(buf.nested_fields(arr)[1].value, FieldValue::U16(296));
        assert_eq!(buf.nested_fields(arr)[2].value, FieldValue::U16(508));
    }

    // -----------------------------------------------------------------------
    // Pattern H: Structured / raw bytes
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_vendor_specific_info() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 43, &[0x01, 0x02, 0x03]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "vendor_specific_info")
                .unwrap()
                .value,
            FieldValue::Bytes(&[0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn parse_dhcp_parameter_request_list() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 55, &[1, 3, 6, 15, 28, 51]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let field = buf
            .field_by_name(&buf.layers()[0], "parameter_request_list")
            .unwrap();
        let expected_codes: &[u8] = &[1, 3, 6, 15, 28, 51];
        match &field.value {
            FieldValue::Array(elements) => {
                assert_eq!(buf.nested_fields(elements).len(), expected_codes.len());
                for (elem, &code) in buf.nested_fields(elements).iter().zip(expected_codes) {
                    assert_eq!(elem.value, FieldValue::U8(code));
                }
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    #[test]
    fn parse_dhcp_vendor_class_identifier() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 60, b"MSFT 5.0");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "vendor_class_identifier")
                .unwrap()
                .value,
            FieldValue::Bytes(b"MSFT 5.0")
        );
    }

    #[test]
    fn parse_dhcp_client_identifier() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // type(1) = Ethernet, then MAC address
        push_option(&mut pkt, 61, &[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let field = buf
            .field_by_name(&buf.layers()[0], "client_identifier")
            .unwrap();
        match &field.value {
            FieldValue::Object(fields) => {
                assert_eq!(buf.nested_fields(fields)[0].name(), "type");
                assert_eq!(buf.nested_fields(fields)[0].value, FieldValue::U8(1));
                assert_eq!(buf.nested_fields(fields)[1].name(), "id");
                assert_eq!(
                    buf.nested_fields(fields)[1].value,
                    FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
                );
            }
            other => panic!("expected Object, got {other:?}"),
        }
    }

    #[test]
    fn parse_dhcp_client_identifier_non_ethernet() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // type(0) = non-Ethernet, arbitrary identifier
        push_option(&mut pkt, 61, &[0x00, 0x01, 0x02, 0x03]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        let field = buf
            .field_by_name(&buf.layers()[0], "client_identifier")
            .unwrap();
        match &field.value {
            FieldValue::Object(fields) => {
                assert_eq!(buf.nested_fields(fields)[0].name(), "type");
                assert_eq!(buf.nested_fields(fields)[0].value, FieldValue::U8(0));
                assert_eq!(buf.nested_fields(fields)[1].name(), "id");
                assert_eq!(
                    buf.nested_fields(fields)[1].value,
                    FieldValue::Bytes(&[0x01, 0x02, 0x03])
                );
            }
            other => panic!("expected Object, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Option 82: Relay Agent Information (RFC 3046)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Option 121: Classless Static Route (RFC 3442)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Option 119: Domain Search List (RFC 3397)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Option 52: Option Overload
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_option_overload_file() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // Place options in the `file` field (bytes 108..236)
        // Put a hostname option there
        pkt[108] = 12; // option 12 = hostname
        pkt[109] = 4;
        pkt[110..114].copy_from_slice(b"test");
        pkt[114] = 255; // end

        // In the regular options area, add option overload = 1 (file field)
        push_option(&mut pkt, 52, &[1]);
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        // Should find the hostname from the file field
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "hostname")
                .unwrap()
                .value,
            FieldValue::Bytes(b"test")
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "option_overload")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_dhcp_option_overload_sname() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // Place options in the `sname` field (bytes 44..108)
        pkt[44] = 15; // option 15 = domain name
        pkt[45] = 7;
        pkt[46..53].copy_from_slice(b"foo.bar");
        pkt[53] = 255; // end

        // In the regular options area, add option overload = 2 (sname field)
        push_option(&mut pkt, 52, &[2]);
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "domain_name")
                .unwrap()
                .value,
            FieldValue::Bytes(b"foo.bar")
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "option_overload")
                .unwrap()
                .value,
            FieldValue::U8(2)
        );
    }

    #[test]
    fn parse_dhcp_option_overload_both() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // sname field: hostname
        pkt[44] = 12;
        pkt[45] = 5;
        pkt[46..51].copy_from_slice(b"sname");
        pkt[51] = 255;

        // file field: domain name
        pkt[108] = 15;
        pkt[109] = 8;
        pkt[110..118].copy_from_slice(b"file.com");
        pkt[118] = 255;

        // Regular options: overload = 3 (both)
        push_option(&mut pkt, 52, &[3]);
        pkt.push(255);

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "hostname")
                .unwrap()
                .value,
            FieldValue::Bytes(b"sname")
        );
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "domain_name")
                .unwrap()
                .value,
            FieldValue::Bytes(b"file.com")
        );
    }

    // -----------------------------------------------------------------------
    // Options 66/67: TFTP server name / Bootfile name (RFC 2132, Sec 9.4/9.5)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_tftp_server_name() {
        // RFC 2132, Section 9.4 — TFTP server name (option 66), NVT ASCII string.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 66, b"tftp.example.com");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "tftp_server_name")
                .unwrap()
                .value,
            FieldValue::Bytes(b"tftp.example.com")
        );
    }

    #[test]
    fn parse_dhcp_bootfile_name() {
        // RFC 2132, Section 9.5 — Bootfile name (option 67), NVT ASCII string.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 67, b"pxelinux.0");
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "bootfile_name")
                .unwrap()
                .value,
            FieldValue::Bytes(b"pxelinux.0")
        );
    }

    // -----------------------------------------------------------------------
    // sname and file fixed header fields (RFC 2131, Section 2)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_sname_field_exposed_when_not_overloaded() {
        // RFC 2131, Section 2 — sname: optional server host name, null-terminated string.
        // When option 52 is absent the field should be exposed as "sname".
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // Write "myserver\0" into sname (bytes 44..108)
        pkt[44..52].copy_from_slice(b"myserver");
        pkt[52] = 0; // null-terminator
        pkt.push(255); // end option

        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "sname").unwrap().value,
            FieldValue::Bytes(b"myserver")
        );
    }

    #[test]
    fn parse_dhcp_sname_empty_when_zeroed() {
        // When sname bytes are all zeros the exposed value should be an empty string.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // sname is already zeroed by build_dhcp_base
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "sname").unwrap().value,
            FieldValue::Bytes(b"")
        );
    }

    #[test]
    fn parse_dhcp_file_field_exposed_when_not_overloaded() {
        // RFC 2131, Section 2 — file: boot file name, null-terminated string.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        pkt[108..118].copy_from_slice(b"pxelinux.0");
        pkt[118] = 0;
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "file").unwrap().value,
            FieldValue::Bytes(b"pxelinux.0")
        );
    }

    #[test]
    fn parse_dhcp_sname_not_exposed_when_overloaded_sname() {
        // When option 52 = 2 (sname carries options), sname must NOT appear as a string field.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        pkt[44] = 15; // domain-name option in sname
        pkt[45] = 7;
        pkt[46..53].copy_from_slice(b"foo.bar");
        pkt[53] = 255;
        push_option(&mut pkt, 52, &[2]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(buf.field_by_name(&buf.layers()[0], "sname").is_none());
    }

    #[test]
    fn parse_dhcp_file_not_exposed_when_overloaded_file() {
        // When option 52 = 1 (file carries options), file must NOT appear as a string field.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        pkt[108] = 12; // hostname option in file
        pkt[109] = 4;
        pkt[110..114].copy_from_slice(b"test");
        pkt[114] = 255;
        push_option(&mut pkt, 52, &[1]);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(buf.field_by_name(&buf.layers()[0], "file").is_none());
    }
}
