//! DHCP (Dynamic Host Configuration Protocol) dissector.
//!
//! ## References
//! - RFC 2131: <https://www.rfc-editor.org/rfc/rfc2131>
//! - RFC 2132 (DHCP Options): <https://www.rfc-editor.org/rfc/rfc2132>
//! - RFC 951 (BOOTP): <https://www.rfc-editor.org/rfc/rfc951>
//! - RFC 1542 (BOOTP Clarifications): <https://www.rfc-editor.org/rfc/rfc1542>
//! - RFC 4390 (DHCP over InfiniBand): <https://www.rfc-editor.org/rfc/rfc4390>
//! - RFC 3203 (DHCP FORCERENEW): <https://www.rfc-editor.org/rfc/rfc3203>
//! - RFC 4388 (DHCP Leasequery): <https://www.rfc-editor.org/rfc/rfc4388>
//! - RFC 6926 (DHCPv4 Bulk Leasequery): <https://www.rfc-editor.org/rfc/rfc6926>
//! - RFC 7724 (Active DHCPv4 Lease Query): <https://www.rfc-editor.org/rfc/rfc7724>
//! - RFC 3396 (Long Options): <https://www.rfc-editor.org/rfc/rfc3396>
//! - RFC 4361 (Client Identifier): <https://www.rfc-editor.org/rfc/rfc4361>
//! - RFC 3046 (Relay Agent Information): <https://www.rfc-editor.org/rfc/rfc3046>
//! - RFC 3397 (Domain Search List): <https://www.rfc-editor.org/rfc/rfc3397>
//! - RFC 3442 (Classless Static Route): <https://www.rfc-editor.org/rfc/rfc3442>
//! - RFC 6842 (Client Identifier in Responses): <https://www.rfc-editor.org/rfc/rfc6842>
//! - RFC 1035 (DNS name compression, used by Domain Search List): <https://www.rfc-editor.org/rfc/rfc1035>
//! - RFC 3527 (Link Selection sub-option): <https://www.rfc-editor.org/rfc/rfc3527>
//! - RFC 3993 (Subscriber-ID sub-option): <https://www.rfc-editor.org/rfc/rfc3993>
//! - RFC 4014 (RADIUS Attributes sub-option): <https://www.rfc-editor.org/rfc/rfc4014>
//! - RFC 2865 (RADIUS attribute encoding): <https://www.rfc-editor.org/rfc/rfc2865>
//! - RFC 4030 (Authentication sub-option): <https://www.rfc-editor.org/rfc/rfc4030>
//! - RFC 4243 (Vendor-Specific sub-option): <https://www.rfc-editor.org/rfc/rfc4243>
//! - RFC 5010 (Relay Agent Flags sub-option): <https://www.rfc-editor.org/rfc/rfc5010>
//! - RFC 5107 (Server Identifier Override sub-option): <https://www.rfc-editor.org/rfc/rfc5107>
//! - RFC 3004 (User Class): <https://www.rfc-editor.org/rfc/rfc3004>
//! - RFC 4039 (Rapid Commit): <https://www.rfc-editor.org/rfc/rfc4039>
//! - RFC 4702 (Client FQDN): <https://www.rfc-editor.org/rfc/rfc4702>
//! - RFC 3118 (Authentication): <https://www.rfc-editor.org/rfc/rfc3118>
//! - RFC 4578 (PXE options 93, 94, 97): <https://www.rfc-editor.org/rfc/rfc4578>
//! - RFC 8925 (IPv6-Only Preferred): <https://www.rfc-editor.org/rfc/rfc8925>
//! - RFC 8910 (Captive-Portal): <https://www.rfc-editor.org/rfc/rfc8910>
//! - RFC 3011 (Subnet Selection): <https://www.rfc-editor.org/rfc/rfc3011>
//! - RFC 3925 (Vendor-Identifying Vendor Options): <https://www.rfc-editor.org/rfc/rfc3925>
//! - RFC 6704 (Forcerenew Nonce Authentication): <https://www.rfc-editor.org/rfc/rfc6704>
//! - RFC 5859 (TFTP Server Address): <https://www.rfc-editor.org/rfc/rfc5859>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, MacAddr, format_fqdn_labels,
    format_utf8_lossy,
};

/// Resolve a [`FieldValue::Scratch`] value to the bytes it refers to, so the
/// shared formatters see a [`FieldValue::Bytes`].
///
/// Values of split options (RFC 3396, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc3396#section-7>) that straddle two split portions are
/// assembled in the scratch buffer.
fn resolve_scratch<'a>(value: &FieldValue<'a>, ctx: &FormatContext<'a>) -> FieldValue<'a> {
    match value {
        FieldValue::Scratch(r) => FieldValue::Bytes(
            ctx.scratch
                .get(r.start as usize..r.end as usize)
                .unwrap_or_default(),
        ),
        other => other.clone(),
    }
}

/// [`format_utf8_lossy`] that also accepts scratch-buffer values.
fn format_text(
    value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    format_utf8_lossy(&resolve_scratch(value, ctx), ctx, w)
}

/// [`format_fqdn_labels`] that also accepts scratch-buffer values.
fn format_fqdn(
    value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    format_fqdn_labels(&resolve_scratch(value, ctx), ctx, w)
}

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
const FD_VEND: usize = 83;
const FD_CHADDR_BYTES: usize = 84;
const FD_MOBILE_IP_HOME_AGENT: usize = 85;
const FD_SMTP_SERVER: usize = 86;
const FD_POP3_SERVER: usize = 87;
const FD_NNTP_SERVER: usize = 88;
const FD_WWW_SERVER: usize = 89;
const FD_FINGER_SERVER: usize = 90;
const FD_IRC_SERVER: usize = 91;
const FD_STREETTALK_SERVER: usize = 92;
const FD_STDA_SERVER: usize = 93;
const FD_USER_CLASS: usize = 94;
const FD_RAPID_COMMIT: usize = 95;
const FD_CLIENT_FQDN: usize = 96;
const FD_AUTHENTICATION: usize = 97;
const FD_CLIENT_SYSTEM_ARCHITECTURE: usize = 98;
const FD_CLIENT_NII: usize = 99;
const FD_CLIENT_MACHINE_ID: usize = 100;
const FD_IPV6_ONLY_PREFERRED: usize = 101;
const FD_CAPTIVE_PORTAL: usize = 102;
const FD_SUBNET_SELECTION: usize = 103;
const FD_VI_VENDOR_CLASS: usize = 104;
const FD_VI_VENDOR_SPECIFIC_INFO: usize = 105;
const FD_FORCERENEW_NONCE_CAPABLE: usize = 106;
const FD_TFTP_SERVER_ADDRESS: usize = 107;
const FD_SPLIT_OPTION: usize = 108;

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
    // RFC 2131, Section 2 — chaddr holds `hlen` octets.
    // <https://www.rfc-editor.org/rfc/rfc2131#section-2>
    // A 6-octet address is emitted as `chaddr`; any other length as
    // `chaddr_bytes` (see `CHADDR_BYTES` below).
    FieldDescriptor::new("chaddr", "Client Hardware Address", FieldType::MacAddr).optional(),
    FieldDescriptor::new("sname", "Server Host Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
    FieldDescriptor::new("file", "Boot File Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
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
        .with_format_fn(format_text),
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
        .with_format_fn(format_text),
    FieldDescriptor::new("domain_search", "Domain Search List", FieldType::Array).optional(),
    FieldDescriptor::new(
        "ethernet_encapsulation",
        "Ethernet Encapsulation",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("extensions_path", "Extensions Path", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
    FieldDescriptor::new("hostname", "Host Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
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
        .with_format_fn(format_text),
    FieldDescriptor::new("message", "Message", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
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
        .with_format_fn(format_text),
    FieldDescriptor::new("nis_domain", "NIS Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
    FieldDescriptor::new("nis_servers", "NIS Servers", FieldType::Array).optional(),
    FieldDescriptor::new("nisplus_domain", "NIS+ Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
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
        .with_format_fn(format_text),
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
        .with_format_fn(format_text),
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
    // RFC 951, Section 3 — BOOTP vendor-specific area (only when the RFC 2132
    // magic cookie is absent)
    // <https://www.rfc-editor.org/rfc/rfc951#section-3>
    FieldDescriptor::new("vend", "Vendor-Specific Area", FieldType::Bytes).optional(),
    // RFC 2131, Section 2 — chaddr when `hlen` is not 6 (the first `hlen`
    // octets, at most 16)
    // <https://www.rfc-editor.org/rfc/rfc2131#section-2>
    FieldDescriptor::new("chaddr_bytes", "Client Hardware Address", FieldType::Bytes).optional(),
    // RFC 2132, Sections 8.13-8.21 — IPv4 server address lists (options 68-76)
    // <https://www.rfc-editor.org/rfc/rfc2132#section-8.13>
    FieldDescriptor::new(
        "mobile_ip_home_agent",
        "Mobile IP Home Agent",
        FieldType::Array,
    )
    .optional(),
    FieldDescriptor::new("smtp_server", "SMTP Server", FieldType::Array).optional(),
    FieldDescriptor::new("pop3_server", "POP3 Server", FieldType::Array).optional(),
    FieldDescriptor::new("nntp_server", "NNTP Server", FieldType::Array).optional(),
    FieldDescriptor::new("www_server", "Default WWW Server", FieldType::Array).optional(),
    FieldDescriptor::new("finger_server", "Default Finger Server", FieldType::Array).optional(),
    FieldDescriptor::new("irc_server", "Default IRC Server", FieldType::Array).optional(),
    FieldDescriptor::new("streettalk_server", "StreetTalk Server", FieldType::Array).optional(),
    FieldDescriptor::new(
        "stda_server",
        "StreetTalk Directory Assistance Server",
        FieldType::Array,
    )
    .optional(),
    // RFC 3004, Section 4 — User Class (option 77); each element is one
    // User Class Data instance.
    // <https://www.rfc-editor.org/rfc/rfc3004#section-4>
    FieldDescriptor::new("user_class", "User Class", FieldType::Array).optional(),
    // RFC 4039, Section 4 — Rapid Commit (option 80), zero-length.
    // <https://www.rfc-editor.org/rfc/rfc4039#section-4>
    FieldDescriptor::new("rapid_commit", "Rapid Commit", FieldType::Bytes).optional(),
    // RFC 4702, Section 2 — Client FQDN (option 81).
    // <https://www.rfc-editor.org/rfc/rfc4702#section-2>
    FieldDescriptor::new("client_fqdn", "Client FQDN", FieldType::Object)
        .optional()
        .with_children(CLIENT_FQDN_CHILDREN),
    // RFC 3118, Section 2 — Authentication (option 90).
    // <https://www.rfc-editor.org/rfc/rfc3118#section-2>
    FieldDescriptor::new("authentication", "Authentication", FieldType::Object)
        .optional()
        .with_children(AUTHENTICATION_CHILDREN),
    // RFC 4578, Section 2.1 — Client System Architecture Type (option 93).
    // <https://www.rfc-editor.org/rfc/rfc4578#section-2.1>
    FieldDescriptor::new(
        "client_system_architecture",
        "Client System Architecture",
        FieldType::Array,
    )
    .optional(),
    // RFC 4578, Section 2.2 — Client Network Interface Identifier (option 94).
    // <https://www.rfc-editor.org/rfc/rfc4578#section-2.2>
    FieldDescriptor::new(
        "client_network_interface_identifier",
        "Client Network Interface Identifier",
        FieldType::Object,
    )
    .optional()
    .with_children(CLIENT_NII_CHILDREN),
    // RFC 4578, Section 2.3 — Client Machine Identifier (option 97).
    // <https://www.rfc-editor.org/rfc/rfc4578#section-2.3>
    FieldDescriptor::new(
        "client_machine_identifier",
        "Client Machine Identifier",
        FieldType::Object,
    )
    .optional()
    .with_children(CLIENT_MACHINE_ID_CHILDREN),
    // RFC 8925, Section 3.1 — IPv6-Only Preferred (option 108), V6ONLY_WAIT.
    // <https://www.rfc-editor.org/rfc/rfc8925#section-3.1>
    FieldDescriptor::new("ipv6_only_preferred", "IPv6-Only Preferred", FieldType::U32).optional(),
    // RFC 8910, Section 2.1 — Captive-Portal (option 114), a URI.
    // <https://www.rfc-editor.org/rfc/rfc8910#section-2.1>
    FieldDescriptor::new("captive_portal", "Captive-Portal URI", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
    // RFC 3011, Section 3 — Subnet Selection (option 118).
    // <https://www.rfc-editor.org/rfc/rfc3011#section-3>
    FieldDescriptor::new("subnet_selection", "Subnet Selection", FieldType::Ipv4Addr).optional(),
    // RFC 3925, Section 3 — V-I Vendor Class (option 124).
    // <https://www.rfc-editor.org/rfc/rfc3925#section-3>
    FieldDescriptor::new("vi_vendor_class", "V-I Vendor Class", FieldType::Array)
        .optional()
        .with_children(VENDOR_ENTRY_CHILDREN),
    // RFC 3925, Section 4 — V-I Vendor-Specific Information (option 125).
    // <https://www.rfc-editor.org/rfc/rfc3925#section-4>
    FieldDescriptor::new(
        "vi_vendor_specific_info",
        "V-I Vendor-Specific Information",
        FieldType::Array,
    )
    .optional()
    .with_children(VENDOR_ENTRY_CHILDREN),
    // RFC 6704, Section 3.1.1 — FORCERENEW_NONCE_CAPABLE (option 145).
    // <https://www.rfc-editor.org/rfc/rfc6704#section-3.1.1>
    FieldDescriptor::new(
        "forcerenew_nonce_capable",
        "Forcerenew Nonce Capable",
        FieldType::Array,
    )
    .optional(),
    // RFC 5859, Section 3 — TFTP Server Address (option 150).
    // <https://www.rfc-editor.org/rfc/rfc5859#section-3>
    FieldDescriptor::new(
        "tftp_server_address",
        "TFTP Server Address",
        FieldType::Array,
    )
    .optional(),
    // RFC 3396, Section 7 — an option found more than once, with its split
    // portions. <https://www.rfc-editor.org/rfc/rfc3396#section-7>
    FieldDescriptor::new("split_option", "Split Option", FieldType::Object)
        .optional()
        .with_children(SPLIT_OPTION_CHILDREN),
];

/// Child field descriptor indices for [`SPLIT_OPTION_CHILDREN`].
const CFD_SPLIT_CODE: usize = 0;
const CFD_SPLIT_FRAGMENTS: usize = 1;

/// Children of a `split_option` object.
///
/// RFC 3396, Section 6 — <https://www.rfc-editor.org/rfc/rfc3396#section-6>
static SPLIT_OPTION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "Option Code", FieldType::U8),
    FieldDescriptor::new("fragments", "Split Portions", FieldType::Array)
        .with_children(SPLIT_FRAGMENT_CHILDREN),
];

/// Child field descriptor indices for [`SPLIT_FRAGMENT_CHILDREN`].
const CFD_FRAGMENT_LENGTH: usize = 0;
const CFD_FRAGMENT_DATA: usize = 1;

/// Children of one split portion: its length octet and data.
static SPLIT_FRAGMENT_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("data", "Data", FieldType::Bytes),
];

/// Descriptor for one split portion Object inside `fragments`.
static FD_SPLIT_FRAGMENT: FieldDescriptor =
    FieldDescriptor::new("fragment", "Split Portion", FieldType::Object)
        .with_children(SPLIT_FRAGMENT_CHILDREN);

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
const CFD_RELAY_LINK_SELECTION: usize = 4;
const CFD_RELAY_SUBSCRIBER_ID: usize = 5;
const CFD_RELAY_RADIUS_ATTRIBUTES: usize = 6;
const CFD_RELAY_ALGORITHM: usize = 7;
const CFD_RELAY_RDM: usize = 8;
const CFD_RELAY_REPLAY_DETECTION: usize = 9;
const CFD_RELAY_RELAY_IDENTIFIER: usize = 10;
const CFD_RELAY_AUTH_INFO: usize = 11;
const CFD_RELAY_VENDOR_SPECIFIC: usize = 12;
const CFD_RELAY_FLAGS: usize = 13;
const CFD_RELAY_UNICAST: usize = 14;
const CFD_RELAY_SERVER_ID_OVERRIDE: usize = 15;

/// Child field descriptors for Relay Agent Information sub-options (RFC 3046
/// and the sub-option RFCs listed on [`relay_agent_sub_option_name`]).
static RELAY_AGENT_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("sub_option", "Sub-Option", FieldType::U8),
    FieldDescriptor::new("circuit_id", "Circuit ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("remote_id", "Remote ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    // RFC 3527, Section 3 — <https://www.rfc-editor.org/rfc/rfc3527#section-3>
    FieldDescriptor::new("link_selection", "Link Selection", FieldType::Ipv4Addr).optional(),
    // RFC 3993, Section 3 — <https://www.rfc-editor.org/rfc/rfc3993#section-3>
    FieldDescriptor::new("subscriber_id", "Subscriber-ID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_text),
    // RFC 4014, Section 3 — <https://www.rfc-editor.org/rfc/rfc4014#section-3>
    FieldDescriptor::new("radius_attributes", "RADIUS Attributes", FieldType::Array)
        .optional()
        .with_children(RADIUS_ATTRIBUTE_CHILDREN),
    // RFC 4030, Section 4 — <https://www.rfc-editor.org/rfc/rfc4030#section-4>
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8).optional(),
    FieldDescriptor::new("rdm", "Replay Detection Method", FieldType::U8).optional(),
    FieldDescriptor::new("replay_detection", "Replay Detection", FieldType::Bytes).optional(),
    FieldDescriptor::new("relay_identifier", "Relay Identifier", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "authentication_information",
        "Authentication Information",
        FieldType::Bytes,
    )
    .optional(),
    // RFC 4243, Section 3 — <https://www.rfc-editor.org/rfc/rfc4243#section-3>
    FieldDescriptor::new(
        "vendor_specific",
        "Vendor-Specific Information",
        FieldType::Array,
    )
    .optional()
    .with_children(VENDOR_ENTRY_CHILDREN),
    // RFC 5010, Section 3 — <https://www.rfc-editor.org/rfc/rfc5010#section-3>
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("unicast", "Unicast", FieldType::U8).optional(),
    // RFC 5107, Section 4 — <https://www.rfc-editor.org/rfc/rfc5107#section-4>
    FieldDescriptor::new(
        "server_identifier_override",
        "Server Identifier Override",
        FieldType::Ipv4Addr,
    )
    .optional(),
];

/// Child field descriptor indices for [`RADIUS_ATTRIBUTE_CHILDREN`].
const CFD_RADIUS_TYPE: usize = 0;
const CFD_RADIUS_VALUE: usize = 1;

/// Child field descriptors for one RADIUS attribute (RFC 2865, Section 5)
/// inside the RADIUS Attributes sub-option (RFC 4014, Section 3).
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
static RADIUS_ATTRIBUTE_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Object container for one RADIUS attribute.
static FD_RADIUS_ATTRIBUTE: FieldDescriptor =
    FieldDescriptor::new("radius_attribute", "RADIUS Attribute", FieldType::Object)
        .with_children(RADIUS_ATTRIBUTE_CHILDREN);

/// Child field descriptor indices for [`VENDOR_ENTRY_CHILDREN`].
const CFD_VENDOR_ENTERPRISE_NUMBER: usize = 0;
const CFD_VENDOR_DATA: usize = 1;

/// Child field descriptors for one enterprise-number / data entry, shared by
/// the Vendor-Specific relay sub-option (RFC 4243, Section 3) and the V-I
/// Vendor Class / V-I Vendor-Specific Information options (RFC 3925,
/// Sections 3 and 4).
/// <https://www.rfc-editor.org/rfc/rfc4243#section-3>
/// <https://www.rfc-editor.org/rfc/rfc3925#section-3>
static VENDOR_ENTRY_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("enterprise_number", "Enterprise Number", FieldType::U32),
    FieldDescriptor::new("data", "Data", FieldType::Bytes),
];

/// Object container for one enterprise-number / data entry.
static FD_VENDOR_ENTRY: FieldDescriptor =
    FieldDescriptor::new("vendor", "Vendor", FieldType::Object)
        .with_children(VENDOR_ENTRY_CHILDREN);

/// Child field descriptor indices for [`CLIENT_FQDN_CHILDREN`].
const CFD_FQDN_FLAGS: usize = 0;
const CFD_FQDN_RCODE1: usize = 1;
const CFD_FQDN_RCODE2: usize = 2;
const CFD_FQDN_DOMAIN_NAME: usize = 3;

/// Child field descriptors for the Client FQDN option (RFC 4702, Section 2).
/// <https://www.rfc-editor.org/rfc/rfc4702#section-2>
static CLIENT_FQDN_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("rcode1", "RCODE1", FieldType::U8),
    FieldDescriptor::new("rcode2", "RCODE2", FieldType::U8),
    // RFC 4702, Section 2.3 — canonical wire format (E = 1) or the deprecated
    // ASCII encoding (E = 0); `format_fqdn_labels` falls back to UTF-8 text
    // when the bytes are not length-prefixed labels.
    // <https://www.rfc-editor.org/rfc/rfc4702#section-2.3>
    FieldDescriptor::new("domain_name", "Domain Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_fqdn),
];

/// Child field descriptor indices for [`AUTHENTICATION_CHILDREN`].
const CFD_AUTH_PROTOCOL: usize = 0;
const CFD_AUTH_ALGORITHM: usize = 1;
const CFD_AUTH_RDM: usize = 2;
const CFD_AUTH_REPLAY_DETECTION: usize = 3;
const CFD_AUTH_INFORMATION: usize = 4;

/// Child field descriptors for the Authentication option (RFC 3118, Section 2).
/// <https://www.rfc-editor.org/rfc/rfc3118#section-2>
static AUTHENTICATION_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("protocol", "Protocol", FieldType::U8),
    FieldDescriptor::new("algorithm", "Algorithm", FieldType::U8),
    FieldDescriptor::new("rdm", "Replay Detection Method", FieldType::U8),
    FieldDescriptor::new("replay_detection", "Replay Detection", FieldType::Bytes),
    FieldDescriptor::new(
        "authentication_information",
        "Authentication Information",
        FieldType::Bytes,
    )
    .optional(),
];

/// Child field descriptors for the Client Network Interface Identifier
/// option (RFC 4578, Section 2.2).
/// <https://www.rfc-editor.org/rfc/rfc4578#section-2.2>
static CLIENT_NII_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("major", "Major", FieldType::U8),
    FieldDescriptor::new("minor", "Minor", FieldType::U8),
];

/// Child field descriptors for the Client Machine Identifier option
/// (RFC 4578, Section 2.3).
/// <https://www.rfc-editor.org/rfc/rfc4578#section-2.3>
static CLIENT_MACHINE_ID_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("machine_identifier", "Machine Identifier", FieldType::Bytes),
];

/// Returns a human-readable name for Relay Agent Information sub-option codes.
///
/// RFC 3046 (1, 2); RFC 3256 (4); RFC 3527 (5); RFC 3993 (6); RFC 4014 (7);
/// RFC 4030 (8); RFC 4243 (9); RFC 5010 (10); RFC 5107 (11); RFC 6925 (12).
fn relay_agent_sub_option_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("Agent Circuit ID"),
        2 => Some("Agent Remote ID"),
        4 => Some("DOCSIS Device Class"),
        5 => Some("Link Selection"),
        6 => Some("Subscriber-ID"),
        7 => Some("RADIUS Attributes"),
        8 => Some("Authentication"),
        9 => Some("Vendor-Specific Information"),
        10 => Some("Relay Agent Flags"),
        11 => Some("Server Identifier Override"),
        12 => Some("Relay Agent Identifier"),
        _ => None,
    }
}

/// Descriptor for the Relay Agent sub-option Object container.
///
/// `display_fn` is invoked by
/// [`DissectBuffer::resolve_container_display_name`] with the container's
/// children, so the outer label resolves to the sub-option name (e.g.
/// "Agent Circuit ID") instead of colliding with the inner `Sub-Option`
/// field.
static FD_RELAY_AGENT_SUB_OPTION: FieldDescriptor = FieldDescriptor {
    name: "relay_agent_sub_option",
    display_name: "Relay Agent Sub-Option",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("sub_option", FieldValue::U8(c)) => relay_agent_sub_option_name(*c),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

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

/// Minimum BOOTP message size: fixed header (236) + 64-octet `vend` area.
///
/// RFC 951, Section 3 — "vend    64      optional vendor-specific area"
/// <https://www.rfc-editor.org/rfc/rfc951#section-3>
const MIN_BOOTP_MSG_SIZE: usize = 300;

/// Byte offset of the `chaddr` field within the fixed header.
const CHADDR_OFFSET: usize = 28;

/// Size of the `chaddr` field in octets.
///
/// RFC 2131, Section 2 — <https://www.rfc-editor.org/rfc/rfc2131#section-2>
const CHADDR_SIZE: usize = 16;

/// DHCP magic cookie: 99.130.83.99 (RFC 2131, Section 3).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Returns a human-readable name for DHCP message type option values.
///
/// RFC 2132, Section 9.6 — DHCP Message Type option (option 53).
/// <https://www.rfc-editor.org/rfc/rfc2132#section-9.6>
///
/// Later values are listed in the IANA "BOOTP and DHCP Parameters" registry,
/// "Message Type 53 Values":
/// <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53>
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
        // RFC 3203, Section 4 — <https://www.rfc-editor.org/rfc/rfc3203#section-4>
        9 => Some("FORCERENEW"),
        // RFC 4388, Section 6.1 — <https://www.rfc-editor.org/rfc/rfc4388#section-6.1>
        10 => Some("LEASEQUERY"),
        11 => Some("LEASEUNASSIGNED"),
        12 => Some("LEASEUNKNOWN"),
        13 => Some("LEASEACTIVE"),
        // RFC 6926, Section 6.2.1 — <https://www.rfc-editor.org/rfc/rfc6926#section-6.2.1>
        14 => Some("BULKLEASEQUERY"),
        15 => Some("LEASEQUERYDONE"),
        // RFC 7724, Section 5.2.1 — <https://www.rfc-editor.org/rfc/rfc7724#section-5.2.1>
        16 => Some("ACTIVELEASEQUERY"),
        17 => Some("LEASEQUERYSTATUS"),
        18 => Some("TLS"),
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
    (118, FD_SUBNET_SELECTION), // RFC 3011, Section 3 — <https://www.rfc-editor.org/rfc/rfc3011#section-3>
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
    (69, FD_SMTP_SERVER), // RFC 2132, Section 8.14 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.14>
    (70, FD_POP3_SERVER), // RFC 2132, Section 8.15 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.15>
    (71, FD_NNTP_SERVER), // RFC 2132, Section 8.16 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.16>
    (72, FD_WWW_SERVER), // RFC 2132, Section 8.17 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.17>
    (73, FD_FINGER_SERVER), // RFC 2132, Section 8.18 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.18>
    (74, FD_IRC_SERVER), // RFC 2132, Section 8.19 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.19>
    (75, FD_STREETTALK_SERVER), // RFC 2132, Section 8.20 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.20>
    (76, FD_STDA_SERVER), // RFC 2132, Section 8.21 — <https://www.rfc-editor.org/rfc/rfc2132#section-8.21>
    (150, FD_TFTP_SERVER_ADDRESS), // RFC 5859, Section 3 — <https://www.rfc-editor.org/rfc/rfc5859#section-3>
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
    (108, FD_IPV6_ONLY_PREFERRED), // RFC 8925, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc8925#section-3.1>
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
    (114, FD_CAPTIVE_PORTAL), // RFC 8910, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc8910#section-2.1>
];

/// Look up option `code` in a table of `(code, FD_index)` tuples.
fn lookup_option(table: &[(u8, usize)], code: u8) -> Option<usize> {
    table.iter().find(|&&(c, _)| c == code).map(|&(_, fd)| fd)
}

/// Fixed part of the Authentication option: Protocol (1), Algorithm (1),
/// RDM (1), Replay Detection (8).
///
/// RFC 3118, Section 2 — <https://www.rfc-editor.org/rfc/rfc3118#section-2>
const DHCP_AUTH_FIXED_LEN: usize = 11;

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
        let obj_idx = buf.begin_container(
            &FD_RELAY_AGENT_SUB_OPTION,
            FieldValue::Object(0..0),
            base..base + 2 + sub_len,
        );
        buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_SUB_OPTION],
            FieldValue::U8(sub_type),
            base..base + 1,
        );
        if !push_relay_sub_option_value(buf, sub_type, sub_data, base + 2) {
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_DATA],
                FieldValue::Bytes(sub_data),
                base + 2..base + 2 + sub_len,
            );
        }
        buf.end_container(obj_idx);
        i += 2 + sub_len;
    }
    buf.end_container(arr_idx);
}

/// Push the decoded value of one Relay Agent Information sub-option.
///
/// `start` is the absolute offset of `data`. Returns `false` when the
/// sub-option is unknown or its data does not match the defined format, in
/// which case the caller pushes the raw bytes instead.
fn push_relay_sub_option_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    sub_type: u8,
    data: &'pkt [u8],
    start: usize,
) -> bool {
    let end = start + data.len();
    match (sub_type, data) {
        // RFC 3046, Section 3.1 — Agent Circuit ID Sub-option
        // <https://www.rfc-editor.org/rfc/rfc3046#section-3.1>
        (1, _) => buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_CIRCUIT_ID],
            FieldValue::Bytes(data),
            start..end,
        ),
        // RFC 3046, Section 3.2 — Agent Remote ID Sub-option
        // <https://www.rfc-editor.org/rfc/rfc3046#section-3.2>
        (2, _) => buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_REMOTE_ID],
            FieldValue::Bytes(data),
            start..end,
        ),
        // RFC 3527, Section 3 — "The sub-option contains a single IP address
        // that is an address contained in a subnet."
        // <https://www.rfc-editor.org/rfc/rfc3527#section-3>
        (5, &[a, b, c, d]) => buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_LINK_SELECTION],
            FieldValue::Ipv4Addr([a, b, c, d]),
            start..end,
        ),
        // RFC 3993, Section 3 — "The Subscriber-ID is an ASCII string"
        // <https://www.rfc-editor.org/rfc/rfc3993#section-3>
        (6, _) => buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_SUBSCRIBER_ID],
            FieldValue::Bytes(data),
            start..end,
        ),
        // RFC 4014, Section 3 — "The RADIUS attributes are encoded according
        // to the encoding rules in RFC 2865, in octets o1...oN."
        // <https://www.rfc-editor.org/rfc/rfc4014#section-3>
        (7, _) if radius_attributes_valid(data) => {
            push_radius_attributes(buf, data, start);
        }
        // RFC 4030, Section 4 — Algorithm (1), MBZ/RDM (1), Replay Detection
        // (8), Relay Identifier (4), Authentication Information (variable).
        // <https://www.rfc-editor.org/rfc/rfc4030#section-4>
        (8, _) if data.len() >= RELAY_AUTH_FIXED_LEN => {
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_ALGORITHM],
                FieldValue::U8(data[0]),
                start..start + 1,
            );
            // "Four bits are reserved for future use.  These bits SHOULD be
            // set to zero and MUST NOT be used when the suboption is
            // processed." — the RDM is the low nibble.
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_RDM],
                FieldValue::U8(data[1] & 0x0F),
                start + 1..start + 2,
            );
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_REPLAY_DETECTION],
                FieldValue::Bytes(&data[2..10]),
                start + 2..start + 10,
            );
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_RELAY_IDENTIFIER],
                FieldValue::Bytes(&data[10..14]),
                start + 10..start + 14,
            );
            if data.len() > RELAY_AUTH_FIXED_LEN {
                buf.push_field(
                    &RELAY_AGENT_CHILDREN[CFD_RELAY_AUTH_INFO],
                    FieldValue::Bytes(&data[RELAY_AUTH_FIXED_LEN..]),
                    start + RELAY_AUTH_FIXED_LEN..end,
                );
            }
        }
        // RFC 4243, Section 3 — Enterprise NumberN (4), DataLenN (1),
        // Suboption DataN; "the minimum length is 4 bytes."
        // <https://www.rfc-editor.org/rfc/rfc4243#section-3>
        (9, _) if vendor_entries_valid(data) => {
            push_vendor_entries(
                buf,
                &RELAY_AGENT_CHILDREN[CFD_RELAY_VENDOR_SPECIFIC],
                data,
                start,
                start..end,
            );
        }
        // RFC 5010, Section 3 — "Length   The suboption length, 1 octet."
        // "U:  UNICAST flag" is the most significant bit.
        // <https://www.rfc-editor.org/rfc/rfc5010#section-3>
        (10, &[flags]) => {
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_FLAGS],
                FieldValue::U8(flags),
                start..end,
            );
            buf.push_field(
                &RELAY_AGENT_CHILDREN[CFD_RELAY_UNICAST],
                FieldValue::U8(flags >> 7),
                start..end,
            );
        }
        // RFC 5107, Section 4 — Server Identifier Override carries one IPv4
        // address.
        // <https://www.rfc-editor.org/rfc/rfc5107#section-4>
        (11, &[a, b, c, d]) => buf.push_field(
            &RELAY_AGENT_CHILDREN[CFD_RELAY_SERVER_ID_OVERRIDE],
            FieldValue::Ipv4Addr([a, b, c, d]),
            start..end,
        ),
        _ => return false,
    }
    true
}

/// Fixed part of the relay Authentication sub-option: Algorithm (1),
/// MBZ/RDM (1), Replay Detection (8), Relay Identifier (4).
///
/// RFC 4030, Section 4 — <https://www.rfc-editor.org/rfc/rfc4030#section-4>
const RELAY_AUTH_FIXED_LEN: usize = 14;

/// Whether `data` is a non-empty sequence of RADIUS attributes that exactly
/// fills it.
///
/// RFC 2865, Section 5 — "The Length field is one octet, and indicates the
/// length of this Attribute including the Type, Length and Value fields."
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
fn radius_attributes_valid(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            return false;
        }
        let attr_len = data[i + 1] as usize;
        if attr_len < 2 || i + attr_len > data.len() {
            return false;
        }
        i += attr_len;
    }
    true
}

/// Push the RADIUS attributes of a RADIUS Attributes sub-option (RFC 4014,
/// Section 3). The caller has checked [`radius_attributes_valid`].
/// <https://www.rfc-editor.org/rfc/rfc4014#section-3>
fn push_radius_attributes<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], start: usize) {
    let arr_idx = buf.begin_container(
        &RELAY_AGENT_CHILDREN[CFD_RELAY_RADIUS_ATTRIBUTES],
        FieldValue::Array(0..0),
        start..start + data.len(),
    );
    let mut i = 0;
    while i + 2 <= data.len() {
        let attr_len = data[i + 1] as usize;
        if attr_len < 2 || i + attr_len > data.len() {
            break;
        }
        let base = start + i;
        let obj_idx = buf.begin_container(
            &FD_RADIUS_ATTRIBUTE,
            FieldValue::Object(0..0),
            base..base + attr_len,
        );
        buf.push_field(
            &RADIUS_ATTRIBUTE_CHILDREN[CFD_RADIUS_TYPE],
            FieldValue::U8(data[i]),
            base..base + 1,
        );
        buf.push_field(
            &RADIUS_ATTRIBUTE_CHILDREN[CFD_RADIUS_VALUE],
            FieldValue::Bytes(&data[i + 2..i + attr_len]),
            base + 2..base + attr_len,
        );
        buf.end_container(obj_idx);
        i += attr_len;
    }
    buf.end_container(arr_idx);
}

/// Whether `data` is a non-empty sequence of (enterprise-number (4),
/// data-len (1), data) entries that exactly fills it.
///
/// Shared by RFC 4243, Section 3 and RFC 3925, Sections 3 and 4.
/// <https://www.rfc-editor.org/rfc/rfc4243#section-3>
/// <https://www.rfc-editor.org/rfc/rfc3925#section-3>
fn vendor_entries_valid(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < data.len() {
        if i + 5 > data.len() {
            return false;
        }
        let data_len = data[i + 4] as usize;
        if i + 5 + data_len > data.len() {
            return false;
        }
        i += 5 + data_len;
    }
    true
}

/// Push (enterprise-number, data) entries as an array of objects. The caller
/// has checked [`vendor_entries_valid`]. `start` is the absolute offset of
/// `data`.
fn push_vendor_entries<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    data: &'pkt [u8],
    start: usize,
    range: core::ops::Range<usize>,
) {
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), range);
    let mut i = 0;
    while i + 5 <= data.len() {
        let data_len = data[i + 4] as usize;
        if i + 5 + data_len > data.len() {
            break;
        }
        let enterprise = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let base = start + i;
        let obj_idx = buf.begin_container(
            &FD_VENDOR_ENTRY,
            FieldValue::Object(0..0),
            base..base + 5 + data_len,
        );
        buf.push_field(
            &VENDOR_ENTRY_CHILDREN[CFD_VENDOR_ENTERPRISE_NUMBER],
            FieldValue::U32(enterprise),
            base..base + 4,
        );
        buf.push_field(
            &VENDOR_ENTRY_CHILDREN[CFD_VENDOR_DATA],
            FieldValue::Bytes(&data[i + 5..i + 5 + data_len]),
            base + 5..base + 5 + data_len,
        );
        buf.end_container(obj_idx);
        i += 5 + data_len;
    }
    buf.end_container(arr_idx);
}

/// Whether `data` is a non-empty sequence of User Class Data instances
/// (UC_Len_i (1) + data) that exactly fills it.
///
/// RFC 3004, Section 4 — "The value in UC_Len_i does not include the length
/// field itself and MUST be non-zero."
/// <https://www.rfc-editor.org/rfc/rfc3004#section-4>
fn user_class_valid(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < data.len() {
        let uc_len = data[i] as usize;
        if uc_len == 0 || i + 1 + uc_len > data.len() {
            return false;
        }
        i += 1 + uc_len;
    }
    true
}

/// Push the User Class Data instances of option 77 (RFC 3004, Section 4).
/// The caller has checked [`user_class_valid`].
/// <https://www.rfc-editor.org/rfc/rfc3004#section-4>
fn push_user_class<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    start: usize,
    range: core::ops::Range<usize>,
) {
    let fd = &FIELD_DESCRIPTORS[FD_USER_CLASS];
    let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), range);
    let mut i = 0;
    while i < data.len() {
        let uc_len = data[i] as usize;
        if uc_len == 0 || i + 1 + uc_len > data.len() {
            break;
        }
        buf.push_field(
            fd,
            FieldValue::Bytes(&data[i + 1..i + 1 + uc_len]),
            start + i + 1..start + i + 1 + uc_len,
        );
        i += 1 + uc_len;
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
/// terminated by a zero-length label or a compression pointer).  Per
/// RFC 3397, Section 2 — <https://www.rfc-editor.org/rfc/rfc3397#section-2>
/// — compression pointers following RFC 1035, Section 4.1.4 are permitted;
/// each name record therefore ends with either the terminating zero label
/// or a 2-octet compression pointer (top two bits = 11).
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
        let mut truncated = false;
        loop {
            if i >= opt_data.len() {
                truncated = has_labels;
                break;
            }
            let label_len = opt_data[i] as usize;
            // RFC 1035, Section 4.1.4 — pointer prefix bits are 11xxxxxx.
            if label_len & 0xC0 == 0xC0 {
                // Compression pointer is 2 octets; if truncated, stop.
                if i + 2 > opt_data.len() {
                    truncated = true;
                    break;
                }
                i += 2;
                has_labels = true;
                break;
            }
            if label_len == 0 {
                i += 1;
                break;
            }
            if i + 1 + label_len > opt_data.len() {
                truncated = true;
                break;
            }
            has_labels = true;
            i += 1 + label_len;
        }
        if has_labels && !truncated {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_DOMAIN_SEARCH],
                FieldValue::Bytes(&opt_data[domain_start..i]),
                (opt_offset + 2 + domain_start)..(opt_offset + 2 + i),
            );
        }
        if truncated {
            break;
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
    split: &CodeSet,
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

        if split.contains(code) {
            // RFC 3396, Section 7 — <https://www.rfc-editor.org/rfc/rfc3396#section-7>:
            // split portions are decoded together by `push_split_options`
            // once every area has been scanned.
            cursor += 2 + len;
            continue;
        }

        let opt_data = &data[cursor + 2..cursor + 2 + len];
        if let Some(v) = decode_option(buf, code, opt_data, offset + cursor) {
            overload = Some(v);
        }
        cursor += 2 + len;
    }

    Ok((cursor - pos, overload))
}

/// A set of option codes.
#[derive(Default)]
struct CodeSet([u64; 4]);

impl CodeSet {
    fn insert(&mut self, code: u8) {
        self.0[(code >> 6) as usize] |= 1 << (code & 63);
    }

    fn contains(&self, code: u8) -> bool {
        self.0[(code >> 6) as usize] & (1 << (code & 63)) != 0
    }

    fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }
}

/// One option instance in the aggregate option buffer.
#[derive(Clone, Copy)]
struct OptionInstance {
    code: u8,
    /// Offset of the code octet within the DHCP message.
    pos: u32,
    /// Length of the option data.
    len: u8,
}

/// Call `f(code, pos, len)` for every option in `area[start..]`, stopping at
/// the End option or at the first truncated option (reported later by
/// [`parse_options`]). Returns the Option Overload value, if seen.
fn scan_area(area: &[u8], start: usize, f: &mut impl FnMut(u8, usize, u8)) -> Option<u8> {
    let mut overload = None;
    let mut cursor = start;
    while let Some(&code) = area.get(cursor) {
        match code {
            // RFC 2132, Sections 3.1 and 3.2 — Pad and End.
            // <https://www.rfc-editor.org/rfc/rfc2132#section-3.1>
            0 => {
                cursor += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let Some(&len) = area.get(cursor + 1) else {
            break;
        };
        if cursor + 2 + len as usize > area.len() {
            break;
        }
        if code == OPTION_OVERLOAD && len == 1 {
            overload = Some(area[cursor + 2]);
        }
        f(code, cursor, len);
        cursor += 2 + len as usize;
    }
    overload
}

/// Call `f(code, pos, len)` for every option in the aggregate option buffer,
/// in its order.
///
/// RFC 3396, Section 5 — <https://www.rfc-editor.org/rfc/rfc3396#section-5>:
/// "The aggregate option buffer is made up of the optional parameters field,
/// the file field, and the sname field, in that order." The `file` and
/// `sname` fields are part of it only when option 52 says so (RFC 2132,
/// Section 9.3 — <https://www.rfc-editor.org/rfc/rfc2132#section-9.3>).
fn scan_aggregate(data: &[u8], mut f: impl FnMut(u8, usize, u8)) {
    let overload = scan_area(data, MIN_MSG_SIZE, &mut f);
    if matches!(overload, Some(1 | 3)) {
        scan_area(&data[..OPTIONS_FIXED_END], FILE_OFFSET, &mut f);
    }
    if matches!(overload, Some(2 | 3)) {
        scan_area(&data[..FILE_OFFSET], SNAME_OFFSET, &mut f);
    }
}

/// Codes that occur more than once in the aggregate option buffer, which
/// RFC 3396, Section 7 — <https://www.rfc-editor.org/rfc/rfc3396#section-7> —
/// requires to be concatenated: "When a decoding agent is scanning an
/// incoming DHCP packet's option buffer and finds two or more options with
/// the same option code, it MUST consider them to be split portions of an
/// option".
///
/// Option Overload (52) is excluded: it selects which fields form the
/// aggregate option buffer, so it is taken from its first instance. Only two
/// small bit sets are used, so ordinary messages pay a single extra pass.
fn split_codes(data: &[u8]) -> CodeSet {
    let mut seen = CodeSet::default();
    let mut split = CodeSet::default();
    scan_aggregate(data, |code, _, _| {
        if code == OPTION_OVERLOAD {
            return;
        }
        if seen.contains(code) {
            split.insert(code);
        }
        seen.insert(code);
    });
    split
}

/// The instances of the split codes, in aggregate option buffer order.
///
/// Built only when a message has split options.
struct OptionInstances {
    items: Vec<OptionInstance>,
}

impl OptionInstances {
    fn collect(data: &[u8], split: &CodeSet) -> Self {
        let mut items = Vec::new();
        scan_aggregate(data, |code, pos, len| {
            if split.contains(code) {
                items.push(OptionInstance {
                    code,
                    pos: pos as u32,
                    len,
                });
            }
        });
        Self { items }
    }

    fn as_slice(&self) -> &[OptionInstance] {
        &self.items
    }
}

/// Option Overload option code (RFC 2132, Section 9.3 —
/// <https://www.rfc-editor.org/rfc/rfc2132#section-9.3>).
const OPTION_OVERLOAD: u8 = 52;

/// Push one `split_option` object per split code, followed by the fields
/// decoded from the concatenated value.
///
/// RFC 3396, Section 7 — <https://www.rfc-editor.org/rfc/rfc3396#section-7>:
/// the decoding agent "MUST treat the contents of that option as a single
/// option, and the contents MUST be reassembled in the order that was
/// described above under encoding agent behavior."
///
/// The concatenated value is decoded into a temporary buffer (this is the
/// only path that allocates). Its fields are then copied into `buf`: a byte
/// value that lies inside one split portion points at the packet, and one
/// that straddles portions is copied to the scratch buffer. A field range
/// that straddles portions covers everything from its first to its last
/// octet in the message.
fn push_split_options<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    split: &CodeSet,
) {
    if split.is_empty() {
        return;
    }
    let instances = &OptionInstances::collect(data, split);
    let mut done = CodeSet::default();
    // Scratch space reused for every split code.
    let mut value: Vec<u8> = Vec::new();
    let mut tmp_store = DissectBuffer::new();
    for first in instances.as_slice() {
        let code = first.code;
        if !split.contains(code) || done.contains(code) {
            continue;
        }
        done.insert(code);
        let parts = || instances.as_slice().iter().filter(move |i| i.code == code);

        let lo = parts().map(|i| i.pos as usize).min().unwrap_or_default();
        let hi = parts()
            .map(|i| i.pos as usize + 2 + i.len as usize)
            .max()
            .unwrap_or_default();
        let obj = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_SPLIT_OPTION],
            FieldValue::Object(0..0),
            offset + lo..offset + hi,
        );
        buf.push_field(
            &SPLIT_OPTION_CHILDREN[CFD_SPLIT_CODE],
            FieldValue::U8(code),
            offset + first.pos as usize..offset + first.pos as usize + 1,
        );
        let arr = buf.begin_container(
            &SPLIT_OPTION_CHILDREN[CFD_SPLIT_FRAGMENTS],
            FieldValue::Array(0..0),
            offset + lo..offset + hi,
        );
        for part in parts() {
            let p = part.pos as usize;
            let end = p + 2 + part.len as usize;
            let frag = buf.begin_container(
                &FD_SPLIT_FRAGMENT,
                FieldValue::Object(0..0),
                offset + p..offset + end,
            );
            buf.push_field(
                &SPLIT_FRAGMENT_CHILDREN[CFD_FRAGMENT_LENGTH],
                FieldValue::U8(part.len),
                offset + p + 1..offset + p + 2,
            );
            buf.push_field(
                &SPLIT_FRAGMENT_CHILDREN[CFD_FRAGMENT_DATA],
                FieldValue::Bytes(&data[p + 2..end]),
                offset + p + 2..offset + end,
            );
            buf.end_container(frag);
        }
        buf.end_container(arr);
        buf.end_container(obj);

        value.clear();
        for part in parts() {
            let p = part.pos as usize + 2;
            value.extend_from_slice(&data[p..p + part.len as usize]);
        }
        let map = SplitMap {
            data,
            offset,
            instances,
            code,
        };
        // The value is decoded as if its code octet were at virtual offset 0.
        let tmp = tmp_store.clear_into();
        decode_option(tmp, code, &value, 0);
        if !is_generic(tmp) {
            map.copy_fields(buf, tmp, &value);
            continue;
        }
        // Some senders repeat a fixed-length option (e.g. two DHCP Message
        // Type options) rather than split it. When the concatenated value
        // does not have the option's format but a single portion does, each
        // portion is decoded on its own so that its meaning is not lost.
        let first_data = &data[first.pos as usize + 2..first.pos as usize + 2 + first.len as usize];
        let probe = tmp_store.clear_into();
        decode_option(probe, code, first_data, 0);
        if is_generic(probe) {
            let tmp = tmp_store.clear_into();
            decode_option(tmp, code, &value, 0);
            map.copy_fields(buf, tmp, &value);
        } else {
            for part in parts() {
                let p = part.pos as usize;
                decode_option(
                    buf,
                    code,
                    &data[p + 2..p + 2 + part.len as usize],
                    offset + p,
                );
            }
        }
    }
}

/// Whether `tmp` holds only the generic `unknown_option` rendering, i.e. no
/// typed decoder accepted the value.
fn is_generic(tmp: &DissectBuffer<'_>) -> bool {
    tmp.fields()
        .first()
        .is_none_or(|f| core::ptr::eq(f.descriptor, &FIELD_DESCRIPTORS[FD_UNKNOWN_OPTION]))
}

/// Maps positions in a concatenated split option value back to the message.
struct SplitMap<'a, 'pkt> {
    data: &'pkt [u8],
    offset: usize,
    instances: &'a OptionInstances,
    code: u8,
}

impl<'pkt> SplitMap<'_, 'pkt> {
    /// The split portions of the option, in aggregate order.
    fn parts(&self) -> impl Iterator<Item = &OptionInstance> {
        let code = self.code;
        self.instances
            .as_slice()
            .iter()
            .filter(move |i| i.code == code)
    }

    /// Locate value octet `i`: the message offset of its split portion's
    /// data and the index of `i` within that portion.
    fn locate(&self, i: usize) -> Option<(usize, usize, usize)> {
        let mut base = 0;
        for part in self.parts() {
            let len = part.len as usize;
            if i < base + len {
                return Some((part.pos as usize + 2, i - base, len));
            }
            base += len;
        }
        None
    }

    /// Message offset of virtual position `v` (the code octet is at 0, the
    /// length octet at 1 and value octet `i` at `2 + i`).
    fn position(&self, v: usize) -> usize {
        if v < 2 {
            let first = self.parts().next().map_or(0, |p| p.pos as usize);
            return first + v;
        }
        match self.locate(v - 2) {
            Some((data_pos, i, _)) => data_pos + i,
            None => self
                .parts()
                .last()
                .map_or(0, |p| p.pos as usize + 1 + p.len as usize),
        }
    }

    /// Absolute range covering virtual range `a..b`.
    fn range(&self, a: usize, b: usize) -> core::ops::Range<usize> {
        let start = self.position(a);
        if b <= a {
            return self.offset + start..self.offset + start;
        }
        let end = self.position(b - 1) + 1;
        let (lo, hi) = if end > start {
            (start, end)
        } else {
            (end - 1, start + 1)
        };
        self.offset + lo..self.offset + hi
    }

    /// The packet bytes for value octets `i..i + len`, when they lie inside
    /// one split portion.
    fn packet_bytes(&self, i: usize, len: usize) -> Option<&'pkt [u8]> {
        let (data_pos, at, part_len) = self.locate(i)?;
        (at + len <= part_len).then(|| &self.data[data_pos + at..data_pos + at + len])
    }

    /// Copy the fields decoded from the concatenated `value` into `buf`.
    fn copy_fields(&self, buf: &mut DissectBuffer<'pkt>, tmp: &DissectBuffer<'_>, value: &[u8]) {
        let base = buf.field_count();
        let value_start = value.as_ptr() as usize;
        let value_end = value_start + value.len();
        // Index of a borrowed slice within `value`, if it points into it.
        let index_of = |ptr: *const u8, len: usize| {
            let p = ptr as usize;
            (p >= value_start && p + len <= value_end && len > 0).then(|| p - value_start)
        };
        for f in tmp.fields() {
            let v = match &f.value {
                FieldValue::Bytes(b) => match index_of(b.as_ptr(), b.len())
                    .and_then(|i| self.packet_bytes(i, b.len()))
                {
                    Some(pkt) => FieldValue::Bytes(pkt),
                    None if b.is_empty() => FieldValue::Bytes(&[]),
                    None => FieldValue::Scratch(buf.push_scratch(b)),
                },
                FieldValue::Str(s) => match index_of(s.as_ptr(), s.len())
                    .and_then(|i| self.packet_bytes(i, s.len()))
                    .and_then(|pkt| core::str::from_utf8(pkt).ok())
                {
                    Some(pkt) => FieldValue::Str(pkt),
                    None if s.is_empty() => FieldValue::Str(""),
                    None => FieldValue::Scratch(buf.push_scratch(s.as_bytes())),
                },
                FieldValue::Scratch(r) => FieldValue::Scratch(
                    buf.push_scratch(
                        tmp.scratch()
                            .get(r.start as usize..r.end as usize)
                            .unwrap_or_default(),
                    ),
                ),
                FieldValue::Array(r) => FieldValue::Array(r.start + base..r.end + base),
                FieldValue::Object(r) => FieldValue::Object(r.start + base..r.end + base),
                FieldValue::U8(x) => FieldValue::U8(*x),
                FieldValue::U16(x) => FieldValue::U16(*x),
                FieldValue::U32(x) => FieldValue::U32(*x),
                FieldValue::U64(x) => FieldValue::U64(*x),
                FieldValue::I32(x) => FieldValue::I32(*x),
                FieldValue::Ipv4Addr(x) => FieldValue::Ipv4Addr(*x),
                FieldValue::Ipv6Addr(x) => FieldValue::Ipv6Addr(*x),
                FieldValue::MacAddr(x) => FieldValue::MacAddr(*x),
            };
            buf.push_field(f.descriptor, v, self.range(f.range.start, f.range.end));
        }
    }
}

/// Decode the value of one option and push its fields.
///
/// `opt_offset` is the absolute offset of the option's code octet; the value
/// starts two octets later. Returns the Option Overload value when `code` is
/// 52 (RFC 2132, Section 9.3 —
/// <https://www.rfc-editor.org/rfc/rfc2132#section-9.3>).
fn decode_option<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    code: u8,
    opt_data: &'pkt [u8],
    opt_offset: usize,
) -> Option<u8> {
    let len = opt_data.len();
    let opt_range = opt_offset..opt_offset + 2 + len;
    let mut overload: Option<u8> = None;

    // --- Table-driven parsing for common patterns ---

    // Single IPv4 address (len == 4)
    if len == 4 {
        if let Some(fd) = lookup_option(IPV4_OPTIONS, code) {
            buf.push_field(
                &FIELD_DESCRIPTORS[fd],
                FieldValue::Ipv4Addr([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]),
                opt_range,
            );
            return overload;
        }
    }

    // IPv4 address list (len >= 4, len % 4 == 0)
    if len >= 4 && len % 4 == 0 {
        if let Some(fd) = lookup_option(IPV4_LIST_OPTIONS, code) {
            push_ipv4_list(buf, &FIELD_DESCRIPTORS[fd], opt_data, opt_offset, opt_range);
            return overload;
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
            return overload;
        }
    }

    // Single U16 (len == 2)
    if len == 2 {
        if let Some(fd) = lookup_option(U16_OPTIONS, code) {
            buf.push_field(
                &FIELD_DESCRIPTORS[fd],
                FieldValue::U16(read_be_u16(opt_data, 0).unwrap_or_default()),
                opt_range,
            );
            return overload;
        }
    }

    // Single U32 (len == 4)
    if len == 4 {
        if let Some(fd) = lookup_option(U32_OPTIONS, code) {
            buf.push_field(
                &FIELD_DESCRIPTORS[fd],
                FieldValue::U32(read_be_u32(opt_data, 0).unwrap_or_default()),
                opt_range,
            );
            return overload;
        }
    }

    // String options
    if let Some(fd) = lookup_option(STRING_OPTIONS, code) {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            FieldValue::Bytes(opt_data),
            opt_range,
        );
        return overload;
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
                FieldValue::I32(read_be_i32(opt_data, 0).unwrap_or_default()),
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

        // RFC 2132, Section 8.13 — Mobile IP Home Agent: "Its minimum
        // length is 0 (indicating no home agents are available) and the
        // length MUST be a multiple of 4."
        // <https://www.rfc-editor.org/rfc/rfc2132#section-8.13>
        68 if len % 4 == 0 => {
            push_ipv4_list(
                buf,
                &FIELD_DESCRIPTORS[FD_MOBILE_IP_HOME_AGENT],
                opt_data,
                opt_offset,
                opt_range,
            );
        }

        // RFC 3004, Section 4 — User Class
        // <https://www.rfc-editor.org/rfc/rfc3004#section-4>
        77 if user_class_valid(opt_data) => {
            push_user_class(buf, opt_data, opt_offset + 2, opt_range);
        }

        // RFC 4039, Section 4 — Rapid Commit: "The code for the Rapid
        // Commit option is 80." Its Len is 0.
        // <https://www.rfc-editor.org/rfc/rfc4039#section-4>
        80 if len == 0 => {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_RAPID_COMMIT],
                FieldValue::Bytes(opt_data),
                opt_range,
            );
        }

        // RFC 4702, Section 2 — Client FQDN: "Len contains the number of
        // octets that follow the Len field, and the minimum value is 3
        // (octets)."
        // <https://www.rfc-editor.org/rfc/rfc4702#section-2>
        81 if len >= 3 => {
            let data_start = opt_offset + 2;
            let obj_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_CLIENT_FQDN],
                FieldValue::Object(0..0),
                opt_range,
            );
            buf.push_field(
                &CLIENT_FQDN_CHILDREN[CFD_FQDN_FLAGS],
                FieldValue::U8(opt_data[0]),
                data_start..data_start + 1,
            );
            buf.push_field(
                &CLIENT_FQDN_CHILDREN[CFD_FQDN_RCODE1],
                FieldValue::U8(opt_data[1]),
                data_start + 1..data_start + 2,
            );
            buf.push_field(
                &CLIENT_FQDN_CHILDREN[CFD_FQDN_RCODE2],
                FieldValue::U8(opt_data[2]),
                data_start + 2..data_start + 3,
            );
            // RFC 4702, Section 2.3 — "A client MAY also leave the Domain
            // Name field empty if it desires the server to provide a
            // name."
            // <https://www.rfc-editor.org/rfc/rfc4702#section-2.3>
            if len > 3 {
                buf.push_field(
                    &CLIENT_FQDN_CHILDREN[CFD_FQDN_DOMAIN_NAME],
                    FieldValue::Bytes(&opt_data[3..]),
                    data_start + 3..data_start + len,
                );
            }
            buf.end_container(obj_idx);
        }

        // RFC 3118, Section 2 — Authentication: Protocol (1), Algorithm
        // (1), RDM (1), Replay Detection (8), Authentication Information.
        // <https://www.rfc-editor.org/rfc/rfc3118#section-2>
        90 if len >= DHCP_AUTH_FIXED_LEN => {
            let data_start = opt_offset + 2;
            let obj_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_AUTHENTICATION],
                FieldValue::Object(0..0),
                opt_range,
            );
            buf.push_field(
                &AUTHENTICATION_CHILDREN[CFD_AUTH_PROTOCOL],
                FieldValue::U8(opt_data[0]),
                data_start..data_start + 1,
            );
            buf.push_field(
                &AUTHENTICATION_CHILDREN[CFD_AUTH_ALGORITHM],
                FieldValue::U8(opt_data[1]),
                data_start + 1..data_start + 2,
            );
            buf.push_field(
                &AUTHENTICATION_CHILDREN[CFD_AUTH_RDM],
                FieldValue::U8(opt_data[2]),
                data_start + 2..data_start + 3,
            );
            buf.push_field(
                &AUTHENTICATION_CHILDREN[CFD_AUTH_REPLAY_DETECTION],
                FieldValue::Bytes(&opt_data[3..DHCP_AUTH_FIXED_LEN]),
                data_start + 3..data_start + DHCP_AUTH_FIXED_LEN,
            );
            if len > DHCP_AUTH_FIXED_LEN {
                buf.push_field(
                    &AUTHENTICATION_CHILDREN[CFD_AUTH_INFORMATION],
                    FieldValue::Bytes(&opt_data[DHCP_AUTH_FIXED_LEN..]),
                    data_start + DHCP_AUTH_FIXED_LEN..data_start + len,
                );
            }
            buf.end_container(obj_idx);
        }

        // RFC 4578, Section 2.1 — Client System Architecture Type: "It
        // MUST be an even number greater than zero."
        // <https://www.rfc-editor.org/rfc/rfc4578#section-2.1>
        93 if len >= 2 && len % 2 == 0 => {
            push_u16_list(
                buf,
                &FIELD_DESCRIPTORS[FD_CLIENT_SYSTEM_ARCHITECTURE],
                opt_data,
                opt_offset,
                opt_range,
            );
        }

        // RFC 4578, Section 2.2 — Client Network Interface Identifier:
        // Type, Major, Minor (Len 3).
        // <https://www.rfc-editor.org/rfc/rfc4578#section-2.2>
        94 if len == 3 => {
            let data_start = opt_offset + 2;
            let obj_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_CLIENT_NII],
                FieldValue::Object(0..0),
                opt_range,
            );
            for (i, fd) in CLIENT_NII_CHILDREN.iter().enumerate() {
                buf.push_field(
                    fd,
                    FieldValue::U8(opt_data[i]),
                    data_start + i..data_start + i + 1,
                );
            }
            buf.end_container(obj_idx);
        }

        // RFC 4578, Section 2.3 — Client Machine Identifier: "Octet "t"
        // describes the type of the machine identifier in the remaining
        // octets in this option."
        // <https://www.rfc-editor.org/rfc/rfc4578#section-2.3>
        97 if len >= 1 => {
            let data_start = opt_offset + 2;
            let obj_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_CLIENT_MACHINE_ID],
                FieldValue::Object(0..0),
                opt_range,
            );
            buf.push_field(
                &CLIENT_MACHINE_ID_CHILDREN[0],
                FieldValue::U8(opt_data[0]),
                data_start..data_start + 1,
            );
            buf.push_field(
                &CLIENT_MACHINE_ID_CHILDREN[1],
                FieldValue::Bytes(&opt_data[1..]),
                data_start + 1..data_start + len,
            );
            buf.end_container(obj_idx);
        }

        // RFC 3925, Section 3 — V-I Vendor Class
        // <https://www.rfc-editor.org/rfc/rfc3925#section-3>
        124 if vendor_entries_valid(opt_data) => {
            push_vendor_entries(
                buf,
                &FIELD_DESCRIPTORS[FD_VI_VENDOR_CLASS],
                opt_data,
                opt_offset + 2,
                opt_range,
            );
        }

        // RFC 3925, Section 4 — V-I Vendor-Specific Information
        // <https://www.rfc-editor.org/rfc/rfc3925#section-4>
        125 if vendor_entries_valid(opt_data) => {
            push_vendor_entries(
                buf,
                &FIELD_DESCRIPTORS[FD_VI_VENDOR_SPECIFIC_INFO],
                opt_data,
                opt_offset + 2,
                opt_range,
            );
        }

        // RFC 6704, Section 3.1.1 — "The FORCERENEW_NONCE_CAPABLE option
        // contains code 145, length n, and a sequence of algorithms the
        // client supports"
        // <https://www.rfc-editor.org/rfc/rfc6704#section-3.1.1>
        145 if len >= 1 => {
            let fd = &FIELD_DESCRIPTORS[FD_FORCERENEW_NONCE_CAPABLE];
            let arr_idx = buf.begin_container(fd, FieldValue::Array(0..0), opt_range);
            for (i, &alg) in opt_data.iter().enumerate() {
                buf.push_field(
                    fd,
                    FieldValue::U8(alg),
                    opt_offset + 2 + i..opt_offset + 3 + i,
                );
            }
            buf.end_container(arr_idx);
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

    overload
}

/// Specification references for the DHCP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2131",
        "Dynamic Host Configuration Protocol",
        "https://www.rfc-editor.org/rfc/rfc2131",
    ),
    SpecReference::new(
        "RFC 2132",
        "DHCP Options and BOOTP Vendor Extensions",
        "https://www.rfc-editor.org/rfc/rfc2132",
    ),
    SpecReference::new(
        "RFC 3396",
        "Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)",
        "https://www.rfc-editor.org/rfc/rfc3396",
    ),
    SpecReference::new(
        "RFC 4361",
        "Node-specific Client Identifiers for Dynamic Host Configuration Protocol Version Four (DHCPv4)",
        "https://www.rfc-editor.org/rfc/rfc4361",
    ),
    SpecReference::new(
        "RFC 3046",
        "DHCP Relay Agent Information Option",
        "https://www.rfc-editor.org/rfc/rfc3046",
    ),
    SpecReference::new(
        "RFC 3397",
        "Dynamic Host Configuration Protocol (DHCP) Domain Search Option",
        "https://www.rfc-editor.org/rfc/rfc3397",
    ),
    SpecReference::new(
        "RFC 3442",
        "The Classless Static Route Option for Dynamic Host Configuration Protocol (DHCP) version 4",
        "https://www.rfc-editor.org/rfc/rfc3442",
    ),
    SpecReference::new(
        "RFC 6842",
        "Client Identifier Option in DHCP Server Replies",
        "https://www.rfc-editor.org/rfc/rfc6842",
    ),
    SpecReference::new(
        "RFC 1035",
        "Domain names - implementation and specification",
        "https://www.rfc-editor.org/rfc/rfc1035",
    ),
    SpecReference::new(
        "RFC 951",
        "Bootstrap Protocol",
        "https://www.rfc-editor.org/rfc/rfc951",
    ),
    SpecReference::new(
        "RFC 1542",
        "Clarifications and Extensions for the Bootstrap Protocol",
        "https://www.rfc-editor.org/rfc/rfc1542",
    ),
    SpecReference::new(
        "RFC 4390",
        "Dynamic Host Configuration Protocol (DHCP) over InfiniBand",
        "https://www.rfc-editor.org/rfc/rfc4390",
    ),
    SpecReference::new(
        "RFC 3203",
        "DHCP reconfigure extension",
        "https://www.rfc-editor.org/rfc/rfc3203",
    ),
    SpecReference::new(
        "RFC 4388",
        "Dynamic Host Configuration Protocol (DHCP) Leasequery",
        "https://www.rfc-editor.org/rfc/rfc4388",
    ),
    SpecReference::new(
        "RFC 6926",
        "DHCPv4 Bulk Leasequery",
        "https://www.rfc-editor.org/rfc/rfc6926",
    ),
    SpecReference::new(
        "RFC 7724",
        "Active DHCPv4 Lease Query",
        "https://www.rfc-editor.org/rfc/rfc7724",
    ),
    SpecReference::new(
        "RFC 3527",
        "Link Selection sub-option for the Relay Agent Information Option for DHCPv4",
        "https://www.rfc-editor.org/rfc/rfc3527",
    ),
    SpecReference::new(
        "RFC 3993",
        "Subscriber-ID Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Option",
        "https://www.rfc-editor.org/rfc/rfc3993",
    ),
    SpecReference::new(
        "RFC 4014",
        "Remote Authentication Dial-In User Service (RADIUS) Attributes Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Information Option",
        "https://www.rfc-editor.org/rfc/rfc4014",
    ),
    SpecReference::new(
        "RFC 4030",
        "The Authentication Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Option",
        "https://www.rfc-editor.org/rfc/rfc4030",
    ),
    SpecReference::new(
        "RFC 4243",
        "Vendor-Specific Information Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Option",
        "https://www.rfc-editor.org/rfc/rfc4243",
    ),
    SpecReference::new(
        "RFC 5010",
        "The Dynamic Host Configuration Protocol Version 4 (DHCPv4) Relay Agent Flags Suboption",
        "https://www.rfc-editor.org/rfc/rfc5010",
    ),
    SpecReference::new(
        "RFC 5107",
        "DHCP Server Identifier Override Suboption",
        "https://www.rfc-editor.org/rfc/rfc5107",
    ),
    SpecReference::new(
        "RFC 3004",
        "The User Class Option for DHCP",
        "https://www.rfc-editor.org/rfc/rfc3004",
    ),
    SpecReference::new(
        "RFC 4039",
        "Rapid Commit Option for the Dynamic Host Configuration Protocol version 4 (DHCPv4)",
        "https://www.rfc-editor.org/rfc/rfc4039",
    ),
    SpecReference::new(
        "RFC 4702",
        "The Dynamic Host Configuration Protocol (DHCP) Client Fully Qualified Domain Name (FQDN) Option",
        "https://www.rfc-editor.org/rfc/rfc4702",
    ),
    SpecReference::new(
        "RFC 3118",
        "Authentication for DHCP Messages",
        "https://www.rfc-editor.org/rfc/rfc3118",
    ),
    SpecReference::new(
        "RFC 4578",
        "Dynamic Host Configuration Protocol (DHCP) Options for the Intel Preboot eXecution Environment (PXE)",
        "https://www.rfc-editor.org/rfc/rfc4578",
    ),
    SpecReference::new(
        "RFC 8925",
        "IPv6-Only Preferred Option for DHCPv4",
        "https://www.rfc-editor.org/rfc/rfc8925",
    ),
    SpecReference::new(
        "RFC 8910",
        "Captive-Portal Identification in DHCP and Router Advertisements (RAs)",
        "https://www.rfc-editor.org/rfc/rfc8910",
    ),
    SpecReference::new(
        "RFC 3011",
        "The IPv4 Subnet Selection Option for DHCP",
        "https://www.rfc-editor.org/rfc/rfc3011",
    ),
    SpecReference::new(
        "RFC 3925",
        "Vendor-Identifying Vendor Options for Dynamic Host Configuration Protocol version 4 (DHCPv4)",
        "https://www.rfc-editor.org/rfc/rfc3925",
    ),
    SpecReference::new(
        "RFC 6704",
        "Forcerenew Nonce Authentication",
        "https://www.rfc-editor.org/rfc/rfc6704",
    ),
    SpecReference::new(
        "RFC 5859",
        "TFTP Server Address Option for DHCPv4",
        "https://www.rfc-editor.org/rfc/rfc5859",
    ),
];

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
        if data.len() < MIN_MSG_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_MSG_SIZE,
                actual: data.len(),
            });
        }

        // RFC 2131, Section 3 — verify the magic cookie.
        // <https://www.rfc-editor.org/rfc/rfc2131#section-3>
        // RFC 2132, Section 2 — the cookie only marks the vendor area as
        // holding options.
        // <https://www.rfc-editor.org/rfc/rfc2132#section-2>
        // Without it the message is plain BOOTP (RFC 951, Section 3), whose
        // `vend` area is exposed as raw bytes.
        // <https://www.rfc-editor.org/rfc/rfc951#section-3>
        let is_bootp = data[236..240] != MAGIC_COOKIE;
        // RFC 1542, Section 2.1 — "The 'op' (opcode) field of the message must
        // contain either the code for a BOOTREQUEST (1) or the code for a
        // BOOTREPLY (2)."
        // <https://www.rfc-editor.org/rfc/rfc1542#section-2.1>
        if is_bootp && (data.len() < MIN_BOOTP_MSG_SIZE || !matches!(data[0], 1 | 2)) {
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

        // RFC 2131, Section 2 — "chaddr  16  Client hardware address." and
        // "hlen  1  Hardware address length (e.g.  '6' for 10mb ethernet)."
        // <https://www.rfc-editor.org/rfc/rfc2131#section-2>
        // Only the first `hlen` octets are the address. An `hlen` larger than
        // the field is clamped to its 16 octets. RFC 4390, Section 2.1 sets
        // `hlen` to 0 for InfiniBand, which yields an empty address.
        // <https://www.rfc-editor.org/rfc/rfc4390#section-2.1>
        let chaddr_len = core::cmp::min(hlen as usize, CHADDR_SIZE);
        let chaddr_raw = &data[CHADDR_OFFSET..CHADDR_OFFSET + chaddr_len];
        let (chaddr_fd, chaddr_value) = match *chaddr_raw {
            [a, b, c, d, e, f] => (
                &FIELD_DESCRIPTORS[FD_CHADDR],
                FieldValue::MacAddr(MacAddr([a, b, c, d, e, f])),
            ),
            _ => (
                &FIELD_DESCRIPTORS[FD_CHADDR_BYTES],
                FieldValue::Bytes(chaddr_raw),
            ),
        };

        let field_start = buf.fields().len();
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
            chaddr_fd,
            chaddr_value,
            offset + CHADDR_OFFSET..offset + CHADDR_OFFSET + chaddr_len,
        );

        // Parse options (after magic cookie at offset 240)
        let options_start = 240;
        let mut total_consumed = options_start;
        let mut overload_value: Option<u8> = None;

        if is_bootp {
            // RFC 951, Section 3 — "vend    64      optional vendor-specific area"
            // <https://www.rfc-editor.org/rfc/rfc951#section-3>
            // RFC 1542, Section 2.1 — "BOOTP messages which, according to the
            // IP Total Length and UDP Length fields, are larger than the
            // minimum size specified by [1] MUST also be accepted."
            // <https://www.rfc-editor.org/rfc/rfc1542#section-2.1>
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_VEND],
                FieldValue::Bytes(&data[OPTIONS_FIXED_END..]),
                offset + OPTIONS_FIXED_END..offset + data.len(),
            );
            total_consumed = data.len();
        } else if data.len() > options_start {
            // RFC 3396, Section 7 — find the codes that occur more than once
            // in the aggregate option buffer before decoding any option.
            // <https://www.rfc-editor.org/rfc/rfc3396#section-7>
            let split = split_codes(data);

            let (opt_consumed, overload) = parse_options(buf, data, offset, options_start, &split)?;
            total_consumed = options_start + opt_consumed;
            overload_value = overload;

            // RFC 2132, Section 9.3 — Option Overload
            // If present, the `file` and/or `sname` fields carry additional options.
            if let Some(ov) = overload {
                // Value 1 or 3: `file` field (bytes 108..236) carries options.
                if ov == 1 || ov == 3 {
                    let (_, _) = parse_options(
                        buf,
                        &data[..OPTIONS_FIXED_END],
                        offset,
                        FILE_OFFSET,
                        &split,
                    )?;
                }
                // Value 2 or 3: `sname` field (bytes 44..108) carries options.
                if ov == 2 || ov == 3 {
                    let (_, _) =
                        parse_options(buf, &data[..FILE_OFFSET], offset, SNAME_OFFSET, &split)?;
                }
            }
            push_split_options(buf, data, offset, &split);
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

        // RFC 2131, Section 3 — "One particular option - the "DHCP message
        // type" option - must be included in every DHCP message."
        // <https://www.rfc-editor.org/rfc/rfc2131#section-3>
        // A message without it is BOOTP, with or without RFC 1497 vendor
        // extensions.
        let has_message_type = buf.fields()[field_start..]
            .iter()
            .any(|f| f.name() == FIELD_DESCRIPTORS[FD_DHCP_MESSAGE_TYPE].name);
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + total_consumed;
            if !has_message_type {
                layer.display_name = Some("BOOTP");
            }
        }
        buf.end_layer();

        Ok(DissectResult::new(total_consumed, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

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
    // | 2           | chaddr, htype 1 / hlen 6 (MAC)      | parse_dhcp_chaddr_ethernet_mac              |
    // | 2           | chaddr, hlen 8                      | parse_dhcp_chaddr_hlen_8                    |
    // | 2           | chaddr, hlen 1                      | parse_dhcp_chaddr_hlen_1                    |
    // | 2           | chaddr, hlen > 16 clamped           | parse_dhcp_chaddr_hlen_over_16_clamped      |
    // | 2           | chaddr value types match descriptors| parse_dhcp_chaddr_value_types_match_descriptors |
    // | 3           | Option 53 absent -> BOOTP label     | parse_bootp_with_vendor_extensions_labeled_bootp |
    //
    // # RFC 4390 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 2.1         | InfiniBand hlen 0, no chaddr        | parse_dhcp_chaddr_hlen_0                    |
    //
    // # RFC 951 (BOOTP) Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 3           | BOOTP message, vend without cookie  | parse_bootp_without_magic_cookie            |
    // | 3           | DHCP message has no vend field      | parse_dhcp_has_no_vend_field                |
    // | 3           | Short message without cookie        | parse_bootp_short_without_magic_cookie_rejected |
    //
    // # RFC 1542 (BOOTP Clarifications) Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 2.1         | BOOTP message larger than 300 octets| parse_bootp_longer_than_300_octets          |
    // | 2.1         | op must be BOOTREQUEST/BOOTREPLY    | parse_bootp_invalid_op_rejected             |
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
    // | 9.6         | Message Types 9-18 (IANA)           | dhcp_message_type_names_later_registrations |
    // | 9.6 / 3203  | DHCPFORCERENEW (RFC 3203, 4)        | parse_dhcp_forcerenew_message_type          |
    //
    // # RFC 3396 (Encoding Long Options) Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 7           | Split option concatenated, decoded once | rfc3396_split_classless_static_route_is_concatenated |
    // | 5, 7        | Aggregate order: options, then file | rfc3396_split_across_options_and_file_with_overload |
    // | 7           | Value straddling portions (scratch) | rfc3396_split_string_straddling_fragments_uses_scratch |
    // | 4, 7        | Single instances unchanged          | rfc3396_single_instances_are_unchanged      |
    // | 4           | Value longer than 255 octets        | rfc3396_split_value_over_255_octets         |
    // | 7           | Unknown split option                | rfc3396_split_unknown_option_keeps_concatenated_data |
    // | 7           | Hundreds of portions                | rfc3396_many_instances_are_concatenated |
    // | 7           | Repeated fixed-length option        | rfc3396_repeated_fixed_length_option_is_decoded_per_portion |
    // | 7           | Numeric values straddling portions  | rfc3396_split_numeric_values_are_reassembled |
    // | 7           | FQDN straddling portions (scratch)  | rfc3396_split_client_fqdn_formats_scratch_name |
    // | —           | Truncated option ends the scan      | rfc3396_scan_stops_at_truncated_option      |
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
    // | 3           | Unassigned sub-option stays raw     | parse_dhcp_relay_agent_info_unknown_sub_option |
    //
    // # Relay Agent Information Sub-Option Coverage
    //
    // | RFC / Section | Description                       | Test                                        |
    // |---------------|-----------------------------------|---------------------------------------------|
    // | 3527 §3       | Link Selection (5)                | parse_relay_sub_option_link_selection       |
    // | 3527 §3       | Link Selection, bad length -> raw | parse_relay_sub_option_link_selection_bad_length_raw |
    // | 3993 §3       | Subscriber-ID (6)                 | parse_relay_sub_option_subscriber_id        |
    // | 4014 §3       | RADIUS Attributes (7)             | parse_relay_sub_option_radius_attributes    |
    // | 4014 §3       | Malformed RADIUS attrs -> raw     | parse_relay_sub_option_radius_attributes_malformed_raw |
    // | 4030 §4       | Authentication (8)                | parse_relay_sub_option_authentication       |
    // | 4030 §4       | Short Authentication -> raw       | parse_relay_sub_option_authentication_short_raw |
    // | 4243 §3       | Vendor-Specific Information (9)   | parse_relay_sub_option_vendor_specific      |
    // | 5010 §3       | Relay Agent Flags (10)            | parse_relay_sub_option_flags                |
    // | 5107 §4       | Server Identifier Override (11)   | parse_relay_sub_option_server_identifier_override |
    //
    // # Later DHCPv4 Option Coverage
    //
    // | RFC / Section | Description                       | Test                                        |
    // |---------------|-----------------------------------|---------------------------------------------|
    // | 2132 §8.13-21 | Options 68-76 (server lists)      | parse_dhcp_server_address_list_options_68_to_76 |
    // | 2132 §8.13    | Mobile IP Home Agent, length 0    | parse_dhcp_mobile_ip_home_agent_empty       |
    // | 3004 §4       | User Class (77)                   | parse_dhcp_user_class                       |
    // | 3004 §4       | Malformed User Class -> raw       | parse_dhcp_user_class_malformed_raw         |
    // | 4039 §4       | Rapid Commit (80)                 | parse_dhcp_rapid_commit                     |
    // | 4702 §2       | Client FQDN (81)                  | parse_dhcp_client_fqdn                      |
    // | 4702 §2       | Client FQDN below 3 octets -> raw | parse_dhcp_client_fqdn_too_short_raw        |
    // | 3118 §2       | Authentication (90)               | parse_dhcp_authentication                   |
    // | 4578 §2.1     | Client System Architecture (93)   | parse_dhcp_client_system_architecture       |
    // | 4578 §2.2     | Client Network Interface Id (94)  | parse_dhcp_client_network_interface_identifier |
    // | 4578 §2.3     | Client Machine Identifier (97)    | parse_dhcp_client_machine_identifier        |
    // | 8925 §3.1     | IPv6-Only Preferred (108)         | parse_dhcp_ipv6_only_preferred              |
    // | 8910 §2.1     | Captive-Portal (114)              | parse_dhcp_captive_portal                   |
    // | 3011 §3       | Subnet Selection (118)            | parse_dhcp_subnet_selection                 |
    // | 3925 §3       | V-I Vendor Class (124)            | parse_dhcp_vi_vendor_class                  |
    // | 3925 §4       | V-I Vendor-Specific Info (125)    | parse_dhcp_vi_vendor_specific_info          |
    // | 3925 §4       | Malformed V-I data -> raw         | parse_dhcp_vi_vendor_specific_info_malformed_raw |
    // | 6704 §3.1.1   | FORCERENEW_NONCE_CAPABLE (145)    | parse_dhcp_forcerenew_nonce_capable         |
    // | 5859 §3       | TFTP Server Address (150)         | parse_dhcp_tftp_server_address              |
    // | (all above)   | Value types match descriptors     | new_option_value_types_match_descriptors    |
    //
    // # RFC 3397 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 2           | Domain Search List encoding         | parse_dhcp_domain_search_single             |
    // | 2           | Multiple domains                    | parse_dhcp_domain_search_multiple           |
    // | 2           | Compression pointers (RFC 1035 4.1.4) | parse_dhcp_domain_search_with_compression_pointer |
    //
    // # RFC 3442 Coverage
    //
    // | RFC Section | Description                         | Test                                        |
    // |-------------|-------------------------------------|---------------------------------------------|
    // | 3           | Classless Static Route              | parse_dhcp_classless_static_route_single     |
    // | 3           | Default + /25 routes                | parse_dhcp_classless_static_route_default_and_prefix |
    // | 3           | Invalid prefix width rejected       | parse_dhcp_classless_static_route_invalid_prefix_stops_parsing |

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

    /// Build a DHCPDISCOVER with the given htype/hlen and raw chaddr bytes.
    fn build_discover_with_hw(htype: u8, hlen: u8, chaddr: &[u8]) -> Vec<u8> {
        let mut pkt = build_dhcp_base(1, 0x01020304, [0; 6], [0; 4]);
        pkt[1] = htype;
        pkt[2] = hlen;
        pkt[28..28 + chaddr.len()].copy_from_slice(chaddr);
        push_option(&mut pkt, 53, &[1]);
        pkt.push(255);
        pkt
    }

    /// RFC 2131, Section 2 — Ethernet (htype 1, hlen 6): chaddr is a MAC
    /// address occupying the first `hlen` octets of the field.
    #[test]
    fn parse_dhcp_chaddr_ethernet_mac() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = build_discover_with_hw(1, 6, &mac);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = buf.field_by_name(&buf.layers()[0], "chaddr").unwrap();
        assert_eq!(f.value, FieldValue::MacAddr(MacAddr(mac)));
        assert_eq!(f.range, 28..34);
        assert!(
            buf.field_by_name(&buf.layers()[0], "chaddr_bytes")
                .is_none()
        );
    }

    /// Every emitted field's value type matches its descriptor, whatever
    /// `hlen` is.
    #[test]
    fn parse_dhcp_chaddr_value_types_match_descriptors() {
        for (htype, hlen) in [(1u8, 6u8), (0x1b, 8), (7, 1), (32, 0), (1, 20)] {
            let pkt = build_discover_with_hw(htype, hlen, &[0x42; 16][..hlen.min(16) as usize]);
            let mut buf = DissectBuffer::new();
            DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
            for f in buf.layer_fields(&buf.layers()[0]) {
                assert_eq!(
                    f.value.field_type(),
                    f.descriptor.field_type,
                    "hlen {hlen}: field {}",
                    f.name()
                );
            }
        }
    }

    /// RFC 1542, Section 2.1 — "The 'op' (opcode) field of the message must
    /// contain either the code for a BOOTREQUEST (1) or the code for a
    /// BOOTREPLY (2)." Without the magic cookie and a valid op, the payload
    /// is not BOOTP.
    #[test]
    fn parse_bootp_invalid_op_rejected() {
        let mut data = vec![0u8; 300];
        data[0] = 0x47;
        let mut buf = DissectBuffer::new();
        let err = DhcpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    /// RFC 2131, Section 3 — the DHCP message type option "must be included
    /// in every DHCP message". A message with the RFC 1497 cookie but no
    /// option 53 is a BOOTP message with vendor extensions.
    #[test]
    fn parse_bootp_with_vendor_extensions_labeled_bootp() {
        let mut pkt = build_dhcp_base(2, 5, [0; 6], [192, 0, 2, 10]);
        push_option(&mut pkt, 1, &[255, 255, 255, 0]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(layer.protocol_name(), "BOOTP");
        assert!(buf.field_by_name(layer, "subnet_mask").is_some());
        assert!(buf.field_by_name(layer, "vend").is_none());
    }

    /// RFC 2131, Section 2 — a hardware address longer than 6 octets
    /// (EUI-64, htype 27, hlen 8) is kept whole.
    #[test]
    fn parse_dhcp_chaddr_hlen_8() {
        let hw = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let pkt = build_discover_with_hw(0x1b, 8, &hw);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "chaddr").is_none());
        let f = buf.field_by_name(layer, "chaddr_bytes").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&hw));
        assert_eq!(f.range, 28..36);
    }

    /// RFC 2131, Section 2 — a 1-octet hardware address (ARCNET, htype 7).
    #[test]
    fn parse_dhcp_chaddr_hlen_1() {
        let pkt = build_discover_with_hw(7, 1, &[0x2a]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "chaddr").is_none());
        let f = buf.field_by_name(layer, "chaddr_bytes").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&[0x2a]));
        assert_eq!(f.range, 28..29);
    }

    /// RFC 4390, Section 2.1 — InfiniBand uses hlen 0 and no chaddr.
    #[test]
    fn parse_dhcp_chaddr_hlen_0() {
        let pkt = build_discover_with_hw(32, 0, &[]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "chaddr").is_none());
        let f = buf.field_by_name(layer, "chaddr_bytes").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&[]));
        assert_eq!(f.range, 28..28);
    }

    /// RFC 2131, Section 2 — chaddr is 16 octets, so an hlen above 16 is
    /// clamped to the field size.
    #[test]
    fn parse_dhcp_chaddr_hlen_over_16_clamped() {
        let hw: Vec<u8> = (1..=16).collect();
        let pkt = build_discover_with_hw(1, 20, &hw);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "chaddr").is_none());
        let f = buf.field_by_name(layer, "chaddr_bytes").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&hw));
        assert_eq!(f.range, 28..44);
        assert_eq!(
            buf.field_by_name(layer, "hlen").unwrap().value,
            FieldValue::U8(20)
        );
    }

    /// RFC 951, Section 3 — a BOOTP message whose 64-octet `vend` area
    /// does not start with the RFC 2132 magic cookie.
    #[test]
    fn parse_bootp_without_magic_cookie() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut pkt = build_dhcp_base(1, 0xCAFEBABE, mac, [0; 4]);
        pkt.truncate(236);
        pkt[108..116].copy_from_slice(b"pxelinux");
        let mut vend = [0u8; 64];
        vend[0] = 0xde;
        vend[63] = 0xad;
        pkt.extend_from_slice(&vend);
        assert_eq!(pkt.len(), 300);

        let mut buf = DissectBuffer::new();
        let result = DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 300);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "DHCP");
        assert_eq!(layer.protocol_name(), "BOOTP");
        assert_eq!(layer.range, 0..300);
        assert_eq!(
            buf.field_by_name(layer, "xid").unwrap().value,
            FieldValue::U32(0xCAFEBABE)
        );
        assert_eq!(
            buf.field_by_name(layer, "chaddr").unwrap().value,
            FieldValue::MacAddr(MacAddr(mac))
        );
        assert_eq!(
            buf.field_by_name(layer, "file").unwrap().value,
            FieldValue::Bytes(b"pxelinux")
        );
        let v = buf.field_by_name(layer, "vend").unwrap();
        assert_eq!(v.value, FieldValue::Bytes(&vend));
        assert_eq!(v.range, 236..300);
        assert!(buf.field_by_name(layer, "dhcp_message_type").is_none());
    }

    /// RFC 1542, Section 2.1 — BOOTP messages larger than 300 octets "MUST
    /// also be accepted"; the whole area after the fixed header is `vend`.
    #[test]
    fn parse_bootp_longer_than_300_octets() {
        let mut pkt = build_dhcp_base(2, 7, [0; 6], [0; 4]);
        pkt.truncate(236);
        pkt.extend_from_slice(&[0x5a; 100]);
        let mut buf = DissectBuffer::new();
        let result = DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 336);
        let layer = &buf.layers()[0];
        assert_eq!(layer.protocol_name(), "BOOTP");
        let v = buf.field_by_name(layer, "vend").unwrap();
        assert_eq!(v.value, FieldValue::Bytes(&[0x5a; 100]));
        assert_eq!(v.range, 236..336);
    }

    /// A DHCP message (with the magic cookie) keeps the DHCP display name
    /// and has no `vend` field.
    #[test]
    fn parse_dhcp_has_no_vend_field() {
        let pkt = build_discover_with_hw(1, 6, &[0; 6]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(layer.protocol_name(), "DHCP");
        assert!(buf.field_by_name(layer, "vend").is_none());
    }

    /// Without the magic cookie, a message shorter than the 300-octet
    /// BOOTP message (RFC 951, Section 3) is rejected.
    #[test]
    fn parse_bootp_short_without_magic_cookie_rejected() {
        let data = vec![0u8; 299];
        let mut buf = DissectBuffer::new();
        let err = DhcpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    /// DHCP Message Type values 9-18 (IANA "BOOTP and DHCP Parameters",
    /// Message Type 53 Values).
    #[test]
    fn dhcp_message_type_names_later_registrations() {
        let expected = [
            (9, "FORCERENEW"),
            (10, "LEASEQUERY"),
            (11, "LEASEUNASSIGNED"),
            (12, "LEASEUNKNOWN"),
            (13, "LEASEACTIVE"),
            (14, "BULKLEASEQUERY"),
            (15, "LEASEQUERYDONE"),
            (16, "ACTIVELEASEQUERY"),
            (17, "LEASEQUERYSTATUS"),
            (18, "TLS"),
        ];
        for (v, name) in expected {
            assert_eq!(dhcp_message_type_name(v), Some(name), "type {v}");
        }
        assert_eq!(dhcp_message_type_name(0), None);
        assert_eq!(dhcp_message_type_name(19), None);
    }

    /// RFC 3203, Section 4 — DHCPFORCERENEW resolves through option 53.
    #[test]
    fn parse_dhcp_forcerenew_message_type() {
        let mut pkt = build_dhcp_base(2, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 53, &[9]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "dhcp_message_type_name"),
            Some("FORCERENEW")
        );
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
    // Option 21: Policy Filter (RFC 2132, Section 4.3)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_policy_filter() {
        // RFC 2132, Section 4.3 — "Min 8, multiple of 8"; each entry is a
        // (destination, mask) IPv4 pair.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let entries = [
            192, 168, 0, 0, 255, 255, 0, 0, // 192.168.0.0/16
            10, 0, 0, 0, 255, 0, 0, 0, // 10.0.0.0/8
        ];
        push_option(&mut pkt, 21, &entries);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "policy_filter")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let pairs: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(pairs.len(), 2);

        let first = buf.nested_fields(pairs[0].value.as_container_range().unwrap());
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].name(), "address");
        assert_eq!(first[0].value, FieldValue::Ipv4Addr([192, 168, 0, 0]));
        assert_eq!(first[1].name(), "mask");
        assert_eq!(first[1].value, FieldValue::Ipv4Addr([255, 255, 0, 0]));

        let second = buf.nested_fields(pairs[1].value.as_container_range().unwrap());
        assert_eq!(second[0].value, FieldValue::Ipv4Addr([10, 0, 0, 0]));
        assert_eq!(second[1].value, FieldValue::Ipv4Addr([255, 0, 0, 0]));
    }

    // -----------------------------------------------------------------------
    // Option 33: Static Route (RFC 2132, Section 5.8)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_static_route() {
        // RFC 2132, Section 5.8 — "Min 8, multiple of 8"; each entry is a
        // (destination, router) IPv4 pair. Default route (0.0.0.0) MUST NOT
        // appear here (see RFC); dissector still records whatever is present.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let entries = [
            10, 0, 0, 0, 192, 168, 1, 1, // 10.0.0.0 via 192.168.1.1
            172, 16, 0, 0, 192, 168, 1, 2, // 172.16.0.0 via 192.168.1.2
        ];
        push_option(&mut pkt, 33, &entries);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "static_route")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let pairs: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(pairs.len(), 2);
        let first = buf.nested_fields(pairs[0].value.as_container_range().unwrap());
        assert_eq!(first[0].name(), "destination");
        assert_eq!(first[0].value, FieldValue::Ipv4Addr([10, 0, 0, 0]));
        assert_eq!(first[1].name(), "router");
        assert_eq!(first[1].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
        let second = buf.nested_fields(pairs[1].value.as_container_range().unwrap());
        assert_eq!(second[0].value, FieldValue::Ipv4Addr([172, 16, 0, 0]));
        assert_eq!(second[1].value, FieldValue::Ipv4Addr([192, 168, 1, 2]));
    }

    // -----------------------------------------------------------------------
    // Option 82: Relay Agent Information (RFC 3046)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_relay_agent_info() {
        // RFC 3046, Section 3 — sub-option TLV encoding. Sub-option 1 is
        // Agent Circuit ID, sub-option 2 is Agent Remote ID.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let relay_info = [
            1, 3, b'c', b'i', b'd', // Circuit ID = "cid"
            2, 4, b'r', b'i', b'd', b'1', // Remote ID = "rid1"
        ];
        push_option(&mut pkt, 82, &relay_info);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "relay_agent_info")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let subs: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(subs.len(), 2);

        // Sub-option 1: Agent Circuit ID
        let first = buf.nested_fields(subs[0].value.as_container_range().unwrap());
        assert_eq!(first[0].name(), "sub_option");
        assert_eq!(first[0].value, FieldValue::U8(1));
        assert_eq!(first[1].name(), "circuit_id");
        assert_eq!(first[1].value, FieldValue::Bytes(b"cid"));

        // Sub-option 2: Agent Remote ID
        let second = buf.nested_fields(subs[1].value.as_container_range().unwrap());
        assert_eq!(second[0].name(), "sub_option");
        assert_eq!(second[0].value, FieldValue::U8(2));
        assert_eq!(second[1].name(), "remote_id");
        assert_eq!(second[1].value, FieldValue::Bytes(b"rid1"));
    }

    #[test]
    fn relay_agent_sub_option_container_resolves_to_name() {
        // Sub-option 1 (Agent Circuit ID): the outer container label should
        // resolve to "Agent Circuit ID" rather than duplicating "Sub-Option".
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let relay_info = [1, 3, b'c', b'i', b'd'];
        push_option(&mut pkt, 82, &relay_info);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "relay_agent_sub_option")
            .expect("sub-option container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "Relay Agent Sub-Option");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("Agent Circuit ID")
        );
    }

    #[test]
    fn parse_dhcp_relay_agent_info_unknown_sub_option() {
        // Unknown sub-option code: surfaced via the generic `data` field.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let relay_info = [200, 2, 0xAA, 0xBB]; // sub-option 200: unassigned, opaque payload
        push_option(&mut pkt, 82, &relay_info);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "relay_agent_info")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let subs: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(subs.len(), 1);
        let fields = buf.nested_fields(subs[0].value.as_container_range().unwrap());
        assert_eq!(fields[0].value, FieldValue::U8(200));
        assert_eq!(fields[1].name(), "data");
        assert_eq!(fields[1].value, FieldValue::Bytes(&[0xAA, 0xBB]));
    }

    // -----------------------------------------------------------------------
    // Option 121: Classless Static Route (RFC 3442)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_classless_static_route_single() {
        // RFC 3442, Section 3 — one /24 route: 192.168.1.0/24 via 10.0.0.1.
        // Destination descriptor: width (1) + significant octets (3) + router (4) = 8 bytes.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let route = [24, 192, 168, 1, 10, 0, 0, 1];
        push_option(&mut pkt, 121, &route);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "classless_static_route")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let routes: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(routes.len(), 1);
        let fields = buf.nested_fields(routes[0].value.as_container_range().unwrap());
        assert_eq!(fields[0].name(), "prefix_length");
        assert_eq!(fields[0].value, FieldValue::U8(24));
        assert_eq!(fields[1].name(), "destination");
        assert_eq!(fields[1].value, FieldValue::Bytes(&[192, 168, 1]));
        assert_eq!(fields[2].name(), "router");
        assert_eq!(fields[2].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
    }

    #[test]
    fn parse_dhcp_classless_static_route_default_and_prefix() {
        // RFC 3442, Section 3 — default route (prefix 0, no subnet octets) plus a /25.
        // Default: width=0 -> 0 significant octets -> router 1.2.3.4 (5 bytes total).
        // /25: width=25 -> 4 significant octets -> router 10.0.0.1 (9 bytes total).
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let mut data = Vec::new();
        data.extend_from_slice(&[0, 1, 2, 3, 4]); // default via 1.2.3.4
        data.extend_from_slice(&[25, 10, 0, 1, 0, 10, 0, 0, 2]); // 10.0.1.0/25 via 10.0.0.2
        push_option(&mut pkt, 121, &data);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "classless_static_route")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let routes: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(routes.len(), 2);

        // Default route
        let default_fields = buf.nested_fields(routes[0].value.as_container_range().unwrap());
        assert_eq!(default_fields[0].value, FieldValue::U8(0));
        assert_eq!(default_fields[1].value, FieldValue::Bytes(&[]));
        assert_eq!(default_fields[2].value, FieldValue::Ipv4Addr([1, 2, 3, 4]));

        // /25 route: 4 significant octets
        let prefix_fields = buf.nested_fields(routes[1].value.as_container_range().unwrap());
        assert_eq!(prefix_fields[0].value, FieldValue::U8(25));
        assert_eq!(prefix_fields[1].value, FieldValue::Bytes(&[10, 0, 1, 0]));
        assert_eq!(prefix_fields[2].value, FieldValue::Ipv4Addr([10, 0, 0, 2]));
    }

    #[test]
    fn parse_dhcp_classless_static_route_invalid_prefix_stops_parsing() {
        // RFC 3442, Section 3 — valid mask widths are 0..=32. Values > 32 are
        // malformed; the dissector stops consuming further entries but does
        // not produce a protocol error (Postel's Law).
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let mut data = Vec::new();
        data.extend_from_slice(&[24, 192, 168, 1, 10, 0, 0, 1]); // valid /24
        data.extend_from_slice(&[33, 0, 0, 0, 0, 0, 0, 0, 0]); // invalid prefix=33
        push_option(&mut pkt, 121, &data);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "classless_static_route")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let routes: Vec<_> = buf
            .nested_fields(arr)
            .iter()
            .filter(|f| f.value.is_object())
            .collect();
        assert_eq!(routes.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Option 119: Domain Search List (RFC 3397)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dhcp_domain_search_single() {
        // RFC 3397, Section 2 — one domain "example.com" using RFC 1035 label
        // encoding: 7 "example" 3 "com" 0.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let domain = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        push_option(&mut pkt, 119, &domain);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "domain_search")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let domains = buf.nested_fields(arr);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].value, FieldValue::Bytes(&domain));
    }

    #[test]
    fn parse_dhcp_domain_search_multiple() {
        // RFC 3397, Section 2 — two independent domains.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let data = [
            3, b'a', b'a', b'a', 3, b'c', b'o', b'm', 0, // "aaa.com"
            3, b'b', b'b', b'b', 3, b'o', b'r', b'g', 0, // "bbb.org"
        ];
        push_option(&mut pkt, 119, &data);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "domain_search")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let domains = buf.nested_fields(arr);
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].value, FieldValue::Bytes(&data[0..9]));
        assert_eq!(domains[1].value, FieldValue::Bytes(&data[9..18]));
    }

    #[test]
    fn parse_dhcp_domain_search_with_compression_pointer() {
        // RFC 3397, Section 2 — compression pointers per RFC 1035 Section
        // 4.1.4 are permitted. Encode three names where the middle name ends
        // with a pointer back into the first name's tail and the third name
        // appears immediately after the pointer. Buggy parsers that treat a
        // pointer as an end-of-option marker will lose the third entry.
        //
        //   offset 0 : 5 f i r s t          (label "first")
        //   offset 6 : 7 e x a m p l e      (label "example")
        //   offset 14: 3 c o m              (label "com")
        //   offset 18: 0                    (root label, terminates #1)
        //   offset 19: 6 s e c o n d        (label "second")
        //   offset 26: 0xC0 0x06            (pointer to offset 6, terminates #2)
        //   offset 28: 3 n e w 0            (label "new" + root; terminates #3)
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let data = [
            5, b'f', b'i', b'r', b's', b't', // "first"
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm', // "com"
            0,    // end of first name
            6, b's', b'e', b'c', b'o', b'n', b'd', // "second"
            0xC0, 0x06, // pointer to offset 6 ("example.com")
            3, b'n', b'e', b'w', 0, // "new"
        ];
        push_option(&mut pkt, 119, &data);
        pkt.push(255);
        let d = DhcpDissector;
        let mut buf = DissectBuffer::new();
        d.dissect(&pkt, &mut buf, 0).unwrap();

        let arr = buf
            .field_by_name(&buf.layers()[0], "domain_search")
            .unwrap()
            .value
            .as_container_range()
            .unwrap();
        let domains = buf.nested_fields(arr);
        assert_eq!(domains.len(), 3);
        // First name: bytes 0..19 (inclusive of terminating 0).
        assert_eq!(domains[0].value, FieldValue::Bytes(&data[0..19]));
        // Second name: "second" label + 2-byte compression pointer (bytes 19..28).
        assert_eq!(domains[1].value, FieldValue::Bytes(&data[19..28]));
        // Third name: "new" + root label (bytes 28..33).
        assert_eq!(domains[2].value, FieldValue::Bytes(&data[28..33]));
    }

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

    // -----------------------------------------------------------------------
    // Relay Agent Information sub-options 5-11 and later DHCPv4 options
    // -----------------------------------------------------------------------

    /// Direct children of a container field (nested containers are skipped
    /// as a whole).
    fn direct_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        field: &packet_dissector_core::field::Field<'pkt>,
    ) -> Vec<&'a packet_dissector_core::field::Field<'pkt>> {
        let range = field.value.as_container_range().unwrap().clone();
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let child = &buf.fields()[i as usize];
            out.push(child);
            i = match child.value.as_container_range() {
                Some(r) => r.end,
                None => i + 1,
            };
        }
        out
    }

    /// Build a DHCPDISCOVER carrying the given options (plus End).
    fn discover_with_options(options: &[(u8, &[u8])]) -> Vec<u8> {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 53, &[1]);
        for (code, data) in options {
            push_option(&mut pkt, *code, data);
        }
        pkt.push(255);
        pkt
    }

    /// Top-level field of layer 0 by name.
    fn top_field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        name: &str,
    ) -> &'a packet_dissector_core::field::Field<'pkt> {
        buf.layer_fields(&buf.layers()[0])
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} not found"))
    }

    /// Children of the single relay agent sub-option in option 82.
    fn relay_sub_option_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
    ) -> Vec<&'a packet_dissector_core::field::Field<'pkt>> {
        let arr = top_field(buf, "relay_agent_info");
        let subs = direct_children(buf, arr);
        assert_eq!(subs.len(), 1);
        direct_children(buf, subs[0])
    }

    fn child<'a, 'pkt>(
        fields: &[&'a packet_dissector_core::field::Field<'pkt>],
        name: &str,
    ) -> &'a packet_dissector_core::field::Field<'pkt> {
        fields
            .iter()
            .find(|f| f.name() == name)
            .copied()
            .unwrap_or_else(|| panic!("child {name} not found"))
    }

    /// RFC 3527, Section 3 — Link Selection sub-option (5) carries one
    /// subnet IPv4 address. Issue repro: `52 06 05 04 0a 00 00 01`.
    #[test]
    fn parse_relay_sub_option_link_selection() {
        let pkt = discover_with_options(&[(82, &[5, 4, 10, 0, 0, 1])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        assert_eq!(child(&fields, "sub_option").value, FieldValue::U8(5));
        let ls = child(&fields, "link_selection");
        assert_eq!(ls.value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        // cookie ends at 240; option 53 (3) + option 82 header (2) + sub header (2)
        assert_eq!(ls.range, 247..251);
        assert!(!fields.iter().any(|f| f.name() == "data"));
    }

    /// A Link Selection sub-option whose length is not 4 stays raw.
    #[test]
    fn parse_relay_sub_option_link_selection_bad_length_raw() {
        let pkt = discover_with_options(&[(82, &[5, 3, 10, 0, 0])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        assert_eq!(child(&fields, "data").value, FieldValue::Bytes(&[10, 0, 0]));
    }

    /// RFC 3993, Section 3 — Subscriber-ID sub-option (6) is an ASCII string.
    #[test]
    fn parse_relay_sub_option_subscriber_id() {
        let pkt = discover_with_options(&[(82, &[6, 5, b's', b'u', b'b', b'-', b'1'])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        let f = child(&fields, "subscriber_id");
        assert_eq!(f.value, FieldValue::Bytes(b"sub-1"));
        assert!(f.descriptor.format_fn.is_some());
    }

    /// RFC 4014, Section 3 — RADIUS Attributes sub-option (7) holds RADIUS
    /// attributes encoded per RFC 2865 (Type, Length, Value).
    #[test]
    fn parse_relay_sub_option_radius_attributes() {
        // User-Name (1) "ab", Framed-Pool (88) "p"
        let sub = [7, 7, 1, 4, b'a', b'b', 88, 3, b'p'];
        let pkt = discover_with_options(&[(82, &sub)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        let attrs = direct_children(&buf, child(&fields, "radius_attributes"));
        assert_eq!(attrs.len(), 2);
        let a0 = direct_children(&buf, attrs[0]);
        assert_eq!(child(&a0, "type").value, FieldValue::U8(1));
        assert_eq!(child(&a0, "value").value, FieldValue::Bytes(b"ab"));
        let a1 = direct_children(&buf, attrs[1]);
        assert_eq!(child(&a1, "type").value, FieldValue::U8(88));
        assert_eq!(child(&a1, "value").value, FieldValue::Bytes(b"p"));
    }

    /// RADIUS attributes that do not parse exactly stay raw.
    #[test]
    fn parse_relay_sub_option_radius_attributes_malformed_raw() {
        // Attribute length 9 overruns the 4-octet sub-option; length 1 is
        // below the RFC 2865 minimum of 2.
        for sub in [&[7u8, 4, 1, 9, b'a', b'b'][..], &[7, 2, 1, 1]] {
            let pkt = discover_with_options(&[(82, sub)]);
            let mut buf = DissectBuffer::new();
            DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let fields = relay_sub_option_children(&buf);
            assert!(!fields.iter().any(|f| f.name() == "radius_attributes"));
            assert_eq!(child(&fields, "data").value, FieldValue::Bytes(&sub[2..]));
        }
    }

    /// RFC 4030, Section 4 — Authentication sub-option (8): Algorithm,
    /// MBZ/RDM, 64-bit Replay Detection, Relay Identifier, Authentication
    /// Information.
    #[test]
    fn parse_relay_sub_option_authentication() {
        let mut sub = vec![8, 0];
        sub.push(1); // Algorithm: HMAC-SHA1
        sub.push(0xF2); // MBZ (ignored) | RDM 2
        sub.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]); // Replay Detection
        sub.extend_from_slice(&[192, 0, 2, 1]); // Relay Identifier
        sub.extend_from_slice(&[0xAA; 4]); // Authentication Information
        sub[1] = (sub.len() - 2) as u8;
        let pkt = discover_with_options(&[(82, &sub)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        assert_eq!(child(&fields, "algorithm").value, FieldValue::U8(1));
        assert_eq!(child(&fields, "rdm").value, FieldValue::U8(2));
        assert_eq!(
            child(&fields, "replay_detection").value,
            FieldValue::Bytes(&[0, 0, 0, 0, 0, 0, 0, 7])
        );
        assert_eq!(
            child(&fields, "relay_identifier").value,
            FieldValue::Bytes(&[192, 0, 2, 1])
        );
        assert_eq!(
            child(&fields, "authentication_information").value,
            FieldValue::Bytes(&[0xAA; 4])
        );
    }

    /// An Authentication sub-option shorter than its fixed fields stays raw.
    #[test]
    fn parse_relay_sub_option_authentication_short_raw() {
        let pkt = discover_with_options(&[(82, &[8, 3, 1, 0, 0])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        assert_eq!(child(&fields, "data").value, FieldValue::Bytes(&[1, 0, 0]));
    }

    /// RFC 4243, Section 3 — Vendor-Specific sub-option (9): repeated
    /// Enterprise Number, DataLen, Suboption Data.
    #[test]
    fn parse_relay_sub_option_vendor_specific() {
        let mut sub = vec![9, 0];
        sub.extend_from_slice(&3561u32.to_be_bytes());
        sub.extend_from_slice(&[2, 0x01, 0x02]);
        sub.extend_from_slice(&9u32.to_be_bytes());
        sub.extend_from_slice(&[0]);
        sub[1] = (sub.len() - 2) as u8;
        let pkt = discover_with_options(&[(82, &sub)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        let vendors = direct_children(&buf, child(&fields, "vendor_specific"));
        assert_eq!(vendors.len(), 2);
        let v0 = direct_children(&buf, vendors[0]);
        assert_eq!(child(&v0, "enterprise_number").value, FieldValue::U32(3561));
        assert_eq!(child(&v0, "data").value, FieldValue::Bytes(&[1, 2]));
        let v1 = direct_children(&buf, vendors[1]);
        assert_eq!(child(&v1, "enterprise_number").value, FieldValue::U32(9));
        assert_eq!(child(&v1, "data").value, FieldValue::Bytes(&[]));
    }

    /// RFC 5010, Section 3 — Relay Agent Flags sub-option (10): one octet,
    /// most significant bit is the UNICAST flag.
    #[test]
    fn parse_relay_sub_option_flags() {
        let pkt = discover_with_options(&[(82, &[10, 1, 0x80])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        assert_eq!(child(&fields, "flags").value, FieldValue::U8(0x80));
        assert_eq!(child(&fields, "unicast").value, FieldValue::U8(1));
    }

    /// RFC 5107, Section 4 — Server Identifier Override sub-option (11)
    /// holds one IPv4 address.
    #[test]
    fn parse_relay_sub_option_server_identifier_override() {
        let pkt = discover_with_options(&[(82, &[11, 4, 192, 0, 2, 10])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = relay_sub_option_children(&buf);
        assert_eq!(
            child(&fields, "server_identifier_override").value,
            FieldValue::Ipv4Addr([192, 0, 2, 10])
        );
    }

    /// RFC 2132, Sections 8.13-8.21 — options 68-76 are IPv4 address lists.
    #[test]
    fn parse_dhcp_server_address_list_options_68_to_76() {
        let expected = [
            (68, "mobile_ip_home_agent"),
            (69, "smtp_server"),
            (70, "pop3_server"),
            (71, "nntp_server"),
            (72, "www_server"),
            (73, "finger_server"),
            (74, "irc_server"),
            (75, "streettalk_server"),
            (76, "stda_server"),
        ];
        for (code, name) in expected {
            let pkt = discover_with_options(&[(code, &[192, 0, 2, 1, 192, 0, 2, 2])]);
            let mut buf = DissectBuffer::new();
            DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let addrs = direct_children(&buf, top_field(&buf, name));
            assert_eq!(addrs.len(), 2, "option {code}");
            assert_eq!(addrs[0].value, FieldValue::Ipv4Addr([192, 0, 2, 1]));
            assert_eq!(addrs[1].value, FieldValue::Ipv4Addr([192, 0, 2, 2]));
        }
    }

    /// RFC 2132, Section 8.13 — "Its minimum length is 0 (indicating no
    /// home agents are available)".
    #[test]
    fn parse_dhcp_mobile_ip_home_agent_empty() {
        let pkt = discover_with_options(&[(68, &[])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let arr = top_field(&buf, "mobile_ip_home_agent");
        assert!(direct_children(&buf, arr).is_empty());
    }

    /// RFC 3004, Section 4 — User Class: one or more UC_Len_i + data.
    #[test]
    fn parse_dhcp_user_class() {
        let pkt = discover_with_options(&[(77, &[3, b'a', b'b', b'c', 1, b'x'])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let classes = direct_children(&buf, top_field(&buf, "user_class"));
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].value, FieldValue::Bytes(b"abc"));
        assert_eq!(classes[1].value, FieldValue::Bytes(b"x"));
    }

    /// User Class data that does not parse exactly (zero UC_Len or overrun)
    /// stays raw.
    #[test]
    fn parse_dhcp_user_class_malformed_raw() {
        for data in [&[0u8, 1][..], &[5, b'a'], &[]] {
            let pkt = discover_with_options(&[(77, data)]);
            let mut buf = DissectBuffer::new();
            DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert!(buf.field_by_name(layer, "user_class").is_none());
            assert!(buf.field_by_name(layer, "unknown_option").is_some());
        }
    }

    /// RFC 4039, Section 4 — Rapid Commit has length 0.
    #[test]
    fn parse_dhcp_rapid_commit() {
        let pkt = discover_with_options(&[(80, &[])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            top_field(&buf, "rapid_commit").value,
            FieldValue::Bytes(&[])
        );
    }

    /// RFC 4702, Section 2 — Client FQDN: Flags, RCODE1, RCODE2, Domain Name.
    #[test]
    fn parse_dhcp_client_fqdn() {
        let mut data = vec![0x05, 0, 255]; // E and S set
        data.extend_from_slice(b"\x04host\x07example\x00");
        let pkt = discover_with_options(&[(81, &data)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = direct_children(&buf, top_field(&buf, "client_fqdn"));
        assert_eq!(child(&fields, "flags").value, FieldValue::U8(0x05));
        assert_eq!(child(&fields, "rcode1").value, FieldValue::U8(0));
        assert_eq!(child(&fields, "rcode2").value, FieldValue::U8(255));
        let name = child(&fields, "domain_name");
        assert_eq!(name.value, FieldValue::Bytes(b"\x04host\x07example\x00"));
        assert!(name.descriptor.format_fn.is_some());
    }

    /// RFC 4702, Section 2 — "the minimum value is 3 (octets)".
    #[test]
    fn parse_dhcp_client_fqdn_too_short_raw() {
        let pkt = discover_with_options(&[(81, &[0x01, 0])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "client_fqdn").is_none());
        assert!(buf.field_by_name(layer, "unknown_option").is_some());
    }

    /// RFC 3118, Section 2 — Authentication: Protocol, Algorithm, RDM,
    /// Replay Detection (64 bits), Authentication Information.
    #[test]
    fn parse_dhcp_authentication() {
        let mut data = vec![3, 1, 0];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[2, 0xAB, 0xCD]);
        let pkt = discover_with_options(&[(90, &data)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = direct_children(&buf, top_field(&buf, "authentication"));
        assert_eq!(child(&fields, "protocol").value, FieldValue::U8(3));
        assert_eq!(child(&fields, "algorithm").value, FieldValue::U8(1));
        assert_eq!(child(&fields, "rdm").value, FieldValue::U8(0));
        assert_eq!(
            child(&fields, "replay_detection").value,
            FieldValue::Bytes(&[0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            child(&fields, "authentication_information").value,
            FieldValue::Bytes(&[2, 0xAB, 0xCD])
        );
    }

    /// RFC 4578, Section 2.1 — Client System Architecture Type: list of
    /// 16-bit types.
    #[test]
    fn parse_dhcp_client_system_architecture() {
        let pkt = discover_with_options(&[(93, &[0x00, 0x07, 0x00, 0x09])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let types = direct_children(&buf, top_field(&buf, "client_system_architecture"));
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].value, FieldValue::U16(7));
        assert_eq!(types[1].value, FieldValue::U16(9));
    }

    /// RFC 4578, Section 2.2 — Client Network Interface Identifier:
    /// Type, Major, Minor.
    #[test]
    fn parse_dhcp_client_network_interface_identifier() {
        let pkt = discover_with_options(&[(94, &[1, 2, 1])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = direct_children(&buf, top_field(&buf, "client_network_interface_identifier"));
        assert_eq!(child(&fields, "type").value, FieldValue::U8(1));
        assert_eq!(child(&fields, "major").value, FieldValue::U8(2));
        assert_eq!(child(&fields, "minor").value, FieldValue::U8(1));
    }

    /// RFC 4578, Section 2.3 — Client Machine Identifier: Type 0 followed by
    /// a 16-octet GUID.
    #[test]
    fn parse_dhcp_client_machine_identifier() {
        let mut data = vec![0];
        data.extend_from_slice(&[0x11; 16]);
        let pkt = discover_with_options(&[(97, &data)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let fields = direct_children(&buf, top_field(&buf, "client_machine_identifier"));
        assert_eq!(child(&fields, "type").value, FieldValue::U8(0));
        assert_eq!(
            child(&fields, "machine_identifier").value,
            FieldValue::Bytes(&[0x11; 16])
        );
    }

    /// RFC 8925, Section 3.1 — IPv6-Only Preferred: 4-octet V6ONLY_WAIT.
    #[test]
    fn parse_dhcp_ipv6_only_preferred() {
        let pkt = discover_with_options(&[(108, &1800u32.to_be_bytes())]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            top_field(&buf, "ipv6_only_preferred").value,
            FieldValue::U32(1800)
        );
    }

    /// RFC 8910, Section 2.1 — Captive-Portal DHCPv4 option carries a URI.
    #[test]
    fn parse_dhcp_captive_portal() {
        let uri = b"https://cp.example/api";
        let pkt = discover_with_options(&[(114, uri)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let f = top_field(&buf, "captive_portal");
        assert_eq!(f.value, FieldValue::Bytes(uri));
        assert!(f.descriptor.format_fn.is_some());
    }

    /// RFC 3011, Section 3 — Subnet Selection: one IPv4 address.
    #[test]
    fn parse_dhcp_subnet_selection() {
        let pkt = discover_with_options(&[(118, &[10, 1, 2, 0])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(
            top_field(&buf, "subnet_selection").value,
            FieldValue::Ipv4Addr([10, 1, 2, 0])
        );
    }

    /// RFC 3925, Section 3 — V-I Vendor Class: repeated enterprise-number,
    /// data-len, vendor-class-data.
    #[test]
    fn parse_dhcp_vi_vendor_class() {
        let mut data = Vec::new();
        data.extend_from_slice(&4491u32.to_be_bytes());
        data.extend_from_slice(&[3, 2, b'o', b'k']);
        let pkt = discover_with_options(&[(124, &data)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let entries = direct_children(&buf, top_field(&buf, "vi_vendor_class"));
        assert_eq!(entries.len(), 1);
        let e = direct_children(&buf, entries[0]);
        assert_eq!(child(&e, "enterprise_number").value, FieldValue::U32(4491));
        assert_eq!(child(&e, "data").value, FieldValue::Bytes(&[2, b'o', b'k']));
    }

    /// RFC 3925, Section 4 — V-I Vendor-Specific Information: repeated
    /// enterprise-number, data-len, option-data.
    #[test]
    fn parse_dhcp_vi_vendor_specific_info() {
        let mut data = Vec::new();
        data.extend_from_slice(&4491u32.to_be_bytes());
        data.extend_from_slice(&[3, 1, 1, 0x7F]);
        data.extend_from_slice(&311u32.to_be_bytes());
        data.push(0);
        let pkt = discover_with_options(&[(125, &data)]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let entries = direct_children(&buf, top_field(&buf, "vi_vendor_specific_info"));
        assert_eq!(entries.len(), 2);
        let e0 = direct_children(&buf, entries[0]);
        assert_eq!(child(&e0, "enterprise_number").value, FieldValue::U32(4491));
        assert_eq!(child(&e0, "data").value, FieldValue::Bytes(&[1, 1, 0x7F]));
        let e1 = direct_children(&buf, entries[1]);
        assert_eq!(child(&e1, "enterprise_number").value, FieldValue::U32(311));
    }

    /// V-I vendor data that does not parse exactly stays raw.
    #[test]
    fn parse_dhcp_vi_vendor_specific_info_malformed_raw() {
        let mut data = Vec::new();
        data.extend_from_slice(&4491u32.to_be_bytes());
        data.extend_from_slice(&[9, 1]); // data-len overruns
        for d in [&data[..], &[0, 0, 1]] {
            let pkt = discover_with_options(&[(125, d)]);
            let mut buf = DissectBuffer::new();
            DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert!(
                buf.field_by_name(layer, "vi_vendor_specific_info")
                    .is_none()
            );
            assert!(buf.field_by_name(layer, "unknown_option").is_some());
        }
    }

    /// RFC 6704, Section 3.1.1 — FORCERENEW_NONCE_CAPABLE: list of
    /// one-octet algorithms.
    #[test]
    fn parse_dhcp_forcerenew_nonce_capable() {
        let pkt = discover_with_options(&[(145, &[1, 2])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let algs = direct_children(&buf, top_field(&buf, "forcerenew_nonce_capable"));
        assert_eq!(algs.len(), 2);
        assert_eq!(algs[0].value, FieldValue::U8(1));
        assert_eq!(algs[1].value, FieldValue::U8(2));
    }

    /// RFC 5859, Section 3 — TFTP Server Address: IPv4 address list.
    #[test]
    fn parse_dhcp_tftp_server_address() {
        let pkt = discover_with_options(&[(150, &[192, 0, 2, 5])]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let addrs = direct_children(&buf, top_field(&buf, "tftp_server_address"));
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].value, FieldValue::Ipv4Addr([192, 0, 2, 5]));
    }

    /// Every emitted field (at any nesting depth) matches its descriptor's
    /// type for the newly decoded options, and none falls back to raw.
    #[test]
    fn new_option_value_types_match_descriptors() {
        let mut fqdn = vec![0x04, 0, 0];
        fqdn.extend_from_slice(b"\x01a\x00");
        let mut vi = Vec::new();
        vi.extend_from_slice(&1u32.to_be_bytes());
        vi.extend_from_slice(&[1, 0]);
        let mut relay = vec![5, 4, 10, 0, 0, 1, 10, 1, 0, 11, 4, 1, 2, 3, 4];
        relay.extend_from_slice(&[7, 3, 1, 3, b'a']);
        relay.extend_from_slice(&[9, 5, 0, 0, 0, 1, 0]);
        relay.extend_from_slice(&[6, 1, b'x']);
        relay.extend_from_slice(&[8, 14, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
        let pkt = discover_with_options(&[
            (68, &[1, 2, 3, 4]),
            (77, &[1, b'a']),
            (80, &[]),
            (81, &fqdn),
            (82, &relay),
            (90, &[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (93, &[0, 7]),
            (94, &[1, 3, 16]),
            (97, &[0; 17]),
            (108, &[0, 0, 7, 8]),
            (114, b"urn:x"),
            (118, &[1, 2, 3, 0]),
            (124, &vi),
            (125, &vi),
            (145, &[1]),
            (150, &[1, 2, 3, 4]),
        ]);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        for f in buf.layer_fields(layer) {
            // Scalar array elements reuse the array's descriptor (crate
            // convention, see `push_ipv4_list`).
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
        assert!(buf.field_by_name(layer, "unknown_option").is_none());
        let subs = direct_children(&buf, top_field(&buf, "relay_agent_info"));
        assert_eq!(subs.len(), 7);
        for sub in subs {
            assert!(
                !direct_children(&buf, sub)
                    .iter()
                    .any(|f| f.name() == "data")
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

        assert_layer_and_references(&DhcpDissector);
    }

    // ---- RFC 3396 — split (long) options ---------------------------------

    /// Direct children of an Object / Array field.
    fn direct_children_of<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        parent: &Field<'pkt>,
    ) -> Vec<&'a Field<'pkt>> {
        let range = parent.value.as_container_range().unwrap().clone();
        let fields = buf.fields();
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let f = &fields[i as usize];
            out.push(f);
            i = match &f.value {
                FieldValue::Object(r) | FieldValue::Array(r) => r.end,
                _ => i + 1,
            };
        }
        out
    }

    /// Top-level (layer-level) fields named `name`.
    fn top_fields<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Vec<&'a Field<'pkt>> {
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let mut out = Vec::new();
        let mut i = 0;
        while i < fields.len() {
            let f = &fields[i];
            if f.name() == name {
                out.push(f);
            }
            i += match &f.value {
                FieldValue::Object(r) | FieldValue::Array(r) => (r.end - r.start) as usize + 1,
                _ => 1,
            };
        }
        out
    }

    #[test]
    fn rfc3396_split_classless_static_route_is_concatenated() {
        // Issue reproduction: option 121 split into two instances.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 53, &[1]);
        let first = pkt.len();
        push_option(&mut pkt, 121, &[0x18, 0x0a, 0x00, 0x00, 0x0a]);
        let second = pkt.len();
        push_option(&mut pkt, 121, &[0x00, 0x00, 0x01]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        let res = DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(res.bytes_consumed, pkt.len());

        // One split_option object with two fragments.
        let split = top_fields(&buf, "split_option");
        assert_eq!(split.len(), 1);
        let children = direct_children_of(&buf, split[0]);
        assert_eq!(children[0].name(), "code");
        assert_eq!(children[0].value, FieldValue::U8(121));
        let frags = direct_children_of(&buf, children[1]);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].range, first..first + 7);
        assert_eq!(frags[1].range, second..second + 5);
        let f0 = direct_children_of(&buf, frags[0]);
        assert_eq!(f0[0].name(), "length");
        assert_eq!(f0[0].value, FieldValue::U8(5));
        assert_eq!(f0[1].name(), "data");
        assert_eq!(
            f0[1].value,
            FieldValue::Bytes(&[0x18, 0x0a, 0x00, 0x00, 0x0a])
        );
        assert_eq!(f0[1].range, first + 2..first + 7);

        // The typed decoder ran once, on 18 0a 00 00 0a 00 00 01.
        let arrays = top_fields(&buf, "classless_static_route");
        assert_eq!(arrays.len(), 1);
        let routes = direct_children_of(&buf, arrays[0]);
        assert_eq!(routes.len(), 1);
        let r = direct_children_of(&buf, routes[0]);
        assert_eq!(r[0].value, FieldValue::U8(24));
        // The destination lies inside the first fragment: zero-copy bytes.
        assert_eq!(r[1].value, FieldValue::Bytes(&[0x0a, 0x00, 0x00]));
        assert_eq!(r[1].range, first + 3..first + 6);
        assert_eq!(r[2].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        // The router straddles both fragments: its range spans them.
        assert_eq!(r[2].range, first + 6..second + 5);
        assert!(top_fields(&buf, "unknown_option").is_empty());
    }

    #[test]
    fn rfc3396_split_across_options_and_file_with_overload() {
        // Option 82 split: first part in `options`, second in `file`
        // (option 52 = 1). RFC 3396, Section 5: options, then file, then sname.
        // <https://www.rfc-editor.org/rfc/rfc3396#section-5>
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        // file field: 82, len 4: rest of Remote-ID sub-option
        pkt[108] = 82;
        pkt[109] = 4;
        pkt[110..114].copy_from_slice(b"cdef");
        pkt[114] = 255;
        push_option(&mut pkt, 52, &[1]);
        // options: 82, len 6: Circuit-ID "ab" + Remote-ID header (len 4) + ""
        push_option(&mut pkt, 82, &[1, 2, b'a', b'b', 2, 4]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();

        let split = top_fields(&buf, "split_option");
        assert_eq!(split.len(), 1);
        let frags = direct_children_of(&buf, direct_children_of(&buf, split[0])[1]);
        assert_eq!(frags.len(), 2);
        // Options-area fragment first, then the file fragment.
        assert!(frags[0].range.start > 236);
        assert_eq!(frags[1].range, 108..114);

        let info = top_fields(&buf, "relay_agent_info");
        assert_eq!(info.len(), 1);
        let subs = direct_children_of(&buf, info[0]);
        assert_eq!(subs.len(), 2);
        let remote = direct_children_of(&buf, subs[1]);
        assert_eq!(remote[1].name(), "remote_id");
        // "cdef" lies entirely inside the file fragment → packet bytes.
        assert_eq!(remote[1].value, FieldValue::Bytes(b"cdef"));
        assert_eq!(remote[1].range, 110..114);
    }

    #[test]
    fn rfc3396_split_string_straddling_fragments_uses_scratch() {
        // Host Name split as "exa" + "mple": the value straddles fragments,
        // so it is assembled in the scratch buffer.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 12, b"exa");
        push_option(&mut pkt, 53, &[1]);
        push_option(&mut pkt, 12, b"mple");
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let host = top_fields(&buf, "hostname");
        assert_eq!(host.len(), 1);
        let FieldValue::Scratch(ref r) = host[0].value else {
            panic!("expected scratch value, got {:?}", host[0].value);
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], b"example");

        // The text formatter reads the scratch buffer.
        let ctx = FormatContext {
            packet_data: &pkt,
            scratch: buf.scratch(),
            layer_range: 0..pkt.len() as u32,
            field_range: host[0].range.start as u32..host[0].range.end as u32,
        };
        let mut out = Vec::new();
        (host[0].descriptor.format_fn.unwrap())(&host[0].value, &ctx, &mut out).unwrap();
        assert_eq!(out, b"\"example\"");
        // The message type between the fragments is still decoded.
        assert!(!top_fields(&buf, "dhcp_message_type").is_empty());
    }

    #[test]
    fn rfc3396_single_instances_are_unchanged() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 53, &[1]);
        push_option(&mut pkt, 12, b"host");
        push_option(&mut pkt, 121, &[24, 192, 168, 1, 10, 0, 0, 1]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert!(top_fields(&buf, "split_option").is_empty());
        let host = top_fields(&buf, "hostname")[0];
        assert_eq!(host.value, FieldValue::Bytes(b"host"));
        // The text formatter passes non-scratch values through.
        let ctx = FormatContext {
            packet_data: &pkt,
            scratch: buf.scratch(),
            layer_range: 0..pkt.len() as u32,
            field_range: host.range.start as u32..host.range.end as u32,
        };
        let mut out = Vec::new();
        (host.descriptor.format_fn.unwrap())(&host.value, &ctx, &mut out).unwrap();
        assert_eq!(out, b"\"host\"");
    }

    #[test]
    fn rfc3396_split_value_over_255_octets() {
        // A 300-octet Domain Search List (RFC 3397, option 119) split in two.
        // <https://www.rfc-editor.org/rfc/rfc3397#section-2>
        let mut value = Vec::new();
        while value.len() < 290 {
            value.extend_from_slice(b"\x09abcdefghi\x00");
        }
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 53, &[1]);
        push_option(&mut pkt, 119, &value[..200]);
        push_option(&mut pkt, 119, &value[200..]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let lists = top_fields(&buf, "domain_search");
        assert_eq!(lists.len(), 1);
        assert_eq!(direct_children_of(&buf, lists[0]).len(), value.len() / 11);
    }

    #[test]
    fn rfc3396_split_unknown_option_keeps_concatenated_data() {
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        let first = pkt.len();
        push_option(&mut pkt, 200, &[1, 2]);
        push_option(&mut pkt, 200, &[3]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let unknown = top_fields(&buf, "unknown_option");
        assert_eq!(unknown.len(), 1);
        let children = direct_children_of(&buf, unknown[0]);
        assert_eq!(children[0].value, FieldValue::U8(200));
        assert_eq!(children[0].range, first..first + 1);
        let FieldValue::Scratch(ref r) = children[1].value else {
            panic!("expected scratch, got {:?}", children[1].value);
        };
        assert_eq!(&buf.scratch()[r.start as usize..r.end as usize], &[1, 2, 3]);
        assert_eq!(children[1].range, first + 2..first + 7);
    }

    #[test]
    fn rfc3396_many_instances_are_concatenated() {
        // 300 portions of one option: all are concatenated.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        for _ in 0..300 {
            push_option(&mut pkt, 12, b"h");
        }
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        let split = top_fields(&buf, "split_option");
        assert_eq!(split.len(), 1);
        let frags = direct_children_of(&buf, direct_children_of(&buf, split[0])[1]);
        assert_eq!(frags.len(), 300);
        let host = top_fields(&buf, "hostname");
        assert_eq!(host.len(), 1);
        let FieldValue::Scratch(ref r) = host[0].value else {
            panic!("expected scratch");
        };
        assert_eq!(r.end - r.start, 300);
    }

    #[test]
    fn rfc3396_repeated_fixed_length_option_is_decoded_per_portion() {
        // Two DHCP Message Type options: "01 01" does not fit option 53's
        // one-octet format, so each portion keeps its typed decoding.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 53, &[1]);
        push_option(&mut pkt, 53, &[1]);
        pkt.push(255);
        let mut buf = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut buf, 0).unwrap();
        assert_eq!(top_fields(&buf, "split_option").len(), 1);
        assert_eq!(top_fields(&buf, "dhcp_message_type").len(), 2);
        assert!(top_fields(&buf, "unknown_option").is_empty());
        assert_eq!(buf.layers()[0].display_name, None);
    }

    #[test]
    fn rfc3396_split_numeric_values_are_reassembled() {
        // Time Offset (I32), Lease Time (U32) and the Path MTU Plateau
        // Table (U16 list) split so that values straddle portions; pads
        // between portions are skipped.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 2, &[0xff, 0xff]);
        push_option(&mut pkt, 51, &[0x00, 0x00, 0x0e]);
        push_option(&mut pkt, 25, &[0x02, 0x40, 0x05]);
        pkt.push(0); // pad
        push_option(&mut pkt, 2, &[0xf1, 0xf0]);
        push_option(&mut pkt, 51, &[0x10]);
        push_option(&mut pkt, 25, &[0xdc]);
        pkt.push(255);
        let mut b = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut b, 0).unwrap();
        assert_eq!(top_fields(&b, "split_option").len(), 3);
        assert_eq!(
            top_fields(&b, "time_offset")[0].value,
            FieldValue::I32(-3600)
        );
        assert_eq!(top_fields(&b, "lease_time")[0].value, FieldValue::U32(3600));
        let mtus: Vec<_> = direct_children_of(&b, top_fields(&b, "path_mtu_plateau_table")[0])
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(mtus, vec![FieldValue::U16(576), FieldValue::U16(1500)]);
    }

    #[test]
    fn rfc3396_split_client_fqdn_formats_scratch_name() {
        // Client FQDN (RFC 4702) whose name straddles the two portions.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 81, &[0, 0, 0, 4, b'h', b'o']);
        push_option(&mut pkt, 81, &[b's', b't', 0]);
        pkt.push(255);
        let mut b = DissectBuffer::new();
        DhcpDissector.dissect(&pkt, &mut b, 0).unwrap();
        let fqdn = top_fields(&b, "client_fqdn");
        let name = direct_children_of(&b, fqdn[0])
            .into_iter()
            .find(|f| f.name() == "domain_name")
            .unwrap();
        assert!(matches!(name.value, FieldValue::Scratch(_)));
        let ctx = FormatContext {
            packet_data: &pkt,
            scratch: b.scratch(),
            layer_range: 0..pkt.len() as u32,
            field_range: name.range.start as u32..name.range.end as u32,
        };
        let mut out = Vec::new();
        (name.descriptor.format_fn.unwrap())(&name.value, &ctx, &mut out).unwrap();
        assert_eq!(out, b"\"host\"");
    }

    #[test]
    fn rfc3396_scan_stops_at_truncated_option() {
        // A split option followed by a truncated option: the scan stops,
        // and the parser reports the truncation as before.
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 12, b"a");
        push_option(&mut pkt, 12, b"b");
        pkt.extend_from_slice(&[15, 9, b'x']);
        let mut b = DissectBuffer::new();
        assert!(DhcpDissector.dissect(&pkt, &mut b, 0).is_err());
        let mut pkt = build_dhcp_base(1, 1, [0; 6], [0; 4]);
        push_option(&mut pkt, 12, b"a");
        pkt.push(15); // code without a length octet
        let mut b = DissectBuffer::new();
        assert!(DhcpDissector.dissect(&pkt, &mut b, 0).is_err());
    }
}
