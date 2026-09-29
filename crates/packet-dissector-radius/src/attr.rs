//! RADIUS attribute type system and lookup tables.
//!
//! ## References
//! - RFC 2865, Section 5 (Attributes): <https://www.rfc-editor.org/rfc/rfc2865#section-5>
//! - RFC 2866, Section 5 (Accounting Attribute Definitions): <https://www.rfc-editor.org/rfc/rfc2866#section-5>
//! - RFC 2868, Section 3 (Tunnel attributes): <https://www.rfc-editor.org/rfc/rfc2868#section-3>
//! - RFC 2869, Section 5 (RADIUS Extensions): <https://www.rfc-editor.org/rfc/rfc2869#section-5>
//! - RFC 3162, Section 2 (IPv6 attributes): <https://www.rfc-editor.org/rfc/rfc3162#section-2>
//! - RFC 5176, Sections 2.3 and 3.5 (Dynamic Authorization): <https://www.rfc-editor.org/rfc/rfc5176>
//! - RFC 6929, Section 2 (Extended attribute formats): <https://www.rfc-editor.org/rfc/rfc6929#section-2>
//! - RFC 8044 (Data Types in RADIUS): <https://www.rfc-editor.org/rfc/rfc8044>
//! - RFC 2548 (Microsoft Vendor-specific RADIUS Attributes): <https://www.rfc-editor.org/rfc/rfc2548>
//! - 3GPP TS 29.061 v19.1.0, clause 16.4.7 (3GPP Vendor-Specific attributes):
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.061/>
//! - IANA RADIUS Types registry: <https://www.iana.org/assignments/radius-types/radius-types.xhtml>

/// RADIUS attribute data type.
///
/// RFC 2865, Section 5 — <https://www.rfc-editor.org/rfc/rfc2865#section-5>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadiusAttrType {
    /// RFC 2865, Section 5 — "1-253 octets containing UTF-8 encoded 10646
    /// [7] characters".
    /// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
    Text,
    /// RFC 2865, Section 5 — "1-253 octets containing binary data (values
    /// 0 through 255 decimal, inclusive)".
    /// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
    String,
    /// RFC 2865, Section 5 — "32 bit value, most significant octet first".
    /// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
    Address,
    /// RFC 2865, Section 5 — "32 bit unsigned value, most significant octet
    /// first".
    /// <https://www.rfc-editor.org/rfc/rfc2865#section-5>
    Integer,
    /// RFC 2865, Section 5.26 — Vendor-Specific attribute with a distinct
    /// format (Vendor-Id followed by vendor-defined String).
    /// <https://www.rfc-editor.org/rfc/rfc2865#section-5.26>
    VendorSpecific,
    /// RFC 8044, Section 3.3 — "The "time" data type encodes time as a
    /// 32-bit unsigned value in network byte order and in seconds since
    /// 00:00:00 UTC, January 1, 1970."
    /// <https://www.rfc-editor.org/rfc/rfc8044#section-3.3>
    Time,
    /// RFC 8044, Section 3.12 — 64-bit unsigned integer ("integer64").
    /// <https://www.rfc-editor.org/rfc/rfc8044#section-3.12>
    Integer64,
    /// RFC 8044, Section 3.9 — 128-bit IPv6 address ("ipv6addr").
    /// <https://www.rfc-editor.org/rfc/rfc8044#section-3.9>
    Ipv6Addr,
    /// RFC 8044, Section 3.10 — Reserved (1) + Prefix-Length (1) + Prefix
    /// (0-16 octets) ("ipv6prefix"; RFC 3162, Section 2.3).
    /// <https://www.rfc-editor.org/rfc/rfc8044#section-3.10>
    Ipv6Prefix,
    /// RFC 8044, Section 3.11 — Reserved (1) + Prefix-Length (1) + Prefix
    /// (4 octets) ("ipv4prefix").
    /// <https://www.rfc-editor.org/rfc/rfc8044#section-3.11>
    Ipv4Prefix,
    /// A single octet value, e.g. 3GPP-RAT-Type (TS 29.061, clause
    /// 16.4.7.2: "RAT field is Octet String type.").
    Octet,
    /// RFC 2868, Section 3.1 — Tag (1) followed by a 3-octet integer Value.
    /// <https://www.rfc-editor.org/rfc/rfc2868#section-3.1>
    TaggedInteger,
    /// RFC 2868, Section 3.3 — optional Tag followed by a text String.
    /// "If the Tag field is greater than 0x1F, it SHOULD be interpreted as
    /// the first byte of the following String field."
    /// <https://www.rfc-editor.org/rfc/rfc2868#section-3.3>
    TaggedText,
    /// RFC 2868, Section 3.5 — Tag (1) + Salt (2) + encrypted String.
    /// <https://www.rfc-editor.org/rfc/rfc2868#section-3.5>
    TunnelPassword,
    /// RFC 6929, Section 2.1 — "Extended Type" format: Extended-Type (1) +
    /// Value.
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.1>
    Extended,
    /// RFC 6929, Section 2.2 — "Long Extended Type" format: Extended-Type
    /// (1) + M flag / Reserved (1) + Value.
    /// <https://www.rfc-editor.org/rfc/rfc6929#section-2.2>
    LongExtended,
}

/// Static definition of a RADIUS attribute.
pub struct RadiusAttrDef {
    /// Human-readable name from the RFC.
    pub name: &'static str,
    /// Wire-format data type.
    pub attr_type: RadiusAttrType,
}

impl RadiusAttrDef {
    /// Create a definition from a name and a data type.
    const fn new(name: &'static str, attr_type: RadiusAttrType) -> Self {
        Self { name, attr_type }
    }
}

/// Binary-search a `(code, definition)` table sorted by code.
fn lookup_in<K: Ord + Copy>(
    table: &'static [(K, RadiusAttrDef)],
    code: K,
) -> Option<&'static RadiusAttrDef> {
    table
        .binary_search_by_key(&code, |(c, _)| *c)
        .ok()
        .map(|i| &table[i].1)
}

/// Look up an attribute definition by type code.
///
/// Returns `None` for unknown attribute types (they will be rendered as raw bytes).
pub fn lookup_attr(code: u8) -> Option<&'static RadiusAttrDef> {
    lookup_in(RADIUS_ATTRS, code)
}

/// Extended-Type value that carries an Extended-Vendor-Specific attribute.
///
/// RFC 6929, Section 2.4 — <https://www.rfc-editor.org/rfc/rfc6929#section-2.4>
pub const EXTENDED_TYPE_EVS: u8 = 26;

/// Look up an extended attribute ("Type.Extended-Type", RFC 6929,
/// Section 2.1) by its outer Type and Extended-Type.
/// <https://www.rfc-editor.org/rfc/rfc6929#section-2.1>
pub fn lookup_extended_attr(code: u8, ext_type: u8) -> Option<&'static RadiusAttrDef> {
    lookup_in(EXTENDED_ATTRS, (code, ext_type))
}

/// Returns the Extended-Vendor-Specific name for an extended Type
/// (241-246).
///
/// RFC 6929, Section 2.4 — <https://www.rfc-editor.org/rfc/rfc6929#section-2.4>
pub fn evs_name(code: u8) -> Option<&'static str> {
    match code {
        241 => Some("Extended-Vendor-Specific-1"),
        242 => Some("Extended-Vendor-Specific-2"),
        243 => Some("Extended-Vendor-Specific-3"),
        244 => Some("Extended-Vendor-Specific-4"),
        245 => Some("Extended-Vendor-Specific-5"),
        246 => Some("Extended-Vendor-Specific-6"),
        _ => None,
    }
}

/// Resolve the display name of an attribute, taking the Extended-Type into
/// account for the RFC 6929 extended attribute space.
pub fn attr_display_name(code: u8, ext_type: Option<u8>) -> Option<&'static str> {
    if let Some(ext) = ext_type {
        if ext == EXTENDED_TYPE_EVS {
            if let Some(name) = evs_name(code) {
                return Some(name);
            }
        }
        if let Some(def) = lookup_extended_attr(code, ext) {
            return Some(def.name);
        }
    }
    lookup_attr(code).map(|d| d.name)
}

/// Returns a human-readable name for an enumerated extended attribute
/// value ("Type.Extended-Type", RFC 6929, Section 2.1).
/// <https://www.rfc-editor.org/rfc/rfc6929#section-2.1>
pub fn extended_enum_value_name(code: u8, ext_type: u8, val: u32) -> Option<&'static str> {
    match (code, ext_type) {
        // RFC 7930, Section 4 — "The Original-Packet-Code contains the code
        // from the request that generated the protocol error".
        // <https://www.rfc-editor.org/rfc/rfc7930#section-4>
        (241, 4) => u8::try_from(val).ok().map(code_name),
        _ => None,
    }
}

/// SMI Network Management Private Enterprise Code of 3GPP.
pub const VENDOR_3GPP: u32 = 10415;

/// SMI Network Management Private Enterprise Code of Microsoft.
pub const VENDOR_MICROSOFT: u32 = 311;

/// Returns the organization name for a Vendor-Id (SMI Network Management
/// Private Enterprise Code) of vendors commonly seen in RADIUS.
///
/// IANA Private Enterprise Numbers —
/// <https://www.iana.org/assignments/enterprise-numbers/>
pub fn vendor_name(vendor_id: u32) -> Option<&'static str> {
    match vendor_id {
        9 => Some("Cisco"),
        VENDOR_MICROSOFT => Some("Microsoft"),
        VENDOR_3GPP => Some("3GPP"),
        24757 => Some("WiMAX Forum"),
        _ => None,
    }
}

/// Look up a vendor-specific sub-attribute definition.
///
/// Returns `None` for vendors or vendor types without a dictionary.
pub fn lookup_vendor_attr(vendor_id: u32, vendor_type: u8) -> Option<&'static RadiusAttrDef> {
    match vendor_id {
        VENDOR_3GPP => lookup_in(TGPP_ATTRS, vendor_type),
        VENDOR_MICROSOFT => lookup_in(MICROSOFT_ATTRS, vendor_type),
        _ => None,
    }
}

/// Returns a human-readable name for an enumerated 3GPP sub-attribute
/// value.
///
/// 3GPP TS 29.061 v19.1.0, clause 16.4.7.2.
pub fn tgpp_value_name(vendor_type: u8, val: u32) -> Option<&'static str> {
    match (vendor_type, val) {
        // 3GPP-PDP-Type — "PDP type may have the following values:"
        (3, 0) => Some("IPv4"),
        (3, 1) => Some("PPP"),
        (3, 2) => Some("IPv6"),
        (3, 3) => Some("IPv4v6"),
        (3, 4) => Some("Non-IP"),
        (3, 5) => Some("Unstructured"),
        (3, 6) => Some("Ethernet"),
        // 3GPP-Allocate-IP-Type — IP Type field.
        (27, 0) => Some("Do not allocate IPv4 address or IPv6 prefix"),
        (27, 1) => Some("Allocate IPv4 address"),
        (27, 2) => Some("Allocate IPv6 prefix"),
        (27, 3) => Some("Allocate IPv4 address and IPv6 prefix"),
        _ => None,
    }
}

/// Returns a human-readable name for an enumerated Microsoft
/// sub-attribute value.
///
/// RFC 2548 — <https://www.rfc-editor.org/rfc/rfc2548>
pub fn microsoft_value_name(vendor_type: u8, val: u32) -> Option<&'static str> {
    match (vendor_type, val) {
        // RFC 2548, Section 2.4.4 — MS-MPPE-Encryption-Policy.
        // <https://www.rfc-editor.org/rfc/rfc2548#section-2.4.4>
        (7, 1) => Some("Encryption-Allowed"),
        (7, 2) => Some("Encryption-Required"),
        // RFC 2548, Section 2.5.1 — MS-BAP-Usage.
        // <https://www.rfc-editor.org/rfc/rfc2548#section-2.5.1>
        (13, 0) => Some("BAP usage not allowed"),
        (13, 1) => Some("BAP usage allowed"),
        (13, 2) => Some("BAP usage required"),
        // RFC 2548, Section 2.6.3 — MS-ARAP-Password-Change-Reason.
        // <https://www.rfc-editor.org/rfc/rfc2548#section-2.6.3>
        (21, 1) => Some("Just-Change-Password"),
        (21, 2) => Some("Expired-Password"),
        (21, 3) => Some("Admin-Requires-Password-Change"),
        (21, 4) => Some("Password-Too-Short"),
        // RFC 2548, Section 2.7.4 — MS-Acct-Auth-Type.
        // <https://www.rfc-editor.org/rfc/rfc2548#section-2.7.4>
        (23, 1) => Some("PAP"),
        (23, 2) => Some("CHAP"),
        (23, 3) => Some("MS-CHAP-1"),
        (23, 4) => Some("MS-CHAP-2"),
        (23, 5) => Some("EAP"),
        // RFC 2548, Section 2.7.5 — MS-Acct-EAP-Type.
        // <https://www.rfc-editor.org/rfc/rfc2548#section-2.7.5>
        (24, 4) => Some("MD5"),
        (24, 5) => Some("OTP"),
        (24, 6) => Some("Generic Token Card"),
        (24, 13) => Some("TLS"),
        _ => None,
    }
}

/// Returns a human-readable name for a RADIUS packet Code value.
///
/// RFC 2865, Section 3 — Code field.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-3>
/// RFC 2866, Section 3 — adds Accounting-Request (4) and Accounting-Response (5).
/// <https://www.rfc-editor.org/rfc/rfc2866#section-3>
/// RFC 5176, Section 2.3 — adds Disconnect and CoA codes 40-45.
/// <https://www.rfc-editor.org/rfc/rfc5176#section-2.3>
pub fn code_name(code: u8) -> &'static str {
    match code {
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        13 => "Status-Client",
        // RFC 5176, Section 2.3 — Dynamic Authorization Extensions.
        // <https://www.rfc-editor.org/rfc/rfc5176#section-2.3>
        40 => "Disconnect-Request",
        41 => "Disconnect-ACK",
        42 => "Disconnect-NAK",
        43 => "CoA-Request",
        44 => "CoA-ACK",
        45 => "CoA-NAK",
        // RFC 7930, Section 4 — "This document defines a new RADIUS code,
        // 52, called Protocol-Error."
        // <https://www.rfc-editor.org/rfc/rfc7930#section-4>
        52 => "Protocol-Error",
        255 => "Reserved",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for an integer-enum attribute value, if applicable.
///
/// Dispatches to the appropriate sub-function based on the attribute type code.
/// Returns `None` for non-enum attributes or unknown enum values.
pub fn enum_value_name(attr_type: u8, val: u32) -> Option<&'static str> {
    match attr_type {
        6 => service_type_name(val),
        7 => framed_protocol_name(val),
        10 => framed_routing_name(val),
        13 => framed_compression_name(val),
        15 => login_service_name(val),
        29 => termination_action_name(val),
        40 => acct_status_type_name(val),
        45 => acct_authentic_name(val),
        49 => acct_terminate_cause_name(val),
        57 => ingress_filters_name(val),
        61 => nas_port_type_name(val),
        64 => tunnel_type_name(val),
        65 => tunnel_medium_type_name(val),
        72 => arap_zone_access_name(val),
        76 => prompt_name(val),
        101 => error_cause_name(val),
        _ => None,
    }
}

/// RFC 4675, Section 2.2 — Ingress-Filters values.
/// <https://www.rfc-editor.org/rfc/rfc4675#section-2.2>
fn ingress_filters_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("Enabled"),
        2 => Some("Disabled"),
        _ => None,
    }
}

/// RFC 2868, Section 3.1 — Tunnel-Type values (13 added by RFC 3580,
/// Section 3.31).
/// <https://www.rfc-editor.org/rfc/rfc2868#section-3.1>
/// <https://www.rfc-editor.org/rfc/rfc3580#section-3.31>
fn tunnel_type_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("Point-to-Point Tunneling Protocol (PPTP)"),
        2 => Some("Layer Two Forwarding (L2F)"),
        3 => Some("Layer Two Tunneling Protocol (L2TP)"),
        4 => Some("Ascend Tunnel Management Protocol (ATMP)"),
        5 => Some("Virtual Tunneling Protocol (VTP)"),
        6 => Some("IP Authentication Header in the Tunnel-mode (AH)"),
        7 => Some("IP-in-IP Encapsulation (IP-IP)"),
        8 => Some("Minimal IP-in-IP Encapsulation (MIN-IP-IP)"),
        9 => Some("IP Encapsulating Security Payload in the Tunnel-mode (ESP)"),
        10 => Some("Generic Route Encapsulation (GRE)"),
        11 => Some("Bay Dial Virtual Services (DVS)"),
        12 => Some("IP-in-IP Tunneling"),
        13 => Some("Virtual LANs (VLAN)"),
        _ => None,
    }
}

/// RFC 2868, Section 3.2 — Tunnel-Medium-Type values.
/// <https://www.rfc-editor.org/rfc/rfc2868#section-3.2>
fn tunnel_medium_type_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("IPv4 (IP version 4)"),
        2 => Some("IPv6 (IP version 6)"),
        3 => Some("NSAP"),
        4 => Some("HDLC (8-bit multidrop)"),
        5 => Some("BBN 1822"),
        6 => Some("802 (includes all 802 media plus Ethernet \"canonical format\")"),
        7 => Some("E.163 (POTS)"),
        8 => Some("E.164 (SMDS, Frame Relay, ATM)"),
        9 => Some("F.69 (Telex)"),
        10 => Some("X.121 (X.25, Frame Relay)"),
        11 => Some("IPX"),
        12 => Some("Appletalk"),
        13 => Some("Decnet IV"),
        14 => Some("Banyan Vines"),
        15 => Some("E.164 with NSAP format subaddress"),
        _ => None,
    }
}

/// RFC 2869, Section 5.6 — ARAP-Zone-Access values.
/// <https://www.rfc-editor.org/rfc/rfc2869#section-5.6>
fn arap_zone_access_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("Only allow access to default zone"),
        2 => Some("Use zone filter inclusively"),
        4 => Some("Use zone filter exclusively"),
        _ => None,
    }
}

/// RFC 2869, Section 5.10 — Prompt values.
/// <https://www.rfc-editor.org/rfc/rfc2869#section-5.10>
fn prompt_name(val: u32) -> Option<&'static str> {
    match val {
        0 => Some("No Echo"),
        1 => Some("Echo"),
        _ => None,
    }
}

/// RFC 5176, Section 3.5 — Error-Cause values; 509 is registered by
/// RFC 5580 and 601 by RFC 7930 (IANA "Values for RADIUS Attribute 101").
/// <https://www.rfc-editor.org/rfc/rfc5176#section-3.5>
/// <https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-18>
fn error_cause_name(val: u32) -> Option<&'static str> {
    match val {
        201 => Some("Residual Session Context Removed"),
        202 => Some("Invalid EAP Packet (Ignored)"),
        401 => Some("Unsupported Attribute"),
        402 => Some("Missing Attribute"),
        403 => Some("NAS Identification Mismatch"),
        404 => Some("Invalid Request"),
        405 => Some("Unsupported Service"),
        406 => Some("Unsupported Extension"),
        407 => Some("Invalid Attribute Value"),
        501 => Some("Administratively Prohibited"),
        502 => Some("Request Not Routable (Proxy)"),
        503 => Some("Session Context Not Found"),
        504 => Some("Session Context Not Removable"),
        505 => Some("Other Proxy Processing Error"),
        506 => Some("Resources Unavailable"),
        507 => Some("Request Initiated"),
        508 => Some("Multiple Session Selection Unsupported"),
        509 => Some("Location-Info-Required"),
        601 => Some("Response Too Big"),
        _ => None,
    }
}

/// RFC 2865, Section 5.6 — Service-Type values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.6>
fn service_type_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("Login"),
        2 => Some("Framed"),
        3 => Some("Callback Login"),
        4 => Some("Callback Framed"),
        5 => Some("Outbound"),
        6 => Some("Administrative"),
        7 => Some("NAS Prompt"),
        8 => Some("Authenticate Only"),
        9 => Some("Callback NAS Prompt"),
        10 => Some("Call Check"),
        11 => Some("Callback Administrative"),
        _ => None,
    }
}

/// RFC 2865, Section 5.7 — Framed-Protocol values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.7>
fn framed_protocol_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("PPP"),
        2 => Some("SLIP"),
        3 => Some("ARAP"),
        4 => Some("Gandalf"),
        5 => Some("Xylogics IPX/SLIP"),
        6 => Some("X.75 Synchronous"),
        _ => None,
    }
}

/// RFC 2865, Section 5.10 — Framed-Routing values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.10>
fn framed_routing_name(val: u32) -> Option<&'static str> {
    match val {
        0 => Some("None"),
        1 => Some("Send routing packets"),
        2 => Some("Listen for routing packets"),
        3 => Some("Send and Listen"),
        _ => None,
    }
}

/// RFC 2865, Section 5.13 — Framed-Compression values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.13>
fn framed_compression_name(val: u32) -> Option<&'static str> {
    match val {
        0 => Some("None"),
        1 => Some("VJ TCP/IP header compression"),
        2 => Some("IPX header compression"),
        3 => Some("Stac-LZS compression"),
        _ => None,
    }
}

/// RFC 2865, Section 5.15 — Login-Service values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.15>
fn login_service_name(val: u32) -> Option<&'static str> {
    match val {
        0 => Some("Telnet"),
        1 => Some("Rlogin"),
        2 => Some("TCP Clear"),
        3 => Some("PortMaster"),
        4 => Some("LAT"),
        5 => Some("X.25-PAD"),
        6 => Some("X.25-T3POS"),
        8 => Some("TCP Clear Quiet"),
        _ => None,
    }
}

/// RFC 2865, Section 5.29 — Termination-Action values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.29>
fn termination_action_name(val: u32) -> Option<&'static str> {
    match val {
        0 => Some("Default"),
        1 => Some("RADIUS-Request"),
        _ => None,
    }
}

/// RFC 2866, Section 5.1 — Acct-Status-Type values.
/// <https://www.rfc-editor.org/rfc/rfc2866#section-5.1>
fn acct_status_type_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("Start"),
        2 => Some("Stop"),
        3 => Some("Interim-Update"),
        7 => Some("Accounting-On"),
        8 => Some("Accounting-Off"),
        // RFC 2867, Section 3 — https://www.rfc-editor.org/rfc/rfc2867#section-3
        9 => Some("Tunnel-Start"),
        10 => Some("Tunnel-Stop"),
        11 => Some("Tunnel-Reject"),
        12 => Some("Tunnel-Link-Start"),
        13 => Some("Tunnel-Link-Stop"),
        14 => Some("Tunnel-Link-Reject"),
        // IANA "Values for RADIUS Attribute 40, Acct-Status-Type" —
        // https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-10
        15 => Some("Failed"),
        _ => None,
    }
}

/// RFC 2866, Section 5.6 — Acct-Authentic values.
/// <https://www.rfc-editor.org/rfc/rfc2866#section-5.6>
fn acct_authentic_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("RADIUS"),
        2 => Some("Local"),
        3 => Some("Remote"),
        _ => None,
    }
}

/// RFC 2866, Section 5.10 — Acct-Terminate-Cause values.
/// <https://www.rfc-editor.org/rfc/rfc2866#section-5.10>
fn acct_terminate_cause_name(val: u32) -> Option<&'static str> {
    match val {
        1 => Some("User Request"),
        2 => Some("Lost Carrier"),
        3 => Some("Lost Service"),
        4 => Some("Idle Timeout"),
        5 => Some("Session Timeout"),
        6 => Some("Admin Reset"),
        7 => Some("Admin Reboot"),
        8 => Some("Port Error"),
        9 => Some("NAS Error"),
        10 => Some("NAS Request"),
        11 => Some("NAS Reboot"),
        12 => Some("Port Unneeded"),
        13 => Some("Port Preempted"),
        14 => Some("Port Suspended"),
        15 => Some("Service Unavailable"),
        16 => Some("Callback"),
        17 => Some("User Error"),
        18 => Some("Host Request"),
        _ => None,
    }
}

/// RFC 2865, Section 5.41 — NAS-Port-Type values.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-5.41>
fn nas_port_type_name(val: u32) -> Option<&'static str> {
    match val {
        0 => Some("Async"),
        1 => Some("Sync"),
        2 => Some("ISDN Sync"),
        3 => Some("ISDN Async V.120"),
        4 => Some("ISDN Async V.110"),
        5 => Some("Virtual"),
        6 => Some("PIAFS"),
        7 => Some("HDLC Clear Channel"),
        8 => Some("X.25"),
        9 => Some("X.75"),
        10 => Some("G.3 Fax"),
        11 => Some("SDSL"),
        12 => Some("ADSL-CAP"),
        13 => Some("ADSL-DMT"),
        14 => Some("IDSL"),
        15 => Some("Ethernet"),
        16 => Some("xDSL"),
        17 => Some("Cable"),
        18 => Some("Wireless - Other"),
        19 => Some("Wireless - IEEE 802.11"),
        _ => None,
    }
}

/// Standard RADIUS attributes sorted by type code for binary search.
///
/// - RFC 2865, Section 5 (types 1–39, 60–63):
///   <https://www.rfc-editor.org/rfc/rfc2865#section-5>
/// - RFC 2866, Section 5 (types 40–51):
///   <https://www.rfc-editor.org/rfc/rfc2866#section-5>
/// - Types 52–59 and 64–246: names and data types from the IANA "RADIUS
///   Attribute Types" registry (data type names per RFC 8044), with the
///   defining RFC noted per entry:
///   <https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-2>
static RADIUS_ATTRS: &[(u8, RadiusAttrDef)] = &[
    (
        1,
        RadiusAttrDef {
            name: "User-Name",
            // RFC 2865, Section 5.1 — https://www.rfc-editor.org/rfc/rfc2865#section-5.1
            // The attribute format diagram labels the value field "String".
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        2,
        RadiusAttrDef {
            name: "User-Password",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        3,
        RadiusAttrDef {
            name: "CHAP-Password",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        4,
        RadiusAttrDef {
            name: "NAS-IP-Address",
            attr_type: RadiusAttrType::Address,
        },
    ),
    (
        5,
        RadiusAttrDef {
            name: "NAS-Port",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        6,
        RadiusAttrDef {
            name: "Service-Type",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        7,
        RadiusAttrDef {
            name: "Framed-Protocol",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        8,
        RadiusAttrDef {
            name: "Framed-IP-Address",
            attr_type: RadiusAttrType::Address,
        },
    ),
    (
        9,
        RadiusAttrDef {
            name: "Framed-IP-Netmask",
            attr_type: RadiusAttrType::Address,
        },
    ),
    (
        10,
        RadiusAttrDef {
            name: "Framed-Routing",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        11,
        RadiusAttrDef {
            name: "Filter-Id",
            attr_type: RadiusAttrType::Text,
        },
    ),
    (
        12,
        RadiusAttrDef {
            name: "Framed-MTU",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        13,
        RadiusAttrDef {
            name: "Framed-Compression",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        14,
        RadiusAttrDef {
            name: "Login-IP-Host",
            attr_type: RadiusAttrType::Address,
        },
    ),
    (
        15,
        RadiusAttrDef {
            name: "Login-Service",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        16,
        RadiusAttrDef {
            name: "Login-TCP-Port",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        18,
        RadiusAttrDef {
            name: "Reply-Message",
            attr_type: RadiusAttrType::Text,
        },
    ),
    (
        19,
        RadiusAttrDef {
            name: "Callback-Number",
            // RFC 2865, Section 5.19 — https://www.rfc-editor.org/rfc/rfc2865#section-5.19
            // Value field labelled "String" ("site or application specific").
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        20,
        RadiusAttrDef {
            name: "Callback-Id",
            // RFC 2865, Section 5.20 — https://www.rfc-editor.org/rfc/rfc2865#section-5.20
            // Value field labelled "String" ("site or application specific").
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        22,
        RadiusAttrDef {
            name: "Framed-Route",
            attr_type: RadiusAttrType::Text,
        },
    ),
    (
        23,
        RadiusAttrDef {
            name: "Framed-IPX-Network",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        24,
        RadiusAttrDef {
            name: "State",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        25,
        RadiusAttrDef {
            name: "Class",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        26,
        RadiusAttrDef {
            name: "Vendor-Specific",
            attr_type: RadiusAttrType::VendorSpecific,
        },
    ),
    (
        27,
        RadiusAttrDef {
            name: "Session-Timeout",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        28,
        RadiusAttrDef {
            name: "Idle-Timeout",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        29,
        RadiusAttrDef {
            name: "Termination-Action",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        30,
        RadiusAttrDef {
            name: "Called-Station-Id",
            // RFC 2865, Section 5.30 — https://www.rfc-editor.org/rfc/rfc2865#section-5.30
            // Value field labelled "String" (phone number / site-specific format).
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        31,
        RadiusAttrDef {
            name: "Calling-Station-Id",
            // RFC 2865, Section 5.31 — https://www.rfc-editor.org/rfc/rfc2865#section-5.31
            // Value field labelled "String" (phone number / site-specific format).
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        32,
        RadiusAttrDef {
            name: "NAS-Identifier",
            // RFC 2865, Section 5.32 — https://www.rfc-editor.org/rfc/rfc2865#section-5.32
            // Value field labelled "String".
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        33,
        RadiusAttrDef {
            name: "Proxy-State",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        34,
        RadiusAttrDef {
            name: "Login-LAT-Service",
            // RFC 2865, Section 5.34 — https://www.rfc-editor.org/rfc/rfc2865#section-5.34
            // Value field labelled "String" (LAT service identity).
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        35,
        RadiusAttrDef {
            name: "Login-LAT-Node",
            // RFC 2865, Section 5.35 — https://www.rfc-editor.org/rfc/rfc2865#section-5.35
            // Value field labelled "String" (LAT node identity).
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        36,
        RadiusAttrDef {
            name: "Login-LAT-Group",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        37,
        RadiusAttrDef {
            name: "Framed-AppleTalk-Link",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        38,
        RadiusAttrDef {
            name: "Framed-AppleTalk-Network",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        39,
        RadiusAttrDef {
            name: "Framed-AppleTalk-Zone",
            // RFC 2865, Section 5.39 — https://www.rfc-editor.org/rfc/rfc2865#section-5.39
            // Value field labelled "String" (AppleTalk Default Zone name).
            attr_type: RadiusAttrType::String,
        },
    ),
    // RFC 2866 Accounting attributes (types 40–51)
    (
        40,
        RadiusAttrDef {
            name: "Acct-Status-Type",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        41,
        RadiusAttrDef {
            name: "Acct-Delay-Time",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        42,
        RadiusAttrDef {
            name: "Acct-Input-Octets",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        43,
        RadiusAttrDef {
            name: "Acct-Output-Octets",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        44,
        RadiusAttrDef {
            name: "Acct-Session-Id",
            attr_type: RadiusAttrType::Text,
        },
    ),
    (
        45,
        RadiusAttrDef {
            name: "Acct-Authentic",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        46,
        RadiusAttrDef {
            name: "Acct-Session-Time",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        47,
        RadiusAttrDef {
            name: "Acct-Input-Packets",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        48,
        RadiusAttrDef {
            name: "Acct-Output-Packets",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        49,
        RadiusAttrDef {
            name: "Acct-Terminate-Cause",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        50,
        RadiusAttrDef {
            name: "Acct-Multi-Session-Id",
            // RFC 2866, Section 5.11 — https://www.rfc-editor.org/rfc/rfc2866#section-5.11
            // Both the attribute format diagram and the field definition label the
            // value "String" (although its contents SHOULD be UTF-8).
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        51,
        RadiusAttrDef {
            name: "Acct-Link-Count",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        52,
        RadiusAttrDef::new("Acct-Input-Gigawords", RadiusAttrType::Integer),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        53,
        RadiusAttrDef::new("Acct-Output-Gigawords", RadiusAttrType::Integer),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        55,
        RadiusAttrDef::new("Event-Timestamp", RadiusAttrType::Time),
    ),
    // RFC 4675 — https://www.rfc-editor.org/rfc/rfc4675
    (
        56,
        RadiusAttrDef::new("Egress-VLANID", RadiusAttrType::Integer),
    ),
    // RFC 4675 — https://www.rfc-editor.org/rfc/rfc4675
    (
        57,
        RadiusAttrDef::new("Ingress-Filters", RadiusAttrType::Integer),
    ),
    // RFC 4675 — https://www.rfc-editor.org/rfc/rfc4675
    (
        58,
        RadiusAttrDef::new("Egress-VLAN-Name", RadiusAttrType::Text),
    ),
    // RFC 4675 — https://www.rfc-editor.org/rfc/rfc4675
    (
        59,
        RadiusAttrDef::new("User-Priority-Table", RadiusAttrType::String),
    ),
    // RFC 2865 attributes (types 60–63)
    (
        60,
        RadiusAttrDef {
            name: "CHAP-Challenge",
            attr_type: RadiusAttrType::String,
        },
    ),
    (
        61,
        RadiusAttrDef {
            name: "NAS-Port-Type",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        62,
        RadiusAttrDef {
            name: "Port-Limit",
            attr_type: RadiusAttrType::Integer,
        },
    ),
    (
        63,
        RadiusAttrDef {
            name: "Login-LAT-Port",
            // RFC 2865, Section 5.43 — https://www.rfc-editor.org/rfc/rfc2865#section-5.43
            // Value field labelled "String" (LAT port identity).
            attr_type: RadiusAttrType::String,
        },
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        64,
        RadiusAttrDef::new("Tunnel-Type", RadiusAttrType::TaggedInteger),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        65,
        RadiusAttrDef::new("Tunnel-Medium-Type", RadiusAttrType::TaggedInteger),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        66,
        RadiusAttrDef::new("Tunnel-Client-Endpoint", RadiusAttrType::TaggedText),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        67,
        RadiusAttrDef::new("Tunnel-Server-Endpoint", RadiusAttrType::TaggedText),
    ),
    // RFC 2867 — https://www.rfc-editor.org/rfc/rfc2867
    (
        68,
        RadiusAttrDef::new("Acct-Tunnel-Connection", RadiusAttrType::Text),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        69,
        RadiusAttrDef::new("Tunnel-Password", RadiusAttrType::TunnelPassword),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        70,
        RadiusAttrDef::new("ARAP-Password", RadiusAttrType::String),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        71,
        RadiusAttrDef::new("ARAP-Features", RadiusAttrType::String),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        72,
        RadiusAttrDef::new("ARAP-Zone-Access", RadiusAttrType::Integer),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        73,
        RadiusAttrDef::new("ARAP-Security", RadiusAttrType::Integer),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        74,
        RadiusAttrDef::new("ARAP-Security-Data", RadiusAttrType::Text),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        75,
        RadiusAttrDef::new("Password-Retry", RadiusAttrType::Integer),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (76, RadiusAttrDef::new("Prompt", RadiusAttrType::Integer)),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (77, RadiusAttrDef::new("Connect-Info", RadiusAttrType::Text)),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        78,
        RadiusAttrDef::new("Configuration-Token", RadiusAttrType::Text),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        79,
        RadiusAttrDef::new("EAP-Message", RadiusAttrType::String),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        80,
        RadiusAttrDef::new("Message-Authenticator", RadiusAttrType::String),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        81,
        RadiusAttrDef::new("Tunnel-Private-Group-ID", RadiusAttrType::TaggedText),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        82,
        RadiusAttrDef::new("Tunnel-Assignment-ID", RadiusAttrType::TaggedText),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        83,
        RadiusAttrDef::new("Tunnel-Preference", RadiusAttrType::TaggedInteger),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        84,
        RadiusAttrDef::new("ARAP-Challenge-Response", RadiusAttrType::String),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (
        85,
        RadiusAttrDef::new("Acct-Interim-Interval", RadiusAttrType::Integer),
    ),
    // RFC 2867 — https://www.rfc-editor.org/rfc/rfc2867
    (
        86,
        RadiusAttrDef::new("Acct-Tunnel-Packets-Lost", RadiusAttrType::Integer),
    ),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (87, RadiusAttrDef::new("NAS-Port-Id", RadiusAttrType::Text)),
    // RFC 2869 — https://www.rfc-editor.org/rfc/rfc2869
    (88, RadiusAttrDef::new("Framed-Pool", RadiusAttrType::Text)),
    // RFC 4372 — https://www.rfc-editor.org/rfc/rfc4372
    (
        89,
        RadiusAttrDef::new("Chargeable-User-Identity", RadiusAttrType::String),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        90,
        RadiusAttrDef::new("Tunnel-Client-Auth-ID", RadiusAttrType::TaggedText),
    ),
    // RFC 2868 — https://www.rfc-editor.org/rfc/rfc2868
    (
        91,
        RadiusAttrDef::new("Tunnel-Server-Auth-ID", RadiusAttrType::TaggedText),
    ),
    // RFC 4849 — https://www.rfc-editor.org/rfc/rfc4849
    (
        92,
        RadiusAttrDef::new("NAS-Filter-Rule", RadiusAttrType::Text),
    ),
    // RFC 7155 — https://www.rfc-editor.org/rfc/rfc7155
    (
        94,
        RadiusAttrDef::new("Originating-Line-Info", RadiusAttrType::String),
    ),
    // RFC 3162 — https://www.rfc-editor.org/rfc/rfc3162
    (
        95,
        RadiusAttrDef::new("NAS-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 3162 — https://www.rfc-editor.org/rfc/rfc3162
    (
        96,
        RadiusAttrDef::new("Framed-Interface-Id", RadiusAttrType::String),
    ),
    // RFC 3162 — https://www.rfc-editor.org/rfc/rfc3162
    (
        97,
        RadiusAttrDef::new("Framed-IPv6-Prefix", RadiusAttrType::Ipv6Prefix),
    ),
    // RFC 3162 — https://www.rfc-editor.org/rfc/rfc3162
    (
        98,
        RadiusAttrDef::new("Login-IPv6-Host", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 3162 — https://www.rfc-editor.org/rfc/rfc3162
    (
        99,
        RadiusAttrDef::new("Framed-IPv6-Route", RadiusAttrType::Text),
    ),
    // RFC 3162 — https://www.rfc-editor.org/rfc/rfc3162
    (
        100,
        RadiusAttrDef::new("Framed-IPv6-Pool", RadiusAttrType::Text),
    ),
    // RFC 5176 — https://www.rfc-editor.org/rfc/rfc5176
    (
        101,
        RadiusAttrDef::new("Error-Cause", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        102,
        RadiusAttrDef::new("EAP-Key-Name", RadiusAttrType::String),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        103,
        RadiusAttrDef::new("Digest-Response", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        104,
        RadiusAttrDef::new("Digest-Realm", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        105,
        RadiusAttrDef::new("Digest-Nonce", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        106,
        RadiusAttrDef::new("Digest-Response-Auth", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        107,
        RadiusAttrDef::new("Digest-Nextnonce", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        108,
        RadiusAttrDef::new("Digest-Method", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (109, RadiusAttrDef::new("Digest-URI", RadiusAttrType::Text)),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (110, RadiusAttrDef::new("Digest-Qop", RadiusAttrType::Text)),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        111,
        RadiusAttrDef::new("Digest-Algorithm", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        112,
        RadiusAttrDef::new("Digest-Entity-Body-Hash", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        113,
        RadiusAttrDef::new("Digest-CNonce", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        114,
        RadiusAttrDef::new("Digest-Nonce-Count", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        115,
        RadiusAttrDef::new("Digest-Username", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        116,
        RadiusAttrDef::new("Digest-Opaque", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        117,
        RadiusAttrDef::new("Digest-Auth-Param", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        118,
        RadiusAttrDef::new("Digest-AKA-Auts", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        119,
        RadiusAttrDef::new("Digest-Domain", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (
        120,
        RadiusAttrDef::new("Digest-Stale", RadiusAttrType::Text),
    ),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (121, RadiusAttrDef::new("Digest-HA1", RadiusAttrType::Text)),
    // RFC 5090 — https://www.rfc-editor.org/rfc/rfc5090
    (122, RadiusAttrDef::new("SIP-AOR", RadiusAttrType::Text)),
    // RFC 4818 — https://www.rfc-editor.org/rfc/rfc4818
    (
        123,
        RadiusAttrDef::new("Delegated-IPv6-Prefix", RadiusAttrType::Ipv6Prefix),
    ),
    // RFC 5447 — https://www.rfc-editor.org/rfc/rfc5447
    (
        124,
        RadiusAttrDef::new("MIP6-Feature-Vector", RadiusAttrType::Integer64),
    ),
    // RFC 5447 — https://www.rfc-editor.org/rfc/rfc5447
    (
        125,
        RadiusAttrDef::new("MIP6-Home-Link-Prefix", RadiusAttrType::String),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        126,
        RadiusAttrDef::new("Operator-Name", RadiusAttrType::Text),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        127,
        RadiusAttrDef::new("Location-Information", RadiusAttrType::String),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        128,
        RadiusAttrDef::new("Location-Data", RadiusAttrType::String),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        129,
        RadiusAttrDef::new("Basic-Location-Policy-Rules", RadiusAttrType::String),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        130,
        RadiusAttrDef::new("Extended-Location-Policy-Rules", RadiusAttrType::String),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        131,
        RadiusAttrDef::new("Location-Capable", RadiusAttrType::Integer),
    ),
    // RFC 5580 — https://www.rfc-editor.org/rfc/rfc5580
    (
        132,
        RadiusAttrDef::new("Requested-Location-Info", RadiusAttrType::Integer),
    ),
    // RFC 5607 — https://www.rfc-editor.org/rfc/rfc5607
    (
        133,
        RadiusAttrDef::new("Framed-Management-Protocol", RadiusAttrType::Integer),
    ),
    // RFC 5607 — https://www.rfc-editor.org/rfc/rfc5607
    (
        134,
        RadiusAttrDef::new("Management-Transport-Protection", RadiusAttrType::Integer),
    ),
    // RFC 5607 — https://www.rfc-editor.org/rfc/rfc5607
    (
        135,
        RadiusAttrDef::new("Management-Policy-Id", RadiusAttrType::Text),
    ),
    // RFC 5607 — https://www.rfc-editor.org/rfc/rfc5607
    (
        136,
        RadiusAttrDef::new("Management-Privilege-Level", RadiusAttrType::Integer),
    ),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (
        137,
        RadiusAttrDef::new("PKM-SS-Cert", RadiusAttrType::String),
    ),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (
        138,
        RadiusAttrDef::new("PKM-CA-Cert", RadiusAttrType::String),
    ),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (
        139,
        RadiusAttrDef::new("PKM-Config-Settings", RadiusAttrType::String),
    ),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (
        140,
        RadiusAttrDef::new("PKM-Cryptosuite-List", RadiusAttrType::String),
    ),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (141, RadiusAttrDef::new("PKM-SAID", RadiusAttrType::Text)),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (
        142,
        RadiusAttrDef::new("PKM-SA-Descriptor", RadiusAttrType::String),
    ),
    // RFC 5904 — https://www.rfc-editor.org/rfc/rfc5904
    (
        143,
        RadiusAttrDef::new("PKM-Auth-Key", RadiusAttrType::String),
    ),
    // RFC 6519 — https://www.rfc-editor.org/rfc/rfc6519
    (
        144,
        RadiusAttrDef::new("DS-Lite-Tunnel-Name", RadiusAttrType::String),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        145,
        RadiusAttrDef::new("Mobile-Node-Identifier", RadiusAttrType::String),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        146,
        RadiusAttrDef::new("Service-Selection", RadiusAttrType::Text),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        147,
        RadiusAttrDef::new("PMIP6-Home-LMA-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        148,
        RadiusAttrDef::new("PMIP6-Visited-LMA-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        149,
        RadiusAttrDef::new("PMIP6-Home-LMA-IPv4-Address", RadiusAttrType::Address),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        150,
        RadiusAttrDef::new("PMIP6-Visited-LMA-IPv4-Address", RadiusAttrType::Address),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        151,
        RadiusAttrDef::new("PMIP6-Home-HN-Prefix", RadiusAttrType::Ipv6Prefix),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        152,
        RadiusAttrDef::new("PMIP6-Visited-HN-Prefix", RadiusAttrType::Ipv6Prefix),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        153,
        RadiusAttrDef::new("PMIP6-Home-Interface-ID", RadiusAttrType::String),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        154,
        RadiusAttrDef::new("PMIP6-Visited-Interface-ID", RadiusAttrType::String),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        155,
        RadiusAttrDef::new("PMIP6-Home-IPv4-HoA", RadiusAttrType::Ipv4Prefix),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        156,
        RadiusAttrDef::new("PMIP6-Visited-IPv4-HoA", RadiusAttrType::Ipv4Prefix),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        157,
        RadiusAttrDef::new("PMIP6-Home-DHCP4-Server-Address", RadiusAttrType::Address),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        158,
        RadiusAttrDef::new(
            "PMIP6-Visited-DHCP4-Server-Address",
            RadiusAttrType::Address,
        ),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        159,
        RadiusAttrDef::new("PMIP6-Home-DHCP6-Server-Address", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        160,
        RadiusAttrDef::new(
            "PMIP6-Visited-DHCP6-Server-Address",
            RadiusAttrType::Ipv6Addr,
        ),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        161,
        RadiusAttrDef::new("PMIP6-Home-IPv4-Gateway", RadiusAttrType::Address),
    ),
    // RFC 6572 — https://www.rfc-editor.org/rfc/rfc6572
    (
        162,
        RadiusAttrDef::new("PMIP6-Visited-IPv4-Gateway", RadiusAttrType::Address),
    ),
    // RFC 6677 — https://www.rfc-editor.org/rfc/rfc6677
    (
        163,
        RadiusAttrDef::new("EAP-Lower-Layer", RadiusAttrType::Integer),
    ),
    // RFC 7055 — https://www.rfc-editor.org/rfc/rfc7055
    (
        164,
        RadiusAttrDef::new("GSS-Acceptor-Service-Name", RadiusAttrType::Text),
    ),
    // RFC 7055 — https://www.rfc-editor.org/rfc/rfc7055
    (
        165,
        RadiusAttrDef::new("GSS-Acceptor-Host-Name", RadiusAttrType::Text),
    ),
    // RFC 7055 — https://www.rfc-editor.org/rfc/rfc7055
    (
        166,
        RadiusAttrDef::new("GSS-Acceptor-Service-Specifics", RadiusAttrType::Text),
    ),
    // RFC 7055 — https://www.rfc-editor.org/rfc/rfc7055
    (
        167,
        RadiusAttrDef::new("GSS-Acceptor-Realm-Name", RadiusAttrType::Text),
    ),
    // RFC 6911 — https://www.rfc-editor.org/rfc/rfc6911
    (
        168,
        RadiusAttrDef::new("Framed-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 6911 — https://www.rfc-editor.org/rfc/rfc6911
    (
        169,
        RadiusAttrDef::new("DNS-Server-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    // RFC 6911 — https://www.rfc-editor.org/rfc/rfc6911
    (
        170,
        RadiusAttrDef::new("Route-IPv6-Information", RadiusAttrType::Ipv6Prefix),
    ),
    // RFC 6911 — https://www.rfc-editor.org/rfc/rfc6911
    (
        171,
        RadiusAttrDef::new("Delegated-IPv6-Prefix-Pool", RadiusAttrType::Text),
    ),
    // RFC 6911 — https://www.rfc-editor.org/rfc/rfc6911
    (
        172,
        RadiusAttrDef::new("Stateful-IPv6-Address-Pool", RadiusAttrType::Text),
    ),
    // RFC 6930 — https://www.rfc-editor.org/rfc/rfc6930
    (
        173,
        RadiusAttrDef::new("IPv6-6rd-Configuration", RadiusAttrType::String),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        174,
        RadiusAttrDef::new("Allowed-Called-Station-Id", RadiusAttrType::Text),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        175,
        RadiusAttrDef::new("EAP-Peer-Id", RadiusAttrType::String),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        176,
        RadiusAttrDef::new("EAP-Server-Id", RadiusAttrType::String),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        177,
        RadiusAttrDef::new("Mobility-Domain-Id", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        178,
        RadiusAttrDef::new("Preauth-Timeout", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        179,
        RadiusAttrDef::new("Network-Id-Name", RadiusAttrType::String),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        180,
        RadiusAttrDef::new("EAPoL-Announcement", RadiusAttrType::String),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (181, RadiusAttrDef::new("WLAN-HESSID", RadiusAttrType::Text)),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        182,
        RadiusAttrDef::new("WLAN-Venue-Info", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        183,
        RadiusAttrDef::new("WLAN-Venue-Language", RadiusAttrType::String),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        184,
        RadiusAttrDef::new("WLAN-Venue-Name", RadiusAttrType::Text),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        185,
        RadiusAttrDef::new("WLAN-Reason-Code", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        186,
        RadiusAttrDef::new("WLAN-Pairwise-Cipher", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        187,
        RadiusAttrDef::new("WLAN-Group-Cipher", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        188,
        RadiusAttrDef::new("WLAN-AKM-Suite", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        189,
        RadiusAttrDef::new("WLAN-Group-Mgmt-Cipher", RadiusAttrType::Integer),
    ),
    // RFC 7268 — https://www.rfc-editor.org/rfc/rfc7268
    (
        190,
        RadiusAttrDef::new("WLAN-RF-Band", RadiusAttrType::Integer),
    ),
    // RFC 6929 — https://www.rfc-editor.org/rfc/rfc6929
    (
        241,
        RadiusAttrDef::new("Extended-Attribute-1", RadiusAttrType::Extended),
    ),
    // RFC 6929 — https://www.rfc-editor.org/rfc/rfc6929
    (
        242,
        RadiusAttrDef::new("Extended-Attribute-2", RadiusAttrType::Extended),
    ),
    // RFC 6929 — https://www.rfc-editor.org/rfc/rfc6929
    (
        243,
        RadiusAttrDef::new("Extended-Attribute-3", RadiusAttrType::Extended),
    ),
    // RFC 6929 — https://www.rfc-editor.org/rfc/rfc6929
    (
        244,
        RadiusAttrDef::new("Extended-Attribute-4", RadiusAttrType::Extended),
    ),
    // RFC 6929 — https://www.rfc-editor.org/rfc/rfc6929
    (
        245,
        RadiusAttrDef::new("Extended-Attribute-5", RadiusAttrType::LongExtended),
    ),
    // RFC 6929 — https://www.rfc-editor.org/rfc/rfc6929
    (
        246,
        RadiusAttrDef::new("Extended-Attribute-6", RadiusAttrType::LongExtended),
    ),
];

/// Extended attributes ("Type.Extended-Type", RFC 6929, Section 2.1/2.2),
/// sorted by `(Type, Extended-Type)` for binary search. Names and data
/// types from the IANA "RADIUS Attribute Types" registry.
/// <https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-2>
///
/// The Extended-Vendor-Specific-N attributes (Extended-Type 26) are
/// resolved by [`evs_name`] instead.
static EXTENDED_ATTRS: &[((u8, u8), RadiusAttrDef)] = &[
    // RFC 7499, Section 10.1 — https://www.rfc-editor.org/rfc/rfc7499#section-10.1
    (
        (241, 1),
        RadiusAttrDef::new("Frag-Status", RadiusAttrType::Integer),
    ),
    // RFC 7499, Section 10.2 — https://www.rfc-editor.org/rfc/rfc7499#section-10.2
    (
        (241, 2),
        RadiusAttrDef::new("Proxy-State-Length", RadiusAttrType::Integer),
    ),
    // RFC 7930, Section 6 — https://www.rfc-editor.org/rfc/rfc7930#section-6
    (
        (241, 3),
        RadiusAttrDef::new("Response-Length", RadiusAttrType::Integer),
    ),
    // RFC 7930, Section 6 — https://www.rfc-editor.org/rfc/rfc7930#section-6
    (
        (241, 4),
        RadiusAttrDef::new("Original-Packet-Code", RadiusAttrType::Integer),
    ),
    // RFC 8045, Section 3.1.1 — https://www.rfc-editor.org/rfc/rfc8045#section-3.1.1
    (
        (241, 5),
        RadiusAttrDef::new("IP-Port-Limit-Info", RadiusAttrType::String),
    ),
    // RFC 8045, Section 3.1.2 — https://www.rfc-editor.org/rfc/rfc8045#section-3.1.2
    (
        (241, 6),
        RadiusAttrDef::new("IP-Port-Range", RadiusAttrType::String),
    ),
    // RFC 8045, Section 3.1.3 — https://www.rfc-editor.org/rfc/rfc8045#section-3.1.3
    (
        (241, 7),
        RadiusAttrDef::new("IP-Port-Forwarding-Map", RadiusAttrType::String),
    ),
    // RFC 8559 — https://www.rfc-editor.org/rfc/rfc8559
    (
        (241, 8),
        RadiusAttrDef::new("Operator-NAS-Identifier", RadiusAttrType::String),
    ),
    // RFC 8658, Section 3.1 — https://www.rfc-editor.org/rfc/rfc8658#section-3.1
    (
        (241, 9),
        RadiusAttrDef::new("Softwire46-Configuration", RadiusAttrType::String),
    ),
    // RFC 8658, Section 3.2 — https://www.rfc-editor.org/rfc/rfc8658#section-3.2
    (
        (241, 10),
        RadiusAttrDef::new("Softwire46-Priority", RadiusAttrType::String),
    ),
    // RFC 8658, Section 3.3 — https://www.rfc-editor.org/rfc/rfc8658#section-3.3
    (
        (241, 11),
        RadiusAttrDef::new("Softwire46-Multicast", RadiusAttrType::String),
    ),
    // RFC 7833 — https://www.rfc-editor.org/rfc/rfc7833
    (
        (245, 1),
        RadiusAttrDef::new("SAML-Assertion", RadiusAttrType::Text),
    ),
    // RFC 7833 — https://www.rfc-editor.org/rfc/rfc7833
    (
        (245, 2),
        RadiusAttrDef::new("SAML-Protocol", RadiusAttrType::Text),
    ),
    // RFC 9445 — https://www.rfc-editor.org/rfc/rfc9445
    (
        (245, 3),
        RadiusAttrDef::new("DHCPv6-Options", RadiusAttrType::String),
    ),
    // RFC 9445 — https://www.rfc-editor.org/rfc/rfc9445
    (
        (245, 4),
        RadiusAttrDef::new("DHCPv4-Options", RadiusAttrType::String),
    ),
];

/// 3GPP Vendor-Specific sub-attributes (Vendor-Id 10415), sorted by
/// vendor type.
///
/// 3GPP TS 29.061 v19.1.0, clause 16.4.7.1 (Table 7, names) and clause
/// 16.4.7.2 (value encodings). "Octet String" values of one octet are
/// decoded as [`RadiusAttrType::Octet`]; longer structured octet strings
/// stay raw.
static TGPP_ATTRS: &[(u8, RadiusAttrDef)] = &[
    (1, RadiusAttrDef::new("3GPP-IMSI", RadiusAttrType::Text)),
    (
        2,
        RadiusAttrDef::new("3GPP-Charging-Id", RadiusAttrType::Integer),
    ),
    (
        3,
        RadiusAttrDef::new("3GPP-PDP-Type", RadiusAttrType::Integer),
    ),
    (
        4,
        RadiusAttrDef::new("3GPP-CG-Address", RadiusAttrType::Address),
    ),
    (
        5,
        RadiusAttrDef::new("3GPP-GPRS-Negotiated-QoS-Profile", RadiusAttrType::Text),
    ),
    (
        6,
        RadiusAttrDef::new("3GPP-SGSN-Address", RadiusAttrType::Address),
    ),
    (
        7,
        RadiusAttrDef::new("3GPP-GGSN-Address", RadiusAttrType::Address),
    ),
    (
        8,
        RadiusAttrDef::new("3GPP-IMSI-MCC-MNC", RadiusAttrType::Text),
    ),
    (
        9,
        RadiusAttrDef::new("3GPP-GGSN-MCC-MNC", RadiusAttrType::Text),
    ),
    (10, RadiusAttrDef::new("3GPP-NSAPI", RadiusAttrType::Text)),
    (
        11,
        RadiusAttrDef::new("3GPP-Session-Stop-Indicator", RadiusAttrType::Octet),
    ),
    (
        12,
        RadiusAttrDef::new("3GPP-Selection-Mode", RadiusAttrType::Text),
    ),
    (
        13,
        RadiusAttrDef::new("3GPP-Charging-Characteristics", RadiusAttrType::Text),
    ),
    (
        14,
        RadiusAttrDef::new("3GPP-CG-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    (
        15,
        RadiusAttrDef::new("3GPP-SGSN-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    (
        16,
        RadiusAttrDef::new("3GPP-GGSN-IPv6-Address", RadiusAttrType::Ipv6Addr),
    ),
    (
        17,
        RadiusAttrDef::new("3GPP-IPv6-DNS-Servers", RadiusAttrType::String),
    ),
    (
        18,
        RadiusAttrDef::new("3GPP-SGSN-MCC-MNC", RadiusAttrType::Text),
    ),
    (
        19,
        RadiusAttrDef::new("3GPP-Teardown-Indicator", RadiusAttrType::Octet),
    ),
    (20, RadiusAttrDef::new("3GPP-IMEISV", RadiusAttrType::Text)),
    (
        21,
        RadiusAttrDef::new("3GPP-RAT-Type", RadiusAttrType::Octet),
    ),
    (
        22,
        RadiusAttrDef::new("3GPP-User-Location-Info", RadiusAttrType::String),
    ),
    (
        23,
        RadiusAttrDef::new("3GPP-MS-TimeZone", RadiusAttrType::String),
    ),
    (
        24,
        RadiusAttrDef::new("3GPP-CAMEL-Charging-Info", RadiusAttrType::String),
    ),
    (
        25,
        RadiusAttrDef::new("3GPP-Packet-Filter", RadiusAttrType::String),
    ),
    (
        26,
        RadiusAttrDef::new("3GPP-Negotiated-DSCP", RadiusAttrType::Octet),
    ),
    (
        27,
        RadiusAttrDef::new("3GPP-Allocate-IP-Type", RadiusAttrType::Octet),
    ),
    (
        28,
        RadiusAttrDef::new("External-Identifier", RadiusAttrType::Text),
    ),
    (
        29,
        RadiusAttrDef::new("TWAN-Identifier", RadiusAttrType::String),
    ),
    (
        30,
        // "User Location Info time field is Unsigned32 type, it indicates the
        // NTP time" — NTP seconds (since 1900), not RFC 8044 "time".
        RadiusAttrDef::new("3GPP-User-Location-Info-Time", RadiusAttrType::Integer),
    ),
    (
        31,
        RadiusAttrDef::new("3GPP-Secondary-RAT-Usage", RadiusAttrType::String),
    ),
    (
        32,
        RadiusAttrDef::new("3GPP-UE-Local-IP-Address", RadiusAttrType::String),
    ),
    (
        33,
        RadiusAttrDef::new("3GPP-UE-Source-Port", RadiusAttrType::String),
    ),
];

/// Microsoft Vendor-Specific sub-attributes (Vendor-Id 311), sorted by
/// vendor type.
///
/// RFC 2548, Section 2 — <https://www.rfc-editor.org/rfc/rfc2548#section-2>.
/// Attributes whose value starts with an Ident or Salt field are kept as
/// raw String.
static MICROSOFT_ATTRS: &[(u8, RadiusAttrDef)] = &[
    (
        1,
        RadiusAttrDef::new("MS-CHAP-Response", RadiusAttrType::String),
    ),
    (
        2,
        RadiusAttrDef::new("MS-CHAP-Error", RadiusAttrType::String),
    ),
    (
        3,
        RadiusAttrDef::new("MS-CHAP-CPW-1", RadiusAttrType::String),
    ),
    (
        4,
        RadiusAttrDef::new("MS-CHAP-CPW-2", RadiusAttrType::String),
    ),
    (
        5,
        RadiusAttrDef::new("MS-CHAP-LM-Enc-PW", RadiusAttrType::String),
    ),
    (
        6,
        RadiusAttrDef::new("MS-CHAP-NT-Enc-PW", RadiusAttrType::String),
    ),
    (
        7,
        RadiusAttrDef::new("MS-MPPE-Encryption-Policy", RadiusAttrType::Integer),
    ),
    (
        8,
        RadiusAttrDef::new("MS-MPPE-Encryption-Types", RadiusAttrType::Integer),
    ),
    (
        9,
        RadiusAttrDef::new("MS-RAS-Vendor", RadiusAttrType::Integer),
    ),
    (
        10,
        RadiusAttrDef::new("MS-CHAP-Domain", RadiusAttrType::String),
    ),
    (
        11,
        RadiusAttrDef::new("MS-CHAP-Challenge", RadiusAttrType::String),
    ),
    (
        12,
        RadiusAttrDef::new("MS-CHAP-MPPE-Keys", RadiusAttrType::String),
    ),
    (
        13,
        RadiusAttrDef::new("MS-BAP-Usage", RadiusAttrType::Integer),
    ),
    (
        14,
        RadiusAttrDef::new("MS-Link-Utilization-Threshold", RadiusAttrType::Integer),
    ),
    (
        15,
        RadiusAttrDef::new("MS-Link-Drop-Time-Limit", RadiusAttrType::Integer),
    ),
    (
        16,
        RadiusAttrDef::new("MS-MPPE-Send-Key", RadiusAttrType::String),
    ),
    (
        17,
        RadiusAttrDef::new("MS-MPPE-Recv-Key", RadiusAttrType::String),
    ),
    (
        18,
        RadiusAttrDef::new("MS-RAS-Version", RadiusAttrType::String),
    ),
    (
        19,
        RadiusAttrDef::new("MS-Old-ARAP-Password", RadiusAttrType::String),
    ),
    (
        20,
        RadiusAttrDef::new("MS-New-ARAP-Password", RadiusAttrType::String),
    ),
    (
        21,
        RadiusAttrDef::new("MS-ARAP-Password-Change-Reason", RadiusAttrType::Integer),
    ),
    (22, RadiusAttrDef::new("MS-Filter", RadiusAttrType::String)),
    (
        23,
        RadiusAttrDef::new("MS-Acct-Auth-Type", RadiusAttrType::Integer),
    ),
    (
        24,
        RadiusAttrDef::new("MS-Acct-EAP-Type", RadiusAttrType::Integer),
    ),
    (
        25,
        RadiusAttrDef::new("MS-CHAP2-Response", RadiusAttrType::String),
    ),
    (
        26,
        RadiusAttrDef::new("MS-CHAP2-Success", RadiusAttrType::String),
    ),
    (
        27,
        RadiusAttrDef::new("MS-CHAP2-CPW", RadiusAttrType::String),
    ),
    (
        28,
        RadiusAttrDef::new("MS-Primary-DNS-Server", RadiusAttrType::Address),
    ),
    (
        29,
        RadiusAttrDef::new("MS-Secondary-DNS-Server", RadiusAttrType::Address),
    ),
    (
        30,
        RadiusAttrDef::new("MS-Primary-NBNS-Server", RadiusAttrType::Address),
    ),
    (
        31,
        RadiusAttrDef::new("MS-Secondary-NBNS-Server", RadiusAttrType::Address),
    ),
    (
        33,
        RadiusAttrDef::new("MS-ARAP-Challenge", RadiusAttrType::String),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_known_attr() {
        // RFC 2865, Section 5.1 — https://www.rfc-editor.org/rfc/rfc2865#section-5.1
        // User-Name is classified by the RFC as a "String" field (not "Text"),
        // even though its contents are typically UTF-8 readable.
        let def = lookup_attr(1).unwrap();
        assert_eq!(def.name, "User-Name");
        assert_eq!(def.attr_type, RadiusAttrType::String);
    }

    /// RFC 2865 labels many identifier-like attributes as "String" in their
    /// per-attribute sections (not as "Text"). The implementation must match
    /// the RFC's own classification.
    ///
    /// - RFC 2865, Section 5.1  — User-Name
    /// - RFC 2865, Section 5.19 — Callback-Number
    /// - RFC 2865, Section 5.20 — Callback-Id
    /// - RFC 2865, Section 5.30 — Called-Station-Id
    /// - RFC 2865, Section 5.31 — Calling-Station-Id
    /// - RFC 2865, Section 5.32 — NAS-Identifier
    /// - RFC 2865, Section 5.34 — Login-LAT-Service
    /// - RFC 2865, Section 5.35 — Login-LAT-Node
    /// - RFC 2865, Section 5.39 — Framed-AppleTalk-Zone
    /// - RFC 2865, Section 5.43 — Login-LAT-Port (attribute type 63)
    /// - RFC 2866, Section 5.11 — Acct-Multi-Session-Id
    #[test]
    fn test_string_typed_attrs_match_rfc_labels() {
        let string_typed = [
            (1, "User-Name"),
            (19, "Callback-Number"),
            (20, "Callback-Id"),
            (30, "Called-Station-Id"),
            (31, "Calling-Station-Id"),
            (32, "NAS-Identifier"),
            (34, "Login-LAT-Service"),
            (35, "Login-LAT-Node"),
            (39, "Framed-AppleTalk-Zone"),
            (63, "Login-LAT-Port"),
            (50, "Acct-Multi-Session-Id"),
        ];
        for (code, name) in string_typed {
            let def = lookup_attr(code).unwrap_or_else(|| panic!("attr {code} missing"));
            assert_eq!(def.name, name, "name mismatch for attr {code}");
            assert_eq!(
                def.attr_type,
                RadiusAttrType::String,
                "attr {code} ({name}) must be String per RFC",
            );
        }
    }

    /// RFC 2865/2866 label these attributes as "Text" in their per-attribute
    /// sections. Keep them as Text to match the RFC.
    ///
    /// - RFC 2865, Section 5.11 — Filter-Id
    /// - RFC 2865, Section 5.18 — Reply-Message
    /// - RFC 2865, Section 5.22 — Framed-Route
    /// - RFC 2866, Section 5.5  — Acct-Session-Id (diagram uses "Text ...")
    #[test]
    fn test_text_typed_attrs_match_rfc_labels() {
        let text_typed = [
            (11, "Filter-Id"),
            (18, "Reply-Message"),
            (22, "Framed-Route"),
            (44, "Acct-Session-Id"),
        ];
        for (code, name) in text_typed {
            let def = lookup_attr(code).unwrap_or_else(|| panic!("attr {code} missing"));
            assert_eq!(def.name, name, "name mismatch for attr {code}");
            assert_eq!(
                def.attr_type,
                RadiusAttrType::Text,
                "attr {code} ({name}) must be Text per RFC",
            );
        }
    }

    #[test]
    fn test_lookup_unknown_attr() {
        assert!(lookup_attr(17).is_none()); // unassigned
        assert!(lookup_attr(255).is_none());
    }

    #[test]
    fn test_lookup_accounting_attr() {
        let def = lookup_attr(40).unwrap();
        assert_eq!(def.name, "Acct-Status-Type");
        assert_eq!(def.attr_type, RadiusAttrType::Integer);
    }

    #[test]
    fn test_code_name_known() {
        assert_eq!(code_name(1), "Access-Request");
        assert_eq!(code_name(2), "Access-Accept");
        assert_eq!(code_name(3), "Access-Reject");
        assert_eq!(code_name(4), "Accounting-Request");
        assert_eq!(code_name(5), "Accounting-Response");
        assert_eq!(code_name(11), "Access-Challenge");
        assert_eq!(code_name(12), "Status-Server");
        assert_eq!(code_name(13), "Status-Client");
        assert_eq!(code_name(255), "Reserved");
    }

    #[test]
    fn test_code_name_unknown() {
        assert_eq!(code_name(0), "Unknown");
        assert_eq!(code_name(100), "Unknown");
    }

    #[test]
    fn test_enum_value_name_service_type() {
        assert_eq!(enum_value_name(6, 1), Some("Login"));
        assert_eq!(enum_value_name(6, 2), Some("Framed"));
        assert_eq!(enum_value_name(6, 99), None);
    }

    #[test]
    fn test_enum_value_name_non_enum_attr() {
        assert_eq!(enum_value_name(1, 0), None); // User-Name is Text, not enum
        assert_eq!(enum_value_name(5, 0), None); // NAS-Port is Integer, not enum
    }

    #[test]
    fn test_enum_value_name_acct_status_type() {
        assert_eq!(enum_value_name(40, 1), Some("Start"));
        assert_eq!(enum_value_name(40, 2), Some("Stop"));
        assert_eq!(enum_value_name(40, 3), Some("Interim-Update"));
    }

    #[test]
    fn test_enum_value_name_acct_status_type_tunnel() {
        // RFC 2867, Section 3 — tunnel accounting Acct-Status-Type values.
        assert_eq!(enum_value_name(40, 9), Some("Tunnel-Start"));
        assert_eq!(enum_value_name(40, 14), Some("Tunnel-Link-Reject"));
        assert_eq!(enum_value_name(40, 15), Some("Failed"));
        assert_eq!(enum_value_name(40, 16), None);
    }

    #[test]
    fn test_enum_value_name_acct_terminate_cause() {
        assert_eq!(enum_value_name(49, 1), Some("User Request"));
        assert_eq!(enum_value_name(49, 18), Some("Host Request"));
    }

    #[test]
    fn test_enum_value_name_nas_port_type() {
        assert_eq!(enum_value_name(61, 0), Some("Async"));
        assert_eq!(enum_value_name(61, 15), Some("Ethernet"));
    }

    #[test]
    fn test_enum_value_name_framed_protocol() {
        assert_eq!(enum_value_name(7, 1), Some("PPP"));
        assert_eq!(enum_value_name(7, 2), Some("SLIP"));
        assert_eq!(enum_value_name(7, 3), Some("ARAP"));
        assert_eq!(enum_value_name(7, 4), Some("Gandalf"));
        assert_eq!(enum_value_name(7, 5), Some("Xylogics IPX/SLIP"));
        assert_eq!(enum_value_name(7, 6), Some("X.75 Synchronous"));
        assert_eq!(enum_value_name(7, 99), None);
    }

    #[test]
    fn test_enum_value_name_framed_routing() {
        assert_eq!(enum_value_name(10, 0), Some("None"));
        assert_eq!(enum_value_name(10, 1), Some("Send routing packets"));
        assert_eq!(enum_value_name(10, 2), Some("Listen for routing packets"));
        assert_eq!(enum_value_name(10, 3), Some("Send and Listen"));
        assert_eq!(enum_value_name(10, 99), None);
    }

    #[test]
    fn test_enum_value_name_framed_compression() {
        assert_eq!(enum_value_name(13, 0), Some("None"));
        assert_eq!(enum_value_name(13, 1), Some("VJ TCP/IP header compression"));
        assert_eq!(enum_value_name(13, 2), Some("IPX header compression"));
        assert_eq!(enum_value_name(13, 3), Some("Stac-LZS compression"));
        assert_eq!(enum_value_name(13, 99), None);
    }

    #[test]
    fn test_enum_value_name_login_service() {
        assert_eq!(enum_value_name(15, 0), Some("Telnet"));
        assert_eq!(enum_value_name(15, 1), Some("Rlogin"));
        assert_eq!(enum_value_name(15, 2), Some("TCP Clear"));
        assert_eq!(enum_value_name(15, 3), Some("PortMaster"));
        assert_eq!(enum_value_name(15, 4), Some("LAT"));
        assert_eq!(enum_value_name(15, 5), Some("X.25-PAD"));
        assert_eq!(enum_value_name(15, 6), Some("X.25-T3POS"));
        assert_eq!(enum_value_name(15, 8), Some("TCP Clear Quiet"));
        assert_eq!(enum_value_name(15, 7), None); // gap in the spec
        assert_eq!(enum_value_name(15, 99), None);
    }

    #[test]
    fn test_enum_value_name_termination_action() {
        assert_eq!(enum_value_name(29, 0), Some("Default"));
        assert_eq!(enum_value_name(29, 1), Some("RADIUS-Request"));
        assert_eq!(enum_value_name(29, 2), None);
    }

    #[test]
    fn test_enum_value_name_acct_authentic() {
        assert_eq!(enum_value_name(45, 1), Some("RADIUS"));
        assert_eq!(enum_value_name(45, 2), Some("Local"));
        assert_eq!(enum_value_name(45, 3), Some("Remote"));
        assert_eq!(enum_value_name(45, 0), None);
    }

    #[test]
    fn test_other_tables_are_sorted() {
        for w in EXTENDED_ATTRS.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
        for w in TGPP_ATTRS.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
        for w in MICROSOFT_ATTRS.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
    }

    #[test]
    fn test_new_enum_value_names() {
        assert_eq!(enum_value_name(57, 1), Some("Enabled"));
        assert_eq!(enum_value_name(57, 3), None);
        assert_eq!(enum_value_name(64, 13), Some("Virtual LANs (VLAN)"));
        assert_eq!(enum_value_name(64, 99), None);
        assert_eq!(
            enum_value_name(65, 15),
            Some("E.164 with NSAP format subaddress")
        );
        assert_eq!(enum_value_name(65, 0), None);
        assert_eq!(enum_value_name(72, 4), Some("Use zone filter exclusively"));
        assert_eq!(enum_value_name(72, 3), None);
        assert_eq!(enum_value_name(76, 0), Some("No Echo"));
        assert_eq!(enum_value_name(76, 2), None);
        assert_eq!(enum_value_name(101, 601), Some("Response Too Big"));
        assert_eq!(enum_value_name(101, 0), None);
    }

    /// Every registered value of the enumerations added for the IANA
    /// registries resolves to a name (counts from the IANA "Values for
    /// RADIUS Attribute N" registries).
    #[test]
    fn test_enum_value_counts_match_iana() {
        let count = |attr: u8| {
            (0..1000)
                .filter(|v| enum_value_name(attr, *v).is_some())
                .count()
        };
        assert_eq!(count(64), 13);
        assert_eq!(count(65), 15);
        assert_eq!(count(72), 3);
        assert_eq!(count(76), 2);
        assert_eq!(count(101), 19);
        let tgpp = (0..32).filter(|v| tgpp_value_name(3, *v).is_some()).count();
        assert_eq!(tgpp, 7);
        let ms = |t: u8| {
            (0..32)
                .filter(|v| microsoft_value_name(t, *v).is_some())
                .count()
        };
        assert_eq!(ms(13) + ms(21) + ms(23) + ms(24), 3 + 4 + 5 + 4);
    }

    #[test]
    fn test_vendor_lookups() {
        assert_eq!(vendor_name(24757), Some("WiMAX Forum"));
        assert_eq!(vendor_name(1), None);
        assert_eq!(
            lookup_vendor_attr(VENDOR_3GPP, 22).unwrap().name,
            "3GPP-User-Location-Info"
        );
        assert_eq!(
            lookup_vendor_attr(VENDOR_MICROSOFT, 33).unwrap().name,
            "MS-ARAP-Challenge"
        );
        assert!(lookup_vendor_attr(VENDOR_MICROSOFT, 32).is_none());
        assert!(lookup_vendor_attr(9, 1).is_none());
        assert_eq!(
            tgpp_value_name(27, 3),
            Some("Allocate IPv4 address and IPv6 prefix")
        );
        assert_eq!(tgpp_value_name(3, 7), None);
        assert_eq!(microsoft_value_name(24, 13), Some("TLS"));
        assert_eq!(microsoft_value_name(21, 4), Some("Password-Too-Short"));
        assert_eq!(microsoft_value_name(13, 2), Some("BAP usage required"));
        assert_eq!(microsoft_value_name(23, 5), Some("EAP"));
        assert_eq!(microsoft_value_name(7, 9), None);
    }

    #[test]
    fn test_attr_display_name() {
        assert_eq!(attr_display_name(241, Some(2)), Some("Proxy-State-Length"));
        assert_eq!(
            attr_display_name(246, Some(26)),
            Some("Extended-Vendor-Specific-6")
        );
        assert_eq!(
            attr_display_name(242, Some(9)),
            Some("Extended-Attribute-2")
        );
        assert_eq!(attr_display_name(1, None), Some("User-Name"));
        assert_eq!(evs_name(1), None);
    }

    #[test]
    fn test_code_name_dynamic_authorization() {
        assert_eq!(code_name(40), "Disconnect-Request");
        assert_eq!(code_name(45), "CoA-NAK");
        assert_eq!(code_name(52), "Protocol-Error");
    }

    #[test]
    fn test_table_is_sorted() {
        for window in RADIUS_ATTRS.windows(2) {
            assert!(
                window[0].0 < window[1].0,
                "RADIUS_ATTRS is not sorted: {} >= {}",
                window[0].0,
                window[1].0,
            );
        }
    }
}
