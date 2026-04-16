//! RADIUS attribute type system and lookup tables.
//!
//! ## References
//! - RFC 2865, Section 5 (Attributes): <https://www.rfc-editor.org/rfc/rfc2865#section-5>
//! - RFC 2866, Section 5 (Accounting Attribute Definitions): <https://www.rfc-editor.org/rfc/rfc2866#section-5>

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
}

/// Static definition of a RADIUS attribute.
pub struct RadiusAttrDef {
    /// Human-readable name from the RFC.
    pub name: &'static str,
    /// Wire-format data type.
    pub attr_type: RadiusAttrType,
}

/// Look up an attribute definition by type code.
///
/// Returns `None` for unknown attribute types (they will be rendered as raw bytes).
pub fn lookup_attr(code: u8) -> Option<&'static RadiusAttrDef> {
    RADIUS_ATTRS
        .binary_search_by_key(&code, |(c, _)| *c)
        .ok()
        .map(|i| &RADIUS_ATTRS[i].1)
}

/// Returns a human-readable name for a RADIUS packet Code value.
///
/// RFC 2865, Section 3 — Code field.
/// <https://www.rfc-editor.org/rfc/rfc2865#section-3>
/// RFC 2866, Section 3 — adds Accounting-Request (4) and Accounting-Response (5).
/// <https://www.rfc-editor.org/rfc/rfc2866#section-3>
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
        61 => nas_port_type_name(val),
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
