//! AVP (Attribute-Value Pair) type system and vendor-extensible lookup tables.
//!
//! ## References
//! - RFC 6733, Section 4: <https://www.rfc-editor.org/rfc/rfc6733#section-4>

/// Diameter AVP data type (RFC 6733, Section 4.2–4.4).
/// <https://www.rfc-editor.org/rfc/rfc6733#section-4.2>
///
/// `Float32` and `Float64` have no variant: no AVP in the dictionaries uses
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvpType {
    /// RFC 6733, Section 4.2 — arbitrary data of variable length.
    OctetString,
    /// RFC 6733, Section 4.2 — 32-bit signed value.
    Integer32,
    /// RFC 6733, Section 4.2 — 32-bit unsigned value.
    Unsigned32,
    /// RFC 6733, Section 4.2 — 64-bit unsigned value.
    Unsigned64,
    /// RFC 6733, Section 4.3.1 — address family + address bytes.
    Address,
    /// RFC 6733, Section 4.3.1 — seconds since 00:00:00 January 1, 1900 UTC.
    Time,
    /// RFC 6733, Section 4.3.1 — UTF-8 encoded text.
    UTF8String,
    /// RFC 6733, Section 4.3.1 — FQDN or IP address (UTF-8).
    DiameterIdentity,
    /// RFC 6733, Section 4.3.1 — Diameter URI (UTF-8).
    DiameterURI,
    /// RFC 6733, Section 4.3.1 — 32-bit signed enumerated value.
    Enumerated,
    /// RFC 6733, Section 4.4 — sequence of AVPs.
    Grouped,
    /// RFC 6733, Section 4.2 — 64-bit signed value. `FieldValue` has no
    /// signed 64-bit variant, so the value is emitted as raw bytes.
    /// <https://www.rfc-editor.org/rfc/rfc6733#section-4.2>
    Integer64,
    /// OctetString carrying a 4-octet IPv4 address, e.g. Framed-IP-Address
    /// (RFC 7155, Section 4.4.10.5.1).
    /// <https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.1>
    Ipv4OctetString,
}

/// Static definition of an AVP: its human-readable name and data type.
pub struct AvpDef {
    /// Human-readable AVP name from the RFC.
    pub name: &'static str,
    /// Wire-format data type.
    pub avp_type: AvpType,
}

/// Look up an AVP definition by (vendor_id, avp_code).
///
/// Returns `None` for unknown AVPs (they will be rendered as raw bytes).
pub fn lookup_avp(vendor_id: u32, avp_code: u32) -> Option<&'static AvpDef> {
    let table = match vendor_id {
        0 => BASE_AVPS,
        10415 => TGPP_AVPS,
        _ => return None,
    };
    table
        .binary_search_by_key(&avp_code, |(code, _)| *code)
        .ok()
        .map(|i| &table[i].1)
}

/// Look up the name of an Enumerated AVP value.
///
/// Returns `None` for AVPs without a value table or unknown values.
pub fn enum_value_name(vendor_id: u32, avp_code: u32, value: i32) -> Option<&'static str> {
    let i = ENUM_VALUES
        .binary_search_by_key(&(vendor_id, avp_code), |(k, _)| *k)
        .ok()?;
    ENUM_VALUES[i]
        .1
        .iter()
        .find(|(v, _)| *v == value)
        .map(|(_, n)| *n)
}

/// Look up a command name by command code and request flag.
pub fn command_name(code: u32, is_request: bool) -> &'static str {
    match (code, is_request) {
        // RFC 6733, Section 3.1 — Diameter Base Protocol Command Codes
        (257, true) => "Capabilities-Exchange-Request",
        (257, false) => "Capabilities-Exchange-Answer",
        (258, true) => "Re-Auth-Request",
        (258, false) => "Re-Auth-Answer",
        (271, true) => "Accounting-Request",
        (271, false) => "Accounting-Answer",
        // RFC 4006, Section 3.1 — https://www.rfc-editor.org/rfc/rfc4006#section-3.1
        (272, true) => "Credit-Control-Request",
        (272, false) => "Credit-Control-Answer",
        (274, true) => "Abort-Session-Request",
        (274, false) => "Abort-Session-Answer",
        (275, true) => "Session-Termination-Request",
        (275, false) => "Session-Termination-Answer",
        (280, true) => "Device-Watchdog-Request",
        (280, false) => "Device-Watchdog-Answer",
        (282, true) => "Disconnect-Peer-Request",
        (282, false) => "Disconnect-Peer-Answer",
        // 3GPP TS 29.272, Section 7.2.2, Table 7.2.2/1 — S6a/S6d Command Codes
        (316, true) => "Update-Location-Request",
        (316, false) => "Update-Location-Answer",
        (317, true) => "Cancel-Location-Request",
        (317, false) => "Cancel-Location-Answer",
        (318, true) => "Authentication-Information-Request",
        (318, false) => "Authentication-Information-Answer",
        (319, true) => "Insert-Subscriber-Data-Request",
        (319, false) => "Insert-Subscriber-Data-Answer",
        (320, true) => "Delete-Subscriber-Data-Request",
        (320, false) => "Delete-Subscriber-Data-Answer",
        (321, true) => "Purge-UE-Request",
        (321, false) => "Purge-UE-Answer",
        (322, true) => "Reset-Request",
        (322, false) => "Reset-Answer",
        (323, true) => "Notify-Request",
        (323, false) => "Notify-Answer",
        // 3GPP TS 29.272, Section 7.2.2, Table 7.2.2/2 — S13/S13' Command Codes
        (324, true) => "ME-Identity-Check-Request",
        (324, false) => "ME-Identity-Check-Answer",
        // RFC 7155, Section 3.1 — https://www.rfc-editor.org/rfc/rfc7155#section-3.1
        (265, true) => "AA-Request",
        (265, false) => "AA-Answer",
        // RFC 4072, Sections 3.1 and 3.2 — https://www.rfc-editor.org/rfc/rfc4072#section-3
        (268, true) => "Diameter-EAP-Request",
        (268, false) => "Diameter-EAP-Answer",
        // 3GPP TS 29.229, Section 6.1, Table 6.1/1 — Cx/Dx Command Codes
        (300, true) => "User-Authorization-Request",
        (300, false) => "User-Authorization-Answer",
        (301, true) => "Server-Assignment-Request",
        (301, false) => "Server-Assignment-Answer",
        (302, true) => "Location-Info-Request",
        (302, false) => "Location-Info-Answer",
        (303, true) => "Multimedia-Auth-Request",
        (303, false) => "Multimedia-Auth-Answer",
        (304, true) => "Registration-Termination-Request",
        (304, false) => "Registration-Termination-Answer",
        (305, true) => "Push-Profile-Request",
        (305, false) => "Push-Profile-Answer",
        // 3GPP TS 29.329, Section 6.1, Table 6.1/1 — Sh Command Codes
        (306, true) => "User-Data-Request",
        (306, false) => "User-Data-Answer",
        (307, true) => "Profile-Update-Request",
        (307, false) => "Profile-Update-Answer",
        (308, true) => "Subscribe-Notifications-Request",
        (308, false) => "Subscribe-Notifications-Answer",
        (309, true) => "Push-Notification-Request",
        (309, false) => "Push-Notification-Answer",
        _ => "Unknown",
    }
}

/// Look up a human-readable name for a Diameter Application-ID.
///
/// RFC 6733, Section 2.4 — Application Identifiers.
/// 3GPP TS 29.272, Section 7.1.8 — Diameter Application Identifiers.
pub fn application_name(app_id: u32) -> &'static str {
    match app_id {
        0 => "Diameter Common Messages",
        // RFC 7155, Section 1.5 — https://www.rfc-editor.org/rfc/rfc7155#section-1.5
        1 => "NASREQ",
        3 => "Diameter Base Accounting",
        // RFC 4006, Section 1.2 — https://www.rfc-editor.org/rfc/rfc4006#section-1.2
        4 => "Diameter Credit-Control",
        // RFC 4072, Section 2.1 — https://www.rfc-editor.org/rfc/rfc4072#section-2.1
        5 => "Diameter EAP",
        // 3GPP TS 29.229, Section 6.2 — Cx/Dx Application Identifier
        16777216 => "3GPP Cx",
        // 3GPP TS 29.329, Section 6.2 — Sh Application Identifier
        16777217 => "3GPP Sh",
        // 3GPP TS 29.109, Section 6.2 — Zh Application Identifier
        16777221 => "3GPP Zh",
        // 3GPP TS 29.214, Section 5.1 — Rx Application Identifier
        16777236 => "3GPP Rx",
        // 3GPP TS 29.212, Section 5.1 — Gx Application Identifier
        16777238 => "3GPP Gx",
        // 3GPP TS 29.272, Section 7.1.8
        16777251 => "3GPP S6a/S6d",
        16777252 => "3GPP S13/S13'",
        // 3GPP TS 29.273 v19.2.0, clause 5.2.1 — STa (also used by SWa, clause 4.2.1)
        16777250 => "3GPP STa",
        // 3GPP TS 29.273, Section 9 — SWm Application Identifier
        16777264 => "3GPP SWm",
        // 3GPP TS 29.273, Section 8 — SWx Application Identifier
        16777265 => "3GPP SWx",
        // 3GPP TS 29.273, Section 10 — S6b Application Identifier
        16777272 => "3GPP S6b",
        16777308 => "3GPP S7a/S7d",
        _ => "Unknown",
    }
}

/// AVP code for Experimental-Result-Code.
pub const AVP_CODE_EXPERIMENTAL_RESULT_CODE: u32 = 298;

/// Look up a human-readable name for a 3GPP Experimental-Result-Code value.
///
/// 3GPP TS 29.272, Section 7.4 — Result-Code and Experimental-Result Values.
pub fn experimental_result_code_name(code: u32) -> &'static str {
    match code {
        // 3GPP TS 29.229, Section 6.2 — Cx/Dx Experimental Result Codes (Success)
        2001 => "DIAMETER_FIRST_REGISTRATION",
        2002 => "DIAMETER_SUBSEQUENT_REGISTRATION",
        2003 => "DIAMETER_UNREGISTERED_SERVICE",
        2004 => "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
        // 3GPP TS 29.272, Section 7.4.4 — Transient Failures
        4181 => "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
        4182 => "DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT",
        // 3GPP TS 29.272, Section 7.4.3 / TS 29.229, Section 6.2 — Permanent Failures
        5001 => "DIAMETER_ERROR_USER_UNKNOWN",
        5002 => "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
        5003 => "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
        5004 => "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
        5011 => "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
        // 3GPP TS 29.214, Section 5.5 — Rx Permanent Failures
        5061 => "DIAMETER_ERROR_IP_CAN_SESSION_NOT_AVAILABLE",
        5063 => "DIAMETER_ERROR_REQUESTED_SERVICE_NOT_AUTHORIZED",
        // 3GPP TS 29.212, Section 5.6 — Gx Permanent Failures
        5065 => "DIAMETER_ERROR_BEARER_NOT_AUTHORIZED",
        5066 => "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED",
        5144 => "DIAMETER_ERROR_CONFLICTING_REQUEST",
        // 3GPP TS 29.272, Section 7.4.3 — S6a/S6d Permanent Failures
        5420 => "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
        5421 => "DIAMETER_ERROR_RAT_NOT_ALLOWED",
        5422 => "DIAMETER_ERROR_EQUIPMENT_UNKNOWN",
        5423 => "DIAMETER_ERROR_UNKNOWN_SERVING_NODE",
        _ => "Unknown",
    }
}

/// AVP code for Result-Code.
pub const AVP_CODE_RESULT_CODE: u32 = 268;

/// Look up a human-readable name for a base Result-Code value.
///
/// RFC 6733, Section 7 — Result-Code AVP Values.
pub fn result_code_name(code: u32) -> &'static str {
    match code {
        // Informational
        1001 => "DIAMETER_MULTI_ROUND_AUTH",
        // Success
        2001 => "DIAMETER_SUCCESS",
        2002 => "DIAMETER_LIMITED_SUCCESS",
        // Protocol Errors
        3001 => "DIAMETER_COMMAND_UNSUPPORTED",
        3002 => "DIAMETER_UNABLE_TO_DELIVER",
        3003 => "DIAMETER_REALM_NOT_SERVED",
        3004 => "DIAMETER_TOO_BUSY",
        3005 => "DIAMETER_LOOP_DETECTED",
        3006 => "DIAMETER_REDIRECT_INDICATION",
        3007 => "DIAMETER_APPLICATION_UNSUPPORTED",
        3008 => "DIAMETER_INVALID_HDR_BITS",
        3009 => "DIAMETER_INVALID_AVP_BITS",
        3010 => "DIAMETER_UNKNOWN_PEER",
        // Transient Failures
        4001 => "DIAMETER_AUTHENTICATION_REJECTED",
        4002 => "DIAMETER_OUT_OF_SPACE",
        4003 => "ELECTION_LOST",
        // Permanent Failures
        5001 => "DIAMETER_AVP_UNSUPPORTED",
        5002 => "DIAMETER_UNKNOWN_SESSION_ID",
        5003 => "DIAMETER_AUTHORIZATION_REJECTED",
        5004 => "DIAMETER_INVALID_AVP_VALUE",
        5005 => "DIAMETER_MISSING_AVP",
        5006 => "DIAMETER_RESOURCES_EXCEEDED",
        5007 => "DIAMETER_CONTRADICTING_AVPS",
        5008 => "DIAMETER_AVP_NOT_ALLOWED",
        5009 => "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES",
        5010 => "DIAMETER_NO_COMMON_APPLICATION",
        5011 => "DIAMETER_UNSUPPORTED_VERSION",
        5012 => "DIAMETER_UNABLE_TO_COMPLY",
        5013 => "DIAMETER_INVALID_BIT_IN_HEADER",
        5014 => "DIAMETER_INVALID_AVP_LENGTH",
        5015 => "DIAMETER_INVALID_MESSAGE_LENGTH",
        5016 => "DIAMETER_INVALID_AVP_BIT_COMBO",
        5017 => "DIAMETER_NO_COMMON_SECURITY",
        _ => "Unknown",
    }
}

/// Base protocol AVPs (vendor_id=0), sorted by AVP code for binary search.
///
/// RFC 6733, Sections 8 and 9.
static BASE_AVPS: &[(u32, AvpDef)] = &[
    (
        1,
        AvpDef {
            name: "User-Name",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.3.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.1
    (
        2,
        AvpDef {
            name: "User-Password",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.2.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.2
    (
        5,
        AvpDef {
            name: "NAS-Port",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.4.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.1
    (
        6,
        AvpDef {
            name: "Service-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.10.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.1
    (
        7,
        AvpDef {
            name: "Framed-Protocol",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.10.5.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.1
    (
        8,
        AvpDef {
            name: "Framed-IP-Address",
            avp_type: AvpType::Ipv4OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.5.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.2
    (
        9,
        AvpDef {
            name: "Framed-IP-Netmask",
            avp_type: AvpType::Ipv4OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.2
    (
        10,
        AvpDef {
            name: "Framed-Routing",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.7
    (
        11,
        AvpDef {
            name: "Filter-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.10.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.3
    (
        12,
        AvpDef {
            name: "Framed-MTU",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.4.10.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.4
    (
        13,
        AvpDef {
            name: "Framed-Compression",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.11.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.1
    (
        14,
        AvpDef {
            name: "Login-IP-Host",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.11.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.3
    (
        15,
        AvpDef {
            name: "Login-Service",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.11.4.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.4.1
    (
        16,
        AvpDef {
            name: "Login-TCP-Port",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.2.9 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.9
    (
        18,
        AvpDef {
            name: "Reply-Message",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.2
    (
        19,
        AvpDef {
            name: "Callback-Number",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.3
    (
        20,
        AvpDef {
            name: "Callback-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.10.5.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.3
    (
        22,
        AvpDef {
            name: "Framed-Route",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.10.6.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.6.1
    (
        23,
        AvpDef {
            name: "Framed-IPX-Network",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        25,
        AvpDef {
            name: "Class",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        27,
        AvpDef {
            name: "Session-Timeout",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.4.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.4
    (
        28,
        AvpDef {
            name: "Idle-Timeout",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.2.5 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.5
    (
        30,
        AvpDef {
            name: "Called-Station-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.2.6 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.6
    (
        31,
        AvpDef {
            name: "Calling-Station-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    (
        33,
        AvpDef {
            name: "Proxy-State",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.11.5.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.5.1
    (
        34,
        AvpDef {
            name: "Login-LAT-Service",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.11.5.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.5.2
    (
        35,
        AvpDef {
            name: "Login-LAT-Node",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.11.5.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.5.3
    (
        36,
        AvpDef {
            name: "Login-LAT-Group",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.7.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.7.1
    (
        37,
        AvpDef {
            name: "Framed-Appletalk-Link",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.4.10.7.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.7.2
    (
        38,
        AvpDef {
            name: "Framed-Appletalk-Network",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.4.10.7.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.7.3
    (
        39,
        AvpDef {
            name: "Framed-Appletalk-Zone",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.6.8 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.8
    (
        41,
        AvpDef {
            name: "Acct-Delay-Time",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        44,
        AvpDef {
            name: "Accounting-Session-Id",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.6.6 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.6
    (
        45,
        AvpDef {
            name: "Acct-Authentic",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.6.5 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.5
    (
        46,
        AvpDef {
            name: "Acct-Session-Time",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        50,
        AvpDef {
            name: "Acct-Multi-Session-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.6.9 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.9
    (
        51,
        AvpDef {
            name: "Acct-Link-Count",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        55,
        AvpDef {
            name: "Event-Timestamp",
            avp_type: AvpType::Time,
        },
    ),
    // RFC 7155, Section 4.3.8 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.8
    (
        60,
        AvpDef {
            name: "CHAP-Challenge",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.2.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.4
    (
        61,
        AvpDef {
            name: "NAS-Port-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.5 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.5
    (
        62,
        AvpDef {
            name: "Port-Limit",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.4.11.5.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.5.4
    (
        63,
        AvpDef {
            name: "Login-LAT-Port",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.2
    (
        64,
        AvpDef {
            name: "Tunnel-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.5.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.3
    (
        65,
        AvpDef {
            name: "Tunnel-Medium-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.5.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.4
    (
        66,
        AvpDef {
            name: "Tunnel-Client-Endpoint",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.5.5 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.5
    (
        67,
        AvpDef {
            name: "Tunnel-Server-Endpoint",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.6.10 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.10
    (
        68,
        AvpDef {
            name: "Acct-Tunnel-Connection",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.6 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.6
    (
        69,
        AvpDef {
            name: "Tunnel-Password",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.3.9 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.9
    (
        70,
        AvpDef {
            name: "ARAP-Password",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.8.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.8.1
    (
        71,
        AvpDef {
            name: "ARAP-Features",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.8.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.8.2
    (
        72,
        AvpDef {
            name: "ARAP-Zone-Access",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.3.11 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.11
    (
        73,
        AvpDef {
            name: "ARAP-Security",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.3.12 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.12
    (
        74,
        AvpDef {
            name: "ARAP-Security-Data",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.3.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.2
    (
        75,
        AvpDef {
            name: "Password-Retry",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.3.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.3
    (
        76,
        AvpDef {
            name: "Prompt",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.2.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.7
    (
        77,
        AvpDef {
            name: "Connect-Info",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.8 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.8
    (
        78,
        AvpDef {
            name: "Configuration-Token",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.7
    (
        81,
        AvpDef {
            name: "Tunnel-Private-Group-Id",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.8 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.8
    (
        82,
        AvpDef {
            name: "Tunnel-Assignment-Id",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.9 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.9
    (
        83,
        AvpDef {
            name: "Tunnel-Preference",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.3.10 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.10
    (
        84,
        AvpDef {
            name: "ARAP-Challenge-Response",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        85,
        AvpDef {
            name: "Acct-Interim-Interval",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.6.11 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.11
    (
        86,
        AvpDef {
            name: "Acct-Tunnel-Packets-Lost",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7155, Section 4.2.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.3
    (
        87,
        AvpDef {
            name: "NAS-Port-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.10.5.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.4
    (
        88,
        AvpDef {
            name: "Framed-Pool",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.10 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.10
    (
        90,
        AvpDef {
            name: "Tunnel-Client-Auth-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.5.11 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.11
    (
        91,
        AvpDef {
            name: "Tunnel-Server-Auth-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.2.8 — https://www.rfc-editor.org/rfc/rfc7155#section-4.2.8
    (
        94,
        AvpDef {
            name: "Originating-Line-Info",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.5.5 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.5
    (
        96,
        AvpDef {
            name: "Framed-Interface-Id",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 7155, Section 4.4.10.5.6 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.6
    (
        97,
        AvpDef {
            name: "Framed-IPv6-Prefix",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.11.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.11.2
    (
        98,
        AvpDef {
            name: "Login-IPv6-Host",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.4.10.5.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.7
    (
        99,
        AvpDef {
            name: "Framed-IPv6-Route",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 7155, Section 4.4.10.5.8 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.8
    (
        100,
        AvpDef {
            name: "Framed-IPv6-Pool",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 4072, Section 4.1.4 — https://www.rfc-editor.org/rfc/rfc4072#section-4.1.4
    (
        102,
        AvpDef {
            name: "EAP-Key-Name",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        257,
        AvpDef {
            name: "Host-IP-Address",
            avp_type: AvpType::Address,
        },
    ),
    (
        258,
        AvpDef {
            name: "Auth-Application-Id",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        259,
        AvpDef {
            name: "Acct-Application-Id",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        260,
        AvpDef {
            name: "Vendor-Specific-Application-Id",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        261,
        AvpDef {
            name: "Redirect-Host-Usage",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        262,
        AvpDef {
            name: "Redirect-Max-Cache-Time",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        263,
        AvpDef {
            name: "Session-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    (
        264,
        AvpDef {
            name: "Origin-Host",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        265,
        AvpDef {
            name: "Supported-Vendor-Id",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        266,
        AvpDef {
            name: "Vendor-Id",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        267,
        AvpDef {
            name: "Firmware-Revision",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        268,
        AvpDef {
            name: "Result-Code",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        269,
        AvpDef {
            name: "Product-Name",
            avp_type: AvpType::UTF8String,
        },
    ),
    (
        270,
        AvpDef {
            name: "Session-Binding",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        271,
        AvpDef {
            name: "Session-Server-Failover",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        272,
        AvpDef {
            name: "Multi-Round-Time-Out",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        273,
        AvpDef {
            name: "Disconnect-Cause",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        274,
        AvpDef {
            name: "Auth-Request-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        276,
        AvpDef {
            name: "Auth-Grace-Period",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        277,
        AvpDef {
            name: "Auth-Session-State",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        278,
        AvpDef {
            name: "Origin-State-Id",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        279,
        AvpDef {
            name: "Failed-AVP",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        280,
        AvpDef {
            name: "Proxy-Host",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        281,
        AvpDef {
            name: "Error-Message",
            avp_type: AvpType::UTF8String,
        },
    ),
    (
        282,
        AvpDef {
            name: "Route-Record",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        283,
        AvpDef {
            name: "Destination-Realm",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        284,
        AvpDef {
            name: "Proxy-Info",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        285,
        AvpDef {
            name: "Re-Auth-Request-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        287,
        AvpDef {
            name: "Accounting-Sub-Session-Id",
            avp_type: AvpType::Unsigned64,
        },
    ),
    (
        291,
        AvpDef {
            name: "Authorization-Lifetime",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        292,
        AvpDef {
            name: "Redirect-Host",
            avp_type: AvpType::DiameterURI,
        },
    ),
    (
        293,
        AvpDef {
            name: "Destination-Host",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        294,
        AvpDef {
            name: "Error-Reporting-Host",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        295,
        AvpDef {
            name: "Termination-Cause",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        296,
        AvpDef {
            name: "Origin-Realm",
            avp_type: AvpType::DiameterIdentity,
        },
    ),
    (
        297,
        AvpDef {
            name: "Experimental-Result",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        298,
        AvpDef {
            name: "Experimental-Result-Code",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        299,
        AvpDef {
            name: "Inband-Security-Id",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 7944 — DRMP (re-used by 3GPP TS 29.272, Table 7.3.1/2)
    (
        301,
        AvpDef {
            name: "DRMP",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 4004, Section 7.4 — MIP-Home-Agent-Address
    (
        334,
        AvpDef {
            name: "MIP-Home-Agent-Address",
            avp_type: AvpType::Address,
        },
    ),
    // RFC 4004, Section 7.5 — MIP-Home-Agent-Host
    (
        348,
        AvpDef {
            name: "MIP-Home-Agent-Host",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 7155, Section 4.6.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.1
    (
        363,
        AvpDef {
            name: "Accounting-Input-Octets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 7155, Section 4.6.2 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.2
    (
        364,
        AvpDef {
            name: "Accounting-Output-Octets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 7155, Section 4.6.3 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.3
    (
        365,
        AvpDef {
            name: "Accounting-Input-Packets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 7155, Section 4.6.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.4
    (
        366,
        AvpDef {
            name: "Accounting-Output-Packets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 7155, Section 4.4.6 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.6
    (
        400,
        AvpDef {
            name: "NAS-Filter-Rule",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.5.1 — https://www.rfc-editor.org/rfc/rfc7155#section-4.5.1
    (
        401,
        AvpDef {
            name: "Tunneling",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 7155, Section 4.3.4 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.4
    (
        402,
        AvpDef {
            name: "CHAP-Auth",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 7155, Section 4.3.5 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.5
    (
        403,
        AvpDef {
            name: "CHAP-Algorithm",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.3.6 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.6
    (
        404,
        AvpDef {
            name: "CHAP-Ident",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.3.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.3.7
    (
        405,
        AvpDef {
            name: "CHAP-Response",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 7155, Section 4.6.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.7
    (
        406,
        AvpDef {
            name: "Accounting-Auth-Method",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 7155, Section 4.4.9 — https://www.rfc-editor.org/rfc/rfc7155#section-4.4.9
    (
        407,
        AvpDef {
            name: "QoS-Filter-Rule",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 8506, Section 8.1 — https://www.rfc-editor.org/rfc/rfc8506#section-8.1
    (
        411,
        AvpDef {
            name: "CC-Correlation-Id",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 4006, Section 8 — Credit-Control AVPs (now RFC 8506, Section 8)
    // <https://www.rfc-editor.org/rfc/rfc8506#section-8>
    (
        412,
        AvpDef {
            name: "CC-Input-Octets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 8506, Section 8.22 — https://www.rfc-editor.org/rfc/rfc8506#section-8.22
    (
        413,
        AvpDef {
            name: "CC-Money",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        414,
        AvpDef {
            name: "CC-Output-Octets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    (
        415,
        AvpDef {
            name: "CC-Request-Number",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        416,
        AvpDef {
            name: "CC-Request-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.26 — https://www.rfc-editor.org/rfc/rfc8506#section-8.26
    (
        417,
        AvpDef {
            name: "CC-Service-Specific-Units",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 8506, Section 8.4 — https://www.rfc-editor.org/rfc/rfc8506#section-8.4
    (
        418,
        AvpDef {
            name: "CC-Session-Failover",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.5 — https://www.rfc-editor.org/rfc/rfc8506#section-8.5
    (
        419,
        AvpDef {
            name: "CC-Sub-Session-Id",
            avp_type: AvpType::Unsigned64,
        },
    ),
    (
        420,
        AvpDef {
            name: "CC-Time",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        421,
        AvpDef {
            name: "CC-Total-Octets",
            avp_type: AvpType::Unsigned64,
        },
    ),
    // RFC 8506, Section 8.6 — https://www.rfc-editor.org/rfc/rfc8506#section-8.6
    (
        422,
        AvpDef {
            name: "Check-Balance-Result",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.7 — https://www.rfc-editor.org/rfc/rfc8506#section-8.7
    (
        423,
        AvpDef {
            name: "Cost-Information",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.12 — https://www.rfc-editor.org/rfc/rfc8506#section-8.12
    (
        424,
        AvpDef {
            name: "Cost-Unit",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.11 — https://www.rfc-editor.org/rfc/rfc8506#section-8.11
    (
        425,
        AvpDef {
            name: "Currency-Code",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 8506, Section 8.13 — https://www.rfc-editor.org/rfc/rfc8506#section-8.13
    (
        426,
        AvpDef {
            name: "Credit-Control",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.14 — https://www.rfc-editor.org/rfc/rfc8506#section-8.14
    (
        427,
        AvpDef {
            name: "Credit-Control-Failure-Handling",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.15 — https://www.rfc-editor.org/rfc/rfc8506#section-8.15
    (
        428,
        AvpDef {
            name: "Direct-Debiting-Failure-Handling",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.9 — https://www.rfc-editor.org/rfc/rfc8506#section-8.9
    (
        429,
        AvpDef {
            name: "Exponent",
            avp_type: AvpType::Integer32,
        },
    ),
    // RFC 8506, Section 8.34 — https://www.rfc-editor.org/rfc/rfc8506#section-8.34
    (
        430,
        AvpDef {
            name: "Final-Unit-Indication",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.17 — https://www.rfc-editor.org/rfc/rfc8506#section-8.17
    (
        431,
        AvpDef {
            name: "Granted-Service-Unit",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        432,
        AvpDef {
            name: "Rating-Group",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 8506, Section 8.38 — https://www.rfc-editor.org/rfc/rfc8506#section-8.38
    (
        433,
        AvpDef {
            name: "Redirect-Address-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.37 — https://www.rfc-editor.org/rfc/rfc8506#section-8.37
    (
        434,
        AvpDef {
            name: "Redirect-Server",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.39 — https://www.rfc-editor.org/rfc/rfc8506#section-8.39
    (
        435,
        AvpDef {
            name: "Redirect-Server-Address",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.41 — https://www.rfc-editor.org/rfc/rfc8506#section-8.41
    (
        436,
        AvpDef {
            name: "Requested-Action",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        437,
        AvpDef {
            name: "Requested-Service-Unit",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.36 — https://www.rfc-editor.org/rfc/rfc8506#section-8.36
    (
        438,
        AvpDef {
            name: "Restriction-Filter-Rule",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        439,
        AvpDef {
            name: "Service-Identifier",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 8506, Section 8.43 — https://www.rfc-editor.org/rfc/rfc8506#section-8.43
    (
        440,
        AvpDef {
            name: "Service-Parameter-Info",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.44 — https://www.rfc-editor.org/rfc/rfc8506#section-8.44
    (
        441,
        AvpDef {
            name: "Service-Parameter-Type",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 8506, Section 8.45 — https://www.rfc-editor.org/rfc/rfc8506#section-8.45
    (
        442,
        AvpDef {
            name: "Service-Parameter-Value",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        443,
        AvpDef {
            name: "Subscription-Id",
            avp_type: AvpType::Grouped,
        },
    ),
    (
        444,
        AvpDef {
            name: "Subscription-Id-Data",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.8 — https://www.rfc-editor.org/rfc/rfc8506#section-8.8
    (
        445,
        AvpDef {
            name: "Unit-Value",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.19 — https://www.rfc-editor.org/rfc/rfc8506#section-8.19
    (
        446,
        AvpDef {
            name: "Used-Service-Unit",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.10 — https://www.rfc-editor.org/rfc/rfc8506#section-8.10
    (
        447,
        AvpDef {
            name: "Value-Digits",
            avp_type: AvpType::Integer64,
        },
    ),
    // RFC 8506, Section 8.33 — https://www.rfc-editor.org/rfc/rfc8506#section-8.33
    (
        448,
        AvpDef {
            name: "Validity-Time",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 8506, Section 8.35 — https://www.rfc-editor.org/rfc/rfc8506#section-8.35
    (
        449,
        AvpDef {
            name: "Final-Unit-Action",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        450,
        AvpDef {
            name: "Subscription-Id-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.20 — https://www.rfc-editor.org/rfc/rfc8506#section-8.20
    (
        451,
        AvpDef {
            name: "Tariff-Time-Change",
            avp_type: AvpType::Time,
        },
    ),
    (
        452,
        AvpDef {
            name: "Tariff-Change-Usage",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.31 — https://www.rfc-editor.org/rfc/rfc8506#section-8.31
    (
        453,
        AvpDef {
            name: "G-S-U-Pool-Identifier",
            avp_type: AvpType::Unsigned32,
        },
    ),
    (
        454,
        AvpDef {
            name: "CC-Unit-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.40 — https://www.rfc-editor.org/rfc/rfc8506#section-8.40
    (
        455,
        AvpDef {
            name: "Multiple-Services-Indicator",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        456,
        AvpDef {
            name: "Multiple-Services-Credit-Control",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.30 — https://www.rfc-editor.org/rfc/rfc8506#section-8.30
    (
        457,
        AvpDef {
            name: "G-S-U-Pool-Reference",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.49 — https://www.rfc-editor.org/rfc/rfc8506#section-8.49
    (
        458,
        AvpDef {
            name: "User-Equipment-Info",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.50 — https://www.rfc-editor.org/rfc/rfc8506#section-8.50
    (
        459,
        AvpDef {
            name: "User-Equipment-Info-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    // RFC 8506, Section 8.51 — https://www.rfc-editor.org/rfc/rfc8506#section-8.51
    (
        460,
        AvpDef {
            name: "User-Equipment-Info-Value",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        461,
        AvpDef {
            name: "Service-Context-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 4072, Section 4.1.1 — https://www.rfc-editor.org/rfc/rfc4072#section-4.1.1
    (
        462,
        AvpDef {
            name: "EAP-Payload",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 4072, Section 4.1.2 — https://www.rfc-editor.org/rfc/rfc4072#section-4.1.2
    (
        463,
        AvpDef {
            name: "EAP-Reissued-Payload",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 4072, Section 4.1.3 — https://www.rfc-editor.org/rfc/rfc4072#section-4.1.3
    (
        464,
        AvpDef {
            name: "EAP-Master-Session-Key",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 4072, Section 4.1.5 — https://www.rfc-editor.org/rfc/rfc4072#section-4.1.5
    (
        465,
        AvpDef {
            name: "Accounting-EAP-Auth-Method",
            avp_type: AvpType::Unsigned64,
        },
    ),
    (
        480,
        AvpDef {
            name: "Accounting-Record-Type",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        483,
        AvpDef {
            name: "Accounting-Realtime-Required",
            avp_type: AvpType::Enumerated,
        },
    ),
    (
        485,
        AvpDef {
            name: "Accounting-Record-Number",
            avp_type: AvpType::Unsigned32,
        },
    ),
    // RFC 5447, Section 4.1 — MIP6-Agent-Info (re-used by 3GPP TS 29.272, Table 7.3.1/2)
    (
        486,
        AvpDef {
            name: "MIP6-Agent-Info",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 5778, Section 6.2 — Service-Selection (re-used by 3GPP TS 29.272, Table 7.3.1/2)
    (
        493,
        AvpDef {
            name: "Service-Selection",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.52 — https://www.rfc-editor.org/rfc/rfc8506#section-8.52
    (
        653,
        AvpDef {
            name: "User-Equipment-Info-Extension",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.53 — https://www.rfc-editor.org/rfc/rfc8506#section-8.53
    (
        654,
        AvpDef {
            name: "User-Equipment-Info-IMEISV",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 8506, Section 8.54 — https://www.rfc-editor.org/rfc/rfc8506#section-8.54
    (
        655,
        AvpDef {
            name: "User-Equipment-Info-MAC",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 8506, Section 8.55 — https://www.rfc-editor.org/rfc/rfc8506#section-8.55
    (
        656,
        AvpDef {
            name: "User-Equipment-Info-EUI64",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 8506, Section 8.56 — https://www.rfc-editor.org/rfc/rfc8506#section-8.56
    (
        657,
        AvpDef {
            name: "User-Equipment-Info-ModifiedEUI64",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 8506, Section 8.57 — https://www.rfc-editor.org/rfc/rfc8506#section-8.57
    (
        658,
        AvpDef {
            name: "User-Equipment-Info-IMEI",
            avp_type: AvpType::OctetString,
        },
    ),
    // RFC 8506, Section 8.58 — https://www.rfc-editor.org/rfc/rfc8506#section-8.58
    (
        659,
        AvpDef {
            name: "Subscription-Id-Extension",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.59 — https://www.rfc-editor.org/rfc/rfc8506#section-8.59
    (
        660,
        AvpDef {
            name: "Subscription-Id-E164",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.60 — https://www.rfc-editor.org/rfc/rfc8506#section-8.60
    (
        661,
        AvpDef {
            name: "Subscription-Id-IMSI",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.61 — https://www.rfc-editor.org/rfc/rfc8506#section-8.61
    (
        662,
        AvpDef {
            name: "Subscription-Id-SIP-URI",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.62 — https://www.rfc-editor.org/rfc/rfc8506#section-8.62
    (
        663,
        AvpDef {
            name: "Subscription-Id-NAI",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.63 — https://www.rfc-editor.org/rfc/rfc8506#section-8.63
    (
        664,
        AvpDef {
            name: "Subscription-Id-Private",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.64 — https://www.rfc-editor.org/rfc/rfc8506#section-8.64
    (
        665,
        AvpDef {
            name: "Redirect-Server-Extension",
            avp_type: AvpType::Grouped,
        },
    ),
    // RFC 8506, Section 8.65 — https://www.rfc-editor.org/rfc/rfc8506#section-8.65
    (
        666,
        AvpDef {
            name: "Redirect-Address-IPAddress",
            avp_type: AvpType::Address,
        },
    ),
    // RFC 8506, Section 8.66 — https://www.rfc-editor.org/rfc/rfc8506#section-8.66
    (
        667,
        AvpDef {
            name: "Redirect-Address-URL",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.67 — https://www.rfc-editor.org/rfc/rfc8506#section-8.67
    (
        668,
        AvpDef {
            name: "Redirect-Address-SIP-URI",
            avp_type: AvpType::UTF8String,
        },
    ),
    // RFC 8506, Section 8.68 — https://www.rfc-editor.org/rfc/rfc8506#section-8.68
    (
        669,
        AvpDef {
            name: "QoS-Final-Unit-Indication",
            avp_type: AvpType::Grouped,
        },
    ),
];

/// 3GPP vendor-specific AVPs (vendor_id=10415), sorted by AVP code for binary search.
///
/// - 3GPP TS 29.212, Table 5.3.0.1 — Gx AVPs (Policy and Charging Control)
/// - 3GPP TS 29.214, Table 5.3.0.1 — Rx AVPs (QoS Authorization)
/// - 3GPP TS 29.229, Table 6.3.1 — Cx/Dx AVPs (IMS HSS)
/// - 3GPP TS 29.272, Section 7.3, Table 7.3.1/1 — S6a/S6d, S7a/S7d and S13/S13' specific AVPs
/// - 3GPP TS 29.329, Table 6.3.1 — Sh AVPs (User Profile)
/// - 3GPP TS 32.299, Table 7.1 — Charging AVPs
#[rustfmt::skip]
static TGPP_AVPS: &[(u32, AvpDef)] = &[
    // 3GPP TS 29.061 v19.1.0, clause 16a.5, Table 9a
    (1,    AvpDef { name: "3GPP-IMSI", avp_type: AvpType::UTF8String }),
    (2,    AvpDef { name: "3GPP-Charging-Id", avp_type: AvpType::OctetString }),
    (3,    AvpDef { name: "3GPP-PDP-Type", avp_type: AvpType::Enumerated }),
    (4,    AvpDef { name: "3GPP-CG-Address", avp_type: AvpType::OctetString }),
    (5,    AvpDef { name: "3GPP-GPRS-Negotiated-QoS-Profile", avp_type: AvpType::UTF8String }),
    (6,    AvpDef { name: "3GPP-SGSN-Address", avp_type: AvpType::OctetString }),
    (7,    AvpDef { name: "3GPP-GGSN-Address", avp_type: AvpType::OctetString }),
    (8,    AvpDef { name: "3GPP-IMSI-MCC-MNC", avp_type: AvpType::UTF8String }),
    (9,    AvpDef { name: "3GPP-GGSN-MCC-MNC", avp_type: AvpType::UTF8String }),
    (10,   AvpDef { name: "3GPP-NSAPI", avp_type: AvpType::OctetString }),
    (12,   AvpDef { name: "3GPP-Selection-Mode", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.061 — Interworking (re-used by TS 29.272, Table 7.3.1/2)
    (13,   AvpDef { name: "3GPP-Charging-Characteristics", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.061 v19.1.0, clause 16a.5, Table 9a
    (14,   AvpDef { name: "3GPP-CG-IPv6-Address", avp_type: AvpType::OctetString }),
    (15,   AvpDef { name: "3GPP-SGSN-IPv6-Address", avp_type: AvpType::OctetString }),
    (16,   AvpDef { name: "3GPP-GGSN-IPv6-Address", avp_type: AvpType::OctetString }),
    (17,   AvpDef { name: "3GPP-IPv6-DNS-Servers", avp_type: AvpType::OctetString }),
    (18,   AvpDef { name: "3GPP-SGSN-MCC-MNC", avp_type: AvpType::UTF8String }),
    (20,   AvpDef { name: "3GPP-IMEISV", avp_type: AvpType::OctetString }),
    (21,   AvpDef { name: "3GPP-RAT-Type", avp_type: AvpType::OctetString }),
    (22,   AvpDef { name: "3GPP-User-Location-Info", avp_type: AvpType::OctetString }),
    (23,   AvpDef { name: "3GPP-MS-TimeZone", avp_type: AvpType::OctetString }),
    (24,   AvpDef { name: "3GPP-CAMEL-Charging-Info", avp_type: AvpType::OctetString }),
    (25,   AvpDef { name: "3GPP-Packet-Filter", avp_type: AvpType::OctetString }),
    (26,   AvpDef { name: "3GPP-Negotiated-DSCP", avp_type: AvpType::OctetString }),
    (27,   AvpDef { name: "3GPP-Allocate-IP-Type", avp_type: AvpType::OctetString }),
    (29,   AvpDef { name: "TWAN-Identifier", avp_type: AvpType::OctetString }),
    (30,   AvpDef { name: "3GPP-User-Location-Info-Time", avp_type: AvpType::OctetString }),
    (31,   AvpDef { name: "3GPP-Secondary-RAT-Usage", avp_type: AvpType::OctetString }),
    (32,   AvpDef { name: "3GPP-UE-Local-IP-Address", avp_type: AvpType::OctetString }),
    (33,   AvpDef { name: "3GPP-UE-Source-Port", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.24
    (318,  AvpDef { name: "3GPP-AAA-Server-Name", avp_type: AvpType::DiameterIdentity }),
    // 3GPP TS 29.214, Table 5.3.0.1 — Rx AVPs
    (504,  AvpDef { name: "AF-Application-Identifier", avp_type: AvpType::OctetString }),
    (505,  AvpDef { name: "AF-Charging-Identifier", avp_type: AvpType::OctetString }),
    (507,  AvpDef { name: "Flow-Description", avp_type: AvpType::OctetString }),
    (509,  AvpDef { name: "Flow-Number", avp_type: AvpType::Unsigned32 }),
    (511,  AvpDef { name: "Flow-Status", avp_type: AvpType::Enumerated }),
    (512,  AvpDef { name: "Flow-Usage", avp_type: AvpType::Enumerated }),
    (513,  AvpDef { name: "Specific-Action", avp_type: AvpType::Enumerated }),
    (515,  AvpDef { name: "Max-Requested-Bandwidth-DL", avp_type: AvpType::Unsigned32 }),
    (516,  AvpDef { name: "Max-Requested-Bandwidth-UL", avp_type: AvpType::Unsigned32 }),
    (517,  AvpDef { name: "Media-Component-Description", avp_type: AvpType::Grouped }),
    (518,  AvpDef { name: "Media-Component-Number", avp_type: AvpType::Unsigned32 }),
    (519,  AvpDef { name: "Media-Sub-Component", avp_type: AvpType::Grouped }),
    (520,  AvpDef { name: "Media-Type", avp_type: AvpType::Enumerated }),
    (524,  AvpDef { name: "Codec-Data", avp_type: AvpType::OctetString }),
    (525,  AvpDef { name: "Service-URN", avp_type: AvpType::OctetString }),
    (527,  AvpDef { name: "Service-Info-Status", avp_type: AvpType::Enumerated }),
    (531,  AvpDef { name: "Sponsor-Identity", avp_type: AvpType::UTF8String }),
    (532,  AvpDef { name: "Application-Service-Provider-Identity", avp_type: AvpType::UTF8String }),
    (533,  AvpDef { name: "Rx-Request-Type", avp_type: AvpType::Enumerated }),
    (534,  AvpDef { name: "Min-Requested-Bandwidth-DL", avp_type: AvpType::Unsigned32 }),
    (535,  AvpDef { name: "Min-Requested-Bandwidth-UL", avp_type: AvpType::Unsigned32 }),
    (554,  AvpDef { name: "Extended-Max-Requested-BW-DL", avp_type: AvpType::Unsigned32 }),
    (555,  AvpDef { name: "Extended-Max-Requested-BW-UL", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.229, Table 6.3.1 — Cx/Dx AVPs
    (600,  AvpDef { name: "Visited-Network-Identifier", avp_type: AvpType::OctetString }),
    (601,  AvpDef { name: "Public-Identity", avp_type: AvpType::UTF8String }),
    (602,  AvpDef { name: "Server-Name", avp_type: AvpType::UTF8String }),
    (603,  AvpDef { name: "Server-Capabilities", avp_type: AvpType::Grouped }),
    (604,  AvpDef { name: "Mandatory-Capability", avp_type: AvpType::Unsigned32 }),
    (605,  AvpDef { name: "Optional-Capability", avp_type: AvpType::Unsigned32 }),
    (606,  AvpDef { name: "User-Data", avp_type: AvpType::OctetString }),
    (607,  AvpDef { name: "SIP-Number-Auth-Items", avp_type: AvpType::Unsigned32 }),
    (608,  AvpDef { name: "SIP-Authentication-Scheme", avp_type: AvpType::UTF8String }),
    (609,  AvpDef { name: "SIP-Authenticate", avp_type: AvpType::OctetString }),
    (610,  AvpDef { name: "SIP-Authorization", avp_type: AvpType::OctetString }),
    (611,  AvpDef { name: "SIP-Authentication-Context", avp_type: AvpType::OctetString }),
    (612,  AvpDef { name: "SIP-Auth-Data-Item", avp_type: AvpType::Grouped }),
    (613,  AvpDef { name: "SIP-Item-Number", avp_type: AvpType::Unsigned32 }),
    (614,  AvpDef { name: "Server-Assignment-Type", avp_type: AvpType::Enumerated }),
    (615,  AvpDef { name: "Deregistration-Reason", avp_type: AvpType::Grouped }),
    (616,  AvpDef { name: "Reason-Code", avp_type: AvpType::Enumerated }),
    (617,  AvpDef { name: "Reason-Info", avp_type: AvpType::UTF8String }),
    (618,  AvpDef { name: "Charging-Information", avp_type: AvpType::Grouped }),
    (619,  AvpDef { name: "Primary-Event-Charging-Function-Name", avp_type: AvpType::DiameterURI }),
    (620,  AvpDef { name: "Secondary-Event-Charging-Function-Name", avp_type: AvpType::DiameterURI }),
    (621,  AvpDef { name: "Primary-Charging-Collection-Function-Name", avp_type: AvpType::DiameterURI }),
    (622,  AvpDef { name: "Secondary-Charging-Collection-Function-Name", avp_type: AvpType::DiameterURI }),
    (623,  AvpDef { name: "User-Authorization-Type", avp_type: AvpType::Enumerated }),
    (624,  AvpDef { name: "User-Data-Already-Available", avp_type: AvpType::Enumerated }),
    (625,  AvpDef { name: "Confidentiality-Key", avp_type: AvpType::OctetString }),
    (626,  AvpDef { name: "Integrity-Key", avp_type: AvpType::OctetString }),
    (628,  AvpDef { name: "Supported-Features", avp_type: AvpType::Grouped }),
    (629,  AvpDef { name: "Feature-List-ID", avp_type: AvpType::Unsigned32 }),
    (630,  AvpDef { name: "Feature-List", avp_type: AvpType::Unsigned32 }),
    (632,  AvpDef { name: "LIA-Flags", avp_type: AvpType::Unsigned32 }),
    (634,  AvpDef { name: "Wildcarded-Public-Identity", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.329, Table 6.3.1 — Sh AVPs
    (700,  AvpDef { name: "User-Identity", avp_type: AvpType::Grouped }),
    (701,  AvpDef { name: "MSISDN", avp_type: AvpType::OctetString }),
    (702,  AvpDef { name: "User-Data-Sh", avp_type: AvpType::OctetString }),
    (703,  AvpDef { name: "Data-Reference", avp_type: AvpType::Enumerated }),
    (704,  AvpDef { name: "Service-Indication", avp_type: AvpType::OctetString }),
    (705,  AvpDef { name: "Subs-Req-Type", avp_type: AvpType::Enumerated }),
    (706,  AvpDef { name: "Requested-Domain", avp_type: AvpType::Enumerated }),
    (707,  AvpDef { name: "Current-Location", avp_type: AvpType::Enumerated }),
    (708,  AvpDef { name: "Identity-Set", avp_type: AvpType::Enumerated }),
    (709,  AvpDef { name: "Expiry-Time", avp_type: AvpType::Time }),
    (710,  AvpDef { name: "Send-Data-Indication", avp_type: AvpType::Enumerated }),
    (711,  AvpDef { name: "DSAI-Tag", avp_type: AvpType::OctetString }),
    // 3GPP TS 32.299, Table 7.1 — Charging AVPs (vendor_id=10415)
    (848,  AvpDef { name: "Served-Party-IP-Address", avp_type: AvpType::Address }),
    (857,  AvpDef { name: "Charged-Party", avp_type: AvpType::UTF8String }),
    (872,  AvpDef { name: "Reporting-Reason", avp_type: AvpType::Enumerated }),
    (873,  AvpDef { name: "Service-Information", avp_type: AvpType::Grouped }),
    (874,  AvpDef { name: "PS-Information", avp_type: AvpType::Grouped }),
    (876,  AvpDef { name: "IMS-Information", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.212, Table 5.3.0.1 — Gx AVPs
    (1001, AvpDef { name: "Charging-Rule-Install", avp_type: AvpType::Grouped }),
    (1002, AvpDef { name: "Charging-Rule-Remove", avp_type: AvpType::Grouped }),
    (1003, AvpDef { name: "Charging-Rule-Definition", avp_type: AvpType::Grouped }),
    (1004, AvpDef { name: "Charging-Rule-Base-Name", avp_type: AvpType::UTF8String }),
    (1005, AvpDef { name: "Charging-Rule-Name", avp_type: AvpType::OctetString }),
    (1006, AvpDef { name: "Event-Trigger", avp_type: AvpType::Enumerated }),
    (1007, AvpDef { name: "Metering-Method", avp_type: AvpType::Enumerated }),
    (1008, AvpDef { name: "Offline", avp_type: AvpType::Enumerated }),
    (1009, AvpDef { name: "Online", avp_type: AvpType::Enumerated }),
    (1010, AvpDef { name: "Precedence", avp_type: AvpType::Unsigned32 }),
    (1011, AvpDef { name: "Reporting-Level", avp_type: AvpType::Enumerated }),
    (1012, AvpDef { name: "TFT-Filter", avp_type: AvpType::OctetString }),
    (1013, AvpDef { name: "TFT-Packet-Filter-Information", avp_type: AvpType::Grouped }),
    (1014, AvpDef { name: "ToS-Traffic-Class", avp_type: AvpType::OctetString }),
    (1016, AvpDef { name: "QoS-Information", avp_type: AvpType::Grouped }),
    (1018, AvpDef { name: "Charging-Rule-Report", avp_type: AvpType::Grouped }),
    (1019, AvpDef { name: "PCC-Rule-Status", avp_type: AvpType::Enumerated }),
    (1020, AvpDef { name: "Bearer-Identifier", avp_type: AvpType::OctetString }),
    (1021, AvpDef { name: "Bearer-Operation", avp_type: AvpType::Enumerated }),
    (1022, AvpDef { name: "Access-Network-Charging-Identifier-Gx", avp_type: AvpType::Grouped }),
    (1023, AvpDef { name: "Bearer-Control-Mode", avp_type: AvpType::Enumerated }),
    (1024, AvpDef { name: "Network-Request-Support", avp_type: AvpType::Enumerated }),
    (1025, AvpDef { name: "Guaranteed-Bitrate-DL", avp_type: AvpType::Unsigned32 }),
    (1026, AvpDef { name: "Guaranteed-Bitrate-UL", avp_type: AvpType::Unsigned32 }),
    (1027, AvpDef { name: "IP-CAN-Type", avp_type: AvpType::Enumerated }),
    (1028, AvpDef { name: "QoS-Class-Identifier", avp_type: AvpType::Enumerated }),
    (1032, AvpDef { name: "RAT-Type", avp_type: AvpType::Enumerated }),
    (1034, AvpDef { name: "Allocation-Retention-Priority", avp_type: AvpType::Grouped }),
    (1040, AvpDef { name: "APN-Aggregate-Max-Bitrate-DL", avp_type: AvpType::Unsigned32 }),
    (1041, AvpDef { name: "APN-Aggregate-Max-Bitrate-UL", avp_type: AvpType::Unsigned32 }),
    (1046, AvpDef { name: "Priority-Level", avp_type: AvpType::Unsigned32 }),
    (1047, AvpDef { name: "Pre-emption-Capability", avp_type: AvpType::Enumerated }),
    (1048, AvpDef { name: "Pre-emption-Vulnerability", avp_type: AvpType::Enumerated }),
    (1049, AvpDef { name: "Default-EPS-Bearer-QoS", avp_type: AvpType::Grouped }),
    (1050, AvpDef { name: "AN-GW-Address", avp_type: AvpType::Address }),
    (1067, AvpDef { name: "Usage-Monitoring-Information", avp_type: AvpType::Grouped }),
    (1068, AvpDef { name: "Usage-Monitoring-Level", avp_type: AvpType::Enumerated }),
    (1069, AvpDef { name: "Usage-Monitoring-Report", avp_type: AvpType::Enumerated }),
    (1070, AvpDef { name: "Usage-Monitoring-Support", avp_type: AvpType::Enumerated }),
    (1073, AvpDef { name: "Charging-Correlation-Indicator", avp_type: AvpType::Enumerated }),
    // 3GPP TS 32.299, Table 7.1 — Charging AVPs (continued)
    (1227, AvpDef { name: "PDP-Address", avp_type: AvpType::Address }),
    (1264, AvpDef { name: "Trigger", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.272 — S6a/S6d, S7a/S7d, S13/S13' (Table 7.3.1/1)
    (1400, AvpDef { name: "Subscription-Data", avp_type: AvpType::Grouped }),
    (1401, AvpDef { name: "Terminal-Information", avp_type: AvpType::Grouped }),
    (1402, AvpDef { name: "IMEI", avp_type: AvpType::UTF8String }),
    (1403, AvpDef { name: "Software-Version", avp_type: AvpType::UTF8String }),
    (1404, AvpDef { name: "QoS-Subscribed", avp_type: AvpType::OctetString }),
    (1405, AvpDef { name: "ULR-Flags", avp_type: AvpType::Unsigned32 }),
    (1406, AvpDef { name: "ULA-Flags", avp_type: AvpType::Unsigned32 }),
    (1407, AvpDef { name: "Visited-PLMN-Id", avp_type: AvpType::OctetString }),
    (1408, AvpDef { name: "Requested-EUTRAN-Authentication-Info", avp_type: AvpType::Grouped }),
    (1409, AvpDef { name: "Requested-UTRAN-GERAN-Authentication-Info", avp_type: AvpType::Grouped }),
    (1410, AvpDef { name: "Number-Of-Requested-Vectors", avp_type: AvpType::Unsigned32 }),
    (1411, AvpDef { name: "Re-Synchronization-Info", avp_type: AvpType::OctetString }),
    (1412, AvpDef { name: "Immediate-Response-Preferred", avp_type: AvpType::Unsigned32 }),
    (1413, AvpDef { name: "Authentication-Info", avp_type: AvpType::Grouped }),
    (1414, AvpDef { name: "E-UTRAN-Vector", avp_type: AvpType::Grouped }),
    (1415, AvpDef { name: "UTRAN-Vector", avp_type: AvpType::Grouped }),
    (1416, AvpDef { name: "GERAN-Vector", avp_type: AvpType::Grouped }),
    (1417, AvpDef { name: "Network-Access-Mode", avp_type: AvpType::Enumerated }),
    (1418, AvpDef { name: "HPLMN-ODB", avp_type: AvpType::Unsigned32 }),
    (1419, AvpDef { name: "Item-Number", avp_type: AvpType::Unsigned32 }),
    (1420, AvpDef { name: "Cancellation-Type", avp_type: AvpType::Enumerated }),
    (1421, AvpDef { name: "DSR-Flags", avp_type: AvpType::Unsigned32 }),
    (1422, AvpDef { name: "DSA-Flags", avp_type: AvpType::Unsigned32 }),
    (1423, AvpDef { name: "Context-Identifier", avp_type: AvpType::Unsigned32 }),
    (1424, AvpDef { name: "Subscriber-Status", avp_type: AvpType::Enumerated }),
    (1425, AvpDef { name: "Operator-Determined-Barring", avp_type: AvpType::Unsigned32 }),
    (1426, AvpDef { name: "Access-Restriction-Data", avp_type: AvpType::Unsigned32 }),
    (1427, AvpDef { name: "APN-OI-Replacement", avp_type: AvpType::UTF8String }),
    (1428, AvpDef { name: "All-APN-Configurations-Included-Indicator", avp_type: AvpType::Enumerated }),
    (1429, AvpDef { name: "APN-Configuration-Profile", avp_type: AvpType::Grouped }),
    (1430, AvpDef { name: "APN-Configuration", avp_type: AvpType::Grouped }),
    (1431, AvpDef { name: "EPS-Subscribed-QoS-Profile", avp_type: AvpType::Grouped }),
    (1432, AvpDef { name: "VPLMN-Dynamic-Address-Allowed", avp_type: AvpType::Enumerated }),
    (1433, AvpDef { name: "STN-SR", avp_type: AvpType::OctetString }),
    (1434, AvpDef { name: "Alert-Reason", avp_type: AvpType::Enumerated }),
    (1435, AvpDef { name: "AMBR", avp_type: AvpType::Grouped }),
    (1436, AvpDef { name: "CSG-Subscription-Data", avp_type: AvpType::Grouped }),
    (1437, AvpDef { name: "CSG-Id", avp_type: AvpType::Unsigned32 }),
    (1438, AvpDef { name: "PDN-GW-Allocation-Type", avp_type: AvpType::Enumerated }),
    (1439, AvpDef { name: "Expiration-Date", avp_type: AvpType::Time }),
    (1440, AvpDef { name: "RAT-Frequency-Selection-Priority-ID", avp_type: AvpType::Unsigned32 }),
    (1441, AvpDef { name: "IDA-Flags", avp_type: AvpType::Unsigned32 }),
    (1442, AvpDef { name: "PUA-Flags", avp_type: AvpType::Unsigned32 }),
    (1443, AvpDef { name: "NOR-Flags", avp_type: AvpType::Unsigned32 }),
    (1444, AvpDef { name: "User-Id", avp_type: AvpType::UTF8String }),
    (1445, AvpDef { name: "Equipment-Status", avp_type: AvpType::Enumerated }),
    (1446, AvpDef { name: "Regional-Subscription-Zone-Code", avp_type: AvpType::OctetString }),
    (1447, AvpDef { name: "RAND", avp_type: AvpType::OctetString }),
    (1448, AvpDef { name: "XRES", avp_type: AvpType::OctetString }),
    (1449, AvpDef { name: "AUTN", avp_type: AvpType::OctetString }),
    (1450, AvpDef { name: "KASME", avp_type: AvpType::OctetString }),
    (1452, AvpDef { name: "Trace-Collection-Entity", avp_type: AvpType::Address }),
    (1453, AvpDef { name: "Kc", avp_type: AvpType::OctetString }),
    (1454, AvpDef { name: "SRES", avp_type: AvpType::OctetString }),
    (1456, AvpDef { name: "PDN-Type", avp_type: AvpType::Enumerated }),
    (1457, AvpDef { name: "Roaming-Restricted-Due-To-Unsupported-Feature", avp_type: AvpType::Enumerated }),
    (1458, AvpDef { name: "Trace-Data", avp_type: AvpType::Grouped }),
    (1459, AvpDef { name: "Trace-Reference", avp_type: AvpType::OctetString }),
    (1462, AvpDef { name: "Trace-Depth", avp_type: AvpType::Enumerated }),
    (1463, AvpDef { name: "Trace-NE-Type-List", avp_type: AvpType::OctetString }),
    (1464, AvpDef { name: "Trace-Interface-List", avp_type: AvpType::OctetString }),
    (1465, AvpDef { name: "Trace-Event-List", avp_type: AvpType::OctetString }),
    (1466, AvpDef { name: "OMC-Id", avp_type: AvpType::OctetString }),
    (1467, AvpDef { name: "GPRS-Subscription-Data", avp_type: AvpType::Grouped }),
    (1468, AvpDef { name: "Complete-Data-List-Included-Indicator", avp_type: AvpType::Enumerated }),
    (1469, AvpDef { name: "PDP-Context", avp_type: AvpType::Grouped }),
    (1470, AvpDef { name: "PDP-Type", avp_type: AvpType::OctetString }),
    (1471, AvpDef { name: "3GPP2-MEID", avp_type: AvpType::OctetString }),
    (1472, AvpDef { name: "Specific-APN-Info", avp_type: AvpType::Grouped }),
    (1473, AvpDef { name: "LCS-Info", avp_type: AvpType::Grouped }),
    (1474, AvpDef { name: "GMLC-Number", avp_type: AvpType::OctetString }),
    (1475, AvpDef { name: "LCS-PrivacyException", avp_type: AvpType::Grouped }),
    (1476, AvpDef { name: "SS-Code", avp_type: AvpType::OctetString }),
    (1477, AvpDef { name: "SS-Status", avp_type: AvpType::OctetString }),
    (1478, AvpDef { name: "Notification-To-UE-User", avp_type: AvpType::Enumerated }),
    (1479, AvpDef { name: "External-Client", avp_type: AvpType::Grouped }),
    (1480, AvpDef { name: "Client-Identity", avp_type: AvpType::OctetString }),
    (1481, AvpDef { name: "GMLC-Restriction", avp_type: AvpType::Enumerated }),
    (1482, AvpDef { name: "PLMN-Client", avp_type: AvpType::Enumerated }),
    (1483, AvpDef { name: "Service-Type", avp_type: AvpType::Grouped }),
    (1484, AvpDef { name: "ServiceTypeIdentity", avp_type: AvpType::Unsigned32 }),
    (1485, AvpDef { name: "MO-LR", avp_type: AvpType::Grouped }),
    (1486, AvpDef { name: "Teleservice-List", avp_type: AvpType::Grouped }),
    (1487, AvpDef { name: "TS-Code", avp_type: AvpType::OctetString }),
    (1488, AvpDef { name: "Call-Barring-Info", avp_type: AvpType::Grouped }),
    (1489, AvpDef { name: "SGSN-Number", avp_type: AvpType::OctetString }),
    (1490, AvpDef { name: "IDR-Flags", avp_type: AvpType::Unsigned32 }),
    (1491, AvpDef { name: "ICS-Indicator", avp_type: AvpType::Enumerated }),
    (1492, AvpDef { name: "IMS-Voice-Over-PS-Sessions-Supported", avp_type: AvpType::Enumerated }),
    (1493, AvpDef { name: "Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions", avp_type: AvpType::Enumerated }),
    (1494, AvpDef { name: "Last-UE-Activity-Time", avp_type: AvpType::Time }),
    (1495, AvpDef { name: "EPS-User-State", avp_type: AvpType::Grouped }),
    (1496, AvpDef { name: "EPS-Location-Information", avp_type: AvpType::Grouped }),
    (1497, AvpDef { name: "MME-User-State", avp_type: AvpType::Grouped }),
    (1498, AvpDef { name: "SGSN-User-State", avp_type: AvpType::Grouped }),
    (1499, AvpDef { name: "User-State", avp_type: AvpType::Enumerated }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.1
    (1500, AvpDef { name: "Non-3GPP-User-Data", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.3
    (1501, AvpDef { name: "Non-3GPP-IP-Access", avp_type: AvpType::Enumerated }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.4
    (1502, AvpDef { name: "Non-3GPP-IP-Access-APN", avp_type: AvpType::Enumerated }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.9
    (1503, AvpDef { name: "AN-Trusted", avp_type: AvpType::Enumerated }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.7
    (1504, AvpDef { name: "ANID", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.13
    (1505, AvpDef { name: "Trace-Info", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.12
    (1506, AvpDef { name: "MIP-FA-RK", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.13
    (1507, AvpDef { name: "MIP-FA-RK-SPI", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.17
    (1508, AvpDef { name: "PPR-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.18
    (1509, AvpDef { name: "WLAN-Identifier", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.19
    (1510, AvpDef { name: "TWAN-Access-Info", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.20
    (1511, AvpDef { name: "Access-Authorization-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.18
    (1512, AvpDef { name: "TWAN-Default-APN-Context-Id", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 9.2.3.1.4
    (1515, AvpDef { name: "Trust-Relationship-Update", avp_type: AvpType::Enumerated }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.14
    (1516, AvpDef { name: "Full-Network-Name", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.15
    (1517, AvpDef { name: "Short-Network-Name", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.21
    (1518, AvpDef { name: "AAA-Failure-Indication", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.19
    (1519, AvpDef { name: "Transport-Access-Type", avp_type: AvpType::Enumerated }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.20
    (1520, AvpDef { name: "DER-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.21
    (1521, AvpDef { name: "DEA-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 9.2.3.1.5
    (1522, AvpDef { name: "RAR-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 9.2.3.7
    (1523, AvpDef { name: "DER-S6b-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.22
    (1524, AvpDef { name: "SSID", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.23
    (1525, AvpDef { name: "HESSID", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.24
    (1526, AvpDef { name: "Access-Network-Info", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.25
    (1527, AvpDef { name: "TWAN-Connection-Mode", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.26
    (1528, AvpDef { name: "TWAN-Connectivity-Parameters", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.27
    (1529, AvpDef { name: "Connectivity-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.28
    (1530, AvpDef { name: "TWAN-PCO", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.29
    (1531, AvpDef { name: "TWAG-CP-Address", avp_type: AvpType::Address }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.30
    (1532, AvpDef { name: "TWAG-UP-Address", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.31
    (1533, AvpDef { name: "TWAN-S2a-Failure-Cause", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.32
    (1534, AvpDef { name: "SM-Back-Off-Timer", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.33
    (1535, AvpDef { name: "WLCP-Key", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.273 v19.2.0, clause 9.2.3.2.6
    (1536, AvpDef { name: "Origination-Time-Stamp", avp_type: AvpType::Unsigned64 }),
    // 3GPP TS 29.273 v19.2.0, clause 9.2.3.2.7
    (1537, AvpDef { name: "Maximum-Wait-Time", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 — SWx/STa/SWm (re-used by TS 29.272, Table 7.3.1/2)
    (1538, AvpDef { name: "Emergency-Services", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 7.2.3.5
    (1539, AvpDef { name: "AAR-Flags", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.35
    (1540, AvpDef { name: "IMEI-Check-In-VPLMN-Result", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 8.2.3.27
    (1541, AvpDef { name: "ERP-Authorization", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.273 v19.2.0, clause 5.2.3.36
    (1542, AvpDef { name: "High-Priority-Access-Info", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.272 — S6a/S6d (Table 7.3.1/1, continued)
    (1600, AvpDef { name: "MME-Location-Information", avp_type: AvpType::Grouped }),
    (1601, AvpDef { name: "SGSN-Location-Information", avp_type: AvpType::Grouped }),
    (1602, AvpDef { name: "E-UTRAN-Cell-Global-Identity", avp_type: AvpType::OctetString }),
    (1603, AvpDef { name: "Tracking-Area-Identity", avp_type: AvpType::OctetString }),
    (1604, AvpDef { name: "Cell-Global-Identity", avp_type: AvpType::OctetString }),
    (1605, AvpDef { name: "Routing-Area-Identity", avp_type: AvpType::OctetString }),
    (1606, AvpDef { name: "Location-Area-Identity", avp_type: AvpType::OctetString }),
    (1607, AvpDef { name: "Service-Area-Identity", avp_type: AvpType::OctetString }),
    (1608, AvpDef { name: "Geographical-Information", avp_type: AvpType::OctetString }),
    (1609, AvpDef { name: "Geodetic-Information", avp_type: AvpType::OctetString }),
    (1610, AvpDef { name: "Current-Location-Retrieved", avp_type: AvpType::Enumerated }),
    (1611, AvpDef { name: "Age-Of-Location-Information", avp_type: AvpType::Unsigned32 }),
    (1612, AvpDef { name: "Active-APN", avp_type: AvpType::Grouped }),
    (1613, AvpDef { name: "SIPTO-Permission", avp_type: AvpType::Enumerated }),
    (1614, AvpDef { name: "Error-Diagnostic", avp_type: AvpType::Enumerated }),
    (1615, AvpDef { name: "UE-SRVCC-Capability", avp_type: AvpType::Enumerated }),
    (1616, AvpDef { name: "MPS-Priority", avp_type: AvpType::Unsigned32 }),
    (1617, AvpDef { name: "VPLMN-LIPA-Allowed", avp_type: AvpType::Enumerated }),
    (1618, AvpDef { name: "LIPA-Permission", avp_type: AvpType::Enumerated }),
    (1619, AvpDef { name: "Subscribed-Periodic-RAU-TAU-Timer", avp_type: AvpType::Unsigned32 }),
    (1620, AvpDef { name: "Ext-PDP-Type", avp_type: AvpType::OctetString }),
    (1621, AvpDef { name: "Ext-PDP-Address", avp_type: AvpType::Address }),
    (1622, AvpDef { name: "MDT-Configuration", avp_type: AvpType::Grouped }),
    (1623, AvpDef { name: "Job-Type", avp_type: AvpType::Enumerated }),
    (1624, AvpDef { name: "Area-Scope", avp_type: AvpType::Grouped }),
    (1625, AvpDef { name: "List-Of-Measurements", avp_type: AvpType::Unsigned32 }),
    (1626, AvpDef { name: "Reporting-Trigger", avp_type: AvpType::Unsigned32 }),
    (1627, AvpDef { name: "Report-Interval", avp_type: AvpType::Enumerated }),
    (1628, AvpDef { name: "Report-Amount", avp_type: AvpType::Enumerated }),
    (1629, AvpDef { name: "Event-Threshold-RSRP", avp_type: AvpType::Unsigned32 }),
    (1630, AvpDef { name: "Event-Threshold-RSRQ", avp_type: AvpType::Unsigned32 }),
    (1631, AvpDef { name: "Logging-Interval", avp_type: AvpType::Enumerated }),
    (1632, AvpDef { name: "Logging-Duration", avp_type: AvpType::Enumerated }),
    (1633, AvpDef { name: "Relay-Node-Indicator", avp_type: AvpType::Enumerated }),
    (1634, AvpDef { name: "MDT-User-Consent", avp_type: AvpType::Enumerated }),
    (1635, AvpDef { name: "PUR-Flags", avp_type: AvpType::Unsigned32 }),
    (1636, AvpDef { name: "Subscribed-VSRVCC", avp_type: AvpType::Enumerated }),
    (1637, AvpDef { name: "Equivalent-PLMN-List", avp_type: AvpType::Grouped }),
    (1638, AvpDef { name: "CLR-Flags", avp_type: AvpType::Unsigned32 }),
    (1639, AvpDef { name: "UVR-Flags", avp_type: AvpType::Unsigned32 }),
    (1640, AvpDef { name: "UVA-Flags", avp_type: AvpType::Unsigned32 }),
    (1641, AvpDef { name: "VPLMN-CSG-Subscription-Data", avp_type: AvpType::Grouped }),
    (1642, AvpDef { name: "Time-Zone", avp_type: AvpType::UTF8String }),
    (1643, AvpDef { name: "A-MSISDN", avp_type: AvpType::OctetString }),
    (1645, AvpDef { name: "MME-Number-for-MT-SMS", avp_type: AvpType::OctetString }),
    (1648, AvpDef { name: "SMS-Register-Request", avp_type: AvpType::Enumerated }),
    (1649, AvpDef { name: "Local-Time-Zone", avp_type: AvpType::Grouped }),
    (1650, AvpDef { name: "Daylight-Saving-Time", avp_type: AvpType::Enumerated }),
    (1654, AvpDef { name: "Subscription-Data-Flags", avp_type: AvpType::Unsigned32 }),
    (1655, AvpDef { name: "Measurement-Period-LTE", avp_type: AvpType::Enumerated }),
    (1656, AvpDef { name: "Measurement-Period-UMTS", avp_type: AvpType::Enumerated }),
    (1657, AvpDef { name: "Collection-Period-RRM-LTE", avp_type: AvpType::Enumerated }),
    (1658, AvpDef { name: "Collection-Period-RRM-UMTS", avp_type: AvpType::Enumerated }),
    (1659, AvpDef { name: "Positioning-Method", avp_type: AvpType::OctetString }),
    (1660, AvpDef { name: "Measurement-Quantity", avp_type: AvpType::OctetString }),
    (1661, AvpDef { name: "Event-Threshold-Event-1F", avp_type: AvpType::Integer32 }),
    (1662, AvpDef { name: "Event-Threshold-Event-1I", avp_type: AvpType::Integer32 }),
    (1663, AvpDef { name: "Restoration-Priority", avp_type: AvpType::Unsigned32 }),
    (1664, AvpDef { name: "SGs-MME-Identity", avp_type: AvpType::UTF8String }),
    (1665, AvpDef { name: "SIPTO-Local-Network-Permission", avp_type: AvpType::Unsigned32 }),
    (1666, AvpDef { name: "Coupled-Node-Diameter-ID", avp_type: AvpType::DiameterIdentity }),
    (1667, AvpDef { name: "WLAN-offloadability", avp_type: AvpType::Grouped }),
    (1668, AvpDef { name: "WLAN-offloadability-EUTRAN", avp_type: AvpType::Unsigned32 }),
    (1669, AvpDef { name: "WLAN-offloadability-UTRAN", avp_type: AvpType::Unsigned32 }),
    (1670, AvpDef { name: "Reset-ID", avp_type: AvpType::OctetString }),
    (1671, AvpDef { name: "MDT-Allowed-PLMN-Id", avp_type: AvpType::OctetString }),
    (1672, AvpDef { name: "Adjacent-PLMNs", avp_type: AvpType::Grouped }),
    (1673, AvpDef { name: "Adjacent-Access-Restriction-Data", avp_type: AvpType::Grouped }),
    (1674, AvpDef { name: "DL-Buffering-Suggested-Packet-Count", avp_type: AvpType::Integer32 }),
    (1675, AvpDef { name: "IMSI-Group-Id", avp_type: AvpType::Grouped }),
    (1676, AvpDef { name: "Group-Service-Id", avp_type: AvpType::Unsigned32 }),
    (1677, AvpDef { name: "Group-PLMN-Id", avp_type: AvpType::OctetString }),
    (1678, AvpDef { name: "Local-Group-Id", avp_type: AvpType::OctetString }),
    (1679, AvpDef { name: "AIR-Flags", avp_type: AvpType::Unsigned32 }),
    (1680, AvpDef { name: "UE-Usage-Type", avp_type: AvpType::Unsigned32 }),
    (1681, AvpDef { name: "Non-IP-PDN-Type-Indicator", avp_type: AvpType::Enumerated }),
    (1682, AvpDef { name: "Non-IP-Data-Delivery-Mechanism", avp_type: AvpType::Unsigned32 }),
    (1683, AvpDef { name: "Additional-Context-ID", avp_type: AvpType::Unsigned32 }),
    (1684, AvpDef { name: "SCEF-Realm", avp_type: AvpType::DiameterIdentity }),
    (1685, AvpDef { name: "Subscription-Data-Deletion", avp_type: AvpType::Grouped }),
    (1686, AvpDef { name: "Preferred-Data-Mode", avp_type: AvpType::Unsigned32 }),
    (1687, AvpDef { name: "Emergency-Info", avp_type: AvpType::Grouped }),
    (1688, AvpDef { name: "V2X-Subscription-Data", avp_type: AvpType::Grouped }),
    (1689, AvpDef { name: "V2X-Permission", avp_type: AvpType::Unsigned32 }),
    (1690, AvpDef { name: "PDN-Connection-Continuity", avp_type: AvpType::Unsigned32 }),
    (1691, AvpDef { name: "eDRX-Cycle-Length", avp_type: AvpType::Grouped }),
    (1692, AvpDef { name: "eDRX-Cycle-Length-Value", avp_type: AvpType::OctetString }),
    (1693, AvpDef { name: "UE-PC5-AMBR", avp_type: AvpType::Unsigned32 }),
    (1694, AvpDef { name: "MBSFN-Area", avp_type: AvpType::Grouped }),
    (1695, AvpDef { name: "MBSFN-Area-ID", avp_type: AvpType::Unsigned32 }),
    (1696, AvpDef { name: "Carrier-Frequency", avp_type: AvpType::Unsigned32 }),
    (1697, AvpDef { name: "RDS-Indicator", avp_type: AvpType::Enumerated }),
    (1698, AvpDef { name: "Service-Gap-Time", avp_type: AvpType::Unsigned32 }),
    (1699, AvpDef { name: "Aerial-UE-Subscription-Information", avp_type: AvpType::Unsigned32 }),
    (1700, AvpDef { name: "Broadcast-Location-Assistance-Data-Types", avp_type: AvpType::Unsigned64 }),
    (1701, AvpDef { name: "Paging-Time-Window", avp_type: AvpType::Grouped }),
    (1702, AvpDef { name: "Operation-Mode", avp_type: AvpType::Unsigned32 }),
    (1703, AvpDef { name: "Paging-Time-Window-Length", avp_type: AvpType::OctetString }),
    (1704, AvpDef { name: "Core-Network-Restrictions", avp_type: AvpType::Unsigned32 }),
    (1705, AvpDef { name: "eDRX-Related-RAT", avp_type: AvpType::Grouped }),
    (1706, AvpDef { name: "Interworking-5GS-Indicator", avp_type: AvpType::Enumerated }),
    (1707, AvpDef { name: "Ethernet-PDN-Type-Indicator", avp_type: AvpType::Enumerated }),
    (1708, AvpDef { name: "Subscribed-ARPI", avp_type: AvpType::Unsigned32 }),
    (1709, AvpDef { name: "IAB-Operation-Permission", avp_type: AvpType::Enumerated }),
    (1710, AvpDef { name: "V2X-Subscription-Data-Nr", avp_type: AvpType::Grouped }),
    (1711, AvpDef { name: "UE-PC5-QoS", avp_type: AvpType::Grouped }),
    (1712, AvpDef { name: "PC5-QoS-Flow", avp_type: AvpType::Grouped }),
    (1713, AvpDef { name: "5QI", avp_type: AvpType::Integer32 }),
    (1714, AvpDef { name: "PC5-Flow-Bitrates", avp_type: AvpType::Grouped }),
    (1715, AvpDef { name: "Guaranteed-Flow-Bitrates", avp_type: AvpType::Integer32 }),
    (1716, AvpDef { name: "Maximum-Flow-Bitrates", avp_type: AvpType::Integer32 }),
    (1717, AvpDef { name: "PC5-Range", avp_type: AvpType::Integer32 }),
    (1718, AvpDef { name: "PC5-Link-AMBR", avp_type: AvpType::Integer32 }),
    (1719, AvpDef { name: "Third-Context-Identifier", avp_type: AvpType::Unsigned32 }),
    (1720, AvpDef { name: "MDT-Configuration-NR", avp_type: AvpType::Grouped }),
    (1721, AvpDef { name: "Event-Threshold-SINR", avp_type: AvpType::Unsigned32 }),
    (1722, AvpDef { name: "Collection-Period-RRM-NR", avp_type: AvpType::Enumerated }),
    (1723, AvpDef { name: "Collection-Period-M6-NR", avp_type: AvpType::Enumerated }),
    (1724, AvpDef { name: "Collection-Period-M7-NR", avp_type: AvpType::Unsigned32 }),
    (1725, AvpDef { name: "Sensor-Measurement", avp_type: AvpType::Enumerated }),
    (1726, AvpDef { name: "NR-Cell-Global-Identity", avp_type: AvpType::OctetString }),
    (1727, AvpDef { name: "Trace-Reporting-Consumer-Uri", avp_type: AvpType::DiameterURI }),
    (1728, AvpDef { name: "PLMN-RAT-Usage-Control", avp_type: AvpType::Unsigned32 }),
    (1729, AvpDef { name: "SF-ULR-Timestamp", avp_type: AvpType::Time }),
    (1730, AvpDef { name: "SF-Provisional-Indication", avp_type: AvpType::Enumerated }),
    // 3GPP TS 32.299 — Charging (re-used by TS 29.272, Table 7.3.1/2)
    (2319, AvpDef { name: "User-CSG-Information", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.173 — SLg (re-used by TS 29.272, Table 7.3.1/2)
    (2405, AvpDef { name: "GMLC-Address", avp_type: AvpType::Address }),
    // 3GPP TS 29.336 — S6t (re-used by TS 29.272, Table 7.3.1/2)
    (3111, AvpDef { name: "External-Identifier", avp_type: AvpType::UTF8String }),
    (3113, AvpDef { name: "AESE-Communication-Pattern", avp_type: AvpType::Grouped }),
    (3114, AvpDef { name: "Communication-Pattern-Set", avp_type: AvpType::Grouped }),
    (3122, AvpDef { name: "Monitoring-Event-Configuration", avp_type: AvpType::Grouped }),
    (3123, AvpDef { name: "Monitoring-Event-Report", avp_type: AvpType::Grouped }),
    (3124, AvpDef { name: "SCEF-Reference-ID", avp_type: AvpType::Unsigned32 }),
    (3125, AvpDef { name: "SCEF-ID", avp_type: AvpType::DiameterIdentity }),
    (3126, AvpDef { name: "SCEF-Reference-ID-for-Deletion", avp_type: AvpType::Unsigned32 }),
    (3127, AvpDef { name: "Monitoring-Type", avp_type: AvpType::Unsigned32 }),
    (3128, AvpDef { name: "Maximum-Number-of-Reports", avp_type: AvpType::Unsigned32 }),
    (3129, AvpDef { name: "UE-Reachability-Configuration", avp_type: AvpType::Grouped }),
    (3130, AvpDef { name: "Monitoring-Duration", avp_type: AvpType::Time }),
    (3132, AvpDef { name: "Reachability-Type", avp_type: AvpType::Unsigned32 }),
    (3134, AvpDef { name: "Maximum-Response-Time", avp_type: AvpType::Unsigned32 }),
    (3135, AvpDef { name: "Location-Information-Configuration", avp_type: AvpType::Grouped }),
    (3140, AvpDef { name: "Reachability-Information", avp_type: AvpType::Unsigned32 }),
    (3142, AvpDef { name: "Monitoring-Event-Config-Status", avp_type: AvpType::Grouped }),
    (3143, AvpDef { name: "Supported-Services", avp_type: AvpType::Grouped }),
    (3144, AvpDef { name: "Supported-Monitoring-Events", avp_type: AvpType::Unsigned64 }),
    (3148, AvpDef { name: "Reference-ID-Validity-Time", avp_type: AvpType::Time }),
    (3162, AvpDef { name: "Loss-Of-Connectivity-Reason", avp_type: AvpType::Unsigned32 }),
    (3178, AvpDef { name: "MTC-Provider-Info", avp_type: AvpType::Grouped }),
    (3180, AvpDef { name: "PDN-Connectivity-Status-Configuration", avp_type: AvpType::Grouped }),
    (3181, AvpDef { name: "PDN-Connectivity-Status-Report", avp_type: AvpType::Grouped }),
    (3183, AvpDef { name: "Traffic-Profile", avp_type: AvpType::Unsigned32 }),
    (3185, AvpDef { name: "Battery-Indicator", avp_type: AvpType::Unsigned32 }),
    (3186, AvpDef { name: "SCEF-Reference-ID-Ext", avp_type: AvpType::Unsigned64 }),
    (3187, AvpDef { name: "SCEF-Reference-ID-for-Deletion-Ext", avp_type: AvpType::Unsigned64 }),
    // 3GPP TS 29.338 — S6c/SGd (re-used by TS 29.272, Table 7.3.1/2)
    (3329, AvpDef { name: "Maximum-UE-Availability-Time", avp_type: AvpType::Time }),
    // 3GPP TS 29.344 — PC6/PC7 (re-used by TS 29.272, Table 7.3.1/2)
    (3701, AvpDef { name: "ProSe-Subscription-Data", avp_type: AvpType::Grouped }),
    // 3GPP TS 29.217 — NPLI (re-used by TS 29.272, Table 7.3.1/2)
    (4008, AvpDef { name: "eNodeB-Id", avp_type: AvpType::OctetString }),
    (4013, AvpDef { name: "Extended-eNodeB-Id", avp_type: AvpType::OctetString }),
    // 3GPP TS 29.128 — T6a/T6b (re-used by TS 29.272, Table 7.3.1/2)
    (4322, AvpDef { name: "Idle-Status-Indication", avp_type: AvpType::Grouped }),
    (4324, AvpDef { name: "Active-Time", avp_type: AvpType::Unsigned32 }),
    (4325, AvpDef { name: "Reachability-Cause", avp_type: AvpType::Unsigned32 }),
];

/// `(value, name)` pairs of one Enumerated AVP.
type EnumTable = &'static [(i32, &'static str)];

/// Enumerated AVP values, sorted by `(vendor_id, avp_code)` for binary search.
///
/// Base and RFC 8506 values follow the IANA "AAA Parameters" registries
/// (<https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xhtml>);
/// the defining clause is noted per entry.
static ENUM_VALUES: &[((u32, u32), EnumTable)] = &[
    // RFC 6733, Section 6.13 — https://www.rfc-editor.org/rfc/rfc6733#section-6.13
    (
        (0, 261),
        &[
            (0, "DONT_CACHE"),
            (1, "ALL_SESSION"),
            (2, "ALL_REALM"),
            (3, "REALM_AND_APPLICATION"),
            (4, "ALL_APPLICATION"),
            (5, "ALL_HOST"),
            (6, "ALL_USER"),
        ],
    ),
    // RFC 6733, Section 8.18 — https://www.rfc-editor.org/rfc/rfc6733#section-8.18
    (
        (0, 271),
        &[
            (0, "REFUSE_SERVICE"),
            (1, "TRY_AGAIN"),
            (2, "ALLOW_SERVICE"),
            (3, "TRY_AGAIN_ALLOW_SERVICE"),
        ],
    ),
    // RFC 6733, Section 5.4.3 — https://www.rfc-editor.org/rfc/rfc6733#section-5.4.3
    (
        (0, 273),
        &[
            (0, "REBOOTING"),
            (1, "BUSY"),
            (2, "DO_NOT_WANT_TO_TALK_TO_YOU"),
        ],
    ),
    // RFC 6733, Section 8.7 — https://www.rfc-editor.org/rfc/rfc6733#section-8.7
    (
        (0, 274),
        &[
            (1, "AUTHENTICATE_ONLY"),
            (2, "AUTHORIZE_ONLY"),
            (3, "AUTHORIZE_AUTHENTICATE"),
        ],
    ),
    // RFC 6733, Section 8.11 — https://www.rfc-editor.org/rfc/rfc6733#section-8.11
    (
        (0, 277),
        &[(0, "STATE_MAINTAINED"), (1, "NO_STATE_MAINTAINED")],
    ),
    // RFC 6733, Section 8.12 — https://www.rfc-editor.org/rfc/rfc6733#section-8.12
    (
        (0, 285),
        &[(0, "AUTHORIZE_ONLY"), (1, "AUTHORIZE_AUTHENTICATE")],
    ),
    // RFC 6733, Section 8.15 — https://www.rfc-editor.org/rfc/rfc6733#section-8.15
    (
        (0, 295),
        &[
            (1, "DIAMETER_LOGOUT"),
            (2, "DIAMETER_SERVICE_NOT_PROVIDED"),
            (3, "DIAMETER_BAD_ANSWER"),
            (4, "DIAMETER_ADMINISTRATIVE"),
            (5, "DIAMETER_LINK_BROKEN"),
            (6, "DIAMETER_AUTH_EXPIRED"),
            (7, "DIAMETER_USER_MOVED"),
            (8, "DIAMETER_SESSION_TIMEOUT"),
            (11, "User Request"),
            (12, "Lost Carrier"),
            (13, "Lost Service"),
            (14, "Idle Timeout"),
            (15, "Session Timeout"),
            (16, "Admin Reset"),
            (17, "Admin Reboot"),
            (18, "Port Error"),
            (19, "NAS Error"),
            (20, "NAS Request"),
            (21, "NAS Reboot"),
            (22, "Port Unneeded"),
            (23, "Port Preempted"),
            (24, "Port Suspended"),
            (25, "Service Unavailable"),
            (26, "Callback"),
            (27, "User Error"),
            (28, "Host Request"),
            (29, "Supplicant Restart"),
            (30, "Reauthentication Failure"),
            (31, "Port Reinitialized"),
            (32, "Port Administratively Disabled"),
        ],
    ),
    // RFC 7155, Section 4.6.7 — https://www.rfc-editor.org/rfc/rfc7155#section-4.6.7
    (
        (0, 406),
        &[
            (1, "PAP"),
            (2, "CHAP"),
            (3, "MS-CHAP-1"),
            (4, "MS-CHAP-2"),
            (5, "EAP"),
            (7, "None"),
        ],
    ),
    // RFC 8506, Section 8.3 — https://www.rfc-editor.org/rfc/rfc8506#section-8.3
    (
        (0, 416),
        &[
            (1, "INITIAL_REQUEST"),
            (2, "UPDATE_REQUEST"),
            (3, "TERMINATION_REQUEST"),
            (4, "EVENT_REQUEST"),
        ],
    ),
    // RFC 8506, Section 8.4 — https://www.rfc-editor.org/rfc/rfc8506#section-8.4
    (
        (0, 418),
        &[(0, "FAILOVER_NOT_SUPPORTED"), (1, "FAILOVER_SUPPORTED")],
    ),
    // RFC 8506, Section 8.6 — https://www.rfc-editor.org/rfc/rfc8506#section-8.6
    ((0, 422), &[(0, "ENOUGH_CREDIT"), (1, "NO_CREDIT")]),
    // RFC 8506, Section 8.13 — https://www.rfc-editor.org/rfc/rfc8506#section-8.13
    (
        (0, 426),
        &[(0, "CREDIT_AUTHORIZATION"), (1, "RE_AUTHORIZATION")],
    ),
    // RFC 8506, Section 8.14 — https://www.rfc-editor.org/rfc/rfc8506#section-8.14
    (
        (0, 427),
        &[
            (0, "TERMINATE"),
            (1, "CONTINUE"),
            (2, "RETRY_AND_TERMINATE"),
        ],
    ),
    // RFC 8506, Section 8.15 — https://www.rfc-editor.org/rfc/rfc8506#section-8.15
    ((0, 428), &[(0, "TERMINATE_OR_BUFFER"), (1, "CONTINUE")]),
    // RFC 8506, Section 8.38 — https://www.rfc-editor.org/rfc/rfc8506#section-8.38
    (
        (0, 433),
        &[
            (0, "IPv4 Address"),
            (1, "IPv6 Address"),
            (2, "URL"),
            (3, "SIP URI"),
        ],
    ),
    // RFC 8506, Section 8.41 — https://www.rfc-editor.org/rfc/rfc8506#section-8.41
    (
        (0, 436),
        &[
            (0, "DIRECT_DEBITING"),
            (1, "REFUND_ACCOUNT"),
            (2, "CHECK_BALANCE"),
            (3, "PRICE_ENQUIRY"),
        ],
    ),
    // RFC 8506, Section 8.35 — https://www.rfc-editor.org/rfc/rfc8506#section-8.35
    (
        (0, 449),
        &[(0, "TERMINATE"), (1, "REDIRECT"), (2, "RESTRICT_ACCESS")],
    ),
    // RFC 8506, Section 8.47 — https://www.rfc-editor.org/rfc/rfc8506#section-8.47
    (
        (0, 450),
        &[
            (0, "END_USER_E164"),
            (1, "END_USER_IMSI"),
            (2, "END_USER_SIP_URI"),
            (3, "END_USER_NAI"),
            (4, "END_USER_PRIVATE"),
        ],
    ),
    // RFC 8506, Section 8.27 — https://www.rfc-editor.org/rfc/rfc8506#section-8.27
    (
        (0, 452),
        &[
            (0, "UNIT_BEFORE_TARIFF_CHANGE"),
            (1, "UNIT_AFTER_TARIFF_CHANGE"),
            (2, "UNIT_INDETERMINATE"),
        ],
    ),
    // RFC 8506, Section 8.32 — https://www.rfc-editor.org/rfc/rfc8506#section-8.32
    (
        (0, 454),
        &[
            (0, "TIME"),
            (1, "MONEY"),
            (2, "TOTAL-OCTETS"),
            (3, "INPUT-OCTETS"),
            (4, "OUTPUT-OCTETS"),
            (5, "SERVICE-SPECIFIC-UNITS"),
        ],
    ),
    // RFC 8506, Section 8.40 — https://www.rfc-editor.org/rfc/rfc8506#section-8.40
    (
        (0, 455),
        &[
            (0, "MULTIPLE_SERVICES_NOT_SUPPORTED"),
            (1, "MULTIPLE_SERVICES_SUPPORTED"),
        ],
    ),
    // RFC 8506, Section 8.50 — https://www.rfc-editor.org/rfc/rfc8506#section-8.50
    (
        (0, 459),
        &[
            (0, "IMEISV"),
            (1, "MAC"),
            (2, "EUI64"),
            (3, "MODIFIED_EUI64"),
        ],
    ),
    // RFC 6733, Section 9.8.1 — https://www.rfc-editor.org/rfc/rfc6733#section-9.8.1
    (
        (0, 480),
        &[
            (1, "EVENT_RECORD"),
            (2, "START_RECORD"),
            (3, "INTERIM_RECORD"),
            (4, "STOP_RECORD"),
        ],
    ),
    // RFC 6733, Section 9.8.7 — https://www.rfc-editor.org/rfc/rfc6733#section-9.8.7
    (
        (0, 483),
        &[
            (1, "DELIVER_AND_GRANT"),
            (2, "GRANT_AND_STORE"),
            (3, "GRANT_AND_LOSE"),
        ],
    ),
    // 3GPP TS 29.061 v19.1.0, clause 16.4.7.2 (3GPP-PDP-Type)
    (
        (10415, 3),
        &[
            (0, "IPv4"),
            (1, "PPP"),
            (2, "IPv6"),
            (3, "IPv4v6"),
            (4, "Non-IP"),
            (5, "Unstructured"),
            (6, "Ethernet"),
        ],
    ),
    // 3GPP TS 29.229 v19.1.0, clause 6.3.15
    (
        (10415, 614),
        &[
            (0, "NO_ASSIGNMENT"),
            (1, "REGISTRATION"),
            (2, "RE_REGISTRATION"),
            (3, "UNREGISTERED_USER"),
            (4, "TIMEOUT_DEREGISTRATION"),
            (5, "USER_DEREGISTRATION"),
            (6, "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME"),
            (7, "USER_DEREGISTRATION_STORE_SERVER_NAME"),
            (8, "ADMINISTRATIVE_DEREGISTRATION"),
            (9, "AUTHENTICATION_FAILURE"),
            (10, "AUTHENTICATION_TIMEOUT"),
            (11, "DEREGISTRATION_TOO_MUCH_DATA"),
            (12, "AAA_USER_DATA_REQUEST"),
            (13, "PGW_UPDATE"),
            (14, "RESTORATION"),
        ],
    ),
    // 3GPP TS 29.229 v19.1.0, clause 6.3.17
    (
        (10415, 616),
        &[
            (0, "PERMANENT_TERMINATION"),
            (1, "NEW_SERVER_ASSIGNED"),
            (2, "SERVER_CHANGE"),
            (3, "REMOVE_S-CSCF"),
        ],
    ),
    // 3GPP TS 29.229 v19.1.0, clause 6.3.24
    (
        (10415, 623),
        &[
            (0, "REGISTRATION"),
            (1, "DE_REGISTRATION"),
            (2, "REGISTRATION_AND_CAPABILITIES"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.8
    (
        (10415, 1007),
        &[
            (0, "DURATION"),
            (1, "VOLUME"),
            (2, "DURATION_VOLUME"),
            (3, "EVENT"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.9
    (
        (10415, 1008),
        &[(0, "DISABLE_OFFLINE"), (1, "ENABLE_OFFLINE")],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.10
    (
        (10415, 1009),
        &[(0, "DISABLE_ONLINE"), (1, "ENABLE_ONLINE")],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.12
    (
        (10415, 1011),
        &[
            (0, "SERVICE_IDENTIFIER_LEVEL"),
            (1, "RATING_GROUP_LEVEL"),
            (2, "SPONSORED_CONNECTIVITY_LEVEL"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.19
    (
        (10415, 1019),
        &[(0, "ACTIVE"), (1, "INACTIVE"), (2, "TEMPORARILY INACTIVE")],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.21
    (
        (10415, 1021),
        &[
            (0, "TERMINATION"),
            (1, "ESTABLISHMENT"),
            (2, "MODIFICATION"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.23
    (
        (10415, 1023),
        &[(0, "UE_ONLY"), (1, "RESERVED"), (2, "UE_NW")],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.24
    (
        (10415, 1024),
        &[
            (0, "NETWORK_REQUEST NOT SUPPORTED"),
            (1, "NETWORK_REQUEST SUPPORTED"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.27
    (
        (10415, 1027),
        &[
            (0, "3GPP-GPRS"),
            (1, "DOCSIS"),
            (2, "xDSL"),
            (3, "WiMAX"),
            (4, "3GPP2"),
            (5, "3GPP-EPS"),
            (6, "Non-3GPP-EPS"),
            (7, "FBA"),
            (8, "3GPP-5GS"),
            (9, "Non-3GPP-5GS"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.17
    (
        (10415, 1028),
        &[
            (1, "QCI_1"),
            (2, "QCI_2"),
            (3, "QCI_3"),
            (4, "QCI_4"),
            (5, "QCI_5"),
            (6, "QCI_6"),
            (7, "QCI_7"),
            (8, "QCI_8"),
            (9, "QCI_9"),
            (65, "QCI_65"),
            (66, "QCI_66"),
            (67, "QCI_67"),
            (69, "QCI_69"),
            (70, "QCI_70"),
            (71, "QCI_71"),
            (72, "QCI_72"),
            (73, "QCI_73"),
            (74, "QCI_74"),
            (75, "QCI_75"),
            (76, "QCI_76"),
            (79, "QCI_79"),
            (80, "QCI_80"),
            (82, "QCI_82"),
            (83, "QCI_83"),
            (84, "QCI_84"),
            (85, "QCI_85"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.31
    (
        (10415, 1032),
        &[
            (0, "WLAN"),
            (1, "VIRTUAL"),
            (2, "TRUSTED-N3GA"),
            (3, "WIRELINE"),
            (4, "WIRELINE-CABLE"),
            (5, "WIRELINE-BBF"),
            (1000, "UTRAN"),
            (1001, "GERAN"),
            (1002, "GAN"),
            (1003, "HSPA_EVOLUTION"),
            (1004, "EUTRAN"),
            (1005, "EUTRAN-NB-IoT"),
            (1006, "NR"),
            (1007, "LTE-M"),
            (1008, "NR-U"),
            (1011, "EUTRAN(LEO)"),
            (1012, "EUTRAN(MEO)"),
            (1013, "EUTRAN(GEO)"),
            (1014, "EUTRAN(OTHERSAT)"),
            (1021, "EUTRAN-NB-IoT(LEO)"),
            (1022, "EUTRAN-NB-IoT(MEO)"),
            (1023, "EUTRAN-NB-IoT(GEO)"),
            (1024, "EUTRAN-NB-IoT(OTHERSAT)"),
            (1031, "LTE-M(LEO)"),
            (1032, "LTE-M(MEO)"),
            (1033, "LTE-M(GEO)"),
            (1034, "LTE-M(OTHERSAT)"),
            (1035, "NR(LEO)"),
            (1036, "NR(MEO)"),
            (1037, "NR(GEO)"),
            (1038, "NR(OTHERSAT)"),
            (1039, "NR-REDCAP"),
            (1040, "NR-EREDCAP"),
            (2000, "CDMA2000_1X"),
            (2001, "HRPD"),
            (2002, "UMB"),
            (2003, "EHRPD"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.46
    (
        (10415, 1047),
        &[
            (0, "PRE-EMPTION_CAPABILITY_ENABLED"),
            (1, "PRE-EMPTION_CAPABILITY_DISABLED"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.47
    (
        (10415, 1048),
        &[
            (0, "PRE-EMPTION_VULNERABILITY_ENABLED"),
            (1, "PRE-EMPTION_VULNERABILITY_DISABLED"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.61
    (
        (10415, 1068),
        &[
            (0, "SESSION_LEVEL"),
            (1, "PCC_RULE_LEVEL"),
            (2, "ADC_RULE_LEVEL"),
        ],
    ),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.62
    ((10415, 1069), &[(0, "USAGE_MONITORING_REPORT_REQUIRED")]),
    // 3GPP TS 29.212 v19.1.0, clause 5.3.63
    ((10415, 1070), &[(0, "USAGE_MONITORING_DISABLED")]),
    // 3GPP TS 29.272 v19.5.0, clause 7.3.21
    (
        (10415, 1417),
        &[(0, "PACKET_AND_CIRCUIT"), (2, "ONLY_PACKET")],
    ),
    // 3GPP TS 29.272 v19.5.0, clause 7.3.24
    (
        (10415, 1420),
        &[
            (0, "MME_UPDATE_PROCEDURE"),
            (1, "SGSN_UPDATE_PROCEDURE"),
            (2, "SUBSCRIPTION_WITHDRAWAL"),
            (3, "UPDATE_PROCEDURE_IWF"),
            (4, "INITIAL_ATTACH_PROCEDURE"),
            (5, "DISASTER_CONDITION_TERMINATED"),
        ],
    ),
    // 3GPP TS 29.272 v19.5.0, clause 7.3.29
    (
        (10415, 1424),
        &[(0, "SERVICE_GRANTED"), (1, "OPERATOR_DETERMINED_BARRING")],
    ),
    // 3GPP TS 29.272 v19.5.0, clause 7.3.33
    (
        (10415, 1428),
        &[
            (0, "All_APN_CONFIGURATIONS_INCLUDED"),
            (1, "MODIFIED_ADDED_APN_CONFIGURATIONS_INCLUDED"),
        ],
    ),
    // 3GPP TS 29.272 v19.5.0, clause 7.3.83
    (
        (10415, 1434),
        &[(0, "UE_PRESENT"), (1, "UE_MEMORY_AVAILABLE")],
    ),
    // 3GPP TS 29.272 v19.5.0, clause 7.3.62
    (
        (10415, 1456),
        &[(0, "IPv4"), (1, "IPv6"), (2, "IPv4v6"), (3, "IPv4_OR_IPv6")],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_values_sorted_and_typed() {
        for window in ENUM_VALUES.windows(2) {
            assert!(window[0].0 < window[1].0, "ENUM_VALUES not sorted");
        }
        // Every table belongs to an AVP that is Enumerated in the dictionary.
        for ((vendor, code), _) in ENUM_VALUES {
            let def = lookup_avp(*vendor, *code).unwrap_or_else(|| panic!("{vendor}/{code}"));
            assert_eq!(def.avp_type, AvpType::Enumerated, "{}", def.name);
        }
    }

    #[test]
    fn enum_value_name_lookup() {
        assert_eq!(enum_value_name(0, 295, 1), Some("DIAMETER_LOGOUT"));
        assert_eq!(enum_value_name(0, 454, 2), Some("TOTAL-OCTETS"));
        assert_eq!(enum_value_name(10415, 1456, 3), Some("IPv4_OR_IPv6"));
        assert_eq!(enum_value_name(10415, 3, 3), Some("IPv4v6"));
        assert_eq!(enum_value_name(10415, 1028, 9), Some("QCI_9"));
        assert_eq!(enum_value_name(10415, 1417, 1), None);
        assert_eq!(enum_value_name(0, 264, 0), None);
        assert_eq!(enum_value_name(9, 1, 0), None);
    }

    #[test]
    fn corrected_rfc8506_codes() {
        // RFC 8506, Section 8 — 446 is Used-Service-Unit, 454 CC-Unit-Type,
        // 456 Multiple-Services-Credit-Control and 419 CC-Sub-Session-Id.
        assert_eq!(lookup_avp(0, 446).unwrap().name, "Used-Service-Unit");
        assert_eq!(lookup_avp(0, 454).unwrap().name, "CC-Unit-Type");
        assert_eq!(
            lookup_avp(0, 456).unwrap().name,
            "Multiple-Services-Credit-Control"
        );
        assert_eq!(lookup_avp(0, 419).unwrap().name, "CC-Sub-Session-Id");
        assert_eq!(lookup_avp(0, 447).unwrap().avp_type, AvpType::Integer64);
        assert_eq!(
            lookup_avp(10415, 1518).unwrap().name,
            "AAA-Failure-Indication"
        );
        assert_eq!(lookup_avp(10415, 318).unwrap().name, "3GPP-AAA-Server-Name");
    }

    #[test]
    fn base_avps_sorted() {
        for window in BASE_AVPS.windows(2) {
            assert!(
                window[0].0 < window[1].0,
                "BASE_AVPS not sorted: {} >= {}",
                window[0].0,
                window[1].0
            );
        }
    }

    #[test]
    fn lookup_known_avp() {
        let def = lookup_avp(0, 264).unwrap();
        assert_eq!(def.name, "Origin-Host");
        assert_eq!(def.avp_type, AvpType::DiameterIdentity);
    }

    #[test]
    fn lookup_unknown_avp() {
        assert!(lookup_avp(0, 9999).is_none());
    }

    #[test]
    fn lookup_unknown_vendor() {
        assert!(lookup_avp(12345, 1).is_none());
    }

    #[test]
    fn command_name_cer() {
        assert_eq!(command_name(257, true), "Capabilities-Exchange-Request");
        assert_eq!(command_name(257, false), "Capabilities-Exchange-Answer");
    }

    #[test]
    fn command_name_credit_control() {
        assert_eq!(command_name(272, true), "Credit-Control-Request");
        assert_eq!(command_name(272, false), "Credit-Control-Answer");
    }

    #[test]
    fn command_name_unknown() {
        assert_eq!(command_name(9999, true), "Unknown");
    }

    #[test]
    fn result_code_name_success() {
        assert_eq!(result_code_name(2001), "DIAMETER_SUCCESS");
    }

    #[test]
    fn result_code_name_protocol_error() {
        assert_eq!(result_code_name(3001), "DIAMETER_COMMAND_UNSUPPORTED");
    }

    #[test]
    fn result_code_name_unknown() {
        assert_eq!(result_code_name(9999), "Unknown");
    }

    // ── 3GPP TS 29.272 S6a/S6d tests ────────────────────────────────────

    #[test]
    fn tgpp_avps_sorted() {
        for window in TGPP_AVPS.windows(2) {
            assert!(
                window[0].0 < window[1].0,
                "TGPP_AVPS not sorted: {} >= {}",
                window[0].0,
                window[1].0
            );
        }
    }

    #[test]
    fn lookup_3gpp_subscription_data() {
        let def = lookup_avp(10415, 1400).unwrap();
        assert_eq!(def.name, "Subscription-Data");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    #[test]
    fn lookup_3gpp_visited_plmn_id() {
        let def = lookup_avp(10415, 1407).unwrap();
        assert_eq!(def.name, "Visited-PLMN-Id");
        assert_eq!(def.avp_type, AvpType::OctetString);
    }

    #[test]
    fn lookup_3gpp_ulr_flags() {
        let def = lookup_avp(10415, 1405).unwrap();
        assert_eq!(def.name, "ULR-Flags");
        assert_eq!(def.avp_type, AvpType::Unsigned32);
    }

    #[test]
    fn lookup_3gpp_unknown_code() {
        assert!(lookup_avp(10415, 9999).is_none());
    }

    #[test]
    fn command_name_s6a_ulr() {
        assert_eq!(command_name(316, true), "Update-Location-Request");
        assert_eq!(command_name(316, false), "Update-Location-Answer");
    }

    #[test]
    fn command_name_s6a_air() {
        assert_eq!(
            command_name(318, true),
            "Authentication-Information-Request"
        );
        assert_eq!(
            command_name(318, false),
            "Authentication-Information-Answer"
        );
    }

    #[test]
    fn command_name_s6a_all_codes() {
        // TS 29.272, Section 7.2.2, Table 7.2.2/1 — S6a/S6d commands
        assert_eq!(command_name(317, true), "Cancel-Location-Request");
        assert_eq!(command_name(317, false), "Cancel-Location-Answer");
        assert_eq!(command_name(319, true), "Insert-Subscriber-Data-Request");
        assert_eq!(command_name(319, false), "Insert-Subscriber-Data-Answer");
        assert_eq!(command_name(320, true), "Delete-Subscriber-Data-Request");
        assert_eq!(command_name(320, false), "Delete-Subscriber-Data-Answer");
        assert_eq!(command_name(321, true), "Purge-UE-Request");
        assert_eq!(command_name(321, false), "Purge-UE-Answer");
        assert_eq!(command_name(322, true), "Reset-Request");
        assert_eq!(command_name(322, false), "Reset-Answer");
        assert_eq!(command_name(323, true), "Notify-Request");
        assert_eq!(command_name(323, false), "Notify-Answer");
    }

    #[test]
    fn command_name_s13_ecr() {
        // TS 29.272, Section 7.2.2, Table 7.2.2/2 — S13/S13' commands
        assert_eq!(command_name(324, true), "ME-Identity-Check-Request");
        assert_eq!(command_name(324, false), "ME-Identity-Check-Answer");
    }

    #[test]
    fn application_name_known() {
        assert_eq!(application_name(0), "Diameter Common Messages");
        assert_eq!(application_name(3), "Diameter Base Accounting");
        assert_eq!(application_name(4), "Diameter Credit-Control");
        assert_eq!(application_name(16777251), "3GPP S6a/S6d");
        assert_eq!(application_name(16777252), "3GPP S13/S13'");
        assert_eq!(application_name(16777308), "3GPP S7a/S7d");
    }

    #[test]
    fn application_name_unknown() {
        assert_eq!(application_name(99999), "Unknown");
    }

    #[test]
    fn experimental_result_code_name_s6a_permanent() {
        // TS 29.272, Section 7.4.3
        assert_eq!(
            experimental_result_code_name(5001),
            "DIAMETER_ERROR_USER_UNKNOWN"
        );
        assert_eq!(
            experimental_result_code_name(5420),
            "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"
        );
        assert_eq!(
            experimental_result_code_name(5421),
            "DIAMETER_ERROR_RAT_NOT_ALLOWED"
        );
        assert_eq!(
            experimental_result_code_name(5004),
            "DIAMETER_ERROR_ROAMING_NOT_ALLOWED"
        );
        assert_eq!(
            experimental_result_code_name(5422),
            "DIAMETER_ERROR_EQUIPMENT_UNKNOWN"
        );
        assert_eq!(
            experimental_result_code_name(5423),
            "DIAMETER_ERROR_UNKNOWN_SERVING_NODE"
        );
    }

    #[test]
    fn experimental_result_code_name_s6a_transient() {
        // TS 29.272, Section 7.4.4
        assert_eq!(
            experimental_result_code_name(4181),
            "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE"
        );
        assert_eq!(
            experimental_result_code_name(4182),
            "DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT"
        );
    }

    #[test]
    fn experimental_result_code_name_unknown() {
        assert_eq!(experimental_result_code_name(9999), "Unknown");
    }

    // ── Imported IETF AVPs (vendor_id=0) from TS 29.272 Table 7.3.1/2 ──

    #[test]
    fn lookup_base_drmp() {
        // RFC 7944 — DRMP
        let def = lookup_avp(0, 301).unwrap();
        assert_eq!(def.name, "DRMP");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    #[test]
    fn lookup_base_mip_home_agent_address() {
        // RFC 4004 — MIP-Home-Agent-Address
        let def = lookup_avp(0, 334).unwrap();
        assert_eq!(def.name, "MIP-Home-Agent-Address");
        assert_eq!(def.avp_type, AvpType::Address);
    }

    #[test]
    fn lookup_base_mip_home_agent_host() {
        // RFC 4004 — MIP-Home-Agent-Host
        let def = lookup_avp(0, 348).unwrap();
        assert_eq!(def.name, "MIP-Home-Agent-Host");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    #[test]
    fn lookup_base_mip6_agent_info() {
        // RFC 5447 — MIP6-Agent-Info
        let def = lookup_avp(0, 486).unwrap();
        assert_eq!(def.name, "MIP6-Agent-Info");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    #[test]
    fn lookup_base_service_selection() {
        // RFC 5778 — Service-Selection
        let def = lookup_avp(0, 493).unwrap();
        assert_eq!(def.name, "Service-Selection");
        assert_eq!(def.avp_type, AvpType::UTF8String);
    }

    // ── Imported 3GPP AVPs (vendor_id=10415) from TS 29.272 Table 7.3.1/2 ──

    #[test]
    fn lookup_3gpp_charging_characteristics() {
        // 3GPP TS 29.061 — 3GPP-Charging-Characteristics
        let def = lookup_avp(10415, 13).unwrap();
        assert_eq!(def.name, "3GPP-Charging-Characteristics");
        assert_eq!(def.avp_type, AvpType::UTF8String);
    }

    #[test]
    fn lookup_3gpp_supported_features() {
        // 3GPP TS 29.229 — Supported-Features
        let def = lookup_avp(10415, 628).unwrap();
        assert_eq!(def.name, "Supported-Features");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    #[test]
    fn lookup_3gpp_feature_list_id() {
        // 3GPP TS 29.229 — Feature-List-ID
        let def = lookup_avp(10415, 629).unwrap();
        assert_eq!(def.name, "Feature-List-ID");
        assert_eq!(def.avp_type, AvpType::Unsigned32);
    }

    #[test]
    fn lookup_3gpp_feature_list() {
        // 3GPP TS 29.229 — Feature-List
        let def = lookup_avp(10415, 630).unwrap();
        assert_eq!(def.name, "Feature-List");
        assert_eq!(def.avp_type, AvpType::Unsigned32);
    }

    #[test]
    fn lookup_3gpp_msisdn() {
        // 3GPP TS 29.329 — MSISDN
        let def = lookup_avp(10415, 701).unwrap();
        assert_eq!(def.name, "MSISDN");
        assert_eq!(def.avp_type, AvpType::OctetString);
    }

    #[test]
    fn lookup_3gpp_qos_class_identifier() {
        // 3GPP TS 29.212 — QoS-Class-Identifier
        let def = lookup_avp(10415, 1028).unwrap();
        assert_eq!(def.name, "QoS-Class-Identifier");
        assert_eq!(def.avp_type, AvpType::Enumerated);
    }

    #[test]
    fn lookup_3gpp_allocation_retention_priority() {
        // 3GPP TS 29.212 — Allocation-Retention-Priority
        let def = lookup_avp(10415, 1034).unwrap();
        assert_eq!(def.name, "Allocation-Retention-Priority");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    #[test]
    fn lookup_3gpp_gmlc_address() {
        // 3GPP TS 29.173 — GMLC-Address
        let def = lookup_avp(10415, 2405).unwrap();
        assert_eq!(def.name, "GMLC-Address");
        assert_eq!(def.avp_type, AvpType::Address);
    }

    // ── Boundary AVP tests (first/last in each table) ──

    #[test]
    fn lookup_base_avp_first() {
        // First entry in BASE_AVPS
        let def = lookup_avp(0, 1).unwrap();
        assert_eq!(def.name, "User-Name");
        assert_eq!(def.avp_type, AvpType::UTF8String);
    }

    #[test]
    fn lookup_base_avp_last() {
        // Last entry in BASE_AVPS
        let def = lookup_avp(0, 493).unwrap();
        assert_eq!(def.name, "Service-Selection");
        assert_eq!(def.avp_type, AvpType::UTF8String);
    }

    #[test]
    fn lookup_3gpp_avp_first() {
        // First entry in TGPP_AVPS
        let def = lookup_avp(10415, 13).unwrap();
        assert_eq!(def.name, "3GPP-Charging-Characteristics");
        assert_eq!(def.avp_type, AvpType::UTF8String);
    }

    #[test]
    fn lookup_3gpp_avp_last() {
        // Last entry in TGPP_AVPS
        let def = lookup_avp(10415, 4325).unwrap();
        assert_eq!(def.name, "Reachability-Cause");
        assert_eq!(def.avp_type, AvpType::Unsigned32);
    }

    #[test]
    fn lookup_unknown_vendor_ids() {
        // Various unknown vendor IDs
        assert!(lookup_avp(1, 1).is_none());
        assert!(lookup_avp(99999, 264).is_none());
        assert!(lookup_avp(10416, 1400).is_none());
    }

    #[test]
    fn lookup_avp_before_first_code() {
        // Code 0 is before the first entry in BASE_AVPS
        assert!(lookup_avp(0, 0).is_none());
    }

    #[test]
    fn lookup_avp_after_last_code() {
        // Code well beyond the last entry
        assert!(lookup_avp(0, 100000).is_none());
        assert!(lookup_avp(10415, 100000).is_none());
    }

    // ── Untested base command codes ──

    #[test]
    fn command_name_base_protocol_codes() {
        assert_eq!(command_name(258, true), "Re-Auth-Request");
        assert_eq!(command_name(258, false), "Re-Auth-Answer");
        assert_eq!(command_name(271, true), "Accounting-Request");
        assert_eq!(command_name(271, false), "Accounting-Answer");
        assert_eq!(command_name(272, true), "Credit-Control-Request");
        assert_eq!(command_name(272, false), "Credit-Control-Answer");
        assert_eq!(command_name(274, true), "Abort-Session-Request");
        assert_eq!(command_name(274, false), "Abort-Session-Answer");
        assert_eq!(command_name(275, true), "Session-Termination-Request");
        assert_eq!(command_name(275, false), "Session-Termination-Answer");
        assert_eq!(command_name(280, true), "Device-Watchdog-Request");
        assert_eq!(command_name(280, false), "Device-Watchdog-Answer");
        assert_eq!(command_name(282, true), "Disconnect-Peer-Request");
        assert_eq!(command_name(282, false), "Disconnect-Peer-Answer");
    }

    // ── Result-Code coverage ──

    #[test]
    fn result_code_name_informational() {
        assert_eq!(result_code_name(1001), "DIAMETER_MULTI_ROUND_AUTH");
    }

    #[test]
    fn result_code_name_limited_success() {
        assert_eq!(result_code_name(2002), "DIAMETER_LIMITED_SUCCESS");
    }

    #[test]
    fn result_code_name_transient_failures() {
        assert_eq!(result_code_name(4001), "DIAMETER_AUTHENTICATION_REJECTED");
        assert_eq!(result_code_name(4002), "DIAMETER_OUT_OF_SPACE");
        assert_eq!(result_code_name(4003), "ELECTION_LOST");
    }

    #[test]
    fn result_code_name_permanent_failures() {
        assert_eq!(result_code_name(5001), "DIAMETER_AVP_UNSUPPORTED");
        assert_eq!(result_code_name(5002), "DIAMETER_UNKNOWN_SESSION_ID");
        assert_eq!(result_code_name(5003), "DIAMETER_AUTHORIZATION_REJECTED");
        assert_eq!(result_code_name(5004), "DIAMETER_INVALID_AVP_VALUE");
        assert_eq!(result_code_name(5005), "DIAMETER_MISSING_AVP");
        assert_eq!(result_code_name(5006), "DIAMETER_RESOURCES_EXCEEDED");
        assert_eq!(result_code_name(5007), "DIAMETER_CONTRADICTING_AVPS");
        assert_eq!(result_code_name(5008), "DIAMETER_AVP_NOT_ALLOWED");
        assert_eq!(result_code_name(5009), "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES");
        assert_eq!(result_code_name(5010), "DIAMETER_NO_COMMON_APPLICATION");
        assert_eq!(result_code_name(5011), "DIAMETER_UNSUPPORTED_VERSION");
        assert_eq!(result_code_name(5012), "DIAMETER_UNABLE_TO_COMPLY");
        assert_eq!(result_code_name(5013), "DIAMETER_INVALID_BIT_IN_HEADER");
        assert_eq!(result_code_name(5014), "DIAMETER_INVALID_AVP_LENGTH");
        assert_eq!(result_code_name(5015), "DIAMETER_INVALID_MESSAGE_LENGTH");
        assert_eq!(result_code_name(5016), "DIAMETER_INVALID_AVP_BIT_COMBO");
        assert_eq!(result_code_name(5017), "DIAMETER_NO_COMMON_SECURITY");
    }

    #[test]
    fn result_code_name_protocol_errors() {
        assert_eq!(result_code_name(3002), "DIAMETER_UNABLE_TO_DELIVER");
        assert_eq!(result_code_name(3003), "DIAMETER_REALM_NOT_SERVED");
        assert_eq!(result_code_name(3004), "DIAMETER_TOO_BUSY");
        assert_eq!(result_code_name(3005), "DIAMETER_LOOP_DETECTED");
        assert_eq!(result_code_name(3006), "DIAMETER_REDIRECT_INDICATION");
        assert_eq!(result_code_name(3007), "DIAMETER_APPLICATION_UNSUPPORTED");
        assert_eq!(result_code_name(3008), "DIAMETER_INVALID_HDR_BITS");
        assert_eq!(result_code_name(3009), "DIAMETER_INVALID_AVP_BITS");
        assert_eq!(result_code_name(3010), "DIAMETER_UNKNOWN_PEER");
    }

    // ── AvpType variant coverage ──

    #[test]
    fn avp_type_variants_base_table() {
        // Ensure we can find AVPs of various types in the base table
        // Unsigned64 — Accounting-Sub-Session-Id (code=287)
        let def = lookup_avp(0, 287).unwrap();
        assert_eq!(def.avp_type, AvpType::Unsigned64);

        // Enumerated — Redirect-Host-Usage (code=261)
        let def = lookup_avp(0, 261).unwrap();
        assert_eq!(def.avp_type, AvpType::Enumerated);

        // DiameterURI — Redirect-Host (code=292)
        let def = lookup_avp(0, 292).unwrap();
        assert_eq!(def.avp_type, AvpType::DiameterURI);

        // Time — Event-Timestamp (code=55)
        let def = lookup_avp(0, 55).unwrap();
        assert_eq!(def.avp_type, AvpType::Time);

        // OctetString — Class (code=25)
        let def = lookup_avp(0, 25).unwrap();
        assert_eq!(def.avp_type, AvpType::OctetString);
    }

    #[test]
    fn avp_type_variants_3gpp_table() {
        // Integer32 — Event-Threshold-Event-1F (code=1661)
        let def = lookup_avp(10415, 1661).unwrap();
        assert_eq!(def.avp_type, AvpType::Integer32);

        // Unsigned64 — Broadcast-Location-Assistance-Data-Types (code=1700)
        let def = lookup_avp(10415, 1700).unwrap();
        assert_eq!(def.avp_type, AvpType::Unsigned64);

        // DiameterIdentity — Coupled-Node-Diameter-ID (code=1666)
        let def = lookup_avp(10415, 1666).unwrap();
        assert_eq!(def.avp_type, AvpType::DiameterIdentity);

        // Time — Expiration-Date (code=1439)
        let def = lookup_avp(10415, 1439).unwrap();
        assert_eq!(def.avp_type, AvpType::Time);

        // Address — Served-Party-IP-Address (code=848)
        let def = lookup_avp(10415, 848).unwrap();
        assert_eq!(def.avp_type, AvpType::Address);

        // DiameterURI — Trace-Reporting-Consumer-Uri (code=1727)
        let def = lookup_avp(10415, 1727).unwrap();
        assert_eq!(def.avp_type, AvpType::DiameterURI);
    }

    // ── 3GPP Application ID tests ──

    #[test]
    fn application_name_3gpp_interfaces() {
        // 3GPP TS 29.229, Section 6.2
        assert_eq!(application_name(16777216), "3GPP Cx");
        // 3GPP TS 29.329, Section 6.2
        assert_eq!(application_name(16777217), "3GPP Sh");
        // 3GPP TS 29.109, Section 6.2
        assert_eq!(application_name(16777221), "3GPP Zh");
        // 3GPP TS 29.214, Section 5.1
        assert_eq!(application_name(16777236), "3GPP Rx");
        // 3GPP TS 29.212, Section 5.1
        assert_eq!(application_name(16777238), "3GPP Gx");
        // 3GPP TS 29.273, Section 9
        assert_eq!(application_name(16777264), "3GPP SWm");
        // 3GPP TS 29.273, Section 8
        assert_eq!(application_name(16777265), "3GPP SWx");
        // 3GPP TS 29.273, Section 10
        assert_eq!(application_name(16777272), "3GPP S6b");
    }

    // ── 3GPP Cx/Dx command code tests (TS 29.229, Table 6.1/1) ──

    #[test]
    fn command_name_cx_all_codes() {
        assert_eq!(command_name(300, true), "User-Authorization-Request");
        assert_eq!(command_name(300, false), "User-Authorization-Answer");
        assert_eq!(command_name(301, true), "Server-Assignment-Request");
        assert_eq!(command_name(301, false), "Server-Assignment-Answer");
        assert_eq!(command_name(302, true), "Location-Info-Request");
        assert_eq!(command_name(302, false), "Location-Info-Answer");
        assert_eq!(command_name(303, true), "Multimedia-Auth-Request");
        assert_eq!(command_name(303, false), "Multimedia-Auth-Answer");
        assert_eq!(command_name(304, true), "Registration-Termination-Request");
        assert_eq!(command_name(304, false), "Registration-Termination-Answer");
        assert_eq!(command_name(305, true), "Push-Profile-Request");
        assert_eq!(command_name(305, false), "Push-Profile-Answer");
    }

    // ── 3GPP Sh command code tests (TS 29.329, Table 6.1/1) ──

    #[test]
    fn command_name_sh_all_codes() {
        assert_eq!(command_name(306, true), "User-Data-Request");
        assert_eq!(command_name(306, false), "User-Data-Answer");
        assert_eq!(command_name(307, true), "Profile-Update-Request");
        assert_eq!(command_name(307, false), "Profile-Update-Answer");
        assert_eq!(command_name(308, true), "Subscribe-Notifications-Request");
        assert_eq!(command_name(308, false), "Subscribe-Notifications-Answer");
        assert_eq!(command_name(309, true), "Push-Notification-Request");
        assert_eq!(command_name(309, false), "Push-Notification-Answer");
    }

    // ── Rx AA command code test (RFC 7155 / TS 29.214) ──

    #[test]
    fn command_name_rx_aa() {
        assert_eq!(command_name(265, true), "AA-Request");
        assert_eq!(command_name(265, false), "AA-Answer");
    }

    // ── 3GPP Cx/Dx AVP tests (TS 29.229, Table 6.3.1) ──

    #[test]
    fn lookup_cx_avps() {
        let def = lookup_avp(10415, 601).unwrap();
        assert_eq!(def.name, "Public-Identity");
        assert_eq!(def.avp_type, AvpType::UTF8String);

        let def = lookup_avp(10415, 602).unwrap();
        assert_eq!(def.name, "Server-Name");
        assert_eq!(def.avp_type, AvpType::UTF8String);

        let def = lookup_avp(10415, 603).unwrap();
        assert_eq!(def.name, "Server-Capabilities");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 612).unwrap();
        assert_eq!(def.name, "SIP-Auth-Data-Item");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 614).unwrap();
        assert_eq!(def.name, "Server-Assignment-Type");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(10415, 615).unwrap();
        assert_eq!(def.name, "Deregistration-Reason");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 618).unwrap();
        assert_eq!(def.name, "Charging-Information");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 623).unwrap();
        assert_eq!(def.name, "User-Authorization-Type");
        assert_eq!(def.avp_type, AvpType::Enumerated);
    }

    // ── 3GPP Sh AVP tests (TS 29.329, Table 6.3.1) ──

    #[test]
    fn lookup_sh_avps() {
        let def = lookup_avp(10415, 700).unwrap();
        assert_eq!(def.name, "User-Identity");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 702).unwrap();
        assert_eq!(def.name, "User-Data-Sh");
        assert_eq!(def.avp_type, AvpType::OctetString);

        let def = lookup_avp(10415, 703).unwrap();
        assert_eq!(def.name, "Data-Reference");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(10415, 705).unwrap();
        assert_eq!(def.name, "Subs-Req-Type");
        assert_eq!(def.avp_type, AvpType::Enumerated);
    }

    // ── 3GPP Gx AVP tests (TS 29.212, Table 5.3.0.1) ──

    #[test]
    fn lookup_gx_avps() {
        let def = lookup_avp(10415, 1001).unwrap();
        assert_eq!(def.name, "Charging-Rule-Install");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 1003).unwrap();
        assert_eq!(def.name, "Charging-Rule-Definition");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 1005).unwrap();
        assert_eq!(def.name, "Charging-Rule-Name");
        assert_eq!(def.avp_type, AvpType::OctetString);

        let def = lookup_avp(10415, 1006).unwrap();
        assert_eq!(def.name, "Event-Trigger");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(10415, 1016).unwrap();
        assert_eq!(def.name, "QoS-Information");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 1027).unwrap();
        assert_eq!(def.name, "IP-CAN-Type");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(10415, 1049).unwrap();
        assert_eq!(def.name, "Default-EPS-Bearer-QoS");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 1067).unwrap();
        assert_eq!(def.name, "Usage-Monitoring-Information");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    // ── 3GPP Rx AVP tests (TS 29.214, Table 5.3.0.1) ──

    #[test]
    fn lookup_rx_avps() {
        let def = lookup_avp(10415, 504).unwrap();
        assert_eq!(def.name, "AF-Application-Identifier");
        assert_eq!(def.avp_type, AvpType::OctetString);

        let def = lookup_avp(10415, 507).unwrap();
        assert_eq!(def.name, "Flow-Description");
        assert_eq!(def.avp_type, AvpType::OctetString);

        let def = lookup_avp(10415, 517).unwrap();
        assert_eq!(def.name, "Media-Component-Description");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 520).unwrap();
        assert_eq!(def.name, "Media-Type");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(10415, 525).unwrap();
        assert_eq!(def.name, "Service-URN");
        assert_eq!(def.avp_type, AvpType::OctetString);
    }

    // ── RFC 4006 Credit-Control AVP tests ──

    #[test]
    fn lookup_credit_control_avps() {
        // RFC 4006, Section 8 — Credit-Control AVPs (vendor_id=0)
        let def = lookup_avp(0, 412).unwrap();
        assert_eq!(def.name, "CC-Input-Octets");
        assert_eq!(def.avp_type, AvpType::Unsigned64);

        let def = lookup_avp(0, 416).unwrap();
        assert_eq!(def.name, "CC-Request-Type");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(0, 432).unwrap();
        assert_eq!(def.name, "Rating-Group");
        assert_eq!(def.avp_type, AvpType::Unsigned32);

        let def = lookup_avp(0, 439).unwrap();
        assert_eq!(def.name, "Service-Identifier");
        assert_eq!(def.avp_type, AvpType::Unsigned32);

        let def = lookup_avp(0, 443).unwrap();
        assert_eq!(def.name, "Subscription-Id");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(0, 461).unwrap();
        assert_eq!(def.name, "Service-Context-Id");
        assert_eq!(def.avp_type, AvpType::UTF8String);
    }

    // ── 3GPP Charging AVP tests (TS 32.299, Table 7.1) ──

    #[test]
    fn lookup_charging_avps() {
        let def = lookup_avp(10415, 872).unwrap();
        assert_eq!(def.name, "Reporting-Reason");
        assert_eq!(def.avp_type, AvpType::Enumerated);

        let def = lookup_avp(10415, 873).unwrap();
        assert_eq!(def.name, "Service-Information");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 874).unwrap();
        assert_eq!(def.name, "PS-Information");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 876).unwrap();
        assert_eq!(def.name, "IMS-Information");
        assert_eq!(def.avp_type, AvpType::Grouped);

        let def = lookup_avp(10415, 1264).unwrap();
        assert_eq!(def.name, "Trigger");
        assert_eq!(def.avp_type, AvpType::Grouped);
    }

    // ── 3GPP Experimental-Result-Code tests ──

    #[test]
    fn experimental_result_code_name_cx_success() {
        // 3GPP TS 29.229, Section 6.2 — Cx/Dx Success codes
        assert_eq!(
            experimental_result_code_name(2001),
            "DIAMETER_FIRST_REGISTRATION"
        );
        assert_eq!(
            experimental_result_code_name(2002),
            "DIAMETER_SUBSEQUENT_REGISTRATION"
        );
        assert_eq!(
            experimental_result_code_name(2003),
            "DIAMETER_UNREGISTERED_SERVICE"
        );
        assert_eq!(
            experimental_result_code_name(2004),
            "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED"
        );
    }

    #[test]
    fn experimental_result_code_name_cx_permanent() {
        // 3GPP TS 29.229, Section 6.2 — Cx/Dx Permanent Failures
        assert_eq!(
            experimental_result_code_name(5002),
            "DIAMETER_ERROR_IDENTITIES_DONT_MATCH"
        );
        assert_eq!(
            experimental_result_code_name(5003),
            "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED"
        );
        assert_eq!(
            experimental_result_code_name(5011),
            "DIAMETER_ERROR_FEATURE_UNSUPPORTED"
        );
    }

    #[test]
    fn experimental_result_code_name_gx() {
        // 3GPP TS 29.212, Section 5.6 — Gx Permanent Failures
        assert_eq!(
            experimental_result_code_name(5065),
            "DIAMETER_ERROR_BEARER_NOT_AUTHORIZED"
        );
        assert_eq!(
            experimental_result_code_name(5066),
            "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED"
        );
        assert_eq!(
            experimental_result_code_name(5144),
            "DIAMETER_ERROR_CONFLICTING_REQUEST"
        );
    }

    #[test]
    fn experimental_result_code_name_rx() {
        // 3GPP TS 29.214, Section 5.5 — Rx Permanent Failures
        assert_eq!(
            experimental_result_code_name(5061),
            "DIAMETER_ERROR_IP_CAN_SESSION_NOT_AVAILABLE"
        );
        assert_eq!(
            experimental_result_code_name(5063),
            "DIAMETER_ERROR_REQUESTED_SERVICE_NOT_AUTHORIZED"
        );
    }
}
