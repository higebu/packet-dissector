//! AVP (Attribute-Value Pair) type system and vendor-extensible lookup tables.
//!
//! ## References
//! - RFC 6733, Section 4: <https://www.rfc-editor.org/rfc/rfc6733#section-4>

/// Diameter AVP data type (RFC 6733, Section 4.2–4.4).
///
/// Not all variants are used by the base RFC 6733 AVP table; the remaining ones
/// (e.g., `Integer32`, `Float32`) are reserved for vendor-specific extensions
/// such as 3GPP (vendor_id=10415).
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
        3 => "Diameter Base Accounting",
        // RFC 4006, Section 1.2 — https://www.rfc-editor.org/rfc/rfc4006#section-1.2
        4 => "Diameter Credit-Control",
        // 3GPP TS 29.272, Section 7.1.8
        16777251 => "3GPP S6a/S6d",
        16777252 => "3GPP S13/S13'",
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
        // 3GPP TS 29.272, Section 7.4.3 — Permanent Failures
        5001 => "DIAMETER_ERROR_USER_UNKNOWN",
        5004 => "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
        5420 => "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
        5421 => "DIAMETER_ERROR_RAT_NOT_ALLOWED",
        5422 => "DIAMETER_ERROR_EQUIPMENT_UNKNOWN",
        5423 => "DIAMETER_ERROR_UNKNOWN_SERVING_NODE",
        // 3GPP TS 29.272, Section 7.4.4 — Transient Failures
        4181 => "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
        4182 => "DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT",
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
    (
        33,
        AvpDef {
            name: "Proxy-State",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        44,
        AvpDef {
            name: "Accounting-Session-Id",
            avp_type: AvpType::OctetString,
        },
    ),
    (
        50,
        AvpDef {
            name: "Acct-Multi-Session-Id",
            avp_type: AvpType::UTF8String,
        },
    ),
    (
        55,
        AvpDef {
            name: "Event-Timestamp",
            avp_type: AvpType::Time,
        },
    ),
    (
        85,
        AvpDef {
            name: "Acct-Interim-Interval",
            avp_type: AvpType::Unsigned32,
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
];

/// 3GPP vendor-specific AVPs (vendor_id=10415), sorted by AVP code for binary search.
///
/// 3GPP TS 29.272, Section 7.3, Table 7.3.1/1 — S6a/S6d, S7a/S7d and S13/S13' specific AVPs.
#[rustfmt::skip]
static TGPP_AVPS: &[(u32, AvpDef)] = &[
    // 3GPP TS 29.061 — Interworking (re-used by TS 29.272, Table 7.3.1/2)
    (13,   AvpDef { name: "3GPP-Charging-Characteristics", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.214 — Rx (re-used by TS 29.272, Table 7.3.1/2)
    (515,  AvpDef { name: "Max-Requested-Bandwidth-DL", avp_type: AvpType::Unsigned32 }),
    (516,  AvpDef { name: "Max-Requested-Bandwidth-UL", avp_type: AvpType::Unsigned32 }),
    (554,  AvpDef { name: "Extended-Max-Requested-BW-DL", avp_type: AvpType::Unsigned32 }),
    (555,  AvpDef { name: "Extended-Max-Requested-BW-UL", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.229 — Cx/Dx (re-used by TS 29.272, Table 7.3.1/2)
    (600,  AvpDef { name: "Visited-Network-Identifier", avp_type: AvpType::OctetString }),
    (625,  AvpDef { name: "Confidentiality-Key", avp_type: AvpType::OctetString }),
    (626,  AvpDef { name: "Integrity-Key", avp_type: AvpType::OctetString }),
    (628,  AvpDef { name: "Supported-Features", avp_type: AvpType::Grouped }),
    (629,  AvpDef { name: "Feature-List-ID", avp_type: AvpType::Unsigned32 }),
    (630,  AvpDef { name: "Feature-List", avp_type: AvpType::Unsigned32 }),
    // 3GPP TS 29.329 — Sh (re-used by TS 29.272, Table 7.3.1/2)
    (701,  AvpDef { name: "MSISDN", avp_type: AvpType::OctetString }),
    // 3GPP TS 32.299 — Charging (re-used by TS 29.272, Table 7.3.1/2)
    (848,  AvpDef { name: "Served-Party-IP-Address", avp_type: AvpType::Address }),
    (857,  AvpDef { name: "Charged-Party", avp_type: AvpType::UTF8String }),
    // 3GPP TS 29.212 — Gx/Sd (re-used by TS 29.272, Table 7.3.1/2)
    (1028, AvpDef { name: "QoS-Class-Identifier", avp_type: AvpType::Enumerated }),
    (1032, AvpDef { name: "RAT-Type", avp_type: AvpType::Enumerated }),
    (1034, AvpDef { name: "Allocation-Retention-Priority", avp_type: AvpType::Grouped }),
    (1040, AvpDef { name: "APN-Aggregate-Max-Bitrate-DL", avp_type: AvpType::Unsigned32 }),
    (1041, AvpDef { name: "APN-Aggregate-Max-Bitrate-UL", avp_type: AvpType::Unsigned32 }),
    (1046, AvpDef { name: "Priority-Level", avp_type: AvpType::Unsigned32 }),
    (1047, AvpDef { name: "Pre-emption-Capability", avp_type: AvpType::Enumerated }),
    (1048, AvpDef { name: "Pre-emption-Vulnerability", avp_type: AvpType::Enumerated }),
    // 3GPP TS 32.299 — Charging (re-used by TS 29.272, Table 7.3.1/2)
    (1227, AvpDef { name: "PDP-Address", avp_type: AvpType::Address }),
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
    // 3GPP TS 29.273 — SWx/STa/SWm (re-used by TS 29.272, Table 7.3.1/2)
    (1538, AvpDef { name: "Emergency-Services", avp_type: AvpType::Unsigned32 }),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
