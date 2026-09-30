//! Name tables for EPS NAS header fields, message types and causes.
//!
//! ## References
//! - 3GPP TS 24.301 v19.8.0, Sections 9.3.1, 9.8, 9.9.3.9 and 9.9.4.4:
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>
//! - 3GPP TS 24.007, Section 11.2.3.1.1:
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.007/>

/// Returns the name of a protocol discriminator handled by this crate.
///
/// 3GPP TS 24.007, Section 11.2.3.1.1, Table 11.2.
pub fn protocol_discriminator_name(pd: u8) -> Option<&'static str> {
    match pd {
        0x2 => Some("EPS session management messages"),
        0x7 => Some("EPS mobility management messages"),
        _ => None,
    }
}

/// Returns the name of a security header type.
///
/// 3GPP TS 24.301, Section 9.3.1, Table 9.3.1 — values 1101 to 1111 "shall
/// be interpreted as '1100'".
pub fn security_header_type_name(sht: u8) -> Option<&'static str> {
    Some(match sht {
        0 => "Plain NAS message, not security protected",
        1 => "Integrity protected",
        2 => "Integrity protected and ciphered",
        3 => "Integrity protected with new EPS security context",
        4 => "Integrity protected and ciphered with new EPS security context",
        5 => "Integrity protected and partially ciphered NAS message",
        0b1011 => "Security header for the EMM TRANSPORT message",
        0b1100..=0b1111 => "Security header for the SERVICE REQUEST message",
        _ => return None,
    })
}

/// Returns the name of an EMM message type.
///
/// 3GPP TS 24.301, Section 9.8, Table 9.8.1.
pub fn emm_message_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x41 => "Attach request",
        0x42 => "Attach accept",
        0x43 => "Attach complete",
        0x44 => "Attach reject",
        0x45 => "Detach request",
        0x46 => "Detach accept",
        0x48 => "Tracking area update request",
        0x49 => "Tracking area update accept",
        0x4a => "Tracking area update complete",
        0x4b => "Tracking area update reject",
        0x4c => "Extended service request",
        0x4d => "Control plane service request",
        0x4e => "Service reject",
        0x4f => "Service accept",
        0x50 => "GUTI reallocation command",
        0x51 => "GUTI reallocation complete",
        0x52 => "Authentication request",
        0x53 => "Authentication response",
        0x54 => "Authentication reject",
        0x5c => "Authentication failure",
        0x55 => "Identity request",
        0x56 => "Identity response",
        0x5d => "Security mode command",
        0x5e => "Security mode complete",
        0x5f => "Security mode reject",
        0x60 => "EMM status",
        0x61 => "EMM information",
        0x62 => "Downlink NAS transport",
        0x63 => "Uplink NAS transport",
        0x64 => "CS Service notification",
        0x68 => "Downlink generic NAS transport",
        0x69 => "Uplink generic NAS transport",
        _ => return None,
    })
}

/// Returns the name of an ESM message type.
///
/// 3GPP TS 24.301, Section 9.8, Table 9.8.2.
pub fn esm_message_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0xc1 => "Activate default EPS bearer context request",
        0xc2 => "Activate default EPS bearer context accept",
        0xc3 => "Activate default EPS bearer context reject",
        0xc5 => "Activate dedicated EPS bearer context request",
        0xc6 => "Activate dedicated EPS bearer context accept",
        0xc7 => "Activate dedicated EPS bearer context reject",
        0xc9 => "Modify EPS bearer context request",
        0xca => "Modify EPS bearer context accept",
        0xcb => "Modify EPS bearer context reject",
        0xcd => "Deactivate EPS bearer context request",
        0xce => "Deactivate EPS bearer context accept",
        0xd0 => "PDN connectivity request",
        0xd1 => "PDN connectivity reject",
        0xd2 => "PDN disconnect request",
        0xd3 => "PDN disconnect reject",
        0xd4 => "Bearer resource allocation request",
        0xd5 => "Bearer resource allocation reject",
        0xd6 => "Bearer resource modification request",
        0xd7 => "Bearer resource modification reject",
        0xd9 => "ESM information request",
        0xda => "ESM information response",
        0xdb => "Notification",
        0xdc => "ESM dummy message",
        0xe8 => "ESM status",
        0xe9 => "Remote UE report",
        0xea => "Remote UE report response",
        0xeb => "ESM data transport",
        _ => return None,
    })
}

/// Returns the name of an EMM cause value.
///
/// 3GPP TS 24.301, Section 9.9.3.9, Table 9.9.3.9.1.
pub fn emm_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        2 => "IMSI unknown in HSS",
        3 => "Illegal UE",
        5 => "IMEI not accepted",
        6 => "Illegal ME",
        7 => "EPS services not allowed",
        8 => "EPS services and non-EPS services not allowed",
        9 => "UE identity cannot be derived by the network",
        10 => "Implicitly detached",
        11 => "PLMN not allowed",
        12 => "Tracking Area not allowed",
        13 => "Roaming not allowed in this tracking area",
        14 => "EPS services not allowed in this PLMN",
        15 => "No Suitable Cells In tracking area",
        16 => "MSC temporarily not reachable",
        17 => "Network failure",
        18 => "CS domain not available",
        19 => "ESM failure",
        20 => "MAC failure",
        21 => "Synch failure",
        22 => "Congestion",
        23 => "UE security capabilities mismatch",
        24 => "Security mode rejected, unspecified",
        25 => "Not authorized for this CSG",
        26 => "Non-EPS authentication unacceptable",
        31 => "Redirection to 5GCN required",
        35 => "Requested service option not authorized in this PLMN",
        36 => "IAB-node operation not authorized",
        39 => "CS service temporarily not available",
        40 => "No EPS bearer context activated",
        42 => "Severe network failure",
        78 => "PLMN not allowed to operate at the present UE location",
        80 => "Disaster roaming for the determined PLMN with disaster condition not allowed",
        83 => "Procedure cannot be completed due to unavailable feeder link while MME is operating in S&F mode",
        95 => "Semantically incorrect message",
        96 => "Invalid mandatory information",
        97 => "Message type non-existent or not implemented",
        98 => "Message type not compatible with the protocol state",
        99 => "Information element non-existent or not implemented",
        100 => "Conditional IE error",
        101 => "Message not compatible with the protocol state",
        111 => "Protocol error, unspecified",
        _ => return None,
    })
}

/// Returns the name of an ESM cause value.
///
/// 3GPP TS 24.301, Section 9.9.4.4, Table 9.9.4.4.1 (value 46 is not used).
pub fn esm_cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        8 => "Operator Determined Barring",
        26 => "Insufficient resources",
        27 => "Missing or unknown APN",
        28 => "Unknown PDN type",
        29 => "User authentication or authorization failed",
        30 => "Request rejected by Serving GW or PDN GW",
        31 => "Request rejected, unspecified",
        32 => "Service option not supported",
        33 => "Requested service option not subscribed",
        34 => "Service option temporarily out of order",
        35 => "PTI already in use",
        36 => "Regular deactivation",
        37 => "EPS QoS not accepted",
        38 => "Network failure",
        39 => "Reactivation requested",
        41 => "Semantic error in the TFT operation",
        42 => "Syntactical error in the TFT operation",
        43 => "Invalid EPS bearer identity",
        44 => "Semantic errors in packet filter(s)",
        45 => "Syntactical errors in packet filter(s)",
        47 => "PTI mismatch",
        49 => "Last PDN disconnection not allowed",
        50 => "PDN type IPv4 only allowed",
        51 => "PDN type IPv6 only allowed",
        52 => "Single address bearers only allowed",
        53 => "ESM information not received",
        54 => "PDN connection does not exist",
        55 => "Multiple PDN connections for a given APN not allowed",
        56 => "Collision with network initiated request",
        57 => "PDN type IPv4v6 only allowed",
        58 => "PDN type non IP only allowed",
        59 => "Unsupported QCI value",
        60 => "Bearer handling not supported",
        61 => "PDN type Ethernet only allowed",
        65 => "Maximum number of EPS bearers reached",
        66 => "Requested APN not supported in current RAT and PLMN combination",
        81 => "Invalid PTI value",
        95 => "Semantically incorrect message",
        96 => "Invalid mandatory information",
        97 => "Message type non-existent or not implemented",
        98 => "Message type not compatible with the protocol state",
        99 => "Information element non-existent or not implemented",
        100 => "Conditional IE error",
        101 => "Message not compatible with the protocol state",
        111 => "Protocol error, unspecified",
        112 => "APN restriction value incompatible with active EPS bearer context",
        113 => "Multiple accesses to a PDN connection not allowed",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(f: fn(u8) -> Option<&'static str>) -> usize {
        (0..=255u8).filter(|v| f(*v).is_some()).count()
    }

    #[test]
    fn table_sizes() {
        assert_eq!(count(emm_message_type_name), 32);
        assert_eq!(count(esm_message_type_name), 27);
        assert_eq!(count(emm_cause_name), 41);
        assert_eq!(count(esm_cause_name), 47);
        assert_eq!(count(security_header_type_name), 11);
        assert_eq!(count(protocol_discriminator_name), 2);
    }

    #[test]
    fn sample_names() {
        assert_eq!(emm_message_type_name(0x41), Some("Attach request"));
        assert_eq!(esm_message_type_name(0xd0), Some("PDN connectivity request"));
        assert_eq!(emm_cause_name(7), Some("EPS services not allowed"));
        assert_eq!(esm_cause_name(27), Some("Missing or unknown APN"));
        assert_eq!(esm_cause_name(46), None);
        assert_eq!(security_header_type_name(13), security_header_type_name(12));
        assert_eq!(security_header_type_name(6), None);
    }
}
