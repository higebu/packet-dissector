//! 5G NAS message type lookup tables.
//!
//! ## References
//! - 3GPP TS 24.501, Section 9.7, Table 9.7.1 — Message types for 5GS
//!   mobility management:
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>
//! - 3GPP TS 24.501, Section 9.7, Table 9.7.2 — Message types for 5GS
//!   session management

/// Returns a human-readable name for a 5GMM message type.
///
/// 3GPP TS 24.501, Section 9.7, Table 9.7.1.
pub fn mm_message_type_name(mt: u8) -> &'static str {
    match mt {
        0x41 => "Registration request",
        0x42 => "Registration accept",
        0x43 => "Registration complete",
        0x44 => "Registration reject",
        0x45 => "Deregistration request (UE originating)",
        0x46 => "Deregistration accept (UE originating)",
        0x47 => "Deregistration request (UE terminated)",
        0x48 => "Deregistration accept (UE terminated)",

        0x4c => "Service request",
        0x4d => "Service reject",
        0x4e => "Service accept",
        0x4f => "Control plane service request",

        0x50 => "Network slice-specific authentication command",
        0x51 => "Network slice-specific authentication complete",
        0x52 => "Network slice-specific authentication result",
        0x54 => "Configuration update command",
        0x55 => "Configuration update complete",
        0x56 => "Authentication request",
        0x57 => "Authentication response",
        0x58 => "Authentication reject",
        0x59 => "Authentication failure",
        0x5a => "Authentication result",
        0x5b => "Identity request",
        0x5c => "Identity response",
        0x5d => "Security mode command",
        0x5e => "Security mode complete",
        0x5f => "Security mode reject",

        0x64 => "5GMM status",
        0x65 => "Notification",
        0x66 => "Notification response",
        0x67 => "UL NAS transport",
        0x68 => "DL NAS transport",

        0x69 => "Relay key request",
        0x6a => "Relay key accept",
        0x6b => "Relay key reject",
        0x6c => "Relay authentication request",
        0x6d => "Relay authentication response",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a 5GSM message type.
///
/// 3GPP TS 24.501, Section 9.7, Table 9.7.2.
pub fn sm_message_type_name(mt: u8) -> &'static str {
    match mt {
        0xc1 => "PDU session establishment request",
        0xc2 => "PDU session establishment accept",
        0xc3 => "PDU session establishment reject",

        0xc5 => "PDU session authentication command",
        0xc6 => "PDU session authentication complete",
        0xc7 => "PDU session authentication result",

        0xc9 => "PDU session modification request",
        0xca => "PDU session modification reject",
        0xcb => "PDU session modification command",
        0xcc => "PDU session modification complete",
        0xcd => "PDU session modification command reject",

        0xd1 => "PDU session release request",
        0xd2 => "PDU session release reject",
        0xd3 => "PDU session release command",
        0xd4 => "PDU session release complete",

        0xd6 => "5GSM status",

        0xd8 => "Service-level authentication command",
        0xd9 => "Service-level authentication complete",

        0xda => "Remote UE report",
        0xdb => "Remote UE report response",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the extended protocol discriminator.
///
/// 3GPP TS 24.007, Table 11.2.
pub fn epd_name(epd: u8) -> &'static str {
    match epd {
        0x2e => "5GS session management",
        0x7e => "5GS mobility management",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for the security header type.
///
/// 3GPP TS 24.501, Section 9.3.
pub fn security_header_type_name(sht: u8) -> &'static str {
    match sht {
        0 => "Plain 5GS NAS message, not security protected",
        1 => "Integrity protected",
        2 => "Integrity protected and ciphered",
        3 => "Integrity protected with new 5G NAS security context",
        4 => "Integrity protected and ciphered with new 5G NAS security context",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 24.501 Message Type Coverage
    //!
    //! | Spec Section          | Description                     | Test                          |
    //! |-----------------------|---------------------------------|-------------------------------|
    //! | 9.7, Table 9.7.1      | 5GMM message types              | known_mm_message_types        |
    //! | 9.7, Table 9.7.1      | 5GMM full table (all 256 codes) | mm_full_table_matches_spec    |
    //! | 9.7, Table 9.7.1      | Unassigned 5GMM codes           | unknown_mm_message_type       |
    //! | 9.7, Table 9.7.2      | 5GSM message types              | known_sm_message_types        |
    //! | 9.7, Table 9.7.2      | 5GSM full table (all 256 codes) | sm_full_table_matches_spec    |
    //! | 9.7, Table 9.7.2      | Unassigned 5GSM codes           | unknown_sm_message_type       |
    //! | TS 24.007 11.2.3.1.1A | Extended protocol discriminator | known_epd_names               |
    //! | 9.3, Table 9.3.1      | Security header type            | known_security_header_types   |

    use super::*;

    /// 3GPP TS 24.501 v19.8.0, Table 9.7.1: Message types for 5GS mobility
    /// management.
    const MM_SPEC_TABLE: &[(u8, &str)] = &[
        (0x41, "Registration request"),
        (0x42, "Registration accept"),
        (0x43, "Registration complete"),
        (0x44, "Registration reject"),
        (0x45, "Deregistration request (UE originating)"),
        (0x46, "Deregistration accept (UE originating)"),
        (0x47, "Deregistration request (UE terminated)"),
        (0x48, "Deregistration accept (UE terminated)"),
        (0x4c, "Service request"),
        (0x4d, "Service reject"),
        (0x4e, "Service accept"),
        (0x4f, "Control plane service request"),
        (0x50, "Network slice-specific authentication command"),
        (0x51, "Network slice-specific authentication complete"),
        (0x52, "Network slice-specific authentication result"),
        (0x54, "Configuration update command"),
        (0x55, "Configuration update complete"),
        (0x56, "Authentication request"),
        (0x57, "Authentication response"),
        (0x58, "Authentication reject"),
        (0x59, "Authentication failure"),
        (0x5a, "Authentication result"),
        (0x5b, "Identity request"),
        (0x5c, "Identity response"),
        (0x5d, "Security mode command"),
        (0x5e, "Security mode complete"),
        (0x5f, "Security mode reject"),
        (0x64, "5GMM status"),
        (0x65, "Notification"),
        (0x66, "Notification response"),
        (0x67, "UL NAS transport"),
        (0x68, "DL NAS transport"),
        (0x69, "Relay key request"),
        (0x6a, "Relay key accept"),
        (0x6b, "Relay key reject"),
        (0x6c, "Relay authentication request"),
        (0x6d, "Relay authentication response"),
    ];

    /// 3GPP TS 24.501 v19.8.0, Table 9.7.2: Message types for 5GS session
    /// management.
    const SM_SPEC_TABLE: &[(u8, &str)] = &[
        (0xc1, "PDU session establishment request"),
        (0xc2, "PDU session establishment accept"),
        (0xc3, "PDU session establishment reject"),
        (0xc5, "PDU session authentication command"),
        (0xc6, "PDU session authentication complete"),
        (0xc7, "PDU session authentication result"),
        (0xc9, "PDU session modification request"),
        (0xca, "PDU session modification reject"),
        (0xcb, "PDU session modification command"),
        (0xcc, "PDU session modification complete"),
        (0xcd, "PDU session modification command reject"),
        (0xd1, "PDU session release request"),
        (0xd2, "PDU session release reject"),
        (0xd3, "PDU session release command"),
        (0xd4, "PDU session release complete"),
        (0xd6, "5GSM status"),
        (0xd8, "Service-level authentication command"),
        (0xd9, "Service-level authentication complete"),
        (0xda, "Remote UE report"),
        (0xdb, "Remote UE report response"),
    ];

    fn assert_table(lookup: fn(u8) -> &'static str, table: &[(u8, &str)]) {
        for code in 0..=u8::MAX {
            let expected = table
                .iter()
                .find(|(c, _)| *c == code)
                .map_or("Unknown", |(_, name)| *name);
            assert_eq!(lookup(code), expected, "message type {code:#04x}");
        }
    }

    #[test]
    fn known_mm_message_types() {
        assert_eq!(mm_message_type_name(0x41), "Registration request");
        assert_eq!(mm_message_type_name(0x4c), "Service request");
        assert_eq!(mm_message_type_name(0x56), "Authentication request");
        assert_eq!(mm_message_type_name(0x5d), "Security mode command");
        assert_eq!(mm_message_type_name(0x5e), "Security mode complete");
        assert_eq!(mm_message_type_name(0x67), "UL NAS transport");
        assert_eq!(mm_message_type_name(0x68), "DL NAS transport");
        assert_eq!(mm_message_type_name(0x6d), "Relay authentication response");
    }

    #[test]
    fn mm_full_table_matches_spec() {
        assert_table(mm_message_type_name, MM_SPEC_TABLE);
    }

    #[test]
    fn unknown_mm_message_type() {
        for code in [
            0x00, 0x40, 0x49, 0x4b, 0x53, 0x60, 0x62, 0x63, 0x6e, 0xc1, 0xff,
        ] {
            assert_eq!(mm_message_type_name(code), "Unknown", "{code:#04x}");
        }
    }

    #[test]
    fn known_sm_message_types() {
        assert_eq!(
            sm_message_type_name(0xc1),
            "PDU session establishment request"
        );
        assert_eq!(sm_message_type_name(0xd3), "PDU session release command");
        assert_eq!(
            sm_message_type_name(0xd8),
            "Service-level authentication command"
        );
        assert_eq!(sm_message_type_name(0xdb), "Remote UE report response");
    }

    #[test]
    fn sm_full_table_matches_spec() {
        assert_table(sm_message_type_name, SM_SPEC_TABLE);
    }

    #[test]
    fn unknown_sm_message_type() {
        for code in [0x00, 0x41, 0xc0, 0xc4, 0xd5, 0xd7, 0xdc, 0xff] {
            assert_eq!(sm_message_type_name(code), "Unknown", "{code:#04x}");
        }
    }

    #[test]
    fn known_epd_names() {
        assert_eq!(epd_name(0x7e), "5GS mobility management");
        assert_eq!(epd_name(0x2e), "5GS session management");
        assert_eq!(epd_name(0x00), "Unknown");
    }

    #[test]
    fn known_security_header_types() {
        assert_eq!(
            security_header_type_name(0),
            "Plain 5GS NAS message, not security protected"
        );
        assert_eq!(
            security_header_type_name(2),
            "Integrity protected and ciphered"
        );
    }
}
