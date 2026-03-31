//! 5G NAS message type lookup tables.
//!
//! ## References
//! - 3GPP TS 24.501, Section 8.2 — 5GS mobility management messages
//! - 3GPP TS 24.501, Section 8.3 — 5GS session management messages

/// Returns a human-readable name for a 5GMM message type.
///
/// 3GPP TS 24.501, Table 8.2.1.
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
        0x54 => "Service request",
        0x55 => "Service reject",
        0x56 => "Service accept",
        0x57 => "Control plane service request",
        0x58 => "Network slice-specific authentication command",
        0x59 => "Network slice-specific authentication complete",
        0x5a => "Network slice-specific authentication result",
        0x5c => "Configuration update command",
        0x5d => "Configuration update complete",
        0x5e => "Authentication request",
        0x5f => "Authentication response",
        0x60 => "Authentication reject",
        0x61 => "Authentication failure",
        0x62 => "Authentication result",
        0x64 => "Identity request",
        0x65 => "Identity response",
        0x66 => "Security mode command",
        0x67 => "Security mode complete",
        0x68 => "Security mode reject",
        0x6a => "5GMM status",
        0x6b => "Notification",
        0x6c => "Notification response",
        0x6d => "UL NAS transport",
        0x6e => "DL NAS transport",
        _ => "Unknown",
    }
}

/// Returns a human-readable name for a 5GSM message type.
///
/// 3GPP TS 24.501, Table 8.3.1.
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
    use super::*;

    #[test]
    fn known_mm_message_types() {
        assert_eq!(mm_message_type_name(0x41), "Registration request");
        assert_eq!(mm_message_type_name(0x5e), "Authentication request");
        assert_eq!(mm_message_type_name(0x66), "Security mode command");
        assert_eq!(mm_message_type_name(0x6d), "UL NAS transport");
    }

    #[test]
    fn unknown_mm_message_type() {
        assert_eq!(mm_message_type_name(0xFF), "Unknown");
    }

    #[test]
    fn known_sm_message_types() {
        assert_eq!(
            sm_message_type_name(0xc1),
            "PDU session establishment request"
        );
        assert_eq!(sm_message_type_name(0xd3), "PDU session release command");
    }

    #[test]
    fn unknown_sm_message_type() {
        assert_eq!(sm_message_type_name(0xFF), "Unknown");
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
