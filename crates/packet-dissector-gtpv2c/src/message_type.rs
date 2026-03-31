//! GTPv2-C message type code-to-name mapping.
//!
//! 3GPP TS 29.274, Table 6.1-1.

/// Returns the human-readable name for a GTPv2-C message type code.
///
/// 3GPP TS 29.274, Table 6.1-1.
pub fn message_type_name(code: u8) -> &'static str {
    match code {
        // Path Management Messages
        1 => "Echo Request",
        2 => "Echo Response",
        3 => "Version Not Supported Indication",

        // Tunnel Management Messages (S4/S11/S5/S8/S2a/S2b)
        32 => "Create Session Request",
        33 => "Create Session Response",
        34 => "Modify Bearer Request",
        35 => "Modify Bearer Response",
        36 => "Delete Session Request",
        37 => "Delete Session Response",
        38 => "Change Notification Request",
        39 => "Change Notification Response",
        40 => "Remote UE Report Notification",
        41 => "Remote UE Report Acknowledge",

        // Tunnel Management Messages (S4/S11 only)
        64 => "Modify Bearer Command",
        65 => "Modify Bearer Failure Indication",
        66 => "Delete Bearer Command",
        67 => "Delete Bearer Failure Indication",
        68 => "Bearer Resource Command",
        69 => "Bearer Resource Failure Indication",
        70 => "Downlink Data Notification Failure Indication",
        71 => "Trace Session Activation",
        72 => "Trace Session Deactivation",
        73 => "Stop Paging Indication",

        // Tunnel Management Messages (S5/S8)
        95 => "Create Bearer Request",
        96 => "Create Bearer Response",
        97 => "Update Bearer Request",
        98 => "Update Bearer Response",
        99 => "Delete Bearer Request",
        100 => "Delete Bearer Response",

        // Mobility Management Messages (S3/S10/S16)
        160 => "Relocation Cancel Request",
        161 => "Relocation Cancel Response",
        162 => "Delete PDN Connection Set Request",
        163 => "Delete PDN Connection Set Response",
        164 => "PGW Downlink Triggering Notification",
        165 => "PGW Downlink Triggering Acknowledge",
        166 => "Update PDN Connection Set Request",
        167 => "Update PDN Connection Set Response",
        170 => "Identification Request",
        171 => "Identification Response",
        172 => "Context Request",
        173 => "Context Response",
        174 => "Context Acknowledge",
        175 => "Forward Relocation Request",
        176 => "Forward Relocation Response",
        177 => "Forward Relocation Complete Notification",
        178 => "Forward Relocation Complete Acknowledge",
        179 => "Forward Access Context Notification",
        180 => "Forward Access Context Acknowledge",

        // CS Fallback Messages
        190 => "Configuration Transfer Tunnel",

        // Paging Messages
        200 => "Suspend Notification",
        201 => "Suspend Acknowledge",
        202 => "Resume Notification",
        203 => "Resume Acknowledge",

        // NAS Messages (S11/S4)
        211 => "Create Indirect Data Forwarding Tunnel Request",
        212 => "Create Indirect Data Forwarding Tunnel Response",
        213 => "Delete Indirect Data Forwarding Tunnel Request",
        214 => "Delete Indirect Data Forwarding Tunnel Response",
        215 => "Release Access Bearers Request",
        216 => "Release Access Bearers Response",

        // Downlink Data Notification Messages
        230 => "Downlink Data Notification",
        231 => "Downlink Data Notification Acknowledge",

        // MBMS Messages
        233 => "MBMS Session Start Request",
        234 => "MBMS Session Start Response",
        235 => "MBMS Session Update Request",
        236 => "MBMS Session Update Response",
        237 => "MBMS Session Stop Request",
        238 => "MBMS Session Stop Response",

        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_management_messages() {
        assert_eq!(message_type_name(1), "Echo Request");
        assert_eq!(message_type_name(2), "Echo Response");
        assert_eq!(message_type_name(3), "Version Not Supported Indication");
    }

    #[test]
    fn tunnel_management_s4_s11_s5_s8() {
        assert_eq!(message_type_name(32), "Create Session Request");
        assert_eq!(message_type_name(33), "Create Session Response");
        assert_eq!(message_type_name(34), "Modify Bearer Request");
        assert_eq!(message_type_name(35), "Modify Bearer Response");
        assert_eq!(message_type_name(36), "Delete Session Request");
        assert_eq!(message_type_name(37), "Delete Session Response");
        assert_eq!(message_type_name(38), "Change Notification Request");
        assert_eq!(message_type_name(39), "Change Notification Response");
        assert_eq!(message_type_name(40), "Remote UE Report Notification");
        assert_eq!(message_type_name(41), "Remote UE Report Acknowledge");
    }

    #[test]
    fn tunnel_management_s4_s11_only() {
        assert_eq!(message_type_name(64), "Modify Bearer Command");
        assert_eq!(message_type_name(65), "Modify Bearer Failure Indication");
        assert_eq!(message_type_name(66), "Delete Bearer Command");
        assert_eq!(message_type_name(67), "Delete Bearer Failure Indication");
        assert_eq!(message_type_name(68), "Bearer Resource Command");
        assert_eq!(message_type_name(69), "Bearer Resource Failure Indication");
        assert_eq!(
            message_type_name(70),
            "Downlink Data Notification Failure Indication"
        );
        assert_eq!(message_type_name(71), "Trace Session Activation");
        assert_eq!(message_type_name(72), "Trace Session Deactivation");
        assert_eq!(message_type_name(73), "Stop Paging Indication");
    }

    #[test]
    fn tunnel_management_s5_s8() {
        assert_eq!(message_type_name(95), "Create Bearer Request");
        assert_eq!(message_type_name(96), "Create Bearer Response");
        assert_eq!(message_type_name(97), "Update Bearer Request");
        assert_eq!(message_type_name(98), "Update Bearer Response");
        assert_eq!(message_type_name(99), "Delete Bearer Request");
        assert_eq!(message_type_name(100), "Delete Bearer Response");
    }

    #[test]
    fn mobility_management_messages() {
        assert_eq!(message_type_name(160), "Relocation Cancel Request");
        assert_eq!(message_type_name(161), "Relocation Cancel Response");
        assert_eq!(message_type_name(162), "Delete PDN Connection Set Request");
        assert_eq!(message_type_name(163), "Delete PDN Connection Set Response");
        assert_eq!(
            message_type_name(164),
            "PGW Downlink Triggering Notification"
        );
        assert_eq!(
            message_type_name(165),
            "PGW Downlink Triggering Acknowledge"
        );
        assert_eq!(message_type_name(166), "Update PDN Connection Set Request");
        assert_eq!(message_type_name(167), "Update PDN Connection Set Response");
        assert_eq!(message_type_name(170), "Identification Request");
        assert_eq!(message_type_name(171), "Identification Response");
        assert_eq!(message_type_name(172), "Context Request");
        assert_eq!(message_type_name(173), "Context Response");
        assert_eq!(message_type_name(174), "Context Acknowledge");
        assert_eq!(message_type_name(175), "Forward Relocation Request");
        assert_eq!(message_type_name(176), "Forward Relocation Response");
        assert_eq!(
            message_type_name(177),
            "Forward Relocation Complete Notification"
        );
        assert_eq!(
            message_type_name(178),
            "Forward Relocation Complete Acknowledge"
        );
        assert_eq!(
            message_type_name(179),
            "Forward Access Context Notification"
        );
        assert_eq!(message_type_name(180), "Forward Access Context Acknowledge");
    }

    #[test]
    fn cs_fallback_messages() {
        assert_eq!(message_type_name(190), "Configuration Transfer Tunnel");
    }

    #[test]
    fn paging_messages() {
        assert_eq!(message_type_name(200), "Suspend Notification");
        assert_eq!(message_type_name(201), "Suspend Acknowledge");
        assert_eq!(message_type_name(202), "Resume Notification");
        assert_eq!(message_type_name(203), "Resume Acknowledge");
    }

    #[test]
    fn nas_messages() {
        assert_eq!(
            message_type_name(211),
            "Create Indirect Data Forwarding Tunnel Request"
        );
        assert_eq!(
            message_type_name(212),
            "Create Indirect Data Forwarding Tunnel Response"
        );
        assert_eq!(
            message_type_name(213),
            "Delete Indirect Data Forwarding Tunnel Request"
        );
        assert_eq!(
            message_type_name(214),
            "Delete Indirect Data Forwarding Tunnel Response"
        );
        assert_eq!(message_type_name(215), "Release Access Bearers Request");
        assert_eq!(message_type_name(216), "Release Access Bearers Response");
    }

    #[test]
    fn downlink_data_notification_messages() {
        assert_eq!(message_type_name(230), "Downlink Data Notification");
        assert_eq!(
            message_type_name(231),
            "Downlink Data Notification Acknowledge"
        );
    }

    #[test]
    fn mbms_messages() {
        assert_eq!(message_type_name(233), "MBMS Session Start Request");
        assert_eq!(message_type_name(234), "MBMS Session Start Response");
        assert_eq!(message_type_name(235), "MBMS Session Update Request");
        assert_eq!(message_type_name(236), "MBMS Session Update Response");
        assert_eq!(message_type_name(237), "MBMS Session Stop Request");
        assert_eq!(message_type_name(238), "MBMS Session Stop Response");
    }

    #[test]
    fn unknown_codes() {
        assert_eq!(message_type_name(0), "Unknown");
        assert_eq!(message_type_name(50), "Unknown");
        assert_eq!(message_type_name(255), "Unknown");
    }
}
