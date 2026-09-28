//! GTPv2-C message type code-to-name mapping.
//!
//! ## References
//! - 3GPP TS 29.274, Section 6.1.0, Table 6.1-1 "Message types for GTPv2":
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.274/>

/// Returns the human-readable name for a GTPv2-C message type code.
///
/// Codes marked "Reserved" or "For future use" in the table return
/// `"Unknown"`.
///
/// 3GPP TS 29.274, Section 6.1.0, Table 6.1-1.
pub fn message_type_name(code: u8) -> &'static str {
    match code {
        // 0: Reserved
        1 => "Echo Request",
        2 => "Echo Response",
        3 => "Version Not Supported Indication",
        // 4 to 16: Reserved for S101 interface (TS 29.276)
        // 17 to 24: Reserved for S121 interface (TS 29.276)
        // 25 to 31: Reserved for Sv interface (TS 29.280)

        // SGSN/MME/TWAN/ePDG to PGW (S4/S11, S5/S8, S2a, S2b)
        32 => "Create Session Request",
        33 => "Create Session Response",
        36 => "Delete Session Request",
        37 => "Delete Session Response",
        // SGSN/MME/ePDG to PGW (S4/S11, S5/S8, S2b)
        34 => "Modify Bearer Request",
        35 => "Modify Bearer Response",
        // MME to PGW (S11, S5/S8)
        40 => "Remote UE Report Notification",
        41 => "Remote UE Report Acknowledge",
        // SGSN/MME to PGW (S4/S11, S5/S8)
        38 => "Change Notification Request",
        39 => "Change Notification Response",
        // 42 to 63: For future use

        // Messages without explicit response
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
        // 74 to 94: For future use

        // PGW to SGSN/MME/TWAN/ePDG (S5/S8, S4/S11, S2a, S2b)
        95 => "Create Bearer Request",
        96 => "Create Bearer Response",
        97 => "Update Bearer Request",
        98 => "Update Bearer Response",
        99 => "Delete Bearer Request",
        100 => "Delete Bearer Response",
        // PGW to MME, MME to PGW, SGW to PGW, SGW to MME, PGW to TWAN/ePDG,
        // TWAN/ePDG to PGW (S5/S8, S11, S2a, S2b)
        101 => "Delete PDN Connection Set Request",
        102 => "Delete PDN Connection Set Response",
        // PGW to SGSN/MME (S5, S4/S11)
        103 => "PGW Downlink Triggering Notification",
        104 => "PGW Downlink Triggering Acknowledge",
        // 105 to 127: For future use

        // MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN, MME to AMF,
        // AMF to MME (S3/S10/S16/N26)
        128 => "Identification Request",
        129 => "Identification Response",
        130 => "Context Request",
        131 => "Context Response",
        132 => "Context Acknowledge",
        133 => "Forward Relocation Request",
        134 => "Forward Relocation Response",
        135 => "Forward Relocation Complete Notification",
        136 => "Forward Relocation Complete Acknowledge",
        137 => "Forward Access Context Notification",
        138 => "Forward Access Context Acknowledge",
        139 => "Relocation Cancel Request",
        140 => "Relocation Cancel Response",
        141 => "Configuration Transfer Tunnel",
        // 142 to 148: For future use
        152 => "RAN Information Relay",

        // SGSN to MME, MME to SGSN (S3)
        149 => "Detach Notification",
        150 => "Detach Acknowledge",
        151 => "CS Paging Indication",
        153 => "Alert MME Notification",
        154 => "Alert MME Acknowledge",
        155 => "UE Activity Notification",
        156 => "UE Activity Acknowledge",
        157 => "ISR Status Indication",
        158 => "UE Registration Query Request",
        159 => "UE Registration Query Response",

        // SGSN/MME to SGW, SGSN to MME (S4/S11/S3),
        // SGSN to SGSN (S16), SGW to PGW (S5/S8)
        162 => "Suspend Notification",
        163 => "Suspend Acknowledge",
        164 => "Resume Notification",
        165 => "Resume Acknowledge",

        // SGSN/MME to SGW (S4/S11)
        160 => "Create Forwarding Tunnel Request",
        161 => "Create Forwarding Tunnel Response",
        166 => "Create Indirect Data Forwarding Tunnel Request",
        167 => "Create Indirect Data Forwarding Tunnel Response",
        168 => "Delete Indirect Data Forwarding Tunnel Request",
        169 => "Delete Indirect Data Forwarding Tunnel Response",
        170 => "Release Access Bearers Request",
        171 => "Release Access Bearers Response",
        // 172 to 175: For future use

        // SGW to SGSN/MME (S4/S11)
        176 => "Downlink Data Notification",
        177 => "Downlink Data Notification Acknowledge",
        179 => "PGW Restart Notification",
        180 => "PGW Restart Notification Acknowledge",
        // SGW to SGSN (S4)
        // 178: Reserved. Allocated in earlier version of the specification.
        // 181 to 199: For future use

        // SGW to PGW, PGW to SGW (S5/S8)
        200 => "Update PDN Connection Set Request",
        201 => "Update PDN Connection Set Response",
        // 202 to 210: For future use

        // MME to SGW (S11)
        211 => "Modify Access Bearers Request",
        212 => "Modify Access Bearers Response",
        // 213 to 230: For future use

        // MBMS GW to MME/SGSN (Sm/Sn)
        231 => "MBMS Session Start Request",
        232 => "MBMS Session Start Response",
        233 => "MBMS Session Update Request",
        234 => "MBMS Session Update Response",
        235 => "MBMS Session Stop Request",
        236 => "MBMS Session Stop Response",
        // 237 to 239: For future use
        // 240 to 247: Reserved for Sv interface (TS 29.280)
        // 248 to 255: For future use
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 29.274 (GTPv2-C) Message Type Coverage
    //!
    //! | Spec Section         | Description                              | Test                                  |
    //! |----------------------|------------------------------------------|---------------------------------------|
    //! | 6.1.0, Table 6.1-1   | Path management (1-3)                    | path_management_messages              |
    //! | 6.1.0, Table 6.1-1   | SGSN/MME/TWAN/ePDG to PGW (32-41)        | tunnel_management_to_pgw              |
    //! | 6.1.0, Table 6.1-1   | Messages without explicit response       | messages_without_explicit_response    |
    //! | 6.1.0, Table 6.1-1   | PGW to SGSN/MME/TWAN/ePDG (95-104)       | pgw_initiated_messages                |
    //! | 6.1.0, Table 6.1-1   | S3/S10/S16/N26 (128-141, 152)            | mobility_management_messages          |
    //! | 6.1.0, Table 6.1-1   | SGSN to MME, MME to SGSN (S3)            | s3_messages                           |
    //! | 6.1.0, Table 6.1-1   | Suspend / Resume                         | suspend_resume_messages               |
    //! | 6.1.0, Table 6.1-1   | SGSN/MME to SGW (S4/S11)                 | sgsn_mme_to_sgw_messages              |
    //! | 6.1.0, Table 6.1-1   | SGW to SGSN/MME (S4/S11)                 | sgw_to_sgsn_mme_messages              |
    //! | 6.1.0, Table 6.1-1   | SGW to PGW, PGW to SGW (S5/S8)           | update_pdn_connection_set_messages    |
    //! | 6.1.0, Table 6.1-1   | MME to SGW (S11)                         | modify_access_bearers_messages        |
    //! | 6.1.0, Table 6.1-1   | MBMS GW to MME/SGSN (Sm/Sn)              | mbms_messages                         |
    //! | 6.1.0, Table 6.1-1   | Reserved / for future use                | unknown_codes                         |
    //! | 6.1.0, Table 6.1-1   | Full table, all 256 codes                | full_table_matches_spec               |

    use super::*;

    /// Every assigned message type in 3GPP TS 29.274 v19.6.0, Table 6.1-1.
    /// Codes not listed here are "Reserved" or "For future use".
    const SPEC_TABLE: &[(u8, &str)] = &[
        (1, "Echo Request"),
        (2, "Echo Response"),
        (3, "Version Not Supported Indication"),
        (32, "Create Session Request"),
        (33, "Create Session Response"),
        (34, "Modify Bearer Request"),
        (35, "Modify Bearer Response"),
        (36, "Delete Session Request"),
        (37, "Delete Session Response"),
        (38, "Change Notification Request"),
        (39, "Change Notification Response"),
        (40, "Remote UE Report Notification"),
        (41, "Remote UE Report Acknowledge"),
        (64, "Modify Bearer Command"),
        (65, "Modify Bearer Failure Indication"),
        (66, "Delete Bearer Command"),
        (67, "Delete Bearer Failure Indication"),
        (68, "Bearer Resource Command"),
        (69, "Bearer Resource Failure Indication"),
        (70, "Downlink Data Notification Failure Indication"),
        (71, "Trace Session Activation"),
        (72, "Trace Session Deactivation"),
        (73, "Stop Paging Indication"),
        (95, "Create Bearer Request"),
        (96, "Create Bearer Response"),
        (97, "Update Bearer Request"),
        (98, "Update Bearer Response"),
        (99, "Delete Bearer Request"),
        (100, "Delete Bearer Response"),
        (101, "Delete PDN Connection Set Request"),
        (102, "Delete PDN Connection Set Response"),
        (103, "PGW Downlink Triggering Notification"),
        (104, "PGW Downlink Triggering Acknowledge"),
        (128, "Identification Request"),
        (129, "Identification Response"),
        (130, "Context Request"),
        (131, "Context Response"),
        (132, "Context Acknowledge"),
        (133, "Forward Relocation Request"),
        (134, "Forward Relocation Response"),
        (135, "Forward Relocation Complete Notification"),
        (136, "Forward Relocation Complete Acknowledge"),
        (137, "Forward Access Context Notification"),
        (138, "Forward Access Context Acknowledge"),
        (139, "Relocation Cancel Request"),
        (140, "Relocation Cancel Response"),
        (141, "Configuration Transfer Tunnel"),
        (149, "Detach Notification"),
        (150, "Detach Acknowledge"),
        (151, "CS Paging Indication"),
        (152, "RAN Information Relay"),
        (153, "Alert MME Notification"),
        (154, "Alert MME Acknowledge"),
        (155, "UE Activity Notification"),
        (156, "UE Activity Acknowledge"),
        (157, "ISR Status Indication"),
        (158, "UE Registration Query Request"),
        (159, "UE Registration Query Response"),
        (160, "Create Forwarding Tunnel Request"),
        (161, "Create Forwarding Tunnel Response"),
        (162, "Suspend Notification"),
        (163, "Suspend Acknowledge"),
        (164, "Resume Notification"),
        (165, "Resume Acknowledge"),
        (166, "Create Indirect Data Forwarding Tunnel Request"),
        (167, "Create Indirect Data Forwarding Tunnel Response"),
        (168, "Delete Indirect Data Forwarding Tunnel Request"),
        (169, "Delete Indirect Data Forwarding Tunnel Response"),
        (170, "Release Access Bearers Request"),
        (171, "Release Access Bearers Response"),
        (176, "Downlink Data Notification"),
        (177, "Downlink Data Notification Acknowledge"),
        (179, "PGW Restart Notification"),
        (180, "PGW Restart Notification Acknowledge"),
        (200, "Update PDN Connection Set Request"),
        (201, "Update PDN Connection Set Response"),
        (211, "Modify Access Bearers Request"),
        (212, "Modify Access Bearers Response"),
        (231, "MBMS Session Start Request"),
        (232, "MBMS Session Start Response"),
        (233, "MBMS Session Update Request"),
        (234, "MBMS Session Update Response"),
        (235, "MBMS Session Stop Request"),
        (236, "MBMS Session Stop Response"),
    ];

    fn assert_codes(codes: core::ops::RangeInclusive<u8>) {
        for code in codes {
            let expected = SPEC_TABLE
                .iter()
                .find(|(c, _)| *c == code)
                .map_or("Unknown", |(_, name)| *name);
            assert_eq!(message_type_name(code), expected, "message type {code}");
        }
    }

    #[test]
    fn path_management_messages() {
        assert_eq!(message_type_name(1), "Echo Request");
        assert_eq!(message_type_name(2), "Echo Response");
        assert_eq!(message_type_name(3), "Version Not Supported Indication");
    }

    #[test]
    fn tunnel_management_to_pgw() {
        assert_eq!(message_type_name(32), "Create Session Request");
        assert_eq!(message_type_name(37), "Delete Session Response");
        assert_eq!(message_type_name(38), "Change Notification Request");
        assert_eq!(message_type_name(41), "Remote UE Report Acknowledge");
        assert_codes(32..=41);
    }

    #[test]
    fn messages_without_explicit_response() {
        assert_eq!(message_type_name(64), "Modify Bearer Command");
        assert_eq!(message_type_name(73), "Stop Paging Indication");
        assert_codes(64..=73);
    }

    #[test]
    fn pgw_initiated_messages() {
        assert_eq!(message_type_name(95), "Create Bearer Request");
        assert_eq!(message_type_name(100), "Delete Bearer Response");
        assert_eq!(message_type_name(101), "Delete PDN Connection Set Request");
        assert_eq!(message_type_name(102), "Delete PDN Connection Set Response");
        assert_eq!(
            message_type_name(103),
            "PGW Downlink Triggering Notification"
        );
        assert_eq!(
            message_type_name(104),
            "PGW Downlink Triggering Acknowledge"
        );
        assert_codes(95..=104);
    }

    #[test]
    fn mobility_management_messages() {
        assert_eq!(message_type_name(128), "Identification Request");
        assert_eq!(message_type_name(130), "Context Request");
        assert_eq!(message_type_name(133), "Forward Relocation Request");
        assert_eq!(message_type_name(139), "Relocation Cancel Request");
        assert_eq!(message_type_name(140), "Relocation Cancel Response");
        assert_eq!(message_type_name(141), "Configuration Transfer Tunnel");
        assert_eq!(message_type_name(152), "RAN Information Relay");
        assert_codes(128..=141);
    }

    #[test]
    fn s3_messages() {
        assert_eq!(message_type_name(149), "Detach Notification");
        assert_eq!(message_type_name(151), "CS Paging Indication");
        assert_eq!(message_type_name(159), "UE Registration Query Response");
        assert_codes(149..=159);
    }

    #[test]
    fn suspend_resume_messages() {
        assert_eq!(message_type_name(162), "Suspend Notification");
        assert_eq!(message_type_name(163), "Suspend Acknowledge");
        assert_eq!(message_type_name(164), "Resume Notification");
        assert_eq!(message_type_name(165), "Resume Acknowledge");
    }

    #[test]
    fn sgsn_mme_to_sgw_messages() {
        assert_eq!(message_type_name(160), "Create Forwarding Tunnel Request");
        assert_eq!(message_type_name(161), "Create Forwarding Tunnel Response");
        assert_eq!(
            message_type_name(166),
            "Create Indirect Data Forwarding Tunnel Request"
        );
        assert_eq!(
            message_type_name(169),
            "Delete Indirect Data Forwarding Tunnel Response"
        );
        assert_eq!(message_type_name(170), "Release Access Bearers Request");
        assert_eq!(message_type_name(171), "Release Access Bearers Response");
        assert_codes(160..=175);
    }

    #[test]
    fn sgw_to_sgsn_mme_messages() {
        assert_eq!(message_type_name(176), "Downlink Data Notification");
        assert_eq!(
            message_type_name(177),
            "Downlink Data Notification Acknowledge"
        );
        // 178: "Reserved. Allocated in earlier version of the specification."
        assert_eq!(message_type_name(178), "Unknown");
        assert_eq!(message_type_name(179), "PGW Restart Notification");
        assert_eq!(
            message_type_name(180),
            "PGW Restart Notification Acknowledge"
        );
        assert_codes(176..=180);
    }

    #[test]
    fn update_pdn_connection_set_messages() {
        assert_eq!(message_type_name(200), "Update PDN Connection Set Request");
        assert_eq!(message_type_name(201), "Update PDN Connection Set Response");
    }

    #[test]
    fn modify_access_bearers_messages() {
        assert_eq!(message_type_name(211), "Modify Access Bearers Request");
        assert_eq!(message_type_name(212), "Modify Access Bearers Response");
    }

    #[test]
    fn mbms_messages() {
        assert_eq!(message_type_name(231), "MBMS Session Start Request");
        assert_eq!(message_type_name(232), "MBMS Session Start Response");
        assert_eq!(message_type_name(233), "MBMS Session Update Request");
        assert_eq!(message_type_name(234), "MBMS Session Update Response");
        assert_eq!(message_type_name(235), "MBMS Session Stop Request");
        assert_eq!(message_type_name(236), "MBMS Session Stop Response");
        assert_codes(231..=239);
    }

    #[test]
    fn unknown_codes() {
        // Reserved (0), reserved for S101/S121/Sv (4-31, 240-247) and
        // "For future use" ranges.
        for code in [0, 4, 16, 17, 24, 25, 31, 42, 63, 74, 94, 105, 127] {
            assert_eq!(message_type_name(code), "Unknown", "message type {code}");
        }
        for code in [142, 148, 172, 175, 181, 190, 199, 202, 210, 213, 230] {
            assert_eq!(message_type_name(code), "Unknown", "message type {code}");
        }
        for code in [237, 239, 240, 247, 248, 255] {
            assert_eq!(message_type_name(code), "Unknown", "message type {code}");
        }
    }

    #[test]
    fn full_table_matches_spec() {
        assert_codes(0..=255);
    }
}
