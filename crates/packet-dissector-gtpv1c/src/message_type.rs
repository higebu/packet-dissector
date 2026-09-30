//! GTPv1 message type names.
//!
//! ## References
//! - 3GPP TS 29.060, Section 7.1, Table 1:
//!   <https://www.3gpp.org/ftp/Specs/archive/29_series/29.060/>

/// Returns the name of a GTPv1 message type.
///
/// 3GPP TS 29.060, Section 7.1, Table 1 — "Messages in GTP". GTP' and
/// GTP-U-only types are included so that a misrouted message is still
/// labelled; unassigned values return `None`.
pub fn message_type_name(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "Echo Request",
        2 => "Echo Response",
        3 => "Version Not Supported",
        4 => "Node Alive Request",
        5 => "Node Alive Response",
        6 => "Redirection Request",
        7 => "Redirection Response",
        16 => "Create PDP Context Request",
        17 => "Create PDP Context Response",
        18 => "Update PDP Context Request",
        19 => "Update PDP Context Response",
        20 => "Delete PDP Context Request",
        21 => "Delete PDP Context Response",
        22 => "Initiate PDP Context Activation Request",
        23 => "Initiate PDP Context Activation Response",
        26 => "Error Indication",
        27 => "PDU Notification Request",
        28 => "PDU Notification Response",
        29 => "PDU Notification Reject Request",
        30 => "PDU Notification Reject Response",
        31 => "Supported Extension Headers Notification",
        32 => "Send Routeing Information for GPRS Request",
        33 => "Send Routeing Information for GPRS Response",
        34 => "Failure Report Request",
        35 => "Failure Report Response",
        36 => "Note MS GPRS Present Request",
        37 => "Note MS GPRS Present Response",
        48 => "Identification Request",
        49 => "Identification Response",
        50 => "SGSN Context Request",
        51 => "SGSN Context Response",
        52 => "SGSN Context Acknowledge",
        53 => "Forward Relocation Request",
        54 => "Forward Relocation Response",
        55 => "Forward Relocation Complete",
        56 => "Relocation Cancel Request",
        57 => "Relocation Cancel Response",
        58 => "Forward SRNS Context",
        59 => "Forward Relocation Complete Acknowledge",
        60 => "Forward SRNS Context Acknowledge",
        61 => "UE Registration Query Request",
        62 => "UE Registration Query Response",
        70 => "RAN Information Relay",
        96 => "MBMS Notification Request",
        97 => "MBMS Notification Response",
        98 => "MBMS Notification Reject Request",
        99 => "MBMS Notification Reject Response",
        100 => "Create MBMS Context Request",
        101 => "Create MBMS Context Response",
        102 => "Update MBMS Context Request",
        103 => "Update MBMS Context Response",
        104 => "Delete MBMS Context Request",
        105 => "Delete MBMS Context Response",
        112 => "MBMS Registration Request",
        113 => "MBMS Registration Response",
        114 => "MBMS De-Registration Request",
        115 => "MBMS De-Registration Response",
        116 => "MBMS Session Start Request",
        117 => "MBMS Session Start Response",
        118 => "MBMS Session Stop Request",
        119 => "MBMS Session Stop Response",
        120 => "MBMS Session Update Request",
        121 => "MBMS Session Update Response",
        128 => "MS Info Change Notification Request",
        129 => "MS Info Change Notification Response",
        240 => "Data Record Transfer Request",
        241 => "Data Record Transfer Response",
        253 => "Tunnel Status",
        254 => "End Marker",
        255 => "G-PDU",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_message_types() {
        assert_eq!(message_type_name(1), Some("Echo Request"));
        assert_eq!(message_type_name(16), Some("Create PDP Context Request"));
        assert_eq!(message_type_name(21), Some("Delete PDP Context Response"));
        assert_eq!(message_type_name(70), Some("RAN Information Relay"));
        assert_eq!(message_type_name(121), Some("MBMS Session Update Response"));
        assert_eq!(
            message_type_name(129),
            Some("MS Info Change Notification Response")
        );
        assert_eq!(message_type_name(255), Some("G-PDU"));
    }

    #[test]
    fn message_type_table_size() {
        // TS 29.060, Table 1: every assigned value, including the GTP' and
        // GTP-U only types.
        let assigned = (0..=255u8)
            .filter(|t| message_type_name(*t).is_some())
            .count();
        assert_eq!(assigned, 70);
    }

    #[test]
    fn unassigned_message_types() {
        for v in [
            0u8, 8, 15, 24, 25, 38, 47, 63, 69, 71, 95, 106, 111, 122, 130, 239, 242, 252,
        ] {
            assert_eq!(message_type_name(v), None, "type {v}");
        }
    }
}
