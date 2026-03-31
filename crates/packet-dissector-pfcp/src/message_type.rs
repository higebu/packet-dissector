//! PFCP message type code-to-name mapping.
//!
//! 3GPP TS 29.244, Table 7.3-1.

/// Returns the human-readable name for a PFCP message type code.
///
/// 3GPP TS 29.244, Table 7.3-1.
pub fn message_type_name(code: u8) -> &'static str {
    match code {
        // PFCP Node related messages
        1 => "Heartbeat Request",
        2 => "Heartbeat Response",
        3 => "PFD Management Request",
        4 => "PFD Management Response",
        5 => "Association Setup Request",
        6 => "Association Setup Response",
        7 => "Association Update Request",
        8 => "Association Update Response",
        9 => "Association Release Request",
        10 => "Association Release Response",
        11 => "Version Not Supported Response",
        12 => "Node Report Request",
        13 => "Node Report Response",
        14 => "Session Set Deletion Request",
        15 => "Session Set Deletion Response",
        16 => "Session Set Modification Request",
        17 => "Session Set Modification Response",

        // PFCP Session related messages
        50 => "Session Establishment Request",
        51 => "Session Establishment Response",
        52 => "Session Modification Request",
        53 => "Session Modification Response",
        54 => "Session Deletion Request",
        55 => "Session Deletion Response",
        56 => "Session Report Request",
        57 => "Session Report Response",

        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_related_messages() {
        assert_eq!(message_type_name(1), "Heartbeat Request");
        assert_eq!(message_type_name(2), "Heartbeat Response");
        assert_eq!(message_type_name(3), "PFD Management Request");
        assert_eq!(message_type_name(4), "PFD Management Response");
        assert_eq!(message_type_name(5), "Association Setup Request");
        assert_eq!(message_type_name(6), "Association Setup Response");
        assert_eq!(message_type_name(7), "Association Update Request");
        assert_eq!(message_type_name(8), "Association Update Response");
        assert_eq!(message_type_name(9), "Association Release Request");
        assert_eq!(message_type_name(10), "Association Release Response");
        assert_eq!(message_type_name(11), "Version Not Supported Response");
        assert_eq!(message_type_name(12), "Node Report Request");
        assert_eq!(message_type_name(13), "Node Report Response");
        assert_eq!(message_type_name(14), "Session Set Deletion Request");
        assert_eq!(message_type_name(15), "Session Set Deletion Response");
        assert_eq!(message_type_name(16), "Session Set Modification Request");
        assert_eq!(message_type_name(17), "Session Set Modification Response");
    }

    #[test]
    fn session_related_messages() {
        assert_eq!(message_type_name(50), "Session Establishment Request");
        assert_eq!(message_type_name(51), "Session Establishment Response");
        assert_eq!(message_type_name(52), "Session Modification Request");
        assert_eq!(message_type_name(53), "Session Modification Response");
        assert_eq!(message_type_name(54), "Session Deletion Request");
        assert_eq!(message_type_name(55), "Session Deletion Response");
        assert_eq!(message_type_name(56), "Session Report Request");
        assert_eq!(message_type_name(57), "Session Report Response");
    }

    #[test]
    fn unknown_codes() {
        assert_eq!(message_type_name(0), "Unknown");
        assert_eq!(message_type_name(18), "Unknown");
        assert_eq!(message_type_name(49), "Unknown");
        assert_eq!(message_type_name(58), "Unknown");
        assert_eq!(message_type_name(100), "Unknown");
        assert_eq!(message_type_name(255), "Unknown");
    }
}
