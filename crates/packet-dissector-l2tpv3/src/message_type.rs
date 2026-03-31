//! L2TPv3 control message type lookup.
//!
//! RFC 3931, Section 3.1: <https://www.rfc-editor.org/rfc/rfc3931#section-3.1>

/// Returns a human-readable name for an L2TPv3 control message type code.
///
/// Message types are defined in RFC 3931, Section 3.1 and Section 6.1.
pub(crate) fn message_type_name(code: u16) -> &'static str {
    match code {
        1 => "SCCRQ",
        2 => "SCCRP",
        3 => "SCCCN",
        4 => "StopCCN",
        6 => "HELLO",
        7 => "OCRQ",
        8 => "OCRP",
        9 => "OCCN",
        10 => "ICRQ",
        11 => "ICRP",
        12 => "ICCN",
        14 => "CDN",
        15 => "WEN",
        16 => "SLI",
        20 => "ACK",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_message_types() {
        assert_eq!(message_type_name(1), "SCCRQ");
        assert_eq!(message_type_name(2), "SCCRP");
        assert_eq!(message_type_name(3), "SCCCN");
        assert_eq!(message_type_name(4), "StopCCN");
        assert_eq!(message_type_name(6), "HELLO");
        assert_eq!(message_type_name(7), "OCRQ");
        assert_eq!(message_type_name(8), "OCRP");
        assert_eq!(message_type_name(9), "OCCN");
        assert_eq!(message_type_name(10), "ICRQ");
        assert_eq!(message_type_name(11), "ICRP");
        assert_eq!(message_type_name(12), "ICCN");
        assert_eq!(message_type_name(14), "CDN");
        assert_eq!(message_type_name(15), "WEN");
        assert_eq!(message_type_name(16), "SLI");
        assert_eq!(message_type_name(20), "ACK");
    }

    #[test]
    fn unknown_message_type() {
        assert_eq!(message_type_name(0), "Unknown");
        assert_eq!(message_type_name(5), "Unknown");
        assert_eq!(message_type_name(99), "Unknown");
    }
}
