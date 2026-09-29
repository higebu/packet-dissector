//! L2TPv3 control message type lookup.
//!
//! RFC 3931, Section 3.1: <https://www.rfc-editor.org/rfc/rfc3931#section-3.1>

/// Returns a human-readable name for an L2TPv3 control message type code.
///
/// Message types are defined in RFC 3931, Section 3.1 and Section 6.1;
/// later values follow the IANA "Message Type AVP (Attribute Type 0)
/// Values" registry (17 RFC 3573, 18-19 RFC 3817, 21-22 RFC 4951,
/// 23-27 RFC 4045, 28-29 RFC 5515).
/// <https://www.rfc-editor.org/rfc/rfc3931#section-3.1>
/// <https://www.rfc-editor.org/rfc/rfc3573>
/// <https://www.rfc-editor.org/rfc/rfc3817>
/// <https://www.rfc-editor.org/rfc/rfc4951>
/// <https://www.rfc-editor.org/rfc/rfc4045>
/// <https://www.rfc-editor.org/rfc/rfc5515>
/// <https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml#l2tp-parameters-2>
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
        // RFC 3573 — https://www.rfc-editor.org/rfc/rfc3573
        17 => "MDMST",
        // RFC 3817 — https://www.rfc-editor.org/rfc/rfc3817
        18 => "SRRQ",
        19 => "SRRP",
        20 => "ACK",
        // RFC 4951, Sections 4.1-4.2 — https://www.rfc-editor.org/rfc/rfc4951#section-4.1
        21 => "FSQ",
        22 => "FSR",
        // RFC 4045 — https://www.rfc-editor.org/rfc/rfc4045
        23 => "MSRQ",
        24 => "MSRP",
        25 => "MSE",
        26 => "MSI",
        27 => "MSEN",
        // RFC 5515 — https://www.rfc-editor.org/rfc/rfc5515
        28 => "CSUN",
        29 => "CSURQ",
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
        assert_eq!(message_type_name(21), "FSQ");
        assert_eq!(message_type_name(22), "FSR");
        for (code, name) in [
            (17, "MDMST"),
            (18, "SRRQ"),
            (19, "SRRP"),
            (23, "MSRQ"),
            (24, "MSRP"),
            (25, "MSE"),
            (26, "MSI"),
            (27, "MSEN"),
            (28, "CSUN"),
            (29, "CSURQ"),
        ] {
            assert_eq!(message_type_name(code), name);
        }
    }

    #[test]
    fn unknown_message_type() {
        assert_eq!(message_type_name(0), "Unknown");
        assert_eq!(message_type_name(5), "Unknown");
        assert_eq!(message_type_name(30), "Unknown");
        assert_eq!(message_type_name(99), "Unknown");
    }
}
