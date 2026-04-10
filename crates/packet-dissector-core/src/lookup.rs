//! Shared lookup tables for well-known protocol values.
//!
//! These mappings are used by multiple dissectors (e.g. IPv4 and IPv6 both
//! need IP protocol number → name translation).

/// Returns a human-readable name for well-known IP protocol / next-header numbers.
///
/// RFC 790 / IANA: <https://www.iana.org/assignments/protocol-numbers/>
pub fn ip_protocol_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("HOPOPT"),
        1 => Some("ICMP"),
        2 => Some("IGMP"),
        4 => Some("IPv4"),
        6 => Some("TCP"),
        17 => Some("UDP"),
        41 => Some("IPv6_ENCAP"),
        43 => Some("IPv6_ROUTE"),
        44 => Some("IPv6_FRAG"),
        47 => Some("GRE"),
        50 => Some("ESP"),
        51 => Some("AH"),
        58 => Some("ICMPv6"),
        59 => Some("IPv6_NONXT"),
        60 => Some("IPv6_OPTS"),
        103 => Some("PIM"),
        108 => Some("IPComp"),
        112 => Some("VRRP"),
        115 => Some("L2TP"),
        132 => Some("SCTP"),
        136 => Some("UDPLite"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_protocol_name_known() {
        assert_eq!(ip_protocol_name(0), Some("HOPOPT"));
        assert_eq!(ip_protocol_name(1), Some("ICMP"));
        assert_eq!(ip_protocol_name(2), Some("IGMP"));
        assert_eq!(ip_protocol_name(4), Some("IPv4"));
        assert_eq!(ip_protocol_name(6), Some("TCP"));
        assert_eq!(ip_protocol_name(17), Some("UDP"));
        assert_eq!(ip_protocol_name(41), Some("IPv6_ENCAP"));
        assert_eq!(ip_protocol_name(43), Some("IPv6_ROUTE"));
        assert_eq!(ip_protocol_name(44), Some("IPv6_FRAG"));
        assert_eq!(ip_protocol_name(47), Some("GRE"));
        assert_eq!(ip_protocol_name(50), Some("ESP"));
        assert_eq!(ip_protocol_name(51), Some("AH"));
        assert_eq!(ip_protocol_name(58), Some("ICMPv6"));
        assert_eq!(ip_protocol_name(59), Some("IPv6_NONXT"));
        assert_eq!(ip_protocol_name(60), Some("IPv6_OPTS"));
        assert_eq!(ip_protocol_name(103), Some("PIM"));
        assert_eq!(ip_protocol_name(108), Some("IPComp"));
        assert_eq!(ip_protocol_name(112), Some("VRRP"));
        assert_eq!(ip_protocol_name(115), Some("L2TP"));
        assert_eq!(ip_protocol_name(132), Some("SCTP"));
        assert_eq!(ip_protocol_name(136), Some("UDPLite"));
    }

    #[test]
    fn ip_protocol_name_unknown() {
        assert_eq!(ip_protocol_name(0), Some("HOPOPT"));
        assert_eq!(ip_protocol_name(255), None);
    }
}
