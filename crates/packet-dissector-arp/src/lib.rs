//! ARP (Address Resolution Protocol) dissector.
//!
//! ## References
//! - RFC 826 — An Ethernet Address Resolution Protocol:
//!   <https://www.rfc-editor.org/rfc/rfc826>
//! - RFC 5227 — IPv4 Address Conflict Detection (updates RFC 826):
//!   <https://www.rfc-editor.org/rfc/rfc5227>
//! - RFC 5494 — IANA Allocation Guidelines for the Address Resolution Protocol
//!   (updates RFC 826): <https://www.rfc-editor.org/rfc/rfc5494>
//! - IANA ARP Parameters registry (hardware types / operation codes):
//!   <https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Returns the IANA-registered name for an ARP operation code (`ar$op`).
///
/// RFC 826 defines `ares_op$REQUEST = 1` and `ares_op$REPLY = 2`; RFC 5494,
/// Section 2 places `ar$op` under IETF Review, and Section 3 reserves the
/// values 0 and 65535. The remaining assignments come from the IANA
/// "Operation Codes (op)" registry
/// (<https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1>).
pub fn arp_oper_name(v: u16) -> Option<&'static str> {
    match v {
        // RFC 5494, Section 3 — "for both ar$hrd and ar$op, the values 0 and
        // 65535 are marked as reserved."
        0 => Some("Reserved"),
        // RFC 826 — `ares_op$REQUEST = 1`.
        1 => Some("REQUEST"),
        // RFC 826 — `ares_op$REPLY = 2`.
        2 => Some("REPLY"),
        // RFC 903 — Reverse ARP.
        3 => Some("request Reverse"),
        4 => Some("reply Reverse"),
        // RFC 1931 — Dynamic RARP.
        5 => Some("DRARP-Request"),
        6 => Some("DRARP-Reply"),
        7 => Some("DRARP-Error"),
        // RFC 2390 — Inverse ARP.
        8 => Some("InARP-Request"),
        9 => Some("InARP-Reply"),
        // RFC 1577 — Classical IP / ATM.
        10 => Some("ARP-NAK"),
        // MARS (Grenville Armitage) — codes 11–22, per IANA registry.
        11 => Some("MARS-Request"),
        12 => Some("MARS-Multi"),
        13 => Some("MARS-MServ"),
        14 => Some("MARS-Join"),
        15 => Some("MARS-Leave"),
        16 => Some("MARS-NAK"),
        17 => Some("MARS-Unserv"),
        18 => Some("MARS-SJoin"),
        19 => Some("MARS-SLeave"),
        20 => Some("MARS-Grouplist-Request"),
        21 => Some("MARS-Grouplist-Reply"),
        22 => Some("MARS-Redirect-Map"),
        // RFC 2176 — MAPOS.
        23 => Some("MAPOS-UNARP"),
        // RFC 5494, Section 3 — experimental allocations.
        24 => Some("OP_EXP1"),
        25 => Some("OP_EXP2"),
        65535 => Some("Reserved"),
        _ => None,
    }
}

/// Returns the IANA-registered name for an ARP hardware type (`ar$hrd`).
///
/// RFC 826 assigns `ares_hrd$Ethernet = 1`. RFC 5494, Section 2 governs
/// future allocations, and Section 3 reserves 0 and 65535 and allocates
/// HW_EXP1 (36) / HW_EXP2 (256) for experimentation. Other values come from
/// the IANA "Hardware Types (hrd)" registry.
pub fn arp_htype_name(v: u16) -> Option<&'static str> {
    match v {
        // RFC 5494, Section 3 — reserved.
        0 => Some("Reserved"),
        // RFC 826 — `ares_hrd$Ethernet = 1`.
        1 => Some("Ethernet"),
        2 => Some("Experimental Ethernet"),
        3 => Some("Amateur Radio AX.25"),
        4 => Some("Proteon ProNET Token Ring"),
        5 => Some("Chaos"),
        6 => Some("IEEE 802"),
        7 => Some("ARCNET"),
        8 => Some("Hyperchannel"),
        9 => Some("Lanstar"),
        10 => Some("Autonet Short Address"),
        11 => Some("LocalTalk"),
        12 => Some("LocalNet"),
        13 => Some("Ultra link"),
        14 => Some("SMDS"),
        15 => Some("Frame Relay"),
        16 => Some("ATM"),
        17 => Some("HDLC"),
        // RFC 4338 — Fibre Channel.
        18 => Some("Fibre Channel"),
        19 => Some("ATM"),
        20 => Some("Serial Line"),
        21 => Some("ATM"),
        22 => Some("MIL-STD-188-220"),
        23 => Some("Metricom"),
        24 => Some("IEEE 1394.1995"),
        25 => Some("MAPOS"),
        26 => Some("Twinaxial"),
        27 => Some("EUI-64"),
        28 => Some("HIPARP"),
        29 => Some("IP and ARP over ISO 7816-3"),
        30 => Some("ARPSec"),
        31 => Some("IPsec tunnel"),
        // RFC 4391 — InfiniBand.
        32 => Some("InfiniBand"),
        33 => Some("TIA-102 Project 25 Common Air Interface (CAI)"),
        34 => Some("Wiegand Interface"),
        35 => Some("Pure IP"),
        // RFC 5494, Section 3 — experimental allocations.
        36 => Some("HW_EXP1"),
        37 => Some("HFI"),
        38 => Some("Unified Bus (UB)"),
        256 => Some("HW_EXP2"),
        65535 => Some("Reserved"),
        _ => None,
    }
}

/// Returns a human-readable name for an ARP protocol type (`ar$pro`).
///
/// RFC 5494, Section 2 states: "These numbers share the Ethertype space.
/// The Ethertype space is administered as described in \[RFC5342\]." We therefore
/// reuse well-known EtherType values to name common `ar$pro` codes.
pub fn arp_ptype_name(v: u16) -> Option<&'static str> {
    match v {
        0x0800 => Some("IPv4"),
        0x0806 => Some("ARP"),
        0x0BAD => Some("Banyan VINES"),
        0x8035 => Some("Reverse ARP"),
        0x809B => Some("AppleTalk"),
        0x8100 => Some("802.1Q"),
        0x8137 => Some("IPX"),
        0x86DD => Some("IPv6"),
        0x8847 => Some("MPLS"),
        0x8848 => Some("MPLS_MC"),
        0x88A8 => Some("802.1ad"),
        0x88CC => Some("LLDP"),
        0x88E5 => Some("MACsec"),
        0x8906 => Some("FCoE"),
        _ => None,
    }
}

/// Classify an ARP packet per RFC 5227 / historical gratuitous-ARP usage.
///
/// Returns `Some(&'static str)` only when the packet matches a well-defined
/// RFC 5227 classification. Plain Request/Reply packets return `None` —
/// their IANA operation name is already surfaced via `oper`'s `display_fn`.
///
/// Classification (all require `htype == 1` Ethernet and `plen == 4` IPv4
/// since RFC 5227 is specific to IPv4 over Ethernet / IEEE 802):
///
/// - **ARP Probe** — RFC 5227, Section 1.1 / Section 2.1.1:
///   "the term 'ARP Probe' is used to refer to an ARP Request packet,
///   broadcast on the local link, with an all-zero 'sender IP address'."
/// - **ARP Announcement** — RFC 5227, Section 1.1 / Section 2.3:
///   "An ARP Announcement is identical to the ARP Probe described above,
///   except that both the sender and target IP address fields contain the
///   IP address being announced."
/// - **Gratuitous ARP Reply** — legacy pattern (RFC 5227, Section 3 /
///   Section 4 discuss why Announcements use Requests rather than Replies,
///   but gratuitous Replies with `spa == tpa` are still observed in practice).
fn arp_kind_name(
    htype: u16,
    plen: usize,
    oper: u16,
    spa: &[u8],
    tpa: &[u8],
) -> Option<&'static str> {
    // RFC 5227 is IPv4-over-Ethernet specific.
    if htype != HTYPE_ETHERNET || plen != IPV4_ADDR_LEN {
        return None;
    }
    // Defensive: caller must have extracted exactly `plen` bytes.
    if spa.len() != IPV4_ADDR_LEN || tpa.len() != IPV4_ADDR_LEN {
        return None;
    }

    let spa_zero = spa.iter().all(|&b| b == 0);
    let tpa_zero = tpa.iter().all(|&b| b == 0);
    let same_ip = spa == tpa;

    match oper {
        OPER_REQUEST => {
            if spa_zero && !tpa_zero {
                // RFC 5227, Section 1.1 — ARP Probe.
                Some("ARP Probe")
            } else if !spa_zero && same_ip {
                // RFC 5227, Section 1.1 / Section 2.3 — ARP Announcement.
                Some("ARP Announcement")
            } else {
                None
            }
        }
        OPER_REPLY => {
            if !spa_zero && same_ip {
                Some("Gratuitous ARP Reply")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Minimum ARP packet size: the fixed fields preceding the variable-length
/// addresses (RFC 826: HTYPE 2 + PTYPE 2 + HLEN 1 + PLEN 1 + OPER 2 = 8 bytes).
const FIXED_HEADER_SIZE: usize = 8;

/// `ares_hrd$Ethernet = 1` per RFC 826.
const HTYPE_ETHERNET: u16 = 1;

/// `ares_op$REQUEST = 1` per RFC 826.
const OPER_REQUEST: u16 = 1;

/// `ares_op$REPLY = 2` per RFC 826.
const OPER_REPLY: u16 = 2;

/// IPv4 protocol address length in octets.
const IPV4_ADDR_LEN: usize = 4;

/// Ethernet hardware address length in octets (RFC 826: `ar$hln = 6`).
const ETHERNET_ADDR_LEN: usize = 6;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_HTYPE: usize = 0;
const FD_PTYPE: usize = 1;
const FD_HLEN: usize = 2;
const FD_PLEN: usize = 3;
const FD_OPER: usize = 4;
const FD_SHA: usize = 5;
const FD_SPA: usize = 6;
const FD_THA: usize = 7;
const FD_TPA: usize = 8;
const FD_KIND: usize = 9;

// RFC 826 defines the variable-length address fields ar$sha/ar$spa/ar$tha/
// ar$tpa. The hardware-address fields are declared as `MacAddr` and the
// protocol-address fields as `Ipv4Addr` because the Ethernet / IPv4 profile
// overwhelmingly dominates deployed ARP traffic. For non-Ethernet hardware or
// non-IPv4 protocols, the dissector emits `FieldValue::Bytes` of the exact
// length reported by `ar$hln` / `ar$pln`.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("htype", "Hardware Type", FieldType::U16).with_display_fn(
        |v, _siblings| match v {
            FieldValue::U16(v) => arp_htype_name(*v),
            _ => None,
        },
    ),
    FieldDescriptor::new("ptype", "Protocol Type", FieldType::U16).with_display_fn(
        |v, _siblings| match v {
            FieldValue::U16(v) => arp_ptype_name(*v),
            _ => None,
        },
    ),
    FieldDescriptor::new("hlen", "Hardware Address Length", FieldType::U8),
    FieldDescriptor::new("plen", "Protocol Address Length", FieldType::U8),
    FieldDescriptor::new("oper", "Operation", FieldType::U16).with_display_fn(
        |v, _siblings| match v {
            FieldValue::U16(v) => arp_oper_name(*v),
            _ => None,
        },
    ),
    FieldDescriptor::new("sha", "Sender Hardware Address", FieldType::MacAddr),
    FieldDescriptor::new("spa", "Sender Protocol Address", FieldType::Ipv4Addr),
    FieldDescriptor::new("tha", "Target Hardware Address", FieldType::MacAddr),
    FieldDescriptor::new("tpa", "Target Protocol Address", FieldType::Ipv4Addr),
    // RFC 5227 classification (Probe / Announcement / Gratuitous Reply);
    // only emitted when the packet matches a well-defined pattern.
    FieldDescriptor::new("kind", "ARP Packet Kind", FieldType::Str).optional(),
];

/// ARP dissector.
///
/// Parses fixed-size `ar$hrd`/`ar$pro`/`ar$hln`/`ar$pln`/`ar$op` fields per
/// RFC 826, followed by the four variable-length addresses whose sizes are
/// dictated by `ar$hln` / `ar$pln` ("the length of each protocol address
/// should be determined by the hardware type ... and the protocol type",
/// RFC 826). The dissector additionally surfaces:
///
/// - RFC 5494 IANA names for `ar$hrd`, `ar$pro`, and `ar$op` via each
///   field's `display_fn`.
/// - An optional `kind` field classifying IPv4-over-Ethernet packets as an
///   ARP Probe, ARP Announcement, or Gratuitous ARP Reply per RFC 5227.
pub struct ArpDissector;

impl Dissector for ArpDissector {
    fn name(&self) -> &'static str {
        "Address Resolution Protocol"
    }

    fn short_name(&self) -> &'static str {
        "ARP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < FIXED_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: FIXED_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 826 — Packet format: "16.bit: (ar$hrd)", "16.bit: (ar$pro)",
        // "8.bit: (ar$hln)", "8.bit: (ar$pln)", "16.bit: (ar$op)".
        let htype = read_be_u16(data, 0)?;
        let ptype = read_be_u16(data, 2)?;
        let hlen = data[4] as usize;
        let plen = data[5] as usize;
        let oper = read_be_u16(data, 6)?;

        // RFC 826 — "nbytes: (ar$sha) ... n from the ar$hln field.
        // mbytes: (ar$spa) ... m from the ar$pln field. nbytes: (ar$tha) ...
        // mbytes: (ar$tpa)." Total packet size is therefore 8 + 2·hlen + 2·plen.
        let total_len = FIXED_HEADER_SIZE + 2 * hlen + 2 * plen;
        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        let sha_start = FIXED_HEADER_SIZE;
        let spa_start = sha_start + hlen;
        let tha_start = spa_start + plen;
        let tpa_start = tha_start + hlen;

        let sha_bytes = &data[sha_start..sha_start + hlen];
        let spa_bytes = &data[spa_start..spa_start + plen];
        let tha_bytes = &data[tha_start..tha_start + hlen];
        let tpa_bytes = &data[tpa_start..tpa_start + plen];

        let sha_value = if hlen == ETHERNET_ADDR_LEN {
            FieldValue::MacAddr(MacAddr([
                sha_bytes[0],
                sha_bytes[1],
                sha_bytes[2],
                sha_bytes[3],
                sha_bytes[4],
                sha_bytes[5],
            ]))
        } else {
            FieldValue::Bytes(sha_bytes)
        };
        let tha_value = if hlen == ETHERNET_ADDR_LEN {
            FieldValue::MacAddr(MacAddr([
                tha_bytes[0],
                tha_bytes[1],
                tha_bytes[2],
                tha_bytes[3],
                tha_bytes[4],
                tha_bytes[5],
            ]))
        } else {
            FieldValue::Bytes(tha_bytes)
        };
        let spa_value = if plen == IPV4_ADDR_LEN {
            FieldValue::Ipv4Addr([spa_bytes[0], spa_bytes[1], spa_bytes[2], spa_bytes[3]])
        } else {
            FieldValue::Bytes(spa_bytes)
        };
        let tpa_value = if plen == IPV4_ADDR_LEN {
            FieldValue::Ipv4Addr([tpa_bytes[0], tpa_bytes[1], tpa_bytes[2], tpa_bytes[3]])
        } else {
            FieldValue::Bytes(tpa_bytes)
        };

        // RFC 5227 classification is derived from already-parsed fields.
        let kind = arp_kind_name(htype, plen, oper, spa_bytes, tpa_bytes);

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HTYPE],
            FieldValue::U16(htype),
            offset..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PTYPE],
            FieldValue::U16(ptype),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HLEN],
            FieldValue::U8(hlen as u8),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PLEN],
            FieldValue::U8(plen as u8),
            offset + 5..offset + 6,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_OPER],
            FieldValue::U16(oper),
            offset + 6..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SHA],
            sha_value,
            offset + sha_start..offset + sha_start + hlen,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SPA],
            spa_value,
            offset + spa_start..offset + spa_start + plen,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_THA],
            tha_value,
            offset + tha_start..offset + tha_start + hlen,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TPA],
            tpa_value,
            offset + tpa_start..offset + tpa_start + plen,
        );
        if let Some(name) = kind {
            // RFC 5227 classification field; anchored to the full ARP header
            // because the classification depends on oper + spa + tpa.
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_KIND],
                FieldValue::Str(name),
                offset..offset + total_len,
            );
        }
        buf.end_layer();

        Ok(DissectResult::new(total_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oper_name_covers_rfc_826() {
        assert_eq!(arp_oper_name(1), Some("REQUEST"));
        assert_eq!(arp_oper_name(2), Some("REPLY"));
    }

    #[test]
    fn oper_name_covers_rarp_drarp_inarp() {
        // RFC 903
        assert_eq!(arp_oper_name(3), Some("request Reverse"));
        assert_eq!(arp_oper_name(4), Some("reply Reverse"));
        // RFC 1931
        assert_eq!(arp_oper_name(5), Some("DRARP-Request"));
        assert_eq!(arp_oper_name(6), Some("DRARP-Reply"));
        assert_eq!(arp_oper_name(7), Some("DRARP-Error"));
        // RFC 2390
        assert_eq!(arp_oper_name(8), Some("InARP-Request"));
        assert_eq!(arp_oper_name(9), Some("InARP-Reply"));
    }

    #[test]
    fn oper_name_covers_mars_and_mapos() {
        assert_eq!(arp_oper_name(11), Some("MARS-Request"));
        assert_eq!(arp_oper_name(22), Some("MARS-Redirect-Map"));
        assert_eq!(arp_oper_name(23), Some("MAPOS-UNARP"));
    }

    #[test]
    fn oper_name_covers_rfc_5494_experimental() {
        assert_eq!(arp_oper_name(24), Some("OP_EXP1"));
        assert_eq!(arp_oper_name(25), Some("OP_EXP2"));
    }

    #[test]
    fn oper_name_reserved_per_rfc_5494() {
        assert_eq!(arp_oper_name(0), Some("Reserved"));
        assert_eq!(arp_oper_name(65535), Some("Reserved"));
    }

    #[test]
    fn oper_name_unknown_returns_none() {
        assert_eq!(arp_oper_name(100), None);
        assert_eq!(arp_oper_name(30000), None);
    }

    #[test]
    fn htype_name_covers_rfc_826_ethernet() {
        assert_eq!(arp_htype_name(1), Some("Ethernet"));
    }

    #[test]
    fn htype_name_covers_iana_registry() {
        assert_eq!(arp_htype_name(6), Some("IEEE 802"));
        assert_eq!(arp_htype_name(16), Some("ATM"));
        assert_eq!(arp_htype_name(18), Some("Fibre Channel"));
        assert_eq!(arp_htype_name(32), Some("InfiniBand"));
    }

    #[test]
    fn htype_name_covers_rfc_5494_experimental_and_reserved() {
        assert_eq!(arp_htype_name(0), Some("Reserved"));
        assert_eq!(arp_htype_name(36), Some("HW_EXP1"));
        assert_eq!(arp_htype_name(256), Some("HW_EXP2"));
        assert_eq!(arp_htype_name(65535), Some("Reserved"));
    }

    #[test]
    fn htype_name_unknown_returns_none() {
        assert_eq!(arp_htype_name(9999), None);
    }

    #[test]
    fn ptype_name_shares_ethertype_space() {
        // RFC 5494, Section 2 — "These numbers share the Ethertype space."
        assert_eq!(arp_ptype_name(0x0800), Some("IPv4"));
        assert_eq!(arp_ptype_name(0x86DD), Some("IPv6"));
    }

    #[test]
    fn ptype_name_unknown_returns_none() {
        assert_eq!(arp_ptype_name(0x1234), None);
    }

    #[test]
    fn kind_probe_classification() {
        // RFC 5227, Section 1.1 — "ARP Probe": Request, spa=0.0.0.0, tpa=target.
        assert_eq!(
            arp_kind_name(1, 4, 1, &[0, 0, 0, 0], &[192, 168, 1, 1]),
            Some("ARP Probe")
        );
    }

    #[test]
    fn kind_announcement_classification() {
        // RFC 5227, Section 1.1 / 2.3 — "ARP Announcement": Request, spa==tpa.
        assert_eq!(
            arp_kind_name(1, 4, 1, &[10, 0, 0, 5], &[10, 0, 0, 5]),
            Some("ARP Announcement")
        );
    }

    #[test]
    fn kind_gratuitous_reply_classification() {
        // Classical gratuitous ARP Reply: Reply with spa==tpa.
        assert_eq!(
            arp_kind_name(1, 4, 2, &[10, 0, 0, 5], &[10, 0, 0, 5]),
            Some("Gratuitous ARP Reply")
        );
    }

    #[test]
    fn kind_plain_request_is_none() {
        // Normal Request — not classified.
        assert_eq!(
            arp_kind_name(1, 4, 1, &[192, 168, 1, 1], &[192, 168, 1, 2]),
            None
        );
    }

    #[test]
    fn kind_plain_reply_is_none() {
        // Normal Reply — not classified.
        assert_eq!(
            arp_kind_name(1, 4, 2, &[192, 168, 1, 1], &[192, 168, 1, 2]),
            None
        );
    }

    #[test]
    fn kind_requires_ethernet_and_ipv4() {
        // RFC 5227 is IPv4-over-Ethernet specific — do not classify other
        // combinations even if the structural pattern matches.
        assert_eq!(arp_kind_name(6, 4, 1, &[0, 0, 0, 0], &[10, 0, 0, 1]), None);
        assert_eq!(
            arp_kind_name(1, 6, 1, &[0; 6], &[0xde, 0xad, 0xbe, 0xef, 0, 1]),
            None
        );
    }

    #[test]
    fn kind_request_all_zero_both_is_none() {
        // spa=0 and tpa=0 together is degenerate — not a probe, not an
        // announcement.
        assert_eq!(arp_kind_name(1, 4, 1, &[0, 0, 0, 0], &[0, 0, 0, 0]), None);
    }

    #[test]
    fn kind_unknown_opcode_is_none() {
        assert_eq!(arp_kind_name(1, 4, 3, &[10, 0, 0, 5], &[10, 0, 0, 5]), None);
    }

    #[test]
    fn oper_name_covers_every_assigned_arm() {
        // Exhaustive sweep so every explicit match arm in `arp_oper_name` is
        // exercised by the coverage tool. Assigned values (RFC 826 /903/1931/
        // 2390/1577, MARS, MAPOS, RFC 5494) must resolve; unassigned values
        // in between must return `None`.
        let assigned: &[u16] = &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 65535,
        ];
        for &v in assigned {
            let name = arp_oper_name(v).unwrap_or_else(|| panic!("oper {v} should resolve"));
            assert!(!name.is_empty(), "oper {v} returned empty name");
        }
        // Unassigned sampling across the registry gap and above the last
        // assigned code keeps the `_ => None` arm covered.
        for v in [26u16, 100, 1000, 30000, 65534] {
            assert_eq!(arp_oper_name(v), None, "oper {v} should be None");
        }
    }

    #[test]
    fn htype_name_covers_every_assigned_arm() {
        // Exhaustive sweep so every explicit match arm in `arp_htype_name` is
        // exercised by the coverage tool.
        let assigned: &[u16] = &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 256, 65535,
        ];
        for &v in assigned {
            let name = arp_htype_name(v).unwrap_or_else(|| panic!("htype {v} should resolve"));
            assert!(!name.is_empty(), "htype {v} returned empty name");
        }
        for v in [39u16, 100, 255, 257, 65534] {
            assert_eq!(arp_htype_name(v), None, "htype {v} should be None");
        }
    }

    #[test]
    fn ptype_name_covers_every_assigned_arm() {
        // Exhaustive sweep of each EtherType listed in `arp_ptype_name`.
        let assigned: &[u16] = &[
            0x0800, 0x0806, 0x0BAD, 0x8035, 0x809B, 0x8100, 0x8137, 0x86DD, 0x8847, 0x8848, 0x88A8,
            0x88CC, 0x88E5, 0x8906,
        ];
        for &v in assigned {
            let name = arp_ptype_name(v).unwrap_or_else(|| panic!("ptype {v:#06x} should resolve"));
            assert!(!name.is_empty(), "ptype {v:#06x} returned empty name");
        }
        for v in [0u16, 0x0001, 0x1234, 0xFFFF] {
            assert_eq!(arp_ptype_name(v), None, "ptype {v:#06x} should be None");
        }
    }

    #[test]
    fn dissect_covers_non_ethernet_and_non_ipv4_branches() {
        // Exercise the `FieldValue::Bytes` branches for non-Ethernet hardware
        // addresses and non-IPv4 protocol addresses, plus the truncated-header
        // and truncated-address error paths.
        use packet_dissector_core::dissector::Dissector;

        // hlen != 6, plen != 4 — drives the `else` arms in `dissect`.
        let raw: &[u8] = &[
            0x00, 0x06, // htype: IEEE 802
            0x86, 0xDD, // ptype: IPv6
            0x08, // hlen = 8
            0x10, // plen = 16
            0x00, 0x08, // oper: InARP-Request
            // SHA (8 bytes)
            1, 2, 3, 4, 5, 6, 7, 8, // SPA (16 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // THA (8 bytes)
            9, 10, 11, 12, 13, 14, 15, 16, // TPA (16 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        let mut buf = DissectBuffer::new();
        ArpDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert!(matches!(fields[5].value, FieldValue::Bytes(_)));
        assert!(matches!(fields[6].value, FieldValue::Bytes(_)));
        assert!(matches!(fields[7].value, FieldValue::Bytes(_)));
        assert!(matches!(fields[8].value, FieldValue::Bytes(_)));

        // Truncated fixed header.
        let mut buf = DissectBuffer::new();
        let short: &[u8] = &[0x00, 0x01, 0x08, 0x00, 0x06];
        match ArpDissector.dissect(short, &mut buf, 0) {
            Err(PacketError::Truncated { .. }) => {}
            other => panic!("expected Truncated error, got {other:?}"),
        }

        // Truncated variable-length addresses.
        let mut buf = DissectBuffer::new();
        let truncated: &[u8] = &[
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // fixed header
            1, 2, 3, 4, 5, 6, // SHA complete
               // remainder missing
        ];
        match ArpDissector.dissect(truncated, &mut buf, 0) {
            Err(PacketError::Truncated { .. }) => {}
            other => panic!("expected Truncated error, got {other:?}"),
        }
    }

    #[test]
    fn dissector_metadata_is_stable() {
        use packet_dissector_core::dissector::Dissector;
        let d = ArpDissector;
        assert_eq!(d.name(), "Address Resolution Protocol");
        assert_eq!(d.short_name(), "ARP");
        assert_eq!(d.field_descriptors().len(), 10);
    }

    #[test]
    fn display_fns_resolve_iana_names() {
        // Exercise the `display_fn` closures so the coverage tool sees each
        // mapping back to its name helper.
        let htype = FIELD_DESCRIPTORS[FD_HTYPE].display_fn.unwrap();
        assert_eq!(htype(&FieldValue::U16(1), &[]), Some("Ethernet"));
        assert_eq!(htype(&FieldValue::U8(0), &[]), None);

        let ptype = FIELD_DESCRIPTORS[FD_PTYPE].display_fn.unwrap();
        assert_eq!(ptype(&FieldValue::U16(0x0800), &[]), Some("IPv4"));
        assert_eq!(ptype(&FieldValue::U8(0), &[]), None);

        let oper = FIELD_DESCRIPTORS[FD_OPER].display_fn.unwrap();
        assert_eq!(oper(&FieldValue::U16(1), &[]), Some("REQUEST"));
        assert_eq!(oper(&FieldValue::U8(0), &[]), None);
    }
}
