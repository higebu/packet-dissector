//! Raw IP link-type dispatchers (`LINKTYPE_RAW`, `LINKTYPE_IPV4`,
//! `LINKTYPE_IPV6`).
//!
//! These link-layer types have no link-layer header: each packet begins
//! directly with an IPv4 or IPv6 header. The dispatchers consume no bytes
//! and add no layer; they only select the IPv4 or IPv6 dissector through
//! [`DispatchHint::ByEtherType`].
//!
//! ## References
//! - LINKTYPE_RAW: <https://www.tcpdump.org/linktypes/LINKTYPE_RAW.html>
//! - LINKTYPE_IPV4: <https://www.tcpdump.org/linktypes/LINKTYPE_IPV4.html>
//! - LINKTYPE_IPV6: <https://www.tcpdump.org/linktypes/LINKTYPE_IPV6.html>
//! - Link-layer header types: <https://www.tcpdump.org/linktypes.html>
//! - RFC 791, Section 3.1 (IPv4 Version): <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
//! - RFC 8200, Section 3 (IPv6 Version): <https://www.rfc-editor.org/rfc/rfc8200#section-3>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::FieldDescriptor;
use packet_dissector_core::packet::DissectBuffer;

/// IP version 4 — RFC 791, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
const IP_VERSION_4: u8 = 4;
/// IP version 6 — RFC 8200, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc8200#section-3>
const IP_VERSION_6: u8 = 6;

/// EtherType for IPv4 (IEEE 802 Numbers).
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6 (IEEE 802 Numbers).
const ETHERTYPE_IPV6: u16 = 0x86DD;

static RAW_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_RAW",
    "LINKTYPE_RAW",
    "https://www.tcpdump.org/linktypes/LINKTYPE_RAW.html",
)];

static IPV4_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_IPV4",
    "LINKTYPE_IPV4",
    "https://www.tcpdump.org/linktypes/LINKTYPE_IPV4.html",
)];

static IPV6_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_IPV6",
    "LINKTYPE_IPV6",
    "https://www.tcpdump.org/linktypes/LINKTYPE_IPV6.html",
)];

/// Read the 4-bit IP version from the first octet.
///
/// Both the IPv4 and the IPv6 header start with a 4-bit Version field.
fn ip_version(data: &[u8]) -> Result<u8, PacketError> {
    data.first().map(|b| b >> 4).ok_or(PacketError::Truncated {
        expected: 1,
        actual: 0,
    })
}

/// Build the error for a version that the link type does not allow.
fn invalid_version(version: u8) -> PacketError {
    PacketError::InvalidFieldValue {
        field: "version",
        value: u32::from(version),
    }
}

/// `LINKTYPE_RAW` (101) dispatcher.
///
/// "Packets are IPv4 or IPv6 datagrams; the packet begins with an IPv4 or
/// IPv6 header, with the version field of the header indicating whether
/// it's an IPv4 or IPv6 packet."
pub struct RawIpDissector;

impl Dissector for RawIpDissector {
    fn name(&self) -> &'static str {
        "Raw IP"
    }

    fn short_name(&self) -> &'static str {
        "RawIP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn references(&self) -> &'static [SpecReference] {
        RAW_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        _buf: &mut DissectBuffer<'pkt>,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let next = match ip_version(data)? {
            IP_VERSION_4 => DispatchHint::ByEtherType(ETHERTYPE_IPV4),
            IP_VERSION_6 => DispatchHint::ByEtherType(ETHERTYPE_IPV6),
            v => return Err(invalid_version(v)),
        };
        Ok(DissectResult::new(0, next))
    }
}

/// `LINKTYPE_IPV4` (228) dispatcher.
///
/// "Packets are IPv4 datagrams beginning with an IPv4 header. This should
/// only be used for traffic that consists solely of IPv4 packets, and in
/// which IPv6 packets should be considered errors."
pub struct RawIpv4Dissector;

impl Dissector for RawIpv4Dissector {
    fn name(&self) -> &'static str {
        "Raw IPv4"
    }

    fn short_name(&self) -> &'static str {
        "RawIPv4"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn references(&self) -> &'static [SpecReference] {
        IPV4_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        _buf: &mut DissectBuffer<'pkt>,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        match ip_version(data)? {
            IP_VERSION_4 => Ok(DissectResult::new(
                0,
                DispatchHint::ByEtherType(ETHERTYPE_IPV4),
            )),
            v => Err(invalid_version(v)),
        }
    }
}

/// `LINKTYPE_IPV6` (229) dispatcher.
///
/// "Packets are IPv6 datagrams beginning with an IPv6 header. This should
/// only be used for traffic that consists solely of IPv6 packets, and in
/// which IPv4 packets should be considered errors."
pub struct RawIpv6Dissector;

impl Dissector for RawIpv6Dissector {
    fn name(&self) -> &'static str {
        "Raw IPv6"
    }

    fn short_name(&self) -> &'static str {
        "RawIPv6"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &[]
    }

    fn references(&self) -> &'static [SpecReference] {
        IPV6_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        _buf: &mut DissectBuffer<'pkt>,
        _offset: usize,
    ) -> Result<DissectResult, PacketError> {
        match ip_version(data)? {
            IP_VERSION_6 => Ok(DissectResult::new(
                0,
                DispatchHint::ByEtherType(ETHERTYPE_IPV6),
            )),
            v => Err(invalid_version(v)),
        }
    }
}

#[cfg(test)]
mod tests {
    //! # LINKTYPE_RAW / LINKTYPE_IPV4 / LINKTYPE_IPV6 Coverage
    //!
    //! Spec: <https://www.tcpdump.org/linktypes/LINKTYPE_RAW.html>,
    //! <https://www.tcpdump.org/linktypes/LINKTYPE_IPV4.html>,
    //! <https://www.tcpdump.org/linktypes/LINKTYPE_IPV6.html>
    //!
    //! | Spec Section            | Description                         | Test                         |
    //! |-------------------------|-------------------------------------|------------------------------|
    //! | LINKTYPE_RAW            | Version 4 → IPv4                    | raw_ipv4                     |
    //! | LINKTYPE_RAW            | Version 6 → IPv6                    | raw_ipv6                     |
    //! | LINKTYPE_RAW            | Other version is an error           | raw_invalid_version          |
    //! | LINKTYPE_RAW            | Empty packet                        | raw_empty                    |
    //! | LINKTYPE_IPV4           | Version 4 → IPv4                    | ipv4_ok                      |
    //! | LINKTYPE_IPV4           | IPv6 packets are errors             | ipv4_rejects_ipv6            |
    //! | LINKTYPE_IPV4           | Empty packet                        | ipv4_empty                   |
    //! | LINKTYPE_IPV6           | Version 6 → IPv6                    | ipv6_ok                      |
    //! | LINKTYPE_IPV6           | IPv4 packets are errors             | ipv6_rejects_ipv4            |
    //! | LINKTYPE_IPV6           | Empty packet                        | ipv6_empty                   |
    //! | —                       | Dissector metadata                  | dissector_metadata           |

    use super::*;

    fn run<D: Dissector>(d: &D, data: &[u8]) -> Result<DissectResult, PacketError> {
        let mut buf = DissectBuffer::new();
        let result = d.dissect(data, &mut buf, 0);
        // Dispatchers never add a layer.
        assert!(buf.layers().is_empty());
        result
    }

    const TRUNCATED: PacketError = PacketError::Truncated {
        expected: 1,
        actual: 0,
    };

    #[test]
    fn raw_ipv4() {
        let r = run(&RawIpDissector, &[0x45, 0x00]).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn raw_ipv6() {
        let r = run(&RawIpDissector, &[0x60, 0x00]).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn raw_invalid_version() {
        let err = run(&RawIpDissector, &[0x50]).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 5
            }
        );
    }

    #[test]
    fn raw_empty() {
        assert_eq!(run(&RawIpDissector, &[]).unwrap_err(), TRUNCATED);
    }

    #[test]
    fn ipv4_ok() {
        let r = run(&RawIpv4Dissector, &[0x45]).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn ipv4_rejects_ipv6() {
        let err = run(&RawIpv4Dissector, &[0x60]).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 6
            }
        );
    }

    #[test]
    fn ipv4_empty() {
        assert_eq!(run(&RawIpv4Dissector, &[]).unwrap_err(), TRUNCATED);
    }

    #[test]
    fn ipv6_ok() {
        let r = run(&RawIpv6Dissector, &[0x60]).unwrap();
        assert_eq!(r.bytes_consumed, 0);
        assert_eq!(r.next, DispatchHint::ByEtherType(0x86DD));
    }

    #[test]
    fn ipv6_rejects_ipv4() {
        let err = run(&RawIpv6Dissector, &[0x45]).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidFieldValue {
                field: "version",
                value: 4
            }
        );
    }

    #[test]
    fn ipv6_empty() {
        assert_eq!(run(&RawIpv6Dissector, &[]).unwrap_err(), TRUNCATED);
    }

    #[test]
    fn dissector_metadata() {
        let all: [(&dyn Dissector, &str, &str, &str); 3] = [
            (&RawIpDissector, "Raw IP", "RawIP", "LINKTYPE_RAW"),
            (&RawIpv4Dissector, "Raw IPv4", "RawIPv4", "LINKTYPE_IPV4"),
            (&RawIpv6Dissector, "Raw IPv6", "RawIPv6", "LINKTYPE_IPV6"),
        ];
        for (d, name, short, reference) in all {
            assert_eq!(d.name(), name);
            assert_eq!(d.short_name(), short);
            assert!(d.field_descriptors().is_empty());
            assert_eq!(d.references()[0].id, reference);
            assert_eq!(d.layer(), Some(ProtocolLayer::Link));
        }
    }
}
