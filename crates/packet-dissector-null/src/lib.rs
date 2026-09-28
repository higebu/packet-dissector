//! BSD loopback encapsulation dissector (`LINKTYPE_NULL` / `LINKTYPE_LOOP`).
//!
//! Both link-layer types prepend a 4-octet protocol type field carrying a
//! `PF_`/`AF_` address family value to the payload:
//!
//! - `LINKTYPE_NULL` (0): the field is in the host byte order of the
//!   capturing machine, so the byte order has to be detected per packet.
//! - `LINKTYPE_LOOP` (108): the field is in big-endian byte order.
//!
//! ## References
//! - LINKTYPE_NULL: <https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html>
//! - LINKTYPE_LOOP: <https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html>
//! - Link-layer header types: <https://www.tcpdump.org/linktypes.html>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// Header size in bytes.
///
/// Layout (LINKTYPE_NULL / LINKTYPE_LOOP "Packet structure"):
/// ```text
/// +---------------------------+
/// |       Protocol type       |
/// |         (4 Octets)        |
/// +---------------------------+
/// |           Payload         |
/// .                           .
/// ```
const HEADER_SIZE: usize = 4;

/// Protocol type values from the LINKTYPE_NULL / LINKTYPE_LOOP pages.
///
/// "2 - payload is an IPv4 packet;"
const FAMILY_IPV4: u32 = 2;
/// "7 - payload is an OSI packet;"
const FAMILY_OSI: u32 = 7;
/// "23 - payload is an IPX packet."
const FAMILY_IPX: u32 = 23;
/// "24 - payload is an IPv6 packet;"
const FAMILY_IPV6_BSD: u32 = 24;
/// "28 - payload is an IPv6 packet;"
const FAMILY_IPV6_FREEBSD: u32 = 28;
/// "30 - payload is an IPv6 packet;"
const FAMILY_IPV6_DARWIN: u32 = 30;

/// EtherType for IPv4 (IEEE 802 Numbers).
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6 (IEEE 802 Numbers).
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Field descriptor index for [`FIELD_DESCRIPTORS`].
const FD_FAMILY: usize = 0;

static FIELD_DESCRIPTORS: &[FieldDescriptor] =
    &[
        FieldDescriptor::new("family", "Family", FieldType::U32).with_display_fn(|v, _| match v {
            FieldValue::U32(f) => family_name(*f),
            _ => None,
        }),
    ];

/// Specification references for the `LINKTYPE_NULL` dissector.
static NULL_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_NULL",
    "LINKTYPE_NULL",
    "https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html",
)];

/// Specification references for the `LINKTYPE_LOOP` dissector.
static LOOP_REFERENCES: &[SpecReference] = &[SpecReference::new(
    "LINKTYPE_LOOP",
    "LINKTYPE_LOOP",
    "https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html",
)];

/// Human-readable name of a protocol type (address family) value.
fn family_name(family: u32) -> Option<&'static str> {
    match family {
        FAMILY_IPV4 => Some("IPv4"),
        FAMILY_OSI => Some("OSI"),
        FAMILY_IPX => Some("IPX"),
        // "All of the IPv6 values correspond to IPv6 packets; code reading
        // files must treat all of them as indicating an IPv6 packet."
        FAMILY_IPV6_BSD | FAMILY_IPV6_FREEBSD | FAMILY_IPV6_DARWIN => Some("IPv6"),
        _ => None,
    }
}

/// Map a protocol type (address family) value to the next dispatch hint.
fn next_hint(family: u32) -> DispatchHint {
    match family {
        FAMILY_IPV4 => DispatchHint::ByEtherType(ETHERTYPE_IPV4),
        FAMILY_IPV6_BSD | FAMILY_IPV6_FREEBSD | FAMILY_IPV6_DARWIN => {
            DispatchHint::ByEtherType(ETHERTYPE_IPV6)
        }
        // OSI and IPX have no registered dissectors; end the chain.
        _ => DispatchHint::End,
    }
}

/// Read the 4-octet protocol type field of a `LINKTYPE_NULL` header.
///
/// "The protocol type field is in the host byte order of the machine on
/// which the capture was done." — the capture file's byte order does not
/// tell which one was used. All defined values fit in 16 bits, so a value
/// read as big-endian whose upper 16 bits are non-zero was written in
/// little-endian order and is byte-swapped back.
fn read_null_family(header: [u8; HEADER_SIZE]) -> u32 {
    let be = u32::from_be_bytes(header);
    if be & 0xFFFF_0000 != 0 {
        be.swap_bytes()
    } else {
        be
    }
}

/// Push the single-field layer and build the dissect result.
fn dissect_header<'pkt>(
    short_name: &'static str,
    family: u32,
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> DissectResult {
    buf.begin_layer(
        short_name,
        None,
        FIELD_DESCRIPTORS,
        offset..offset + HEADER_SIZE,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_FAMILY],
        FieldValue::U32(family),
        offset..offset + HEADER_SIZE,
    );
    buf.end_layer();
    DissectResult::new(HEADER_SIZE, next_hint(family))
}

/// Return the 4-octet header, or a truncation error.
fn header(data: &[u8]) -> Result<[u8; HEADER_SIZE], PacketError> {
    data.get(..HEADER_SIZE)
        .and_then(|h| <[u8; HEADER_SIZE]>::try_from(h).ok())
        .ok_or(PacketError::Truncated {
            expected: HEADER_SIZE,
            actual: data.len(),
        })
}

/// `LINKTYPE_NULL` (0) dissector — BSD loopback encapsulation with the
/// protocol type in the capturing host's byte order.
pub struct NullDissector;

impl Dissector for NullDissector {
    fn name(&self) -> &'static str {
        "BSD loopback encapsulation"
    }

    fn short_name(&self) -> &'static str {
        "Null"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        NULL_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let family = read_null_family(header(data)?);
        Ok(dissect_header("Null", family, buf, offset))
    }
}

/// `LINKTYPE_LOOP` (108) dissector — OpenBSD loopback encapsulation with the
/// protocol type in big-endian byte order.
pub struct LoopDissector;

impl Dissector for LoopDissector {
    fn name(&self) -> &'static str {
        "OpenBSD loopback encapsulation"
    }

    fn short_name(&self) -> &'static str {
        "Loop"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        LOOP_REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // "The protocol type field is in big-endian byte order."
        let family = u32::from_be_bytes(header(data)?);
        Ok(dissect_header("Loop", family, buf, offset))
    }
}

#[cfg(test)]
mod tests {
    //! # LINKTYPE_NULL / LINKTYPE_LOOP Coverage
    //!
    //! Spec: <https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html>,
    //! <https://www.tcpdump.org/linktypes/LINKTYPE_LOOP.html>
    //!
    //! | Spec Section                 | Description                         | Test                                   |
    //! |------------------------------|-------------------------------------|----------------------------------------|
    //! | Packet structure             | 4-octet header, IPv4 dispatch       | null_ipv4_little_endian                |
    //! | Packet structure             | Offset handling                     | null_with_offset                       |
    //! | Packet structure             | Truncated input                     | null_truncated, loop_truncated         |
    //! | Description (NULL host order)| Little-endian protocol type         | null_ipv4_little_endian                |
    //! | Description (NULL host order)| Big-endian protocol type            | null_ipv4_big_endian                   |
    //! | Description (IPv6 values)    | 24 / 28 / 30 all mean IPv6          | null_ipv6_all_values, loop_ipv6_all_values |
    //! | Description (OSI / IPX)      | No dissector, chain ends            | null_osi_ends_chain, loop_ipx_ends_chain |
    //! | Description (values)         | Unknown value ends chain            | null_unknown_family_ends_chain         |
    //! | Description (LOOP big-endian)| Big-endian protocol type            | loop_ipv4                              |
    //! | Description (LOOP big-endian)| No byte-order detection             | loop_little_endian_value_not_swapped   |
    //! | Description (values)         | Family display names                | family_display_names                   |
    //! | —                            | Dissector metadata                  | dissector_metadata                     |

    use super::*;

    fn dissect_ok<D: Dissector>(d: &D, data: &[u8]) -> (DissectResult, u32) {
        let mut buf = DissectBuffer::new();
        let result = d.dissect(data, &mut buf, 0).unwrap();
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..HEADER_SIZE);
        let family = buf.field_by_name(layer, "family").unwrap();
        assert_eq!(family.range, 0..HEADER_SIZE);
        let FieldValue::U32(v) = family.value else {
            panic!("family must be U32, got {:?}", family.value);
        };
        (result, v)
    }

    #[test]
    fn null_ipv4_little_endian() {
        // macOS lo0 capture: AF_INET (2) in little-endian host order.
        let data = [0x02, 0x00, 0x00, 0x00, 0x45, 0x00];
        let (result, family) = dissect_ok(&NullDissector, &data);
        assert_eq!(family, 2);
        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn null_ipv4_big_endian() {
        let data = [0x00, 0x00, 0x00, 0x02, 0x45, 0x00];
        let (result, family) = dissect_ok(&NullDissector, &data);
        assert_eq!(family, 2);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
    }

    #[test]
    fn null_ipv6_all_values() {
        for af in [24u32, 28, 30] {
            for bytes in [af.to_le_bytes(), af.to_be_bytes()] {
                let (result, family) = dissect_ok(&NullDissector, &bytes);
                assert_eq!(family, af);
                assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
            }
        }
    }

    #[test]
    fn null_osi_ends_chain() {
        let (result, family) = dissect_ok(&NullDissector, &7u32.to_le_bytes());
        assert_eq!(family, 7);
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn null_unknown_family_ends_chain() {
        let (result, family) = dissect_ok(&NullDissector, &99u32.to_be_bytes());
        assert_eq!(family, 99);
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn null_with_offset() {
        let data = [0xAA, 0xBB, 0x1E, 0x00, 0x00, 0x00, 0x60];
        let mut buf = DissectBuffer::new();
        let result = NullDissector.dissect(&data[2..], &mut buf, 2).unwrap();
        assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "Null");
        assert_eq!(layer.range, 2..6);
        assert_eq!(buf.field_by_name(layer, "family").unwrap().range, 2..6);
    }

    #[test]
    fn null_truncated() {
        let mut buf = DissectBuffer::new();
        let err = NullDissector
            .dissect(&[0x02, 0x00, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn loop_ipv4() {
        let data = [0x00, 0x00, 0x00, 0x02, 0x45];
        let mut buf = DissectBuffer::new();
        let result = LoopDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));
        assert_eq!(buf.layers()[0].name, "Loop");
    }

    #[test]
    fn loop_ipv6_all_values() {
        for af in [24u32, 28, 30] {
            let (result, family) = dissect_ok(&LoopDissector, &af.to_be_bytes());
            assert_eq!(family, af);
            assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
        }
    }

    #[test]
    fn loop_ipx_ends_chain() {
        let (result, family) = dissect_ok(&LoopDissector, &23u32.to_be_bytes());
        assert_eq!(family, 23);
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn loop_little_endian_value_not_swapped() {
        // LINKTYPE_LOOP is always big-endian; a little-endian 2 is 0x02000000.
        let (result, family) = dissect_ok(&LoopDissector, &[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(family, 0x0200_0000);
        assert_eq!(result.next, DispatchHint::End);
    }

    #[test]
    fn loop_truncated() {
        let mut buf = DissectBuffer::new();
        let err = LoopDissector.dissect(&[], &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 0
            }
        );
    }

    #[test]
    fn family_display_names() {
        let display = FIELD_DESCRIPTORS[FD_FAMILY].display_fn.unwrap();
        assert_eq!(display(&FieldValue::U32(2), &[]), Some("IPv4"));
        assert_eq!(display(&FieldValue::U32(7), &[]), Some("OSI"));
        assert_eq!(display(&FieldValue::U32(23), &[]), Some("IPX"));
        for af in [24, 28, 30] {
            assert_eq!(display(&FieldValue::U32(af), &[]), Some("IPv6"));
        }
        assert_eq!(display(&FieldValue::U32(99), &[]), None);
        assert_eq!(display(&FieldValue::U8(2), &[]), None);
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(NullDissector.name(), "BSD loopback encapsulation");
        assert_eq!(NullDissector.short_name(), "Null");
        assert_eq!(NullDissector.field_descriptors().len(), 1);
        assert_eq!(NullDissector.references()[0].id, "LINKTYPE_NULL");
        assert_eq!(NullDissector.layer(), Some(ProtocolLayer::Link));
        assert_eq!(LoopDissector.name(), "OpenBSD loopback encapsulation");
        assert_eq!(LoopDissector.short_name(), "Loop");
        assert_eq!(LoopDissector.field_descriptors().len(), 1);
        assert_eq!(LoopDissector.references()[0].id, "LINKTYPE_LOOP");
        assert_eq!(LoopDissector.layer(), Some(ProtocolLayer::Link));
    }
}
