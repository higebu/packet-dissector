//! VRRP (Virtual Router Redundancy Protocol) dissector.
//!
//! Decodes VRRPv3 (RFC 9568) and VRRPv2 (RFC 3768) advertisements. The
//! header layout is selected by the Version field.
//!
//! ## References
//! - RFC 9568 (VRRPv3): <https://www.rfc-editor.org/rfc/rfc9568>
//! - RFC 3768 (VRRPv2): <https://www.rfc-editor.org/rfc/rfc3768>

#![deny(missing_docs)]

use packet_dissector_core::checksum::{
    ChecksumStatus, checksum_status_descriptor, internet_checksum, verify_pseudo_header_checksum,
};
use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_ipv6_addr};

/// Minimum VRRP header size in bytes (Version/Type + VRID + Priority +
/// Count + Rsvd/MaxAdvInt + Checksum).
/// RFC 9568, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9568#section-5.1>
const HEADER_SIZE: usize = 8;

/// VRRPv2 version number.
/// RFC 3768, Section 5.3.1 — <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.1>
const VERSION_2: u8 = 2;

/// VRRPv3 version number.
/// RFC 9568, Section 5.2.1 — <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.1>
const VERSION_3: u8 = 3;

/// Size of the VRRPv2 Authentication Data trailer in bytes.
/// RFC 3768, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc3768#section-5.1>
const V2_AUTH_DATA_SIZE: usize = 8;

/// Size of a single IPv4 address in bytes.
const IPV4_ADDR_SIZE: usize = 4;

/// Size of a single IPv6 address in bytes.
const IPV6_ADDR_SIZE: usize = 16;

/// Returns a human-readable name for the VRRP type field.
///
/// RFC 9568, Section 5.2.2 — <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.2>
fn vrrp_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("ADVERTISEMENT"),
        _ => None,
    }
}

/// Returns a human-readable name for well-known VRRP priority values.
///
/// RFC 9568, Section 5.2.4 — <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.4>
fn priority_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Stop participating"),
        255 => Some("Address owner"),
        _ => None,
    }
}

/// Returns a human-readable name for the VRRPv2 Authentication Type field.
///
/// RFC 3768, Section 5.3.6 — <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.6>
fn auth_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("No Authentication"),
        1 | 2 => Some("Reserved"),
        _ => None,
    }
}

/// Determines whether the encapsulating IP layer is IPv6.
///
/// Inspects previously dissected layers in the buffer to find the most recent
/// IP layer. Returns `true` if the preceding IP layer is "IPv6", `false` if
/// "IPv4", and defaults to `false` when no IP layer is found.
fn is_ipv6(buf: &DissectBuffer) -> bool {
    for layer in buf.layers().iter().rev() {
        match layer.name {
            "IPv6" => return true,
            "IPv4" => return false,
            _ => continue,
        }
    }
    false
}

/// Child field descriptor index for the address entry.
const FD_ADDRESS_ENTRY: usize = 0;

/// Child field descriptors for the `addresses` array.
///
/// RFC 9568, Section 5.2.9 — <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.9>
///
/// The concrete address family (IPv4 vs IPv6) is inferred from the
/// encapsulating IP layer at dissect time, so the descriptor uses
/// [`FieldType::Bytes`] as a generic container; the pushed
/// [`FieldValue::Ipv4Addr`] / [`FieldValue::Ipv6Addr`] values carry
/// canonical textual formatting via their [`core::fmt::Display`] impls.
static ADDRESS_CHILD_FIELDS: &[FieldDescriptor] =
    &[FieldDescriptor::new("address", "Address", FieldType::Bytes)];

/// Field descriptors for the VRRP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => vrrp_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("vrid", "Virtual Router ID", FieldType::U8),
    FieldDescriptor {
        name: "priority",
        display_name: "Priority",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(p) => priority_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("addr_count", "IPvX Addr Count", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8).optional(),
    FieldDescriptor::new("max_advert_int", "Max Advertise Interval", FieldType::U16).optional(),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("addresses", "IPvX Addresses", FieldType::Array)
        .optional()
        .with_children(ADDRESS_CHILD_FIELDS),
    FieldDescriptor {
        name: "auth_type",
        display_name: "Authentication Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => auth_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("advert_int", "Advertisement Interval", FieldType::U8).optional(),
    FieldDescriptor::new(
        "authentication_data",
        "Authentication Data",
        FieldType::Bytes,
    )
    .optional(),
    checksum_status_descriptor("checksum_status", "Checksum Status"),
];

/// Index constants for `FIELD_DESCRIPTORS`.
const FD_VERSION: usize = 0;
const FD_TYPE: usize = 1;
const FD_VRID: usize = 2;
const FD_PRIORITY: usize = 3;
const FD_ADDR_COUNT: usize = 4;
const FD_RESERVED: usize = 5;
const FD_MAX_ADVERT_INT: usize = 6;
const FD_CHECKSUM: usize = 7;
const FD_ADDRESSES: usize = 8;
const FD_AUTH_TYPE: usize = 9;
const FD_ADVERT_INT: usize = 10;
const FD_AUTHENTICATION_DATA: usize = 11;
const FD_CHECKSUM_STATUS: usize = 12;

/// IP protocol number of VRRP, used in the IPv6 checksum pseudo-header.
const IP_PROTO_VRRP: u8 = 112;

/// VRRP dissector.
///
/// Parses VRRPv3 packets as defined in RFC 9568 and VRRPv2 packets as
/// defined in RFC 3768. Other versions are rejected with
/// [`PacketError::InvalidFieldValue`].
///   <https://www.rfc-editor.org/rfc/rfc9568>
///   <https://www.rfc-editor.org/rfc/rfc3768>
pub struct VrrpDissector;

/// Specification references for the VRRP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 9568",
        "Virtual Router Redundancy Protocol (VRRP) Version 3 for IPv4 and IPv6",
        "https://www.rfc-editor.org/rfc/rfc9568",
    ),
    SpecReference::new(
        "RFC 3768",
        "Virtual Router Redundancy Protocol (VRRP)",
        "https://www.rfc-editor.org/rfc/rfc3768",
    ),
];

impl Dissector for VrrpDissector {
    fn name(&self) -> &'static str {
        "Virtual Router Redundancy Protocol"
    }

    fn short_name(&self) -> &'static str {
        "VRRP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 9568, Section 5.1 — Packet Format (fixed header fields)
        //   <https://www.rfc-editor.org/rfc/rfc9568#section-5.1>
        // RFC 3768, Section 5.1 — VRRP Packet Format
        //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.1>
        // Bytes 0..4 and the checksum share the same layout in both versions.
        let version = (data[0] >> 4) & 0x0F;
        let vrrp_type = data[0] & 0x0F;
        let vrid = data[1];
        let priority = data[2];
        let addr_count = data[3];
        let checksum = read_be_u16(data, 6)?;

        if version != VERSION_2 && version != VERSION_3 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        let is_v2 = version == VERSION_2;

        // RFC 9568, Section 5.2.9 — IPvX Address(es)
        //   <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.9>
        // The address family is not encoded in the VRRP header; infer it from
        // the encapsulating IP layer that was already dissected. VRRPv2 is
        // defined for IPv4 only (RFC 3768, Section 5.3.9 —
        // <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.9>).
        let ipv6 = !is_v2 && is_ipv6(buf);
        let addr_size = if ipv6 { IPV6_ADDR_SIZE } else { IPV4_ADDR_SIZE };
        let count = addr_count as usize;
        let mut pos = HEADER_SIZE;

        let addrs_end = HEADER_SIZE + count * addr_size;
        // RFC 3768, Section 5.1 — VRRPv2 appends 8 bytes of Authentication
        // Data after the IP addresses.
        //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.1>
        let total_pos = if is_v2 {
            addrs_end + V2_AUTH_DATA_SIZE
        } else {
            addrs_end
        };
        if data.len() < total_pos {
            return Err(PacketError::Truncated {
                expected: total_pos,
                actual: data.len(),
            });
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_pos,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(vrrp_type),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VRID],
            FieldValue::U8(vrid),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PRIORITY],
            FieldValue::U8(priority),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ADDR_COUNT],
            FieldValue::U8(addr_count),
            offset + 3..offset + 4,
        );
        if is_v2 {
            // RFC 3768, Section 5.3.6 — Authentication Type (8 bits)
            //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.6>
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_AUTH_TYPE],
                FieldValue::U8(data[4]),
                offset + 4..offset + 5,
            );
            // RFC 3768, Section 5.3.7 — Advertisement Interval (seconds)
            //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.7>
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ADVERT_INT],
                FieldValue::U8(data[5]),
                offset + 5..offset + 6,
            );
        } else {
            // RFC 9568, Sections 5.2.6 & 5.2.7 — Reserve (4 bits) and
            // Max Advertise Interval (12 bits) share bytes 4..6.
            //   <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.6>
            //   <https://www.rfc-editor.org/rfc/rfc9568#section-5.2.7>
            let reserved = (data[4] >> 4) & 0x0F;
            let max_advert_int = read_be_u16(data, 4)? & 0x0FFF;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_RESERVED],
                FieldValue::U8(reserved),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_MAX_ADVERT_INT],
                FieldValue::U16(max_advert_int),
                offset + 4..offset + 6,
            );
        }
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(checksum),
            offset + 6..offset + 8,
        );
        if buf.verify_checksums() {
            // RFC 9568, Section 5.2.8 — "For the IPv4 address family, the
            // checksum calculation only includes the VRRP message starting
            // with the Version field and ending after the last IPv4
            // address"; for IPv6 it "also includes a prepended
            // "pseudo-header"". RFC 3768, Section 5.3.8 — VRRPv2 covers the
            // entire VRRP message (including Authentication Data).
            // https://www.rfc-editor.org/rfc/rfc9568#section-5.2.8
            // https://www.rfc-editor.org/rfc/rfc3768#section-5.3.8
            let status = if ipv6 {
                verify_pseudo_header_checksum(buf, offset, IP_PROTO_VRRP, data, Some(total_pos))
            } else if internet_checksum(&[&data[..total_pos]]) == 0 {
                ChecksumStatus::Good
            } else if !is_v2
                && verify_pseudo_header_checksum(buf, offset, IP_PROTO_VRRP, data, Some(total_pos))
                    == ChecksumStatus::Good
            {
                // RFC 5798, Section 5.2.8 included the pseudo-header for IPv4
                // as well; RFC 9568, Section 1.1 clarified that it does not.
                // Senders that follow RFC 5798 are still valid.
                // https://www.rfc-editor.org/rfc/rfc5798#section-5.2.8
                // https://www.rfc-editor.org/rfc/rfc9568#section-1.1
                ChecksumStatus::Good
            } else {
                ChecksumStatus::Bad
            };
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_CHECKSUM_STATUS],
                status.to_field_value(),
                offset + 6..offset + 8,
            );
        }

        if count > 0 {
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_ADDRESSES],
                FieldValue::Array(0..0),
                offset + HEADER_SIZE..offset + addrs_end,
            );

            for _ in 0..count {
                if ipv6 {
                    let addr = read_ipv6_addr(data, pos)?;
                    buf.push_field(
                        &ADDRESS_CHILD_FIELDS[FD_ADDRESS_ENTRY],
                        FieldValue::Ipv6Addr(addr),
                        offset + pos..offset + pos + IPV6_ADDR_SIZE,
                    );
                } else {
                    let addr = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                    buf.push_field(
                        &ADDRESS_CHILD_FIELDS[FD_ADDRESS_ENTRY],
                        FieldValue::Ipv4Addr(addr),
                        offset + pos..offset + pos + IPV4_ADDR_SIZE,
                    );
                }
                pos += addr_size;
            }

            buf.end_container(array_idx);
        }

        if is_v2 {
            // RFC 3768, Section 5.3.10 — Authentication Data
            //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.10>
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_AUTHENTICATION_DATA],
                FieldValue::Bytes(&data[addrs_end..total_pos]),
                offset + addrs_end..offset + total_pos,
            );
        }

        buf.end_layer();

        Ok(DissectResult::new(total_pos, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FormatContext;

    // # RFC 9568 (VRRP) Coverage
    //
    // | RFC Section | Description                   | Test                                |
    // |-------------|-------------------------------|-------------------------------------|
    // | 5.1         | Minimum header truncation     | parse_vrrp_truncated                |
    // | 5.2.1       | Version                       | parse_vrrp_ipv4_advertisement       |
    // | 5.2.2       | Type (Advertisement)          | parse_vrrp_ipv4_advertisement       |
    // | 5.2.3       | Virtual Router ID             | parse_vrrp_ipv4_advertisement       |
    // | 5.2.4       | Priority (default backup)     | parse_vrrp_ipv4_advertisement       |
    // | 5.2.4       | Priority 255 (address owner)  | parse_vrrp_priority_owner           |
    // | 5.2.4       | Priority 0 (stop)             | parse_vrrp_priority_stop            |
    // | 5.2.5       | IPvX Addr Count               | parse_vrrp_multiple_ipv4_addrs      |
    // | 5.2.5       | Zero addr count               | parse_vrrp_zero_addr_count          |
    // | 5.2.5       | Truncated addresses           | parse_vrrp_truncated_addresses      |
    // | 5.2.6       | Reserved (bit masking)        | parse_vrrp_reserved_bits_nonzero    |
    // | 5.2.7       | Max Advertise Interval        | parse_vrrp_ipv4_advertisement       |
    // | 5.2.7       | Max Advertise Interval 12-bit | parse_vrrp_max_advert_int_12bit_max |
    // | 5.2.8       | Checksum                      | parse_vrrp_ipv4_advertisement       |
    // | 5.2.8       | Checksum verified (IPv4)      | checksum_status_ipv4                |
    // | 5.2.8       | IPv6 without IP addresses     | checksum_status_ipv6_without_ip_layer_fields |
    // | 5.2.8 (5798) | IPv4 with RFC 5798 pseudo-header | checksum_status_ipv4_rfc5798_pseudo_header |
    // | 5.2.9       | IPvX Addresses (IPv4)         | parse_vrrp_ipv4_advertisement       |
    // | 5.2.9       | IPvX Addresses (IPv6)         | parse_vrrp_ipv6_advertisement       |
    // | 5.2.9       | Address serialization         | address_child_field_has_no_format_fn|
    // | —           | Default address family (IPv4) | parse_vrrp_no_ip_layer_defaults_ipv4|
    // | —           | Unsupported version rejected  | parse_vrrp_unsupported_version      |
    //
    // # RFC 3768 (VRRPv2) Coverage
    //
    // | RFC Section | Description                   | Test                                |
    // |-------------|-------------------------------|-------------------------------------|
    // | 5.1         | Packet Format (v2 layout)     | parse_vrrpv2_ipv4_advertisement     |
    // | 5.1         | Truncated Authentication Data | parse_vrrpv2_truncated_auth_data    |
    // | 5.3.1       | Version 2                     | parse_vrrpv2_ipv4_advertisement     |
    // | 5.3.6       | Auth Type 0 (No Auth)         | parse_vrrpv2_ipv4_advertisement     |
    // | 5.3.6       | Auth Type 1 (Reserved)        | parse_vrrpv2_auth_type_reserved     |
    // | 5.3.7       | Adver Int (seconds)           | parse_vrrpv2_ipv4_advertisement     |
    // | 5.3.9       | IP Address(es)                | parse_vrrpv2_ipv4_advertisement     |
    // | 5.3.10      | Authentication Data           | parse_vrrpv2_auth_type_reserved     |
    // | 5.3.8       | Checksum verified (VRRPv2)    | checksum_status_vrrpv2              |

    /// Helper: builds a DissectBuffer with an IPv4 layer already present, simulating
    /// the registry dispatch chain.
    fn buf_with_ipv4_layer() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv4", None, &[], 0..20);
        buf.end_layer();
        buf
    }

    /// Helper: builds a DissectBuffer with an IPv6 layer already present.
    fn buf_with_ipv6_layer() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv6", None, &[], 0..40);
        buf.end_layer();
        buf
    }

    #[test]
    fn parse_vrrp_ipv4_advertisement() {
        // VRRPv3 Advertisement: VRID=1, Priority=100, 1 IPv4 addr (192.168.1.1)
        // Max Advert Int = 100 centiseconds (1 sec)
        let raw: &[u8] = &[
            0x31, // Version=3, Type=1 (Advertisement)
            0x01, // VRID=1
            0x64, // Priority=100
            0x01, // Count=1
            0x00, 0x64, // Rsvd=0, MaxAdvInt=100
            0xA8, 0xFD, // Checksum
            192, 168, 1, 1, // IPv4 address
        ];

        let mut buf = buf_with_ipv4_layer();
        let result = VrrpDissector.dissect(raw, &mut buf, 20).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        assert!(matches!(result.next, DispatchHint::End));

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("ADVERTISEMENT")
        );
        assert_eq!(
            buf.field_by_name(layer, "vrid").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(100)
        );
        assert!(buf.resolve_display_name(layer, "priority_name").is_none());
        assert_eq!(
            buf.field_by_name(layer, "addr_count").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "max_advert_int").unwrap().value,
            FieldValue::U16(100)
        );
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xA8FD)
        );

        // Check address array — addresses are pushed as flat Array children.
        let addresses_field = buf.field_by_name(layer, "addresses").unwrap();
        if let FieldValue::Array(ref range) = addresses_field.value {
            let elems = buf.nested_fields(range);
            assert_eq!(elems.len(), 1);
            assert_eq!(elems[0].value, FieldValue::Ipv4Addr([192, 168, 1, 1]));
            assert_eq!(elems[0].descriptor.display_name, "Address");
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_vrrp_ipv6_advertisement() {
        // VRRPv3 Advertisement: VRID=2, Priority=200, 1 IPv6 addr (fe80::1)
        let raw: &[u8] = &[
            0x31, // Version=3, Type=1
            0x02, // VRID=2
            0xC8, // Priority=200
            0x01, // Count=1
            0x01, 0x00, // Rsvd=0, MaxAdvInt=256
            0x00, 0x00, // Checksum
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fe80::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let mut buf = buf_with_ipv6_layer();
        let result = VrrpDissector.dissect(raw, &mut buf, 40).unwrap();

        assert_eq!(result.bytes_consumed, 24);

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "vrid").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(200)
        );

        let addresses_field = buf.field_by_name(layer, "addresses").unwrap();
        if let FieldValue::Array(ref range) = addresses_field.value {
            let elems = buf.nested_fields(range);
            assert_eq!(elems.len(), 1);
            let expected: [u8; 16] = [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ];
            assert_eq!(elems[0].value, FieldValue::Ipv6Addr(expected));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_vrrp_multiple_ipv4_addrs() {
        // 2 IPv4 addresses
        let raw: &[u8] = &[
            0x31, 0x01, 0x64, 0x02, // v3, type=1, vrid=1, pri=100, count=2
            0x00, 0x64, 0x00, 0x00, // rsvd=0, maxadvint=100, cksum=0
            10, 0, 0, 1, // addr 1
            10, 0, 0, 2, // addr 2
        ];

        let mut buf = buf_with_ipv4_layer();
        let result = VrrpDissector.dissect(raw, &mut buf, 20).unwrap();
        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("VRRP").unwrap();
        let addresses_field = buf.field_by_name(layer, "addresses").unwrap();
        if let FieldValue::Array(ref range) = addresses_field.value {
            let elems = buf.nested_fields(range);
            assert_eq!(elems.len(), 2);
            assert_eq!(elems[0].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
            assert_eq!(elems[1].value, FieldValue::Ipv4Addr([10, 0, 0, 2]));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_vrrp_priority_owner() {
        // Priority 255 = address owner
        let raw: &[u8] = &[
            0x31, 0x01, 0xFF, 0x01, 0x00, 0x64, 0x00, 0x00, 192, 168, 1, 1,
        ];

        let mut buf = buf_with_ipv4_layer();
        VrrpDissector.dissect(raw, &mut buf, 20).unwrap();

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(255)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "priority_name"),
            Some("Address owner")
        );
    }

    #[test]
    fn parse_vrrp_priority_stop() {
        // Priority 0 = stop participating
        let raw: &[u8] = &[
            0x31, 0x01, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 192, 168, 1, 1,
        ];

        let mut buf = buf_with_ipv4_layer();
        VrrpDissector.dissect(raw, &mut buf, 20).unwrap();

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "priority").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "priority_name"),
            Some("Stop participating")
        );
    }

    #[test]
    fn parse_vrrp_truncated() {
        let raw: &[u8] = &[0x31, 0x01, 0x64];
        let mut buf = DissectBuffer::new();
        let err = VrrpDissector.dissect(raw, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_vrrp_zero_addr_count() {
        // Count=0: header only, no addresses field
        let raw: &[u8] = &[
            0x31, 0x01, 0x64, 0x00, // count=0
            0x00, 0x64, 0x00, 0x00,
        ];

        let mut buf = buf_with_ipv4_layer();
        let result = VrrpDissector.dissect(raw, &mut buf, 20).unwrap();
        assert_eq!(result.bytes_consumed, 8);

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert!(buf.field_by_name(layer, "addresses").is_none());
    }

    #[test]
    fn parse_vrrp_no_ip_layer_defaults_ipv4() {
        // When no IP layer is present, default to IPv4 address parsing
        let raw: &[u8] = &[0x31, 0x01, 0x64, 0x01, 0x00, 0x64, 0x00, 0x00, 10, 0, 0, 1];

        let mut buf = DissectBuffer::new();
        let result = VrrpDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 12);

        let layer = buf.layer_by_name("VRRP").unwrap();
        let addresses_field = buf.field_by_name(layer, "addresses").unwrap();
        if let FieldValue::Array(ref range) = addresses_field.value {
            let elems = buf.nested_fields(range);
            assert_eq!(elems.len(), 1);
            assert_eq!(elems[0].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn parse_vrrp_truncated_addresses() {
        // Count=2 but only 1 address worth of data — must return Truncated
        let raw: &[u8] = &[
            0x31, 0x01, 0x64, 0x02, // count=2
            0x00, 0x64, 0x00, 0x00, 10, 0, 0, 1, // only 1 addr
        ];

        let mut buf = buf_with_ipv4_layer();
        let err = VrrpDissector.dissect(raw, &mut buf, 20).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 16, // HEADER_SIZE + 2 * 4
                actual: 12
            }
        ));
    }

    #[test]
    fn parse_vrrp_max_advert_int_12bit_max() {
        // RFC 9568, Section 5.2.7 — Max Advertise Interval is 12 bits; max value
        // is 0xFFF (4095 centiseconds). Section 5.2.6 — Reserve bits are masked
        // out of the advertise interval.
        let raw: &[u8] = &[
            0x31, 0x01, 0x64, 0x01, // v3, type=1, vrid=1, pri=100, count=1
            0x0F, 0xFF, // Reserve=0, MaxAdvInt=0xFFF
            0x00, 0x00, // checksum
            10, 0, 0, 1,
        ];
        let mut buf = buf_with_ipv4_layer();
        VrrpDissector.dissect(raw, &mut buf, 20).unwrap();

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "max_advert_int").unwrap().value,
            FieldValue::U16(0x0FFF)
        );
    }

    #[test]
    fn parse_vrrp_reserved_bits_nonzero() {
        // RFC 9568, Section 5.2.6 — Reserve "MUST be set to zero on transmission
        // and ignored on reception." Non-zero reserved bits MUST NOT leak into
        // the Max Advertise Interval field.
        let raw: &[u8] = &[
            0x31, 0x01, 0x64, 0x01, // v3, type=1, vrid=1, pri=100, count=1
            0xF1, 0x23, // Reserve=0xF, MaxAdvInt=0x123
            0x00, 0x00, // checksum
            10, 0, 0, 1,
        ];
        let mut buf = buf_with_ipv4_layer();
        VrrpDissector.dissect(raw, &mut buf, 20).unwrap();

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "reserved").unwrap().value,
            FieldValue::U8(0x0F)
        );
        assert_eq!(
            buf.field_by_name(layer, "max_advert_int").unwrap().value,
            FieldValue::U16(0x123)
        );
    }

    #[test]
    fn parse_vrrpv2_ipv4_advertisement() {
        // RFC 3768, Section 5.1 — VRRPv2 packet: Auth Type and Adver Int
        // occupy bytes 4..6 and 8 bytes of Authentication Data follow the
        // IP addresses.
        //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.1>
        let raw: &[u8] = &[
            0x21, // Version=2, Type=1 (Advertisement)
            0x01, // VRID=1
            0x64, // Priority=100
            0x01, // Count IP Addrs=1
            0x00, // Auth Type=0 (No Authentication)
            0x01, // Adver Int=1 second
            0xB8, 0xFA, // Checksum
            192, 0, 2, 1, // IP Address
            0, 0, 0, 0, 0, 0, 0, 0, // Authentication Data
        ];

        let mut buf = buf_with_ipv4_layer();
        let result = VrrpDissector.dissect(raw, &mut buf, 20).unwrap();
        assert_eq!(result.bytes_consumed, 20);

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(layer.range, 20..40);
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_type").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "auth_type_name"),
            Some("No Authentication")
        );
        let advert_int = buf.field_by_name(layer, "advert_int").unwrap();
        assert_eq!(advert_int.value, FieldValue::U8(1));
        assert_eq!(advert_int.range, 25..26);
        assert_eq!(
            buf.field_by_name(layer, "checksum").unwrap().value,
            FieldValue::U16(0xB8FA)
        );
        assert!(buf.field_by_name(layer, "reserved").is_none());
        assert!(buf.field_by_name(layer, "max_advert_int").is_none());

        let addresses_field = buf.field_by_name(layer, "addresses").unwrap();
        if let FieldValue::Array(ref range) = addresses_field.value {
            let elems = buf.nested_fields(range);
            assert_eq!(elems.len(), 1);
            assert_eq!(elems[0].value, FieldValue::Ipv4Addr([192, 0, 2, 1]));
        } else {
            panic!("expected Array");
        }

        let auth = buf.field_by_name(layer, "authentication_data").unwrap();
        assert_eq!(auth.value, FieldValue::Bytes(&[0; 8]));
        assert_eq!(auth.range, 32..40);
    }

    #[test]
    fn parse_vrrpv2_auth_type_reserved() {
        // RFC 3768, Section 5.3.6.2 — Auth Type 1 is reserved for RFC 2338
        // compatibility (simple text password). Section 5.3.10 —
        // Authentication Data carries the legacy password.
        //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.3.6.2>
        //   <https://www.rfc-editor.org/rfc/rfc2338>
        let raw: &[u8] = &[
            0x21, 0x07, 0xFF, 0x00, // v2, type=1, vrid=7, pri=255, count=0
            0x01, 0x03, // Auth Type=1, Adver Int=3
            0x00, 0x00, // Checksum
            b'p', b'a', b's', b's', b'w', b'o', b'r', b'd',
        ];

        let mut buf = buf_with_ipv4_layer();
        let result = VrrpDissector.dissect(raw, &mut buf, 20).unwrap();
        assert_eq!(result.bytes_consumed, 16);

        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "auth_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "auth_type_name"),
            Some("Reserved")
        );
        assert_eq!(
            buf.field_by_name(layer, "advert_int").unwrap().value,
            FieldValue::U8(3)
        );
        assert!(buf.field_by_name(layer, "addresses").is_none());
        assert_eq!(
            buf.field_by_name(layer, "authentication_data")
                .unwrap()
                .value,
            FieldValue::Bytes(b"password")
        );
    }

    #[test]
    fn parse_vrrpv2_truncated_auth_data() {
        // RFC 3768, Section 5.1 — the 8-byte Authentication Data trailer is
        // part of every VRRPv2 packet.
        //   <https://www.rfc-editor.org/rfc/rfc3768#section-5.1>
        let raw: &[u8] = &[
            0x21, 0x01, 0x64, 0x01, 0x00, 0x01, 0x00, 0x00, 192, 0, 2, 1, 0, 0, 0, 0,
        ];
        let mut buf = buf_with_ipv4_layer();
        let err = VrrpDissector.dissect(raw, &mut buf, 20).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 20,
                actual: 16
            }
        ));
    }

    #[test]
    fn parse_vrrp_unsupported_version() {
        // Only VRRPv2 (RFC 3768) and VRRPv3 (RFC 9568) are defined.
        //   <https://www.rfc-editor.org/rfc/rfc3768>
        //   <https://www.rfc-editor.org/rfc/rfc9568>
        for first in [0x11u8, 0x41] {
            let raw: &[u8] = &[first, 0x01, 0x64, 0x00, 0x00, 0x64, 0x00, 0x00];
            let mut buf = buf_with_ipv4_layer();
            let err = VrrpDissector.dissect(raw, &mut buf, 20).unwrap_err();
            assert!(matches!(
                err,
                PacketError::InvalidFieldValue {
                    field: "version",
                    value
                } if value == u32::from(first >> 4)
            ));
        }
    }

    #[test]
    fn vrrpv3_has_no_v2_fields() {
        let raw: &[u8] = &[0x31, 0x01, 0x64, 0x01, 0x00, 0x64, 0x00, 0x00, 10, 0, 0, 1];
        let mut buf = buf_with_ipv4_layer();
        VrrpDissector.dissect(raw, &mut buf, 20).unwrap();
        let layer = buf.layer_by_name("VRRP").unwrap();
        assert!(buf.field_by_name(layer, "auth_type").is_none());
        assert!(buf.field_by_name(layer, "advert_int").is_none());
        assert!(buf.field_by_name(layer, "authentication_data").is_none());
    }

    fn call_format_fn(
        f: fn(&FieldValue<'_>, &FormatContext<'_>, &mut dyn std::io::Write) -> std::io::Result<()>,
        value: &FieldValue<'_>,
    ) -> String {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        f(value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn address_child_field_has_no_format_fn() {
        // RFC 9568, Section 5.2.9 — IPvX Address(es) are pushed as
        // FieldValue::Ipv4Addr / Ipv6Addr, whose Display impls yield the
        // canonical textual form. A custom format_fn intended for raw bytes
        // (such as format_utf8_lossy) would emit an empty string for these
        // variants and must not be attached.
        let desc = &ADDRESS_CHILD_FIELDS[FD_ADDRESS_ENTRY];
        assert!(
            desc.format_fn.is_none(),
            "ADDRESS_CHILD_FIELDS must not override formatting for IP address values"
        );

        // If a format_fn is ever added, it must handle Ipv4Addr and Ipv6Addr.
        if let Some(f) = desc.format_fn {
            assert_ne!(
                call_format_fn(f, &FieldValue::Ipv4Addr([192, 168, 1, 1])),
                "\"\""
            );
            assert_ne!(
                call_format_fn(
                    f,
                    &FieldValue::Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                ),
                "\"\""
            );
        }
    }

    #[test]
    fn references_and_layer() {
        let references = VrrpDissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(VrrpDissector.layer(), Some(ProtocolLayer::Network));
    }

    fn checksum_status(buf: &DissectBuffer<'_>) -> Option<u8> {
        let layer = buf.layer_by_name("VRRP").unwrap();
        buf.field_by_name(layer, "checksum_status")
            .and_then(|f| f.value.as_u8())
    }

    #[test]
    fn checksum_status_ipv4() {
        // RFC 9568, Section 5.2.8 — for IPv4 no pseudo-header; the message
        // ends after the last IPv4 address.
        // https://www.rfc-editor.org/rfc/rfc9568#section-5.2.8
        let mut raw = vec![
            0x31, 0x01, 0x64, 0x01, 0x00, 0x64, 0x00, 0x00, 192, 168, 1, 1,
        ];
        let c = packet_dissector_core::checksum::internet_checksum(&[&raw]);
        raw[6..8].copy_from_slice(&c.to_be_bytes());
        raw.extend_from_slice(&[0xEE, 0xEE]); // trailing bytes are not covered

        let mut buf = buf_with_ipv4_layer();
        VrrpDissector.dissect(&raw, &mut buf, 20).unwrap();
        assert_eq!(checksum_status(&buf), None);

        let mut buf = buf_with_ipv4_layer();
        buf.set_verify_checksums(true);
        VrrpDissector.dissect(&raw, &mut buf, 20).unwrap();
        assert_eq!(checksum_status(&buf), Some(1));
        let layer = buf.layer_by_name("VRRP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "checksum_status").unwrap().range,
            26..28
        );

        raw[2] = 0x65;
        let mut buf = buf_with_ipv4_layer();
        buf.set_verify_checksums(true);
        VrrpDissector.dissect(&raw, &mut buf, 20).unwrap();
        assert_eq!(checksum_status(&buf), Some(0));
    }

    #[test]
    fn checksum_status_vrrpv2() {
        // RFC 3768, Section 5.3.8 — checksum over the entire VRRP message,
        // including the Authentication Data.
        // https://www.rfc-editor.org/rfc/rfc3768#section-5.3.8
        let mut raw = vec![0x21, 0x01, 0x64, 0x01, 0x00, 0x01, 0x00, 0x00, 10, 0, 0, 1];
        raw.extend_from_slice(&[0u8; 8]);
        let c = packet_dissector_core::checksum::internet_checksum(&[&raw]);
        raw[6..8].copy_from_slice(&c.to_be_bytes());
        let mut buf = buf_with_ipv4_layer();
        buf.set_verify_checksums(true);
        VrrpDissector.dissect(&raw, &mut buf, 20).unwrap();
        assert_eq!(checksum_status(&buf), Some(1));

        raw[19] = 1; // Authentication Data
        let mut buf = buf_with_ipv4_layer();
        buf.set_verify_checksums(true);
        VrrpDissector.dissect(&raw, &mut buf, 20).unwrap();
        assert_eq!(checksum_status(&buf), Some(0));
    }

    #[test]
    fn checksum_status_ipv6_without_ip_layer_fields() {
        // The IPv6 pseudo-header needs the IPv6 addresses; the helper layer
        // has none, so the checksum cannot be verified.
        let mut raw = vec![0x31, 0x01, 0x64, 0x01, 0x00, 0x64, 0x00, 0x00];
        raw.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut buf = buf_with_ipv6_layer();
        buf.set_verify_checksums(true);
        VrrpDissector.dissect(&raw, &mut buf, 40).unwrap();
        assert_eq!(checksum_status(&buf), Some(2));
    }

    #[test]
    fn checksum_status_ipv4_rfc5798_pseudo_header() {
        // RFC 5798, Section 5.2.8 included a pseudo-header for IPv4 too;
        // RFC 9568, Section 1.1 clarified that it does not. Implementations
        // following RFC 5798 are still accepted.
        // https://www.rfc-editor.org/rfc/rfc5798#section-5.2.8
        // https://www.rfc-editor.org/rfc/rfc9568#section-1.1
        static IPV4_FIELDS: &[FieldDescriptor] = &[
            FieldDescriptor::new("total_length", "Total Length", FieldType::U16),
            FieldDescriptor::new("flags", "Flags", FieldType::U8),
            FieldDescriptor::new("fragment_offset", "Fragment Offset", FieldType::U16),
            FieldDescriptor::new("src", "Source Address", FieldType::Ipv4Addr),
            FieldDescriptor::new("dst", "Destination Address", FieldType::Ipv4Addr),
        ];
        let src = [192, 168, 1, 2];
        let dst = [224, 0, 0, 18];
        let mut raw = vec![
            0x31, 0x01, 0x64, 0x01, 0x00, 0x64, 0x00, 0x00, 192, 168, 1, 1,
        ];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.extend_from_slice(&[0, 112, 0, raw.len() as u8]);
        let c = packet_dissector_core::checksum::internet_checksum(&[&pseudo, &raw]);
        raw[6..8].copy_from_slice(&c.to_be_bytes());

        let mut buf = DissectBuffer::new();
        buf.set_verify_checksums(true);
        buf.begin_layer("IPv4", None, IPV4_FIELDS, 0..20);
        buf.push_field(&IPV4_FIELDS[0], FieldValue::U16(32), 2..4);
        buf.push_field(&IPV4_FIELDS[1], FieldValue::U8(0), 6..7);
        buf.push_field(&IPV4_FIELDS[2], FieldValue::U16(0), 6..8);
        buf.push_field(&IPV4_FIELDS[3], FieldValue::Ipv4Addr(src), 12..16);
        buf.push_field(&IPV4_FIELDS[4], FieldValue::Ipv4Addr(dst), 16..20);
        buf.end_layer();
        VrrpDissector.dissect(&raw, &mut buf, 20).unwrap();
        assert_eq!(checksum_status(&buf), Some(1));
    }
}
