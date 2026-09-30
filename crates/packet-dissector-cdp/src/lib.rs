//! CDP (Cisco Discovery Protocol) dissector.
//!
//! CDP is carried in IEEE 802.3 frames with an LLC/SNAP header whose
//! Organization Code is Cisco's (00-00-0C) and whose Protocol Identifier is
//! 0x2000, sent to 01-00-0C-CC-CC-CC. The PDU is a 4-octet header (Version,
//! TTL, Checksum) followed by TLVs whose 16-bit Length includes the 4-octet
//! TLV header.
//!
//! CDP has no IETF or IEEE specification. The frame layout follows Cisco's
//! description of CDP; TLV type names and the Addresses TLV encoding follow
//! Wireshark's and tcpdump's CDP dissectors (secondary sources). The SNAP
//! framing is IEEE Std 802-2014, Clause 10.
//!
//! The checksum is not verified.
//!
//! ## References
//! - Cisco, "Cisco Discovery Protocol Configuration Guide":
//!   <https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cdp/configuration/15-mt/cdp-15-mt-book.html>
//! - Wireshark `packet-cdp.c` (secondary):
//!   <https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cdp.c>
//! - tcpdump `print-cdp.c` (secondary):
//!   <https://github.com/the-tcpdump-group/tcpdump/blob/master/print-cdp.c>
//! - IEEE Std 802-2014, Clause 10 (SNAP): <https://standards.ieee.org/standard/802-2014.html>
//! - ISO/IEC TR 9577 (NLPID 0xCC for IP), as listed in RFC 2427, Section 7:
//!   <https://www.rfc-editor.org/rfc/rfc2427#section-7>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Cisco Organization Code (OUI 00-00-0C) of the SNAP header carrying CDP.
pub const SNAP_OUI_CISCO: u32 = 0x00_000C;

/// SNAP Protocol Identifier of CDP under the Cisco OUI.
pub const SNAP_PID_CDP: u16 = 0x2000;

/// CDP header size: Version (1), TTL (1), Checksum (2).
pub const HEADER_SIZE: usize = 4;

/// TLV header size: Type (2) and Length (2); Length includes it.
const TLV_HEADER_SIZE: usize = 4;

// TLV types (Wireshark `packet-cdp.c`, secondary source).
const TLV_DEVICE_ID: u16 = 0x0001;
const TLV_ADDRESSES: u16 = 0x0002;
const TLV_PORT_ID: u16 = 0x0003;
const TLV_CAPABILITIES: u16 = 0x0004;
const TLV_SOFTWARE_VERSION: u16 = 0x0005;
const TLV_PLATFORM: u16 = 0x0006;
const TLV_VTP_MGMT_DOMAIN: u16 = 0x0009;
const TLV_NATIVE_VLAN: u16 = 0x000A;
const TLV_DUPLEX: u16 = 0x000B;
const TLV_SYSTEM_NAME: u16 = 0x0014;
const TLV_MANAGEMENT_ADDRESSES: u16 = 0x0016;

/// Address protocol type: the protocol field is an OSI NLPID.
const PROTO_TYPE_NLPID: u8 = 1;
/// Address protocol type: the protocol field is an IEEE 802.2 LLC/SNAP header.
const PROTO_TYPE_IEEE_802_2: u8 = 2;
/// NLPID of IP (ISO/IEC TR 9577; RFC 2427, Section 7 —
/// <https://www.rfc-editor.org/rfc/rfc2427#section-7>).
const NLPID_IP: u8 = 0xCC;
/// LLC/SNAP header announcing IPv6 (DSAP/SSAP 0xAA, UI, OUI 0, EtherType
/// 0x86DD), used as the protocol of an IPv6 address entry.
const LLC_SNAP_IPV6: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD];

/// Returns the name of a CDP TLV type (Wireshark `packet-cdp.c`, secondary
/// source).
pub fn tlv_type_name(tlv_type: u16) -> Option<&'static str> {
    match tlv_type {
        0x0001 => Some("Device ID"),
        0x0002 => Some("Addresses"),
        0x0003 => Some("Port ID"),
        0x0004 => Some("Capabilities"),
        0x0005 => Some("Software Version"),
        0x0006 => Some("Platform"),
        0x0007 => Some("IP Prefix"),
        0x0008 => Some("Protocol Hello"),
        0x0009 => Some("VTP Management Domain"),
        0x000A => Some("Native VLAN"),
        0x000B => Some("Duplex"),
        0x000E => Some("VoIP VLAN Reply"),
        0x000F => Some("VoIP VLAN Query"),
        0x0010 => Some("Power Consumption"),
        0x0011 => Some("MTU"),
        0x0012 => Some("Trust Bitmap"),
        0x0013 => Some("Untrusted Port CoS"),
        0x0014 => Some("System Name"),
        0x0015 => Some("System Object ID"),
        0x0016 => Some("Management Addresses"),
        0x0017 => Some("Location"),
        0x0018 => Some("External Port ID"),
        0x0019 => Some("Power Requested"),
        0x001A => Some("Power Available"),
        0x001B => Some("Port Unidirectional"),
        0x001D => Some("EnergyWise"),
        0x001F => Some("Spare PoE"),
        _ => None,
    }
}

/// Returns the name of an Addresses TLV protocol type.
fn protocol_type_name(protocol_type: u8) -> Option<&'static str> {
    match protocol_type {
        PROTO_TYPE_NLPID => Some("NLPID"),
        PROTO_TYPE_IEEE_802_2 => Some("802.2"),
        _ => None,
    }
}

/// Returns the name of a Duplex TLV value.
fn duplex_name(duplex: u8) -> &'static str {
    if duplex == 0 { "Half" } else { "Full" }
}

/// Capabilities TLV bits, least significant first (Wireshark
/// `packet-cdp.c`, secondary source).
static CAPABILITY_BITS: &[FieldDescriptor] = &[
    FieldDescriptor::new("router", "Router", FieldType::U8),
    FieldDescriptor::new("transparent_bridge", "Transparent Bridge", FieldType::U8),
    FieldDescriptor::new("source_route_bridge", "Source Route Bridge", FieldType::U8),
    FieldDescriptor::new("switch", "Switch", FieldType::U8),
    FieldDescriptor::new("host", "Host", FieldType::U8),
    FieldDescriptor::new("igmp_capable", "IGMP Capable", FieldType::U8),
    FieldDescriptor::new("repeater", "Repeater", FieldType::U8),
    FieldDescriptor::new("voip_phone", "VoIP Phone", FieldType::U8),
    FieldDescriptor::new("remotely_managed", "Remotely Managed Device", FieldType::U8),
    FieldDescriptor::new(
        "cvta",
        "CVTA/STP Dispute Resolution/Cisco VT Camera",
        FieldType::U8,
    ),
    FieldDescriptor::new("two_port_mac_relay", "Two Port MAC Relay", FieldType::U8),
];

const FD_ADDR_PROTOCOL_TYPE: usize = 0;
const FD_ADDR_PROTOCOL_LENGTH: usize = 1;
const FD_ADDR_PROTOCOL: usize = 2;
const FD_ADDR_ADDRESS_LENGTH: usize = 3;
const FD_ADDR_ADDRESS: usize = 4;

/// Fields of one Addresses TLV entry.
static ADDRESS_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("protocol_type", "Protocol Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => protocol_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("protocol_length", "Protocol Length", FieldType::U8),
    FieldDescriptor::new("protocol", "Protocol", FieldType::Bytes),
    FieldDescriptor::new("address_length", "Address Length", FieldType::U16),
    // IPv4, IPv6 or raw bytes depending on the protocol.
    FieldDescriptor::new("address", "Address", FieldType::Any),
];

/// One Addresses TLV entry.
static FD_ADDRESS: FieldDescriptor = FieldDescriptor::new("address", "Address", FieldType::Object)
    .with_children(ADDRESS_CHILD_FIELDS);

const FD_TLV_TYPE: usize = 0;
const FD_TLV_LENGTH: usize = 1;
const FD_TLV_STRING: usize = 2;
const FD_TLV_CAPABILITIES: usize = 3;
const FD_TLV_CAPABILITY_FLAGS: usize = 4;
const FD_TLV_NATIVE_VLAN: usize = 5;
const FD_TLV_DUPLEX: usize = 6;
const FD_TLV_ADDRESS_COUNT: usize = 7;
const FD_TLV_ADDRESSES: usize = 8;
const FD_TLV_VALUE: usize = 9;

/// Fields of one TLV.
static TLV_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("string", "Value", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("capabilities", "Capabilities", FieldType::U32).optional(),
    FieldDescriptor::new("capability_flags", "Capability Flags", FieldType::Object)
        .optional()
        .with_children(CAPABILITY_BITS),
    FieldDescriptor::new("native_vlan", "Native VLAN", FieldType::U16).optional(),
    FieldDescriptor::new("duplex", "Duplex", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(d) => Some(duplex_name(*d)),
            _ => None,
        }),
    FieldDescriptor::new("address_count", "Number of Addresses", FieldType::U32).optional(),
    FieldDescriptor::new("addresses", "Addresses", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_ADDRESS)),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

/// One TLV; its label resolves to the TLV name.
static FD_TLV: FieldDescriptor = FieldDescriptor::new("tlv", "TLV", FieldType::Object)
    .with_children(TLV_CHILD_FIELDS)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => tlv_type_name(*t),
            _ => None,
        }),
        _ => None,
    });

const FD_VERSION: usize = 0;
const FD_TTL: usize = 1;
const FD_CHECKSUM: usize = 2;
const FD_TLVS: usize = 3;

/// Field descriptors of the `CDP` layer.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("ttl", "TTL", FieldType::U8),
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_TLV)),
];

/// Specification references for the CDP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "Cisco CDP",
        "Cisco Discovery Protocol Configuration Guide",
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cdp/configuration/15-mt/cdp-15-mt-book.html",
    ),
    SpecReference::new(
        "IEEE 802-2014",
        "IEEE Standard for Local and Metropolitan Area Networks: Overview and Architecture",
        "https://standards.ieee.org/standard/802-2014.html",
    ),
];

/// CDP dissector, registered on SNAP OUI 00-00-0C / PID 0x2000.
pub struct CdpDissector;

impl Dissector for CdpDissector {
    fn name(&self) -> &'static str {
        "Cisco Discovery Protocol"
    }

    fn short_name(&self) -> &'static str {
        "CDP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
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
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mark = buf.field_count() as usize;
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(data[0]),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TTL],
            FieldValue::U8(data[1]),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CHECKSUM],
            FieldValue::U16(read_be_u16(data, 2)?),
            offset + 2..offset + 4,
        );
        if let Err(e) = push_tlvs(data, offset, buf) {
            buf.truncate_fields(mark);
            buf.pop_layer();
            return Err(e);
        }
        buf.end_layer();
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

/// Push the TLVs that follow the header. On error the caller removes the
/// layer, so a malformed PDU leaves nothing behind.
fn push_tlvs<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if data.len() == HEADER_SIZE {
        return Ok(());
    }
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_TLVS],
        FieldValue::Array(0..0),
        offset + HEADER_SIZE..offset + data.len(),
    );
    let mut pos = HEADER_SIZE;
    while pos < data.len() {
        if pos + TLV_HEADER_SIZE > data.len() {
            return Err(PacketError::Truncated {
                expected: pos + TLV_HEADER_SIZE,
                actual: data.len(),
            });
        }
        // The TLV Length includes the 4-octet TLV header.
        let tlv_len = usize::from(read_be_u16(data, pos + 2)?);
        if tlv_len < TLV_HEADER_SIZE {
            return Err(PacketError::InvalidHeader("CDP TLV length is less than 4"));
        }
        let Some(tlv) = data.get(pos..pos + tlv_len) else {
            return Err(PacketError::Truncated {
                expected: pos + tlv_len,
                actual: data.len(),
            });
        };
        push_tlv(tlv, offset + pos, buf)?;
        pos += tlv_len;
    }
    buf.end_container(array_idx);
    Ok(())
}

/// Push one TLV; `tlv` is the whole TLV including its header.
fn push_tlv<'pkt>(
    tlv: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let tlv_type = read_be_u16(tlv, 0)?;
    let value = &tlv[TLV_HEADER_SIZE..];
    let value_offset = offset + TLV_HEADER_SIZE;
    let value_range = value_offset..value_offset + value.len();

    let obj_idx = buf.begin_container(
        &FD_TLV,
        FieldValue::Object(0..0),
        offset..offset + tlv.len(),
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_TYPE],
        FieldValue::U16(tlv_type),
        offset..offset + 2,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_LENGTH],
        FieldValue::U16(tlv.len() as u16),
        offset + 2..offset + 4,
    );
    match tlv_type {
        TLV_DEVICE_ID | TLV_PORT_ID | TLV_SOFTWARE_VERSION | TLV_PLATFORM | TLV_VTP_MGMT_DOMAIN
        | TLV_SYSTEM_NAME => buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_STRING],
            FieldValue::Bytes(value),
            value_range,
        ),
        TLV_ADDRESSES | TLV_MANAGEMENT_ADDRESSES => {
            // A malformed address list is shown as the raw value.
            let mark = buf.field_count() as usize;
            if push_addresses(value, value_offset, buf).is_none() {
                buf.truncate_fields(mark);
                push_raw_value(value, value_offset, buf);
            }
        }
        TLV_CAPABILITIES if value.len() == 4 => {
            let bits = read_be_u32(value, 0)?;
            buf.push_field(
                &TLV_CHILD_FIELDS[FD_TLV_CAPABILITIES],
                FieldValue::U32(bits),
                value_range.clone(),
            );
            let idx = buf.begin_container(
                &TLV_CHILD_FIELDS[FD_TLV_CAPABILITY_FLAGS],
                FieldValue::Object(0..0),
                value_range.clone(),
            );
            for (bit, descriptor) in CAPABILITY_BITS.iter().enumerate() {
                buf.push_field(
                    descriptor,
                    FieldValue::U8(((bits >> bit) & 1) as u8),
                    value_range.clone(),
                );
            }
            buf.end_container(idx);
        }
        TLV_NATIVE_VLAN if value.len() == 2 => buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_NATIVE_VLAN],
            FieldValue::U16(read_be_u16(value, 0)?),
            value_range,
        ),
        TLV_DUPLEX if value.len() == 1 => buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_DUPLEX],
            FieldValue::U8(value[0]),
            value_range,
        ),
        _ => push_raw_value(value, value_offset, buf),
    }
    buf.end_container(obj_idx);
    Ok(())
}

/// Push `value` as a raw `value` field, if any.
fn push_raw_value<'pkt>(value: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    if !value.is_empty() {
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_VALUE],
            FieldValue::Bytes(value),
            offset..offset + value.len(),
        );
    }
}

/// Size of the Number of Addresses field of an Addresses TLV.
const ADDRESS_COUNT_SIZE: usize = 4;

/// Push an Addresses TLV value: a 4-octet count, then per entry Protocol
/// Type (1), Protocol Length (1), Protocol, Address Length (2) and Address.
/// Octets after the last entry are kept as a raw `value`.
///
/// Returns `None` if an entry does not fit; the caller then removes what
/// was pushed.
fn push_addresses<'pkt>(
    value: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Option<()> {
    let count = read_be_u32(value, 0).ok()?;
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_ADDRESS_COUNT],
        FieldValue::U32(count),
        offset..offset + ADDRESS_COUNT_SIZE,
    );
    let array_idx = buf.begin_container(
        &TLV_CHILD_FIELDS[FD_TLV_ADDRESSES],
        FieldValue::Array(0..0),
        offset + ADDRESS_COUNT_SIZE..offset + value.len(),
    );
    let mut pos = ADDRESS_COUNT_SIZE;
    // Every entry is at least 4 octets or the walk stops, so a large count
    // is bounded by the value length.
    for _ in 0..count {
        let protocol_type = *value.get(pos)?;
        let protocol_length = usize::from(*value.get(pos + 1)?);
        let protocol = value.get(pos + 2..pos + 2 + protocol_length)?;
        let address_length_at = pos + 2 + protocol_length;
        let address_length = usize::from(read_be_u16(value, address_length_at).ok()?);
        let address_at = address_length_at + 2;
        let end = address_at + address_length;
        let address = value.get(address_at..end)?;

        let address_value = match (protocol_type, protocol) {
            (PROTO_TYPE_NLPID, [NLPID_IP]) => <[u8; 4]>::try_from(address)
                .map_or(FieldValue::Bytes(address), FieldValue::Ipv4Addr),
            (PROTO_TYPE_IEEE_802_2, p) if p == LLC_SNAP_IPV6 => <[u8; 16]>::try_from(address)
                .map_or(FieldValue::Bytes(address), FieldValue::Ipv6Addr),
            _ => FieldValue::Bytes(address),
        };

        let obj_idx = buf.begin_container(
            &FD_ADDRESS,
            FieldValue::Object(0..0),
            offset + pos..offset + end,
        );
        buf.push_field(
            &ADDRESS_CHILD_FIELDS[FD_ADDR_PROTOCOL_TYPE],
            FieldValue::U8(protocol_type),
            offset + pos..offset + pos + 1,
        );
        buf.push_field(
            &ADDRESS_CHILD_FIELDS[FD_ADDR_PROTOCOL_LENGTH],
            FieldValue::U8(protocol_length as u8),
            offset + pos + 1..offset + pos + 2,
        );
        buf.push_field(
            &ADDRESS_CHILD_FIELDS[FD_ADDR_PROTOCOL],
            FieldValue::Bytes(protocol),
            offset + pos + 2..offset + address_length_at,
        );
        buf.push_field(
            &ADDRESS_CHILD_FIELDS[FD_ADDR_ADDRESS_LENGTH],
            FieldValue::U16(address_length as u16),
            offset + address_length_at..offset + address_at,
        );
        buf.push_field(
            &ADDRESS_CHILD_FIELDS[FD_ADDR_ADDRESS],
            address_value,
            offset + address_at..offset + end,
        );
        buf.end_container(obj_idx);
        pos = end;
    }
    buf.end_container(array_idx);
    push_raw_value(&value[pos..], offset + pos, buf);
    Some(())
}

#[cfg(test)]
mod tests {
    //! # CDP Coverage (Cisco CDP; Wireshark / tcpdump as secondary sources)
    //!
    //! | Item                      | Description                               | Test                             |
    //! |---------------------------|-------------------------------------------|----------------------------------|
    //! | Header                    | Version 2, TTL, Checksum                  | cdpv2_full_frame                 |
    //! | Header                    | Version 1 frame                           | cdpv1_frame                      |
    //! | Header                    | Header truncated                          | truncated_header                 |
    //! | TLV 0x0001 / 0x0003 / ... | Text TLVs                                 | cdpv2_full_frame                 |
    //! | TLV 0x0002                | Addresses: one IPv4                       | cdpv2_full_frame                 |
    //! | TLV 0x0016                | Management Addresses: IPv6 via LLC/SNAP   | management_address_ipv6          |
    //! | TLV 0x0002                | Unknown protocol keeps raw address        | address_other_protocol_raw       |
    //! | TLV 0x0002                | Malformed address list → raw value        | address_list_malformed_raw       |
    //! | TLV 0x0002                | Octets after the entries kept raw         | address_trailing_bytes_raw       |
    //! | Header                    | Header only, no TLVs                      | header_only                      |
    //! | TLV 0x0004                | Capabilities and bit names                | cdpv2_full_frame                 |
    //! | TLV 0x000a                | Native VLAN                               | cdpv2_full_frame                 |
    //! | TLV 0x000b                | Duplex                                    | cdpv2_full_frame                 |
    //! | TLV 0x000a / 0x000b / 4   | Wrong fixed length → raw value            | fixed_tlv_wrong_length_raw       |
    //! | TLV                       | Unknown TLV type                          | unknown_tlv_type                 |
    //! | TLV                       | TLV Length < 4                            | tlv_length_below_header          |
    //! | TLV                       | TLV past end of data                      | tlv_overrun                      |
    //! | TLV                       | TLV header truncated                      | tlv_header_truncated             |
    //! | —                         | Name tables                               | name_tables                      |

    use super::*;
    use packet_dissector_core::field::Field;

    fn tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let mut t = tlv_type.to_be_bytes().to_vec();
        t.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        t.extend_from_slice(value);
        t
    }

    fn ipv4_addresses(addr: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0, 0, 0, 1, PROTO_TYPE_NLPID, 1, NLPID_IP, 0, 4];
        v.extend_from_slice(&addr);
        v
    }

    fn tlv_objects<'a>(buf: &'a DissectBuffer<'_>) -> Vec<&'a [Field<'a>]> {
        let layer = &buf.layers()[0];
        let Some(FieldValue::Array(r)) = buf.field_by_name(layer, "tlvs").map(|f| &f.value) else {
            panic!("tlvs must be an Array");
        };
        buf.nested_fields(r)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(r) if f.name() == "tlv" => Some(buf.nested_fields(r)),
                _ => None,
            })
            .collect()
    }

    fn child<'a>(fields: &'a [Field<'a>], name: &str) -> Option<&'a Field<'a>> {
        fields.iter().find(|f| f.name() == name)
    }

    #[test]
    fn cdpv2_full_frame() {
        let mut raw = vec![0x02, 0xB4, 0x12, 0x34];
        raw.extend(tlv(TLV_DEVICE_ID, b"sw1"));
        raw.extend(tlv(TLV_ADDRESSES, &ipv4_addresses([192, 0, 2, 1])));
        raw.extend(tlv(TLV_PORT_ID, b"Gi0/1"));
        raw.extend(tlv(TLV_CAPABILITIES, &[0, 0, 0, 0x29]));
        raw.extend(tlv(TLV_SOFTWARE_VERSION, b"IOS 15.2"));
        raw.extend(tlv(TLV_PLATFORM, b"cisco WS-C2960"));
        raw.extend(tlv(TLV_NATIVE_VLAN, &[0x00, 0x01]));
        raw.extend(tlv(TLV_DUPLEX, &[0x01]));

        let mut buf = DissectBuffer::new();
        let r = CdpDissector.dissect(&raw, &mut buf, 22).unwrap();
        assert_eq!(r.bytes_consumed, raw.len());
        assert_eq!(r.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "CDP");
        assert_eq!(layer.range, 22..22 + raw.len());
        assert_eq!(buf.field_u8(layer, "version"), Some(2));
        assert_eq!(buf.field_u8(layer, "ttl"), Some(180));
        assert_eq!(buf.field_u16(layer, "checksum"), Some(0x1234));

        let tlvs = tlv_objects(&buf);
        assert_eq!(tlvs.len(), 8);
        assert_eq!(child(tlvs[0], "type").unwrap().value, FieldValue::U16(1));
        assert_eq!(child(tlvs[0], "length").unwrap().value, FieldValue::U16(7));
        assert_eq!(
            child(tlvs[0], "string").unwrap().value,
            FieldValue::Bytes(b"sw1")
        );
        assert_eq!(child(tlvs[0], "string").unwrap().range, 30..33);

        // Addresses: one IPv4 entry.
        assert_eq!(
            child(tlvs[1], "address_count").unwrap().value,
            FieldValue::U32(1)
        );
        let FieldValue::Array(ar) = &child(tlvs[1], "addresses").unwrap().value else {
            panic!("addresses must be an Array");
        };
        let entry = buf.nested_fields(ar);
        assert_eq!(entry[0].name(), "address");
        assert_eq!(entry[1].value, FieldValue::U8(PROTO_TYPE_NLPID));
        assert_eq!(entry[2].value, FieldValue::U8(1));
        assert_eq!(entry[3].value, FieldValue::Bytes(&[NLPID_IP]));
        assert_eq!(entry[4].value, FieldValue::U16(4));
        assert_eq!(entry[5].value, FieldValue::Ipv4Addr([192, 0, 2, 1]));

        assert_eq!(
            child(tlvs[2], "string").unwrap().value,
            FieldValue::Bytes(b"Gi0/1")
        );

        // Capabilities 0x29: Router, Switch, IGMP capable.
        assert_eq!(
            child(tlvs[3], "capabilities").unwrap().value,
            FieldValue::U32(0x29)
        );
        let FieldValue::Object(cr) = &child(tlvs[3], "capability_flags").unwrap().value else {
            panic!("capability_flags must be an Object");
        };
        let flags = buf.nested_fields(cr);
        assert_eq!(flags.len(), CAPABILITY_BITS.len());
        let set: Vec<_> = flags
            .iter()
            .filter(|f| f.value == FieldValue::U8(1))
            .map(|f| f.name())
            .collect();
        assert_eq!(set, ["router", "switch", "igmp_capable"]);

        assert_eq!(
            child(tlvs[6], "native_vlan").unwrap().value,
            FieldValue::U16(1)
        );
        let duplex = child(tlvs[7], "duplex").unwrap();
        assert_eq!(duplex.value, FieldValue::U8(1));
        assert_eq!(
            duplex.descriptor.display_fn.unwrap()(&duplex.value, tlvs[7]),
            Some("Full")
        );

        let idx = buf.fields().iter().position(|f| f.name() == "tlv").unwrap() as u32;
        assert_eq!(buf.resolve_container_display_name(idx), Some("Device ID"));
    }

    #[test]
    fn cdpv1_frame() {
        let mut raw = vec![0x01, 0x3C, 0x00, 0x00];
        raw.extend(tlv(TLV_DEVICE_ID, b"r1"));
        raw.extend(tlv(TLV_VTP_MGMT_DOMAIN, b"lab"));
        raw.extend(tlv(TLV_SYSTEM_NAME, b"r1.example"));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(buf.field_u8(layer, "version"), Some(1));
        let tlvs = tlv_objects(&buf);
        assert_eq!(
            child(tlvs[1], "string").unwrap().value,
            FieldValue::Bytes(b"lab")
        );
        assert_eq!(
            child(tlvs[2], "string").unwrap().value,
            FieldValue::Bytes(b"r1.example")
        );
    }

    #[test]
    fn management_address_ipv6() {
        let mut value = vec![0, 0, 0, 1, PROTO_TYPE_IEEE_802_2, 8];
        value.extend_from_slice(&LLC_SNAP_IPV6);
        value.extend_from_slice(&[0, 16]);
        let addr = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        value.extend_from_slice(&addr);
        let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
        raw.extend(tlv(TLV_MANAGEMENT_ADDRESSES, &value));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        let FieldValue::Array(ar) = &child(tlvs[0], "addresses").unwrap().value else {
            panic!("addresses must be an Array");
        };
        let entry = buf.nested_fields(ar);
        assert_eq!(entry[5].value, FieldValue::Ipv6Addr(addr));
        assert_eq!(
            entry[1].descriptor.display_fn.unwrap()(&entry[1].value, entry),
            Some("802.2")
        );
    }

    #[test]
    fn address_other_protocol_raw() {
        // NLPID 0x81 (CLNP) with a 3-octet address.
        let value = [
            0,
            0,
            0,
            1,
            PROTO_TYPE_NLPID,
            1,
            0x81,
            0,
            3,
            0x49,
            0x00,
            0x01,
        ];
        let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
        raw.extend(tlv(TLV_ADDRESSES, &value));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        let FieldValue::Array(ar) = &child(tlvs[0], "addresses").unwrap().value else {
            panic!("addresses must be an Array");
        };
        let entry = buf.nested_fields(ar);
        assert_eq!(entry[5].value, FieldValue::Bytes(&[0x49, 0x00, 0x01]));
    }

    #[test]
    fn address_list_malformed_raw() {
        // Count 2 but only one entry present.
        let mut value = ipv4_addresses([192, 0, 2, 1]);
        value[3] = 2;
        let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
        raw.extend(tlv(TLV_ADDRESSES, &value));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert!(child(tlvs[0], "addresses").is_none());
        assert!(child(tlvs[0], "address_count").is_none());
        assert_eq!(
            child(tlvs[0], "value").unwrap().value,
            FieldValue::Bytes(&value)
        );
    }

    #[test]
    fn address_trailing_bytes_raw() {
        let mut value = ipv4_addresses([192, 0, 2, 1]);
        value.extend_from_slice(&[0xDE, 0xAD]);
        let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
        raw.extend(tlv(TLV_ADDRESSES, &value));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert!(child(tlvs[0], "addresses").is_some());
        let trailing = child(tlvs[0], "value").unwrap();
        assert_eq!(trailing.value, FieldValue::Bytes(&[0xDE, 0xAD]));
        assert_eq!(trailing.range, 21..23);
    }

    #[test]
    fn fixed_tlv_wrong_length_raw() {
        let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
        raw.extend(tlv(TLV_NATIVE_VLAN, &[0x01]));
        raw.extend(tlv(TLV_DUPLEX, &[]));
        raw.extend(tlv(TLV_CAPABILITIES, &[0x01, 0x02]));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert!(child(tlvs[0], "native_vlan").is_none());
        assert_eq!(
            child(tlvs[0], "value").unwrap().value,
            FieldValue::Bytes(&[0x01])
        );
        assert!(child(tlvs[1], "duplex").is_none());
        assert!(child(tlvs[1], "value").is_none());
        assert!(child(tlvs[2], "capabilities").is_none());
        assert_eq!(
            child(tlvs[2], "value").unwrap().value,
            FieldValue::Bytes(&[0x01, 0x02])
        );
    }

    #[test]
    fn unknown_tlv_type() {
        let mut raw = vec![0x02, 0xB4, 0x00, 0x00];
        raw.extend(tlv(0x7777, &[0xAB]));
        let mut buf = DissectBuffer::new();
        CdpDissector.dissect(&raw, &mut buf, 0).unwrap();
        let tlvs = tlv_objects(&buf);
        assert_eq!(
            child(tlvs[0], "type").unwrap().value,
            FieldValue::U16(0x7777)
        );
        assert_eq!(
            child(tlvs[0], "value").unwrap().value,
            FieldValue::Bytes(&[0xAB])
        );
    }

    #[test]
    fn header_only() {
        let mut buf = DissectBuffer::new();
        let r = CdpDissector
            .dissect(&[0x02, 0xB4, 0x00, 0x00], &mut buf, 0)
            .unwrap();
        assert_eq!(r.bytes_consumed, 4);
        assert!(buf.field_by_name(&buf.layers()[0], "tlvs").is_none());
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        let err = CdpDissector
            .dissect(&[0x02, 0xB4], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 2
            }
        );
    }

    #[test]
    fn tlv_length_below_header() {
        let raw = [0x02, 0xB4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03];
        let mut buf = DissectBuffer::new();
        let err = CdpDissector.dissect(&raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("CDP TLV length is less than 4")
        );
        assert!(buf.layers().is_empty());
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn tlv_overrun() {
        let raw = [0x02, 0xB4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x09, b'a'];
        let mut buf = DissectBuffer::new();
        let err = CdpDissector.dissect(&raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 13,
                actual: 9
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn tlv_header_truncated() {
        let raw = [0x02, 0xB4, 0x00, 0x00, 0x00, 0x01];
        let mut buf = DissectBuffer::new();
        let err = CdpDissector.dissect(&raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 6
            }
        );
    }

    #[test]
    fn name_tables() {
        for t in [
            0x0007u16, 0x0008, 0x000E, 0x000F, 0x0010, 0x0011, 0x0012, 0x0013, 0x0015, 0x0017,
            0x0018, 0x0019, 0x001A, 0x001B, 0x001D, 0x001F,
        ] {
            assert!(tlv_type_name(t).is_some(), "TLV {t:#06x}");
        }
        assert_eq!(tlv_type_name(0x0000), None);
        assert_eq!(protocol_type_name(3), None);
        assert_eq!(duplex_name(0), "Half");
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(CdpDissector.name(), "Cisco Discovery Protocol");
        assert_eq!(CdpDissector.short_name(), "CDP");
        assert_eq!(CdpDissector.field_descriptors().len(), 4);
        assert_eq!(CdpDissector.references()[0].id, "Cisco CDP");
        assert_eq!(CdpDissector.layer(), Some(ProtocolLayer::Link));
    }
}
