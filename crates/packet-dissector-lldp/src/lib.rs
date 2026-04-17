//! LLDP (Link Layer Discovery Protocol) dissector.
//!
//! Parses LLDP Data Units (LLDPDUs) consisting of a sequence of TLV
//! (Type-Length-Value) structures. Each TLV is encoded as a 2-byte header
//! where the upper 7 bits encode the type and the lower 9 bits encode the
//! information string length.
//!
//! ## References
//! - IEEE 802.1AB-2016: <https://standards.ieee.org/ieee/802.1AB/6047/>
//!
//! ## Coverage (IEEE 802.1AB-2016)
//!
//! | Section | Description | Test |
//! |---------|-------------|------|
//! | 8.5 | LLDPDU format / TLV structure | `parse_lldp_mandatory_tlvs` |
//! | 8.5.1 | End Of LLDPDU TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.1 | End Of LLDPDU length != 0 | `parse_lldp_end_invalid_length` |
//! | 8.5.2 | Chassis ID TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.3 | Port ID TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.4 | Time To Live TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.4 | TTL length != 2 | `parse_lldp_ttl_invalid_length` |
//! | 8.5.5 | Port Description TLV | `parse_lldp_optional_tlvs` |
//! | 8.5.6 | System Name TLV | `parse_lldp_optional_tlvs` |
//! | 8.5.7 | System Description TLV | `parse_lldp_optional_tlvs` |
//! | 8.5.8 | System Capabilities TLV | `parse_lldp_system_capabilities` |
//! | 8.5.8 | System Capabilities length != 4 | `parse_lldp_system_capabilities_invalid_length` |
//! | 8.5.9 | Management Address TLV (IPv4) | `parse_lldp_management_address` |
//! | 8.5.9 | Management Address TLV (IPv6) | `parse_lldp_management_address_ipv6` |
//! | 8.5.9 | Management Address TLV with OID | `parse_lldp_management_address_with_oid` |
//! | 8.5.9 | Management Address length < 9 | `parse_lldp_management_address_too_short` |
//! | 8.5.9 | Management Address length > 167 | `parse_lldp_management_address_too_long` |
//! | 8.6 | Organizationally Specific TLV | `parse_lldp_org_specific` |
//! | — | Truncated LLDPDU | `parse_lldp_truncated` |
//! | — | Empty LLDPDU | `parse_lldp_empty_data` |

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, MacAddr, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Minimum TLV header size (type + length encoded in 2 bytes).
/// IEEE 802.1AB-2016, Section 8.5 — LLDPDU format.
const TLV_HEADER_SIZE: usize = 2;

/// Minimum Management Address TLV value length (8.5.9): 1B S + 2 (subtype + 1 addr byte) +
/// 1B iface subtype + 4B iface number + 1B OID length + 0B OID.
const MGMT_ADDR_MIN_LENGTH: usize = 9;

/// Maximum Management Address TLV value length (8.5.9): 1B S + 32 (subtype + 31 addr bytes) +
/// 1B iface subtype + 4B iface number + 1B OID length + 128B OID.
const MGMT_ADDR_MAX_LENGTH: usize = 167;

/// Maximum OID string length in the Management Address TLV (8.5.9.6).
const MGMT_ADDR_OID_MAX_LENGTH: usize = 128;

/// IANA Address Family Number for IPv4. Used as Management Address subtype (8.5.9.3).
const ADDR_FAMILY_IPV4: u8 = 1;
/// IANA Address Family Number for IPv6. Used as Management Address subtype (8.5.9.3).
const ADDR_FAMILY_IPV6: u8 = 2;

// ---------------------------------------------------------------------------
// TLV type constants — IEEE 802.1AB-2016, Table 8-1
// ---------------------------------------------------------------------------

/// End Of LLDPDU TLV type.
const TLV_TYPE_END: u8 = 0;
/// Chassis ID TLV type.
const TLV_TYPE_CHASSIS_ID: u8 = 1;
/// Port ID TLV type.
const TLV_TYPE_PORT_ID: u8 = 2;
/// Time To Live TLV type.
const TLV_TYPE_TTL: u8 = 3;
/// Port Description TLV type.
const TLV_TYPE_PORT_DESCRIPTION: u8 = 4;
/// System Name TLV type.
const TLV_TYPE_SYSTEM_NAME: u8 = 5;
/// System Description TLV type.
const TLV_TYPE_SYSTEM_DESCRIPTION: u8 = 6;
/// System Capabilities TLV type.
const TLV_TYPE_SYSTEM_CAPABILITIES: u8 = 7;
/// Management Address TLV type.
const TLV_TYPE_MANAGEMENT_ADDRESS: u8 = 8;
/// Organizationally Specific TLV type.
const TLV_TYPE_ORG_SPECIFIC: u8 = 127;

// ---------------------------------------------------------------------------
// Chassis ID subtypes — IEEE 802.1AB-2016, Table 8-2
// ---------------------------------------------------------------------------

/// Chassis ID subtype whose value is a MAC address (6 bytes).
/// IEEE 802.1AB-2016, Table 8-2, entry 4.
const CHASSIS_ID_SUBTYPE_MAC: u8 = 4;
/// Returns a human-readable name for a Chassis ID subtype.
///
/// IEEE 802.1AB-2016, Section 8.5.2.2 — chassis ID subtype.
fn chassis_id_subtype_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Chassis component"),
        2 => Some("Interface alias"),
        3 => Some("Port component"),
        4 => Some("MAC address"),
        5 => Some("Network address"),
        6 => Some("Interface name"),
        7 => Some("Locally assigned"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Port ID subtypes — IEEE 802.1AB-2016, Table 8-4
// ---------------------------------------------------------------------------

/// Port ID subtype whose value is a MAC address (6 bytes).
/// IEEE 802.1AB-2016, Table 8-4, entry 3.
const PORT_ID_SUBTYPE_MAC: u8 = 3;

/// Returns a human-readable name for a Port ID subtype.
///
/// IEEE 802.1AB-2016, Section 8.5.3.2 — port ID subtype.
fn port_id_subtype_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Interface alias"),
        2 => Some("Port component"),
        3 => Some("MAC address"),
        4 => Some("Network address"),
        5 => Some("Interface name"),
        6 => Some("Agent circuit ID"),
        7 => Some("Locally assigned"),
        _ => None,
    }
}

/// Returns a human-readable name for a TLV type.
///
/// IEEE 802.1AB-2016, Table 8-1 — TLV type values.
fn tlv_type_name(v: u8) -> &'static str {
    match v {
        TLV_TYPE_END => "End Of LLDPDU",
        TLV_TYPE_CHASSIS_ID => "Chassis ID",
        TLV_TYPE_PORT_ID => "Port ID",
        TLV_TYPE_TTL => "Time To Live",
        TLV_TYPE_PORT_DESCRIPTION => "Port Description",
        TLV_TYPE_SYSTEM_NAME => "System Name",
        TLV_TYPE_SYSTEM_DESCRIPTION => "System Description",
        TLV_TYPE_SYSTEM_CAPABILITIES => "System Capabilities",
        TLV_TYPE_MANAGEMENT_ADDRESS => "Management Address",
        TLV_TYPE_ORG_SPECIFIC => "Organizationally Specific",
        _ => "Reserved",
    }
}

// ---------------------------------------------------------------------------
// Top-level field descriptor indices
// ---------------------------------------------------------------------------

/// Index of the `tlvs` field in [`FIELD_DESCRIPTORS`].
const FD_TLVS: usize = 0;

/// Top-level field descriptors for the LLDP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] =
    &[FieldDescriptor::new("tlvs", "TLVs", FieldType::Array).with_children(TLV_CHILD_FIELDS)];

// ---------------------------------------------------------------------------
// Child field descriptors for TLV entries
// ---------------------------------------------------------------------------

/// Child field descriptor indices for [`TLV_CHILD_FIELDS`].
const FD_TLV_TYPE: usize = 0;
const FD_TLV_LENGTH: usize = 1;
const FD_TLV_SUBTYPE: usize = 2;
const FD_TLV_ID: usize = 3;
const FD_TLV_TTL: usize = 4;
const FD_TLV_VALUE: usize = 5;
const FD_TLV_AVAILABLE_CAPABILITIES: usize = 6;
const FD_TLV_ENABLED_CAPABILITIES: usize = 7;
const FD_TLV_OUI: usize = 8;
const FD_TLV_ORG_SUBTYPE: usize = 9;
const FD_TLV_INFO: usize = 10;
const FD_TLV_RAW: usize = 11;
// Management Address TLV subfields (IEEE 802.1AB-2016, Section 8.5.9).
const FD_TLV_MGMT_ADDR_STRING_LENGTH: usize = 12;
const FD_TLV_MGMT_ADDR_SUBTYPE: usize = 13;
const FD_TLV_MGMT_ADDRESS: usize = 14;
const FD_TLV_IFACE_NUMBERING_SUBTYPE: usize = 15;
const FD_TLV_IFACE_NUMBER: usize = 16;
const FD_TLV_OID_LENGTH: usize = 17;
const FD_TLV_OID: usize = 18;

/// Container descriptor for a TLV Object.
///
/// The outer label resolves to the TLV name (e.g. `Chassis ID`) by looking
/// up the inner `type` field, avoiding collision with the inner "TLV Type"
/// label.
static FD_TLV: FieldDescriptor = FieldDescriptor {
    name: "tlv",
    display_name: "TLV",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U8(t)) => Some(tlv_type_name(*t)),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Child field descriptors for each TLV entry within the `tlvs` array.
static TLV_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "TLV Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => Some(tlv_type_name(*t)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "TLV Length", FieldType::U16),
    FieldDescriptor {
        name: "subtype",
        display_name: "Subtype",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, siblings| match v {
            FieldValue::U8(sub) => {
                siblings
                    .iter()
                    .find(|f| f.name() == "type")
                    .and_then(|f| match &f.value {
                        FieldValue::U8(TLV_TYPE_CHASSIS_ID) => chassis_id_subtype_name(*sub),
                        FieldValue::U8(TLV_TYPE_PORT_ID) => port_id_subtype_name(*sub),
                        _ => None,
                    })
            }
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("id", "ID", FieldType::MacAddr).optional(),
    FieldDescriptor::new("ttl", "TTL", FieldType::U16).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new(
        "available_capabilities",
        "Available Capabilities",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "enabled_capabilities",
        "Enabled Capabilities",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("oui", "OUI", FieldType::Bytes).optional(),
    FieldDescriptor::new("org_subtype", "Organization Subtype", FieldType::U8).optional(),
    FieldDescriptor::new("info", "Information", FieldType::Bytes).optional(),
    FieldDescriptor::new("raw", "Raw Value", FieldType::Bytes).optional(),
    // Management Address TLV subfields — IEEE 802.1AB-2016, Section 8.5.9.
    FieldDescriptor::new(
        "addr_string_length",
        "Mgmt Address String Length",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("addr_subtype", "Mgmt Address Subtype", FieldType::U8).optional(),
    FieldDescriptor::new("address", "Management Address", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "iface_numbering_subtype",
        "Interface Numbering Subtype",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("iface_number", "Interface Number", FieldType::U32).optional(),
    FieldDescriptor::new("oid_length", "OID String Length", FieldType::U8).optional(),
    FieldDescriptor::new("oid", "Object Identifier", FieldType::Bytes).optional(),
];

/// LLDP dissector.
pub struct LldpDissector;

impl Dissector for LldpDissector {
    fn name(&self) -> &'static str {
        "Link Layer Discovery Protocol"
    }

    fn short_name(&self) -> &'static str {
        "LLDP"
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
        let mut pos = 0;

        buf.begin_layer(self.short_name(), None, FIELD_DESCRIPTORS, offset..offset);

        // Begin the top-level "tlvs" Array container.
        let array_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_TLVS],
            FieldValue::Array(0..0),
            offset..offset,
        );

        loop {
            // IEEE 802.1AB-2016, Section 8.5 — each TLV header is 2 bytes.
            if pos + TLV_HEADER_SIZE > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + TLV_HEADER_SIZE,
                    actual: data.len(),
                });
            }

            // IEEE 802.1AB-2016, Section 8.5 — TLV header encoding:
            // Bits 15..9 = TLV type (7 bits), Bits 8..0 = information string length (9 bits)
            let tlv_header = read_be_u16(data, pos)?;
            let tlv_type = (tlv_header >> 9) as u8;
            let tlv_length = (tlv_header & 0x01FF) as usize;

            // Verify we have enough data for the value
            if pos + TLV_HEADER_SIZE + tlv_length > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + TLV_HEADER_SIZE + tlv_length,
                    actual: data.len(),
                });
            }

            let tlv_value_start = pos + TLV_HEADER_SIZE;
            let tlv_value = &data[tlv_value_start..tlv_value_start + tlv_length];
            let tlv_total = TLV_HEADER_SIZE + tlv_length;

            let hdr_range = offset + pos..offset + pos + TLV_HEADER_SIZE;

            // Begin Object for this TLV entry.
            let obj_idx = buf.begin_container(
                &FD_TLV,
                FieldValue::Object(0..0),
                offset + pos..offset + pos + tlv_total,
            );

            buf.push_field(
                &TLV_CHILD_FIELDS[FD_TLV_TYPE],
                FieldValue::U8(tlv_type),
                hdr_range.clone(),
            );
            buf.push_field(
                &TLV_CHILD_FIELDS[FD_TLV_LENGTH],
                FieldValue::U16(tlv_length as u16),
                hdr_range,
            );

            match tlv_type {
                // IEEE 802.1AB-2016, Section 8.5.2 — Chassis ID TLV
                TLV_TYPE_CHASSIS_ID => {
                    parse_id_tlv(
                        buf,
                        tlv_value,
                        offset + tlv_value_start,
                        CHASSIS_ID_SUBTYPE_MAC,
                    )?;
                }
                // IEEE 802.1AB-2016, Section 8.5.3 — Port ID TLV
                TLV_TYPE_PORT_ID => {
                    parse_id_tlv(
                        buf,
                        tlv_value,
                        offset + tlv_value_start,
                        PORT_ID_SUBTYPE_MAC,
                    )?;
                }
                // IEEE 802.1AB-2016, Section 8.5.4 — Time To Live TLV (length = 2).
                TLV_TYPE_TTL => {
                    if tlv_length != 2 {
                        return Err(PacketError::InvalidHeader(
                            "TTL TLV value must be exactly 2 bytes",
                        ));
                    }
                    let ttl = read_be_u16(tlv_value, 0)?;
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_TTL],
                        FieldValue::U16(ttl),
                        offset + tlv_value_start..offset + tlv_value_start + 2,
                    );
                }
                // IEEE 802.1AB-2016, Sections 8.5.5 / 8.5.6 / 8.5.7 — string TLVs.
                TLV_TYPE_PORT_DESCRIPTION | TLV_TYPE_SYSTEM_NAME | TLV_TYPE_SYSTEM_DESCRIPTION => {
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_VALUE],
                        FieldValue::Bytes(tlv_value),
                        offset + tlv_value_start..offset + tlv_value_start + tlv_length,
                    );
                }
                // IEEE 802.1AB-2016, Section 8.5.8 — System Capabilities TLV (length = 4).
                TLV_TYPE_SYSTEM_CAPABILITIES => {
                    if tlv_length != 4 {
                        return Err(PacketError::InvalidHeader(
                            "System Capabilities TLV must be exactly 4 bytes",
                        ));
                    }
                    let available = read_be_u16(tlv_value, 0)?;
                    let enabled = read_be_u16(tlv_value, 2)?;
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_AVAILABLE_CAPABILITIES],
                        FieldValue::U16(available),
                        offset + tlv_value_start..offset + tlv_value_start + 2,
                    );
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_ENABLED_CAPABILITIES],
                        FieldValue::U16(enabled),
                        offset + tlv_value_start + 2..offset + tlv_value_start + 4,
                    );
                }
                // IEEE 802.1AB-2016, Section 8.5.9 — Management Address TLV.
                TLV_TYPE_MANAGEMENT_ADDRESS => {
                    parse_management_address_tlv(buf, tlv_value, offset + tlv_value_start)?;
                }
                // IEEE 802.1AB-2016, Section 8.6 — Organizationally Specific TLV (type 127).
                TLV_TYPE_ORG_SPECIFIC => {
                    if tlv_length < 4 {
                        return Err(PacketError::InvalidHeader(
                            "Organizationally Specific TLV must be at least 4 bytes",
                        ));
                    }
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_OUI],
                        FieldValue::Bytes(&tlv_value[..3]),
                        offset + tlv_value_start..offset + tlv_value_start + 3,
                    );
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_ORG_SUBTYPE],
                        FieldValue::U8(tlv_value[3]),
                        offset + tlv_value_start + 3..offset + tlv_value_start + 4,
                    );
                    if tlv_length > 4 {
                        buf.push_field(
                            &TLV_CHILD_FIELDS[FD_TLV_INFO],
                            FieldValue::Bytes(&tlv_value[4..]),
                            offset + tlv_value_start + 4..offset + tlv_value_start + tlv_length,
                        );
                    }
                }
                // IEEE 802.1AB-2016, Section 8.5.1 — End Of LLDPDU TLV (length = 0).
                TLV_TYPE_END => {
                    if tlv_length != 0 {
                        return Err(PacketError::InvalidHeader(
                            "End Of LLDPDU TLV length must be 0",
                        ));
                    }
                }
                // Reserved TLV types (8..=126): store value as raw bytes.
                _ => {
                    if !tlv_value.is_empty() {
                        buf.push_field(
                            &TLV_CHILD_FIELDS[FD_TLV_RAW],
                            FieldValue::Bytes(tlv_value),
                            offset + tlv_value_start..offset + tlv_value_start + tlv_length,
                        );
                    }
                }
            }

            buf.end_container(obj_idx);
            pos += tlv_total;

            // IEEE 802.1AB-2016, Section 8.5.1 — End Of LLDPDU terminates the PDU.
            if tlv_type == TLV_TYPE_END {
                break;
            }
        }

        buf.end_container(array_idx);

        // Fix up the Array field's byte range now that we know `pos`.
        if let Some(field) = buf.field_mut(array_idx as usize) {
            field.range = offset..offset + pos;
        }

        // Fix up the layer range now that we know total bytes consumed.
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + pos;
        }
        buf.end_layer();

        Ok(DissectResult::new(pos, DispatchHint::End))
    }
}

/// Parse a Chassis ID or Port ID TLV value and push fields into the buffer.
///
/// Both TLV types share the same structure: 1-byte subtype followed by the ID value.
/// IEEE 802.1AB-2016, Sections 8.5.2 and 8.5.3.
///
/// `mac_subtype` encodes the subtype number for MAC address IDs
/// (Chassis ID: 4, Port ID: 3).
fn parse_id_tlv<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    abs_offset: usize,
    mac_subtype: u8,
) -> Result<(), PacketError> {
    if value.is_empty() {
        return Err(PacketError::InvalidHeader(
            "ID TLV must contain at least a subtype byte",
        ));
    }

    let subtype = value[0];

    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_SUBTYPE],
        FieldValue::U8(subtype),
        abs_offset..abs_offset + 1,
    );

    let id_data = &value[1..];
    let id_offset = abs_offset + 1;

    // Subtype 4 (Chassis) / 3 (Port) with a 6-byte value → MacAddr; otherwise raw bytes.
    let id_value = if id_data.len() == 6 && subtype == mac_subtype {
        FieldValue::MacAddr(MacAddr([
            id_data[0], id_data[1], id_data[2], id_data[3], id_data[4], id_data[5],
        ]))
    } else {
        FieldValue::Bytes(id_data)
    };

    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_ID],
        id_value,
        id_offset..id_offset + id_data.len(),
    );

    Ok(())
}

/// Parse a Management Address TLV value (IEEE 802.1AB-2016, Section 8.5.9).
///
/// Value layout:
/// - 1 byte: management address string length `S` (range 2..=32)
/// - 1 byte: management address subtype (IANA address family number)
/// - `S - 1` bytes: management address (range 1..=31)
/// - 1 byte: interface numbering subtype
/// - 4 bytes: interface number
/// - 1 byte: OID string length `O` (range 0..=128)
/// - `O` bytes: object identifier
///
/// Total value length is 9..=167 octets.
fn parse_management_address_tlv<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    abs_offset: usize,
) -> Result<(), PacketError> {
    if value.len() < MGMT_ADDR_MIN_LENGTH || value.len() > MGMT_ADDR_MAX_LENGTH {
        return Err(PacketError::InvalidHeader(
            "Management Address TLV value length must be 9..=167 bytes",
        ));
    }

    let addr_string_length = value[0] as usize;
    // Per 8.5.9.2, `S` counts the subtype byte plus the address bytes (1..=31),
    // giving a valid range of 2..=32.
    if !(2..=32).contains(&addr_string_length) {
        return Err(PacketError::InvalidHeader(
            "Management Address string length must be 2..=32",
        ));
    }

    // Offsets within the TLV value:
    //   [0]                   S
    //   [1]                   addr subtype
    //   [2 .. 1+S]            address  (S-1 bytes)
    //   [1+S]                 iface numbering subtype
    //   [2+S .. 6+S]          iface number (u32)
    //   [6+S]                 OID length O
    //   [7+S .. 7+S+O]        OID
    let iface_subtype_off = 1 + addr_string_length;
    let iface_number_off = iface_subtype_off + 1;
    let oid_length_off = iface_number_off + 4;
    let oid_off = oid_length_off + 1;

    // Bounds already covered by MGMT_ADDR_MAX_LENGTH / addr_string_length range,
    // but verify once more to keep slice access tight.
    if oid_off > value.len() {
        return Err(PacketError::InvalidHeader(
            "Management Address TLV truncated before OID length",
        ));
    }

    let oid_length = value[oid_length_off] as usize;
    if oid_length > MGMT_ADDR_OID_MAX_LENGTH {
        return Err(PacketError::InvalidHeader(
            "Management Address OID length must be 0..=128",
        ));
    }
    if oid_off + oid_length != value.len() {
        return Err(PacketError::InvalidHeader(
            "Management Address TLV length mismatch",
        ));
    }

    let addr_subtype = value[1];
    let addr_bytes = &value[2..iface_subtype_off];
    let iface_subtype = value[iface_subtype_off];
    let iface_number = read_be_u32(value, iface_number_off)?;

    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_MGMT_ADDR_STRING_LENGTH],
        FieldValue::U8(addr_string_length as u8),
        abs_offset..abs_offset + 1,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_MGMT_ADDR_SUBTYPE],
        FieldValue::U8(addr_subtype),
        abs_offset + 1..abs_offset + 2,
    );

    // IEEE 802.1AB-2016, Section 8.5.9.3 — address subtype values use IANA
    // Address Family Numbers. Surface IPv4/IPv6 as typed addresses when the
    // address-bytes length matches, otherwise keep raw bytes.
    let addr_range = abs_offset + 2..abs_offset + iface_subtype_off;
    let addr_value = match (addr_subtype, addr_bytes.len()) {
        (ADDR_FAMILY_IPV4, 4) => {
            FieldValue::Ipv4Addr([addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]])
        }
        (ADDR_FAMILY_IPV6, 16) => {
            let mut buf16 = [0u8; 16];
            buf16.copy_from_slice(addr_bytes);
            FieldValue::Ipv6Addr(buf16)
        }
        _ => FieldValue::Bytes(addr_bytes),
    };
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_MGMT_ADDRESS],
        addr_value,
        addr_range,
    );

    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_IFACE_NUMBERING_SUBTYPE],
        FieldValue::U8(iface_subtype),
        abs_offset + iface_subtype_off..abs_offset + iface_number_off,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_IFACE_NUMBER],
        FieldValue::U32(iface_number),
        abs_offset + iface_number_off..abs_offset + oid_length_off,
    );
    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_OID_LENGTH],
        FieldValue::U8(oid_length as u8),
        abs_offset + oid_length_off..abs_offset + oid_off,
    );
    if oid_length > 0 {
        buf.push_field(
            &TLV_CHILD_FIELDS[FD_TLV_OID],
            FieldValue::Bytes(&value[oid_off..oid_off + oid_length]),
            abs_offset + oid_off..abs_offset + oid_off + oid_length,
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;

    /// Build a minimal LLDP frame with mandatory TLVs only:
    /// Chassis ID (MAC 00:11:22:33:44:55) + Port ID (locally assigned "ge0") + TTL 120 + End
    fn build_mandatory_lldp() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0207u16.to_be_bytes()); // Chassis ID, length=7
        data.push(4); // subtype: MAC address
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&0x0404u16.to_be_bytes()); // Port ID, length=4
        data.push(7); // subtype: Locally assigned
        data.extend_from_slice(b"ge0");
        data.extend_from_slice(&0x0602u16.to_be_bytes()); // TTL, length=2
        data.extend_from_slice(&120u16.to_be_bytes());
        data.extend_from_slice(&0x0000u16.to_be_bytes()); // End Of LLDPDU
        data
    }

    /// Build an LLDP frame with the standard mandatory TLV prefix followed by
    /// one additional optional TLV and a final End Of LLDPDU.
    fn build_lldp_with_optional(tlv_header: u16, tlv_value: &[u8]) -> Vec<u8> {
        let mut data = build_mandatory_lldp();
        // Strip trailing End Of LLDPDU (2 bytes) before appending the optional TLV.
        let trim = data.len() - 2;
        data.truncate(trim);
        data.extend_from_slice(&tlv_header.to_be_bytes());
        data.extend_from_slice(tlv_value);
        data.extend_from_slice(&0x0000u16.to_be_bytes()); // End Of LLDPDU
        data
    }

    /// Helper: get the Object range for the n-th TLV within the array.
    fn tlv_object_range(
        buf: &DissectBuffer,
        array_range: &core::ops::Range<u32>,
        index: usize,
    ) -> core::ops::Range<u32> {
        let children = buf.nested_fields(array_range);
        let mut obj_count = 0;
        for field in children {
            if let FieldValue::Object(r) = &field.value {
                if obj_count == index {
                    return r.clone();
                }
                obj_count += 1;
            }
        }
        panic!("TLV object at index {index} not found");
    }

    /// Helper: find a named field within an Object range.
    fn obj_field_value<'a>(
        buf: &'a DissectBuffer,
        obj_range: &core::ops::Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'a> {
        let fields = buf.nested_fields(obj_range);
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field '{name}' not found"))
            .value
    }

    /// Helper: count the number of Object entries in an array range.
    fn count_objects(buf: &DissectBuffer, array_range: &core::ops::Range<u32>) -> usize {
        buf.nested_fields(array_range)
            .iter()
            .filter(|f| f.value.is_object())
            .count()
    }

    /// Helper: get the tlvs Array range from the LLDP layer.
    fn tlvs_array_range(buf: &DissectBuffer) -> core::ops::Range<u32> {
        let layer = buf.layer_by_name("LLDP").unwrap();
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        match &tlvs_field.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn parse_lldp_mandatory_tlvs() {
        let data = build_mandatory_lldp();
        let mut buf = DissectBuffer::new();
        let result = LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);

        let array_range = tlvs_array_range(&buf);
        assert_eq!(count_objects(&buf, &array_range), 4); // Chassis ID, Port ID, TTL, End

        // Chassis ID TLV
        let chassis_range = tlv_object_range(&buf, &array_range, 0);
        assert_eq!(
            *obj_field_value(&buf, &chassis_range, "type"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *obj_field_value(&buf, &chassis_range, "id"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );

        // Port ID TLV
        let port_range = tlv_object_range(&buf, &array_range, 1);
        assert_eq!(
            *obj_field_value(&buf, &port_range, "type"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *obj_field_value(&buf, &port_range, "id"),
            FieldValue::Bytes(b"ge0" as &[u8])
        );

        // TTL TLV
        let ttl_range = tlv_object_range(&buf, &array_range, 2);
        assert_eq!(
            *obj_field_value(&buf, &ttl_range, "ttl"),
            FieldValue::U16(120)
        );

        // End TLV
        let end_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &end_range, "type"),
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_lldp_optional_tlvs() {
        // Start with mandatory prefix then append three optional string TLVs + End.
        let mut data = build_mandatory_lldp();
        let trim = data.len() - 2;
        data.truncate(trim); // strip End Of LLDPDU

        let desc = b"Uplink01";
        data.extend_from_slice(&((4u16 << 9) | desc.len() as u16).to_be_bytes());
        data.extend_from_slice(desc);

        let sname = b"switch";
        data.extend_from_slice(&((5u16 << 9) | sname.len() as u16).to_be_bytes());
        data.extend_from_slice(sname);

        let sdesc = b"Linux 6.1";
        data.extend_from_slice(&((6u16 << 9) | sdesc.len() as u16).to_be_bytes());
        data.extend_from_slice(sdesc);

        data.extend_from_slice(&0x0000u16.to_be_bytes()); // End Of LLDPDU

        let mut buf = DissectBuffer::new();
        let result = LldpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());

        let array_range = tlvs_array_range(&buf);
        assert_eq!(count_objects(&buf, &array_range), 7); // 3 mandatory + 3 optional + End

        // Port Description
        let port_desc_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &port_desc_range, "value"),
            FieldValue::Bytes(b"Uplink01" as &[u8])
        );
        {
            let fields = buf.nested_fields(&port_desc_range);
            let base = fields.iter().find(|f| f.name() == "type").unwrap();
            let display = base.descriptor.display_fn.unwrap()(&base.value, &[]);
            assert_eq!(display, Some("Port Description"));
        }

        // System Name
        let sys_name_range = tlv_object_range(&buf, &array_range, 4);
        assert_eq!(
            *obj_field_value(&buf, &sys_name_range, "value"),
            FieldValue::Bytes(b"switch" as &[u8])
        );

        // System Description
        let sys_desc_range = tlv_object_range(&buf, &array_range, 5);
        assert_eq!(
            *obj_field_value(&buf, &sys_desc_range, "value"),
            FieldValue::Bytes(b"Linux 6.1" as &[u8])
        );
    }

    #[test]
    fn parse_lldp_system_capabilities() {
        // System Capabilities TLV: type=7, length=4
        // Available: Bridge(0x0004) | Router(0x0010) = 0x0014; Enabled: Router = 0x0010
        let caps_value = [0x00u8, 0x14, 0x00, 0x10];
        let data = build_lldp_with_optional(0x0E04, &caps_value);

        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = tlvs_array_range(&buf);

        // System Capabilities TLV is at index 3
        let caps_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &caps_range, "available_capabilities"),
            FieldValue::U16(0x0014)
        );
        assert_eq!(
            *obj_field_value(&buf, &caps_range, "enabled_capabilities"),
            FieldValue::U16(0x0010)
        );
    }

    #[test]
    fn parse_lldp_management_address() {
        // Management Address TLV: type=8; addr=IPv4 192.168.1.1, ifIndex=1
        let mgmt_value: &[u8] = &[
            5, 1, 192, 168, 1, 1, // addr string length=5, subtype=IPv4, address
            2, 0, 0, 0, 1, // interface numbering subtype=ifIndex, number=1
            0, // OID string length=0
        ];
        let hdr = (8u16 << 9) | mgmt_value.len() as u16;
        let data = build_lldp_with_optional(hdr, mgmt_value);

        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = tlvs_array_range(&buf);

        let mgmt_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "type"),
            FieldValue::U8(8)
        );
        {
            let fields = buf.nested_fields(&mgmt_range);
            let base = fields.iter().find(|f| f.name() == "type").unwrap();
            let display = base.descriptor.display_fn.unwrap()(&base.value, &[]);
            assert_eq!(display, Some("Management Address"));
        }
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "addr_string_length"),
            FieldValue::U8(5)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "addr_subtype"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "address"),
            FieldValue::Ipv4Addr([192, 168, 1, 1])
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "iface_numbering_subtype"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "iface_number"),
            FieldValue::U32(1)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "oid_length"),
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_lldp_management_address_ipv6() {
        // Management Address TLV with IPv6 address (subtype=2, 16-byte address).
        let ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let mut mgmt_value = Vec::new();
        mgmt_value.push(17); // addr string length = 1 (subtype) + 16 (address)
        mgmt_value.push(2); // addr subtype: IPv6
        mgmt_value.extend_from_slice(&ipv6);
        mgmt_value.push(2); // iface numbering subtype
        mgmt_value.extend_from_slice(&42u32.to_be_bytes());
        mgmt_value.push(0); // OID length = 0

        let hdr = (8u16 << 9) | mgmt_value.len() as u16;
        let data = build_lldp_with_optional(hdr, &mgmt_value);

        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = tlvs_array_range(&buf);
        let mgmt_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "addr_subtype"),
            FieldValue::U8(2)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "address"),
            FieldValue::Ipv6Addr(ipv6)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "iface_number"),
            FieldValue::U32(42)
        );
    }

    #[test]
    fn parse_lldp_management_address_with_oid() {
        // Management Address TLV with a non-empty OID trailer.
        let oid = [0x2b, 0x06, 0x01, 0x04, 0x01]; // iso.org.dod.internet.private
        let mut mgmt_value = Vec::new();
        mgmt_value.push(5); // addr string length
        mgmt_value.push(1); // IPv4 subtype
        mgmt_value.extend_from_slice(&[10, 0, 0, 1]);
        mgmt_value.push(2); // iface numbering subtype
        mgmt_value.extend_from_slice(&7u32.to_be_bytes());
        mgmt_value.push(oid.len() as u8);
        mgmt_value.extend_from_slice(&oid);

        let hdr = (8u16 << 9) | mgmt_value.len() as u16;
        let data = build_lldp_with_optional(hdr, &mgmt_value);

        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = tlvs_array_range(&buf);
        let mgmt_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "oid_length"),
            FieldValue::U8(oid.len() as u8)
        );
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "oid"),
            FieldValue::Bytes(&oid)
        );
    }

    #[test]
    fn parse_lldp_management_address_too_short() {
        // Mgmt Address TLV value only 8 bytes (below 9-byte minimum from 8.5.9).
        let mgmt_value: &[u8] = &[2, 1, 127, 0, 0, 1, 2, 0];
        let hdr = (8u16 << 9) | mgmt_value.len() as u16;
        let data = build_lldp_with_optional(hdr, mgmt_value);

        let mut buf = DissectBuffer::new();
        assert!(LldpDissector.dissect(&data, &mut buf, 0).is_err());
    }

    #[test]
    fn parse_lldp_management_address_too_long() {
        // Mgmt Address TLV value 168 bytes (above 167-byte maximum from 8.5.9).
        let mut mgmt_value = Vec::new();
        mgmt_value.push(32); // max addr string length
        mgmt_value.push(0); // addr subtype = other (falls back to Bytes)
        mgmt_value.extend_from_slice(&[0u8; 31]); // 31 address bytes
        mgmt_value.push(2); // iface numbering subtype
        mgmt_value.extend_from_slice(&0u32.to_be_bytes());
        mgmt_value.push(129); // OID length claim = 129 (one over max)
        mgmt_value.extend_from_slice(&[0u8; 129]);
        assert_eq!(mgmt_value.len(), 168);

        let hdr = (8u16 << 9) | mgmt_value.len() as u16;
        let data = build_lldp_with_optional(hdr, &mgmt_value);

        let mut buf = DissectBuffer::new();
        assert!(LldpDissector.dissect(&data, &mut buf, 0).is_err());
    }

    #[test]
    fn parse_lldp_org_specific() {
        // Org Specific TLV: type=127, length=7; OUI=00:80:C2 (IEEE 802.1), subtype=1
        let org_value = [0x00u8, 0x80, 0xC2, 0x01, 0x01, 0x02, 0x03];
        let data = build_lldp_with_optional(0xFE07, &org_value);

        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = tlvs_array_range(&buf);

        let org_range = tlv_object_range(&buf, &array_range, 3);
        assert_eq!(
            *obj_field_value(&buf, &org_range, "type"),
            FieldValue::U8(127)
        );
        assert_eq!(
            *obj_field_value(&buf, &org_range, "oui"),
            FieldValue::Bytes(&[0x00, 0x80, 0xC2])
        );
        assert_eq!(
            *obj_field_value(&buf, &org_range, "org_subtype"),
            FieldValue::U8(1)
        );
        assert_eq!(
            *obj_field_value(&buf, &org_range, "info"),
            FieldValue::Bytes(&[0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn parse_lldp_truncated() {
        // Only 1 byte — not enough for a TLV header
        let data: &[u8] = &[0x00];
        let mut buf = DissectBuffer::new();
        let result = LldpDissector.dissect(data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_lldp_empty_data() {
        let data: &[u8] = &[];
        let mut buf = DissectBuffer::new();
        let result = LldpDissector.dissect(data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_lldp_truncated_tlv_value() {
        // Chassis ID TLV header says length=7 but only 3 bytes of value follow
        let data: &[u8] = &[0x02, 0x07, 0x04, 0x00, 0x11];
        let mut buf = DissectBuffer::new();
        let result = LldpDissector.dissect(data, &mut buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_lldp_with_offset() {
        let data = build_mandatory_lldp();
        let mut buf = DissectBuffer::new();
        let offset = 14; // e.g., after Ethernet header
        let result = LldpDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = buf.layer_by_name("LLDP").unwrap();
        assert_eq!(layer.range.start, offset);
        assert_eq!(layer.range.end, offset + result.bytes_consumed);
    }

    #[test]
    fn chassis_and_port_subtype_display_names() {
        // Verify the subtype display_fn resolves the correct table based on
        // the sibling "type" field (Chassis ID vs Port ID).
        let data = build_mandatory_lldp();
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let array_range = tlvs_array_range(&buf);

        let chassis_range = tlv_object_range(&buf, &array_range, 0);
        let chassis_fields = buf.nested_fields(&chassis_range);
        let chassis_subtype = chassis_fields
            .iter()
            .find(|f| f.name() == "subtype")
            .unwrap();
        let display =
            chassis_subtype.descriptor.display_fn.unwrap()(&chassis_subtype.value, chassis_fields);
        assert_eq!(display, Some("MAC address"));

        let port_range = tlv_object_range(&buf, &array_range, 1);
        let port_fields = buf.nested_fields(&port_range);
        let port_subtype = port_fields.iter().find(|f| f.name() == "subtype").unwrap();
        let display = port_subtype.descriptor.display_fn.unwrap()(&port_subtype.value, port_fields);
        assert_eq!(display, Some("Locally assigned"));
    }

    #[test]
    fn parse_lldp_ttl_invalid_length() {
        // IEEE 802.1AB-2016, Section 8.5.4: TTL TLV length must be exactly 2.
        // Build a frame whose TTL TLV has length=3 instead of 2.
        let mut data = Vec::new();
        data.extend_from_slice(&0x0207u16.to_be_bytes()); // Chassis ID, length=7
        data.push(4);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&0x0404u16.to_be_bytes()); // Port ID, length=4
        data.push(7);
        data.extend_from_slice(b"ge0");
        data.extend_from_slice(&0x0603u16.to_be_bytes()); // TTL, length=3 (invalid)
        data.extend_from_slice(&[0x00, 0x00, 0x78]);
        data.extend_from_slice(&0x0000u16.to_be_bytes()); // End

        let mut buf = DissectBuffer::new();
        assert!(LldpDissector.dissect(&data, &mut buf, 0).is_err());
    }

    #[test]
    fn parse_lldp_system_capabilities_invalid_length() {
        // IEEE 802.1AB-2016, Section 8.5.8: System Capabilities length must be 4.
        // Append a System Capabilities TLV with length=3 to the mandatory prefix.
        let caps_value = [0x00u8, 0x14, 0x00];
        let hdr = (7u16 << 9) | caps_value.len() as u16;
        let data = build_lldp_with_optional(hdr, &caps_value);

        let mut buf = DissectBuffer::new();
        assert!(LldpDissector.dissect(&data, &mut buf, 0).is_err());
    }

    #[test]
    fn parse_lldp_end_invalid_length() {
        // IEEE 802.1AB-2016, Section 8.5.1: End Of LLDPDU length must be 0.
        // Construct an End Of LLDPDU TLV with length=1.
        let mut data = Vec::new();
        data.extend_from_slice(&0x0207u16.to_be_bytes()); // Chassis ID, length=7
        data.push(4);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&0x0404u16.to_be_bytes()); // Port ID, length=4
        data.push(7);
        data.extend_from_slice(b"ge0");
        data.extend_from_slice(&0x0602u16.to_be_bytes()); // TTL, length=2
        data.extend_from_slice(&120u16.to_be_bytes());
        data.extend_from_slice(&0x0001u16.to_be_bytes()); // End with length=1 (invalid)
        data.push(0xff);

        let mut buf = DissectBuffer::new();
        assert!(LldpDissector.dissect(&data, &mut buf, 0).is_err());
    }

    #[test]
    fn tlv_container_resolves_to_tlv_name() {
        // Minimal LLDPDU — the first TLV is Chassis ID so the container
        // label resolves to "Chassis ID" instead of duplicating "TLV Type".
        let data = build_mandatory_lldp();
        let mut buf = DissectBuffer::new();
        LldpDissector.dissect(&data, &mut buf, 0).unwrap();

        let (idx, field) = buf
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "tlv")
            .expect("tlv container not found");
        assert!(matches!(field.value, FieldValue::Object(_)));
        assert_eq!(field.display_name(), "TLV");
        assert_eq!(
            buf.resolve_container_display_name(idx as u32),
            Some("Chassis ID")
        );
    }
}
