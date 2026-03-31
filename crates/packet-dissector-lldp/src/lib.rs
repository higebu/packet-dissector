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
//! | 8.5.2 | LLDPDU format / TLV structure | `parse_lldp_mandatory_tlvs` |
//! | 8.5.3 | Chassis ID TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.4 | Port ID TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.5 | Time To Live TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.6 | End Of LLDPDU TLV | `parse_lldp_mandatory_tlvs` |
//! | 8.5.7 | Port Description TLV | `parse_lldp_optional_tlvs` |
//! | 8.5.8 | System Name TLV | `parse_lldp_optional_tlvs` |
//! | 8.5.9 | System Description TLV | `parse_lldp_optional_tlvs` |
//! | 8.5.10 | System Capabilities TLV | `parse_lldp_system_capabilities` |
//! | 8.5.11 | Management Address TLV | `parse_lldp_management_address` |
//! | 9.6.1 | Organizationally Specific TLV | `parse_lldp_org_specific` |
//! | — | Truncated LLDPDU | `parse_lldp_truncated` |
//! | — | Empty LLDPDU | `parse_lldp_empty_data` |

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, MacAddr, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

/// Minimum TLV header size (type + length encoded in 2 bytes).
/// IEEE 802.1AB-2016, Section 8.5.2 — LLDPDU format.
const TLV_HEADER_SIZE: usize = 2;

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
/// IEEE 802.1AB-2016, Section 8.5.3.2 — chassis ID subtype.
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
/// IEEE 802.1AB-2016, Section 8.5.4.2 — port ID subtype.
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
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8).optional(),
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
            // IEEE 802.1AB-2016, Section 8.5.2 — each TLV header is 2 bytes.
            if pos + TLV_HEADER_SIZE > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + TLV_HEADER_SIZE,
                    actual: data.len(),
                });
            }

            // IEEE 802.1AB-2016, Section 8.5.2 — TLV header encoding:
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
                &TLV_CHILD_FIELDS[FD_TLV_TYPE], // placeholder descriptor, overwritten by Object
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
                // IEEE 802.1AB-2016, Section 8.5.3 — Chassis ID TLV
                TLV_TYPE_CHASSIS_ID => {
                    parse_id_tlv(
                        buf,
                        tlv_value,
                        offset + tlv_value_start,
                        chassis_id_subtype_name,
                        CHASSIS_ID_SUBTYPE_MAC,
                    )?;
                }
                // IEEE 802.1AB-2016, Section 8.5.4 — Port ID TLV
                TLV_TYPE_PORT_ID => {
                    parse_id_tlv(
                        buf,
                        tlv_value,
                        offset + tlv_value_start,
                        port_id_subtype_name,
                        PORT_ID_SUBTYPE_MAC,
                    )?;
                }
                // IEEE 802.1AB-2016, Section 8.5.5 — Time To Live TLV
                TLV_TYPE_TTL => {
                    if tlv_length < 2 {
                        return Err(PacketError::InvalidHeader(
                            "TTL TLV value must be at least 2 bytes",
                        ));
                    }
                    let ttl = read_be_u16(tlv_value, 0)?;
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_TTL],
                        FieldValue::U16(ttl),
                        offset + tlv_value_start..offset + tlv_value_start + 2,
                    );
                }
                // IEEE 802.1AB-2016, Section 8.5.7/8.5.8/8.5.9 — String TLVs
                TLV_TYPE_PORT_DESCRIPTION | TLV_TYPE_SYSTEM_NAME | TLV_TYPE_SYSTEM_DESCRIPTION => {
                    buf.push_field(
                        &TLV_CHILD_FIELDS[FD_TLV_VALUE],
                        FieldValue::Bytes(tlv_value),
                        offset + tlv_value_start..offset + tlv_value_start + tlv_length,
                    );
                }
                // IEEE 802.1AB-2016, Section 8.5.10 — System Capabilities TLV
                TLV_TYPE_SYSTEM_CAPABILITIES => {
                    if tlv_length < 4 {
                        return Err(PacketError::InvalidHeader(
                            "System Capabilities TLV must be at least 4 bytes",
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
                // IEEE 802.1AB-2016, Section 9.6.1 — Organizationally Specific TLV
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
                // End Of LLDPDU — no additional fields
                TLV_TYPE_END => {}
                // IEEE 802.1AB-2016, Section 8.5.11 — Management Address TLV and
                // unknown/reserved TLV types: store value as raw bytes.
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

            // IEEE 802.1AB-2016, Section 8.5.6 — End Of LLDPDU terminates the PDU
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
/// IEEE 802.1AB-2016, Sections 8.5.3 and 8.5.4.
///
/// `mac_subtype` encodes the subtype number for MAC address IDs.
fn parse_id_tlv<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    value: &'pkt [u8],
    abs_offset: usize,
    subtype_name_fn: fn(u8) -> Option<&'static str>,
    mac_subtype: u8,
) -> Result<(), PacketError> {
    if value.is_empty() {
        return Err(PacketError::InvalidHeader(
            "ID TLV must contain at least a subtype byte",
        ));
    }

    let subtype = value[0];
    // Call once and reuse for both the display field and value-type classification.
    let subtype_name = subtype_name_fn(subtype);

    buf.push_field(
        &TLV_CHILD_FIELDS[FD_TLV_SUBTYPE],
        FieldValue::U8(subtype),
        abs_offset..abs_offset + 1,
    );

    let _ = subtype_name;

    let id_data = &value[1..];
    let id_offset = abs_offset + 1;

    // Dispatch on the numeric subtype to choose the field value type:
    // - mac_subtype (Chassis ID: 4, Port ID: 3) with a 6-byte value → MacAddr
    // - string_subtypes (Interface alias/name, Locally assigned) → Bytes (deferred formatting)
    // - all other subtypes → raw Bytes
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
        // Raw value contains the full management address structure
        assert_eq!(
            *obj_field_value(&buf, &mgmt_range, "raw"),
            FieldValue::Bytes(mgmt_value)
        );
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
}
