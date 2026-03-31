//! STP/RSTP BPDU dissector.
//!
//! Parses Spanning Tree Protocol (STP) and Rapid Spanning Tree Protocol (RSTP)
//! Bridge Protocol Data Units (BPDUs) as defined in IEEE 802.1D-2004 and
//! IEEE 802.1w-2004.
//!
//! ## References
//! - IEEE 802.1D-2004 (STP): <https://standards.ieee.org/ieee/802.1D/2486/>
//! - IEEE 802.1w-2004 (RSTP, incorporated into IEEE 802.1D-2004):
//!   <https://standards.ieee.org/ieee/802.1w/1039/>
//!
//! ## BPDU Types
//!
//! | Type | Version | Name                            | Size    |
//! |------|---------|---------------------------------|---------|
//! | 0x00 | 0       | STP Configuration BPDU          | 35 bytes|
//! | 0x02 | 2       | RST BPDU                        | 36 bytes|
//! | 0x80 | 0       | Topology Change Notification    | 4 bytes |

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, MacAddr};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_PROTOCOL_ID: usize = 0;
const FD_VERSION: usize = 1;
const FD_BPDU_TYPE: usize = 2;
const FD_FLAGS: usize = 3;
const FD_FLAGS_TC: usize = 4;
const FD_FLAGS_PROPOSAL: usize = 5;
const FD_FLAGS_PORT_ROLE: usize = 6;
const FD_FLAGS_LEARNING: usize = 7;
const FD_FLAGS_FORWARDING: usize = 8;
const FD_FLAGS_AGREEMENT: usize = 9;
const FD_FLAGS_TCA: usize = 10;
const FD_ROOT_PRIORITY: usize = 11;
const FD_ROOT_MAC: usize = 12;
const FD_ROOT_PATH_COST: usize = 13;
const FD_BRIDGE_PRIORITY: usize = 14;
const FD_BRIDGE_MAC: usize = 15;
const FD_PORT_ID: usize = 16;
const FD_MESSAGE_AGE: usize = 17;
const FD_MAX_AGE: usize = 18;
const FD_HELLO_TIME: usize = 19;
const FD_FORWARD_DELAY: usize = 20;
const FD_VERSION1_LENGTH: usize = 21;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("protocol_id", "Protocol Identifier", FieldType::U16),
    FieldDescriptor::new("version", "Protocol Version", FieldType::U8),
    FieldDescriptor {
        name: "bpdu_type",
        display_name: "BPDU Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => bpdu_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("flags_tc", "Topology Change", FieldType::U8).optional(),
    FieldDescriptor::new("flags_proposal", "Proposal", FieldType::U8).optional(),
    FieldDescriptor::new("flags_port_role", "Port Role", FieldType::U8).optional(),
    FieldDescriptor::new("flags_learning", "Learning", FieldType::U8).optional(),
    FieldDescriptor::new("flags_forwarding", "Forwarding", FieldType::U8).optional(),
    FieldDescriptor::new("flags_agreement", "Agreement", FieldType::U8).optional(),
    FieldDescriptor::new("flags_tca", "Topology Change Acknowledgment", FieldType::U8).optional(),
    FieldDescriptor::new("root_priority", "Root Bridge Priority", FieldType::U16).optional(),
    FieldDescriptor::new("root_mac", "Root Bridge MAC", FieldType::MacAddr).optional(),
    FieldDescriptor::new("root_path_cost", "Root Path Cost", FieldType::U32).optional(),
    FieldDescriptor::new("bridge_priority", "Bridge Priority", FieldType::U16).optional(),
    FieldDescriptor::new("bridge_mac", "Bridge MAC", FieldType::MacAddr).optional(),
    FieldDescriptor::new("port_id", "Port Identifier", FieldType::U16).optional(),
    FieldDescriptor::new("message_age", "Message Age", FieldType::U16).optional(),
    FieldDescriptor::new("max_age", "Max Age", FieldType::U16).optional(),
    FieldDescriptor::new("hello_time", "Hello Time", FieldType::U16).optional(),
    FieldDescriptor::new("forward_delay", "Forward Delay", FieldType::U16).optional(),
    FieldDescriptor::new("version1_length", "Version 1 Length", FieldType::U8).optional(),
];

/// Minimum BPDU size: Protocol ID (2) + Version (1) + Type (1).
/// IEEE 802.1D-2004, Section 9.3.1.
const MIN_BPDU_SIZE: usize = 4;

/// Full Configuration BPDU size: 35 bytes.
/// IEEE 802.1D-2004, Section 9.3.1, Table 9-1:
/// Header (4) + Flags (1) + Root ID (8) + Root Path Cost (4) +
/// Bridge ID (8) + Port ID (2) + Message Age (2) + Max Age (2) +
/// Hello Time (2) + Forward Delay (2) = 35.
const CONFIG_BPDU_SIZE: usize = 35;

/// RST BPDU size: 36 bytes.
/// IEEE 802.1w-2004 (incorporated into IEEE 802.1D-2004), Section 9.3.3:
/// Configuration BPDU (35) + Version 1 Length (1) = 36.
const RST_BPDU_SIZE: usize = 36;

/// BPDU type value for Configuration BPDUs.
/// IEEE 802.1D-2004, Section 9.3.1.
const BPDU_TYPE_CONFIG: u8 = 0x00;

/// BPDU type value for RST BPDUs.
/// IEEE 802.1D-2004, Section 9.3.3.
const BPDU_TYPE_RST: u8 = 0x02;

/// BPDU type value for Topology Change Notification BPDUs.
/// IEEE 802.1D-2004, Section 9.3.2.
const BPDU_TYPE_TCN: u8 = 0x80;

/// Returns a human-readable name for BPDU type values.
fn bpdu_type_name(v: u8) -> Option<&'static str> {
    match v {
        BPDU_TYPE_CONFIG => Some("Configuration"),
        BPDU_TYPE_RST => Some("RST"),
        BPDU_TYPE_TCN => Some("Topology Change Notification"),
        _ => None,
    }
}

/// STP/RSTP BPDU dissector.
///
/// Handles STP Configuration BPDUs (type 0x00), RST BPDUs (type 0x02),
/// and Topology Change Notification BPDUs (type 0x80).
pub struct StpDissector;

impl Dissector for StpDissector {
    fn name(&self) -> &'static str {
        "Spanning Tree Protocol"
    }

    fn short_name(&self) -> &'static str {
        "STP"
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
        // IEEE 802.1D-2004, Section 9.3: minimum BPDU is 4 bytes (TCN BPDU).
        if data.len() < MIN_BPDU_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_BPDU_SIZE,
                actual: data.len(),
            });
        }

        // IEEE 802.1D-2004, Section 9.3.1: Protocol Identifier (2 octets, always 0x0000).
        let protocol_id = read_be_u16(data, 0)?;
        if protocol_id != 0x0000 {
            return Err(PacketError::InvalidFieldValue {
                field: "protocol_id",
                value: protocol_id as u32,
            });
        }

        // IEEE 802.1D-2004, Section 9.3.1: Protocol Version Identifier (1 octet).
        let version = data[2];
        // IEEE 802.1D-2004, Section 9.3.1: BPDU Type (1 octet).
        let bpdu_type = data[3];

        // Determine BPDU size and parse type-specific fields.
        let bytes_consumed = match bpdu_type {
            BPDU_TYPE_TCN => {
                // IEEE 802.1D-2004, Section 9.3.2: TCN BPDU is exactly 4 bytes.
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + MIN_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                buf.end_layer();
                MIN_BPDU_SIZE
            }
            BPDU_TYPE_CONFIG => {
                // IEEE 802.1D-2004, Section 9.3.1: Configuration BPDU is 35 bytes.
                if data.len() < CONFIG_BPDU_SIZE {
                    return Err(PacketError::Truncated {
                        expected: CONFIG_BPDU_SIZE,
                        actual: data.len(),
                    });
                }
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + CONFIG_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                self.push_config_fields(data, offset, buf, false);
                buf.end_layer();
                CONFIG_BPDU_SIZE
            }
            BPDU_TYPE_RST => {
                // IEEE 802.1D-2004, Section 9.3.3: RST BPDU is 36 bytes.
                if data.len() < RST_BPDU_SIZE {
                    return Err(PacketError::Truncated {
                        expected: RST_BPDU_SIZE,
                        actual: data.len(),
                    });
                }
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + RST_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                self.push_config_fields(data, offset, buf, true);
                // Version 1 Length field (1 octet, must be 0x00).
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION1_LENGTH],
                    FieldValue::U8(data[CONFIG_BPDU_SIZE]),
                    offset + CONFIG_BPDU_SIZE..offset + RST_BPDU_SIZE,
                );
                buf.end_layer();
                RST_BPDU_SIZE
            }
            _ => {
                // Unknown BPDU type — consume only the common header.
                buf.begin_layer(
                    self.short_name(),
                    None,
                    FIELD_DESCRIPTORS,
                    offset..offset + MIN_BPDU_SIZE,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PROTOCOL_ID],
                    FieldValue::U16(protocol_id),
                    offset..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_VERSION],
                    FieldValue::U8(version),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_BPDU_TYPE],
                    FieldValue::U8(bpdu_type),
                    offset + 3..offset + 4,
                );
                buf.end_layer();
                MIN_BPDU_SIZE
            }
        };

        Ok(DissectResult::new(bytes_consumed, DispatchHint::End))
    }
}

impl StpDissector {
    /// Push fields common to Configuration BPDUs and RST BPDUs into the buffer.
    ///
    /// IEEE 802.1D-2004, Section 9.3.1, Table 9-1 and Section 9.3.3:
    /// - Flags (1 octet at offset 4)
    /// - Root Identifier (8 octets at offset 5): Priority (2) + MAC (6)
    /// - Root Path Cost (4 octets at offset 13)
    /// - Bridge Identifier (8 octets at offset 17): Priority (2) + MAC (6)
    /// - Port Identifier (2 octets at offset 25)
    /// - Message Age (2 octets at offset 27)
    /// - Max Age (2 octets at offset 29)
    /// - Hello Time (2 octets at offset 31)
    /// - Forward Delay (2 octets at offset 33)
    fn push_config_fields<'pkt>(
        &self,
        data: &'pkt [u8],
        offset: usize,
        buf: &mut DissectBuffer<'pkt>,
        is_rstp: bool,
    ) {
        // IEEE 802.1D-2004, Section 9.3.1: Flags (1 octet).
        // Bit 0: Topology Change (TC)
        // Bit 1: Proposal (RSTP only)
        // Bits 2-3: Port Role (RSTP only): 0=Unknown, 1=Alternate/Backup, 2=Root, 3=Designated
        // Bit 4: Learning (RSTP only)
        // Bit 5: Forwarding (RSTP only)
        // Bit 6: Agreement (RSTP only)
        // Bit 7: Topology Change Acknowledgment (TCA)
        let flags = data[4];
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::U8(flags),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS_TC],
            FieldValue::U8(flags & 0x01),
            offset + 4..offset + 5,
        );

        if is_rstp {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_PROPOSAL],
                FieldValue::U8((flags >> 1) & 0x01),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_PORT_ROLE],
                FieldValue::U8((flags >> 2) & 0x03),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_LEARNING],
                FieldValue::U8((flags >> 4) & 0x01),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_FORWARDING],
                FieldValue::U8((flags >> 5) & 0x01),
                offset + 4..offset + 5,
            );
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FLAGS_AGREEMENT],
                FieldValue::U8((flags >> 6) & 0x01),
                offset + 4..offset + 5,
            );
        }

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FLAGS_TCA],
            FieldValue::U8((flags >> 7) & 0x01),
            offset + 4..offset + 5,
        );

        // IEEE 802.1D-2004, Section 9.2.5: Bridge Identifier is 8 octets:
        // Priority (4 bits) + System ID Extension (12 bits) + MAC Address (6 octets).
        // Root Bridge Identifier at offset 5.
        let root_priority = read_be_u16(data, 5).unwrap_or_default();
        let root_mac = MacAddr([data[7], data[8], data[9], data[10], data[11], data[12]]);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_PRIORITY],
            FieldValue::U16(root_priority),
            offset + 5..offset + 7,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_MAC],
            FieldValue::MacAddr(root_mac),
            offset + 7..offset + 13,
        );

        // Root Path Cost (4 octets at offset 13).
        let root_path_cost = read_be_u32(data, 13).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_PATH_COST],
            FieldValue::U32(root_path_cost),
            offset + 13..offset + 17,
        );

        // Bridge Identifier at offset 17.
        let bridge_priority = read_be_u16(data, 17).unwrap_or_default();
        let bridge_mac = MacAddr([data[19], data[20], data[21], data[22], data[23], data[24]]);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BRIDGE_PRIORITY],
            FieldValue::U16(bridge_priority),
            offset + 17..offset + 19,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BRIDGE_MAC],
            FieldValue::MacAddr(bridge_mac),
            offset + 19..offset + 25,
        );

        // Port Identifier (2 octets at offset 25).
        let port_id = read_be_u16(data, 25).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PORT_ID],
            FieldValue::U16(port_id),
            offset + 25..offset + 27,
        );

        // Timer fields are encoded in units of 1/256 second (IEEE 802.1D-2004, Section 9.3.1).
        // Message Age (2 octets at offset 27).
        let message_age = read_be_u16(data, 27).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_AGE],
            FieldValue::U16(message_age),
            offset + 27..offset + 29,
        );

        // Max Age (2 octets at offset 29).
        let max_age = read_be_u16(data, 29).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MAX_AGE],
            FieldValue::U16(max_age),
            offset + 29..offset + 31,
        );

        // Hello Time (2 octets at offset 31).
        let hello_time = read_be_u16(data, 31).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HELLO_TIME],
            FieldValue::U16(hello_time),
            offset + 31..offset + 33,
        );

        // Forward Delay (2 octets at offset 33).
        let forward_delay = read_be_u16(data, 33).unwrap_or_default();
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FORWARD_DELAY],
            FieldValue::U16(forward_delay),
            offset + 33..offset + 35,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal STP Configuration BPDU (35 bytes).
    fn build_config_bpdu() -> Vec<u8> {
        let mut pkt = vec![0u8; CONFIG_BPDU_SIZE];
        // Protocol ID = 0x0000
        pkt[0] = 0x00;
        pkt[1] = 0x00;
        // Version = 0 (STP)
        pkt[2] = 0x00;
        // BPDU Type = 0x00 (Configuration)
        pkt[3] = 0x00;
        // Flags: TC=1, TCA=1 → 0x81
        pkt[4] = 0x81;
        // Root Bridge ID: priority=0x8000, MAC=00:11:22:33:44:55
        pkt[5] = 0x80;
        pkt[6] = 0x00;
        pkt[7..13].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Root Path Cost = 4
        pkt[13..17].copy_from_slice(&4u32.to_be_bytes());
        // Bridge ID: priority=0x8001, MAC=AA:BB:CC:DD:EE:FF
        pkt[17] = 0x80;
        pkt[18] = 0x01;
        pkt[19..25].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Port ID = 0x8002
        pkt[25..27].copy_from_slice(&0x8002u16.to_be_bytes());
        // Message Age = 256 (1 second in 1/256 units)
        pkt[27..29].copy_from_slice(&256u16.to_be_bytes());
        // Max Age = 5120 (20 seconds)
        pkt[29..31].copy_from_slice(&5120u16.to_be_bytes());
        // Hello Time = 512 (2 seconds)
        pkt[31..33].copy_from_slice(&512u16.to_be_bytes());
        // Forward Delay = 3840 (15 seconds)
        pkt[33..35].copy_from_slice(&3840u16.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_stp_config_bpdu() {
        let data = build_config_bpdu();
        let mut buf = DissectBuffer::new();
        let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 35);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "protocol_id").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "bpdu_type").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "bpdu_type_name"),
            Some("Configuration")
        );
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0x81)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tc").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tca").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_priority").unwrap().value,
            FieldValue::U16(0x8000)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_mac").unwrap().value,
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(
            buf.field_by_name(layer, "root_path_cost").unwrap().value,
            FieldValue::U32(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "bridge_priority").unwrap().value,
            FieldValue::U16(0x8001)
        );
        assert_eq!(
            buf.field_by_name(layer, "bridge_mac").unwrap().value,
            FieldValue::MacAddr(MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
        );
        assert_eq!(
            buf.field_by_name(layer, "port_id").unwrap().value,
            FieldValue::U16(0x8002)
        );
        assert_eq!(
            buf.field_by_name(layer, "message_age").unwrap().value,
            FieldValue::U16(256)
        );
        assert_eq!(
            buf.field_by_name(layer, "max_age").unwrap().value,
            FieldValue::U16(5120)
        );
        assert_eq!(
            buf.field_by_name(layer, "hello_time").unwrap().value,
            FieldValue::U16(512)
        );
        assert_eq!(
            buf.field_by_name(layer, "forward_delay").unwrap().value,
            FieldValue::U16(3840)
        );
    }

    #[test]
    fn parse_stp_tcn_bpdu() {
        // TCN BPDU: Protocol ID (0x0000) + Version (0x00) + Type (0x80)
        let data = [0x00, 0x00, 0x00, 0x80];
        let mut buf = DissectBuffer::new();
        let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 4);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "bpdu_type").unwrap().value,
            FieldValue::U8(0x80)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "bpdu_type_name"),
            Some("Topology Change Notification")
        );
        // TCN BPDUs have no flags or bridge fields.
        assert!(buf.field_by_name(layer, "flags").is_none());
    }

    #[test]
    fn parse_rstp_bpdu() {
        let mut data = vec![0u8; RST_BPDU_SIZE];
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x02; // Version = 2 (RSTP)
        data[3] = 0x02; // BPDU Type = RST
        // Flags: TC=1, Proposal=1, Port Role=3 (Designated), Learning=1,
        // Forwarding=1, Agreement=1, TCA=0
        // Bits: 0=TC(1), 1=Proposal(1), 2-3=Role(11), 4=Learning(1),
        //       5=Forwarding(1), 6=Agreement(1), 7=TCA(0)
        // = 0b0111_1111 = 0x7F
        data[4] = 0x7F;
        // Root Bridge ID: priority=0x8000, MAC=00:AA:BB:CC:DD:EE
        data[5] = 0x80;
        data[6] = 0x00;
        data[7..13].copy_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        // Root Path Cost = 10
        data[13..17].copy_from_slice(&10u32.to_be_bytes());
        // Bridge ID: priority=0x8000, MAC=00:11:22:33:44:55
        data[17] = 0x80;
        data[18] = 0x00;
        data[19..25].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Port ID = 0x8001
        data[25..27].copy_from_slice(&0x8001u16.to_be_bytes());
        // Message Age = 0
        data[27..29].copy_from_slice(&0u16.to_be_bytes());
        // Max Age = 5120 (20s)
        data[29..31].copy_from_slice(&5120u16.to_be_bytes());
        // Hello Time = 512 (2s)
        data[31..33].copy_from_slice(&512u16.to_be_bytes());
        // Forward Delay = 3840 (15s)
        data[33..35].copy_from_slice(&3840u16.to_be_bytes());
        // Version 1 Length = 0x00
        data[35] = 0x00;

        let mut buf = DissectBuffer::new();
        let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 36);
        assert_eq!(result.next, DispatchHint::End);

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "bpdu_type").unwrap().value,
            FieldValue::U8(0x02)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "bpdu_type_name"),
            Some("RST")
        );

        // RSTP flags
        assert_eq!(
            buf.field_by_name(layer, "flags").unwrap().value,
            FieldValue::U8(0x7F)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tc").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_proposal").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_port_role").unwrap().value,
            FieldValue::U8(3)
        ); // Designated
        assert_eq!(
            buf.field_by_name(layer, "flags_learning").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_forwarding").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_agreement").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "flags_tca").unwrap().value,
            FieldValue::U8(0)
        );

        assert_eq!(
            buf.field_by_name(layer, "version1_length").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_stp_truncated_header() {
        let data = [0x00, 0x00, 0x00]; // 3 bytes, need 4
        let mut buf = DissectBuffer::new();
        let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_stp_truncated_config() {
        // 4-byte header + not enough for config body
        let data = [0x00, 0x00, 0x00, 0x00, 0x00]; // 5 bytes, need 35
        let mut buf = DissectBuffer::new();
        let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 35,
                actual: 5
            }
        ));
    }

    #[test]
    fn parse_stp_invalid_protocol_id() {
        let data = [0x00, 0x01, 0x00, 0x80]; // Protocol ID = 0x0001 (invalid)
        let mut buf = DissectBuffer::new();
        let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidFieldValue { .. }));
    }

    #[test]
    fn stp_dissector_metadata() {
        let d = StpDissector;
        assert_eq!(d.name(), "Spanning Tree Protocol");
        assert_eq!(d.short_name(), "STP");
        assert!(!d.field_descriptors().is_empty());
    }

    #[test]
    fn parse_stp_with_offset() {
        let data = build_config_bpdu();
        let mut buf = DissectBuffer::new();
        StpDissector.dissect(&data, &mut buf, 17).unwrap();

        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(layer.range, 17..17 + 35);
        assert_eq!(
            buf.field_by_name(layer, "protocol_id").unwrap().range,
            17..19
        );
    }
}
