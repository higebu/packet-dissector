//! # IEEE 802.1D / 802.1w (STP/RSTP) Coverage
//!
//! | Spec                      | Description                              | Test                          |
//! |---------------------------|------------------------------------------|-------------------------------|
//! | IEEE 802.1D-2004 §9.3.1   | Configuration BPDU parsing               | parse_stp_config_bpdu         |
//! | IEEE 802.1D-2004 §9.3.2   | TCN BPDU parsing                         | parse_stp_tcn_bpdu            |
//! | IEEE 802.1D-2004 §9.3.3   | RST BPDU parsing                         | parse_rstp_bpdu               |
//! | IEEE 802.1D-2004 §9.3.1   | Truncated Config BPDU                    | parse_stp_truncated_config    |
//! | IEEE 802.1D-2004 §9.3     | Truncated header (< 4 bytes)             | parse_stp_truncated_header    |
//! | IEEE 802.1D-2004 §9.3.1   | Invalid Protocol ID                      | parse_stp_invalid_protocol_id |
//! | IEEE 802.1D-2004 §9.3.1   | Flags: TC and TCA bits                   | parse_stp_flags_tc_tca        |
//! | IEEE 802.1w-2004 §9.3.3   | RSTP flags: all bits                     | parse_rstp_flags_all          |
//! | IEEE 802.1D-2004 §9.2.5   | Bridge ID: priority + MAC                | parse_stp_bridge_id           |
//! | —                         | Dissector metadata                       | stp_dissector_metadata        |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::{FieldValue, MacAddr};
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::stp::StpDissector;

/// Build a minimal STP Configuration BPDU (35 bytes).
fn build_config_bpdu(
    root_priority: u16,
    root_mac: [u8; 6],
    root_path_cost: u32,
    bridge_priority: u16,
    bridge_mac: [u8; 6],
    port_id: u16,
    flags: u8,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 35];
    pkt[0] = 0x00;
    pkt[1] = 0x00; // Protocol ID
    pkt[2] = 0x00; // Version (STP)
    pkt[3] = 0x00; // Type (Configuration)
    pkt[4] = flags;
    pkt[5..7].copy_from_slice(&root_priority.to_be_bytes());
    pkt[7..13].copy_from_slice(&root_mac);
    pkt[13..17].copy_from_slice(&root_path_cost.to_be_bytes());
    pkt[17..19].copy_from_slice(&bridge_priority.to_be_bytes());
    pkt[19..25].copy_from_slice(&bridge_mac);
    pkt[25..27].copy_from_slice(&port_id.to_be_bytes());
    // Message Age = 256 (1s), Max Age = 5120 (20s), Hello = 512 (2s), Forward Delay = 3840 (15s)
    pkt[27..29].copy_from_slice(&256u16.to_be_bytes());
    pkt[29..31].copy_from_slice(&5120u16.to_be_bytes());
    pkt[31..33].copy_from_slice(&512u16.to_be_bytes());
    pkt[33..35].copy_from_slice(&3840u16.to_be_bytes());
    pkt
}

#[test]
fn parse_stp_config_bpdu() {
    let data = build_config_bpdu(
        0x8000,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        4,
        0x8001,
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x8002,
        0x00, // no flags
    );
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
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("Configuration")
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
}

#[test]
fn parse_stp_tcn_bpdu() {
    let data = [0x00, 0x00, 0x00, 0x80];
    let mut buf = DissectBuffer::new();
    let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 4);
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "bpdu_type").unwrap().value,
        FieldValue::U8(0x80)
    );
    assert_eq!(
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("Topology Change Notification")
    );
    assert!(buf.field_by_name(layer, "flags").is_none());
}

#[test]
fn parse_rstp_bpdu() {
    let mut data = vec![0u8; 36];
    data[2] = 0x02; // Version 2 (RSTP)
    data[3] = 0x02; // Type RST
    data[4] = 0x3C; // Flags: Port Role=3 (Designated), Learning=1, Forwarding=1
    data[5..7].copy_from_slice(&0x8000u16.to_be_bytes());
    data[7..13].copy_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    data[13..17].copy_from_slice(&10u32.to_be_bytes());
    data[17..19].copy_from_slice(&0x8000u16.to_be_bytes());
    data[19..25].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    data[25..27].copy_from_slice(&0x8001u16.to_be_bytes());
    data[29..31].copy_from_slice(&5120u16.to_be_bytes());
    data[31..33].copy_from_slice(&512u16.to_be_bytes());
    data[33..35].copy_from_slice(&3840u16.to_be_bytes());
    data[35] = 0x00; // Version 1 Length

    let mut buf = DissectBuffer::new();
    let result = StpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 36);
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "version").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("RST")
    );
    // Verify RSTP-specific flag fields exist
    assert!(buf.field_by_name(layer, "flags_proposal").is_some());
    assert!(buf.field_by_name(layer, "flags_port_role").is_some());
    assert!(buf.field_by_name(layer, "flags_learning").is_some());
    assert!(buf.field_by_name(layer, "flags_forwarding").is_some());
    assert!(buf.field_by_name(layer, "flags_agreement").is_some());
    assert_eq!(
        buf.field_by_name(layer, "version1_length").unwrap().value,
        FieldValue::U8(0)
    );
}

#[test]
fn parse_stp_truncated_config() {
    let data = [0x00, 0x00, 0x00, 0x00, 0x00];
    let mut buf = DissectBuffer::new();
    let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 35,
            actual: 5
        }
    ));
}

#[test]
fn parse_stp_truncated_header() {
    let data = [0x00, 0x00, 0x00];
    let mut buf = DissectBuffer::new();
    let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 4,
            actual: 3
        }
    ));
}

#[test]
fn parse_stp_invalid_protocol_id() {
    let data = [0x00, 0x01, 0x00, 0x80];
    let mut buf = DissectBuffer::new();
    let err = StpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { .. }
    ));
}

#[test]
fn parse_stp_flags_tc_tca() {
    let data = build_config_bpdu(
        0x8000, [0; 6], 0, 0x8000, [0; 6], 0x8001, 0x81, // TC=1, TCA=1
    );
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags_tc").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags_tca").unwrap().value,
        FieldValue::U8(1)
    );
}

#[test]
fn parse_rstp_flags_all() {
    let mut data = vec![0u8; 36];
    data[2] = 0x02;
    data[3] = 0x02;
    // All RSTP flags set: TC=1, Proposal=1, Role=3, Learning=1, Forwarding=1, Agreement=1, TCA=1
    // = 0xFF
    data[4] = 0xFF;
    // Fill remaining required fields
    data[5..7].copy_from_slice(&0x8000u16.to_be_bytes());
    data[7..13].copy_from_slice(&[0; 6]);
    data[17..19].copy_from_slice(&0x8000u16.to_be_bytes());
    data[19..25].copy_from_slice(&[0; 6]);
    data[25..27].copy_from_slice(&0x8001u16.to_be_bytes());
    data[29..31].copy_from_slice(&5120u16.to_be_bytes());
    data[31..33].copy_from_slice(&512u16.to_be_bytes());
    data[33..35].copy_from_slice(&3840u16.to_be_bytes());

    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("STP").unwrap();
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
    );
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
        FieldValue::U8(1)
    );
}

#[test]
fn parse_stp_bridge_id() {
    let data = build_config_bpdu(
        0x6001, // Priority 0x6000 + Sys ID Ext 1
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        100,
        0x8064, // Priority 0x8000 + Sys ID Ext 100
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        0x8003,
        0x00,
    );
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "root_priority").unwrap().value,
        FieldValue::U16(0x6001)
    );
    assert_eq!(
        buf.field_by_name(layer, "root_mac").unwrap().value,
        FieldValue::MacAddr(MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
    );
    assert_eq!(
        buf.field_by_name(layer, "bridge_priority").unwrap().value,
        FieldValue::U16(0x8064)
    );
    assert_eq!(
        buf.field_by_name(layer, "bridge_mac").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
}

#[test]
fn stp_dissector_metadata() {
    let d = StpDissector;
    assert_eq!(d.name(), "Spanning Tree Protocol");
    assert_eq!(d.short_name(), "STP");
    assert!(!d.field_descriptors().is_empty());
}
