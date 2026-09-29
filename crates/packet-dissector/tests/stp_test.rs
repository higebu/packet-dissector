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
//! | IEEE 802.1Q §14.2.5       | Bridge ID kept as the raw 16-bit value   | parse_stp_bridge_id_split     |
//! | IEEE 802.1Q §14.2.9       | Port Role names (Unknown vs Master)      | parse_port_role_names         |
//! | IEEE 802.1Q §14.4 a)–u)   | MST BPDU without MSTI messages           | parse_mst_bpdu_no_msti        |
//! | IEEE 802.1Q §14.4 j)      | Octets 18–25 = CIST Regional Root in MST | parse_mst_bpdu_no_msti        |
//! | IEEE 802.1Q §14.4.1       | MSTI Configuration Messages              | parse_mst_bpdu_two_mstis      |
//! | IEEE 802.1Q §14.5 d)      | Bad Version 3 Length → RST + unparsed    | parse_mst_bpdu_bad_version3_length |
//! | IEEE 802.1Q §14.5 d) 1)   | Version 3 but < 102 octets → RST         | parse_mst_bpdu_short          |
//! | IEEE 802.1Q §14.4 w)      | SPT BPDU: Version 4 Length + unparsed    | parse_spt_bpdu_version4       |
//! | IEEE 802.1Q §14.4 w)      | SPT data bounded by Version 4 Length     | parse_spt_bpdu_version4       |
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

/// MST BPDU (IEEE 802.1Q Clause 14.4) with `mstis` 16-octet MSTI messages.
fn build_mst_bpdu(mstis: &[[u8; 16]]) -> Vec<u8> {
    let mut pkt = vec![
        0x00, 0x00, 0x03, 0x02, // protocol 0, version 3, type 0x02
        0x7C, // flags: role Designated, learning, forwarding, agreement
        0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // CIST root ID
        0x00, 0x00, 0x00, 0x00, // CIST external root path cost
        0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // CIST regional root ID
        0x80, 0x01, // CIST port ID
        0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0F, 0x00, // timers
        0x00, // Version 1 Length
    ];
    pkt.extend_from_slice(&((64 + 16 * mstis.len()) as u16).to_be_bytes());
    pkt.push(0x00); // format selector
    let mut name = [0u8; 32];
    name[..7].copy_from_slice(b"REGION1");
    pkt.extend_from_slice(&name);
    pkt.extend_from_slice(&[0x00, 0x05]); // revision level
    pkt.extend_from_slice(&[0xAC; 16]); // digest
    pkt.extend_from_slice(&[0x00, 0x00, 0x4E, 0x20]); // CIST internal root path cost 20000
    pkt.extend_from_slice(&[0x80, 0x00, 0x00, 0x66, 0x77, 0x88, 0x99, 0xAA]); // CIST bridge ID
    pkt.push(20); // CIST remaining hops
    for m in mstis {
        pkt.extend_from_slice(m);
    }
    pkt
}

fn msti(id: u16, flags: u8) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = flags;
    m[1..3].copy_from_slice(&(0x8000 | id).to_be_bytes());
    m[3..9].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    m[9..13].copy_from_slice(&2000u32.to_be_bytes());
    m[13] = 0x90; // bridge priority 9 → 36864
    m[14] = 0x80; // port priority 128
    m[15] = 19;
    m
}

fn field<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a FieldValue<'a>> {
    let layer = buf.layer_by_name("STP")?;
    buf.field_by_name(layer, name).map(|f| &f.value)
}

#[test]
fn parse_mst_bpdu_no_msti() {
    let data = build_mst_bpdu(&[]);
    assert_eq!(data.len(), 102);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, 102);
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(layer.range, 0..102);
    assert_eq!(
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("MST")
    );

    // Octets 18-25 are the CIST Regional Root Identifier in an MST BPDU; the
    // bridge_* fields keep reporting them for compatibility.
    assert_eq!(
        field(&buf, "bridge_priority"),
        Some(&FieldValue::U16(0x8000))
    );
    assert_eq!(
        field(&buf, "cist_regional_root_priority"),
        Some(&FieldValue::U16(0x8000))
    );
    assert_eq!(
        field(&buf, "cist_regional_root_mac"),
        Some(&FieldValue::MacAddr(MacAddr([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ])))
    );
    assert_eq!(field(&buf, "version1_length"), Some(&FieldValue::U8(0)));
    assert_eq!(field(&buf, "version3_length"), Some(&FieldValue::U16(64)));
    assert_eq!(
        field(&buf, "mst_config_format_selector"),
        Some(&FieldValue::U8(0))
    );
    assert_eq!(
        field(&buf, "mst_config_name"),
        Some(&FieldValue::Bytes(b"REGION1"))
    );
    assert_eq!(
        field(&buf, "mst_config_revision"),
        Some(&FieldValue::U16(5))
    );
    assert_eq!(
        field(&buf, "mst_config_digest"),
        Some(&FieldValue::Bytes(&[0xAC; 16]))
    );
    assert_eq!(
        field(&buf, "cist_internal_root_path_cost"),
        Some(&FieldValue::U32(20000))
    );
    assert_eq!(
        field(&buf, "cist_bridge_priority"),
        Some(&FieldValue::U16(0x8000))
    );
    assert_eq!(
        field(&buf, "cist_bridge_mac"),
        Some(&FieldValue::MacAddr(MacAddr([
            0x00, 0x66, 0x77, 0x88, 0x99, 0xAA
        ])))
    );
    assert_eq!(
        field(&buf, "cist_remaining_hops"),
        Some(&FieldValue::U8(20))
    );
    assert!(field(&buf, "mstis").is_none());
    assert!(field(&buf, "unparsed").is_none());
    assert_eq!(
        buf.field_by_name(layer, "cist_remaining_hops")
            .unwrap()
            .range,
        101..102
    );
    assert_eq!(
        buf.field_by_name(layer, "mst_config_name").unwrap().range,
        39..71
    );
}

#[test]
fn parse_mst_bpdu_two_mstis() {
    let data = build_mst_bpdu(&[msti(10, 0x7C), msti(20, 0x81)]);
    assert_eq!(data.len(), 134);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, 134);
    assert_eq!(field(&buf, "version3_length"), Some(&FieldValue::U16(96)));
    // MSTI children do not shadow top-level fields.
    assert_eq!(
        field(&buf, "bridge_priority"),
        Some(&FieldValue::U16(0x8000))
    );

    let Some(FieldValue::Array(arr)) = field(&buf, "mstis") else {
        panic!("mstis")
    };
    let objs: Vec<_> = buf
        .nested_fields(arr)
        .iter()
        .filter_map(|f| match &f.value {
            FieldValue::Object(o) => Some((f.range.clone(), buf.nested_fields(o))),
            _ => None,
        })
        .collect();
    assert_eq!(objs.len(), 2);
    assert_eq!(objs[0].0, 102..118);
    assert_eq!(objs[1].0, 118..134);
    fn get<'a>(
        fields: &[packet_dissector::field::Field<'a>],
        name: &str,
    ) -> Option<FieldValue<'a>> {
        fields
            .iter()
            .find(|f| f.name() == name)
            .map(|f| f.value.clone())
    }
    let m0 = objs[0].1;
    assert_eq!(get(m0, "msti_flags"), Some(FieldValue::U8(0x7C)));
    assert_eq!(get(m0, "msti_flags_port_role"), Some(FieldValue::U8(3)));
    assert_eq!(get(m0, "msti_flags_agreement"), Some(FieldValue::U8(1)));
    assert_eq!(get(m0, "msti_flags_master"), Some(FieldValue::U8(0)));
    assert_eq!(
        get(m0, "msti_regional_root_priority"),
        Some(FieldValue::U16(0x8000))
    );
    assert_eq!(get(m0, "msti_id"), Some(FieldValue::U16(10)));
    assert_eq!(
        get(m0, "msti_regional_root_mac"),
        Some(FieldValue::MacAddr(MacAddr([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ])))
    );
    assert_eq!(
        get(m0, "msti_internal_root_path_cost"),
        Some(FieldValue::U32(2000))
    );
    assert_eq!(
        get(m0, "msti_bridge_priority"),
        Some(FieldValue::U16(36864))
    );
    assert_eq!(get(m0, "msti_port_priority"), Some(FieldValue::U8(128)));
    assert_eq!(get(m0, "msti_remaining_hops"), Some(FieldValue::U8(19)));
    let m1 = objs[1].1;
    assert_eq!(get(m1, "msti_id"), Some(FieldValue::U16(20)));
    assert_eq!(get(m1, "msti_flags_tc"), Some(FieldValue::U8(1)));
    assert_eq!(get(m1, "msti_flags_master"), Some(FieldValue::U8(1)));
    assert_eq!(get(m1, "msti_flags_port_role"), Some(FieldValue::U8(0)));
    assert_eq!(
        buf.resolve_nested_display_name(
            match &buf
                .nested_fields(arr)
                .iter()
                .filter(|f| f.value.is_object())
                .nth(1)
                .unwrap()
                .value
            {
                FieldValue::Object(o) => o,
                _ => unreachable!(),
            },
            "msti_flags_port_role_name"
        ),
        Some("Master")
    );
}

#[test]
fn parse_mst_bpdu_bad_version3_length() {
    // Version 3 Length 70 is not 64 + 16n: decoded as an RST BPDU and the
    // remaining octets are reported as unparsed (IEEE 802.1Q §14.5 d) 3)).
    let mut data = build_mst_bpdu(&[msti(10, 0)]);
    data[36..38].copy_from_slice(&70u16.to_be_bytes());
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, data.len());
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("RST")
    );
    assert_eq!(
        field(&buf, "bridge_priority"),
        Some(&FieldValue::U16(0x8000))
    );
    assert!(field(&buf, "mst_config_name").is_none());
    assert_eq!(
        field(&buf, "unparsed"),
        Some(&FieldValue::Bytes(&data[36..]))
    );
    assert_eq!(
        buf.field_by_name(layer, "unparsed").unwrap().range,
        36..data.len()
    );

    // Version 1 Length other than 0 also prevents MST decoding (§14.5 d) 2)).
    let mut data = build_mst_bpdu(&[]);
    data[35] = 1;
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert!(field(&buf, "mst_config_name").is_none());

    // More than 64 MSTI messages.
    let mut data = build_mst_bpdu(&[]);
    data[36..38].copy_from_slice(&(64u16 + 16 * 65).to_be_bytes());
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert!(field(&buf, "mst_config_name").is_none());

    // Version 3 Length claims an MSTI message that was not captured.
    let mut data = build_mst_bpdu(&[]);
    data[36..38].copy_from_slice(&80u16.to_be_bytes());
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert!(field(&buf, "mst_config_name").is_none());
    assert_eq!(
        field(&buf, "unparsed"),
        Some(&FieldValue::Bytes(&data[36..]))
    );
}

#[test]
fn parse_mst_bpdu_short() {
    // Version 3 but fewer than 102 octets: an RST BPDU (§14.5 d) 1)).
    let data = build_mst_bpdu(&[]);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data[..60], &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, 60);
    assert_eq!(
        field(&buf, "unparsed"),
        Some(&FieldValue::Bytes(&data[36..60]))
    );

    // Exactly 36 octets: plain RST BPDU fields, nothing unparsed.
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data[..36], &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, 36);
    assert!(field(&buf, "unparsed").is_none());
}

#[test]
fn parse_spt_bpdu_version4() {
    // SPT BPDU: MST part, Version 4 Length, then SPT data (IEEE 802.1Q §14.4 w)-y)).
    let mut data = build_mst_bpdu(&[]);
    data[2] = 4;
    data.extend_from_slice(&[0x00, 0x04, 0x05, 0x00, 0xDE, 0xAD]);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, data.len());
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("SPT")
    );
    assert_eq!(
        field(&buf, "cist_remaining_hops"),
        Some(&FieldValue::U8(20))
    );
    assert_eq!(field(&buf, "version4_length"), Some(&FieldValue::U16(4)));
    assert_eq!(
        field(&buf, "unparsed"),
        Some(&FieldValue::Bytes(&[0x05, 0x00, 0xDE, 0xAD]))
    );

    // Octets after those covered by the Version 4 Length are not part of it.
    data.extend_from_slice(&[0xEE, 0xEE]);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, data.len() - 2);
    assert_eq!(
        field(&buf, "unparsed"),
        Some(&FieldValue::Bytes(&[0x05, 0x00, 0xDE, 0xAD]))
    );

    // Version 4 with nothing after the MST part is an MST BPDU.
    let mut data = build_mst_bpdu(&[]);
    data[2] = 4;
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "bpdu_type_name"),
        Some("MST")
    );

    // Version 3 MST BPDU followed by extra octets: they are not part of it.
    let mut data = build_mst_bpdu(&[]);
    data.extend_from_slice(&[0xFF, 0xFF]);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, 102);
    assert!(field(&buf, "version4_length").is_none());

    // Version 4 with a single trailing octet: no room for Version 4 Length.
    let mut data = build_mst_bpdu(&[]);
    data[2] = 4;
    data.push(0x00);
    let mut buf = DissectBuffer::new();
    let r = StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, 103);
    assert!(field(&buf, "version4_length").is_none());
    assert_eq!(field(&buf, "unparsed"), Some(&FieldValue::Bytes(&[0x00])));
}

#[test]
fn parse_stp_bridge_id_split() {
    // Priority 32768 + VLAN 100 (PVST+ / MSTP system ID extension): the
    // 16-bit priority part is reported as-is; no split fields are emitted.
    let data = build_config_bpdu(
        0x8064,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        0,
        0x7065,
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        0x8001,
        0x00,
    );
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(field(&buf, "root_priority"), Some(&FieldValue::U16(0x8064)));
    assert_eq!(
        field(&buf, "bridge_priority"),
        Some(&FieldValue::U16(0x7065))
    );
    assert_eq!(field(&buf, "port_id"), Some(&FieldValue::U16(0x8001)));
    assert!(field(&buf, "root_system_id_extension").is_none());
    assert!(field(&buf, "port_number").is_none());
}

#[test]
fn parse_port_role_names() {
    let mut rst = vec![0u8; 36];
    rst[2] = 2;
    rst[3] = 2;
    for (flags, name) in [
        (0x00, "Unknown"),
        (0x04, "Alternate/Backup"),
        (0x08, "Root"),
        (0x0C, "Designated"),
    ] {
        rst[4] = flags;
        let mut buf = DissectBuffer::new();
        StpDissector.dissect(&rst, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("STP").unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "flags_port_role_name"),
            Some(name)
        );
    }
    // In an MST BPDU role 0 is Master (IEEE 802.1Q §14.2.9 a)).
    let mut mst = build_mst_bpdu(&[]);
    mst[4] = 0x00;
    let mut buf = DissectBuffer::new();
    StpDissector.dissect(&mst, &mut buf, 0).unwrap();
    let layer = buf.layer_by_name("STP").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "flags_port_role_name"),
        Some("Master")
    );
}
