//! # IEEE 802.3 / 802.1Q / 802.1ad / 802.2 (Ethernet) Coverage
//!
//! | Spec                  | Description                          | Test                                    |
//! |-----------------------|--------------------------------------|-----------------------------------------|
//! | IEEE 802.3 cl.3.2.3   | Basic frame (dst, src, type)         | parse_ethernet_ii_frame                 |
//! | IEEE 802.3 cl.3.2.6   | EtherType dispatch (IPv4)            | parse_ethernet_ii_frame                 |
//! | IEEE 802.3 cl.3.2.6   | EtherType dispatch (IPv6)            | parse_ethernet_ipv6_ethertype           |
//! | IEEE 802.3 cl.3.2.6   | EtherType dispatch (ARP)             | parse_ethernet_arp_ethertype            |
//! | IEEE 802.3 cl.3.2.6   | Length field → LLC dispatch          | parse_ethernet_llc_frame                |
//! | IEEE 802.3 cl.3.2.6   | Reserved type (1501–1535) rejected   | parse_ethernet_reserved_type_rejected   |
//! | IEEE 802.3 cl.3.2.3   | Truncated frame                      | parse_ethernet_truncated                |
//! | IEEE 802.3 cl.3.2.3   | Offset handling                      | parse_ethernet_with_offset              |
//! | IEEE 802.1Q cl.9.6    | VLAN tag (TPID, PCP, DEI, VID)       | parse_ethernet_with_8021q_vlan_tag      |
//! | IEEE 802.1Q cl.9.6    | Truncated VLAN tag                   | parse_ethernet_vlan_truncated           |
//! | IEEE 802.1Q cl.9.6    | VLAN TPID field value                | parse_ethernet_vlan_tpid_field          |
//! | IEEE 802.1ad cl.9.6   | S-VLAN tag (TPID=0x88A8)             | parse_ethernet_with_8021ad_vlan_tag     |
//! | IEEE 802.1ad cl.9.6   | QinQ double-tagged frame             | parse_ethernet_qinq_double_tag          |
//! | IEEE 802.1ad cl.9.6   | Truncated inner QinQ tag rejected    | parse_ethernet_qinq_truncated_inner_tag |
//! | IEEE 802.1Q cl.9.6    | Triple stacked VLAN tags             | parse_ethernet_triple_vlan_tag          |
//! | IEEE 802.2 §3         | LLC frame parsing (DSAP, SSAP, Ctrl) | parse_ethernet_llc_frame                |
//! | IEEE 802.2 §3         | LLC frame truncated                  | parse_ethernet_llc_frame_truncated      |
//! | IEEE 802.2 §3         | LLC SAP dispatch                     | parse_ethernet_llc_dispatch             |
//! | —                     | Dissector metadata                   | ethernet_dissector_metadata             |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::{FieldValue, MacAddr};
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::ethernet::EthernetDissector;

#[test]
fn parse_ethernet_ii_frame() {
    // dst: 00:11:22:33:44:55, src: 66:77:88:99:aa:bb, ethertype: 0x0800 (IPv4)
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x08, 0x00, // EtherType: IPv4
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 14);
    assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.name, "Ethernet");
    assert_eq!(layer.range, 0..14);

    assert_eq!(
        buf.field_by_name(layer, "dst").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
    assert_eq!(
        buf.field_by_name(layer, "src").unwrap().value,
        FieldValue::MacAddr(MacAddr([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]))
    );
    assert_eq!(
        buf.field_by_name(layer, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );
}

#[test]
fn parse_ethernet_ipv6_ethertype() {
    let mut data = [0u8; 16];
    data[12] = 0x86;
    data[13] = 0xDD; // EtherType: IPv6
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.next, DispatchHint::ByEtherType(0x86DD));
}

#[test]
fn parse_ethernet_arp_ethertype() {
    let mut data = [0u8; 16];
    data[12] = 0x08;
    data[13] = 0x06; // EtherType: ARP
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.next, DispatchHint::ByEtherType(0x0806));
}

#[test]
fn parse_ethernet_with_8021q_vlan_tag() {
    // dst + src + 802.1Q tag (TPID=0x8100, TCI=0x0064 -> VID=100) + inner ethertype 0x0800
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x81, 0x00, // TPID: 802.1Q
        0x00, 0x64, // TCI: PCP=0, DEI=0, VID=100
        0x08, 0x00, // Inner EtherType: IPv4
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    // 802.1Q tagged frame: 14 + 4 = 18 bytes header
    assert_eq!(result.bytes_consumed, 18);
    assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.range, 0..18);

    assert_eq!(
        buf.field_by_name(layer, "vlan_id").unwrap().value,
        FieldValue::U16(100)
    );
    assert_eq!(
        buf.field_by_name(layer, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );
}

#[test]
fn parse_ethernet_truncated() {
    let data = [0u8; 10]; // too short for Ethernet header (14 bytes)
    let mut buf = DissectBuffer::new();
    let err = EthernetDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 14,
            actual: 10
        }
    ));
}

#[test]
fn parse_ethernet_vlan_truncated() {
    // Has 802.1Q TPID but not enough bytes for full VLAN tag
    let mut data = [0u8; 15]; // 14 bytes header + 1 byte (need 4 more for VLAN)
    data[12] = 0x81;
    data[13] = 0x00;
    let mut buf = DissectBuffer::new();
    let err = EthernetDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 18,
            actual: 15
        }
    ));
}

#[test]
fn parse_ethernet_with_offset() {
    let mut data = [0u8; 16];
    data[12] = 0x08;
    data[13] = 0x00;
    let mut buf = DissectBuffer::new();
    EthernetDissector.dissect(&data, &mut buf, 10).unwrap();

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.range, 10..24);
    assert_eq!(buf.field_by_name(layer, "dst").unwrap().range, 10..16);
    assert_eq!(buf.field_by_name(layer, "src").unwrap().range, 16..22);
    assert_eq!(buf.field_by_name(layer, "ethertype").unwrap().range, 22..24);
}

#[test]
fn ethernet_dissector_metadata() {
    let d = EthernetDissector;
    assert_eq!(d.name(), "Ethernet II");
    assert_eq!(d.short_name(), "Ethernet");
}

// IEEE 802.3 clause 3.2.6: values ≤ 1500 indicate a length field (IEEE 802.3 LLC frame).
// The Ethernet dissector parses the LLC header inline and dispatches by DSAP.
#[test]
fn parse_ethernet_llc_frame() {
    // dst (6) + src (6) + length (2) + LLC (DSAP=0x42, SSAP=0x42, Control=0x03) + payload
    let data = [
        0x01, 0x80, 0xC2, 0x00, 0x00, 0x00, // dst: STP multicast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        0x00, 0x26, // Length: 38
        0x42, 0x42, 0x03, // LLC: DSAP=0x42, SSAP=0x42, Control=0x03
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    // Ethernet (14) + LLC (3) = 17 bytes consumed
    assert_eq!(result.bytes_consumed, 17);
    assert_eq!(result.next, DispatchHint::ByLlcSap(0x42));

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.range, 0..17);

    // Length field (not EtherType)
    assert_eq!(
        buf.field_by_name(layer, "length").unwrap().value,
        FieldValue::U16(0x0026)
    );
    // LLC fields
    assert_eq!(
        buf.field_by_name(layer, "llc_dsap").unwrap().value,
        FieldValue::U8(0x42)
    );
    assert_eq!(
        buf.field_by_name(layer, "llc_ssap").unwrap().value,
        FieldValue::U8(0x42)
    );
    assert_eq!(
        buf.field_by_name(layer, "llc_control").unwrap().value,
        FieldValue::U8(0x03)
    );
    // No ethertype field in LLC frames
    assert!(buf.field_by_name(layer, "ethertype").is_none());
}

// LLC frame with truncated LLC header (14-byte Ethernet + not enough for 3-byte LLC).
#[test]
fn parse_ethernet_llc_frame_truncated() {
    let mut data = [0u8; 16]; // 14 + 2 bytes — need 3 more for LLC
    data[12] = 0x00;
    data[13] = 0x26; // Length field (38)
    let mut buf = DissectBuffer::new();
    let err = EthernetDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 17,
            actual: 16
        }
    ));
}

// Verify that LLC DSAP is used for dispatch hint.
#[test]
fn parse_ethernet_llc_dispatch() {
    // Use a different DSAP value (0xAA for SNAP) to confirm dispatch uses DSAP.
    let mut data = [0u8; 17]; // Ethernet (14) + LLC (3)
    data[12] = 0x00;
    data[13] = 0x03; // Length: 3
    data[14] = 0xAA; // DSAP: SNAP
    data[15] = 0xAA; // SSAP: SNAP
    data[16] = 0x03; // Control: UI
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.next, DispatchHint::ByLlcSap(0xAA));
}

// IEEE 802.3 clause 3.2.6: values 1501–1535 (0x05DD–0x05FF) are undefined/reserved.
// The Ethernet II dissector must reject such frames.
#[test]
fn parse_ethernet_reserved_type_rejected() {
    let mut data = [0u8; 16];
    data[12] = 0x05;
    data[13] = 0xDD; // 1501 decimal — in the reserved range
    let mut buf = DissectBuffer::new();
    let err = EthernetDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { .. }
    ));
}

// IEEE 802.1Q clause 9.3: verify that the vlan_tpid field reflects the actual TPID value parsed.
#[test]
fn parse_ethernet_vlan_tpid_field() {
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x81, 0x00, // TPID: 802.1Q
        0x00, 0x64, // TCI: PCP=0, DEI=0, VID=100
        0x08, 0x00, // Inner EtherType: IPv4
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "vlan_tpid").unwrap().value,
        FieldValue::U16(0x8100)
    );
}

// IEEE 802.1ad clause 9.6 (S-VLAN tag): TPID 0x88A8 identifies a Service VLAN tag (QinQ outer tag).
// The dissector must recognise it the same way as 0x8100 and extract PCP, DEI, VID correctly.
#[test]
fn parse_ethernet_with_8021ad_vlan_tag() {
    // dst + src + 802.1ad S-VLAN tag (TPID=0x88A8, TCI=0xA064 -> PCP=5, DEI=0, VID=100)
    // + inner EtherType 0x0800 (IPv4)
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x88, 0xA8, // TPID: 802.1ad S-VLAN
        0xA0, 0x64, // TCI: PCP=5, DEI=0, VID=100  (0xA064 = 1010_0000_0110_0100)
        0x08, 0x00, // Inner EtherType: IPv4
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    // S-VLAN tagged frame: 14 + 4 = 18 bytes header
    assert_eq!(result.bytes_consumed, 18);
    assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.range, 0..18);

    assert_eq!(
        buf.field_by_name(layer, "vlan_tpid").unwrap().value,
        FieldValue::U16(0x88A8)
    );
    assert_eq!(
        buf.field_by_name(layer, "vlan_pcp").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "vlan_dei").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "vlan_id").unwrap().value,
        FieldValue::U16(100)
    );
    assert_eq!(
        buf.field_by_name(layer, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );
}

// IEEE 802.1ad clause 9.6 (QinQ): outer S-Tag (0x88A8) followed by inner C-Tag (0x8100)
// then the final EtherType. Both tags must be parsed and the dispatch hint uses the
// final EtherType.
#[test]
fn parse_ethernet_qinq_double_tag() {
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x88, 0xA8, // outer TPID: 802.1ad S-VLAN
        0x00, 0x64, // outer TCI: PCP=0, DEI=0, VID=100
        0x81, 0x00, // inner TPID: 802.1Q C-VLAN
        0x00, 0xC8, // inner TCI: PCP=0, DEI=0, VID=200
        0x08, 0x00, // final EtherType: IPv4
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    // Ethernet (14) + S-Tag (4) + C-Tag (4) = 22 bytes consumed
    assert_eq!(result.bytes_consumed, 22);
    assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.range, 0..22);

    // Both vlan_id fields are present; field_by_name returns the first match.
    // Iterate over the layer fields to verify both tags were pushed.
    let fields = buf.layer_fields(layer);
    let vlan_ids: Vec<u16> = fields
        .iter()
        .filter(|f| f.descriptor.name == "vlan_id")
        .filter_map(|f| match f.value {
            FieldValue::U16(v) => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(vlan_ids, vec![100, 200]);

    let tpids: Vec<u16> = fields
        .iter()
        .filter(|f| f.descriptor.name == "vlan_tpid")
        .filter_map(|f| match f.value {
            FieldValue::U16(v) => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(tpids, vec![0x88A8, 0x8100]);

    assert_eq!(
        buf.field_by_name(layer, "ethertype").unwrap().value,
        FieldValue::U16(0x0800)
    );
}

// IEEE 802.1ad clause 9.6 (QinQ): after an outer S-Tag, if the inner TPID indicates
// another VLAN tag but the frame is truncated before the inner TCI / EtherType,
// the dissector must reject the frame as Truncated rather than silently treating
// the inner TPID as a final EtherType.
#[test]
fn parse_ethernet_qinq_truncated_inner_tag() {
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x88, 0xA8, // outer TPID: 802.1ad S-VLAN
        0x00, 0x64, // outer TCI: VID=100
        0x81, 0x00, // inner TPID: 802.1Q C-VLAN
        0x00, // <-- only 1 byte of the inner TCI; inner tag truncated
    ];
    let mut buf = DissectBuffer::new();
    let err = EthernetDissector.dissect(&data, &mut buf, 0).unwrap_err();

    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 22,
            actual: 19
        }
    ));
}

// IEEE 802.1Q clause 9.6: triple-stacked VLAN tags (e.g. S-Tag + S-Tag + C-Tag) are
// valid constructs in provider networks. The dissector must parse all stacked tags
// and use the final EtherType as dispatch hint.
#[test]
fn parse_ethernet_triple_vlan_tag() {
    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src MAC
        0x88, 0xA8, // outer TPID: S-VLAN
        0x00, 0x0A, // outer TCI: VID=10
        0x88, 0xA8, // middle TPID: S-VLAN
        0x00, 0x14, // middle TCI: VID=20
        0x81, 0x00, // inner TPID: C-VLAN
        0x00, 0x1E, // inner TCI: VID=30
        0x08, 0x00, // final EtherType: IPv4
        0xDE, 0xAD, // payload
    ];
    let mut buf = DissectBuffer::new();
    let result = EthernetDissector.dissect(&data, &mut buf, 0).unwrap();

    // Ethernet (14) + 3 tags (12) = 26 bytes consumed
    assert_eq!(result.bytes_consumed, 26);
    assert_eq!(result.next, DispatchHint::ByEtherType(0x0800));

    let layer = buf.layer_by_name("Ethernet").unwrap();
    assert_eq!(layer.range, 0..26);

    let fields = buf.layer_fields(layer);
    let vlan_ids: Vec<u16> = fields
        .iter()
        .filter(|f| f.descriptor.name == "vlan_id")
        .filter_map(|f| match f.value {
            FieldValue::U16(v) => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(vlan_ids, vec![10, 20, 30]);
}
