//! # RFC 8200 (IPv6) Coverage
//!
//! | RFC Section | Description                    | Test                                    |
//! |-------------|--------------------------------|-----------------------------------------|
//! | 3           | Version                        | parse_ipv6_basic                        |
//! | 3           | Version validation (must be 6) | parse_ipv6_invalid_version              |
//! | 3           | Traffic Class                  | parse_ipv6_traffic_class_and_flow_label |
//! | 3           | Flow Label                     | parse_ipv6_traffic_class_and_flow_label |
//! | 3           | Payload Length                  | parse_ipv6_basic                        |
//! | 3           | Next Header (TCP=6)            | parse_ipv6_basic                        |
//! | 3           | Next Header (UDP=17)           | parse_ipv6_udp                          |
//! | 3           | Hop Limit                      | parse_ipv6_basic                        |
//! | 3           | Source / Destination Address    | parse_ipv6_basic                        |
//! | 4.3         | Hop-by-Hop Options Header      | parse_ipv6_hop_by_hop                   |
//! | 4.3         | Hop-by-Hop truncated           | parse_ipv6_hop_by_hop_truncated         |
//! | 4.4         | Routing dispatcher             | routing_dispatcher_returns_by_ipv6_routing_type |
//! | 4.4         | Routing dispatcher truncated   | routing_dispatcher_truncated            |
//! | 4.4         | Routing Header (generic)       | parse_ipv6_routing                      |
//! | 4.4         | Routing truncated (generic)    | parse_ipv6_routing_truncated            |
//! | 4.5         | Fragment Header                | parse_ipv6_fragment                     |
//! | 4.5         | Fragment reserved / res fields  | parse_ipv6_fragment                     |
//! | 4.5         | Fragment truncated             | parse_ipv6_fragment_truncated           |
//! | 4.6         | Destination Options Header     | parse_ipv6_destination_options          |
//! | 4.6         | Destination Options truncated  | parse_ipv6_destination_options_truncated|
//! | 4.3+4.5     | Chained ext headers            | parse_ipv6_chained_extension_headers    |
//! | 4.2         | Pad1 / PadN options            | parse_ipv6_option_pad1_padn             |
//! | 4.2         | Action and change bits         | parse_ipv6_option_action_change_bits    |
//! | 4.2         | Unknown option keeps raw value | parse_ipv6_option_unknown               |
//! | 4.2         | Option length past header      | parse_ipv6_option_length_past_end       |
//! | 4.2         | Length octet missing           | parse_ipv6_option_missing_length        |
//! | 4.2         | Fixed-length option wrong size | parse_ipv6_option_router_alert_bad_length |
//! | 4.6         | Destination Options walked     | parse_ipv6_option_home_address          |
//! | 4.4 / 5095  | Type 0 Routing Header          | parse_ipv6_routing_type0                |
//!
//! # IPv6 Options Coverage
//!
//! | Spec        | Description                    | Test                                    |
//! |-------------|--------------------------------|-----------------------------------------|
//! | 2711 §2.1   | Router Alert                   | parse_ipv6_option_router_alert          |
//! | 2675 §2     | Jumbo Payload                  | parse_ipv6_option_jumbo_payload         |
//! | 2675 §2     | Jumbo only bounds Hop-by-Hop   | parse_ipv6_option_jumbo_in_destination_options |
//! | 2675 §3     | Jumbogram through the registry | parse_ipv6_jumbogram_payload_bounded    |
//! | 2675 §2     | Jumbo length <= 65535 ignored  | parse_ipv6_option_jumbo_invalid_length_ignored |
//! | 2473 §5.1   | Tunnel Encapsulation Limit     | parse_ipv6_option_tunnel_encap_limit    |
//! | 6275 §6.3   | Home Address                   | parse_ipv6_option_home_address          |
//! | 5570 §5.1   | CALIPSO                        | parse_ipv6_option_calipso               |
//! | 6553 §3     | RPL Option (0x63)              | parse_ipv6_option_rpl                   |
//! | 9008 §11.1  | RPL Option (0x23)              | parse_ipv6_option_rpl                   |
//! | 7731 §6.1   | MPL Option                     | parse_ipv6_option_mpl                   |
//! | 7731 §6.1   | MPL seed-id sizes (S=0,2,3)    | parse_ipv6_option_mpl_seed_id_sizes     |
//! | IANA        | Option names                   | parse_ipv6_option_names                 |
//! | 9486 §3     | IOAM                           | parse_ipv6_option_ioam                  |
//! | 8250 §3.2.1 | PDM                            | parse_ipv6_option_pdm                   |
//! | 4782 §3.2   | Quick-Start                    | parse_ipv6_option_quick_start           |
//!
//! # IPv6 Routing Header Types Coverage
//!
//! | Spec        | Description                    | Test                                    |
//! |-------------|--------------------------------|-----------------------------------------|
//! | 6275 §6.4   | Type 2 Routing Header          | parse_ipv6_routing_type2                |
//! | 6275 §6.4   | Type 2 with bad length is raw  | parse_ipv6_routing                      |
//! | 6554 §3     | Type 3 RPL Source Route        | parse_ipv6_routing_type3                |
//! | 6554 §3     | Type 3 inconsistent sizes raw  | parse_ipv6_routing_type3_inconsistent   |
//! | IANA        | Routing Type names             | parse_ipv6_routing_type_names           |
//! | —           | Truncated header               | parse_ipv6_truncated                    |
//! | —           | Offset handling                | parse_ipv6_with_offset                  |
//! | —           | Dissector metadata             | ipv6_dissector_metadata                 |
//!
//! # RFC 4302 (AH) Coverage
//!
//! | RFC Section | Description                    | Test                                    |
//! |-------------|--------------------------------|-----------------------------------------|
//! | 2.2         | AH Header Format               | parse_ipv6_ah_basic                     |
//! | 2.2         | AH with ICV                    | parse_ipv6_ah_with_icv                  |
//! | 2.2         | AH truncated (fixed)           | parse_ipv6_ah_truncated                 |
//! | 2.2         | AH truncated (payload)         | parse_ipv6_ah_truncated_payload         |
//! | 2.2         | AH invalid Payload Len (= 0)   | parse_ipv6_ah_invalid_payload_len       |
//! | —           | AH dissector metadata          | ah_dissector_metadata                   |
//!
//! # RFC 4303 (ESP) Coverage
//!
//! | RFC Section | Description                    | Test                                    |
//! |-------------|--------------------------------|-----------------------------------------|
//! | 2.1         | ESP Header Format              | parse_ipv6_esp_basic                    |
//! | 2.1         | ESP truncated                  | parse_ipv6_esp_truncated                |
//! | —           | ESP dissector metadata         | esp_dissector_metadata                  |
//!
//! # RFC 6275 (Mobility Header) Coverage
//!
//! | RFC Section | Description                    | Test                                    |
//! |-------------|--------------------------------|-----------------------------------------|
//! | 6.1         | MH Header Format               | parse_ipv6_mobility_basic               |
//! | 6.1         | MH with message data           | parse_ipv6_mobility_with_data           |
//! | 6.1         | MH reserved byte               | parse_ipv6_mobility_basic               |
//! | 6.1         | MH truncated (fixed)           | parse_ipv6_mobility_truncated           |
//! | 6.1         | MH truncated (payload)         | parse_ipv6_mobility_truncated_payload   |
//! | 6.1.1       | MH Type name                   | parse_ipv6_mobility_binding_update      |
//! | 6.1.2       | Binding Refresh Request        | parse_ipv6_mobility_brr                 |
//! | 6.1.3/6.1.4 | HoTI / CoTI                    | parse_ipv6_mobility_hoti_coti           |
//! | 6.1.5/6.1.6 | HoT / CoT                      | parse_ipv6_mobility_hot_cot             |
//! | 6.1.7       | Binding Update                 | parse_ipv6_mobility_binding_update      |
//! | 6.1.8       | Binding Acknowledgement        | parse_ipv6_mobility_binding_ack         |
//! | 6.1.9       | Binding Error                  | parse_ipv6_mobility_binding_error       |
//! | 6.1.x       | Body shorter than defined      | parse_ipv6_mobility_short_body          |
//! | 6.2.2/6.2.3 | Pad1 / PadN                    | parse_ipv6_mobility_pad1_padn           |
//! | 6.2.4       | Binding Refresh Advice         | parse_ipv6_mobility_binding_ack         |
//! | 6.2.5       | Alternate Care-of Address      | parse_ipv6_mobility_options             |
//! | 6.2.6       | Nonce Indices                  | parse_ipv6_mobility_options             |
//! | 6.2.7       | Binding Authorization Data     | parse_ipv6_mobility_options             |
//! | 6.2.1       | Unknown / malformed option     | parse_ipv6_mobility_options_malformed   |
//! | 6.2.1       | Option without Length octet    | parse_ipv6_mobility_option_missing_length |
//! | 6.1.2-6.1.9 | MH Type and option names       | parse_ipv6_mobility_names               |
//! | —           | MH dissector metadata          | mobility_dissector_metadata             |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::dissectors::ah::AhDissector;
use packet_dissector::dissectors::esp::EspDissector;
use packet_dissector::dissectors::ipv6::{
    DestinationOptionsDissector, FragmentDissector, GenericRoutingDissector, HopByHopDissector,
    Ipv6Dissector, MobilityDissector, RoutingDissector,
};
use packet_dissector::field::{Field, FieldValue};
use packet_dissector::packet::DissectBuffer;

/// Build a minimal IPv6 header (40 bytes, no extension headers).
fn build_ipv6_packet(
    next_header: u8,
    src: [u8; 16],
    dst: [u8; 16],
    payload_length: u16,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    // RFC 8200, Section 3 — IPv6 Header Format
    pkt[0] = 0x60; // Version=6, Traffic Class (high 4 bits)=0
    pkt[1] = 0x00; // Traffic Class (low 4 bits)=0, Flow Label (high 4 bits)=0
    pkt[2] = 0x00; // Flow Label
    pkt[3] = 0x00; // Flow Label
    pkt[4..6].copy_from_slice(&payload_length.to_be_bytes());
    pkt[6] = next_header;
    pkt[7] = 64; // Hop Limit
    pkt[8..24].copy_from_slice(&src);
    pkt[24..40].copy_from_slice(&dst);
    pkt
}

#[test]
fn parse_ipv6_basic() {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let data = build_ipv6_packet(6, src, dst, 20); // TCP

    let mut buf = DissectBuffer::new();
    let result = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 40);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

    let layer = buf.layer_by_name("IPv6").unwrap();
    assert_eq!(layer.name, "IPv6");
    assert_eq!(layer.range, 0..40);

    assert_eq!(
        buf.field_by_name(layer, "version").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "traffic_class").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "flow_label").unwrap().value,
        FieldValue::U32(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "payload_length").unwrap().value,
        FieldValue::U16(20)
    );
    assert_eq!(
        buf.field_by_name(layer, "next_header").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "hop_limit").unwrap().value,
        FieldValue::U8(64)
    );
    assert_eq!(
        buf.field_by_name(layer, "src").unwrap().value,
        FieldValue::Ipv6Addr(src)
    );
    assert_eq!(
        buf.field_by_name(layer, "dst").unwrap().value,
        FieldValue::Ipv6Addr(dst)
    );
}

#[test]
fn parse_ipv6_udp() {
    let data = build_ipv6_packet(17, [0; 16], [0; 16], 8);
    let mut buf = DissectBuffer::new();
    let result = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.next, DispatchHint::ByIpProtocol(17));
}

#[test]
fn parse_ipv6_traffic_class_and_flow_label() {
    let mut data = build_ipv6_packet(6, [0; 16], [0; 16], 0);
    // Version=6, Traffic Class=0xAB, Flow Label=0xCDEF0
    // Byte 0: 0110 1010  (version=6, TC high 4 bits=0xA)
    // Byte 1: 1011 1100  (TC low 4 bits=0xB, FL high 4 bits=0xC)
    // Byte 2: 0xDE
    // Byte 3: 0xF0
    data[0] = 0x6A; // 0110 1010
    data[1] = 0xBC; // 1011 1100
    data[2] = 0xDE;
    data[3] = 0xF0;

    let mut buf = DissectBuffer::new();
    Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("IPv6").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "traffic_class").unwrap().value,
        FieldValue::U8(0xAB)
    );
    assert_eq!(
        buf.field_by_name(layer, "flow_label").unwrap().value,
        FieldValue::U32(0xCDEF0)
    );
}

#[test]
fn parse_ipv6_invalid_version() {
    // RFC 8200, Section 3 — Version must be 6
    let mut data = build_ipv6_packet(6, [0; 16], [0; 16], 0);
    data[0] = 0x40; // Version=4 (IPv4), not 6
    let mut buf = DissectBuffer::new();
    let err = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue {
            field: "version",
            ..
        }
    ));
}

#[test]
fn parse_ipv6_truncated() {
    let data = [0x60, 0x00]; // Only 2 bytes
    let mut buf = DissectBuffer::new();
    let err = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 40,
            actual: 2
        }
    ));
}

#[test]
fn parse_ipv6_with_offset() {
    let data = build_ipv6_packet(6, [0; 16], [0; 16], 0);
    let mut buf = DissectBuffer::new();
    Ipv6Dissector.dissect(&data, &mut buf, 14).unwrap();

    let layer = buf.layer_by_name("IPv6").unwrap();
    assert_eq!(layer.range, 14..54);
    assert_eq!(buf.field_by_name(layer, "src").unwrap().range, 22..38);
    assert_eq!(buf.field_by_name(layer, "dst").unwrap().range, 38..54);
}

#[test]
fn ipv6_dissector_metadata() {
    let d = Ipv6Dissector;
    assert_eq!(d.name(), "Internet Protocol version 6");
    assert_eq!(d.short_name(), "IPv6");
}

// --- Extension Header tests (RFC 8200, Section 4) ---

#[test]
fn parse_ipv6_hop_by_hop() {
    // RFC 8200, Section 4.3 — Hop-by-Hop Options Header
    // Next Header=6 (TCP), Hdr Ext Len=0 (8 bytes total), 6 bytes padding (PadN)
    let ext_header: [u8; 8] = [
        6, // Next Header: TCP
        0, // Hdr Ext Len: 0 (= 8 bytes total)
        1, // PadN option type
        4, // PadN length: 4 bytes of padding
        0, 0, 0, 0, // padding
    ];

    let mut buf = DissectBuffer::new();
    let result = HopByHopDissector
        .dissect(&ext_header, &mut buf, 40)
        .unwrap();

    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

    let layer = buf.layer_by_name("IPv6 Hop-by-Hop").unwrap();
    assert_eq!(layer.name, "IPv6 Hop-by-Hop");
    assert_eq!(layer.range, 40..48);
    assert_eq!(
        buf.field_by_name(layer, "next_header").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "hdr_ext_len").unwrap().value,
        FieldValue::U8(0)
    );
}

#[test]
fn parse_ipv6_hop_by_hop_truncated() {
    let data = [0u8; 1]; // Too short
    let mut buf = DissectBuffer::new();
    let err = HopByHopDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 2,
            actual: 1
        }
    ));
}

#[test]
fn routing_dispatcher_returns_by_ipv6_routing_type() {
    // RoutingDissector is now a thin dispatcher: peeks at routing_type, consumes 0 bytes
    let ext_header: [u8; 8] = [
        6, // Next Header: TCP
        0, // Hdr Ext Len: 0 (= 8 bytes total)
        2, // Routing Type
        1, // Segments Left
        0, 0, 0, 0, // type-specific data
    ];

    let mut buf = DissectBuffer::new();
    let result = RoutingDissector.dissect(&ext_header, &mut buf, 40).unwrap();

    assert_eq!(result.bytes_consumed, 0);
    assert_eq!(result.next, DispatchHint::ByIpv6RoutingType(2));
    // Dispatcher does not add a layer
    assert_eq!(buf.layers().len(), 0);
}

#[test]
fn routing_dispatcher_truncated() {
    let data = [6, 0]; // 2 bytes, need at least 3 to peek at routing_type
    let mut buf = DissectBuffer::new();
    let err = RoutingDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 3,
            actual: 2
        }
    ));
}

#[test]
fn parse_ipv6_routing() {
    // RFC 8200, Section 4.4 — Routing Header via GenericRoutingDissector (fallback)
    // 8 bytes: Next Header=6, Hdr Ext Len=0, Routing Type=2, Segments Left=1, 4 bytes data
    let ext_header: [u8; 8] = [
        6, // Next Header: TCP
        0, // Hdr Ext Len: 0 (= 8 bytes total)
        2, // Routing Type
        1, // Segments Left
        0, 0, 0, 0, // type-specific data
    ];

    let mut buf = DissectBuffer::new();
    let result = GenericRoutingDissector
        .dissect(&ext_header, &mut buf, 40)
        .unwrap();

    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

    let layer = buf.layer_by_name("IPv6 Routing").unwrap();
    assert_eq!(layer.name, "IPv6 Routing");
    assert_eq!(
        buf.field_by_name(layer, "routing_type").unwrap().value,
        FieldValue::U8(2)
    );
    assert_eq!(
        buf.field_by_name(layer, "segments_left").unwrap().value,
        FieldValue::U8(1)
    );
}

#[test]
fn parse_ipv6_routing_truncated() {
    let data = [6, 0, 2]; // 3 bytes, need at least 4 for fixed fields
    let mut buf = DissectBuffer::new();
    let err = GenericRoutingDissector
        .dissect(&data, &mut buf, 0)
        .unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated { expected: 4, .. }
    ));
}

#[test]
fn parse_ipv6_fragment() {
    // RFC 8200, Section 4.5 — Fragment Header (always 8 bytes)
    let ext_header: [u8; 8] = [
        6, // Next Header: TCP
        0, // Reserved
        0x00, 0x39, // Fragment Offset=7, Res=0, M=1
        0xDE, 0xAD, 0xBE, 0xEF, // Identification
    ];

    let mut buf = DissectBuffer::new();
    let result = FragmentDissector
        .dissect(&ext_header, &mut buf, 40)
        .unwrap();

    assert_eq!(result.bytes_consumed, 8);
    // Fragment Offset 7: the data starts mid-packet, so nothing is dispatched.
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("IPv6 Fragment").unwrap();
    assert_eq!(layer.name, "IPv6 Fragment");
    assert_eq!(
        buf.field_by_name(layer, "next_header").unwrap().value,
        FieldValue::U8(6)
    );
    // RFC 8200, Section 4.5 — Reserved byte (data[1]).
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "fragment_offset").unwrap().value,
        FieldValue::U16(7)
    );
    // RFC 8200, Section 4.5 — Res (2-bit reserved within bytes 2-3).
    assert_eq!(
        buf.field_by_name(layer, "res").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "m_flag").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "identification").unwrap().value,
        FieldValue::U32(0xDEADBEEF)
    );
}

#[test]
fn parse_ipv6_fragment_truncated() {
    let data = [6, 0, 0, 0]; // 4 bytes, need 8
    let mut buf = DissectBuffer::new();
    let err = FragmentDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 8,
            actual: 4
        }
    ));
}

#[test]
fn parse_ipv6_destination_options() {
    // RFC 8200, Section 4.6 — Destination Options Header
    // Same format as Hop-by-Hop
    let ext_header: [u8; 8] = [
        6, // Next Header: TCP
        0, // Hdr Ext Len: 0 (= 8 bytes total)
        1, // PadN option type
        4, // PadN length
        0, 0, 0, 0,
    ];

    let mut buf = DissectBuffer::new();
    let result = DestinationOptionsDissector
        .dissect(&ext_header, &mut buf, 40)
        .unwrap();

    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

    let layer = buf.layer_by_name("IPv6 Destination Options").unwrap();
    assert_eq!(layer.name, "IPv6 Destination Options");
}

#[test]
fn parse_ipv6_destination_options_truncated() {
    let data = [6]; // 1 byte, need at least 2
    let mut buf = DissectBuffer::new();
    let err = DestinationOptionsDissector
        .dissect(&data, &mut buf, 0)
        .unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 2,
            actual: 1
        }
    ));
}

#[test]
fn parse_ipv6_chained_extension_headers() {
    // IPv6 header (NH=0 Hop-by-Hop) → Hop-by-Hop (NH=44 Fragment) → Fragment (NH=6 TCP)
    let mut data = build_ipv6_packet(0, [0; 16], [0; 16], 16); // NH=0 (Hop-by-Hop)

    // Hop-by-Hop: NH=44 (Fragment), Hdr Ext Len=0 (8 bytes), PadN padding
    data.extend_from_slice(&[44, 0, 1, 4, 0, 0, 0, 0]);

    // Fragment: NH=6 (TCP), Reserved=0, Offset=0 M=0, ID=0x12345678
    data.extend_from_slice(&[6, 0, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78]);

    let mut buf = DissectBuffer::new();

    // Parse IPv6 header
    let result = Ipv6Dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.bytes_consumed, 40);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(0)); // Hop-by-Hop

    // Parse Hop-by-Hop
    let result = HopByHopDissector
        .dissect(&data[40..], &mut buf, 40)
        .unwrap();
    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(44)); // Fragment

    // Parse Fragment
    let result = FragmentDissector
        .dissect(&data[48..], &mut buf, 48)
        .unwrap();
    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6)); // TCP

    assert_eq!(buf.layers().len(), 3);

    // Verify Fragment identification
    let frag = buf.layer_by_name("IPv6 Fragment").unwrap();
    assert_eq!(
        buf.field_by_name(frag, "identification").unwrap().value,
        FieldValue::U32(0x12345678)
    );
    assert_eq!(
        buf.field_by_name(frag, "m_flag").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(frag, "fragment_offset").unwrap().value,
        FieldValue::U16(0)
    );
}

// --- Authentication Header tests (RFC 4302) ---

#[test]
fn parse_ipv6_ah_basic() {
    // RFC 4302, Section 2.2 — Authentication Header
    // Minimum AH: 12 bytes (Payload Len=1 → (1+2)*4=12, no ICV)
    let ah_header: [u8; 12] = [
        6, // Next Header: TCP
        1, // Payload Length: 1 (= (1+2)*4 = 12 bytes total)
        0, 0, // Reserved
        0xDE, 0xAD, 0xBE, 0xEF, // SPI
        0x00, 0x00, 0x00, 0x01, // Sequence Number
    ];

    let mut buf = DissectBuffer::new();
    let result = AhDissector.dissect(&ah_header, &mut buf, 40).unwrap();

    assert_eq!(result.bytes_consumed, 12);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

    let layer = buf.layer_by_name("AH").unwrap();
    assert_eq!(layer.name, "AH");
    assert_eq!(layer.range, 40..52);
    assert_eq!(
        buf.field_by_name(layer, "next_header").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "payload_len").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "spi").unwrap().value,
        FieldValue::U32(0xDEADBEEF)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U32(1)
    );
}

#[test]
fn parse_ipv6_ah_with_icv() {
    // RFC 4302, Section 2.2 — AH with 12-byte ICV (HMAC-SHA-1-96)
    // Payload Len=4 → (4+2)*4 = 24 bytes total, ICV = 24-12 = 12 bytes
    let mut ah_header = vec![
        17, // Next Header: UDP
        4,  // Payload Length: 4
        0, 0, // Reserved
        0x00, 0x00, 0x01, 0x00, // SPI
        0x00, 0x00, 0x00, 0x0A, // Sequence Number = 10
    ];
    // 12 bytes of ICV
    ah_header.extend_from_slice(&[0xAA; 12]);

    let mut buf = DissectBuffer::new();
    let result = AhDissector.dissect(&ah_header, &mut buf, 40).unwrap();

    assert_eq!(result.bytes_consumed, 24);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(17));

    let layer = buf.layer_by_name("AH").unwrap();
    assert_eq!(layer.range, 40..64);
    assert_eq!(
        buf.field_by_name(layer, "spi").unwrap().value,
        FieldValue::U32(0x00000100)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U32(10)
    );

    // ICV field should contain the 12 bytes
    let icv = buf.field_by_name(layer, "icv").unwrap();
    assert_eq!(icv.value, FieldValue::Bytes(&[0xAA; 12]));
    assert_eq!(icv.range, 52..64);
}

#[test]
fn parse_ipv6_ah_truncated() {
    // Less than the 12-byte fixed minimum
    let data = [6, 1, 0, 0, 0, 0, 0, 0]; // 8 bytes, need 12
    let mut buf = DissectBuffer::new();
    let err = AhDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 12,
            actual: 8
        }
    ));
}

#[test]
fn parse_ipv6_ah_truncated_payload() {
    // Fixed header present but data shorter than declared payload length
    // Payload Len=4 → total=24 bytes, but only provide 12
    let data: [u8; 12] = [6, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut buf = DissectBuffer::new();
    let err = AhDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 24,
            actual: 12
        }
    ));
}

#[test]
fn parse_ipv6_ah_invalid_payload_len() {
    // RFC 4302, Section 2.2 — Payload Len=0 gives total_len=8 < AH_FIXED_SIZE=12; must be rejected
    let data: [u8; 12] = [
        6, // Next Header: TCP
        0, // Payload Length: 0 — invalid (would imply only 8 bytes, but fixed fields need 12)
        0, 0, // Reserved
        0xDE, 0xAD, 0xBE, 0xEF, // SPI
        0x00, 0x00, 0x00, 0x01, // Sequence Number
    ];
    let mut buf = DissectBuffer::new();
    let err = AhDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidHeader(_)
    ));
}

#[test]
fn ah_dissector_metadata() {
    let d = AhDissector;
    assert_eq!(d.name(), "Authentication Header");
    assert_eq!(d.short_name(), "AH");
}

// --- Encapsulating Security Payload tests (RFC 4303) ---

#[test]
fn parse_ipv6_esp_basic() {
    // RFC 4303, Section 2.1 — ESP Header
    // SPI (4 bytes) + Sequence Number (4 bytes) + encrypted payload
    let mut esp_data = vec![
        0xDE, 0xAD, 0xBE, 0xEF, // SPI
        0x00, 0x00, 0x00, 0x05, // Sequence Number = 5
    ];
    // Encrypted payload (cannot be parsed further)
    esp_data.extend_from_slice(&[0x00; 16]);

    let mut buf = DissectBuffer::new();
    let result = EspDissector::new()
        .dissect(&esp_data, &mut buf, 40)
        .unwrap();

    assert_eq!(result.bytes_consumed, esp_data.len());
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("ESP").unwrap();
    assert_eq!(layer.name, "ESP");
    assert_eq!(layer.range, 40..40 + esp_data.len());
    assert_eq!(
        buf.field_by_name(layer, "spi").unwrap().value,
        FieldValue::U32(0xDEADBEEF)
    );
    assert_eq!(
        buf.field_by_name(layer, "sequence_number").unwrap().value,
        FieldValue::U32(5)
    );
    // Encrypted data field
    assert_eq!(
        buf.field_by_name(layer, "encrypted_data").unwrap().value,
        FieldValue::Bytes(&[0x00; 16])
    );
}

#[test]
fn parse_ipv6_esp_truncated() {
    // Less than 8 bytes
    let data = [0xDE, 0xAD, 0xBE, 0xEF]; // 4 bytes, need at least 8
    let mut buf = DissectBuffer::new();
    let err = EspDissector::new().dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 8,
            actual: 4
        }
    ));
}

#[test]
fn esp_dissector_metadata() {
    let d = EspDissector::new();
    assert_eq!(d.name(), "Encapsulating Security Payload");
    assert_eq!(d.short_name(), "ESP");
}

// --- Mobility Header tests (RFC 6275) ---

#[test]
fn parse_ipv6_mobility_basic() {
    // RFC 6275, Section 6.1 — Mobility Header
    // Minimum 8 bytes: Payload Proto, Header Len=0 ((0+1)*8=8), MH Type, Reserved, Checksum
    let mh_header: [u8; 8] = [
        6, // Payload Proto (Next Header): TCP
        0, // Header Len: 0 (= 8 bytes total)
        1, // MH Type: Binding Refresh Request (1)
        0, // Reserved
        0xAB, 0xCD, // Checksum
        0, 0, // Message Data (none for BRR, just padding)
    ];

    let mut buf = DissectBuffer::new();
    let result = MobilityDissector.dissect(&mh_header, &mut buf, 40).unwrap();

    assert_eq!(result.bytes_consumed, 8);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert_eq!(layer.name, "IPv6 Mobility");
    assert_eq!(layer.range, 40..48);
    assert_eq!(
        buf.field_by_name(layer, "payload_proto").unwrap().value,
        FieldValue::U8(6)
    );
    assert_eq!(
        buf.field_by_name(layer, "header_len").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "mh_type").unwrap().value,
        FieldValue::U8(1)
    );
    // RFC 6275, Section 6.1.1 — Reserved byte.
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0xABCD)
    );
}

#[test]
fn parse_ipv6_mobility_with_data() {
    // RFC 6275, Section 6.1 — MH with message data
    // Header Len=1 → (1+1)*8 = 16 bytes total, message data = 16-6 = 10 bytes
    let mut mh_header = vec![
        59,  // Payload Proto: No Next Header
        1,   // Header Len: 1 (= 16 bytes total)
        200, // MH Type: not decoded, so the body stays raw
        0,   // Reserved
        0x12, 0x34, // Checksum
    ];
    // 10 bytes of message data
    mh_header.extend_from_slice(&[0xBB; 10]);

    let mut buf = DissectBuffer::new();
    let result = MobilityDissector.dissect(&mh_header, &mut buf, 40).unwrap();

    assert_eq!(result.bytes_consumed, 16);
    assert_eq!(result.next, DispatchHint::ByIpProtocol(59));

    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert_eq!(layer.range, 40..56);
    assert_eq!(
        buf.field_by_name(layer, "header_len").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "mh_type").unwrap().value,
        FieldValue::U8(200)
    );

    let msg_data = buf.field_by_name(layer, "message_data").unwrap();
    assert_eq!(msg_data.value, FieldValue::Bytes(&[0xBB; 10]));
    assert_eq!(msg_data.range, 46..56);
}

#[test]
fn parse_ipv6_mobility_truncated() {
    // Less than 6-byte fixed minimum
    let data = [6, 0, 1, 0, 0]; // 5 bytes, need at least 6
    let mut buf = DissectBuffer::new();
    let err = MobilityDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 6,
            actual: 5
        }
    ));
}

#[test]
fn parse_ipv6_mobility_truncated_payload() {
    // Fixed header present but data shorter than declared length
    // Header Len=1 → total=16 bytes, but only provide 8
    let data: [u8; 8] = [6, 1, 1, 0, 0, 0, 0, 0];
    let mut buf = DissectBuffer::new();
    let err = MobilityDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 16,
            actual: 8
        }
    ));
}

#[test]
fn mobility_dissector_metadata() {
    let d = MobilityDissector;
    assert_eq!(d.name(), "IPv6 Mobility Header");
    assert_eq!(d.short_name(), "IPv6 Mobility");
}

// ---------------------------------------------------------------------------
// Helpers for nested option objects
// ---------------------------------------------------------------------------

/// Return the direct children of an array as (range, value) pairs.
fn direct_children<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    array: &FieldValue<'pkt>,
) -> Vec<&'a Field<'pkt>> {
    let FieldValue::Array(range) = array else {
        panic!("expected an array, got {array:?}");
    };
    let children = buf.nested_fields(range);
    let mut out = Vec::new();
    let mut i = 0;
    while i < children.len() {
        out.push(&children[i]);
        i = match &children[i].value {
            FieldValue::Object(obj) => (obj.end - range.start) as usize,
            _ => i + 1,
        };
    }
    out
}

/// Return every option object in `name` as its byte range and nested fields.
fn option_objects<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    layer_name: &str,
    name: &str,
) -> Vec<(std::ops::Range<usize>, &'a [Field<'pkt>])> {
    let layer = buf.layer_by_name(layer_name).unwrap();
    let array = &buf.field_by_name(layer, name).unwrap().value;
    direct_children(buf, array)
        .into_iter()
        .map(|f| {
            let FieldValue::Object(obj) = &f.value else {
                panic!("option entries must be objects");
            };
            (f.range.clone(), buf.nested_fields(obj))
        })
        .collect()
}

fn child<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> Option<&'a FieldValue<'pkt>> {
    fields.iter().find(|f| f.name() == name).map(|f| &f.value)
}

fn hbh_options(data: &[u8]) -> DissectBuffer<'_> {
    let mut buf = DissectBuffer::new();
    HopByHopDissector.dissect(data, &mut buf, 40).unwrap();
    buf
}

// ---------------------------------------------------------------------------
// Hop-by-Hop / Destination options (RFC 8200, Section 4.2)
// ---------------------------------------------------------------------------

#[test]
fn parse_ipv6_option_pad1_padn() {
    // RFC 8200, Section 4.2 — Pad1 is a single octet; PadN has a length and
    // zero or more padding octets.
    let data = [0x3a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(opts.len(), 3);
    assert_eq!(opts[0].0, 42..43);
    assert_eq!(child(opts[0].1, "type"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opts[0].1, "length"), None);
    assert_eq!(opts[1].0, 43..45);
    assert_eq!(child(opts[1].1, "length"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opts[1].1, "value"), None);
    assert_eq!(opts[2].0, 45..48);
    assert_eq!(child(opts[2].1, "value"), Some(&FieldValue::Bytes(&[0])));
}

#[test]
fn parse_ipv6_option_router_alert() {
    // RFC 2711, Section 2.1 — Router Alert as carried by MLDv2 reports.
    let data = [0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];
    let buf = hbh_options(&data);
    let layer = buf.layer_by_name("IPv6 Hop-by-Hop").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "router_alert").unwrap().value,
        FieldValue::U16(0)
    );
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(opts.len(), 2);
    assert_eq!(child(opts[0].1, "action"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opts[0].1, "change"), Some(&FieldValue::U8(0)));
    let idx = buf
        .fields()
        .iter()
        .position(|f| f.name() == "option")
        .unwrap() as u32;
    assert_eq!(
        buf.resolve_container_display_name(idx),
        Some("Router Alert")
    );
}

#[test]
fn parse_ipv6_option_router_alert_bad_length() {
    // RFC 2711, Section 2.1 — Opt Data Len is 2; other lengths stay raw.
    let data = [0x3a, 0x00, 0x05, 0x01, 0x00, 0x01, 0x01, 0x00];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(child(opts[0].1, "router_alert"), None);
    assert_eq!(child(opts[0].1, "value"), Some(&FieldValue::Bytes(&[0])));
}

#[test]
fn parse_ipv6_option_action_change_bits() {
    // RFC 8200, Section 4.2 — the highest-order two bits of the Option Type
    // are the action, the third-highest bit says whether the data may change
    // en route. 0x63 = 01 1 00011.
    let data = [0x3a, 0x00, 0x63, 0x04, 0x00, 0x1E, 0x01, 0x00];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(child(opts[0].1, "action"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opts[0].1, "change"), Some(&FieldValue::U8(1)));
}

#[test]
fn parse_ipv6_option_jumbo_payload() {
    // RFC 2675, Section 2 — Jumbo Payload: type 0xC2, Opt Data Len 4. The
    // length excludes the IPv6 header but includes this Hop-by-Hop header,
    // so the payload after this header is 70000 - 8 octets.
    let data = [0x06, 0x00, 0xC2, 0x04, 0x00, 0x01, 0x11, 0x70];
    let mut buf = DissectBuffer::new();
    let result = HopByHopDissector.dissect(&data, &mut buf, 40).unwrap();
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(
        child(opts[0].1, "jumbo_payload_length"),
        Some(&FieldValue::U32(70000))
    );
    assert_eq!(result.payload_len, Some(70000 - 8));
}

#[test]
fn parse_ipv6_option_jumbo_in_destination_options() {
    // RFC 2675, Section 2 — the Jumbo Payload option belongs in the
    // Hop-by-Hop header only; elsewhere it does not bound the payload.
    let data = [0x06, 0x00, 0xC2, 0x04, 0x00, 0x01, 0x11, 0x70];
    let mut buf = DissectBuffer::new();
    let result = DestinationOptionsDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    assert_eq!(result.payload_len, None);
}

#[test]
fn parse_ipv6_jumbogram_payload_bounded() {
    // RFC 2675, Section 3 — Payload Length 0 with a Jumbo Payload option of
    // 70000 octets: the 8-octet Hop-by-Hop header plus a 69992-octet ICMPv6
    // Echo Request. The 8 trailing octets are not part of the Echo data.
    use packet_dissector::registry::DissectorRegistry;
    let mut pkt = build_ipv6_packet(0, [0; 16], [0; 16], 0);
    pkt.extend_from_slice(&[58, 0x00, 0xC2, 0x04, 0x00, 0x01, 0x11, 0x70]);
    pkt.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
    pkt.extend_from_slice(&vec![0xAA; 69992 - 8]);
    pkt.extend_from_slice(&[0xBB; 8]);
    let registry = DissectorRegistry::default();
    let mut buf = DissectBuffer::new();
    registry
        .dissect_with_link_type(&pkt, 229, &mut buf)
        .unwrap();
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(
        child(opts[0].1, "jumbo_payload_length"),
        Some(&FieldValue::U32(70000))
    );
    let icmpv6 = buf.layer_by_name("ICMPv6").unwrap();
    assert_eq!(icmpv6.range, 48..40 + 70000);
    let FieldValue::Bytes(data) = buf.field_by_name(icmpv6, "data").unwrap().value else {
        panic!("echo data must be bytes");
    };
    assert_eq!(data.len(), 69992 - 8);
    assert!(data.iter().all(|&b| b == 0xAA));
}

#[test]
fn parse_ipv6_option_jumbo_invalid_length_ignored() {
    // RFC 2675, Section 2 — the Jumbo Payload Length "Must be greater than
    // 65,535." A smaller value is still shown but does not bound the payload,
    // so a bogus option cannot hide the upper layers.
    let data = [0x06, 0x00, 0xC2, 0x04, 0x00, 0x00, 0x00, 0x08];
    let mut buf = DissectBuffer::new();
    let result = HopByHopDissector.dissect(&data, &mut buf, 40).unwrap();
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(
        child(opts[0].1, "jumbo_payload_length"),
        Some(&FieldValue::U32(8))
    );
    assert_eq!(result.payload_len, None);
}

#[test]
fn parse_ipv6_option_tunnel_encap_limit() {
    // RFC 2473, Section 5.1 — Tunnel Encapsulation Limit: type 0x04, one
    // octet limit.
    let data = [0x29, 0x00, 0x04, 0x01, 0x04, 0x01, 0x01, 0x00];
    let mut buf = DissectBuffer::new();
    DestinationOptionsDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let opts = option_objects(&buf, "IPv6 Destination Options", "options");
    assert_eq!(
        child(opts[0].1, "tunnel_encap_limit"),
        Some(&FieldValue::U8(4))
    );
}

#[test]
fn parse_ipv6_option_home_address() {
    // RFC 6275, Section 6.3 — Home Address destination option: type 0xC9,
    // Opt Data Len 16.
    let mut data = vec![0x3b, 0x02, 0x01, 0x02, 0x00, 0x00, 0xC9, 0x10];
    let home = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    data.extend_from_slice(&home);
    let mut buf = DissectBuffer::new();
    DestinationOptionsDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let opts = option_objects(&buf, "IPv6 Destination Options", "options");
    assert_eq!(opts.len(), 2);
    assert_eq!(opts[1].0, 46..64);
    assert_eq!(
        child(opts[1].1, "home_address"),
        Some(&FieldValue::Ipv6Addr(home))
    );
}

#[test]
fn parse_ipv6_option_calipso() {
    // RFC 5570, Section 5.1 — CALIPSO: DOI, Cmpt Length (32-bit words),
    // Sens Level, Checksum, Compartment Bitmap.
    let data = [
        0x3a, 0x01, 0x07, 0x0C, // NH, len, type, Opt Data Len 12
        0x00, 0x00, 0x00, 0x03, // DOI 3
        0x01, 0x05, 0xAB, 0xCD, // Cmpt Length 1, Sens Level 5, Checksum
        0x80, 0x00, 0x00, 0x01, // Compartment Bitmap
    ];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    let opt = opts[0].1;
    assert_eq!(child(opt, "calipso_doi"), Some(&FieldValue::U32(3)));
    assert_eq!(child(opt, "cmpt_length"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "sens_level"), Some(&FieldValue::U8(5)));
    assert_eq!(child(opt, "checksum"), Some(&FieldValue::U16(0xABCD)));
    assert_eq!(
        child(opt, "compartment_bitmap"),
        Some(&FieldValue::Bytes(&[0x80, 0x00, 0x00, 0x01]))
    );
}

#[test]
fn parse_ipv6_option_rpl() {
    // RFC 6553, Section 3 — O|R|F flags, RPLInstanceID, SenderRank.
    // RFC 9008, Section 11.1 assigns 0x23 as the RPL Option type as well.
    for opt_type in [0x63u8, 0x23u8] {
        let data = [0x3a, 0x00, opt_type, 0x04, 0xA0, 0x1E, 0x01, 0x00];
        let buf = hbh_options(&data);
        let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
        let opt = opts[0].1;
        assert_eq!(child(opt, "rpl_down"), Some(&FieldValue::U8(1)));
        assert_eq!(child(opt, "rpl_rank_error"), Some(&FieldValue::U8(0)));
        assert_eq!(child(opt, "rpl_forwarding_error"), Some(&FieldValue::U8(1)));
        assert_eq!(child(opt, "rpl_instance_id"), Some(&FieldValue::U8(0x1E)));
        assert_eq!(child(opt, "sender_rank"), Some(&FieldValue::U16(0x0100)));
        assert_eq!(child(opt, "sub_tlvs"), None);
    }
}

#[test]
fn parse_ipv6_option_mpl() {
    // RFC 7731, Section 6.1 — S=1 (16-bit seed-id), M=1, V=0, sequence.
    let data = [0x3a, 0x00, 0x6D, 0x04, 0x60, 0x2A, 0xBE, 0xEF];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    let opt = opts[0].1;
    assert_eq!(child(opt, "mpl_seed_id_length"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "mpl_max"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "mpl_version"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opt, "mpl_sequence"), Some(&FieldValue::U8(0x2A)));
    assert_eq!(
        child(opt, "mpl_seed_id"),
        Some(&FieldValue::Bytes(&[0xBE, 0xEF]))
    );
}

#[test]
fn parse_ipv6_option_ioam() {
    // RFC 9486, Section 3 — Reserved, IOAM Option-Type, Option Data.
    let data = [
        0x3a, 0x01, 0x31, 0x06, 0x00, 0x00, 0x11, 0x22, // Pre-allocated Trace
        0x33, 0x44, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, // PadN
    ];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    let opt = opts[0].1;
    assert_eq!(child(opt, "ioam_reserved"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opt, "ioam_type"), Some(&FieldValue::U8(0)));
    assert_eq!(
        child(opt, "ioam_data"),
        Some(&FieldValue::Bytes(&[0x11, 0x22, 0x33, 0x44]))
    );
}

#[test]
fn parse_ipv6_option_pdm() {
    // RFC 8250, Section 3.2.1 — PDM: Opt Data Len 10.
    let data = [
        0x06, 0x01, 0x0F, 0x0A, 0x01, 0x02, 0x00, 0x10, // ScaleDTLR/S, PSNTP
        0x00, 0x0F, 0x12, 0x34, 0x56, 0x78, 0x01, 0x00, // PSNLR, DTLR, DTLS, PadN
    ];
    let mut buf = DissectBuffer::new();
    DestinationOptionsDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let opts = option_objects(&buf, "IPv6 Destination Options", "options");
    let opt = opts[0].1;
    assert_eq!(child(opt, "scale_dtlr"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opt, "scale_dtls"), Some(&FieldValue::U8(2)));
    assert_eq!(child(opt, "psn_this_packet"), Some(&FieldValue::U16(0x10)));
    assert_eq!(
        child(opt, "psn_last_received"),
        Some(&FieldValue::U16(0x0F))
    );
    assert_eq!(
        child(opt, "delta_time_last_received"),
        Some(&FieldValue::U16(0x1234))
    );
    assert_eq!(
        child(opt, "delta_time_last_sent"),
        Some(&FieldValue::U16(0x5678))
    );
}

#[test]
fn parse_ipv6_option_quick_start() {
    // RFC 4782, Section 3.2 — Quick-Start option for IPv6: type 0x26, same
    // data layout as the IPv4 option.
    let data = [
        0x06, 0x01, 0x26, 0x06, 0x05, 0x40, 0x12, 0x34, //
        0x56, 0x7B, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    let opt = opts[0].1;
    assert_eq!(child(opt, "qs_function"), Some(&FieldValue::U8(0)));
    assert_eq!(child(opt, "qs_rate"), Some(&FieldValue::U8(5)));
    assert_eq!(child(opt, "qs_ttl"), Some(&FieldValue::U8(0x40)));
    assert_eq!(
        child(opt, "qs_nonce"),
        Some(&FieldValue::U32(0x1234_567B >> 2))
    );
}

#[test]
fn parse_ipv6_option_unknown() {
    // RFC 8200, Section 4.2 — unrecognized options keep their data raw.
    let data = [0x06, 0x00, 0x1E, 0x02, 0xDE, 0xAD, 0x01, 0x00];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(
        child(opts[0].1, "value"),
        Some(&FieldValue::Bytes(&[0xDE, 0xAD]))
    );
}

#[test]
fn parse_ipv6_option_length_past_end() {
    // RFC 8200, Section 4.2 — Opt Data Len that runs past the header is
    // reported as a malformed option holding the remaining octets.
    let data = [0x06, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00, 0x00];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(opts.len(), 1);
    assert_eq!(opts[0].0, 42..48);
    assert_eq!(child(opts[0].1, "length"), Some(&FieldValue::U8(9)));
    assert_eq!(
        child(opts[0].1, "malformed"),
        Some(&FieldValue::Bytes(&[0, 0, 0, 0]))
    );
    assert_eq!(child(opts[0].1, "router_alert"), None);
}

#[test]
fn parse_ipv6_option_missing_length() {
    // A non-Pad1 option type in the last octet has no Opt Data Len.
    let data = [0x06, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x05];
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(opts.len(), 2);
    assert_eq!(opts[1].0, 47..48);
    assert_eq!(child(opts[1].1, "length"), None);
    assert_eq!(child(opts[1].1, "malformed"), Some(&FieldValue::Bytes(&[])));
}

// ---------------------------------------------------------------------------
// Routing header types
// ---------------------------------------------------------------------------

#[test]
fn parse_ipv6_routing_type0() {
    // RFC 5095 deprecates Type 0; its layout (RFC 2460, Section 4.4) is a
    // 32-bit Reserved field followed by 128-bit addresses.
    let mut data = vec![59, 4, 0, 1, 0, 0, 0, 0];
    let a1 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let a2 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    data.extend_from_slice(&a1);
    data.extend_from_slice(&a2);
    let mut buf = DissectBuffer::new();
    GenericRoutingDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let layer = buf.layer_by_name("IPv6 Routing").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "routing_type_name"),
        Some("Source Route (deprecated)")
    );
    assert!(buf.field_by_name(layer, "data").is_none());
    let addrs = &buf.field_by_name(layer, "addresses").unwrap().value;
    let addrs: Vec<_> = direct_children(&buf, addrs)
        .into_iter()
        .map(|f| f.value.clone())
        .collect();
    assert_eq!(
        addrs,
        vec![FieldValue::Ipv6Addr(a1), FieldValue::Ipv6Addr(a2)]
    );
}

#[test]
fn parse_ipv6_routing_type2() {
    // RFC 6275, Section 6.4 — Type 2: Hdr Ext Len 2, Segments Left 1,
    // Reserved, Home Address.
    let mut data = vec![6, 2, 2, 1, 0, 0, 0, 0];
    let home = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    data.extend_from_slice(&home);
    let mut buf = DissectBuffer::new();
    GenericRoutingDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let layer = buf.layer_by_name("IPv6 Routing").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U32(0)
    );
    let field = buf.field_by_name(layer, "home_address").unwrap();
    assert_eq!(field.value, FieldValue::Ipv6Addr(home));
    assert_eq!(field.range, 48..64);
    assert!(buf.field_by_name(layer, "data").is_none());
}

#[test]
fn parse_ipv6_routing_type3() {
    // RFC 6554, Section 3 — CmprI 8, CmprE 12, Pad 4: n = ((24 - 4 - 4) / 8)
    // + 1 = 3 addresses of 8, 8 and 4 octets.
    let data = [
        59, 3, 3, 2, // NH, Hdr Ext Len 3 (32 octets), type 3, Segments Left 2
        0x8C, 0x40, 0x00, 0x00, // CmprI 8, CmprE 12, Pad 4, Reserved
        1, 1, 1, 1, 1, 1, 1, 1, // Address[1]
        2, 2, 2, 2, 2, 2, 2, 2, // Address[2]
        3, 3, 3, 3, // Address[3]
        0, 0, 0, 0, // padding
    ];
    let mut buf = DissectBuffer::new();
    GenericRoutingDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let layer = buf.layer_by_name("IPv6 Routing").unwrap();
    assert_eq!(buf.field_u8(layer, "cmpr_i"), Some(8));
    assert_eq!(buf.field_u8(layer, "cmpr_e"), Some(12));
    assert_eq!(buf.field_u8(layer, "pad"), Some(4));
    assert!(buf.field_by_name(layer, "addresses").is_none());
    let addrs = &buf
        .field_by_name(layer, "compressed_addresses")
        .unwrap()
        .value;
    let addrs: Vec<_> = direct_children(&buf, addrs)
        .into_iter()
        .map(|f| (f.value.clone(), f.range.clone()))
        .collect();
    assert_eq!(
        addrs,
        vec![
            (FieldValue::Bytes(&[1; 8]), 48..56),
            (FieldValue::Bytes(&[2; 8]), 56..64),
            (FieldValue::Bytes(&[3; 4]), 64..68),
        ]
    );
    assert!(buf.field_by_name(layer, "data").is_none());
}

#[test]
fn parse_ipv6_routing_type3_inconsistent() {
    // RFC 6554, Section 3 — Pad larger than the header leaves no room for
    // Address[n]; the body stays raw.
    let data = [59, 0, 3, 0, 0x00, 0xF0, 0x00, 0x00];
    let mut buf = DissectBuffer::new();
    GenericRoutingDissector
        .dissect(&data, &mut buf, 40)
        .unwrap();
    let layer = buf.layer_by_name("IPv6 Routing").unwrap();
    assert!(buf.field_by_name(layer, "compressed_addresses").is_none());
    assert_eq!(
        buf.field_by_name(layer, "data").unwrap().value,
        FieldValue::Bytes(&[0x00, 0xF0, 0x00, 0x00])
    );
}

// ---------------------------------------------------------------------------
// Mobility Header messages (RFC 6275, Section 6.1)
// ---------------------------------------------------------------------------

fn dissect_mh(data: &[u8]) -> DissectBuffer<'_> {
    let mut buf = DissectBuffer::new();
    MobilityDissector.dissect(data, &mut buf, 40).unwrap();
    buf
}

#[test]
fn parse_ipv6_mobility_brr() {
    // RFC 6275, Section 6.1.2 — Binding Refresh Request: 16-bit Reserved.
    let data = [59, 0, 0, 0, 0, 0, 0, 0];
    let buf = dissect_mh(&data);
    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "mh_type_name"),
        Some("Binding Refresh Request")
    );
    assert!(buf.field_by_name(layer, "message_data").is_none());
    assert!(buf.field_by_name(layer, "mobility_options").is_none());
}

#[test]
fn parse_ipv6_mobility_hoti_coti() {
    // RFC 6275, Sections 6.1.3 / 6.1.4 — Reserved, Init Cookie (64 bits).
    for mh_type in [1u8, 2u8] {
        let data = [59, 1, mh_type, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let buf = dissect_mh(&data);
        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        let cookie = buf.field_by_name(layer, "init_cookie").unwrap();
        assert_eq!(cookie.value, FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(cookie.range, 48..56);
    }
}

#[test]
fn parse_ipv6_mobility_hot_cot() {
    // RFC 6275, Sections 6.1.5 / 6.1.6 — Nonce Index, Init Cookie, Keygen
    // Token.
    for mh_type in [3u8, 4u8] {
        let mut data = vec![59, 2, mh_type, 0, 0, 0, 0x00, 0x07];
        data.extend_from_slice(&[0xC0; 8]);
        data.extend_from_slice(&[0x4B; 8]);
        let buf = dissect_mh(&data);
        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        assert_eq!(buf.field_u16(layer, "nonce_index"), Some(7));
        assert_eq!(
            buf.field_by_name(layer, "init_cookie").unwrap().value,
            FieldValue::Bytes(&[0xC0; 8])
        );
        assert_eq!(
            buf.field_by_name(layer, "keygen_token").unwrap().value,
            FieldValue::Bytes(&[0x4B; 8])
        );
    }
}

#[test]
fn parse_ipv6_mobility_binding_update() {
    // RFC 6275, Section 6.1.7 — Sequence #, A|H|L|K + Reserved, Lifetime,
    // followed by a PadN option (Section 6.2.3).
    let data = [
        59, 1, 5, 0, 0, 0, // fixed MH fields
        0x12, 0x34, // Sequence #
        0xC0, 0x00, // A=1, H=1
        0x00, 0x96, // Lifetime (4-second units)
        0x01, 0x02, 0x00, 0x00, // PadN
    ];
    let buf = dissect_mh(&data);
    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "mh_type_name"),
        Some("Binding Update")
    );
    assert_eq!(buf.field_u16(layer, "sequence_number"), Some(0x1234));
    assert_eq!(buf.field_u16(layer, "flags"), Some(0xC000));
    assert_eq!(buf.field_u16(layer, "lifetime"), Some(0x96));
    let opts = option_objects(&buf, "IPv6 Mobility", "mobility_options");
    assert_eq!(opts.len(), 1);
    assert_eq!(opts[0].0, 52..56);
    assert_eq!(child(opts[0].1, "type"), Some(&FieldValue::U8(1)));
    assert_eq!(child(opts[0].1, "value"), Some(&FieldValue::Bytes(&[0, 0])));
    assert!(buf.field_by_name(layer, "message_data").is_none());
}

#[test]
fn parse_ipv6_mobility_binding_ack() {
    // RFC 6275, Section 6.1.8 — Status, K + Reserved, Sequence #, Lifetime,
    // then a Binding Refresh Advice (Section 6.2.4), which "is only valid in
    // the Binding Acknowledgement".
    let data = [
        59, 1, 6, 0, 0, 0, // fixed MH fields
        0x00, 0x80, // Status 0 (accepted), K=1
        0x12, 0x34, // Sequence #
        0x00, 0x96, // Lifetime
        0x02, 0x02, 0x00, 0x3C, // Binding Refresh Advice, interval 60
    ];
    let buf = dissect_mh(&data);
    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert_eq!(buf.field_u8(layer, "status"), Some(0));
    assert_eq!(buf.field_u8(layer, "ack_flags"), Some(0x80));
    assert_eq!(buf.field_u16(layer, "sequence_number"), Some(0x1234));
    assert_eq!(buf.field_u16(layer, "lifetime"), Some(0x96));
    let opts = option_objects(&buf, "IPv6 Mobility", "mobility_options");
    assert_eq!(opts.len(), 1);
    assert_eq!(opts[0].0, 52..56);
    assert_eq!(
        child(opts[0].1, "refresh_interval"),
        Some(&FieldValue::U16(60))
    );
    let idx = buf
        .fields()
        .iter()
        .position(|f| f.name() == "option")
        .unwrap() as u32;
    assert_eq!(
        buf.resolve_container_display_name(idx),
        Some("Binding Refresh Advice")
    );
}

#[test]
fn parse_ipv6_mobility_pad1_padn() {
    // RFC 6275, Sections 6.2.2 / 6.2.3 — Pad1 has no length; PadN does.
    let data = [59, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0];
    let mut data = data.to_vec();
    data[1] = 1; // Header Len 1 (16 octets)
    let buf = dissect_mh(&data);
    let opts = option_objects(&buf, "IPv6 Mobility", "mobility_options");
    assert_eq!(opts[0].0, 48..49);
    assert_eq!(child(opts[0].1, "length"), None);
    assert_eq!(opts[1].0, 49..52);
    assert_eq!(child(opts[1].1, "value"), Some(&FieldValue::Bytes(&[0])));
}

#[test]
fn parse_ipv6_mobility_binding_error() {
    // RFC 6275, Section 6.1.9 — Status, Reserved, Home Address.
    let mut data = vec![59, 2, 7, 0, 0, 0, 0x02, 0x00];
    let home = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    data.extend_from_slice(&home);
    let buf = dissect_mh(&data);
    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert_eq!(buf.field_u8(layer, "status"), Some(2));
    let field = buf.field_by_name(layer, "home_address").unwrap();
    assert_eq!(field.value, FieldValue::Ipv6Addr(home));
    assert_eq!(field.range, 48..64);
}

#[test]
fn parse_ipv6_mobility_short_body() {
    // A Binding Error needs 18 octets of message data; with Header Len 0
    // only 2 are present, so the body stays raw.
    let data = [59, 0, 7, 0, 0, 0, 0x02, 0x00];
    let buf = dissect_mh(&data);
    let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
    assert!(buf.field_by_name(layer, "status").is_none());
    assert_eq!(
        buf.field_by_name(layer, "message_data").unwrap().value,
        FieldValue::Bytes(&[0x02, 0x00])
    );
}

#[test]
fn parse_ipv6_mobility_options() {
    // RFC 6275, Sections 6.2.5-6.2.7 — Alternate Care-of Address, Nonce
    // Indices, Binding Authorization Data, carried in a Binding Update.
    let coa = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
    let mut data = vec![
        59, 5, 5, 0, 0, 0, // fixed MH fields, Header Len 5 (48 octets)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x10, // Sequence #, flags, Lifetime
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, // PadN
        0x03, 0x10, // Alternate Care-of Address
    ];
    data.extend_from_slice(&coa);
    data.extend_from_slice(&[0x04, 0x04, 0x00, 0x01, 0x00, 0x02]); // Nonce Indices
    data.extend_from_slice(&[0x05, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]); // Auth Data
    assert_eq!(data.len(), 48);
    let buf = dissect_mh(&data);
    let opts = option_objects(&buf, "IPv6 Mobility", "mobility_options");
    assert_eq!(opts.len(), 4);
    assert_eq!(
        child(opts[1].1, "alternate_care_of_address"),
        Some(&FieldValue::Ipv6Addr(coa))
    );
    assert_eq!(
        child(opts[2].1, "home_nonce_index"),
        Some(&FieldValue::U16(1))
    );
    assert_eq!(
        child(opts[2].1, "care_of_nonce_index"),
        Some(&FieldValue::U16(2))
    );
    assert_eq!(
        child(opts[3].1, "authenticator"),
        Some(&FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD]))
    );
}

#[test]
fn parse_ipv6_mobility_options_malformed() {
    // RFC 6275, Section 6.2.1 — unrecognized options are skipped (kept as
    // raw values); an option running past the header is malformed.
    let data = [
        59, 1, 0, 0, 0, 0, 0, 0, // BRR, Reserved
        0x2A, 0x01, 0xEE, // unknown option, 1 octet of data
        0x02, 0x07, 0x00, 0x00, 0x00, // BRA with Option Length past the end
    ];
    let buf = dissect_mh(&data);
    let opts = option_objects(&buf, "IPv6 Mobility", "mobility_options");
    assert_eq!(opts.len(), 2);
    assert_eq!(child(opts[0].1, "value"), Some(&FieldValue::Bytes(&[0xEE])));
    assert_eq!(opts[1].0, 51..56);
    assert_eq!(
        child(opts[1].1, "malformed"),
        Some(&FieldValue::Bytes(&[0, 0, 0]))
    );
    assert_eq!(child(opts[1].1, "refresh_interval"), None);
}

fn option_display_names(buf: &DissectBuffer<'_>) -> Vec<Option<&'static str>> {
    buf.fields()
        .iter()
        .enumerate()
        .filter(|(_, f)| f.name() == "option")
        .map(|(i, f)| {
            let FieldValue::Object(range) = &f.value else {
                panic!("option must be an object");
            };
            let by_container = buf.resolve_container_display_name(i as u32);
            assert_eq!(
                by_container,
                buf.resolve_nested_display_name(range, "type_name")
            );
            by_container
        })
        .collect()
}

#[test]
fn parse_ipv6_option_mpl_seed_id_sizes() {
    // RFC 7731, Section 6.1 — S selects a seed-id of 0, 2, 8 or 16 octets.
    let buf = hbh_options(&[0x3a, 0x00, 0x6D, 0x02, 0x00, 0x07, 0x01, 0x00]);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(child(opts[0].1, "mpl_seed_id"), None);
    assert_eq!(child(opts[0].1, "mpl_sequence"), Some(&FieldValue::U8(7)));

    let mut data = vec![0x3a, 0x01, 0x6D, 0x0A, 0x80, 0x07];
    data.extend_from_slice(&[0xAB; 8]);
    data.extend_from_slice(&[0x01, 0x00]);
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(
        child(opts[0].1, "mpl_seed_id"),
        Some(&FieldValue::Bytes(&[0xAB; 8]))
    );

    let mut data = vec![0x3a, 0x02, 0x6D, 0x12, 0xC0, 0x07];
    data.extend_from_slice(&[0xCD; 16]);
    data.extend_from_slice(&[0x01, 0x00]);
    let buf = hbh_options(&data);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(
        child(opts[0].1, "mpl_seed_id"),
        Some(&FieldValue::Bytes(&[0xCD; 16]))
    );

    // S=3 but only 2 octets of seed-id: kept raw.
    let buf = hbh_options(&[0x3a, 0x00, 0x6D, 0x04, 0xC0, 0x07, 0x01, 0x02]);
    let opts = option_objects(&buf, "IPv6 Hop-by-Hop", "options");
    assert_eq!(child(opts[0].1, "mpl_seed_id"), None);
    assert_eq!(
        child(opts[0].1, "value"),
        Some(&FieldValue::Bytes(&[0xC0, 0x07, 0x01, 0x02]))
    );
}

#[test]
fn parse_ipv6_option_names() {
    // IANA "Destination Options and Hop-by-Hop Options" registry names.
    let data = [
        0x3a, 0x03, // NH, Hdr Ext Len 3 (32 octets)
        0x00, // Pad1
        0x01, 0x00, // PadN
        0x04, 0x00, // Tunnel Encapsulation Limit (bad length)
        0x07, 0x00, // CALIPSO (bad length)
        0x0F, 0x00, // PDM (bad length)
        0x11, 0x00, // IOAM (dest)
        0x31, 0x00, // IOAM (HBH)
        0x23, 0x00, // RPL Option
        0x63, 0x00, // RPL Option (deprecated)
        0x26, 0x00, // Quick-Start
        0x6D, 0x00, // MPL Option
        0xC2, 0x00, // Jumbo Payload
        0xC9, 0x00, // Home Address
        0x1E, 0x00, // unknown
        0x01, 0x01, 0x00, // PadN
    ];
    let buf = hbh_options(&data);
    assert_eq!(
        option_display_names(&buf),
        vec![
            Some("Pad1"),
            Some("PadN"),
            Some("Tunnel Encapsulation Limit"),
            Some("CALIPSO"),
            Some("Performance and Diagnostic Metrics"),
            Some("IOAM"),
            Some("IOAM"),
            Some("RPL Option"),
            Some("RPL Option (deprecated)"),
            Some("Quick-Start"),
            Some("MPL Option"),
            Some("Jumbo Payload"),
            Some("Home Address"),
            None,
            Some("PadN"),
        ]
    );
}

#[test]
fn parse_ipv6_routing_type_names() {
    // IANA "Routing Types" registry.
    for (t, name) in [
        (0u8, Some("Source Route (deprecated)")),
        (2, Some("Type 2 Routing Header")),
        (3, Some("RPL Source Route Header")),
        (4, Some("Segment Routing Header")),
        (5, None),
    ] {
        let data = [59, 0, t, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        GenericRoutingDissector
            .dissect(&data, &mut buf, 40)
            .unwrap();
        let layer = buf.layer_by_name("IPv6 Routing").unwrap();
        assert_eq!(buf.resolve_display_name(layer, "routing_type_name"), name);
    }
}

#[test]
fn parse_ipv6_mobility_option_missing_length() {
    // A non-Pad1 mobility option in the last octet has no Option Length.
    let data = [59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
    let mut data = data.to_vec();
    data[1] = 1;
    let buf = dissect_mh(&data);
    let opts = option_objects(&buf, "IPv6 Mobility", "mobility_options");
    let last = opts.last().unwrap();
    assert_eq!(last.0, 55..56);
    assert_eq!(child(last.1, "length"), None);
    assert_eq!(child(last.1, "malformed"), Some(&FieldValue::Bytes(&[])));
}

#[test]
fn parse_ipv6_mobility_names() {
    // RFC 6275, Sections 6.1.2-6.1.9 (MH Types) and 6.2.2-6.2.7 (options).
    for (t, name) in [
        (0u8, Some("Binding Refresh Request")),
        (1, Some("Home Test Init")),
        (2, Some("Care-of Test Init")),
        (3, Some("Home Test")),
        (4, Some("Care-of Test")),
        (5, Some("Binding Update")),
        (6, Some("Binding Acknowledgement")),
        (7, Some("Binding Error")),
        (8, None),
    ] {
        let data = [59, 0, t, 0, 0, 0, 0, 0];
        let buf = dissect_mh(&data);
        let layer = buf.layer_by_name("IPv6 Mobility").unwrap();
        assert_eq!(buf.resolve_display_name(layer, "mh_type_name"), name);
    }

    let coa = [0u8; 16];
    let mut data = vec![59, 5, 0, 0, 0, 0, 0, 0]; // BRR, Header Len 5 (48 octets)
    data.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00]);
    data.extend_from_slice(&[0x03, 0x10]);
    data.extend_from_slice(&coa);
    data.extend_from_slice(&[0x04, 0x04, 0, 1, 0, 2, 0x05, 0x01, 0xAA]);
    data.extend_from_slice(&[0x2A, 0x00, 0x01, 0x02, 0, 0]);
    assert_eq!(data.len(), 48);
    let buf = dissect_mh(&data);
    assert_eq!(
        option_display_names(&buf),
        vec![
            Some("Pad1"),
            Some("PadN"),
            Some("Binding Refresh Advice"),
            Some("Alternate Care-of Address"),
            Some("Nonce Indices"),
            Some("Binding Authorization Data"),
            None,
            Some("PadN"),
        ]
    );
}
