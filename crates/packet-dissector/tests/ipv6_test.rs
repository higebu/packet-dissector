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
//! | —           | MH dissector metadata          | mobility_dissector_metadata             |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::dissectors::ah::AhDissector;
use packet_dissector::dissectors::esp::EspDissector;
use packet_dissector::dissectors::ipv6::{
    DestinationOptionsDissector, FragmentDissector, GenericRoutingDissector, HopByHopDissector,
    Ipv6Dissector, MobilityDissector, RoutingDissector,
};
use packet_dissector::field::FieldValue;
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
    assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

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
        59, // Payload Proto: No Next Header
        1,  // Header Len: 1 (= 16 bytes total)
        5,  // MH Type: Binding Update (5)
        0,  // Reserved
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
        FieldValue::U8(5)
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
