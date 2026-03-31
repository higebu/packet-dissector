//! # RFC 6733 (Diameter) and 3GPP TS 29.272 (S6a/S6d) Coverage
//!
//! | Spec              | Section | Description                          | Test                                      |
//! |-------------------|---------|--------------------------------------|-------------------------------------------|
//! | RFC 6733          | 3       | Header parsing, command code/flags   | parse_diameter_basic                      |
//! | RFC 6733          | 3       | Invalid version                      | parse_diameter_invalid_version            |
//! | RFC 6733          | 3       | Truncated header                     | parse_diameter_truncated                  |
//! | RFC 6733          | 4       | AVP parsing (no vendor)              | parse_diameter_avp_no_vendor              |
//! | RFC 6733          | 4       | AVP with vendor                      | parse_diameter_avp_with_vendor            |
//! | RFC 6733          | 4.1     | AVP padding to 4-byte boundary       | parse_diameter_avp_padding                |
//! | RFC 6733          | 7       | Result-Code name annotation          | parse_diameter_result_code_name           |
//! | —                 | —       | Header-only (no AVPs)                | parse_diameter_header_only                |
//! | —                 | —       | Dissector metadata                   | diameter_dissector_metadata               |
//! | —                 | —       | TCP port 3868 registered             | diameter_registered_on_tcp_3868           |
//! | —                 | —       | CER full stack via TCP registry      | diameter_via_registry_tcp                 |
//! | 3GPP TS 29.272    | 7.1.8   | Application-ID name resolution       | s6a_application_name                      |
//! | 3GPP TS 29.272    | 7.2.2   | S6a command code name resolution     | s6a_ulr_command_name                      |
//! | 3GPP TS 29.272    | 7.3     | 3GPP vendor AVP name resolution      | s6a_vendor_avp_name_resolution            |
//! | 3GPP TS 29.272    | 7.4     | Experimental-Result-Code annotation  | s6a_experimental_result_code              |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;

use packet_dissector::dissectors::diameter::DiameterDissector;

// ── Constants ────────────────────────────────────────────────────────────────

const HEADER_SIZE: usize = 20;
const FLAG_REQUEST: u8 = 0x80;
const AVP_FLAG_VENDOR: u8 = 0x80;

// ── Builders ─────────────────────────────────────────────────────────────────

/// Build a minimal Diameter message header (no AVPs).
fn build_header(flags: u8, command_code: u32, app_id: u32, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0] = 1; // Version
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = HEADER_SIZE as u8; // message_length = 20
    buf[4] = flags;
    buf[5] = ((command_code >> 16) & 0xFF) as u8;
    buf[6] = ((command_code >> 8) & 0xFF) as u8;
    buf[7] = (command_code & 0xFF) as u8;
    buf[8..12].copy_from_slice(&app_id.to_be_bytes());
    buf[12..16].copy_from_slice(&hbh.to_be_bytes());
    buf[16..20].copy_from_slice(&e2e.to_be_bytes());
    buf
}

/// Build a Diameter message with one AVP (no vendor-id).
fn build_message_with_avp(avp_code: u32, avp_flags: u8, avp_data: &[u8]) -> Vec<u8> {
    let avp_length = 8 + avp_data.len();
    let padded = (avp_length + 3) & !3;
    let total = HEADER_SIZE + padded;

    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0] = 1;
    buf[1] = ((total >> 16) & 0xFF) as u8;
    buf[2] = ((total >> 8) & 0xFF) as u8;
    buf[3] = (total & 0xFF) as u8;
    buf[4] = FLAG_REQUEST;
    buf[5] = 0x00;
    buf[6] = 0x01;
    buf[7] = 0x01; // command_code = 257 (CER)

    // AVP header
    buf.extend_from_slice(&avp_code.to_be_bytes());
    buf.push(avp_flags);
    buf.push(((avp_length >> 16) & 0xFF) as u8);
    buf.push(((avp_length >> 8) & 0xFF) as u8);
    buf.push((avp_length & 0xFF) as u8);
    buf.extend_from_slice(avp_data);
    buf.resize(HEADER_SIZE + padded, 0);
    buf
}

/// Build a Diameter message with a vendor-specific AVP.
fn build_message_with_vendor_avp(avp_code: u32, vendor_id: u32, avp_data: &[u8]) -> Vec<u8> {
    let avp_length = 12 + avp_data.len();
    let padded = (avp_length + 3) & !3;
    let total = HEADER_SIZE + padded;

    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0] = 1;
    buf[1] = ((total >> 16) & 0xFF) as u8;
    buf[2] = ((total >> 8) & 0xFF) as u8;
    buf[3] = (total & 0xFF) as u8;
    buf[4] = FLAG_REQUEST;
    buf[5] = 0x00;
    buf[6] = 0x01;
    buf[7] = 0x01;

    buf.extend_from_slice(&avp_code.to_be_bytes());
    buf.push(AVP_FLAG_VENDOR | 0x40); // V + M flags
    buf.push(((avp_length >> 16) & 0xFF) as u8);
    buf.push(((avp_length >> 8) & 0xFF) as u8);
    buf.push((avp_length & 0xFF) as u8);
    buf.extend_from_slice(&vendor_id.to_be_bytes());
    buf.extend_from_slice(avp_data);
    buf.resize(HEADER_SIZE + padded, 0);
    buf
}

// ── Helper accessors ──────────────────────────────────────────────────────────

fn get_avp_field<'a>(
    buf: &'a packet_dissector::packet::DissectBuffer<'_>,
    layer: &packet_dissector::packet::Layer,
    avp_index: usize,
    field_name: &str,
) -> Option<FieldValue<'a>> {
    let avps_field = buf.field_by_name(layer, "avps")?;
    let FieldValue::Array(ref arr_range) = avps_field.value else {
        return None;
    };
    let arr = buf.nested_fields(arr_range);
    let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
    let obj = objects.get(avp_index)?;
    let FieldValue::Object(ref obj_range) = obj.value else {
        return None;
    };
    let fields = buf.nested_fields(obj_range);
    fields
        .iter()
        .find(|f| f.name() == field_name)
        .map(|f| f.value.clone())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn parse_diameter_basic() {
    // CER: flags=0x80 (R), code=257, app_id=0, hbh=0xCAFE, e2e=0xBABE
    let data = build_header(FLAG_REQUEST, 257, 0, 0xCAFE, 0xBABE);
    let mut buf = DissectBuffer::new();
    let result = DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, HEADER_SIZE);
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("Diameter").unwrap();
    assert_eq!(layer.range, 0..HEADER_SIZE);
    assert_eq!(
        buf.field_by_name(layer, "version").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "command_code").unwrap().value,
        FieldValue::U32(257)
    );
    assert_eq!(
        buf.field_by_name(layer, "is_request").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.resolve_display_name(layer, "command_code_name"),
        Some("Capabilities-Exchange-Request")
    );
    assert_eq!(
        buf.field_by_name(layer, "application_id").unwrap().value,
        FieldValue::U32(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "hop_by_hop_id").unwrap().value,
        FieldValue::U32(0xCAFE)
    );
    assert_eq!(
        buf.field_by_name(layer, "end_to_end_id").unwrap().value,
        FieldValue::U32(0xBABE)
    );
}

#[test]
fn parse_diameter_header_only() {
    let data = build_header(FLAG_REQUEST, 280, 0, 0, 0);
    let mut buf = DissectBuffer::new();
    let result = DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, HEADER_SIZE);
    let layer = buf.layer_by_name("Diameter").unwrap();
    // No avps field when no AVPs present.
    assert!(buf.field_by_name(layer, "avps").is_none());
}

#[test]
fn parse_diameter_invalid_version() {
    let mut data = build_header(FLAG_REQUEST, 257, 0, 0, 0);
    data[0] = 2; // wrong version
    let mut buf = DissectBuffer::new();
    let err = DiameterDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue {
            field: "version",
            ..
        }
    ));
}

#[test]
fn parse_diameter_truncated() {
    let data = vec![0x01, 0x00, 0x00]; // only 3 bytes
    let mut buf = DissectBuffer::new();
    let err = DiameterDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 20,
            actual: 3
        }
    ));
}

#[test]
fn parse_diameter_avp_no_vendor() {
    // Vendor-Id (266): Unsigned32 = 10415
    let data = build_message_with_avp(266, 0x40, &10415u32.to_be_bytes());
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    assert_eq!(
        get_avp_field(&buf, layer, 0, "code"),
        Some(FieldValue::U32(266))
    );
    assert_eq!(
        get_avp_field(&buf, layer, 0, "value"),
        Some(FieldValue::U32(10415))
    );
    assert_eq!(get_avp_field(&buf, layer, 0, "vendor_id"), None);
}

#[test]
fn parse_diameter_avp_with_vendor() {
    let data = build_message_with_vendor_avp(1, 10415, b"test");
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    assert_eq!(
        get_avp_field(&buf, layer, 0, "vendor_id"),
        Some(FieldValue::U32(10415))
    );
}

#[test]
fn parse_diameter_avp_padding() {
    // "ab" is 2 bytes — padded to 4. AVP length should be 10, padded to 12.
    // Using Class (25): OctetString
    let data = build_message_with_avp(25, 0x40, b"ab");
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    // AVP length = 8 + 2 = 10
    assert_eq!(
        get_avp_field(&buf, layer, 0, "length"),
        Some(FieldValue::U32(10))
    );
    // Data should be 2 bytes only (no padding in value).
    assert_eq!(
        get_avp_field(&buf, layer, 0, "value"),
        Some(FieldValue::Bytes(b"ab"))
    );
}

#[test]
fn parse_diameter_result_code_name() {
    // Result-Code (268): DIAMETER_SUCCESS = 2001
    let data = build_message_with_avp(268, 0x40, &2001u32.to_be_bytes());
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    assert_eq!(
        get_avp_field(&buf, layer, 0, "value"),
        Some(FieldValue::U32(2001))
    );
    {
        let avps_field = buf.field_by_name(layer, "avps").unwrap();
        let FieldValue::Array(ref arr_range) = avps_field.value else {
            panic!("expected Array")
        };
        let arr = buf.nested_fields(arr_range);
        let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
        let FieldValue::Object(ref obj_range) = objects[0].value else {
            panic!("expected Object")
        };
        assert_eq!(
            buf.resolve_nested_display_name(obj_range, "value_name"),
            Some("DIAMETER_SUCCESS")
        );
    }
}

#[test]
fn diameter_dissector_metadata() {
    assert_eq!(DiameterDissector.name(), "Diameter");
    assert_eq!(DiameterDissector.short_name(), "Diameter");
}

#[test]
fn diameter_registered_on_tcp_3868() {
    let reg = DissectorRegistry::default();
    let d = reg.get_by_tcp_port(3868);
    assert!(d.is_some(), "Diameter not registered on TCP port 3868");
    assert_eq!(d.unwrap().short_name(), "Diameter");
}

// ── Full-stack registry test ──────────────────────────────────────────────────

/// Build Ethernet + IPv4 + TCP + Diameter (CER) packet.
fn build_eth_ipv4_tcp_diameter_cer() -> Vec<u8> {
    let mac_dst = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac_src = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let ipv4_src = [10, 0, 0, 1];
    let ipv4_dst = [10, 0, 0, 2];

    let mut pkt = Vec::new();

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&mac_dst);
    pkt.extend_from_slice(&mac_src);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // IPv4 header (20 bytes), protocol=6 (TCP)
    let ipv4_start = pkt.len();
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Total Length placeholder
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&ipv4_src);
    pkt.extend_from_slice(&ipv4_dst);

    // TCP header (20 bytes): src=12345, dst=3868, ACK+PSH
    pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
    pkt.extend_from_slice(&3868u16.to_be_bytes()); // dst port
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // Seq
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // Ack
    pkt.push(0x50); // Data Offset = 5
    pkt.push(0x18); // PSH + ACK
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // Window
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // Urgent

    // Diameter CER payload
    pkt.extend_from_slice(&build_cer_payload());

    // Fix IPv4 Total Length
    let total_len = (pkt.len() - ipv4_start) as u16;
    pkt[ipv4_start + 2..ipv4_start + 4].copy_from_slice(&total_len.to_be_bytes());

    pkt
}

/// Build a minimal Diameter CER (Capabilities-Exchange-Request) payload.
///
/// Includes a single Origin-Host AVP (264, DiameterIdentity).
fn build_cer_payload() -> Vec<u8> {
    let origin_host = b"host.example.com";
    let avp_length = 8 + origin_host.len();
    let avp_padded = (avp_length + 3) & !3;
    let total = HEADER_SIZE + avp_padded;

    let mut buf = Vec::with_capacity(total);
    buf.push(1); // version
    buf.push(((total >> 16) & 0xFF) as u8);
    buf.push(((total >> 8) & 0xFF) as u8);
    buf.push((total & 0xFF) as u8);
    buf.push(FLAG_REQUEST); // R flag
    buf.push(0x00); // command_code[2]
    buf.push(0x01); // command_code[1]
    buf.push(0x01); // command_code[0] → 257
    buf.extend_from_slice(&0u32.to_be_bytes()); // Application-ID
    buf.extend_from_slice(&0x00000001u32.to_be_bytes()); // HbH ID
    buf.extend_from_slice(&0x00000001u32.to_be_bytes()); // E2E ID

    // Origin-Host AVP (264, M flag)
    buf.extend_from_slice(&264u32.to_be_bytes());
    buf.push(0x40); // M flag
    buf.push(((avp_length >> 16) & 0xFF) as u8);
    buf.push(((avp_length >> 8) & 0xFF) as u8);
    buf.push((avp_length & 0xFF) as u8);
    buf.extend_from_slice(origin_host);
    buf.resize(total, 0);
    buf
}

#[test]
fn diameter_via_registry_tcp() {
    // TCP stack: Ethernet → IPv4 → TCP → Diameter (CER)
    let reg = DissectorRegistry::default();
    let data = build_eth_ipv4_tcp_diameter_cer();
    let mut buf = DissectBuffer::new();
    reg.dissect(&data, &mut buf).unwrap();

    assert!(
        buf.layers().len() >= 4,
        "expected at least 4 layers, got {}",
        buf.layers().len()
    );
    assert_eq!(buf.layers()[0].name, "Ethernet");
    assert_eq!(buf.layers()[1].name, "IPv4");
    assert_eq!(buf.layers()[2].name, "TCP");
    assert_eq!(buf.layers()[3].name, "Diameter");

    let diameter = &buf.layers()[3];
    assert_eq!(
        buf.field_by_name(diameter, "command_code").unwrap().value,
        FieldValue::U32(257)
    );
    assert_eq!(
        buf.resolve_display_name(diameter, "command_code_name"),
        Some("Capabilities-Exchange-Request")
    );
    let avps_field = buf.field_by_name(diameter, "avps").unwrap();
    let FieldValue::Array(ref avps_range) = avps_field.value else {
        panic!("expected Array")
    };
    let avps_all = buf.nested_fields(avps_range);
    let avps: Vec<_> = avps_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(avps.len(), 1);
}

// ── 3GPP TS 29.272 S6a/S6d integration tests ───────────────────────────────

const FLAG_PROXIABLE: u8 = 0x40;
const S6A_APP_ID: u32 = 16777251;

/// Build a Diameter message with given command code, app_id, and multiple AVPs.
fn build_s6a_message(flags: u8, command_code: u32, app_id: u32, avp_bytes: &[u8]) -> Vec<u8> {
    let total = HEADER_SIZE + avp_bytes.len();
    let total_aligned = (total + 3) & !3;

    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0] = 1;
    buf[1] = ((total_aligned >> 16) & 0xFF) as u8;
    buf[2] = ((total_aligned >> 8) & 0xFF) as u8;
    buf[3] = (total_aligned & 0xFF) as u8;
    buf[4] = flags;
    buf[5] = ((command_code >> 16) & 0xFF) as u8;
    buf[6] = ((command_code >> 8) & 0xFF) as u8;
    buf[7] = (command_code & 0xFF) as u8;
    buf[8..12].copy_from_slice(&app_id.to_be_bytes());
    buf[12..16].copy_from_slice(&1u32.to_be_bytes()); // HbH
    buf[16..20].copy_from_slice(&2u32.to_be_bytes()); // E2E
    buf.extend_from_slice(avp_bytes);
    buf.resize(total_aligned, 0);
    buf
}

/// Build a 3GPP vendor AVP (vendor_id=10415) with given code and data.
fn build_3gpp_avp(avp_code: u32, avp_data: &[u8]) -> Vec<u8> {
    let avp_length = 12 + avp_data.len();
    let padded = (avp_length + 3) & !3;
    let mut buf = Vec::with_capacity(padded);
    buf.extend_from_slice(&avp_code.to_be_bytes());
    buf.push(AVP_FLAG_VENDOR | 0x40); // V + M flags
    buf.push(((avp_length >> 16) & 0xFF) as u8);
    buf.push(((avp_length >> 8) & 0xFF) as u8);
    buf.push((avp_length & 0xFF) as u8);
    buf.extend_from_slice(&10415u32.to_be_bytes()); // 3GPP vendor-id
    buf.extend_from_slice(avp_data);
    buf.resize(padded, 0);
    buf
}

/// Build a base AVP (no vendor) with given code and data.
fn build_base_avp(avp_code: u32, avp_data: &[u8]) -> Vec<u8> {
    let avp_length = 8 + avp_data.len();
    let padded = (avp_length + 3) & !3;
    let mut buf = Vec::with_capacity(padded);
    buf.extend_from_slice(&avp_code.to_be_bytes());
    buf.push(0x40); // M flag
    buf.push(((avp_length >> 16) & 0xFF) as u8);
    buf.push(((avp_length >> 8) & 0xFF) as u8);
    buf.push((avp_length & 0xFF) as u8);
    buf.extend_from_slice(avp_data);
    buf.resize(padded, 0);
    buf
}

#[test]
fn s6a_application_name() {
    // 3GPP TS 29.272, Section 7.1.8 — Application-ID 16777251 = "3GPP S6a/S6d"
    let data = build_header(FLAG_REQUEST | FLAG_PROXIABLE, 316, S6A_APP_ID, 1, 2);
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "application_id_name"),
        Some("3GPP S6a/S6d")
    );
}

#[test]
fn s6a_ulr_command_name() {
    // 3GPP TS 29.272, Section 7.2.2 — ULR (code=316, Request+Proxiable)
    let data = build_header(FLAG_REQUEST | FLAG_PROXIABLE, 316, S6A_APP_ID, 1, 2);
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    assert_eq!(
        buf.resolve_display_name(layer, "command_code_name"),
        Some("Update-Location-Request")
    );
}

#[test]
fn s6a_vendor_avp_name_resolution() {
    // 3GPP TS 29.272, Section 7.3 — Visited-PLMN-Id (1407, OctetString)
    let plmn = b"\x09\xF1\x07"; // MCC=901, MNC=70
    let mut avp_bytes = build_3gpp_avp(1407, plmn);
    // Also add ULR-Flags (1405, Unsigned32)
    avp_bytes.extend(build_3gpp_avp(1405, &0x00000003u32.to_be_bytes()));

    let data = build_s6a_message(FLAG_REQUEST | FLAG_PROXIABLE, 316, S6A_APP_ID, &avp_bytes);
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    // Visited-PLMN-Id
    assert_eq!(
        get_avp_field(&buf, layer, 0, "name"),
        Some(FieldValue::Str("Visited-PLMN-Id"))
    );
    assert_eq!(
        get_avp_field(&buf, layer, 0, "value"),
        Some(FieldValue::Bytes(plmn))
    );
    // ULR-Flags
    assert_eq!(
        get_avp_field(&buf, layer, 1, "name"),
        Some(FieldValue::Str("ULR-Flags"))
    );
    assert_eq!(
        get_avp_field(&buf, layer, 1, "value"),
        Some(FieldValue::U32(3))
    );
}

#[test]
fn s6a_experimental_result_code() {
    // 3GPP TS 29.272, Section 7.4 — Experimental-Result-Code in an Experimental-Result grouped AVP
    // Experimental-Result (297, Grouped) contains:
    //   - Vendor-Id (266, Unsigned32) = 10415
    //   - Experimental-Result-Code (298, Unsigned32) = 5420
    let mut inner_avps = build_base_avp(266, &10415u32.to_be_bytes());
    inner_avps.extend(build_base_avp(298, &5420u32.to_be_bytes()));
    let exp_result_avp = build_base_avp(297, &inner_avps);

    let data = build_s6a_message(FLAG_PROXIABLE, 316, S6A_APP_ID, &exp_result_avp);
    let mut buf = DissectBuffer::new();
    DiameterDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("Diameter").unwrap();
    // Outer AVP should be Experimental-Result (297)
    assert_eq!(
        get_avp_field(&buf, layer, 0, "name"),
        Some(FieldValue::Str("Experimental-Result"))
    );
    // The Experimental-Result is a Grouped AVP containing children
    let avps_field = buf.field_by_name(layer, "avps").unwrap();
    let FieldValue::Array(ref arr_range) = avps_field.value else {
        panic!("expected Array")
    };
    let arr = buf.nested_fields(arr_range);
    let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
    let FieldValue::Object(ref obj_range) = objects[0].value else {
        panic!("expected Object")
    };
    let exp_fields = buf.nested_fields(obj_range);
    let value_field = exp_fields.iter().find(|f| f.name() == "value").unwrap();
    let FieldValue::Array(ref children_range) = value_field.value else {
        panic!("expected Array")
    };
    let children = buf.nested_fields(children_range);
    // Find the Experimental-Result-Code child (second Object in children)
    let child_objects: Vec<_> = children.iter().filter(|f| f.value.is_object()).collect();
    let FieldValue::Object(ref erc_range) = child_objects[1].value else {
        panic!("expected Object")
    };
    assert_eq!(
        buf.resolve_nested_display_name(erc_range, "value_name"),
        Some("DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION")
    );
}
