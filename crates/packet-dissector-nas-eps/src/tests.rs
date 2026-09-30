//! # 3GPP TS 24.301 (EPS NAS) Coverage
//!
//! | Section       | Description                                  | Test                                   |
//! |---------------|----------------------------------------------|----------------------------------------|
//! | 9.1, 8.2.4    | Plain EMM: Attach request                    | attach_request_with_esm_container      |
//! | 9.9.3.15      | ESM message container decoded as ESM         | attach_request_with_esm_container      |
//! | 9.1, 8.3.6    | Plain ESM: Activate default bearer request   | activate_default_bearer_request        |
//! | 9.1, 9.3.1    | Integrity protected (type 1, 3)              | integrity_protected_decodes_inner      |
//! | 4.4.5, 9.3.1  | Ciphered (type 2, 4) kept opaque             | ciphered_not_decoded                   |
//! | 4.4.5, 9.3.1  | Partially ciphered: container not decoded    | partially_ciphered_container_raw       |
//! | 9.1, 9.3.1    | EMM TRANSPORT: data container ciphered       | emm_transport_ciphered                 |
//! | 8.2.25        | SERVICE REQUEST header (1100..1111)          | service_request                        |
//! | 9.3.1         | Reserved security header type                | reserved_security_header_type          |
//! | 9.1           | Inner message must be plain                  | nested_security_protected_not_decoded  |
//! | 9.1           | Security protected without payload           | security_protected_without_payload     |
//! | 8.2.11        | DETACH REQUEST layouts                       | detach_request_both_directions         |
//! | 7.4           | Unknown message type body kept raw           | unknown_message_type_undecoded         |
//! | 7.5           | Missing mandatory IE                         | missing_mandatory_ie                   |
//! | 7.6 / 24.007 11.2.4 | Unknown IEIs (TV1, TLV, TLV-E) skipped  | unknown_optional_ieis                  |
//! | 24.007 11.2.4 | Truncated optional IE                        | truncated_optional_ie                  |
//! | 9.2           | Unknown protocol discriminator               | dissect_errors                         |
//! | 9.1           | Header too short                             | dissect_errors, push_nas_pdu_rejects   |
//! | 9.9.3.12      | EPS mobile identity (IMSI, GUTI, IMEI)       | eps_mobile_identity                    |
//! | 9.9.2.3       | Mobile identity (TMSI, IMEISV, none)         | mobile_identity                        |
//! | 9.9.3.32/33   | TAI and TAI list (types 0, 1, 2)             | tai_and_tai_list                       |
//! | 9.9.2.2       | Location area identification                 | tai_and_tai_list                       |
//! | 9.9.3.23      | NAS security algorithms                      | security_mode_command                  |
//! | 9.9.3.36      | UE security capability                       | security_mode_command                  |
//! | 9.9.3.34      | UE network capability                        | attach_request_with_esm_container      |
//! | 9.9.4.9       | PDN address (IPv4, IPv6, IPv4v6, non IP)     | pdn_address_variants                   |
//! | 9.9.4.3       | EPS QoS                                      | activate_default_bearer_request        |
//! | 9.9.3.16      | GPRS timer                                   | attach_accept                          |
//! | 9.9.3.x       | Half-octet IEs                               | half_octet_values                      |

use super::*;
use packet_dissector_core::field::{Field, FormatContext};

fn dissect(data: &[u8]) -> DissectBuffer<'_> {
    let mut buf = DissectBuffer::new();
    NasEpsDissector.dissect(data, &mut buf, 0).unwrap();
    buf
}

fn top<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Option<&'a FieldValue<'pkt>> {
    let layer = &buf.layers()[0];
    buf.field_by_name(layer, name).map(|f| &f.value)
}

/// All `ie` objects anywhere in the buffer, as (name, children).
fn ies<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<(&'a str, &'a [Field<'pkt>])> {
    buf.fields()
        .iter()
        .filter_map(|f| match (f.name(), &f.value) {
            ("ie", FieldValue::Object(r)) => {
                let children = buf.nested_fields(r);
                let name = children.iter().find_map(|c| match (c.name(), &c.value) {
                    ("name", FieldValue::Str(s)) => Some(*s),
                    _ => None,
                })?;
                Some((name, children))
            }
            _ => None,
        })
        .collect()
}

fn ie<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> &'a [Field<'pkt>] {
    ies(buf)
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("IE {name} missing"))
        .1
}

fn get<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> &'a FieldValue<'pkt> {
    &fields
        .iter()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| panic!("field {name} missing"))
        .value
}

fn has(fields: &[Field<'_>], name: &str) -> bool {
    fields.iter().any(|f| f.name() == name)
}

/// Run a field's format function and return the output.
fn formatted(field: &Field<'_>) -> String {
    let ctx = FormatContext {
        packet_data: &[],
        scratch: &[],
        layer_range: 0..0,
        field_range: 0..0,
    };
    let mut out = Vec::new();
    (field.descriptor.format_fn.unwrap())(&field.value, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn field<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> &'a Field<'pkt> {
    fields.iter().find(|f| f.name() == name).unwrap()
}

const PDN_CONNECTIVITY_REQUEST: &[u8] = &[
    0x02, 0x01, 0xD0, // ESM, EBI 0, PTI 1, PDN connectivity request
    0x31, // PDN type IPv4v6 (bits 5-8), request type initial (bits 1-4)
    0x28, 0x04, 0x03, b'a', b'p', b'n', // APN
];

fn attach_request() -> Vec<u8> {
    let mut v = vec![
        0x07, 0x41, // plain EMM, Attach request
        0x71, // NAS KSI 7 (bits 5-8), EPS attach type 1 (bits 1-4)
        0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, // IMSI 001010123456789
        0x04, 0xE0, 0xE0, 0xC0, 0x40, // UE network capability
    ];
    v.extend_from_slice(&(PDN_CONNECTIVITY_REQUEST.len() as u16).to_be_bytes());
    v.extend_from_slice(PDN_CONNECTIVITY_REQUEST);
    v.extend_from_slice(&[0x52, 0x00, 0xF1, 0x10, 0x00, 0x01]); // Last visited TAI
    v.push(0x91); // TMSI status (TV1, IEI 9)
    v
}

#[test]
fn attach_request_with_esm_container() {
    let data = attach_request();
    let buf = dissect(&data);
    let layer = &buf.layers()[0];
    assert_eq!(layer.name, "NAS-EPS");
    assert_eq!(top(&buf, "security_header_type"), Some(&FieldValue::U8(0)));
    assert_eq!(
        top(&buf, "protocol_discriminator"),
        Some(&FieldValue::U8(7))
    );
    assert_eq!(top(&buf, "message_type"), Some(&FieldValue::U8(0x41)));
    assert_eq!(
        buf.resolve_display_name(layer, "message_type_name"),
        Some("Attach request")
    );
    assert_eq!(
        buf.resolve_display_name(layer, "protocol_discriminator_name"),
        Some("EPS mobility management messages")
    );
    assert_eq!(
        buf.resolve_display_name(layer, "security_header_type_name"),
        Some("Plain NAS message, not security protected")
    );

    let attach_type = ie(&buf, "EPS attach type");
    assert_eq!(get(attach_type, "eps_attach_type"), &FieldValue::U8(1));
    let ksi = ie(&buf, "NAS key set identifier");
    assert_eq!(get(ksi, "tsc"), &FieldValue::U8(0));
    assert_eq!(get(ksi, "nas_key_set_identifier"), &FieldValue::U8(7));

    let id = ie(&buf, "EPS mobile identity");
    assert_eq!(get(id, "length"), &FieldValue::U8(8));
    assert_eq!(get(id, "type_of_identity"), &FieldValue::U8(1));
    assert_eq!(get(id, "odd_even_indication"), &FieldValue::U8(1));
    assert_eq!(
        formatted(field(id, "identity_digits")),
        "\"001010123456789\""
    );

    let uenc = ie(&buf, "UE network capability");
    assert_eq!(get(uenc, "eea"), &FieldValue::U8(0xE0));
    assert_eq!(get(uenc, "eia"), &FieldValue::U8(0xE0));
    assert_eq!(get(uenc, "uea"), &FieldValue::U8(0xC0));
    assert_eq!(get(uenc, "uia"), &FieldValue::U8(0x40));
    assert!(!has(uenc, "additional_octets"));

    let container = ie(&buf, "ESM message container");
    assert_eq!(get(container, "length"), &FieldValue::U16(10));
    let FieldValue::Object(esm) = get(container, "esm_message") else {
        panic!("no nested ESM message")
    };
    let esm_fields = buf.nested_fields(esm);
    assert_eq!(
        get(esm_fields, "protocol_discriminator"),
        &FieldValue::U8(2)
    );
    assert_eq!(get(esm_fields, "eps_bearer_identity"), &FieldValue::U8(0));
    assert_eq!(
        get(esm_fields, "procedure_transaction_identity"),
        &FieldValue::U8(1)
    );
    assert_eq!(get(esm_fields, "message_type"), &FieldValue::U8(0xD0));
    assert_eq!(
        buf.resolve_nested_display_name(esm, "message_type_name"),
        Some("PDN connectivity request")
    );
    assert_eq!(
        get(ie(&buf, "Request type"), "request_type"),
        &FieldValue::U8(1)
    );
    assert_eq!(get(ie(&buf, "PDN type"), "pdn_type"), &FieldValue::U8(3));
    let apn = ie(&buf, "Access point name");
    assert_eq!(get(apn, "iei"), &FieldValue::U8(0x28));
    assert_eq!(formatted(field(apn, "apn")), "\"apn\"");

    let tai = ie(&buf, "Last visited registered TAI");
    assert_eq!(get(tai, "tac"), &FieldValue::U16(1));
    assert_eq!(formatted(field(tai, "mcc")), "\"001\"");
    assert_eq!(formatted(field(tai, "mnc")), "\"01\"");

    let tmsi_status = ie(&buf, "TMSI status");
    assert_eq!(get(tmsi_status, "iei"), &FieldValue::U8(9));
    assert_eq!(get(tmsi_status, "value"), &FieldValue::U8(1));
}

#[test]
fn attach_accept() {
    let esm = [0x52, 0x01, 0xC2]; // Activate default EPS bearer context accept
    let mut data = vec![
        0x07, 0x42, // Attach accept
        0x01, // EPS attach result: EPS only (bits 1-4), spare
        0x29, // T3412: unit 1 minute, value 9
        0x06, 0x00, 0x00, 0xF1, 0x10, 0x00, 0x01, // TAI list type 0, 1 element
        0x00, 0x03,
    ];
    data.extend_from_slice(&esm);
    data.extend_from_slice(&[
        0x50, 0x0B, 0xF6, 0x00, 0xF1, 0x10, 0x80, 0x01, 0x02, 0xC0, 0x00, 0x00, 0x01, // GUTI
        0x53, 0x12, // EMM cause 18
        0x17, 0xE0, // T3402 deactivated
    ]);
    let buf = dissect(&data);
    assert_eq!(
        get(ie(&buf, "EPS attach result"), "eps_attach_result"),
        &FieldValue::U8(1)
    );
    let t3412 = ie(&buf, "T3412 value");
    assert_eq!(get(t3412, "timer_unit"), &FieldValue::U8(1));
    assert_eq!(get(t3412, "timer_value"), &FieldValue::U8(9));
    let t3402 = ie(&buf, "T3402 value");
    assert_eq!(get(t3402, "timer_unit"), &FieldValue::U8(7));
    let guti = ie(&buf, "GUTI");
    assert_eq!(get(guti, "type_of_identity"), &FieldValue::U8(6));
    assert_eq!(get(guti, "mme_group_id"), &FieldValue::U16(0x8001));
    assert_eq!(get(guti, "mme_code"), &FieldValue::U8(2));
    assert_eq!(get(guti, "m_tmsi"), &FieldValue::U32(0xC000_0001));
    assert_eq!(get(ie(&buf, "EMM cause"), "cause"), &FieldValue::U8(18));
    assert!(ies(&buf).iter().any(|(n, _)| *n == "ESM message container"));
}

#[test]
fn activate_default_bearer_request() {
    let data = [
        0x52, 0x01, 0xC1, // EBI 5, PTI 1, Activate default EPS bearer context request
        0x01, 0x09, // EPS QoS: QCI 9
        0x04, 0x03, b'a', b'p', b'n', // APN
        0x05, 0x01, 10, 0, 0, 1, // PDN address IPv4
        0x5E, 0x02, 0xFE, 0xFE, // APN-AMBR (raw)
        0x58, 0x32, // ESM cause 50
    ];
    let buf = dissect(&data);
    assert_eq!(top(&buf, "eps_bearer_identity"), Some(&FieldValue::U8(5)));
    assert!(top(&buf, "security_header_type").is_none());
    let qos = ie(&buf, "EPS QoS");
    assert_eq!(get(qos, "qci"), &FieldValue::U8(9));
    assert!(!has(qos, "bit_rates"));
    let pdn = ie(&buf, "PDN address");
    assert_eq!(get(pdn, "pdn_type"), &FieldValue::U8(1));
    assert_eq!(
        get(pdn, "ipv4_address"),
        &FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
    assert_eq!(
        get(ie(&buf, "APN-AMBR"), "value"),
        &FieldValue::Bytes(&[0xFE, 0xFE])
    );
    let cause = ie(&buf, "ESM cause");
    assert_eq!(get(cause, "cause"), &FieldValue::U8(50));
    let layer = &buf.layers()[0];
    assert_eq!(
        buf.resolve_display_name(layer, "message_type_name"),
        Some("Activate default EPS bearer context request")
    );
}

#[test]
fn pdn_address_variants() {
    let body = |pdn: &[u8]| {
        let mut d = vec![0x52, 0x01, 0xC1, 0x01, 0x09, 0x01, 0x00];
        d.push(pdn.len() as u8);
        d.extend_from_slice(pdn);
        d
    };
    let v6 = body(&[0x02, 1, 2, 3, 4, 5, 6, 7, 8]);
    let buf = dissect(&v6);
    let pdn = ie(&buf, "PDN address");
    assert_eq!(
        get(pdn, "ipv6_interface_identifier"),
        &FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8])
    );
    assert!(!has(pdn, "ipv4_address"));

    let both = body(&[0x03, 1, 2, 3, 4, 5, 6, 7, 8, 192, 0, 2, 1]);
    let buf = dissect(&both);
    let pdn = ie(&buf, "PDN address");
    assert!(has(pdn, "ipv6_interface_identifier"));
    assert_eq!(
        get(pdn, "ipv4_address"),
        &FieldValue::Ipv4Addr([192, 0, 2, 1])
    );

    let non_ip = body(&[0x05, 0, 0, 0, 0]);
    let buf = dissect(&non_ip);
    let pdn = ie(&buf, "PDN address");
    assert_eq!(get(pdn, "pdn_type"), &FieldValue::U8(5));
    assert!(!has(pdn, "ipv4_address"));

    // Wrong length for the PDN type, and an empty value: kept raw.
    let bad = body(&[0x01, 1, 2]);
    let buf = dissect(&bad);
    assert_eq!(
        get(ie(&buf, "PDN address"), "value"),
        &FieldValue::Bytes(&[0x01, 1, 2])
    );
    let empty = body(&[]);
    let buf = dissect(&empty);
    assert_eq!(
        get(ie(&buf, "PDN address"), "value"),
        &FieldValue::Bytes(&[])
    );
}

#[test]
fn integrity_protected_decodes_inner() {
    for sht in [1u8, 3] {
        let mut data = vec![(sht << 4) | 7, 0xAA, 0xBB, 0xCC, 0xDD, 0x05];
        data.extend_from_slice(&attach_request());
        let buf = dissect(&data);
        assert_eq!(
            top(&buf, "message_authentication_code"),
            Some(&FieldValue::U32(0xAABB_CCDD))
        );
        assert_eq!(top(&buf, "sequence_number"), Some(&FieldValue::U8(5)));
        let Some(FieldValue::Object(inner)) = top(&buf, "plain_nas_message") else {
            panic!("no plain NAS message")
        };
        let inner = buf.nested_fields(inner);
        assert_eq!(get(inner, "message_type"), &FieldValue::U8(0x41));
        // The ESM message container is decoded inside the inner message.
        assert!(has(ie(&buf, "ESM message container"), "esm_message"));
    }
    // An ESM message inside a security protected message.
    let mut data = vec![0x17, 0, 0, 0, 0, 0];
    data.extend_from_slice(PDN_CONNECTIVITY_REQUEST);
    let buf = dissect(&data);
    let Some(FieldValue::Object(inner)) = top(&buf, "plain_nas_message") else {
        panic!("no plain NAS message")
    };
    assert_eq!(
        get(buf.nested_fields(inner), "protocol_discriminator"),
        &FieldValue::U8(2)
    );
}

#[test]
fn ciphered_not_decoded() {
    for sht in [2u8, 4] {
        let mut data = vec![(sht << 4) | 7, 0, 0, 0, 1, 0x02];
        data.extend_from_slice(&attach_request());
        let buf = dissect(&data);
        assert_eq!(
            top(&buf, "ciphered_nas_message"),
            Some(&FieldValue::Bytes(&data[6..]))
        );
        assert!(top(&buf, "plain_nas_message").is_none());
        assert!(ies(&buf).is_empty());
    }
}

#[test]
fn partially_ciphered_container_raw() {
    // TS 24.301, Section 4.4.5 — CONTROL PLANE SERVICE REQUEST with a
    // partially ciphered ESM message container.
    let mut data = vec![0x57, 0, 0, 0, 0, 0x01];
    data.extend_from_slice(&[0x07, 0x4D, 0x71, 0x78, 0x00, 0x03]);
    data.extend_from_slice(&PDN_CONNECTIVITY_REQUEST[..3]);
    let buf = dissect(&data);
    let container = ie(&buf, "ESM message container");
    assert!(!has(container, "esm_message"));
    assert_eq!(
        get(container, "value"),
        &FieldValue::Bytes(&PDN_CONNECTIVITY_REQUEST[..3])
    );
}

#[test]
fn emm_transport_ciphered() {
    let data = [0xB7, 1, 2, 3, 4, 9, 0xDE, 0xAD];
    let buf = dissect(&data);
    assert_eq!(top(&buf, "security_header_type"), Some(&FieldValue::U8(11)));
    assert_eq!(
        top(&buf, "ciphered_nas_message"),
        Some(&FieldValue::Bytes(&[0xDE, 0xAD]))
    );
}

#[test]
fn service_request() {
    for sht in [0xC7u8, 0xD7, 0xF7] {
        let data = [sht, 0x45, 0x12, 0x34];
        let buf = dissect(&data);
        assert_eq!(
            top(&buf, "nas_key_set_identifier"),
            Some(&FieldValue::U8(2))
        );
        assert_eq!(top(&buf, "sequence_number"), Some(&FieldValue::U8(5)));
        assert_eq!(top(&buf, "short_mac"), Some(&FieldValue::U16(0x1234)));
        assert!(top(&buf, "message_type").is_none());
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "security_header_type_name"),
            Some("Security header for the SERVICE REQUEST message")
        );
    }
}

#[test]
fn reserved_security_header_type() {
    let data = [0x67, 0x01, 0x02];
    let buf = dissect(&data);
    assert_eq!(
        top(&buf, "raw_nas_message"),
        Some(&FieldValue::Bytes(&[0x01, 0x02]))
    );
    let buf = dissect(&[0x87]);
    assert!(top(&buf, "raw_nas_message").is_none());
}

#[test]
fn nested_security_protected_not_decoded() {
    let mut data = vec![0x17, 0, 0, 0, 0, 0];
    data.extend_from_slice(&[0x17, 0, 0, 0, 0, 0, 0x07, 0x43]);
    let buf = dissect(&data);
    let Some(FieldValue::Object(inner)) = top(&buf, "plain_nas_message") else {
        panic!("no plain NAS message")
    };
    assert_eq!(
        get(buf.nested_fields(inner), "raw_nas_message"),
        &FieldValue::Bytes(&data[6..])
    );
}

#[test]
fn security_protected_without_payload() {
    let buf = dissect(&[0x27, 0, 0, 0, 0, 1]);
    assert!(top(&buf, "ciphered_nas_message").is_none());
    assert_eq!(top(&buf, "sequence_number"), Some(&FieldValue::U8(1)));
}

#[test]
fn detach_request_both_directions() {
    // UE originating: switch off, EPS detach; KSI 1; GUTI.
    let orig = [
        0x07, 0x45, 0x19, 0x0B, 0xF6, 0x00, 0xF1, 0x10, 0x80, 0x01, 0x02, 0xC0, 0x00, 0x00, 0x01,
    ];
    let buf = dissect(&orig);
    let dt = ie(&buf, "Detach type");
    assert_eq!(get(dt, "switch_off"), &FieldValue::U8(1));
    assert_eq!(get(dt, "type_of_detach"), &FieldValue::U8(1));
    assert_eq!(
        get(ie(&buf, "NAS key set identifier"), "nas_key_set_identifier"),
        &FieldValue::U8(1)
    );
    assert!(has(ie(&buf, "EPS mobile identity"), "m_tmsi"));

    // UE terminated: re-attach not required, EMM cause 7.
    let term = [0x07, 0x45, 0x02, 0x53, 0x07];
    let buf = dissect(&term);
    assert_eq!(
        get(ie(&buf, "Detach type"), "type_of_detach"),
        &FieldValue::U8(2)
    );
    assert_eq!(get(ie(&buf, "EMM cause"), "cause"), &FieldValue::U8(7));
}

#[test]
fn unknown_message_type_undecoded() {
    let buf = dissect(&[0x07, 0x47, 0x01, 0x02]);
    assert_eq!(
        top(&buf, "undecoded_octets"),
        Some(&FieldValue::Bytes(&[0x01, 0x02]))
    );
    assert_eq!(
        buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
        None
    );
    let buf = dissect(&[0x02, 0x00, 0xFF, 0x09]);
    assert_eq!(
        top(&buf, "undecoded_octets"),
        Some(&FieldValue::Bytes(&[0x09]))
    );
    // Empty body of a message without IEs: nothing is pushed.
    let buf = dissect(&[0x07, 0x47]);
    assert!(top(&buf, "undecoded_octets").is_none());
    let buf = dissect(&[0x07, 0x43]);
    assert!(top(&buf, "information_elements").is_none());
    assert_eq!(
        top(&buf, "missing_mandatory_ie"),
        Some(&FieldValue::Str("ESM message container"))
    );
}

#[test]
fn missing_mandatory_ie() {
    // Attach request whose EPS mobile identity length runs past the end.
    let data = [0x07, 0x41, 0x71, 0x08, 0x09];
    let buf = dissect(&data);
    assert_eq!(
        top(&buf, "missing_mandatory_ie"),
        Some(&FieldValue::Str("EPS mobile identity"))
    );
    assert_eq!(
        top(&buf, "undecoded_octets"),
        Some(&FieldValue::Bytes(&[0x08, 0x09]))
    );
    // The half-octet IEs before it were decoded.
    assert!(ies(&buf).iter().any(|(n, _)| *n == "EPS attach type"));
    // Missing half-octet IE and missing LV-E length.
    let buf = dissect(&[0x07, 0x41]);
    assert_eq!(
        top(&buf, "missing_mandatory_ie"),
        Some(&FieldValue::Str("EPS attach type"))
    );
    let buf = dissect(&[0x07, 0x43, 0x00]);
    assert_eq!(
        top(&buf, "missing_mandatory_ie"),
        Some(&FieldValue::Str("ESM message container"))
    );
    // Missing LV length octet.
    let buf = dissect(&[0x07, 0x41, 0x71]);
    assert_eq!(
        top(&buf, "missing_mandatory_ie"),
        Some(&FieldValue::Str("EPS mobile identity"))
    );
}

#[test]
fn unknown_optional_ieis() {
    let data = [
        0x07, 0x61, // EMM information
        0xA5, // unknown TV1 (IEI A)
        0x3F, 0x01, 0xAA, // unknown TLV
        0x7E, 0x00, 0x01, 0xBB, // unknown TLV-E
        0x46, 0x23, // Local time zone (TV 2)
    ];
    let buf = dissect(&data);
    let all = ies(&buf);
    assert_eq!(all.len(), 4);
    assert_eq!(all[0].0, "Unknown");
    assert_eq!(get(all[0].1, "iei"), &FieldValue::U8(0xA));
    assert_eq!(get(all[0].1, "value"), &FieldValue::U8(5));
    assert_eq!(get(all[1].1, "value"), &FieldValue::Bytes(&[0xAA]));
    assert_eq!(get(all[2].1, "length"), &FieldValue::U16(1));
    assert_eq!(get(all[2].1, "value"), &FieldValue::Bytes(&[0xBB]));
    assert_eq!(all[3].0, "Local time zone");
    assert!(!has(all[3].1, "length"));
}

#[test]
fn truncated_optional_ie() {
    for data in [
        &[0x07, 0x61, 0x43, 0x05, 0x01][..],
        &[0x07, 0x61, 0x43][..],
        &[0x07, 0x61, 0x7E, 0x00][..],
    ] {
        let buf = dissect(data);
        assert_eq!(
            top(&buf, "undecoded_octets"),
            Some(&FieldValue::Bytes(&data[2..]))
        );
        assert!(top(&buf, "missing_mandatory_ie").is_none());
        assert!(top(&buf, "information_elements").is_none());
    }
}

#[test]
fn eps_mobile_identity() {
    let with_id = |id: &[u8]| {
        let mut d = vec![0x07, 0x45, 0x01, id.len() as u8];
        d.extend_from_slice(id);
        d
    };
    // IMEI 3534...: type 3, odd.
    let imei = with_id(&[0x3B, 0x55, 0x40, 0x03, 0x00, 0x00, 0x00, 0x10]);
    let buf = dissect(&imei);
    let id = ie(&buf, "EPS mobile identity");
    assert_eq!(get(id, "type_of_identity"), &FieldValue::U8(3));
    assert_eq!(
        formatted(field(id, "identity_digits")),
        "\"355043000000001\""
    );
    // Reserved type and a GUTI of the wrong length: raw.
    for bad in [&[0xF2, 0x00][..], &[0xF6, 0x00, 0xF1][..]] {
        let data = with_id(bad);
        let buf = dissect(&data);
        assert_eq!(
            get(ie(&buf, "EPS mobile identity"), "value"),
            &FieldValue::Bytes(bad)
        );
    }
    // Zero length.
    let data = with_id(&[]);
    let buf = dissect(&data);
    assert_eq!(
        get(ie(&buf, "EPS mobile identity"), "value"),
        &FieldValue::Bytes(&[])
    );
}

#[test]
fn mobile_identity() {
    let identity_response = |id: &[u8]| {
        let mut d = vec![0x07, 0x56, id.len() as u8];
        d.extend_from_slice(id);
        d
    };
    let tmsi = identity_response(&[0xF4, 0x12, 0x34, 0x56, 0x78]);
    let buf = dissect(&tmsi);
    let id = ie(&buf, "Mobile identity");
    assert_eq!(get(id, "type_of_identity"), &FieldValue::U8(4));
    assert_eq!(get(id, "tmsi"), &FieldValue::U32(0x1234_5678));
    let imeisv = identity_response(&[0x33, 0x55, 0x40, 0x03, 0x00, 0x00, 0x00, 0x10, 0xF2]);
    let buf = dissect(&imeisv);
    let id = ie(&buf, "Mobile identity");
    assert_eq!(get(id, "type_of_identity"), &FieldValue::U8(3));
    assert_eq!(get(id, "odd_even_indication"), &FieldValue::U8(0));
    assert_eq!(
        formatted(field(id, "identity_digits")),
        "\"3550430000000012\""
    );
    let none = identity_response(&[0xF0]);
    let buf = dissect(&none);
    assert_eq!(
        get(ie(&buf, "Mobile identity"), "type_of_identity"),
        &FieldValue::U8(0)
    );
    for bad in [&[0xF4, 0x12][..], &[0xF5, 0x00][..], &[][..]] {
        let data = identity_response(bad);
        let buf = dissect(&data);
        assert_eq!(
            get(ie(&buf, "Mobile identity"), "value"),
            &FieldValue::Bytes(bad)
        );
    }
}

#[test]
fn tai_and_tai_list() {
    let data = [
        0x07, 0x49, 0x00, // TAU accept, TA updated
        0x54, 0x14, // TAI list, 20 octets
        0x01, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x00, 0x02, // type 0, 2 TACs
        0x22, 0x00, 0xF1, 0x10, 0x00, 0x05, // type 1, 3 consecutive TACs
        0x40, 0x00, 0xF1, 0x10, 0x00, 0x09, // type 2, 1 TAI
        0x13, 0x00, 0xF1, 0x10, 0x12, 0x34, // LAI
    ];
    let buf = dissect(&data);
    let list = ie(&buf, "TAI list");
    let FieldValue::Array(r) = get(list, "partial_tai_lists") else {
        panic!("not an array")
    };
    let nested = buf.nested_fields(r);
    let types: Vec<_> = nested
        .iter()
        .filter(|f| f.name() == "type_of_list")
        .filter_map(|f| f.value.as_u8())
        .collect();
    assert_eq!(types, vec![0, 1, 2]);
    let tacs: Vec<_> = nested
        .iter()
        .filter(|f| f.name() == "tac")
        .filter_map(|f| f.value.as_u16())
        .collect();
    assert_eq!(tacs, vec![1, 2, 5, 9]);
    let counts: Vec<_> = nested
        .iter()
        .filter(|f| f.name() == "number_of_elements")
        .filter_map(|f| f.value.as_u8())
        .collect();
    assert_eq!(counts, vec![2, 3, 1]);
    let lai = ie(&buf, "Location area identification");
    assert_eq!(get(lai, "lac"), &FieldValue::U16(0x1234));

    // Reserved type of list, a list running past the value, a bad TAI and a
    // bad LAI length: raw.
    for bad in [
        &[0x07, 0x49, 0x00, 0x54, 0x01, 0x60][..],
        &[0x07, 0x49, 0x00, 0x54, 0x02, 0x01, 0x00][..],
    ] {
        let buf = dissect(bad);
        assert!(has(ie(&buf, "TAI list"), "value"));
    }
    let bad_lai = [0x07, 0x49, 0x00, 0x13, 0x00, 0xF1, 0x10, 0x12, 0x34, 0x00];
    let buf = dissect(&bad_lai);
    assert_eq!(ies(&buf).len(), 2);
    let bad_tai = [0x07, 0x41, 0x71, 0x01, 0xF1, 0x02, 0xE0, 0xE0, 0x00, 0x00];
    let _ = dissect(&bad_tai);
}

#[test]
fn security_mode_command() {
    let data = [
        0x07, 0x5D, // Security mode command
        0x02, // EEA0, 128-EIA2
        0x00, // KSI 0, spare
        0x05, 0xE0, 0xE0, 0x00, 0x00, 0x80, // Replayed UE security capabilities
        0xC1, // IMEISV request
    ];
    let buf = dissect(&data);
    let algs = ie(&buf, "Selected NAS security algorithms");
    assert_eq!(get(algs, "ciphering_algorithm"), &FieldValue::U8(0));
    assert_eq!(get(algs, "integrity_algorithm"), &FieldValue::U8(2));
    let cap = ie(&buf, "Replayed UE security capabilities");
    assert_eq!(get(cap, "eea"), &FieldValue::U8(0xE0));
    assert_eq!(get(cap, "gea"), &FieldValue::U8(0));
    assert!(!has(cap, "additional_octets"));
    assert_eq!(get(ie(&buf, "IMEISV request"), "value"), &FieldValue::U8(1));

    // A too-short capability and a bad algorithms length.
    let short = [0x07, 0x5D, 0x02, 0x00, 0x01, 0xE0];
    let buf = dissect(&short);
    assert!(has(ie(&buf, "Replayed UE security capabilities"), "value"));

    // UE network capability with feature octets.
    let mut tau = vec![
        0x07, 0x48, 0x00, 0x0B, 0xF6, 0, 0xF1, 0x10, 0, 1, 2, 0, 0, 0, 1,
    ];
    tau.extend_from_slice(&[0x58, 0x06, 0xE0, 0xE0, 0, 0, 0x11, 0x22]);
    let buf = dissect(&tau);
    let uenc = ie(&buf, "UE network capability");
    assert_eq!(
        get(uenc, "additional_octets"),
        &FieldValue::Bytes(&[0x11, 0x22])
    );
}

#[test]
fn half_octet_values() {
    // TAU request: active flag + update type, KSI.
    let tau = [
        0x07, 0x48, 0x09, 0x0B, 0xF6, 0, 0xF1, 0x10, 0, 1, 2, 0, 0, 0, 1,
    ];
    let buf = dissect(&tau);
    let ut = ie(&buf, "EPS update type");
    assert_eq!(get(ut, "active_flag"), &FieldValue::U8(1));
    assert_eq!(get(ut, "eps_update_type"), &FieldValue::U8(1));
    // TAU accept result.
    let buf = dissect(&[0x07, 0x49, 0x04]);
    assert_eq!(
        get(ie(&buf, "EPS update result"), "eps_update_result"),
        &FieldValue::U8(4)
    );
    // Extended service request: service type 8, KSI 1.
    let esr = [0x07, 0x4C, 0x18, 0x05, 0xF4, 0, 0, 0, 1];
    let buf = dissect(&esr);
    assert_eq!(
        get(ie(&buf, "Service type"), "service_type"),
        &FieldValue::U8(8)
    );
    // Identity request: IMEISV.
    let buf = dissect(&[0x07, 0x55, 0x03]);
    assert_eq!(
        get(ie(&buf, "Identity type"), "identity_type"),
        &FieldValue::U8(3)
    );
    // PDN disconnect request: linked EBI 6.
    let buf = dissect(&[0x02, 0x02, 0xD2, 0x06]);
    assert_eq!(
        get(
            ie(&buf, "Linked EPS bearer identity"),
            "eps_bearer_identity"
        ),
        &FieldValue::U8(6)
    );
}

#[test]
fn dissect_errors() {
    let mut buf = DissectBuffer::new();
    assert!(matches!(
        NasEpsDissector.dissect(&[], &mut buf, 0),
        Err(PacketError::Truncated {
            expected: 1,
            actual: 0
        })
    ));
    assert!(matches!(
        NasEpsDissector.dissect(&[0x05, 0x00], &mut buf, 0),
        Err(PacketError::InvalidFieldValue {
            field: "protocol_discriminator",
            value: 5
        })
    ));
    for (data, expected) in [
        (&[0x07][..], 2),
        (&[0x02, 0x00][..], 3),
        (&[0x17, 0, 0, 0, 0][..], 6),
        (&[0xB7, 0, 0][..], 6),
        (&[0xC7, 0, 0][..], 4),
    ] {
        match NasEpsDissector.dissect(data, &mut buf, 0) {
            Err(PacketError::Truncated {
                expected: e,
                actual,
            }) => {
                assert_eq!((e, actual), (expected, data.len()));
            }
            other => panic!("{data:?}: {other:?}"),
        }
    }
    assert!(buf.layers().is_empty());
}

#[test]
fn push_nas_pdu_rejects() {
    let mut buf = DissectBuffer::new();
    assert!(!push_nas_pdu(&mut buf, &[], 0));
    assert!(!push_nas_pdu(&mut buf, &[0x05, 0x00], 0));
    assert!(!push_nas_pdu(&mut buf, &[0x07], 0));
    assert!(buf.fields().is_empty());
    let data = attach_request();
    assert!(push_nas_pdu(&mut buf, &data, 10));
    assert_eq!(buf.fields()[0].range, 10..11);
}

#[test]
fn dissector_metadata() {
    let d = NasEpsDissector;
    assert_eq!(d.name(), "EPS NAS");
    assert_eq!(d.short_name(), "NAS-EPS");
    assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    assert_eq!(d.references().len(), 3);
    let names: Vec<_> = d.field_descriptors().iter().map(|f| f.name).collect();
    for n in [
        "security_header_type",
        "information_elements",
        "plain_nas_message",
    ] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    let res = d
        .dissect(&[0x07, 0x43, 0x00, 0x00], &mut DissectBuffer::new(), 0)
        .unwrap();
    assert_eq!(res.bytes_consumed, 4);
    assert_eq!(res.next, DispatchHint::End);
}
