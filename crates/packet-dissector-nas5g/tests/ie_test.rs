//! # 3GPP TS 24.501 (5G NAS) Information Element Coverage
//!
//! | Spec Section         | Description                                  | Test                                         |
//! |----------------------|----------------------------------------------|----------------------------------------------|
//! | 8.1                  | Half-octet IE order (first in bits 1-4)      | registration_request_suci_imsi               |
//! | 8.2.6, 9.11.3.4      | SUCI (IMSI, null scheme)                     | registration_request_suci_imsi               |
//! | 9.11.3.4             | SUCI (IMSI, ECIES scheme output)             | suci_ecies_scheme_output_is_hex              |
//! | 9.11.3.4             | SUCI (network specific identifier NAI)       | suci_nai                                     |
//! | 9.11.3.4             | 5G-GUTI                                      | registration_accept_ies                      |
//! | 9.11.3.4             | 5G-S-TMSI                                    | service_request_5g_s_tmsi                    |
//! | 9.11.3.4             | IMEISV                                       | security_mode_complete_imeisv                |
//! | 9.11.3.4             | IMEI, MAC address, EUI-64, no identity       | identity_response_other_identity_types       |
//! | 9.11.3.4             | Malformed identity kept as raw value         | malformed_ie_value_falls_back_to_raw         |
//! | 9.11.3.4             | No identity with extra octets kept raw       | no_identity_with_extra_octets_kept_raw       |
//! | 9.11.3.7, 9.11.3.32  | Registration type, ngKSI                     | registration_request_suci_imsi               |
//! | 9.11.3.32            | Non-current ngKSI (TV type 1)                | registration_request_optional_ies            |
//! | 9.11.3.54            | UE security capability                       | registration_request_optional_ies            |
//! | 9.11.3.37, 9.11.2.8  | NSSAI / S-NSSAI (all lengths)                | registration_accept_ies                      |
//! | 9.11.2.8             | S-NSSAI with reserved length                 | malformed_ie_value_falls_back_to_raw         |
//! | 9.11.3.8             | 5GS TAI (TV type 3)                          | registration_request_optional_ies            |
//! | 9.11.3.9             | TAI list (type of list 00, 01, 10)           | registration_accept_ies                      |
//! | 9.11.3.6             | 5GS registration result                      | registration_accept_ies                      |
//! | 9.11.3.2             | 5GMM cause                                   | registration_reject_cause                    |
//! | 9.11.3.10, .15, .16  | ABBA, AUTN, RAND                             | authentication_request                       |
//! | 9.11.3.17            | Authentication response parameter (RES*)     | authentication_response                      |
//! | 9.11.3.34            | NAS security algorithms                      | security_mode_command                        |
//! | 9.11.3.28            | IMEISV request (TV type 1, raw value)        | security_mode_command                        |
//! | 9.11.3.20            | De-registration type                         | deregistration_request                       |
//! | 9.11.3.50            | Service type                                 | service_request_5g_s_tmsi                    |
//! | 9.11.3.3             | 5GS identity type                            | identity_request                             |
//! | 9.11.3.39, .40, .41  | UL NAS transport, N1 SM container decoded    | ul_nas_transport_n1_sm                       |
//! | 9.11.3.47, 9.11.2.1B | Request type, DNN                            | ul_nas_transport_n1_sm                       |
//! | 9.11.3.39            | Non-N1 SM payload kept raw                   | dl_nas_transport_sms_payload_kept_raw        |
//! | 9.11.4.2             | 5GSM cause                                   | pdu_session_establishment_reject             |
//! | 9.11.4.7             | Integrity protection maximum data rate       | ul_nas_transport_n1_sm                       |
//! | 9.11.4.11, 9.11.4.16 | PDU session type, SSC mode                   | pdu_session_establishment_accept             |
//! | 9.11.4.13            | QoS rules                                    | pdu_session_establishment_accept             |
//! | 9.11.4.13            | QoS rule: delete packet filters              | qos_rules_delete_packet_filters              |
//! | 9.11.4.12            | QoS flow descriptions                        | pdu_session_establishment_accept             |
//! | 9.11.4.14            | Session-AMBR                                 | pdu_session_establishment_accept             |
//! | 9.11.4.10            | PDU address (IPv4, IPv6, IPv4v6 + SMF LLA)   | pdu_address_variants                         |
//! | TS 24.007 11.2.4     | Unknown IEIs skipped (type 1, TLV, TLV-E)    | unknown_optional_ies_are_skipped             |
//! | TS 24.007 11.2.4     | Truncated optional IE                        | truncated_optional_ie_reported               |
//! | 8.2.6                | Truncated mandatory IE                       | truncated_mandatory_ie_reported              |
//! | 8.2.10, 8.3.16       | Absent mandatory IE                          | absent_mandatory_ie_reported                 |
//! | 9.7                  | Message type without IE table                | unknown_message_type_body_kept_raw           |
//! | 4.4.5, 9.1.1         | IEs of integrity protected inner message     | integrity_protected_inner_message_ies        |
//! |                      | Dissector trait path decodes IEs             | dissector_decodes_ies                        |
//! |                      | Arbitrary bodies: no panic, ranges in bounds | arbitrary_bodies_never_panic                 |
//! | 9.11.3.39            | Field descriptor schema is acyclic           | field_descriptor_schema_is_acyclic           |

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::{Field, FieldDescriptor, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_nas5g::{Nas5gDissector, push_nas_pdu};

// ── Helpers ─────────────────────────────────────────────────────────────

/// Fields pushed by `push_nas_pdu` for `data` at offset 0.
fn dissect(data: &[u8]) -> DissectBuffer<'_> {
    let mut buf = DissectBuffer::new();
    assert!(push_nas_pdu(&mut buf, data, 0), "push_nas_pdu failed");
    buf
}

/// Top-level fields (those not nested in any container).
fn top_level<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<&'a Field<'pkt>> {
    let fields = buf.fields();
    let mut out = Vec::new();
    let mut i = 0;
    while i < fields.len() {
        out.push(&fields[i]);
        i = match &fields[i].value {
            FieldValue::Array(r) | FieldValue::Object(r) => r.end as usize,
            _ => i + 1,
        };
    }
    out
}

/// Direct children of a container field.
fn children<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, field: &Field<'pkt>) -> Vec<&'a Field<'pkt>> {
    let range = field
        .value
        .as_container_range()
        .unwrap_or_else(|| panic!("{} is not a container", field.name()));
    let nested = buf.nested_fields(range);
    let base = range.start as usize;
    let mut out = Vec::new();
    let mut i = 0;
    while i < nested.len() {
        out.push(&nested[i]);
        i = match &nested[i].value {
            FieldValue::Array(r) | FieldValue::Object(r) => r.end as usize - base,
            _ => i + 1,
        };
    }
    out
}

/// The field named `name` among `fields`.
fn get<'a, 'pkt>(fields: &[&'a Field<'pkt>], name: &str) -> &'a Field<'pkt> {
    fields
        .iter()
        .copied()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| {
            let names: Vec<_> = fields.iter().map(|f| f.name()).collect();
            panic!("no field {name} in {names:?}")
        })
}

/// Children of every IE object in `information_elements` of `fields`.
fn ies<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    fields: &[&'a Field<'pkt>],
) -> Vec<Vec<&'a Field<'pkt>>> {
    let list = get(fields, "information_elements");
    children(buf, list)
        .into_iter()
        .map(|ie| {
            assert_eq!(ie.name(), "ie");
            children(buf, ie)
        })
        .collect()
}

/// Names of the IEs in `information_elements` of `fields`.
fn ie_names<'pkt>(buf: &DissectBuffer<'pkt>, fields: &[&Field<'pkt>]) -> Vec<&'pkt str> {
    ies(buf, fields)
        .iter()
        .map(|ie| match get(ie, "name").value {
            FieldValue::Str(s) => s,
            ref v => panic!("IE name is {v:?}"),
        })
        .collect()
}

/// Children of the IE named `name` in `information_elements` of `fields`.
fn ie<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    fields: &[&'a Field<'pkt>],
    name: &str,
) -> Vec<&'a Field<'pkt>> {
    ies(buf, fields)
        .into_iter()
        .find(|ie| get(ie, "name").value == FieldValue::Str(name))
        .unwrap_or_else(|| panic!("no IE {name:?} in {:?}", ie_names(buf, fields)))
}

fn u8_of(fields: &[&Field<'_>], name: &str) -> u8 {
    get(fields, name)
        .value
        .as_u8()
        .unwrap_or_else(|| panic!("{name} is not U8"))
}

fn u16_of(fields: &[&Field<'_>], name: &str) -> u16 {
    get(fields, name)
        .value
        .as_u16()
        .unwrap_or_else(|| panic!("{name} is not U16"))
}

fn u32_of(fields: &[&Field<'_>], name: &str) -> u32 {
    get(fields, name)
        .value
        .as_u32()
        .unwrap_or_else(|| panic!("{name} is not U32"))
}

fn bytes_of<'pkt>(fields: &[&Field<'pkt>], name: &str) -> &'pkt [u8] {
    match get(fields, name).value {
        FieldValue::Bytes(b) => b,
        ref v => panic!("{name} is {v:?}"),
    }
}

/// Display name produced by the field's `display_fn`.
fn display(fields: &[&Field<'_>], name: &str) -> Option<&'static str> {
    let field = get(fields, name);
    let f = field
        .descriptor
        .display_fn
        .unwrap_or_else(|| panic!("{name} has no display_fn"));
    f(&field.value, &[])
}

/// Serialized value produced by the field's `format_fn`.
fn formatted(fields: &[&Field<'_>], name: &str) -> String {
    let field = get(fields, name);
    let f = field
        .descriptor
        .format_fn
        .unwrap_or_else(|| panic!("{name} has no format_fn"));
    let ctx = FormatContext {
        packet_data: &[],
        scratch: &[],
        layer_range: 0..0,
        field_range: 0..0,
    };
    let mut out = Vec::new();
    f(&field.value, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

// ── 5GMM ────────────────────────────────────────────────────────────────

/// Registration request with a SUCI (IMSI, null scheme) — the example in
/// the tracker issue.
const REGISTRATION_REQUEST_SUCI: &[u8] = &[
    0x7e, 0x00, 0x41, // 5GMM, plain, Registration request
    0x79, // ngKSI TSC 0 / KSI 7 | FOR 1, type 1 (initial)
    0x00, 0x0d, // 5GS mobile identity, length 13 (LV-E)
    0x01, // SUPI format IMSI, type SUCI
    0x00, 0xf1, 0x10, // MCC 001, MNC 01
    0xf0, 0xff, // routing indicator "0"
    0x00, 0x00, // protection scheme null, HN public key ID 0
    0x00, 0x00, 0x00, 0x00, 0x10, // scheme output (MSIN 0000000001)
];

#[test]
fn registration_request_suci_imsi() {
    let buf = dissect(REGISTRATION_REQUEST_SUCI);
    let top = top_level(&buf);
    assert_eq!(
        ie_names(&buf, &top),
        ["5GS registration type", "ngKSI", "5GS mobile identity"]
    );

    // TS 24.501, 8.1: the first half-octet IE occupies bits 1 to 4.
    let reg = ie(&buf, &top, "5GS registration type");
    assert_eq!(u8_of(&reg, "follow_on_request"), 1);
    assert_eq!(u8_of(&reg, "registration_type"), 1);
    assert_eq!(
        display(&reg, "registration_type"),
        Some("initial registration")
    );
    assert_eq!(get(&reg, "registration_type").range, 3..4);

    let ksi = ie(&buf, &top, "ngKSI");
    assert_eq!(u8_of(&ksi, "tsc"), 0);
    assert_eq!(u8_of(&ksi, "nas_key_set_identifier"), 7);
    assert_eq!(
        display(&ksi, "nas_key_set_identifier"),
        Some("no key is available (UE to network); reserved (network to UE)")
    );

    let id = ie(&buf, &top, "5GS mobile identity");
    assert_eq!(u16_of(&id, "length"), 13);
    assert_eq!(get(&id, "length").range, 4..6);
    assert!(id.iter().all(|f| f.name() != "iei"));
    assert_eq!(u8_of(&id, "type_of_identity"), 1);
    assert_eq!(display(&id, "type_of_identity"), Some("SUCI"));
    assert_eq!(u8_of(&id, "supi_format"), 0);
    assert_eq!(display(&id, "supi_format"), Some("IMSI"));
    assert_eq!(formatted(&id, "mcc"), "\"001\"");
    assert_eq!(formatted(&id, "mnc"), "\"01\"");
    assert_eq!(get(&id, "mcc").range, 7..10);
    assert_eq!(formatted(&id, "routing_indicator"), "\"0\"");
    assert_eq!(u8_of(&id, "protection_scheme_id"), 0);
    assert_eq!(display(&id, "protection_scheme_id"), Some("Null scheme"));
    assert_eq!(u8_of(&id, "home_network_public_key_id"), 0);
    assert_eq!(formatted(&id, "msin"), "\"0000000001\"");
    assert_eq!(get(&id, "msin").range, 14..19);
    assert!(top.iter().all(|f| f.name() != "undecoded_octets"));
}

#[test]
fn suci_ecies_scheme_output_is_hex() {
    let data = [
        0x7e, 0x00, 0x41, 0x01, 0x00, 0x0c, // Registration request, SUCI length 12
        0x01, 0x21, 0x63, 0x54, // SUCI, MCC 123, MNC 456
        0x21, 0x43, // routing indicator 1234
        0x01, 0x05, // ECIES scheme profile A, PKI 5
        0xde, 0xad, 0xbe, 0xef, // scheme output
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "5GS mobile identity");
    assert_eq!(formatted(&id, "mcc"), "\"123\"");
    assert_eq!(formatted(&id, "mnc"), "\"456\"");
    assert_eq!(formatted(&id, "routing_indicator"), "\"1234\"");
    assert_eq!(
        display(&id, "protection_scheme_id"),
        Some("ECIES scheme profile A")
    );
    assert_eq!(u8_of(&id, "home_network_public_key_id"), 5);
    assert_eq!(bytes_of(&id, "scheme_output"), &[0xde, 0xad, 0xbe, 0xef]);
    assert!(id.iter().all(|f| f.name() != "msin"));
}

#[test]
fn suci_nai() {
    let data = [
        0x7e, 0x00, 0x41, 0x01, 0x00, 0x04, // Registration request, SUCI length 4
        0x11, // SUPI format network specific identifier, SUCI
        b'a', b'@', b'b',
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "5GS mobile identity");
    assert_eq!(
        display(&id, "supi_format"),
        Some("Network specific identifier")
    );
    assert_eq!(formatted(&id, "suci_nai"), "\"a@b\"");
}

#[test]
fn registration_request_optional_ies() {
    let data = [
        0x7e, 0x00, 0x41, 0x09, // Registration request, initial, ngKSI 0
        0x00, 0x01, 0x00, // 5GS mobile identity: no identity
        0xc9, // Non-current native ngKSI: TSC 1, KSI 1
        0x2e, 0x04, 0xf0, 0xf0, 0x80, 0x40, // UE security capability
        0x52, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x2a, // Last visited TAI (TV 7)
        0x2f, 0x05, 0x04, 0x01, 0x00, 0x00, 0x01, // Requested NSSAI: SST 1, SD 1
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(
        ie_names(&buf, &top),
        [
            "5GS registration type",
            "ngKSI",
            "5GS mobile identity",
            "Non-current native NAS key set identifier",
            "UE security capability",
            "Last visited registered TAI",
            "Requested NSSAI",
        ]
    );

    let ksi = ie(&buf, &top, "Non-current native NAS key set identifier");
    assert_eq!(u8_of(&ksi, "iei"), 0xc);
    assert_eq!(u8_of(&ksi, "tsc"), 1);
    assert_eq!(display(&ksi, "tsc"), Some("mapped security context"));
    assert_eq!(u8_of(&ksi, "nas_key_set_identifier"), 1);

    let cap = ie(&buf, &top, "UE security capability");
    assert_eq!(u8_of(&cap, "iei"), 0x2e);
    assert_eq!(u8_of(&cap, "length"), 4);
    assert_eq!(u8_of(&cap, "ea_5g"), 0xf0);
    assert_eq!(u8_of(&cap, "ia_5g"), 0xf0);
    assert_eq!(u8_of(&cap, "eea"), 0x80);
    assert_eq!(u8_of(&cap, "eia"), 0x40);

    // TS 24.007, 11.2.4: IEI 0x52 would be TLV if it were unknown, but it
    // is known here as a TV IE of 7 octets.
    let tai = ie(&buf, &top, "Last visited registered TAI");
    assert!(tai.iter().all(|f| f.name() != "length"));
    assert_eq!(formatted(&tai, "mcc"), "\"208\"");
    assert_eq!(formatted(&tai, "mnc"), "\"93\"");
    assert_eq!(u32_of(&tai, "tac"), 0x2a);

    let nssai = ie(&buf, &top, "Requested NSSAI");
    let list = children(&buf, get(&nssai, "s_nssai_list"));
    assert_eq!(list.len(), 1);
    let s = children(&buf, list[0]);
    assert_eq!(u8_of(&s, "sst"), 1);
    assert_eq!(u32_of(&s, "sd"), 1);
}

#[test]
fn registration_accept_ies() {
    let data = [
        0x7e, 0x00, 0x42, // Registration accept
        0x01, 0x09, // 5GS registration result: SMS allowed, 3GPP access
        0x77, 0x00, 0x0b, 0xf2, // 5G-GUTI (TLV-E), type 5G-GUTI
        0x02, 0xf8, 0x39, // MCC 208, MNC 93
        0xca, 0xfe, 0x41, // AMF region 0xca, set 0x3f9, pointer 1
        0x12, 0x34, 0x56, 0x78, // 5G-TMSI
        0x54, 0x18, // TAI list, length 24
        0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, // 00: 2 TACs
        0x22, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x10, // 01: 3 consecutive TACs
        0x40, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x07, // 10: one TAI
        0x15, 0x19, // Allowed NSSAI, length 25
        0x01, 0x01, // SST 1
        0x02, 0x02, 0x03, // SST 2, mapped SST 3
        0x04, 0x01, 0xaa, 0xbb, 0xcc, // SST 1, SD
        0x05, 0x01, 0x00, 0x00, 0x01, 0x09, // SST, SD, mapped SST
        0x08, 0x01, 0x00, 0x00, 0x01, 0x09, 0x00, 0x00, 0x02, // all four
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);

    let res = ie(&buf, &top, "5GS registration result");
    assert_eq!(u8_of(&res, "length"), 1);
    assert_eq!(u8_of(&res, "sms_allowed"), 1);
    assert_eq!(u8_of(&res, "emergency_registered"), 0);
    assert_eq!(u8_of(&res, "nssaa_to_be_performed"), 0);
    assert_eq!(u8_of(&res, "disaster_roaming_registration_result"), 0);
    assert_eq!(display(&res, "registration_result"), Some("3GPP access"));

    let guti = ie(&buf, &top, "5G-GUTI");
    assert_eq!(u8_of(&guti, "iei"), 0x77);
    assert_eq!(u16_of(&guti, "length"), 11);
    assert_eq!(display(&guti, "type_of_identity"), Some("5G-GUTI"));
    assert_eq!(formatted(&guti, "mcc"), "\"208\"");
    assert_eq!(formatted(&guti, "mnc"), "\"93\"");
    assert_eq!(u8_of(&guti, "amf_region_id"), 0xca);
    assert_eq!(u16_of(&guti, "amf_set_id"), 0x3f9);
    assert_eq!(u8_of(&guti, "amf_pointer"), 1);
    assert_eq!(u32_of(&guti, "tmsi_5g"), 0x1234_5678);

    let tais = ie(&buf, &top, "TAI list");
    let partial = children(&buf, get(&tais, "partial_tai_lists"));
    assert_eq!(partial.len(), 3);

    let p0 = children(&buf, partial[0]);
    assert_eq!(u8_of(&p0, "type_of_list"), 0);
    assert_eq!(u8_of(&p0, "number_of_elements"), 2);
    let t0 = children(&buf, get(&p0, "tais"));
    assert_eq!(t0.len(), 2);
    let second = children(&buf, t0[1]);
    assert_eq!(formatted(&second, "mcc"), "\"208\"");
    assert_eq!(u32_of(&second, "tac"), 2);

    let p1 = children(&buf, partial[1]);
    assert_eq!(u8_of(&p1, "type_of_list"), 1);
    assert_eq!(u8_of(&p1, "number_of_elements"), 3);
    let t1 = children(&buf, get(&p1, "tais"));
    assert_eq!(t1.len(), 1);
    assert_eq!(u32_of(&children(&buf, t1[0]), "tac"), 0x10);

    let p2 = children(&buf, partial[2]);
    assert_eq!(u8_of(&p2, "type_of_list"), 2);
    assert_eq!(
        display(&p2, "type_of_list"),
        Some("list of TAIs belonging to different PLMNs")
    );
    let t2 = children(&buf, get(&p2, "tais"));
    let tai = children(&buf, t2[0]);
    assert_eq!(formatted(&tai, "mcc"), "\"001\"");
    assert_eq!(formatted(&tai, "mnc"), "\"01\"");
    assert_eq!(u32_of(&tai, "tac"), 7);

    let nssai = ie(&buf, &top, "Allowed NSSAI");
    let list = children(&buf, get(&nssai, "s_nssai_list"));
    assert_eq!(list.len(), 5);
    let s: Vec<_> = list.iter().map(|f| children(&buf, f)).collect();
    assert_eq!(u8_of(&s[0], "sst"), 1);
    assert!(s[0].iter().all(|f| f.name() != "sd"));
    assert_eq!(u8_of(&s[1], "mapped_hplmn_sst"), 3);
    assert_eq!(u32_of(&s[2], "sd"), 0xaabbcc);
    assert_eq!(u8_of(&s[3], "mapped_hplmn_sst"), 9);
    assert!(s[3].iter().all(|f| f.name() != "mapped_hplmn_sd"));
    assert_eq!(u32_of(&s[4], "mapped_hplmn_sd"), 2);
}

#[test]
fn registration_reject_cause() {
    let buf = dissect(&[0x7e, 0x00, 0x44, 0x16]);
    let top = top_level(&buf);
    let cause = ie(&buf, &top, "5GMM cause");
    assert_eq!(u8_of(&cause, "cause"), 22);
    assert_eq!(display(&cause, "cause"), Some("Congestion"));
}

#[test]
fn authentication_request() {
    let mut data = vec![
        0x7e, 0x00, 0x56, // Authentication request
        0x02, // ngKSI 2 | spare
        0x02, 0x00, 0x00, // ABBA, length 2
        0x21, // RAND (TV 17)
    ];
    data.extend_from_slice(&[0x11; 16]);
    data.extend_from_slice(&[0x20, 0x10]); // AUTN (TLV 18)
    data.extend_from_slice(&[0x22; 16]);
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(
        ie_names(&buf, &top),
        [
            "ngKSI",
            "ABBA",
            "Authentication parameter RAND (5G authentication challenge)",
            "Authentication parameter AUTN (5G authentication challenge)",
        ]
    );
    assert_eq!(u8_of(&ie(&buf, &top, "ngKSI"), "nas_key_set_identifier"), 2);
    let abba = ie(&buf, &top, "ABBA");
    assert_eq!(u8_of(&abba, "length"), 2);
    assert_eq!(bytes_of(&abba, "value"), &[0, 0]);
    let rand = ie(
        &buf,
        &top,
        "Authentication parameter RAND (5G authentication challenge)",
    );
    assert_eq!(u8_of(&rand, "iei"), 0x21);
    assert_eq!(bytes_of(&rand, "value"), &[0x11; 16]);
    let autn = ie(
        &buf,
        &top,
        "Authentication parameter AUTN (5G authentication challenge)",
    );
    assert_eq!(bytes_of(&autn, "value"), &[0x22; 16]);
}

#[test]
fn authentication_response() {
    let mut data = vec![0x7e, 0x00, 0x57, 0x2d, 0x10];
    data.extend_from_slice(&[0xab; 16]);
    let buf = dissect(&data);
    let top = top_level(&buf);
    let res = ie(&buf, &top, "Authentication response parameter");
    assert_eq!(bytes_of(&res, "value"), &[0xab; 16]);
}

#[test]
fn security_mode_command() {
    let data = [
        0x7e, 0x00, 0x5d, // Security mode command
        0x21, // 128-5G-EA2, 128-5G-IA1
        0x01, // ngKSI 1 | spare
        0x02, 0xe0, 0xe0, // Replayed UE security capabilities (LV)
        0xe1, // IMEISV request: requested
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(
        ie_names(&buf, &top),
        [
            "Selected NAS security algorithms",
            "ngKSI",
            "Replayed UE security capabilities",
            "IMEISV request",
        ]
    );
    let alg = ie(&buf, &top, "Selected NAS security algorithms");
    assert_eq!(u8_of(&alg, "ciphering_algorithm"), 2);
    assert_eq!(
        display(&alg, "ciphering_algorithm"),
        Some("5G encryption algorithm 128-5G-EA2")
    );
    assert_eq!(u8_of(&alg, "integrity_algorithm"), 1);
    assert_eq!(
        display(&alg, "integrity_algorithm"),
        Some("5G integrity algorithm 128-5G-IA1")
    );
    let cap = ie(&buf, &top, "Replayed UE security capabilities");
    assert_eq!(u8_of(&cap, "ea_5g"), 0xe0);
    assert!(cap.iter().all(|f| f.name() != "eea"));
    let imeisv = ie(&buf, &top, "IMEISV request");
    assert_eq!(u8_of(&imeisv, "iei"), 0xe);
    assert_eq!(u8_of(&imeisv, "value"), 1);
}

#[test]
fn security_mode_complete_imeisv() {
    let data = [
        0x7e, 0x00, 0x5e, // Security mode complete
        0x77, 0x00, 0x09, // IMEISV (TLV-E)
        0x35, // digit 1 = 3, even, IMEISV
        0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5,
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "IMEISV");
    assert_eq!(display(&id, "type_of_identity"), Some("IMEISV"));
    assert_eq!(u8_of(&id, "odd_even_indication"), 0);
    assert_eq!(formatted(&id, "identity_digits"), "\"3123456789012345\"");
}

#[test]
fn identity_response_other_identity_types() {
    // IMEI with an odd number of digits: no end mark.
    let buf = dissect(&[0x7e, 0x00, 0x5c, 0x00, 0x02, 0x1b, 0x32]);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "Mobile identity");
    assert_eq!(display(&id, "type_of_identity"), Some("IMEI"));
    assert_eq!(u8_of(&id, "odd_even_indication"), 1);
    assert_eq!(formatted(&id, "identity_digits"), "\"123\"");

    let buf = dissect(&[
        0x7e, 0x00, 0x5c, 0x00, 0x07, 0x0e, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ]);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "Mobile identity");
    assert_eq!(display(&id, "type_of_identity"), Some("MAC address"));
    assert_eq!(u8_of(&id, "mauri"), 1);
    assert_eq!(
        get(&id, "mac_address").value,
        FieldValue::MacAddr(packet_dissector_core::field::MacAddr([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ]))
    );

    let buf = dissect(&[0x7e, 0x00, 0x5c, 0x00, 0x09, 0x07, 1, 2, 3, 4, 5, 6, 7, 8]);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "Mobile identity");
    assert_eq!(display(&id, "type_of_identity"), Some("EUI-64"));
    assert_eq!(bytes_of(&id, "eui_64"), &[1, 2, 3, 4, 5, 6, 7, 8]);

    let buf = dissect(&[0x7e, 0x00, 0x5c, 0x00, 0x01, 0x00]);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "Mobile identity");
    assert_eq!(display(&id, "type_of_identity"), Some("No identity"));
}

#[test]
fn deregistration_request() {
    let data = [
        0x7e, 0x00, 0x45, // De-registration request (UE originating)
        0x09, // switch off, 3GPP access | ngKSI 0
        0x00, 0x07, 0xf4, 0x00, 0x41, 0x12, 0x34, 0x56, 0x78, // 5G-S-TMSI
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let t = ie(&buf, &top, "De-registration type");
    assert_eq!(u8_of(&t, "switch_off"), 1);
    assert_eq!(u8_of(&t, "re_registration_required"), 0);
    assert_eq!(u8_of(&t, "access_type"), 1);
    assert_eq!(display(&t, "access_type"), Some("3GPP access"));
    let id = ie(&buf, &top, "5GS mobile identity");
    assert_eq!(display(&id, "type_of_identity"), Some("5G-S-TMSI"));
}

#[test]
fn service_request_5g_s_tmsi() {
    let data = [
        0x7e, 0x00, 0x4c, // Service request
        0x10, // ngKSI 0 | service type data
        0x00, 0x07, 0xf4, // 5G-S-TMSI
        0x00, 0x41, // AMF set ID 1, pointer 1
        0x12, 0x34, 0x56, 0x78,
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(ie_names(&buf, &top), ["ngKSI", "Service type", "5G-S-TMSI"]);
    let st = ie(&buf, &top, "Service type");
    assert_eq!(u8_of(&st, "service_type"), 1);
    assert_eq!(display(&st, "service_type"), Some("data"));
    let id = ie(&buf, &top, "5G-S-TMSI");
    assert_eq!(u16_of(&id, "amf_set_id"), 1);
    assert_eq!(u8_of(&id, "amf_pointer"), 1);
    assert_eq!(u32_of(&id, "tmsi_5g"), 0x1234_5678);
    assert!(id.iter().all(|f| f.name() != "mcc"));
}

#[test]
fn identity_request() {
    let buf = dissect(&[0x7e, 0x00, 0x5b, 0x01]);
    let top = top_level(&buf);
    let t = ie(&buf, &top, "Identity type");
    assert_eq!(u8_of(&t, "type_of_identity"), 1);
    assert_eq!(display(&t, "type_of_identity"), Some("SUCI"));

    // Table 9.11.3.3.1 has no "No identity": value 0 is unused.
    let buf = dissect(&[0x7e, 0x00, 0x5b, 0x00]);
    let top = top_level(&buf);
    let t = ie(&buf, &top, "Identity type");
    assert_eq!(u8_of(&t, "type_of_identity"), 0);
    assert_eq!(display(&t, "type_of_identity"), None);
}

/// UL NAS transport carrying a 5GSM PDU session establishment request —
/// the example in the tracker issue, extended with a request type and a
/// DNN.
const UL_NAS_TRANSPORT_N1_SM: &[u8] = &[
    0x7e, 0x00, 0x67, // 5GMM, plain, UL NAS transport
    0x01, // payload container type 1 (N1 SM information)
    0x00, 0x06, // payload container length
    0x2e, 0x01, 0x01, 0xc1, 0xff, 0xff, // 5GSM: PSI 1, PTI 1, establishment request
    0x12, 0x01, // PDU session ID 2 (TV), PSI 1
    0x81, // Request type: initial request
    0x25, 0x09, 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', // DNN
];

#[test]
fn ul_nas_transport_n1_sm() {
    let buf = dissect(UL_NAS_TRANSPORT_N1_SM);
    let top = top_level(&buf);
    assert_eq!(display(&top, "message_type"), Some("UL NAS transport"));
    assert_eq!(
        ie_names(&buf, &top),
        [
            "Payload container type",
            "Payload container",
            "PDU session ID",
            "Request type",
            "DNN",
        ]
    );

    let pct = ie(&buf, &top, "Payload container type");
    assert_eq!(u8_of(&pct, "payload_container_type"), 1);
    assert_eq!(
        display(&pct, "payload_container_type"),
        Some("N1 SM information")
    );

    let pc = ie(&buf, &top, "Payload container");
    assert_eq!(u16_of(&pc, "length"), 6);
    let sm = children(&buf, get(&pc, "n1_sm_message"));
    assert_eq!(get(&pc, "n1_sm_message").range, 6..12);
    assert_eq!(u8_of(&sm, "extended_protocol_discriminator"), 0x2e);
    assert_eq!(u8_of(&sm, "pdu_session_id"), 1);
    assert_eq!(u8_of(&sm, "procedure_transaction_identity"), 1);
    assert_eq!(
        display(&sm, "message_type"),
        Some("PDU session establishment request")
    );
    let rate = ie(&buf, &sm, "Integrity protection maximum data rate");
    assert_eq!(u8_of(&rate, "max_data_rate_uplink"), 0xff);
    assert_eq!(
        display(&rate, "max_data_rate_uplink"),
        Some("Full data rate")
    );
    assert_eq!(u8_of(&rate, "max_data_rate_downlink"), 0xff);

    let psi = ie(&buf, &top, "PDU session ID");
    assert_eq!(u8_of(&psi, "iei"), 0x12);
    assert_eq!(u8_of(&psi, "pdu_session_id"), 1);

    let rt = ie(&buf, &top, "Request type");
    assert_eq!(u8_of(&rt, "request_type"), 1);
    assert_eq!(display(&rt, "request_type"), Some("initial request"));

    let dnn = ie(&buf, &top, "DNN");
    assert_eq!(formatted(&dnn, "dnn"), "\"internet\"");
}

#[test]
fn dl_nas_transport_sms_payload_kept_raw() {
    let data = [
        0x7e, 0x00, 0x68, 0x02, // DL NAS transport, payload container type SMS
        0x00, 0x03, 0x2e, 0x01, 0x02, // payload that looks like 5GSM
        0x58, 0x6f, // 5GMM cause (TV 2): protocol error, unspecified
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let pc = ie(&buf, &top, "Payload container");
    assert_eq!(bytes_of(&pc, "value"), &[0x2e, 0x01, 0x02]);
    assert!(pc.iter().all(|f| f.name() != "n1_sm_message"));
    let cause = ie(&buf, &top, "5GMM cause");
    assert_eq!(
        display(&cause, "cause"),
        Some("Protocol error, unspecified")
    );
}

// ── 5GSM ────────────────────────────────────────────────────────────────

#[test]
fn pdu_session_establishment_reject() {
    let buf = dissect(&[0x2e, 0x05, 0x01, 0xc3, 0x1b]);
    let top = top_level(&buf);
    let cause = ie(&buf, &top, "5GSM cause");
    assert_eq!(u8_of(&cause, "cause"), 27);
    assert_eq!(display(&cause, "cause"), Some("Missing or unknown DNN"));
}

#[test]
fn pdu_session_establishment_accept() {
    let data = [
        0x2e, 0x05, 0x01, 0xc2, // PSI 5, PTI 1, establishment accept
        0x11, // selected PDU session type IPv4 | selected SSC mode 1
        0x00, 0x09, // Authorized QoS rules, length 9
        0x01, 0x00, 0x06, // QRI 1, rule length 6
        0x31, // create new QoS rule, DQR, 1 packet filter
        0x31, 0x01, 0x01, // bidirectional PF 1, match-all
        0xff, // precedence 255
        0x09, // QFI 9
        0x06, 0x06, 0x03, 0xe8, 0x06, 0x01, 0xf4, // Session-AMBR 1000/500 Mbps
        0x29, 0x05, 0x01, 0x0a, 0x2d, 0x00, 0x01, // PDU address IPv4 10.45.0.1
        0x22, 0x01, 0x01, // S-NSSAI: SST 1
        0x79, 0x00, 0x06, // Authorized QoS flow descriptions, length 6
        0x09, 0x20, 0x41, 0x01, 0x01, 0x09, // QFI 9, create, E=1, 5QI 9
        0x25, 0x04, 0x03, b'i', b'm', b's', // DNN "ims"
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(
        ie_names(&buf, &top),
        [
            "Selected PDU session type",
            "Selected SSC mode",
            "Authorized QoS rules",
            "Session AMBR",
            "PDU address",
            "S-NSSAI",
            "Authorized QoS flow descriptions",
            "DNN",
        ]
    );

    let t = ie(&buf, &top, "Selected PDU session type");
    assert_eq!(display(&t, "pdu_session_type"), Some("IPv4"));
    let m = ie(&buf, &top, "Selected SSC mode");
    assert_eq!(display(&m, "ssc_mode"), Some("SSC mode 1"));

    let rules = ie(&buf, &top, "Authorized QoS rules");
    assert_eq!(u16_of(&rules, "length"), 9);
    let list = children(&buf, get(&rules, "qos_rules"));
    assert_eq!(list.len(), 1);
    let rule = children(&buf, list[0]);
    assert_eq!(u8_of(&rule, "qos_rule_identifier"), 1);
    assert_eq!(u16_of(&rule, "length"), 6);
    assert_eq!(u8_of(&rule, "rule_operation_code"), 1);
    assert_eq!(
        display(&rule, "rule_operation_code"),
        Some("Create new QoS rule")
    );
    assert_eq!(u8_of(&rule, "dqr"), 1);
    assert_eq!(u8_of(&rule, "number_of_packet_filters"), 1);
    assert_eq!(u8_of(&rule, "qos_rule_precedence"), 255);
    assert_eq!(u8_of(&rule, "segregation"), 0);
    assert_eq!(u8_of(&rule, "qfi"), 9);
    let pfs = children(&buf, get(&rule, "packet_filters"));
    let pf = children(&buf, pfs[0]);
    assert_eq!(u8_of(&pf, "packet_filter_direction"), 3);
    assert_eq!(
        display(&pf, "packet_filter_direction"),
        Some("bidirectional")
    );
    assert_eq!(u8_of(&pf, "packet_filter_identifier"), 1);
    assert_eq!(u8_of(&pf, "length"), 1);
    assert_eq!(bytes_of(&pf, "contents"), &[0x01]);

    let ambr = ie(&buf, &top, "Session AMBR");
    assert_eq!(u8_of(&ambr, "downlink_unit"), 6);
    assert_eq!(display(&ambr, "downlink_unit"), Some("1 Mbps"));
    assert_eq!(u16_of(&ambr, "downlink_ambr"), 1000);
    assert_eq!(u16_of(&ambr, "uplink_ambr"), 500);

    let addr = ie(&buf, &top, "PDU address");
    assert_eq!(display(&addr, "pdu_session_type"), Some("IPv4"));
    assert_eq!(
        get(&addr, "ipv4_address").value,
        FieldValue::Ipv4Addr([10, 45, 0, 1])
    );

    let snssai = ie(&buf, &top, "S-NSSAI");
    assert_eq!(u8_of(&snssai, "sst"), 1);

    let flows = ie(&buf, &top, "Authorized QoS flow descriptions");
    let list = children(&buf, get(&flows, "qos_flow_descriptions"));
    let flow = children(&buf, list[0]);
    assert_eq!(u8_of(&flow, "qfi"), 9);
    assert_eq!(u8_of(&flow, "operation_code"), 1);
    assert_eq!(
        display(&flow, "operation_code"),
        Some("Create new QoS flow description")
    );
    assert_eq!(u8_of(&flow, "e_bit"), 1);
    assert_eq!(u8_of(&flow, "number_of_parameters"), 1);
    let params = children(&buf, get(&flow, "parameters"));
    let p = children(&buf, params[0]);
    assert_eq!(display(&p, "parameter_identifier"), Some("5QI"));
    assert_eq!(u8_of(&p, "five_qi"), 9);

    let dnn = ie(&buf, &top, "DNN");
    assert_eq!(formatted(&dnn, "dnn"), "\"ims\"");
}

#[test]
fn qos_rules_delete_packet_filters() {
    let data = [
        0x2e, 0x05, 0x01, 0xcb, // PDU session modification command
        0x7a, 0x00, 0x08, // Authorized QoS rules (TLV-E)
        0x02, 0x00, 0x05, // QRI 2, length 5
        0xa2, // modify and delete packet filters, 2 filters
        0x01, 0x02, // packet filter identifiers 1 and 2
        0x80, 0x05, // precedence 128, QFI 5
        0x2a, 0x06, 0x01, 0x00, 0x64, 0x01, 0x00, 0x32, // Session-AMBR (TLV)
        0x56, 0x21, // RQ timer value (TV 2)
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let rules = ie(&buf, &top, "Authorized QoS rules");
    let list = children(&buf, get(&rules, "qos_rules"));
    let rule = children(&buf, list[0]);
    assert_eq!(u8_of(&rule, "rule_operation_code"), 5);
    let pfs = children(&buf, get(&rule, "packet_filters"));
    assert_eq!(pfs.len(), 2);
    let pf = children(&buf, pfs[1]);
    assert_eq!(u8_of(&pf, "packet_filter_identifier"), 2);
    assert!(pf.iter().all(|f| f.name() != "packet_filter_direction"));
    assert_eq!(u8_of(&rule, "qfi"), 5);

    let ambr = ie(&buf, &top, "Session AMBR");
    assert_eq!(u8_of(&ambr, "iei"), 0x2a);
    assert_eq!(u16_of(&ambr, "downlink_ambr"), 100);
    let rq = ie(&buf, &top, "RQ timer value");
    assert_eq!(bytes_of(&rq, "value"), &[0x21]);
}

#[test]
fn pdu_address_variants() {
    // IPv6 interface identifier.
    let buf = dissect(&[
        0x2e, 0x05, 0x01, 0xc2, // PDU session establishment accept
        0x12, // IPv6 | SSC mode 1
        0x00, 0x00, // empty QoS rules
        0x06, 0x06, 0x00, 0x01, 0x06, 0x00, 0x01, // Session-AMBR
        0x29, 0x09, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, // PDU address
    ]);
    let top = top_level(&buf);
    let addr = ie(&buf, &top, "PDU address");
    assert_eq!(display(&addr, "pdu_session_type"), Some("IPv6"));
    assert_eq!(
        bytes_of(&addr, "ipv6_interface_identifier"),
        &[1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert!(addr.iter().all(|f| f.name() != "ipv4_address"));

    // IPv4v6 with the SMF's IPv6 link local address.
    let mut data = vec![
        0x2e, 0x05, 0x01, 0xc2, 0x13, 0x00, 0x00, 0x06, 0x06, 0x00, 0x01, 0x06, 0x00, 0x01, 0x29,
        0x1d, 0x0b, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 1,
    ];
    data.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let buf = dissect(&data);
    let top = top_level(&buf);
    let addr = ie(&buf, &top, "PDU address");
    assert_eq!(u8_of(&addr, "si6lla"), 1);
    assert_eq!(display(&addr, "pdu_session_type"), Some("IPv4v6"));
    assert_eq!(
        get(&addr, "ipv4_address").value,
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
    assert_eq!(
        get(&addr, "smf_ipv6_link_local_address").value,
        FieldValue::Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
}

// ── IE framing and error handling ───────────────────────────────────────

#[test]
fn unknown_optional_ies_are_skipped() {
    let data = [
        0x7e, 0x00, 0x43, // Registration complete
        0x95, // unknown type 1 IE
        0x0f, 0x02, 0xaa, 0xbb, // unknown TLV IE
        0x7f, 0x00, 0x01, 0xcc, // unknown TLV-E IE
        0x73, 0x00, 0x01, 0xdd, // SOR transparent container (known)
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(
        ie_names(&buf, &top),
        ["Unknown", "Unknown", "Unknown", "SOR transparent container"]
    );
    let all = ies(&buf, &top);
    assert_eq!(u8_of(&all[0], "iei"), 0x9);
    assert_eq!(u8_of(&all[0], "value"), 0x5);
    assert_eq!(u8_of(&all[1], "iei"), 0x0f);
    assert_eq!(bytes_of(&all[1], "value"), &[0xaa, 0xbb]);
    assert_eq!(u8_of(&all[2], "iei"), 0x7f);
    assert_eq!(u16_of(&all[2], "length"), 1);
    assert_eq!(bytes_of(&all[2], "value"), &[0xcc]);
    assert_eq!(bytes_of(&all[3], "value"), &[0xdd]);
}

#[test]
fn truncated_optional_ie_reported() {
    let data = [0x7e, 0x00, 0x44, 0x03, 0x16, 0x05, 0x01];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(ie_names(&buf, &top), ["5GMM cause"]);
    let rest = get(&top, "undecoded_octets");
    assert_eq!(rest.value, FieldValue::Bytes(&[0x16, 0x05, 0x01]));
    assert_eq!(rest.range, 4..7);
}

#[test]
fn truncated_mandatory_ie_reported() {
    // Mobile identity length 13 but only 2 octets follow.
    let data = [0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x00];
    let buf = dissect(&data);
    let top = top_level(&buf);
    assert_eq!(ie_names(&buf, &top), ["5GS registration type", "ngKSI"]);
    let rest = get(&top, "undecoded_octets");
    assert_eq!(rest.value, FieldValue::Bytes(&data[4..]));
    assert_eq!(rest.range, 4..8);
    let missing = get(&top, "missing_mandatory_ie");
    assert_eq!(missing.value, FieldValue::Str("5GS mobile identity"));
    assert_eq!(missing.range, 4..8);
}

#[test]
fn absent_mandatory_ie_reported() {
    // UL NAS transport ending right after the payload container type: the
    // mandatory payload container is absent.
    let buf = dissect(&[0x7e, 0x00, 0x67, 0x01]);
    let top = top_level(&buf);
    assert_eq!(ie_names(&buf, &top), ["Payload container type"]);
    assert!(top.iter().all(|f| f.name() != "undecoded_octets"));
    let missing = get(&top, "missing_mandatory_ie");
    assert_eq!(missing.value, FieldValue::Str("Payload container"));
    assert_eq!(missing.range, 4..4);

    // Header only: nothing framed, the first mandatory IE is missing.
    let buf = dissect(&[0x2e, 0x05, 0x01, 0xd6]);
    let top = top_level(&buf);
    assert!(top.iter().all(|f| f.name() != "information_elements"));
    assert_eq!(
        get(&top, "missing_mandatory_ie").value,
        FieldValue::Str("5GSM cause")
    );

    // A message without mandatory IEs may end after the header.
    let buf = dissect(&[0x7e, 0x00, 0x43]);
    let top = top_level(&buf);
    assert_eq!(top.len(), 3);
}

#[test]
fn malformed_ie_value_falls_back_to_raw() {
    let data = [
        0x7e, 0x00, 0x42, 0x01, 0x01, // Registration accept
        0x77, 0x00, 0x03, 0xf2, 0x02, 0xf8, // 5G-GUTI far too short
        0x15, 0x04, 0x03, 0x01, 0x02, 0x03, // S-NSSAI with reserved length 3
    ];
    let buf = dissect(&data);
    let top = top_level(&buf);
    let guti = ie(&buf, &top, "5G-GUTI");
    assert_eq!(bytes_of(&guti, "value"), &[0xf2, 0x02, 0xf8]);
    assert!(guti.iter().all(|f| f.name() != "mcc"));
    let nssai = ie(&buf, &top, "Allowed NSSAI");
    assert_eq!(bytes_of(&nssai, "value"), &[0x03, 0x01, 0x02, 0x03]);
    assert!(top.iter().all(|f| f.name() != "undecoded_octets"));
}

#[test]
fn no_identity_with_extra_octets_kept_raw() {
    // TS 24.501, 9.11.3.4: "For Type of identity "No identity", the length
    // of mobile identity contents parameter shall be set to 1".
    let buf = dissect(&[0x7e, 0x00, 0x5c, 0x00, 0x03, 0x00, 0x12, 0x34]);
    let top = top_level(&buf);
    let id = ie(&buf, &top, "Mobile identity");
    assert_eq!(bytes_of(&id, "value"), &[0x00, 0x12, 0x34]);
    assert!(id.iter().all(|f| f.name() != "type_of_identity"));
}

/// Panics if a descriptor's `children` slice is reachable from itself.
fn assert_acyclic(fields: &'static [FieldDescriptor], ancestors: &mut Vec<*const FieldDescriptor>) {
    for fd in fields {
        let Some(children) = fd.children else {
            continue;
        };
        let ptr = children.as_ptr();
        assert!(
            !ancestors.contains(&ptr),
            "`{}` contains one of its ancestors",
            fd.name
        );
        ancestors.push(ptr);
        assert_acyclic(children, ancestors);
        ancestors.pop();
    }
}

#[test]
fn field_descriptor_schema_is_acyclic() {
    // A cyclic schema makes any recursive walk of `children`, including
    // `FieldDescriptor`'s `PartialEq`, recurse without bound.
    let fields = Nas5gDissector.field_descriptors();
    assert_acyclic(fields, &mut vec![fields.as_ptr()]);
    assert_eq!(fields, Nas5gDissector.field_descriptors());
}

#[test]
fn unknown_message_type_body_kept_raw() {
    let buf = dissect(&[0x7e, 0x00, 0x50, 0x01, 0x02]);
    let top = top_level(&buf);
    assert!(top.iter().all(|f| f.name() != "information_elements"));
    assert_eq!(bytes_of(&top, "undecoded_octets"), &[0x01, 0x02]);
    assert_eq!(get(&top, "undecoded_octets").range, 3..5);
}

#[test]
fn integrity_protected_inner_message_ies() {
    let mut data = vec![0x7e, 0x01, 0x12, 0x34, 0x56, 0x78, 0x02];
    data.extend_from_slice(REGISTRATION_REQUEST_SUCI);
    let buf = dissect(&data);
    let top = top_level(&buf);
    let plain = children(&buf, get(&top, "plain_nas_message"));
    let id = ie(&buf, &plain, "5GS mobile identity");
    assert_eq!(formatted(&id, "msin"), "\"0000000001\"");
    assert_eq!(get(&id, "msin").range, 21..26);
}

#[test]
fn dissector_decodes_ies() {
    for data in [REGISTRATION_REQUEST_SUCI, UL_NAS_TRANSPORT_N1_SM] {
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert!(buf.layer_by_name("NAS-5G").is_some());
        let top = top_level(&buf);
        assert!(!ies(&buf, &top).is_empty());
    }

    let mut buf = DissectBuffer::new();
    Nas5gDissector
        .dissect(&[0x2e, 0x05, 0x01, 0xc3, 0x1b], &mut buf, 0)
        .unwrap();
    let top = top_level(&buf);
    assert_eq!(ie_names(&buf, &top), ["5GSM cause"]);
}

/// Every 5GMM and 5GSM message type followed by pseudo-random bodies: the
/// walker must never panic, and every field range must lie within the
/// input (Postel's law).
#[test]
fn arbitrary_bodies_never_panic() {
    // Small linear congruential generator for a deterministic corpus.
    let mut state: u32 = 0x1234_5678;
    let mut next = move || {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (state >> 24) as u8
    };
    for round in 0..64 {
        for message_type in 0x40..=0xdfu8 {
            let len = usize::from(next()) % (8 + round * 4);
            let mut data = if message_type < 0xc0 {
                vec![0x7e, 0x00, message_type]
            } else {
                vec![0x2e, 0x05, 0x01, message_type]
            };
            for _ in 0..len {
                data.push(next());
            }
            let mut buf = DissectBuffer::new();
            assert!(push_nas_pdu(&mut buf, &data, 0));
            for f in buf.fields() {
                assert!(
                    f.range.start <= f.range.end && f.range.end <= data.len(),
                    "{} range {:?} out of bounds for {data:02x?}",
                    f.name(),
                    f.range
                );
            }
        }
    }
}
