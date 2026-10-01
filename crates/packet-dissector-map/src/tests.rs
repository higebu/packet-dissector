//! # 3GPP TS 29.002 (MAP) Coverage
//!
//! | Clause      | Description                                              | Test                                  |
//! |-------------|----------------------------------------------------------|---------------------------------------|
//! | 17.3.3      | Application context name and version from the AARQ       | parse_sai_v3_begin                    |
//! | 17.3.3      | Non-MAP application context not named                    | parse_non_map_context                 |
//! | 17.5, 17.6  | Operation codes (names, incl. reserved legacy codes)     | name_tables                           |
//! | 17.6.6      | Error codes (names) on a Return Error                    | parse_return_error                    |
//! | 17.7.1      | SendAuthenticationInfoArg (v3 SEQUENCE, v2 IMSI)         | parse_sai_v3_begin, parse_sai_v2_imsi |
//! | 17.7.1      | UpdateLocationArg / UpdateLocationRes                    | parse_update_location                 |
//! | 17.7.1      | UpdateGprsLocationArg                                    | parse_update_gprs_location            |
//! | 17.7.1      | CancelLocationArg ([3], earlier bare Identity forms)     | parse_cancel_location                 |
//! | 17.7.1      | PurgeMS-Arg (current and version 2)                      | parse_purge_ms                        |
//! | 17.7.1      | InsertSubscriberDataArg (imsi, msisdn)                   | parse_insert_subscriber_data          |
//! | 17.7.3      | ProvideRoamingNumberArg                                  | parse_provide_roaming_number          |
//! | 17.7.6      | RoutingInfoForSM-Arg                                     | parse_sri_for_sm                      |
//! | 17.7.6      | MO-ForwardSM-Arg / MT-ForwardSM-Arg, SM-RP-DA / SM-RP-OA | parse_forward_sm                      |
//! | 17.7.8      | TBCD-STRING digits and filler                            | tbcd_digits                           |
//! | 17.7.8      | AddressString nature of address / numbering plan         | parse_update_location                 |
//! | 17.7        | Raw parameter always kept; malformed arguments           | malformed_arguments_raw               |
//! | —           | TCAP errors propagate; TCAP layer always emitted         | tcap_errors_and_layers                |
//! | —           | Name tables and display functions                        | name_tables                           |
//! | 17.7.8      | Digits formatting and component display                  | format_and_component_display          |

use super::*;
use packet_dissector_core::field::Field;
use packet_dissector_core::packet::Layer;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 0x80 {
        v.push(content.len() as u8);
    } else {
        v.extend_from_slice(&[0x81, content.len() as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// {0 4 0 0 1 0 <ac> <version>} encoded (0.4 is the first octet 0x04).
fn ac(arc: u8, version: u8) -> Vec<u8> {
    vec![0x04, 0x00, 0x00, 0x01, 0x00, arc, version]
}

/// IMSI 001010123456789 as TBCD (odd: filler 1111).
const IMSI: &[u8] = &[0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xf9];
const IMSI_DIGITS: &str = "001010123456789";
/// ISDN-AddressString: international, E.164, digits 81901234567.
const MSISDN: &[u8] = &[0x91, 0x18, 0x09, 0x21, 0x43, 0x65, 0xf7];
const MSISDN_DIGITS: &str = "81901234567";

/// TCAP Begin with an AARQ for `context` and one Invoke of `opcode` with
/// `parameter`.
fn begin(context: &[u8], opcode: u8, parameter: Option<Vec<u8>>) -> Vec<u8> {
    let aarq = tlv(0x60, &tlv(0xa1, &tlv(0x06, context)));
    let dialogue = tlv(
        0x6b,
        &tlv(
            0x28,
            &cat(&[
                tlv(0x06, packet_dissector_tcap::DIALOGUE_AS_ID),
                tlv(0xa0, &aarq),
            ]),
        ),
    );
    let mut invoke = cat(&[tlv(0x02, &[0x01]), tlv(0x02, &[opcode])]);
    if let Some(p) = parameter {
        invoke.extend(p);
    }
    tlv(
        0x62,
        &cat(&[
            tlv(0x48, &[1, 2, 3, 4]),
            dialogue,
            tlv(0x6c, &tlv(0xa1, &invoke)),
        ]),
    )
}

/// TCAP End with the given components and no dialogue portion.
fn end(components: &[Vec<u8>]) -> Vec<u8> {
    tlv(
        0x64,
        &cat(&[tlv(0x49, &[1, 2, 3, 4]), tlv(0x6c, &cat(components))]),
    )
}

fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
    let mut buf = DissectBuffer::new();
    let r = MapDissector.dissect(data, &mut buf, 0).unwrap();
    (buf, r)
}

fn map_layer<'a>(buf: &'a DissectBuffer<'a>) -> &'a Layer {
    buf.layer_by_name("MAP").expect("no MAP layer")
}

fn map_field<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a FieldValue<'a> {
    &buf.field_by_name(map_layer(buf), name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .value
}

fn components<'a>(buf: &'a DissectBuffer<'a>) -> Vec<&'a [Field<'a>]> {
    let FieldValue::Array(r) = map_field(buf, "components") else {
        panic!("components is not an array")
    };
    let all = buf.nested_fields(r);
    let mut out = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let FieldValue::Object(cr) = &all[i].value else {
            panic!("component is not an object")
        };
        out.push(buf.nested_fields(cr));
        i += 1 + (cr.end - cr.start) as usize;
    }
    out
}

fn get<'a>(fields: &'a [Field<'a>], name: &str) -> &'a FieldValue<'a> {
    &fields
        .iter()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .value
}

fn has(fields: &[Field<'_>], name: &str) -> bool {
    fields.iter().any(|f| f.name() == name)
}

fn object<'a>(buf: &'a DissectBuffer<'a>, fields: &'a [Field<'a>], name: &str) -> &'a [Field<'a>] {
    let FieldValue::Object(r) = get(fields, name) else {
        panic!("{name} is not an object")
    };
    buf.nested_fields(r)
}

fn digits<'a>(buf: &'a DissectBuffer<'a>, fields: &[Field<'_>], name: &str) -> &'a str {
    let FieldValue::Scratch(r) = get(fields, name) else {
        panic!("{name} is not scratch")
    };
    core::str::from_utf8(&buf.scratch()[r.start as usize..r.end as usize]).unwrap()
}

fn display(fields: &[Field<'_>], name: &str) -> Option<&'static str> {
    let f = fields.iter().find(|f| f.name() == name)?;
    (f.descriptor.display_fn?)(&f.value, fields)
}

#[test]
fn parse_sai_v3_begin() {
    // SendAuthenticationInfoArg ::= SEQUENCE { imsi [0] IMSI,
    // numberOfRequestedVectors NumberOfRequestedVectors, ... }
    let arg = tlv(0x30, &cat(&[tlv(0x80, IMSI), tlv(0x02, &[0x05])]));
    let data = begin(&ac(14, 3), 56, Some(arg));
    let (buf, r) = dissect(&data);
    assert_eq!(r.bytes_consumed, data.len());
    assert_eq!(r.next, DispatchHint::End);
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["TCAP", "MAP"]);
    let layer = map_layer(&buf);
    assert_eq!(*map_field(&buf, "application_context"), FieldValue::U8(14));
    assert_eq!(
        buf.resolve_display_name(layer, "application_context_name"),
        Some("infoRetrieval")
    );
    assert_eq!(
        *map_field(&buf, "application_context_version"),
        FieldValue::U8(3)
    );
    let cs = components(&buf);
    assert_eq!(cs.len(), 1);
    assert_eq!(*get(cs[0], "component_type"), FieldValue::U8(1));
    assert_eq!(display(cs[0], "component_type"), Some("invoke"));
    assert_eq!(*get(cs[0], "invoke_id"), FieldValue::I32(1));
    assert_eq!(*get(cs[0], "operation"), FieldValue::I32(56));
    assert_eq!(display(cs[0], "operation"), Some("sendAuthenticationInfo"));
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    assert_eq!(
        *get(cs[0], "number_of_requested_vectors"),
        FieldValue::I32(5)
    );
    // The raw parameter is kept alongside the decoded fields.
    assert!(has(cs[0], "parameter"));
    // The layer spans the dialogue portion (application context) and the
    // component portion, so every field lies inside it.
    let layer = map_layer(&buf);
    for f in buf.layer_fields(layer) {
        assert!(
            f.range.start >= layer.range.start && f.range.end <= layer.range.end,
            "{} {:?} outside {:?}",
            f.name(),
            f.range,
            layer.range
        );
    }
}

#[test]
fn parse_sai_v2_imsi() {
    // Version 2: the argument is the IMSI itself.
    let data = begin(&ac(14, 2), 56, Some(tlv(0x04, IMSI)));
    let (buf, _) = dissect(&data);
    assert_eq!(
        *map_field(&buf, "application_context_version"),
        FieldValue::U8(2)
    );
    let cs = components(&buf);
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    assert!(!has(cs[0], "number_of_requested_vectors"));
}

#[test]
fn parse_update_location() {
    // UpdateLocationArg ::= SEQUENCE { imsi IMSI, msc-Number [1]
    // ISDN-AddressString, vlr-Number ISDN-AddressString, lmsi [10] LMSI, ... }
    let arg = tlv(
        0x30,
        &cat(&[
            tlv(0x04, IMSI),
            tlv(0x81, MSISDN),
            tlv(0x04, MSISDN),
            tlv(0x8a, &[1, 2, 3, 4]),
        ]),
    );
    let data = begin(&ac(1, 3), 2, Some(arg));
    let (buf, _) = dissect(&data);
    assert_eq!(
        buf.resolve_display_name(map_layer(&buf), "application_context_name"),
        Some("networkLocUp")
    );
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("updateLocation"));
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    let msc = object(&buf, cs[0], "msc_number");
    assert_eq!(*get(msc, "extension"), FieldValue::U8(1));
    assert_eq!(*get(msc, "nature_of_address"), FieldValue::U8(1));
    assert_eq!(
        display(msc, "nature_of_address"),
        Some("international number")
    );
    assert_eq!(*get(msc, "numbering_plan"), FieldValue::U8(1));
    assert_eq!(
        display(msc, "numbering_plan"),
        Some("ISDN/Telephony Numbering Plan (Rec ITU-T E.164)")
    );
    assert_eq!(digits(&buf, msc, "digits"), MSISDN_DIGITS);
    let vlr = object(&buf, cs[0], "vlr_number");
    assert_eq!(digits(&buf, vlr, "digits"), MSISDN_DIGITS);
    assert_eq!(*get(cs[0], "lmsi"), FieldValue::Bytes(&[1, 2, 3, 4]));

    // UpdateLocationRes ::= SEQUENCE { hlr-Number ISDN-AddressString, ... }
    let rr = tlv(
        0xa2,
        &cat(&[
            tlv(0x02, &[0x01]),
            tlv(
                0x30,
                &cat(&[tlv(0x02, &[0x02]), tlv(0x30, &tlv(0x04, MSISDN))]),
            ),
        ]),
    );
    let data = end(&[rr]);
    let (buf, _) = dissect(&data);
    // No dialogue portion: the application context is absent.
    assert!(
        buf.field_by_name(map_layer(&buf), "application_context")
            .is_none()
    );
    let cs = components(&buf);
    assert_eq!(display(cs[0], "component_type"), Some("returnResultLast"));
    let hlr = object(&buf, cs[0], "hlr_number");
    assert_eq!(digits(&buf, hlr, "digits"), MSISDN_DIGITS);
}

#[test]
fn parse_update_gprs_location() {
    let arg = tlv(
        0x30,
        &cat(&[
            tlv(0x04, IMSI),
            tlv(0x04, MSISDN),
            tlv(0x04, &[0x04, 10, 0, 0, 1]),
        ]),
    );
    let data = begin(&ac(32, 3), 23, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("updateGprsLocation"));
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    assert!(has(cs[0], "sgsn_number"));
}

#[test]
fn parse_cancel_location() {
    // CancelLocationArg ::= [3] SEQUENCE { identity Identity, ... }
    let arg = tlv(0xa3, &tlv(0x04, IMSI));
    let data = begin(&ac(2, 3), 3, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("cancelLocation"));
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    // Earlier versions: the Identity itself, imsi-WithLMSI or a bare IMSI.
    let arg = tlv(0x30, &cat(&[tlv(0x04, IMSI), tlv(0x04, &[9, 9, 9, 9])]));
    let data = begin(&ac(2, 2), 3, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    assert_eq!(*get(cs[0], "lmsi"), FieldValue::Bytes(&[9, 9, 9, 9]));
    let data = begin(&ac(2, 1), 3, Some(tlv(0x04, IMSI)));
    let (buf, _) = dissect(&data);
    assert_eq!(digits(&buf, components(&buf)[0], "imsi"), IMSI_DIGITS);
    // [3] with imsi-WithLMSI.
    let arg = tlv(
        0xa3,
        &tlv(0x30, &cat(&[tlv(0x04, IMSI), tlv(0x04, &[9, 9, 9, 9])])),
    );
    let data = begin(&ac(2, 3), 3, Some(arg));
    let (buf, _) = dissect(&data);
    assert!(has(components(&buf)[0], "lmsi"));
}

#[test]
fn parse_purge_ms() {
    // PurgeMS-Arg ::= [3] SEQUENCE { imsi IMSI, vlr-Number [0]
    // ISDN-AddressString OPTIONAL, sgsn-Number [1] ... OPTIONAL, ... }
    let arg = tlv(
        0xa3,
        &cat(&[tlv(0x04, IMSI), tlv(0x80, MSISDN), tlv(0x81, MSISDN)]),
    );
    let data = begin(&ac(27, 3), 67, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("purgeMS"));
    assert!(has(cs[0], "vlr_number"));
    assert!(has(cs[0], "sgsn_number"));
    // Version 2: SEQUENCE { imsi IMSI, vlr-Number ISDN-AddressString }.
    let arg = tlv(0x30, &cat(&[tlv(0x04, IMSI), tlv(0x04, MSISDN)]));
    let data = begin(&ac(27, 2), 67, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    let imsis = cs[0].iter().filter(|f| f.name() == "imsi").count();
    assert_eq!(imsis, 1);
    let vlr = object(&buf, cs[0], "vlr_number");
    assert_eq!(digits(&buf, vlr, "digits"), MSISDN_DIGITS);
}

#[test]
fn parse_insert_subscriber_data() {
    // InsertSubscriberDataArg ::= SEQUENCE { imsi [0] IMSI OPTIONAL,
    // COMPONENTS OF SubscriberData (msisdn [1] ...), ... }
    let arg = tlv(
        0x30,
        &cat(&[tlv(0x80, IMSI), tlv(0x81, MSISDN), tlv(0x82, &[0x00])]),
    );
    let data = begin(&ac(16, 3), 7, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("insertSubscriberData"));
    assert_eq!(digits(&buf, cs[0], "imsi"), IMSI_DIGITS);
    let msisdn = object(&buf, cs[0], "msisdn");
    assert_eq!(digits(&buf, msisdn, "digits"), MSISDN_DIGITS);
}

#[test]
fn parse_provide_roaming_number() {
    let arg = tlv(
        0x30,
        &cat(&[tlv(0x80, IMSI), tlv(0x81, MSISDN), tlv(0x82, MSISDN)]),
    );
    let data = begin(&ac(3, 3), 4, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("provideRoamingNumber"));
    assert!(has(cs[0], "imsi") && has(cs[0], "msc_number") && has(cs[0], "msisdn"));
}

#[test]
fn parse_sri_for_sm() {
    // RoutingInfoForSM-Arg ::= SEQUENCE { msisdn [0], sm-RP-PRI [1] BOOLEAN,
    // serviceCentreAddress [2] AddressString, ... }
    let arg = tlv(
        0x30,
        &cat(&[tlv(0x80, MSISDN), tlv(0x81, &[0xff]), tlv(0x82, MSISDN)]),
    );
    let data = begin(&ac(20, 3), 45, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("sendRoutingInfoForSM"));
    assert!(has(cs[0], "msisdn"));
    assert!(has(cs[0], "service_centre_address"));
}

#[test]
fn parse_forward_sm() {
    // MO-ForwardSM-Arg ::= SEQUENCE { sm-RP-DA SM-RP-DA, sm-RP-OA SM-RP-OA,
    // sm-RP-UI SignalInfo, ... }; SM-RP-DA ::= CHOICE { imsi [0], lmsi [1],
    // serviceCentreAddressDA [4], noSM-RP-DA [5] }; SM-RP-OA ::= CHOICE {
    // msisdn [2], serviceCentreAddressOA [4], noSM-RP-OA [5] }.
    let tpdu = [0x01, 0x00, 0x0b, 0x91];
    let mo = tlv(
        0x30,
        &cat(&[tlv(0x84, MSISDN), tlv(0x82, MSISDN), tlv(0x04, &tpdu)]),
    );
    let data = begin(&ac(21, 3), 46, Some(mo));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "operation"), Some("mo-ForwardSM"));
    let da = object(&buf, cs[0], "sm_rp_da");
    assert!(has(da, "service_centre_address"));
    let oa = object(&buf, cs[0], "sm_rp_oa");
    assert_eq!(
        digits(&buf, object(&buf, oa, "msisdn"), "digits"),
        MSISDN_DIGITS
    );
    assert_eq!(*get(cs[0], "sm_rp_ui"), FieldValue::Bytes(&tpdu));

    for (da, key) in [
        (tlv(0x80, IMSI), "imsi"),
        (tlv(0x81, &[1, 2, 3, 4]), "lmsi"),
        (tlv(0x85, &[]), "no_address"),
    ] {
        let mt = tlv(
            0x30,
            &cat(&[da, tlv(0x85, &[]), tlv(0x04, &tpdu), tlv(0x05, &[])]),
        );
        let data = begin(&ac(25, 3), 44, Some(mt));
        let (buf, _) = dissect(&data);
        let cs = components(&buf);
        assert_eq!(display(cs[0], "operation"), Some("mt-ForwardSM"));
        assert!(has(object(&buf, cs[0], "sm_rp_da"), key), "{key}");
        assert!(has(object(&buf, cs[0], "sm_rp_oa"), "no_address"));
    }
    // An unknown SM-RP-DA alternative is left out of the object.
    let mt = tlv(
        0x30,
        &cat(&[tlv(0x86, &[1]), tlv(0x85, &[]), tlv(0x04, &tpdu)]),
    );
    let data = begin(&ac(25, 3), 44, Some(mt));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert!(object(&buf, cs[0], "sm_rp_da").is_empty());
}

#[test]
fn parse_return_error() {
    let re = tlv(0xa3, &cat(&[tlv(0x02, &[0x01]), tlv(0x02, &[0x22])]));
    let re_legacy = tlv(0xa3, &cat(&[tlv(0x02, &[0x02]), tlv(0x02, &[0x18])]));
    let rej = tlv(0xa4, &cat(&[tlv(0x02, &[0x03]), tlv(0x80, &[0x00])]));
    let data = end(&[re, re_legacy, rej]);
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(*get(cs[0], "error"), FieldValue::I32(0x22));
    assert_eq!(display(cs[0], "error"), Some("systemFailure"));
    assert_eq!(display(cs[1], "error"), Some("noRadioResourceAvailable"));
    assert_eq!(display(cs[2], "component_type"), Some("reject"));
    assert_eq!(cs[2].len(), 2);
}

#[test]
fn parse_non_map_context() {
    // A context outside {0 4 0 0 1 0} (e.g. CAP) is not a MAP context.
    let data = begin(&[0x04, 0x00, 0x00, 0x01, 0x15, 0x03, 0x04], 0, None);
    let (buf, _) = dissect(&data);
    assert!(
        buf.field_by_name(map_layer(&buf), "application_context")
            .is_none()
    );
    // A MAP-prefixed context with a multi-octet arc is not decoded either.
    let data = begin(&[0x04, 0x00, 0x00, 0x01, 0x00, 0x81, 0x00, 0x03], 2, None);
    let (buf, _) = dissect(&data);
    assert!(
        buf.field_by_name(map_layer(&buf), "application_context")
            .is_none()
    );
}

#[test]
fn malformed_arguments_raw() {
    for (opcode, arg) in [
        // Not a SEQUENCE.
        (2u8, tlv(0x04, IMSI)),
        // SEQUENCE with no known elements.
        (7, tlv(0x30, &tlv(0x99, &[0x01]))),
        // Unsupported operation.
        (22, tlv(0x30, &tlv(0x80, MSISDN))),
        // SAI with an unexpected tag.
        (56, tlv(0x05, &[])),
        // Forward SM that is not a SEQUENCE.
        (46, tlv(0x04, &[1])),
        // Cancel Location with a NULL argument.
        (3, tlv(0x05, &[])),
        // Purge MS, Insert Subscriber Data, Provide Roaming Number and
        // Send Routing Info for SM that are not a SEQUENCE.
        (67, tlv(0x05, &[])),
        (7, tlv(0x05, &[])),
        (4, tlv(0x05, &[])),
        (45, tlv(0x05, &[])),
        // Purge MS (version 2) with a third, unexpected OCTET STRING.
        (
            67,
            tlv(
                0x30,
                &cat(&[tlv(0x04, IMSI), tlv(0x04, MSISDN), tlv(0x04, &[1])]),
            ),
        ),
    ] {
        let data = begin(&ac(1, 3), opcode, Some(arg.clone()));
        let (buf, _) = dissect(&data);
        let cs = components(&buf);
        assert_eq!(
            *get(cs[0], "parameter"),
            FieldValue::Bytes(&arg),
            "{opcode}"
        );
    }
    // Invoke without a parameter: no parameter field.
    let data = begin(&ac(1, 3), 2, None);
    let (buf, _) = dissect(&data);
    assert!(!has(components(&buf)[0], "parameter"));
    // Empty AddressString: the object only holds nothing decodable.
    let arg = tlv(
        0x30,
        &cat(&[tlv(0x04, IMSI), tlv(0x81, &[]), tlv(0x04, MSISDN)]),
    );
    let data = begin(&ac(1, 3), 2, Some(arg));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert!(object(&buf, cs[0], "msc_number").is_empty());
}

#[test]
fn tbcd_digits() {
    let mut buf = DissectBuffer::new();
    for (bcd, want) in [
        (&[0x21, 0x43][..], "1234"),
        (&[0x21, 0xf3], "123"),
        (&[0xba, 0xdc, 0xfe], "*#abc"),
        (&[0xff], ""),
    ] {
        buf.clear();
        let r = push_tbcd(bcd, &mut buf);
        assert_eq!(
            &buf.scratch()[r.start as usize..r.end as usize],
            want.as_bytes()
        );
    }
}

#[test]
fn tcap_errors_and_layers() {
    let mut buf = DissectBuffer::new();
    assert!(matches!(
        MapDissector.dissect(&[0x62, 0x05], &mut buf, 0),
        Err(PacketError::Truncated { .. })
    ));
    assert!(buf.layers().is_empty());
    // A TC-Abort without dialogue or components emits the TCAP layer only.
    let data = tlv(0x67, &cat(&[tlv(0x49, &[1]), tlv(0x4a, &[0x01])]));
    let (buf, r) = dissect(&data);
    assert_eq!(r.bytes_consumed, data.len());
    let names: Vec<_> = buf.layers().iter().map(|l| l.name).collect();
    assert_eq!(names, ["TCAP"]);
    // Absolute offsets.
    let arg = tlv(0x30, &cat(&[tlv(0x80, IMSI), tlv(0x02, &[0x05])]));
    let data = begin(&ac(14, 3), 56, Some(arg));
    let mut buf = DissectBuffer::new();
    MapDissector.dissect(&data, &mut buf, 100).unwrap();
    assert_eq!(buf.layers()[0].range, 100..100 + data.len());
    let map = buf.layer_by_name("MAP").unwrap();
    assert!(map.range.start >= 100 && map.range.end <= 100 + data.len());
}

/// Number of codes in `0..=max` that `name` knows.
fn known<T: TryFrom<u32> + Copy>(max: u32, name: impl Fn(T) -> Option<&'static str>) -> usize {
    (0..=max)
        .filter_map(|c| T::try_from(c).ok())
        .filter(|c| name(*c).is_some())
        .count()
}

/// Calls every `display_fn` in the tree with values of the declared type and
/// with a mismatched type.
fn exercise_display_fns(fds: &'static [FieldDescriptor], depth: usize) {
    for fd in fds {
        if let Some(display) = fd.display_fn {
            for v in 0u8..16 {
                let value = match fd.field_type {
                    FieldType::U8 => FieldValue::U8(v),
                    FieldType::I32 => FieldValue::I32(i32::from(v)),
                    _ => FieldValue::Object(0..0),
                };
                let _ = display(&value, &[]);
            }
            assert_eq!(display(&FieldValue::Bytes(&[]), &[]), None, "{}", fd.name);
        }
        if let (Some(children), true) = (fd.children, depth < 4) {
            exercise_display_fns(children, depth + 1);
        }
    }
}

/// Calls `format_digits` and returns what it writes.
fn format(value: &FieldValue<'_>, scratch: &[u8]) -> String {
    let ctx = FormatContext {
        packet_data: &[],
        scratch,
        layer_range: 0..0,
        field_range: 0..0,
    };
    let mut out = Vec::new();
    format_digits(value, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn format_and_component_display() {
    assert_eq!(format(&FieldValue::Scratch(1..3), b"x12y"), "\"12\"");
    // Out-of-range scratch and other value types write an empty string.
    assert_eq!(format(&FieldValue::Scratch(2..9), b"x12y"), "\"\"");
    assert_eq!(format(&FieldValue::Bytes(&[0x21]), &[]), "\"\"");
    // Descriptor constructors used at run time.
    assert_eq!(digits_fd("d", "D").field_type, FieldType::Bytes);
    assert_eq!(address_fd("a", "A").children, Some(ADDRESS_FIELDS));
    // The component display names the operation, else the error.
    let display = FD_COMPONENT.display_fn.unwrap();
    let field = |name: usize, value: FieldValue<'static>| Field {
        descriptor: &COMPONENT_FIELDS[name],
        value,
        range: 0..0,
    };
    let find = |name: &str| {
        COMPONENT_FIELDS
            .iter()
            .position(|f| f.name == name)
            .unwrap()
    };
    let (op, err) = (find("operation"), find("error"));
    assert_eq!(
        display(&FieldValue::Object(0..0), &[field(op, FieldValue::I32(56))]),
        operation_name(56)
    );
    assert_eq!(
        display(&FieldValue::Object(0..0), &[field(err, FieldValue::I32(1))]),
        error_name(1)
    );
    assert_eq!(
        display(&FieldValue::Object(0..0), &[field(op, FieldValue::U8(1))]),
        None
    );
}

#[test]
fn name_tables() {
    exercise_display_fns(FIELD_DESCRIPTORS, 0);
    // TS 29.002, clauses 17.6.1-17.6.8: 70 operations; clause 17.5: 11
    // reserved legacy operation codes.
    assert_eq!(known(255, |c: u32| operation_name(c as i32)), 81);
    // Clause 17.6.6: 55 errors; clause 17.5: 3 reserved legacy error codes.
    assert_eq!(known(255, |c: u32| error_name(c as i32)), 58);
    // Clause 17.3.3: application contexts 1-47 except 30 and 40.
    assert_eq!(known(255, application_context_name), 45);
    assert_eq!(known(255, component_type_name), 5);
    assert_eq!(known(15, nature_of_address_name), 8);
    assert_eq!(known(15, numbering_plan_name), 8);
    assert_eq!(operation_name(-1), None);
    let d = MapDissector;
    assert_eq!(d.name(), "Mobile Application Part");
    assert_eq!(d.short_name(), "MAP");
    assert_eq!(d.references()[0].id, "3GPP TS 29.002");
    assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    assert_eq!(d.field_descriptors().len(), FD_COMPONENTS + 1);
}

#[test]
fn visit_sub_dissectors_lists_embedded_layers() {
    let mut names = Vec::new();
    MapDissector.visit_sub_dissectors(&mut |d| names.push(d.short_name()));
    assert_eq!(names, ["TCAP"]);
}
