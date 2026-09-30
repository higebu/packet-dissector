//! # ITU-T Q.773 (TCAP) Coverage
//!
//! | Clause      | Description                                        | Test                                   |
//! |-------------|----------------------------------------------------|----------------------------------------|
//! | 3.1         | Begin: OTID, dialogue portion, Invoke              | parse_begin_aarq_invoke                |
//! | 3.1         | Continue: OTID + DTID, ReturnResultLast            | parse_continue_return_result           |
//! | 3.1         | End: DTID, AARE, ReturnError, ReturnResultNotLast  | parse_end_aare_return_error            |
//! | 3.1         | Abort with P-Abort cause                           | parse_abort_p_abort_cause              |
//! | 3.1         | Abort with u-abort ABRT-apdu                       | parse_abort_abrt                       |
//! | 3.1         | Unidirectional with AUDT                           | parse_unidirectional_audt              |
//! | 3.1         | Reject (derivable / not derivable invoke ID)       | parse_reject                           |
//! | 3.1         | Invoke with linked ID and global opcode            | parse_invoke_linked_global             |
//! | 3.1         | Malformed / unknown components                     | parse_malformed_components             |
//! | 3.1         | Unknown message type                               | reject_unknown_message_type            |
//! | 4.1.2.3     | Indefinite length message                          | parse_indefinite_length                |
//! | 4.1.2.3     | Truncated / malformed message                      | truncated_and_malformed                |
//! | 4.2.3       | Dialogue with user-defined abstract syntax         | parse_user_defined_dialogue            |
//! | 3.1, 3.2    | Name tables and display functions                  | names_and_display                      |

use super::*;

/// Encode a BER element with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    match content.len() {
        n if n < 0x80 => v.push(n as u8),
        n if n < 0x100 => v.extend_from_slice(&[0x81, n as u8]),
        n => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    v.extend_from_slice(content);
    v
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// OBJECT IDENTIFIER element.
fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

/// MAP application context networkLocUp version 3
/// {0 4 0 0 1 0 1 3} (TS 29.002, clause 17.3.2).
const AC_NETWORK_LOC_UP_V3: &[u8] = &[0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03];

/// Dialogue portion carrying `pdu` with the given abstract syntax.
fn dialogue(as_id: &[u8], pdu: Vec<u8>) -> Vec<u8> {
    tlv(0x6b, &tlv(0x28, &cat(&[oid(as_id), tlv(0xa0, &pdu)])))
}

/// AARQ-apdu with protocol version and application context name.
fn aarq(ac: &[u8]) -> Vec<u8> {
    tlv(0x60, &cat(&[tlv(0x80, &[0x07, 0x80]), tlv(0xa1, &oid(ac))]))
}

fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
    let mut buf = DissectBuffer::new();
    let r = TcapDissector.dissect(data, &mut buf, 0).unwrap();
    (buf, r)
}

fn field<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a FieldValue<'a> {
    &buf.field_by_name(&buf.layers()[0], name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .value
}

fn object<'a>(buf: &'a DissectBuffer<'a>, name: &str) -> &'a [Field<'a>] {
    let FieldValue::Object(r) = field(buf, name) else {
        panic!("{name} is not an object")
    };
    buf.nested_fields(r)
}

fn components<'a>(buf: &'a DissectBuffer<'a>) -> Vec<&'a [Field<'a>]> {
    let FieldValue::Array(r) = field(buf, "components") else {
        panic!("components is not an array")
    };
    buf.nested_fields(r)
        .iter()
        .filter_map(|f| match &f.value {
            FieldValue::Object(cr) if f.name() == "component" => Some(buf.nested_fields(cr)),
            _ => None,
        })
        .collect()
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

fn display(fields: &[Field<'_>], name: &str) -> Option<&'static str> {
    let f = fields.iter().find(|f| f.name() == name)?;
    (f.descriptor.display_fn?)(&f.value, fields)
}

fn oid_string(v: &FieldValue<'_>) -> String {
    let ctx = FormatContext {
        packet_data: &[],
        scratch: &[],
        layer_range: 0..0,
        field_range: 0..0,
    };
    let mut out = Vec::new();
    format_oid(v, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// Begin { otid, dialogue(AARQ networkLocUp v3), components { invoke id 1,
/// opcode 2 (updateLocation), parameter SEQUENCE { 04 01 99 } } }.
fn begin_message() -> Vec<u8> {
    let invoke = tlv(
        0xa1,
        &cat(&[
            tlv(0x02, &[0x01]),
            tlv(0x02, &[0x02]),
            tlv(0x30, &tlv(0x04, &[0x99])),
        ]),
    );
    tlv(
        0x62,
        &cat(&[
            tlv(0x48, &[0x01, 0x02, 0x03, 0x04]),
            dialogue(DIALOGUE_AS_ID, aarq(AC_NETWORK_LOC_UP_V3)),
            tlv(0x6c, &invoke),
        ]),
    )
}

#[test]
fn parse_begin_aarq_invoke() {
    let data = begin_message();
    let (buf, r) = dissect(&data);
    assert_eq!(r.bytes_consumed, data.len());
    assert_eq!(r.next, DispatchHint::End);
    let layer = &buf.layers()[0];
    assert_eq!(layer.name, "TCAP");
    assert_eq!(layer.range, 0..data.len());
    assert_eq!(*field(&buf, "message_type"), FieldValue::U8(2));
    assert_eq!(
        buf.resolve_display_name(layer, "message_type_name"),
        Some("Begin")
    );
    assert_eq!(
        *field(&buf, "otid"),
        FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04])
    );
    let d = object(&buf, "dialogue");
    assert_eq!(oid_string(get(d, "dialogue_as_id")), "\"0.0.17.773.1.1.1\"");
    assert_eq!(*get(d, "pdu_type"), FieldValue::U8(0));
    assert_eq!(display(d, "pdu_type"), Some("dialogueRequest (AARQ-apdu)"));
    assert_eq!(
        *get(d, "protocol_version"),
        FieldValue::Bytes(&[0x07, 0x80])
    );
    assert_eq!(
        oid_string(get(d, "application_context_name")),
        "\"0.4.0.0.1.0.1.3\""
    );
    let cs = components(&buf);
    assert_eq!(cs.len(), 1);
    assert_eq!(*get(cs[0], "component_type"), FieldValue::U8(1));
    assert_eq!(display(cs[0], "component_type"), Some("invoke"));
    assert_eq!(*get(cs[0], "invoke_id"), FieldValue::I32(1));
    assert_eq!(*get(cs[0], "opcode"), FieldValue::I32(2));
    assert_eq!(
        *get(cs[0], "parameter"),
        FieldValue::Bytes(&[0x30, 0x03, 0x04, 0x01, 0x99])
    );

    // The view exposes the same information to TC-users.
    let msg = Message::parse(&data).unwrap();
    assert_eq!(msg.application_context_name(), Some(AC_NETWORK_LOC_UP_V3));
    let c = msg.components().next().unwrap();
    assert_eq!(
        c.opcode,
        Some(Code::Local(Int {
            value: 2,
            range: c.opcode.as_ref().map_or(0..0, |o| match o {
                Code::Local(i) => i.range.clone(),
                Code::Global(r) => r.clone(),
            })
        }))
    );
}

#[test]
fn parse_continue_return_result() {
    let rr = tlv(
        0xa2,
        &cat(&[
            tlv(0x02, &[0x01]),
            tlv(0x30, &cat(&[tlv(0x02, &[0x38]), tlv(0x30, &[])])),
        ]),
    );
    let rr_empty = tlv(0xa2, &tlv(0x02, &[0x02]));
    let data = tlv(
        0x65,
        &cat(&[
            tlv(0x48, &[0xaa]),
            tlv(0x49, &[0xbb, 0xcc]),
            tlv(0x6c, &cat(&[rr, rr_empty])),
        ]),
    );
    let (buf, _) = dissect(&data);
    assert_eq!(*field(&buf, "otid"), FieldValue::Bytes(&[0xaa]));
    assert_eq!(*field(&buf, "dtid"), FieldValue::Bytes(&[0xbb, 0xcc]));
    let cs = components(&buf);
    assert_eq!(cs.len(), 2);
    assert_eq!(display(cs[0], "component_type"), Some("returnResultLast"));
    assert_eq!(*get(cs[0], "opcode"), FieldValue::I32(0x38));
    assert_eq!(*get(cs[0], "parameter"), FieldValue::Bytes(&[0x30, 0x00]));
    assert_eq!(*get(cs[1], "invoke_id"), FieldValue::I32(2));
    assert!(!has(cs[1], "opcode"));
}

#[test]
fn parse_end_aare_return_error() {
    let aare = tlv(
        0x61,
        &cat(&[
            tlv(0x80, &[0x07, 0x80]),
            tlv(0xa1, &oid(AC_NETWORK_LOC_UP_V3)),
            tlv(0xa2, &tlv(0x02, &[0x01])),
            tlv(0xa3, &tlv(0xa1, &tlv(0x02, &[0x02]))),
            tlv(0xbe, &tlv(0x28, &[])),
        ]),
    );
    let re = tlv(0xa3, &cat(&[tlv(0x02, &[0x05]), tlv(0x02, &[0x1b])]));
    let rrnl = tlv(
        0xa7,
        &cat(&[tlv(0x02, &[0x06]), tlv(0x30, &tlv(0x02, &[0x07]))]),
    );
    let data = tlv(
        0x64,
        &cat(&[
            tlv(0x49, &[0x01]),
            dialogue(DIALOGUE_AS_ID, aare),
            tlv(0x6c, &cat(&[re, rrnl])),
        ]),
    );
    let (buf, _) = dissect(&data);
    assert_eq!(
        buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
        Some("End")
    );
    let d = object(&buf, "dialogue");
    assert_eq!(display(d, "pdu_type"), Some("dialogueResponse (AARE-apdu)"));
    assert_eq!(*get(d, "result"), FieldValue::I32(1));
    assert_eq!(display(d, "result"), Some("reject-permanent"));
    assert_eq!(*get(d, "result_source"), FieldValue::U8(1));
    assert_eq!(display(d, "result_source"), Some("dialogue-service-user"));
    assert_eq!(
        display(d, "diagnostic"),
        Some("application-context-name-not-supported")
    );
    assert_eq!(
        *get(d, "user_information"),
        FieldValue::Bytes(&[0xbe, 0x02, 0x28, 0x00])
    );
    let cs = components(&buf);
    assert_eq!(display(cs[0], "component_type"), Some("returnError"));
    assert_eq!(*get(cs[0], "error_code"), FieldValue::I32(0x1b));
    assert!(!has(cs[0], "parameter"));
    assert_eq!(
        display(cs[1], "component_type"),
        Some("returnResultNotLast")
    );
    assert_eq!(*get(cs[1], "opcode"), FieldValue::I32(7));
}

#[test]
fn parse_abort_p_abort_cause() {
    let data = tlv(0x67, &cat(&[tlv(0x49, &[0x01]), tlv(0x4a, &[0x01])]));
    let (buf, _) = dissect(&data);
    assert_eq!(*field(&buf, "p_abort_cause"), FieldValue::I32(1));
    assert_eq!(
        buf.resolve_display_name(&buf.layers()[0], "p_abort_cause_name"),
        Some("unrecognizedTransactionID")
    );
}

#[test]
fn parse_abort_abrt() {
    let abrt = tlv(0x64, &tlv(0x80, &[0x01]));
    let data = tlv(
        0x67,
        &cat(&[tlv(0x49, &[0x01]), dialogue(DIALOGUE_AS_ID, abrt)]),
    );
    let (buf, _) = dissect(&data);
    let d = object(&buf, "dialogue");
    assert_eq!(display(d, "pdu_type"), Some("dialogueAbort (ABRT-apdu)"));
    assert_eq!(*get(d, "abort_source"), FieldValue::I32(1));
    assert_eq!(
        display(d, "abort_source"),
        Some("dialogue-service-provider")
    );
}

#[test]
fn parse_unidirectional_audt() {
    let invoke = tlv(0xa1, &cat(&[tlv(0x02, &[0x00]), tlv(0x02, &[0x2f])]));
    let data = tlv(
        0x61,
        &cat(&[
            dialogue(UNIDIALOGUE_AS_ID, aarq(AC_NETWORK_LOC_UP_V3)),
            tlv(0x6c, &invoke),
        ]),
    );
    let (buf, _) = dissect(&data);
    let d = object(&buf, "dialogue");
    assert_eq!(*get(d, "unidialogue"), FieldValue::U8(1));
    assert_eq!(display(d, "pdu_type"), Some("unidialoguePDU (AUDT-apdu)"));
    assert!(has(d, "application_context_name"));
    assert_eq!(*get(components(&buf)[0], "opcode"), FieldValue::I32(0x2f));
}

#[test]
fn parse_user_defined_dialogue() {
    // EXTERNAL with a user-defined direct reference and octet-aligned data.
    let ext = tlv(0x28, &cat(&[oid(&[0x2a, 0x03]), tlv(0x81, &[0x01, 0x02])]));
    let data = tlv(0x67, &cat(&[tlv(0x49, &[0x01]), tlv(0x6b, &ext)]));
    let (buf, _) = dissect(&data);
    let d = object(&buf, "dialogue");
    assert_eq!(oid_string(get(d, "dialogue_as_id")), "\"1.2.3\"");
    assert!(!has(d, "pdu_type"));
    assert_eq!(
        *get(d, "user_information"),
        FieldValue::Bytes(&[0x81, 0x02, 0x01, 0x02])
    );
    // A dialogue portion without an EXTERNAL.
    let data = tlv(0x67, &cat(&[tlv(0x49, &[0x01]), tlv(0x6b, &[0x05, 0x00])]));
    let (buf, _) = dissect(&data);
    assert_eq!(object(&buf, "dialogue").len(), 0);
    // A structured dialogue whose [0] does not hold an APPLICATION PDU.
    let ext = tlv(
        0x28,
        &cat(&[oid(DIALOGUE_AS_ID), tlv(0xa0, &tlv(0x30, &[]))]),
    );
    let data = tlv(0x67, &cat(&[tlv(0x49, &[0x01]), tlv(0x6b, &ext)]));
    let (buf, _) = dissect(&data);
    let d = object(&buf, "dialogue");
    assert!(!has(d, "pdu_type"));
    assert!(has(d, "user_information"));
}

#[test]
fn parse_reject() {
    let rej1 = tlv(0xa4, &cat(&[tlv(0x02, &[0x03]), tlv(0x81, &[0x01])]));
    let rej2 = tlv(0xa4, &cat(&[tlv(0x05, &[]), tlv(0x80, &[0x02])]));
    let data = tlv(
        0x64,
        &cat(&[tlv(0x49, &[0x01]), tlv(0x6c, &cat(&[rej1, rej2]))]),
    );
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(display(cs[0], "component_type"), Some("reject"));
    assert_eq!(*get(cs[0], "invoke_id"), FieldValue::I32(3));
    assert_eq!(*get(cs[0], "problem_type"), FieldValue::U8(1));
    assert_eq!(display(cs[0], "problem_type"), Some("invokeProblem"));
    assert_eq!(
        display(cs[0], "problem_code"),
        Some("unrecognizedOperation")
    );
    assert!(!has(cs[1], "invoke_id"));
    assert_eq!(
        display(cs[1], "problem_code"),
        Some("badlyStructuredComponent")
    );
}

#[test]
fn parse_invoke_linked_global() {
    let invoke = tlv(
        0xa1,
        &cat(&[
            tlv(0x02, &[0xff]),
            tlv(0x80, &[0x05]),
            oid(&[0x2a, 0x03, 0x04]),
        ]),
    );
    let re = tlv(
        0xa3,
        &cat(&[tlv(0x02, &[0x01]), oid(&[0x2a]), tlv(0x30, &[])]),
    );
    let data = tlv(
        0x64,
        &cat(&[tlv(0x49, &[0x01]), tlv(0x6c, &cat(&[invoke, re]))]),
    );
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(*get(cs[0], "invoke_id"), FieldValue::I32(-1));
    assert_eq!(*get(cs[0], "linked_id"), FieldValue::I32(5));
    assert_eq!(oid_string(get(cs[0], "opcode_global")), "\"1.2.3.4\"");
    assert!(!has(cs[0], "parameter"));
    assert_eq!(oid_string(get(cs[1], "error_code_global")), "\"1.2\"");
    assert!(has(cs[1], "parameter"));
}

#[test]
fn parse_malformed_components() {
    let comps = cat(&[
        // Unknown component tag: only the type is reported.
        tlv(0xa5, &tlv(0x02, &[0x01])),
        // Primitive element: type 0.
        tlv(0x81, &[0x01]),
        // Invoke without invoke ID.
        tlv(0xa1, &tlv(0x04, &[0x01])),
        // Invoke whose opcode is not INTEGER / OID: no parameter taken.
        tlv(0xa1, &cat(&[tlv(0x02, &[0x01]), tlv(0x04, &[0x01])])),
        // Return Error without an error code.
        tlv(0xa3, &cat(&[tlv(0x02, &[0x01]), tlv(0x30, &[])])),
        // Reject with a constructed problem.
        tlv(0xa4, &cat(&[tlv(0x02, &[0x01]), tlv(0xa0, &[])])),
        // Truncated element: iteration stops.
        vec![0xa1, 0x10, 0x02],
    ]);
    let data = tlv(0x64, &cat(&[tlv(0x49, &[0x01]), tlv(0x6c, &comps)]));
    let (buf, _) = dissect(&data);
    let cs = components(&buf);
    assert_eq!(cs.len(), 6);
    assert_eq!(*get(cs[0], "component_type"), FieldValue::U8(5));
    assert_eq!(cs[0].len(), 1);
    assert_eq!(*get(cs[1], "component_type"), FieldValue::U8(0));
    assert_eq!(cs[2].len(), 1);
    assert!(!has(cs[3], "opcode") && !has(cs[3], "parameter"));
    assert!(!has(cs[4], "error_code") && !has(cs[4], "parameter"));
    assert!(!has(cs[5], "problem_type"));
}

#[test]
fn parse_indefinite_length() {
    // Begin (indefinite) { otid, component portion (indefinite) { invoke } }
    let mut data = vec![0x62, 0x80];
    data.extend(tlv(0x48, &[0x01]));
    data.extend_from_slice(&[0x6c, 0x80]);
    data.extend(tlv(0xa1, &cat(&[tlv(0x02, &[0x01]), tlv(0x02, &[0x2d])])));
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let (buf, r) = dissect(&data);
    assert_eq!(r.bytes_consumed, data.len());
    assert_eq!(*get(components(&buf)[0], "opcode"), FieldValue::I32(0x2d));
}

#[test]
fn truncated_and_malformed() {
    let data = begin_message();
    let mut buf = DissectBuffer::new();
    assert_eq!(
        TcapDissector.dissect(&data[..data.len() - 1], &mut buf, 0),
        Err(PacketError::Truncated {
            expected: data.len(),
            actual: data.len() - 1
        })
    );
    assert_eq!(
        TcapDissector.dissect(&[], &mut buf, 0),
        Err(PacketError::Truncated {
            expected: 1,
            actual: 0
        })
    );
    assert!(matches!(
        TcapDissector.dissect(&[0x62, 0xff], &mut buf, 0),
        Err(PacketError::InvalidHeader(_))
    ));
    assert!(buf.layers().is_empty());
    // Trailing octets after the message are not consumed.
    let mut data = begin_message();
    let len = data.len();
    data.push(0x00);
    let (_, r) = dissect(&data);
    assert_eq!(r.bytes_consumed, len);
    // Malformed / unknown elements in the transaction portion are skipped.
    let data = tlv(
        0x62,
        &cat(&[
            tlv(0x48, &[0x01]),
            tlv(0x48, &[0x02]),
            tlv(0x04, &[0x01]),
            tlv(0x6d, &[]),
        ]),
    );
    let (buf, _) = dissect(&data);
    assert_eq!(*field(&buf, "otid"), FieldValue::Bytes(&[0x01]));
    assert!(buf.field_by_name(&buf.layers()[0], "components").is_none());
    assert_eq!(
        Message::parse(&data).unwrap().application_context_name(),
        None
    );
    assert_eq!(Message::parse(&data).unwrap().components().count(), 0);
}

#[test]
fn reject_unknown_message_type() {
    for tag in [0x63, 0x30, 0x22] {
        let data = [tag, 0x00];
        let mut buf = DissectBuffer::new();
        assert_eq!(
            TcapDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "message_type",
                value: u32::from(tag)
            })
        );
    }
}

#[test]
fn dissect_at_nonzero_offset() {
    let data = begin_message();
    let mut buf = DissectBuffer::new();
    TcapDissector.dissect(&data, &mut buf, 50).unwrap();
    assert_eq!(buf.layers()[0].range, 50..50 + data.len());
    let otid = buf.field_by_name(&buf.layers()[0], "otid").unwrap();
    assert_eq!(otid.range, 54..58);
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
fn exercise_display_fns(fds: &'static [FieldDescriptor]) {
    for fd in fds {
        if let Some(display) = fd.display_fn {
            for v in 0u8..8 {
                let value = match fd.field_type {
                    FieldType::U8 => FieldValue::U8(v),
                    FieldType::I32 => FieldValue::I32(i32::from(v)),
                    _ => FieldValue::Object(0..0),
                };
                let _ = display(&value, &[]);
            }
            assert_eq!(display(&FieldValue::Bytes(&[]), &[]), None, "{}", fd.name);
        }
        if let Some(children) = fd.children {
            exercise_display_fns(children);
        }
    }
}

#[test]
fn names_and_display() {
    exercise_display_fns(FIELD_DESCRIPTORS);
    assert_eq!(known(255, message_type_name), 5);
    assert_eq!(known(255, |c: u32| p_abort_cause_name(c as i32)), 5);
    assert_eq!(known(255, component_type_name), 5);
    assert_eq!(known(255, problem_type_name), 4);
    let codes: usize = (0..=4u8)
        .map(|t| known(255, |c: u32| problem_code_name(t, c as i32)))
        .sum();
    assert_eq!(codes, 3 + 8 + 3 + 5);
    assert_eq!(known(255, |t: u8| dialogue_pdu_name(t, false)), 3);
    assert_eq!(known(255, |t: u8| dialogue_pdu_name(t, true)), 1);
    assert_eq!(known(255, |c: u32| associate_result_name(c as i32)), 2);
    assert_eq!(known(255, diagnostic_source_name), 2);
    assert_eq!(known(255, |c: u32| diagnostic_name(1, c as i32)), 3);
    assert_eq!(known(255, |c: u32| diagnostic_name(2, c as i32)), 3);
    assert_eq!(known(255, |c: u32| diagnostic_name(3, c as i32)), 2);
    assert_eq!(known(255, |c: u32| abort_source_name(c as i32)), 2);
    // OID formatting falls back to hex for malformed encodings.
    assert_eq!(oid_string(&FieldValue::Bytes(&[0x86])), "\"86\"");
    assert_eq!(oid_string(&FieldValue::U8(1)), "\"\"");
    let d = TcapDissector;
    assert_eq!(d.name(), "Transaction Capabilities Application Part");
    assert_eq!(d.field_descriptors().len(), FD_COMPONENTS + 1);
    assert_eq!(d.references()[0].id, "ITU-T Q.773");
    assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    assert_eq!(DIALOGUE_FIELDS.len(), DFD_UNIDIALOGUE + 1);
    assert_eq!(COMPONENT_FIELDS.len(), CFD_PROBLEM_CODE + 1);
}
