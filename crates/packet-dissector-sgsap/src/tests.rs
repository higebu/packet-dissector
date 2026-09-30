//! # 3GPP TS 29.118 (SGsAP) Coverage
//!
//! | Section  | Description                                          | Test                                  |
//! |----------|------------------------------------------------------|---------------------------------------|
//! | 9.1      | Message too short / message type only                | header                                |
//! | 9.2      | Message type names                                   | message_type_names                    |
//! | 9.3      | IE identifier names                                  | ie_type_names                         |
//! | 9.3a     | One-octet length indicator; truncated IE             | truncated_ie                          |
//! | 7.5      | Unknown IE kept raw and skipped                      | unknown_ie_skipped                    |
//! | 8.11     | SGsAP-LOCATION-UPDATE-REQUEST                        | location_update_request               |
//! | 8.14     | SGsAP-PAGING-REQUEST (CS call indicator, CLI)        | paging_request                        |
//! | 8.4      | SGsAP-DOWNLINK-UNITDATA (SMS CP-DATA container)      | downlink_unitdata                     |
//! | 8.18     | SGsAP-STATUS (SGs cause, erroneous message)          | status                                |
//! | 9.4.1    | CLI with octet 3a                                    | cli_with_presentation                 |
//! | 9.4.14   | Mobile identity (IMSI, IMEI, IMEISV, TMSI)           | mobile_identity                       |
//! | 9.4.x    | Value names, flags and time values                   | value_names_and_scalars               |
//! | 9.4.x    | Complete value name tables                           | value_name_tables                     |
//! | 9.4.x    | Wrong length values kept raw                         | wrong_length_values_kept_raw          |
//! | 9.4.13, 9.4.22 | Names as labels or legacy dotted strings       | names_format                          |

use super::*;
use packet_dissector_core::dissector::ProtocolLayer;
use packet_dissector_core::field::{Field, FieldValue, FormatContext};

fn dissect(data: &[u8]) -> DissectBuffer<'_> {
    let mut buf = DissectBuffer::new();
    let r = SgsapDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(r.bytes_consumed, data.len());
    buf
}

fn top<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Option<&'a Field<'pkt>> {
    buf.field_by_name(&buf.layers()[0], name)
}

fn ies<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<&'a [Field<'pkt>]> {
    let Some(FieldValue::Array(r)) = top(buf, "ies").map(|f| &f.value) else {
        return Vec::new();
    };
    buf.nested_fields(r)
        .iter()
        .filter_map(|f| match &f.value {
            FieldValue::Object(r) => Some(buf.nested_fields(r)),
            _ => None,
        })
        .collect()
}

fn ie<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, ie_type: u8) -> &'a [Field<'pkt>] {
    ies(buf)
        .into_iter()
        .find(|f| f[0].value == FieldValue::U8(ie_type))
        .unwrap_or_else(|| panic!("IE {ie_type} missing"))
}

fn field<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> &'a Field<'pkt> {
    fields
        .iter()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| panic!("{name} missing"))
}

fn get<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> &'a FieldValue<'pkt> {
    &field(fields, name).value
}

fn has(fields: &[Field<'_>], name: &str) -> bool {
    fields.iter().any(|f| f.name() == name)
}

/// Renders a field with its `format_fn`.
fn formatted(f: &Field<'_>) -> String {
    let ctx = FormatContext {
        packet_data: &[],
        scratch: &[],
        layer_range: 0..0,
        field_range: 0..0,
    };
    let mut out = Vec::new();
    (f.descriptor.format_fn.unwrap())(&f.value, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// Displayed name of a field value.
fn shown(f: &Field<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    (f.descriptor.display_fn.unwrap())(&f.value, siblings)
}

/// IMSI 001010123456789 (TS 29.018, Section 18.4.10: digit 1, odd parity,
/// type 001, then two digits per octet).
const IMSI: [u8; 10] = [0x01, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98];

fn msg(message_type: u8, ies: &[&[u8]]) -> Vec<u8> {
    let mut v = vec![message_type];
    for ie in ies {
        v.extend_from_slice(ie);
    }
    v
}

#[test]
fn header() {
    let mut buf = DissectBuffer::new();
    assert!(matches!(
        SgsapDissector.dissect(&[], &mut buf, 0),
        Err(PacketError::Truncated {
            expected: 1,
            actual: 0
        })
    ));
    assert!(buf.layers().is_empty());

    // A message type alone is a complete message (e.g. SGsAP-RESET-ACK
    // carries only a name, but the walk must not require any IE).
    let buf = dissect(&[0x16]);
    assert_eq!(buf.layers()[0].name, "SGsAP");
    let mt = top(&buf, "message_type").unwrap();
    assert_eq!(mt.value, FieldValue::U8(0x16));
    assert_eq!(shown(mt, &[]), Some("SGsAP-RESET-ACK"));
    assert!(top(&buf, "ies").is_none());

    // The offset is added to every range.
    let mut buf = DissectBuffer::new();
    SgsapDissector
        .dissect(&[0x01, 0x03, 0x04, 1, 2, 3, 4], &mut buf, 10)
        .unwrap();
    assert_eq!(buf.layers()[0].range, 10..17);
    assert_eq!(top(&buf, "message_type").unwrap().range, 10..11);
}

#[test]
fn message_type_names() {
    let expected: &[(u8, &str)] = &[
        (0x01, "SGsAP-PAGING-REQUEST"),
        (0x02, "SGsAP-PAGING-REJECT"),
        (0x06, "SGsAP-SERVICE-REQUEST"),
        (0x07, "SGsAP-DOWNLINK-UNITDATA"),
        (0x08, "SGsAP-UPLINK-UNITDATA"),
        (0x09, "SGsAP-LOCATION-UPDATE-REQUEST"),
        (0x0A, "SGsAP-LOCATION-UPDATE-ACCEPT"),
        (0x0B, "SGsAP-LOCATION-UPDATE-REJECT"),
        (0x0C, "SGsAP-TMSI-REALLOCATION-COMPLETE"),
        (0x0D, "SGsAP-ALERT-REQUEST"),
        (0x0E, "SGsAP-ALERT-ACK"),
        (0x0F, "SGsAP-ALERT-REJECT"),
        (0x10, "SGsAP-UE-ACTIVITY-INDICATION"),
        (0x11, "SGsAP-EPS-DETACH-INDICATION"),
        (0x12, "SGsAP-EPS-DETACH-ACK"),
        (0x13, "SGsAP-IMSI-DETACH-INDICATION"),
        (0x14, "SGsAP-IMSI-DETACH-ACK"),
        (0x15, "SGsAP-RESET-INDICATION"),
        (0x16, "SGsAP-RESET-ACK"),
        (0x17, "SGsAP-SERVICE-ABORT-REQUEST"),
        (0x18, "SGsAP-MO-CSFB-INDICATION"),
        (0x1A, "SGsAP-MM-INFORMATION-REQUEST"),
        (0x1B, "SGsAP-RELEASE-REQUEST"),
        (0x1D, "SGsAP-STATUS"),
        (0x1F, "SGsAP-UE-UNREACHABLE"),
    ];
    for &(t, name) in expected {
        assert_eq!(message_type_name(t), Some(name), "{t:#04x}");
    }
    let named = (0..=u8::MAX)
        .filter(|&t| message_type_name(t).is_some())
        .count();
    assert_eq!(named, expected.len());
}

#[test]
fn ie_type_names() {
    let expected: &[(u8, &str)] = &[
        (1, "IMSI"),
        (2, "VLR name"),
        (3, "TMSI"),
        (4, "Location area identifier"),
        (5, "Channel Needed"),
        (6, "eMLPP Priority"),
        (7, "TMSI status"),
        (8, "SGs cause"),
        (9, "MME name"),
        (10, "EPS location update type"),
        (11, "Global CN-Id"),
        (14, "Mobile identity"),
        (15, "Reject cause"),
        (16, "IMSI detach from EPS service type"),
        (17, "IMSI detach from non-EPS service type"),
        (21, "IMEISV"),
        (22, "NAS message container"),
        (23, "MM information"),
        (27, "Erroneous message"),
        (28, "CLI"),
        (29, "LCS client identity"),
        (30, "LCS indicator"),
        (31, "SS code"),
        (32, "Service indicator"),
        (33, "UE Time Zone"),
        (34, "Mobile Station Classmark 2"),
        (35, "Tracking Area Identity"),
        (36, "E-UTRAN Cell Global Identity"),
        (37, "UE EMM mode"),
        (38, "Additional paging indicators"),
        (39, "TMSI based NRI container"),
        (40, "Selected CS domain operator"),
        (41, "Maximum UE Availability Time"),
        (42, "SM Delivery Timer"),
        (43, "SM Delivery Start Time"),
        (44, "Additional UE Unreachable indicators"),
        (45, "Maximum Retransmission Time"),
        (46, "Requested Retransmission Time"),
    ];
    for &(t, name) in expected {
        assert_eq!(ie::ie_type_name(t), Some(name), "{t}");
    }
    let named = (0..=u8::MAX)
        .filter(|&t| ie::ie_type_name(t).is_some())
        .count();
    assert_eq!(named, expected.len());
}

#[test]
fn location_update_request() {
    let mme_name: &[u8] = &[
        0x09, 0x0E, 0x04, b'm', b'm', b'e', b'1', 0x03, b'e', b'p', b'c', 0x03, b'o', b'r', b'g',
        0x00,
    ];
    let data = msg(
        0x09,
        &[
            &IMSI,
            mme_name,
            &[0x0A, 0x01, 0x01],                         // IMSI attach
            &[0x04, 0x05, 0x00, 0xF1, 0x10, 0x00, 0x01], // new LAI
            &[0x04, 0x05, 0x00, 0xF1, 0x10, 0x12, 0x34], // old LAI
            &[0x07, 0x01, 0x01],                         // TMSI status
            &[0x15, 0x08, 0x53, 0x91, 0x00, 0x21, 0x43, 0x65, 0x87, 0x09], // IMEISV
            &[0x23, 0x05, 0x00, 0xF1, 0x10, 0x00, 0x07], // TAI
            &[0x24, 0x07, 0x00, 0xF1, 0x10, 0x01, 0x23, 0x45, 0x67], // E-CGI
            &[0x27, 0x02, 0xAB, 0xC0],                   // NRI container
            &[0x28, 0x03, 0x00, 0xF1, 0x10],             // selected CS operator
        ],
    );
    let buf = dissect(&data);
    let mt = top(&buf, "message_type").unwrap();
    assert_eq!(shown(mt, &[]), Some("SGsAP-LOCATION-UPDATE-REQUEST"));
    assert_eq!(ies(&buf).len(), 11);

    let imsi = ie(&buf, 1);
    assert_eq!(shown(&imsi[0], imsi), Some("IMSI"));
    assert_eq!(get(imsi, "length"), &FieldValue::U8(8));
    assert_eq!(field(imsi, "length").range, 2..3);
    let f = field(imsi, "imsi");
    assert_eq!(f.range, 3..11);
    assert_eq!(formatted(f), "\"001010123456789\"");
    assert!(!has(imsi, "value"));

    let name = ie(&buf, 9);
    assert_eq!(formatted(field(name, "name")), "\"mme1.epc.org\"");

    let lut = ie(&buf, 10);
    let f = field(lut, "eps_location_update_type");
    assert_eq!(f.value, FieldValue::U8(1));
    assert_eq!(shown(f, lut), Some("IMSI attach"));

    let lais: Vec<_> = ies(&buf)
        .into_iter()
        .filter(|f| f[0].value == FieldValue::U8(4))
        .collect();
    assert_eq!(formatted(field(lais[0], "mcc")), "\"001\"");
    assert_eq!(formatted(field(lais[0], "mnc")), "\"01\"");
    assert_eq!(get(lais[0], "lac"), &FieldValue::U16(1));
    assert_eq!(get(lais[1], "lac"), &FieldValue::U16(0x1234));

    assert_eq!(get(ie(&buf, 7), "tmsi_flag"), &FieldValue::U8(1));
    assert_eq!(
        formatted(field(ie(&buf, 21), "imeisv")),
        "\"3519001234567890\""
    );

    let tai = ie(&buf, 35);
    assert_eq!(formatted(field(tai, "mnc")), "\"01\"");
    assert_eq!(get(tai, "tac"), &FieldValue::U16(7));

    let ecgi = ie(&buf, 36);
    assert_eq!(formatted(field(ecgi, "mcc")), "\"001\"");
    assert_eq!(get(ecgi, "eci"), &FieldValue::U32(0x0123_4567));

    // TS 24.008, Section 10.5.5.31: octet 3 and bits 8-7 of octet 4.
    assert_eq!(get(ie(&buf, 39), "nri_container"), &FieldValue::U16(0x2AF));
    assert_eq!(formatted(field(ie(&buf, 40), "mcc")), "\"001\"");
}

#[test]
fn paging_request() {
    let data = msg(
        0x01,
        &[
            &IMSI,
            &[0x02, 0x05, 0x03, b'v', b'l', b'r', 0x00], // VLR name
            &[0x20, 0x01, 0x01],                         // CS call indicator
            &[0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF],       // TMSI
            &[0x1C, 0x04, 0x91, 0x21, 0x43, 0xF5],       // CLI +12345
            &[0x04, 0x05, 0x00, 0xF1, 0x10, 0x00, 0x01], // LAI
            &[0x0B, 0x05, 0x00, 0xF1, 0x10, 0x0F, 0xFF], // Global CN-Id
            &[0x05, 0x01, 0x40],                         // Channel needed
            &[0x06, 0x01, 0x03],                         // eMLPP priority
            &[0x26, 0x01, 0x01],                         // CSRI
        ],
    );
    let buf = dissect(&data);
    assert_eq!(formatted(field(ie(&buf, 2), "name")), "\"vlr\"");

    let si = ie(&buf, 32);
    let f = field(si, "service_indicator");
    assert_eq!(f.value, FieldValue::U8(1));
    assert_eq!(shown(f, si), Some("CS call indicator"));

    assert_eq!(get(ie(&buf, 3), "tmsi"), &FieldValue::U32(0xDEAD_BEEF));

    let cli = ie(&buf, 28);
    assert_eq!(get(cli, "type_of_number"), &FieldValue::U8(1));
    assert_eq!(get(cli, "numbering_plan"), &FieldValue::U8(1));
    assert!(!has(cli, "presentation_indicator"));
    assert_eq!(formatted(field(cli, "digits")), "\"12345\"");

    let cn = ie(&buf, 11);
    assert_eq!(formatted(field(cn, "mnc")), "\"01\"");
    assert_eq!(get(cn, "cn_id"), &FieldValue::U16(0x0FFF));

    assert_eq!(get(ie(&buf, 5), "channel_needed"), &FieldValue::U8(0x40));
    assert_eq!(get(ie(&buf, 6), "emlpp_priority"), &FieldValue::U8(3));
    assert_eq!(get(ie(&buf, 38), "csri"), &FieldValue::U8(1));
}

#[test]
fn downlink_unitdata() {
    // CP-DATA (TS 24.011, Section 7.2.1): TI/PD 0x09 (SMS), type 0x01,
    // then the RP-DATA as a length-prefixed CP-User data.
    let cp_data: &[u8] = &[0x09, 0x01, 0x03, 0x01, 0x02, 0x03];
    let mut nas = vec![0x16, cp_data.len() as u8];
    nas.extend_from_slice(cp_data);
    let data = msg(0x07, &[&IMSI, &nas]);
    let buf = dissect(&data);
    let f = field(ie(&buf, 22), "nas_message_container");
    assert_eq!(f.value, FieldValue::Bytes(cp_data));
    assert_eq!(f.range, 13..19);
}

#[test]
fn status() {
    // SGs cause 13, then the erroneous message (a location update request
    // cut after its message type).
    let data = msg(
        0x1D,
        &[&[0x08, 0x01, 0x0D], &[0x1B, 0x03, 0x09, 0x01, 0x02]],
    );
    let buf = dissect(&data);
    let cause = ie(&buf, 8);
    let f = field(cause, "sgs_cause");
    assert_eq!(f.value, FieldValue::U8(13));
    assert_eq!(
        shown(f, cause),
        Some("Mobile terminating CS fallback call rejected by the user")
    );
    let err = ie(&buf, 27);
    let f = field(err, "erroneous_message_type");
    assert_eq!(f.value, FieldValue::U8(9));
    assert_eq!(shown(f, err), Some("SGsAP-LOCATION-UPDATE-REQUEST"));
    assert_eq!(get(err, "value"), &FieldValue::Bytes(&[0x09, 0x01, 0x02]));
}

#[test]
fn cli_with_presentation() {
    // Octet 3 ext=0 (octet 3a follows), unknown number, ISDN plan; octet
    // 3a presentation restricted, network provided; digits 123.
    let data = msg(0x01, &[&IMSI, &[0x1C, 0x04, 0x01, 0xA3, 0x21, 0xF3]]);
    let buf = dissect(&data);
    let cli = ie(&buf, 28);
    assert_eq!(get(cli, "type_of_number"), &FieldValue::U8(0));
    assert_eq!(get(cli, "presentation_indicator"), &FieldValue::U8(1));
    assert_eq!(get(cli, "screening_indicator"), &FieldValue::U8(3));
    assert_eq!(formatted(field(cli, "digits")), "\"123\"");
    // Octet 3 alone: no digits.
    let data = msg(0x01, &[&[0x1C, 0x01, 0x81]]);
    let buf = dissect(&data);
    assert!(!has(ie(&buf, 28), "digits"));
}

#[test]
fn mobile_identity() {
    let cases: &[(&[u8], u8, &str)] = &[
        (
            &[0x0E, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98],
            1,
            "001010123456789",
        ),
        (
            &[0x0E, 0x08, 0x3A, 0x95, 0x10, 0x32, 0x54, 0x76, 0x98, 0x00],
            2,
            "359012345678900",
        ),
        (
            &[
                0x0E, 0x09, 0x33, 0x95, 0x10, 0x32, 0x54, 0x76, 0x98, 0x00, 0xF1,
            ],
            3,
            "3590123456789001",
        ),
    ];
    for &(bytes, identity_type, digits) in cases {
        let data = msg(0x0A, &[&IMSI, bytes]);
        let buf = dissect(&data);
        let mi = ie(&buf, 14);
        let f = field(mi, "type_of_identity");
        assert_eq!(f.value, FieldValue::U8(identity_type));
        assert!(shown(f, mi).is_some());
        assert_eq!(
            formatted(field(mi, "identity_digits")),
            format!("\"{digits}\"")
        );
    }
    // TMSI: 1111 0 100, then four octets.
    let data = msg(0x0A, &[&IMSI, &[0x0E, 0x05, 0xF4, 0x01, 0x02, 0x03, 0x04]]);
    let buf = dissect(&data);
    let mi = ie(&buf, 14);
    assert_eq!(
        shown(field(mi, "type_of_identity"), mi),
        Some("TMSI/P-TMSI/M-TMSI")
    );
    assert_eq!(get(mi, "tmsi"), &FieldValue::U32(0x0102_0304));
    // No identity: only the type is decoded.
    let data = msg(0x0A, &[&[0x0E, 0x01, 0xF0]]);
    let buf = dissect(&data);
    let mi = ie(&buf, 14);
    assert_eq!(get(mi, "type_of_identity"), &FieldValue::U8(0));
    assert!(!has(mi, "value"));
}

#[test]
fn value_names_and_scalars() {
    let named: &[(&[u8], &str, &str)] = &[
        (
            &[0x10, 0x01, 0x02],
            "imsi_detach_from_eps_service_type",
            "UE initiated IMSI detach from EPS services",
        ),
        (
            &[0x11, 0x01, 0x03],
            "imsi_detach_from_non_eps_service_type",
            "Implicit network initiated IMSI detach from EPS and non-EPS services",
        ),
        (&[0x25, 0x01, 0x01], "ue_emm_mode", "EMM-CONNECTED"),
        (&[0x1E, 0x01, 0x01], "lcs_indicator", "MT-LR"),
        (&[0x20, 0x01, 0x02], "service_indicator", "SMS indicator"),
        (
            &[0x0A, 0x01, 0x02],
            "eps_location_update_type",
            "Normal location update",
        ),
        (&[0x08, 0x01, 0x06], "sgs_cause", "UE unreachable"),
    ];
    for &(bytes, name, value) in named {
        let data = msg(0x11, &[bytes]);
        let buf = dissect(&data);
        let fields = ie(&buf, bytes[0]);
        assert_eq!(shown(field(fields, name), fields), Some(value), "{name}");
    }
    // Values the table leaves unassigned have no name.
    let data = msg(0x11, &[&[0x25, 0x01, 0x07]]);
    let buf = dissect(&data);
    let fields = ie(&buf, 0x25);
    assert_eq!(shown(field(fields, "ue_emm_mode"), fields), None);

    let data = msg(
        0x1F,
        &[
            &IMSI,
            &[0x0F, 0x01, 0x11],                   // Reject cause
            &[0x1F, 0x01, 0x21],                   // SS code
            &[0x21, 0x01, 0x40],                   // UE time zone
            &[0x29, 0x04, 0x00, 0x00, 0x01, 0x00], // Maximum UE availability time
            &[0x2A, 0x02, 0x00, 0x3C],             // SM delivery timer
            &[0x2B, 0x04, 0x01, 0x02, 0x03, 0x04], // SM delivery start time
            &[0x2C, 0x01, 0x01],                   // SMBRI
            &[0x2D, 0x04, 0x00, 0x00, 0x00, 0x05], // Maximum retransmission time
            &[0x2E, 0x04, 0x00, 0x00, 0x00, 0x06], // Requested retransmission time
            &[0x17, 0x02, 0x43, 0x00],             // MM information (raw)
            &[0x22, 0x03, 0x33, 0x19, 0xA2],       // MS classmark 2 (raw)
            &[0x1D, 0x01, 0x00],                   // LCS client identity (raw)
        ],
    );
    let buf = dissect(&data);
    assert_eq!(get(ie(&buf, 15), "reject_cause"), &FieldValue::U8(0x11));
    assert_eq!(get(ie(&buf, 31), "ss_code"), &FieldValue::U8(0x21));
    assert_eq!(get(ie(&buf, 33), "ue_time_zone"), &FieldValue::U8(0x40));
    assert_eq!(get(ie(&buf, 41), "time"), &FieldValue::U32(0x100));
    assert_eq!(get(ie(&buf, 42), "sm_delivery_timer"), &FieldValue::U16(60));
    assert_eq!(get(ie(&buf, 43), "time"), &FieldValue::U32(0x0102_0304));
    assert_eq!(get(ie(&buf, 44), "smbri"), &FieldValue::U8(1));
    assert_eq!(get(ie(&buf, 45), "time"), &FieldValue::U32(5));
    assert_eq!(get(ie(&buf, 46), "time"), &FieldValue::U32(6));
    assert_eq!(
        get(ie(&buf, 23), "value"),
        &FieldValue::Bytes(&[0x43, 0x00])
    );
    assert_eq!(
        get(ie(&buf, 34), "value"),
        &FieldValue::Bytes(&[0x33, 0x19, 0xA2])
    );
    assert_eq!(get(ie(&buf, 29), "value"), &FieldValue::Bytes(&[0x00]));
}

/// Every assigned value of each table has a name, and nothing else does.
#[test]
fn value_name_tables() {
    let count =
        |f: fn(u8) -> Option<&'static str>| (0..=u8::MAX).filter(|&v| f(v).is_some()).count();
    // Tables 9.4.2.1, 9.4.7.1, 9.4.8.1, 9.4.10.1, 9.4.17.1, 9.4.18.1,
    // 9.4.21c.1 of TS 29.118 and Table 10.5.4 of TS 24.008.
    assert_eq!(count(ie::eps_location_update_type_name), 2);
    assert_eq!(count(ie::imsi_detach_from_eps_name), 3);
    assert_eq!(count(ie::imsi_detach_from_non_eps_name), 3);
    assert_eq!(count(ie::lcs_indicator_name), 1);
    assert_eq!(count(ie::service_indicator_name), 2);
    assert_eq!(count(ie::sgs_cause_name), 15);
    assert_eq!(count(ie::ue_emm_mode_name), 2);
    assert_eq!(count(ie::type_of_identity_name), 6);
    assert_eq!(ie::sgs_cause_name(0), Some("Normal, unspecified"));
    assert_eq!(ie::sgs_cause_name(14), Some("UE temporarily unreachable"));
    assert_eq!(ie::type_of_identity_name(0), Some("No Identity"));

    // The IE object is labelled with the IE name.
    let buf = dissect(&[0x09, 0x0A, 0x01, 0x01]);
    let Some(FieldValue::Array(r)) = top(&buf, "ies").map(|f| &f.value) else {
        panic!("ies missing")
    };
    let obj = &buf.nested_fields(r)[0];
    let FieldValue::Object(children) = &obj.value else {
        panic!("IE is not an object")
    };
    let label = (obj.descriptor.display_fn.unwrap())(&obj.value, buf.nested_fields(children));
    assert_eq!(label, Some("EPS location update type"));
    assert_eq!(
        (obj.descriptor.display_fn.unwrap())(&FieldValue::U8(0), &[]),
        None
    );
    assert_eq!((obj.descriptor.display_fn.unwrap())(&obj.value, &[]), None);
}

#[test]
fn unknown_ie_skipped() {
    // TS 29.118, Section 7.5: an unknown IE is ignored; the walk goes on.
    let data = msg(
        0x09,
        &[&IMSI, &[0xEE, 0x02, 0xAA, 0xBB], &[0x0A, 0x01, 0x01]],
    );
    let buf = dissect(&data);
    let all = ies(&buf);
    assert_eq!(all.len(), 3);
    assert_eq!(shown(&all[1][0], all[1]), None);
    assert_eq!(get(all[1], "value"), &FieldValue::Bytes(&[0xAA, 0xBB]));
    assert_eq!(get(all[2], "eps_location_update_type"), &FieldValue::U8(1));
}

#[test]
fn truncated_ie() {
    // A length past the end of the message: the rest is kept raw and the
    // walk ends (TS 29.118, Section 7.2).
    let data = msg(0x09, &[&IMSI, &[0x0A, 0x05, 0x01]]);
    let buf = dissect(&data);
    let all = ies(&buf);
    assert_eq!(all.len(), 2);
    assert!(!has(all[1], "length"));
    let f = field(all[1], "value");
    assert_eq!(f.value, FieldValue::Bytes(&[0x05, 0x01]));
    assert_eq!(f.range, 12..14);
    // An IE identifier without a length indicator.
    let buf = dissect(&[0x09, 0x01]);
    let all = ies(&buf);
    assert_eq!(all.len(), 1);
    assert!(!has(all[0], "value"));
}

#[test]
fn wrong_length_values_kept_raw() {
    for bytes in [
        &[0x03, 0x03, 0x01, 0x02, 0x03][..],               // TMSI
        &[0x04, 0x04, 0x00, 0xF1, 0x10, 0x00],             // LAI
        &[0x07, 0x00],                                     // TMSI status
        &[0x24, 0x06, 0x00, 0xF1, 0x10, 0x01, 0x23, 0x45], // E-CGI
        &[0x0B, 0x04, 0x00, 0xF1, 0x10, 0x0F],             // Global CN-Id
        &[0x0E, 0x04, 0xF4, 0x01, 0x02, 0x03],             // Mobile identity TMSI
        &[0x0E, 0x00],                                     // Mobile identity
        &[0x1C, 0x00],                                     // CLI
        &[0x1B, 0x00],                                     // Erroneous message
        &[0x29, 0x03, 0x00, 0x00, 0x01],                   // Time
        &[0x2A, 0x01, 0x00],                               // SM delivery timer
        &[0x27, 0x01, 0xAB],                               // NRI container
    ] {
        let data = msg(0x01, &[bytes]);
        let buf = dissect(&data);
        let fields = ie(&buf, bytes[0]);
        assert_eq!(
            fields.len(),
            3,
            "{bytes:02x?}: expected type, length, value only"
        );
        assert!(has(fields, "value"), "{bytes:02x?}");
    }
}

#[test]
fn names_format() {
    // Earlier implementations sent the name as a dotted string (TS 29.118,
    // Section 9.4.22, NOTE); it is rendered as text.
    let data = msg(0x15, &[b"\x02\x07vlr.org"]);
    let buf = dissect(&data);
    assert_eq!(formatted(field(ie(&buf, 2), "name")), "\"vlr.org\"");
}

#[test]
fn format_fns_reject_other_values() {
    for d in ie::IE_FIELD_DESCRIPTORS {
        if let Some(f) = d.format_fn {
            let ctx = FormatContext {
                packet_data: &[],
                scratch: &[],
                layer_range: 0..0,
                field_range: 0..0,
            };
            let mut out = Vec::new();
            f(&FieldValue::U8(0), &ctx, &mut out).unwrap();
            assert!(out.starts_with(b"\""), "{}", d.name);
        }
        if let Some(f) = d.display_fn {
            assert_eq!(f(&FieldValue::U64(0), &[]), None, "{}", d.name);
        }
    }
    for d in FIELD_DESCRIPTORS {
        if let Some(f) = d.display_fn {
            assert_eq!(f(&FieldValue::U64(0), &[]), None, "{}", d.name);
        }
    }
}

#[test]
fn metadata() {
    let d = SgsapDissector;
    assert_eq!(d.name(), "SGs Application Part");
    assert_eq!(d.short_name(), "SGsAP");
    assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    assert_eq!(d.field_descriptors().len(), 2);
    assert_eq!(d.references()[0].id, "3GPP TS 29.118");
}
