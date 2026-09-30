//! # 3GPP TS 36.413 (S1AP) Coverage
//!
//! | Section | Description                                       | Test                                  |
//! |---------|---------------------------------------------------|---------------------------------------|
//! | 9.3.2   | S1AP-PDU header (3 alternatives)                  | initial_ue_message, pdu_types         |
//! | 9.3.2   | Extension / invalid PDU type rejected             | header_errors                         |
//! | 9.3.2   | Truncated header / value                          | header_errors                         |
//! | 9.3.2   | Fragmented value kept undecoded                   | fragmented_value                      |
//! | 9.3.3   | PrivateMessage kept raw                           | private_message_kept_raw              |
//! | 9.3.7   | ProtocolIE-Container (IE count, fields)           | initial_ue_message                    |
//! | 9.3.7   | Malformed container                               | container_errors                      |
//! | 9.3.7   | Message extension additions skipped               | container_errors                      |
//! | 9.3.4   | MME-UE-S1AP-ID / ENB-UE-S1AP-ID                   | ue_s1ap_ids                           |
//! | 9.3.4   | Cause (all groups, extension value)               | cause_values                          |
//! | 9.3.4   | TAI, EUTRAN-CGI                                   | initial_ue_message                    |
//! | 9.3.4   | NAS-PDU decoded as EPS NAS                        | initial_ue_message                    |
//! | 9.3.4   | NAS-PDU that is not EPS NAS kept raw              | nas_pdu_not_eps                       |
//! | 9.3.4   | Global-ENB-ID (macro, home, long macro), ENBname  | s1_setup_request                      |
//! | 9.3.4   | S-TMSI, RRC-Establishment-Cause                   | initial_ue_message                    |
//! | 9.3.4   | UESecurityCapabilities, UEAggregateMaximumBitrate | initial_context_setup_request         |
//! | 9.3.3   | E-RABToBeSetupListCtxtSUReq item (TLA, TEID, NAS) | initial_context_setup_request         |
//! | 9.3.3   | E-RABToBeSetupItemBearerSUReq with GBR QoS        | e_rab_setup_request_gbr               |
//! | 9.3.3   | E-RABSetupListCtxtSURes item (IPv6)               | initial_context_setup_response        |
//! | 9.3.4   | Malformed IE values kept raw                      | malformed_values_kept_raw             |
//! | 9.3.2-9.3.4 | Vectors from an independent APER encoder      | independent_encoder_vectors           |
//! | 9.3.4   | Value names and PLMN digit formatting             | value_display_and_format              |

use super::*;
use packet_dissector_core::field::Field;

/// Bit-level writer for building APER encodings in tests.
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    nbits: usize,
}

impl Bits {
    fn put(mut self, value: u64, n: usize) -> Self {
        for i in (0..n).rev() {
            if self.nbits % 8 == 0 {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 0x80 >> (self.nbits % 8);
            }
            self.nbits += 1;
        }
        self
    }

    fn align(mut self) -> Self {
        self.nbits = self.bytes.len() * 8;
        self
    }

    fn octets(self, o: &[u8]) -> Self {
        let mut s = self.align();
        s.bytes.extend_from_slice(o);
        s.nbits += o.len() * 8;
        s
    }

    fn done(self) -> Vec<u8> {
        self.bytes
    }
}

fn b() -> Bits {
    Bits::default()
}

/// One ProtocolIE-Field.
fn ie(id: u16, crit: u8, value: &[u8]) -> Vec<u8> {
    let mut v = id.to_be_bytes().to_vec();
    v.push(crit << 6);
    v.push(value.len() as u8);
    v.extend_from_slice(value);
    v
}

/// An S1AP-PDU carrying a message SEQUENCE with the given IEs.
fn pdu(pdu_type: u8, proc: u8, crit: u8, ies: &[Vec<u8>]) -> Vec<u8> {
    let mut value = vec![0x00];
    value.extend_from_slice(&(ies.len() as u16).to_be_bytes());
    for i in ies {
        value.extend_from_slice(i);
    }
    let mut v = vec![pdu_type << 5, proc, crit << 6];
    if value.len() < 128 {
        v.push(value.len() as u8);
    } else {
        v.extend_from_slice(&(0x8000 | value.len() as u16).to_be_bytes());
    }
    v.extend_from_slice(&value);
    v
}

fn dissect(data: &[u8]) -> DissectBuffer<'_> {
    let mut buf = DissectBuffer::new();
    let res = S1apDissector.dissect(data, &mut buf, 0).unwrap();
    assert_eq!(res.bytes_consumed, data.len());
    buf
}

/// Children of each IE object with the given id, in order, at any depth.
fn ies_with_id<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, id: u16) -> Vec<&'a [Field<'pkt>]> {
    buf.fields()
        .iter()
        .filter_map(|f| match (f.name(), &f.value) {
            ("ie", FieldValue::Object(r)) => {
                let c = buf.nested_fields(r);
                (c.first()?.value == FieldValue::U16(id)).then_some(c)
            }
            _ => None,
        })
        .collect()
}

fn ie_fields<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, id: u16) -> &'a [Field<'pkt>] {
    ies_with_id(buf, id)
        .first()
        .copied()
        .unwrap_or_else(|| panic!("IE {id} missing"))
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

const PLMN: [u8; 3] = [0x00, 0xF1, 0x10];

/// Plain EMM Attach request with a PDN connectivity request (TS 24.301).
const ATTACH_REQUEST: &[u8] = &[
    0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x02, 0xE0, 0xE0, 0x00,
    0x04, 0x02, 0x01, 0xD0, 0x11,
];

fn nas_pdu_value(nas: &[u8]) -> Vec<u8> {
    let mut v = vec![nas.len() as u8];
    v.extend_from_slice(nas);
    v
}

fn tai_value() -> Vec<u8> {
    b().put(0, 2).octets(&PLMN).put(0x0001, 16).done()
}

fn build_initial_ue_message() -> Vec<u8> {
    pdu(
        0,
        12,
        1,
        &[
            ie(8, 0, &b().put(0, 2).octets(&[0x05]).done()), // eNB-UE-S1AP-ID 5
            ie(26, 0, &nas_pdu_value(ATTACH_REQUEST)),
            ie(67, 0, &tai_value()),
            // EUTRAN-CGI: cell identity 0x1234567.
            ie(
                100,
                1,
                &b().put(0, 2).octets(&PLMN).put(0x1234567, 28).done(),
            ),
            // RRC-Establishment-Cause mo-Signalling (3).
            ie(134, 1, &b().put(0, 1).put(3, 3).done()),
            // S-TMSI: MMEC 0x12, M-TMSI 0xC0000001.
            ie(
                96,
                0,
                &b().put(0, 2).put(0x12, 8).octets(&[0xC0, 0, 0, 1]).done(),
            ),
        ],
    )
}

#[test]
fn initial_ue_message() {
    let data = build_initial_ue_message();
    let buf = dissect(&data);
    let layer = &buf.layers()[0];
    assert_eq!(layer.name, "S1AP");
    assert_eq!(layer.range, 0..data.len());
    assert_eq!(buf.field_u8(layer, "pdu_type"), Some(0));
    assert_eq!(
        buf.resolve_display_name(layer, "pdu_type_name"),
        Some("initiatingMessage")
    );
    assert_eq!(buf.field_u8(layer, "procedure_code"), Some(12));
    assert_eq!(
        buf.resolve_display_name(layer, "procedure_code_name"),
        Some("initialUEMessage")
    );
    assert_eq!(buf.field_u8(layer, "criticality"), Some(1));
    assert_eq!(
        buf.resolve_display_name(layer, "criticality_name"),
        Some("ignore")
    );
    assert!(buf.field_by_name(layer, "ie_container_error").is_none());

    let enb = ie_fields(&buf, 8);
    assert_eq!(get(enb, "enb_ue_s1ap_id"), &FieldValue::U32(5));
    assert!(!has(enb, "value"));

    let nas = ie_fields(&buf, 26);
    let FieldValue::Object(r) = get(nas, "nas_pdu") else {
        panic!("nas_pdu not an object")
    };
    // The NAS-PDU is handed to the EPS NAS decoder (its fields are checked
    // by the integration tests) rather than kept raw.
    assert!(!buf.nested_fields(r).is_empty());
    assert!(!has(nas, "raw"));

    let tai = ie_fields(&buf, 67);
    assert_eq!(get(tai, "mcc"), &FieldValue::Bytes(&PLMN));
    assert_eq!(get(tai, "tac"), &FieldValue::U16(1));

    let cgi = ie_fields(&buf, 100);
    assert_eq!(get(cgi, "cell_identity"), &FieldValue::U32(0x1234567));

    let rrc = ie_fields(&buf, 134);
    assert_eq!(get(rrc, "rrc_establishment_cause"), &FieldValue::U8(3));
    let rrc_field = rrc
        .iter()
        .find(|f| f.name() == "rrc_establishment_cause")
        .unwrap();
    assert_eq!(
        (rrc_field.descriptor.display_fn.unwrap())(&rrc_field.value, rrc),
        Some("mo-Signalling")
    );

    let s_tmsi = ie_fields(&buf, 96);
    assert_eq!(get(s_tmsi, "mme_code"), &FieldValue::U8(0x12));
    assert_eq!(get(s_tmsi, "m_tmsi"), &FieldValue::U32(0xC000_0001));

    // IE container display names resolve to the IE name.
    let idx = buf.fields().iter().position(|f| f.name() == "ie").unwrap() as u32;
    assert_eq!(
        buf.resolve_container_display_name(idx),
        Some("eNB-UE-S1AP-ID")
    );
}

#[test]
fn pdu_types() {
    for (t, name) in [(1u8, "successfulOutcome"), (2, "unsuccessfulOutcome")] {
        let data = pdu(t, 17, 0, &[]);
        let buf = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(buf.resolve_display_name(layer, "pdu_type_name"), Some(name));
        assert_eq!(
            buf.resolve_display_name(layer, "procedure_code_name"),
            Some("S1Setup")
        );
        assert!(buf.field_by_name(layer, "ies").is_some());
    }
    // A value holding only the SEQUENCE preamble has no IE container.
    let data = [0x00, 17, 0x00, 0x01, 0x00];
    let buf = dissect(&data);
    assert!(buf.field_by_name(&buf.layers()[0], "ies").is_none());
}

#[test]
fn header_errors() {
    let mut buf = DissectBuffer::new();
    assert!(matches!(
        S1apDissector.dissect(&[0x00, 0x11], &mut buf, 0),
        Err(PacketError::Truncated {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        S1apDissector.dissect(&[0x80, 0x11, 0x00, 0x00], &mut buf, 0),
        Err(PacketError::InvalidHeader(_))
    ));
    assert!(matches!(
        S1apDissector.dissect(&[0x60, 0x11, 0x00, 0x00], &mut buf, 0),
        Err(PacketError::InvalidFieldValue {
            field: "pdu_type",
            value: 3
        })
    ));
    assert!(matches!(
        S1apDissector.dissect(&[0x00, 0x11, 0x00, 0x05, 0x00], &mut buf, 0),
        Err(PacketError::Truncated {
            expected: 9,
            actual: 5
        })
    ));
    assert!(matches!(
        S1apDissector.dissect(&[0x00, 0x11, 0x00], &mut buf, 0),
        Err(PacketError::Truncated { .. })
    ));
    assert!(buf.layers().is_empty());
}

#[test]
fn fragmented_value() {
    // A value of 16384 + 1 octets: one fragment (0xC1) then a final length.
    let mut data = vec![0x00, 17, 0x00, 0xC1];
    data.extend(std::iter::repeat_n(0u8, 16384));
    data.extend_from_slice(&[0x01, 0x00]);
    let buf = dissect(&data);
    let layer = &buf.layers()[0];
    assert_eq!(buf.field_u32(layer, "value_length"), Some(16385));
    assert_eq!(
        buf.field_by_name(layer, "ie_container_error")
            .unwrap()
            .value,
        FieldValue::Str("fragmented message value not decoded")
    );
}

#[test]
fn private_message_kept_raw() {
    // PrivateMessage: the SEQUENCE preamble, a SIZE(1..) count of 0 (= 1 IE),
    // a local PrivateIE-ID (CHOICE index 0, value 5), criticality and value
    // (3GPP TS 36.413, Section 9.3.7).
    let value = [0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x40, 0x01, 0xAB];
    let mut data = vec![0x00, 39, 0x40, value.len() as u8];
    data.extend_from_slice(&value);
    let buf = dissect(&data);
    let layer = &buf.layers()[0];
    assert_eq!(
        buf.field_by_name(layer, "private_ies").unwrap().value,
        FieldValue::Bytes(&value)
    );
    assert!(buf.field_by_name(layer, "ies").is_none());
    assert!(buf.field_by_name(layer, "ie_container_error").is_none());
}

#[test]
fn container_errors() {
    // IE count larger than the IEs present.
    let mut data = pdu(0, 17, 0, &[ie(59, 0, &[0x00])]);
    data[6] = 2; // count = 2
    let buf = dissect(&data);
    let layer = &buf.layers()[0];
    assert_eq!(
        buf.field_by_name(layer, "ie_container_error")
            .unwrap()
            .value,
        FieldValue::Str("fewer IEs than the IE count")
    );

    // Truncated IE header and value.
    for (tail, reason) in [
        (&[0x00, 0x3B][..], "IE header truncated"),
        (&[0x00, 0x3B, 0x00, 0x05, 0x00][..], "IE value truncated"),
        (
            &[0x00, 0x3B, 0x00, 0xE0][..],
            "IE value length determinant invalid",
        ),
    ] {
        let mut v = vec![0x00, 0x00, 0x01];
        v.extend_from_slice(tail);
        let mut data = vec![0x00, 17, 0x00, v.len() as u8];
        data.extend_from_slice(&v);
        let buf = dissect(&data);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "ie_container_error")
                .unwrap()
                .value,
            FieldValue::Str(reason)
        );
        assert!(buf.field_by_name(layer, "undecoded_ies").is_some());
    }

    // IE count missing: a partial count, only the preamble, or an empty
    // value.
    for data in [
        &[0x00, 17, 0x00, 0x02, 0x00, 0x00][..],
        &[0x00, 17, 0x00, 0x01, 0x00],
        &[0x00, 17, 0x00, 0x00],
    ] {
        let buf = dissect(data);
        assert_eq!(
            buf.field_by_name(&buf.layers()[0], "ie_container_error")
                .unwrap()
                .value,
            FieldValue::Str("IE count truncated"),
            "{data:02x?}"
        );
    }

    // Trailing octets after the last IE: reported, unless the message
    // SEQUENCE is extended and they are its extension additions.
    let mut data = pdu(0, 17, 0, &[]);
    data.push(0xAA);
    data[3] += 1;
    let buf = dissect(&data);
    assert_eq!(
        buf.field_by_name(&buf.layers()[0], "ie_container_error")
            .unwrap()
            .value,
        FieldValue::Str("octets after the last IE")
    );
    let mut data = pdu(0, 17, 0, &[]);
    data[4] = 0x80; // extension bit
    data.extend_from_slice(&[0x01, 0x01, 0xAA]); // one present addition
    data[3] += 3;
    let buf = dissect(&data);
    assert!(
        buf.field_by_name(&buf.layers()[0], "ie_container_error")
            .is_none()
    );
}

#[test]
fn ue_s1ap_ids() {
    let data = pdu(
        0,
        13,
        1,
        &[
            // MME-UE-S1AP-ID 0x12345678: 2-bit length (4 - 1), then 4 octets.
            ie(
                0,
                0,
                &b().put(3, 2).octets(&[0x12, 0x34, 0x56, 0x78]).done(),
            ),
            // eNB-UE-S1AP-ID 0x012345: 2-bit length (3 - 1), then 3 octets.
            ie(8, 0, &b().put(2, 2).octets(&[0x01, 0x23, 0x45]).done()),
        ],
    );
    let buf = dissect(&data);
    assert_eq!(
        get(ie_fields(&buf, 0), "mme_ue_s1ap_id"),
        &FieldValue::U32(0x1234_5678)
    );
    assert_eq!(
        get(ie_fields(&buf, 8), "enb_ue_s1ap_id"),
        &FieldValue::U32(0x01_2345)
    );
}

#[test]
fn cause_values() {
    let cases: [(Vec<u8>, u8, u8, &str, &str); 6] = [
        // radioNetwork (3-bit index 0), user-inactivity (6-bit 20).
        (
            b().put(0, 4).put(0, 1).put(20, 6).done(),
            0,
            20,
            "radioNetwork",
            "user-inactivity",
        ),
        (
            b().put(1, 4).put(0, 1).put(1, 1).done(),
            1,
            1,
            "transport",
            "unspecified",
        ),
        (
            b().put(2, 4).put(0, 1).put(2, 2).done(),
            2,
            2,
            "nas",
            "detach",
        ),
        (
            b().put(3, 4).put(0, 1).put(4, 3).done(),
            3,
            4,
            "protocol",
            "semantic-error",
        ),
        (
            b().put(4, 4).put(0, 1).put(5, 3).done(),
            4,
            5,
            "misc",
            "unknown-PLMN",
        ),
        // Extension value 0 of CauseRadioNetwork: normally small 0.
        (
            b().put(0, 4).put(1, 1).put(0, 7).done(),
            0,
            36,
            "radioNetwork",
            "redirection-towards-1xRTT",
        ),
    ];
    for (value, group, cause, gname, cname) in cases {
        let data = pdu(0, 15, 1, &[ie(2, 1, &value)]);
        let buf = dissect(&data);
        let c = ie_fields(&buf, 2);
        assert_eq!(get(c, "cause_group"), &FieldValue::U8(group));
        assert_eq!(get(c, "cause"), &FieldValue::U8(cause));
        let names: Vec<_> = c
            .iter()
            .filter_map(|f| f.descriptor.display_fn.map(|d| d(&f.value, c)))
            .collect();
        assert!(names.contains(&Some(gname)), "{names:?}");
        assert!(names.contains(&Some(cname)), "{names:?}");
    }
    // An extension alternative of the Cause CHOICE is kept raw.
    let data = pdu(0, 15, 1, &[ie(2, 1, &b().put(1, 1).put(0, 7).done())]);
    let buf = dissect(&data);
    assert!(has(ie_fields(&buf, 2), "value"));
}

#[test]
fn s1_setup_request() {
    // BIT STRINGs longer than 16 bits are octet-aligned (X.691, 16.11).
    let macro_id = b()
        .put(0, 2)
        .octets(&PLMN)
        .put(0, 2)
        .align()
        .put(0x12345, 20)
        .done();
    let home_id = b()
        .put(0, 2)
        .octets(&PLMN)
        .put(1, 2)
        .align()
        .put(0x1234567, 28)
        .done();
    // long-macroENB-ID: extension index 1, open type holding 21 bits.
    let inner = b().put(0x1ABCDE, 21).done();
    let long_id = b()
        .put(0, 2)
        .octets(&PLMN)
        .put(1, 1)
        .put(1, 7)
        .octets(&[inner.len() as u8])
        .octets(&inner)
        .done();
    // ENBname "enb1": extension bit, 8-bit length (4 - 1), then octets.
    let name = b().put(0, 1).put(3, 8).octets(b"enb1").done();
    let data = pdu(
        0,
        17,
        0,
        &[
            ie(59, 0, &macro_id),
            ie(59, 0, &home_id),
            ie(59, 0, &long_id),
            ie(60, 1, &name),
            // DefaultPagingDRX v128 (index 2).
            ie(137, 1, &b().put(0, 1).put(2, 2).done()),
        ],
    );
    let buf = dissect(&data);
    let ids = ies_with_id(&buf, 59);
    assert_eq!(get(ids[0], "enb_id_type"), &FieldValue::U8(0));
    assert_eq!(get(ids[0], "enb_id"), &FieldValue::U32(0x12345));
    assert_eq!(get(ids[1], "enb_id_type"), &FieldValue::U8(1));
    assert_eq!(get(ids[1], "enb_id"), &FieldValue::U32(0x1234567));
    assert_eq!(get(ids[2], "enb_id_type"), &FieldValue::U8(3));
    assert_eq!(get(ids[2], "enb_id"), &FieldValue::U32(0x1ABCDE));
    assert_eq!(get(ie_fields(&buf, 60), "name"), &FieldValue::Str("enb1"));
    assert_eq!(
        get(ie_fields(&buf, 137), "default_paging_drx"),
        &FieldValue::U8(2)
    );
}

/// An E-RABToBeSetupItemCtxtSUReq value.
fn e_rab_item_ctxt(nas: Option<&[u8]>) -> Vec<u8> {
    let w = b()
        .put(0, 1)
        .put(u64::from(nas.is_some()), 1)
        .put(0, 1) // preamble
        .put(0, 1)
        .put(5, 4) // e-RAB-ID 5
        .put(0, 1)
        .put(0, 2) // QoS preamble: no GBR, no extensions
        .octets(&[9]) // QCI 9
        .put(0, 2) // ARP preamble
        .put(15, 4)
        .put(0, 1)
        .put(1, 1) // priority 15, shall-not-trigger, pre-emptable
        .put(0, 1)
        .put(31, 8) // TLA: 32 bits
        .octets(&[192, 0, 2, 1])
        .octets(&[0x00, 0x00, 0x00, 0x01]); // GTP-TEID
    match nas {
        Some(n) => w.octets(&[n.len() as u8]).octets(n).done(),
        None => w.done(),
    }
}

fn e_rab_list(id: u16, items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![(items.len() - 1) as u8];
    for item in items {
        v.extend_from_slice(&ie(id, 0, item));
    }
    v
}

#[test]
fn initial_context_setup_request() {
    // Activate default EPS bearer context request (ESM) in the E-RAB item.
    let esm: &[u8] = &[
        0x52, 0x01, 0xC1, 0x01, 0x09, 0x01, 0x00, 0x05, 0x01, 10, 0, 0, 1,
    ];
    let data = pdu(
        0,
        9,
        0,
        &[
            ie(0, 0, &b().put(0, 2).octets(&[0x01]).done()),
            ie(8, 0, &b().put(0, 2).octets(&[0x05]).done()),
            // UEAggregateMaximumBitrate: DL 100000000 (4 octets), UL 50000000.
            ie(
                66,
                0,
                &b().put(0, 2)
                    .put(3, 3)
                    .octets(&100_000_000u32.to_be_bytes())
                    .put(3, 3)
                    .octets(&50_000_000u32.to_be_bytes())
                    .done(),
            ),
            ie(
                24,
                0,
                &e_rab_list(52, &[e_rab_item_ctxt(Some(esm)), e_rab_item_ctxt(None)]),
            ),
            // UESecurityCapabilities: EEA 0xE000, EIA 0xC000.
            ie(
                107,
                0,
                &b().put(0, 2)
                    .put(0, 1)
                    .put(0xE000, 16)
                    .put(0, 1)
                    .put(0xC000, 16)
                    .done(),
            ),
        ],
    );
    let buf = dissect(&data);
    assert!(
        buf.field_by_name(&buf.layers()[0], "ie_container_error")
            .is_none()
    );
    let ambr = ie_fields(&buf, 66);
    assert_eq!(
        get(ambr, "ue_aggregate_maximum_bitrate_dl"),
        &FieldValue::U64(100_000_000)
    );
    assert_eq!(
        get(ambr, "ue_aggregate_maximum_bitrate_ul"),
        &FieldValue::U64(50_000_000)
    );
    let sec = ie_fields(&buf, 107);
    assert_eq!(get(sec, "encryption_algorithms"), &FieldValue::U16(0xE000));
    assert_eq!(
        get(sec, "integrity_protection_algorithms"),
        &FieldValue::U16(0xC000)
    );

    let list = ie_fields(&buf, 24);
    assert!(matches!(get(list, "items"), FieldValue::Array(_)));
    let items = ies_with_id(&buf, 52);
    assert_eq!(items.len(), 2);
    let item = items[0];
    assert_eq!(get(item, "e_rab_id"), &FieldValue::U8(5));
    assert_eq!(get(item, "qci"), &FieldValue::U8(9));
    assert_eq!(get(item, "priority_level"), &FieldValue::U8(15));
    assert_eq!(get(item, "pre_emption_capability"), &FieldValue::U8(0));
    assert_eq!(get(item, "pre_emption_vulnerability"), &FieldValue::U8(1));
    assert_eq!(
        get(item, "transport_layer_address"),
        &FieldValue::Ipv4Addr([192, 0, 2, 1])
    );
    assert_eq!(get(item, "gtp_teid"), &FieldValue::U32(1));
    let FieldValue::Object(r) = get(item, "nas_pdu") else {
        panic!("nas_pdu missing")
    };
    assert!(!buf.nested_fields(r).is_empty());
    assert!(!has(items[1], "nas_pdu"));
}

#[test]
fn e_rab_setup_request_gbr() {
    let item = b()
        .put(0, 2) // preamble (no extensions)
        .put(0, 1)
        .put(6, 4) // e-RAB-ID 6
        .put(0, 1)
        .put(1, 1)
        .put(0, 1) // QoS: GBR present
        .octets(&[1]) // QCI 1
        .put(0, 2)
        .put(2, 4)
        .put(1, 1)
        .put(0, 1) // ARP
        .put(0, 2) // GBR preamble
        .put(1, 3)
        .octets(&[0x01, 0x00]) // MBR DL 256
        .put(0, 3)
        .octets(&[0x40]) // MBR UL 64
        .put(0, 3)
        .octets(&[0x20]) // GBR DL 32
        .put(0, 3)
        .octets(&[0x10]) // GBR UL 16
        .put(0, 1)
        .put(127, 8) // TLA: 128 bits
        .octets(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        .octets(&[0, 0, 0, 7])
        .octets(&[0x03, 0x52, 0x01, 0xC6]) // NAS-PDU (mandatory)
        .done();
    let data = pdu(0, 5, 0, &[ie(16, 0, &e_rab_list(17, &[item]))]);
    let buf = dissect(&data);
    let item = ie_fields(&buf, 17);
    assert_eq!(get(item, "e_rab_id"), &FieldValue::U8(6));
    assert_eq!(get(item, "e_rab_maximum_bitrate_dl"), &FieldValue::U64(256));
    assert_eq!(get(item, "e_rab_maximum_bitrate_ul"), &FieldValue::U64(64));
    assert_eq!(
        get(item, "e_rab_guaranteed_bitrate_dl"),
        &FieldValue::U64(32)
    );
    assert_eq!(
        get(item, "e_rab_guaranteed_bitrate_ul"),
        &FieldValue::U64(16)
    );
    assert!(matches!(
        get(item, "transport_layer_address"),
        FieldValue::Ipv6Addr(a) if a[15] == 1
    ));
    assert_eq!(get(item, "gtp_teid"), &FieldValue::U32(7));
    assert!(has(item, "nas_pdu"));
}

#[test]
fn initial_context_setup_response() {
    // IPv4 and IPv6 address pair (160 bits) is kept as octets.
    let mut pair = vec![192, 0, 2, 1];
    pair.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let item = b()
        .put(0, 2)
        .put(0, 1)
        .put(5, 4)
        .put(0, 1)
        .put(159, 8)
        .octets(&pair)
        .octets(&[0, 0, 0, 9])
        .done();
    let data = pdu(1, 9, 0, &[ie(51, 1, &e_rab_list(50, &[item]))]);
    let buf = dissect(&data);
    let item = ie_fields(&buf, 50);
    assert_eq!(
        get(item, "transport_layer_address"),
        &FieldValue::Bytes(&pair)
    );
    assert_eq!(get(item, "gtp_teid"), &FieldValue::U32(9));
}

#[test]
fn nas_pdu_not_eps() {
    let data = pdu(0, 13, 1, &[ie(26, 0, &nas_pdu_value(&[0x7E, 0x00]))]);
    let buf = dissect(&data);
    let nas = ie_fields(&buf, 26);
    let FieldValue::Object(r) = get(nas, "nas_pdu") else {
        panic!("nas_pdu missing")
    };
    assert_eq!(
        get(buf.nested_fields(r), "raw"),
        &FieldValue::Bytes(&[0x7E, 0x00])
    );
}

#[test]
fn malformed_values_kept_raw() {
    // (IE id, value, id of the IE expected to keep a raw value, raw value)
    let bad_item = b().put(0, 3).put(1, 1).put(0, 7).done();
    let short_tla = b().put(0, 2).put(0, 1).put(5, 4).put(0, 1).put(7, 8).done();
    let ext_tla = b().put(0, 2).put(0, 1).put(5, 4).put(1, 1).done();
    let inner_list = e_rab_list(52, &[vec![0x00]]);
    let cases: Vec<(u16, Vec<u8>, u16, Vec<u8>)> = vec![
        // Trailing octet after an eNB-UE-S1AP-ID.
        (8, vec![0x00, 0x05, 0xFF], 8, vec![0x00, 0x05, 0xFF]),
        // Truncated TAI.
        (67, vec![0x00, 0x00, 0xF1], 67, vec![0x00, 0x00, 0xF1]),
        // Unknown IE id.
        (5, vec![0x01], 5, vec![0x01]),
        // Extended E-RAB-ID: the item is kept raw inside the decoded list.
        (
            24,
            e_rab_list(52, std::slice::from_ref(&bad_item)),
            52,
            bad_item,
        ),
        // TLA shorter than 17 bits, and an extended TLA size.
        (
            51,
            e_rab_list(50, std::slice::from_ref(&short_tla)),
            50,
            short_tla,
        ),
        (
            51,
            e_rab_list(50, std::slice::from_ref(&ext_tla)),
            50,
            ext_tla,
        ),
        // Extended encryption algorithm bit string.
        (
            107,
            b().put(0, 2).put(1, 1).done(),
            107,
            b().put(0, 2).put(1, 1).done(),
        ),
        // Unknown ENB-ID extension alternative.
        (
            59,
            b().put(0, 2).octets(&PLMN).put(1, 1).put(5, 7).done(),
            59,
            b().put(0, 2).octets(&PLMN).put(1, 1).put(5, 7).done(),
        ),
        // E-RAB list with more items than present.
        (24, vec![0x05], 24, vec![0x05]),
        // A list is not decoded inside a list item.
        (52, inner_list.clone(), 52, inner_list),
        // NAS-PDU length past the end.
        (26, vec![0x05], 26, vec![0x05]),
        // ENBname length past the end.
        (
            60,
            b().put(0, 1).put(9, 8).octets(b"ab").done(),
            60,
            b().put(0, 1).put(9, 8).octets(b"ab").done(),
        ),
        // ENBname that is not a PrintableString.
        (
            60,
            b().put(0, 1).put(0, 8).octets(&[0xFF]).done(),
            60,
            b().put(0, 1).put(0, 8).octets(&[0xFF]).done(),
        ),
    ];
    for (id, value, check_id, raw) in cases {
        let data = pdu(0, 17, 0, &[ie(id, 0, &value)]);
        let buf = dissect(&data);
        let f = ies_with_id(&buf, check_id);
        assert_eq!(
            get(f.last().unwrap(), "value"),
            &FieldValue::Bytes(&raw),
            "IE {id}"
        );
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Messages encoded by an independent APER encoder (pycrate `S1AP`, TS
/// 36.413 ASN.1) decode to the values given to the encoder.
#[test]
fn independent_encoder_vectors() {
    // InitialUEMessage: eNB-UE-S1AP-ID 5, NAS-PDU, TAI, EUTRAN-CGI,
    // RRC-Establishment-Cause mo-Signalling, S-TMSI.
    let iue = hex(
        "000c4048000006000800020005001a00161507417108091010103254769802e0e00004\
         0201d011004300060000f1100001006440080000f110123456700086400130006000060480c0000001",
    );
    assert_eq!(iue, build_initial_ue_message());

    // InitialContextSetupRequest with two E-RAB items.
    let ics = hex(
        "0009005d0000050000000200010008000200050042000a1805f5e1006002faf0800018\
         0033010034001c4500093d0f80c0000201000000010d5201c10109010005010a000001\
         0034000e0500093d0f80c000020100000001006b00051c000c0000",
    );
    let buf = dissect(&ics);
    assert_eq!(
        get(ie_fields(&buf, 0), "mme_ue_s1ap_id"),
        &FieldValue::U32(1)
    );
    assert_eq!(ies_with_id(&buf, 52).len(), 2);
    assert_eq!(
        get(ie_fields(&buf, 52), "transport_layer_address"),
        &FieldValue::Ipv4Addr([192, 0, 2, 1])
    );
    assert_eq!(
        get(ie_fields(&buf, 107), "integrity_protection_algorithms"),
        &FieldValue::U16(0xC000)
    );

    // S1SetupRequest: macro, home and long macro eNB IDs, ENBname, PagingDRX.
    let s1s = hex(
        "00110038000005003b00080000f11000123450003b00090000f1104012345670003b00\
         090000f1108103d5e6f0003c40060180656e62310089400140",
    );
    let buf = dissect(&s1s);
    let ids: Vec<_> = ies_with_id(&buf, 59)
        .iter()
        .map(|f| get(f, "enb_id").clone())
        .collect();
    assert_eq!(
        ids,
        [
            FieldValue::U32(0x12345),
            FieldValue::U32(0x1234567),
            FieldValue::U32(0x1ABCDE)
        ]
    );
    assert_eq!(get(ie_fields(&buf, 60), "name"), &FieldValue::Str("enb1"));

    // UplinkNASTransport with 4-octet MME-UE-S1AP-ID and 3-octet eNB ID.
    let unt = hex(
        "000d403600000500000005c0123456780008000480012345001a000807074300035201\
         c2006440080000f11012345670004340060000f1100001",
    );
    let buf = dissect(&unt);
    assert_eq!(
        get(ie_fields(&buf, 0), "mme_ue_s1ap_id"),
        &FieldValue::U32(0x1234_5678)
    );
    assert_eq!(
        get(ie_fields(&buf, 8), "enb_ue_s1ap_id"),
        &FieldValue::U32(0x01_2345)
    );

    // E-RABSetupRequest with a GBR bearer and an IPv6 transport address.
    let ers = hex(
        "0005003f0000030000000200010008000200050010002c00001100270c80010a080100\
         0040002000103f8020010db800000000000000000000000100000007035201c6",
    );
    let buf = dissect(&ers);
    let item = ie_fields(&buf, 17);
    assert_eq!(get(item, "e_rab_maximum_bitrate_dl"), &FieldValue::U64(256));
    assert_eq!(get(item, "pre_emption_capability"), &FieldValue::U8(1));

    // Cause values.
    for (h, group, cause) in [
        ("000f4009000001000240020280", 0, 20),
        ("000f40080000010002400124", 2, 2),
        ("000f40080000010002400145", 4, 5),
        ("000f4009000001000240020800", 0, 36),
        ("000f40080000010002400134", 3, 4),
        ("000f40080000010002400114", 1, 1),
    ] {
        let data = hex(h);
        let buf = dissect(&data);
        let c = ie_fields(&buf, 2);
        assert_eq!(get(c, "cause_group"), &FieldValue::U8(group), "{h}");
        assert_eq!(get(c, "cause"), &FieldValue::U8(cause), "{h}");
    }
}

#[test]
fn display_fns_reject_other_values() {
    for d in FIELD_DESCRIPTORS
        .iter()
        .chain(container::IE_CHILD_FIELDS)
        .chain(ie_parsers::VALUE_FIELDS)
    {
        if let Some(f) = d.display_fn {
            assert_eq!(f(&FieldValue::U64(0), &[]), None, "{}", d.name);
        }
    }
    assert_eq!(pdu_type_name(3), None);
    assert_eq!(criticality_name(3), None);
}

fn value_field(name: &str) -> &'static FieldDescriptor {
    ie_parsers::VALUE_FIELDS
        .iter()
        .find(|d| d.name == name)
        .unwrap()
}

fn display(name: &str, v: u8) -> Option<&'static str> {
    (value_field(name).display_fn.unwrap())(&FieldValue::U8(v), &[])
}

fn format(name: &str, v: &FieldValue<'_>) -> String {
    let ctx = packet_dissector_core::field::FormatContext {
        packet_data: &[],
        scratch: &[],
        layer_range: 0..0,
        field_range: 0..0,
    };
    let mut out = Vec::new();
    (value_field(name).format_fn.unwrap())(v, &ctx, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn value_display_and_format() {
    assert_eq!(display("enb_id_type", 0), Some("macroENB-ID"));
    assert_eq!(display("enb_id_type", 9), None);
    assert_eq!(
        display("pre_emption_capability", 0),
        Some("shall-not-trigger-pre-emption")
    );
    assert_eq!(
        display("pre_emption_vulnerability", 1),
        Some("pre-emptable")
    );
    assert_eq!(display("default_paging_drx", 0), Some("v32"));
    assert_eq!(display("rrc_establishment_cause", 3), Some("mo-Signalling"));
    // 3GPP TS 36.413, Section 9.2.3.8: PLMN identity is TBCD, MNC digit 3
    // filler 0xF for a 2-digit MNC.
    assert_eq!(format("mcc", &FieldValue::Bytes(&PLMN)), "\"001\"");
    assert_eq!(format("mnc", &FieldValue::Bytes(&PLMN)), "\"01\"");
    assert_eq!(
        format("mnc", &FieldValue::Bytes(&[0x13, 0x00, 0x62])),
        "\"260\""
    );
    assert_eq!(format("mcc", &FieldValue::U8(0)), "\"\"");
    assert_eq!(format("mnc", &FieldValue::U8(0)), "\"\"");
}

#[test]
fn metadata() {
    let d = S1apDissector;
    assert_eq!(d.name(), "S1 Application Protocol");
    assert_eq!(d.short_name(), "S1AP");
    assert_eq!(d.layer(), Some(ProtocolLayer::Application));
    assert_eq!(d.references().len(), 2);
    assert!(d.field_descriptors().iter().any(|f| f.name == "ies"));
}
