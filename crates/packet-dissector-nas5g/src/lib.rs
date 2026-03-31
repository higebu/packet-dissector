//! 5G NAS (Non-Access Stratum) dissector.
//!
//! Parses 5GS Mobility Management (5GMM) and 5GS Session Management (5GSM)
//! messages as defined in 3GPP TS 24.501. Typically carried inside NGAP
//! NAS-PDU Information Elements.
//!
//! ## References
//! - 3GPP TS 24.501: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>
//! - 3GPP TS 24.007, Section 11.2 — Extended Protocol Discriminator

#![deny(missing_docs)]

pub mod message_type;

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

use message_type::{
    epd_name, mm_message_type_name, security_header_type_name, sm_message_type_name,
};

/// Extended protocol discriminator for 5GS Mobility Management.
///
/// 3GPP TS 24.007, Table 11.2.
const EPD_5GMM: u8 = 0x7E;

/// Extended protocol discriminator for 5GS Session Management.
///
/// 3GPP TS 24.007, Table 11.2.
const EPD_5GSM: u8 = 0x2E;

/// Minimum message size: EPD (1) + security header / PDU session ID (1) +
/// message type (1) = 3 bytes for plain 5GMM. 5GSM requires 4 bytes.
const MIN_5GMM_SIZE: usize = 3;

/// Minimum 5GSM message size: EPD (1) + PDU session ID (1) + PTI (1) +
/// message type (1) = 4 bytes.
const MIN_5GSM_SIZE: usize = 4;

/// Security-protected 5GMM message minimum: EPD (1) + security header (1) +
/// MAC (4) + sequence number (1) + inner EPD (1) = 8 bytes.
const MIN_SECURITY_PROTECTED_SIZE: usize = 7;

// ── Field descriptors for 5GMM plain messages ──────────────────────────

static FD_EPD: FieldDescriptor = FieldDescriptor {
    name: "extended_protocol_discriminator",
    display_name: "Extended Protocol Discriminator",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(e) => Some(epd_name(*e)),
        _ => None,
    }),
    format_fn: None,
};

static FD_SECURITY_HEADER_TYPE: FieldDescriptor = FieldDescriptor {
    name: "security_header_type",
    display_name: "Security Header Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(s) => Some(security_header_type_name(*s)),
        _ => None,
    }),
    format_fn: None,
};

static FD_MM_MESSAGE_TYPE: FieldDescriptor = FieldDescriptor {
    name: "message_type",
    display_name: "Message Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(m) => Some(mm_message_type_name(*m)),
        _ => None,
    }),
    format_fn: None,
};

static FD_MAC: FieldDescriptor = FieldDescriptor::new(
    "message_authentication_code",
    "Message Authentication Code",
    FieldType::U32,
)
.optional();

static FD_SEQUENCE_NUMBER: FieldDescriptor =
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U8).optional();

static FD_PLAIN_NAS: FieldDescriptor =
    FieldDescriptor::new("plain_nas_message", "Plain NAS Message", FieldType::Object).optional();

// ── Field descriptors for 5GSM messages ────────────────────────────────

static FD_PDU_SESSION_ID: FieldDescriptor =
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8);

static FD_PTI: FieldDescriptor = FieldDescriptor::new(
    "procedure_transaction_identity",
    "Procedure Transaction Identity",
    FieldType::U8,
);

static FD_SM_MESSAGE_TYPE: FieldDescriptor = FieldDescriptor {
    name: "message_type",
    display_name: "Message Type",
    field_type: FieldType::U8,
    optional: false,
    children: None,
    display_fn: Some(|v, _siblings| match v {
        FieldValue::U8(m) => Some(sm_message_type_name(*m)),
        _ => None,
    }),
    format_fn: None,
};

// ── Top-level field descriptors for Dissector trait ─────────────────────

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "extended_protocol_discriminator",
        display_name: "Extended Protocol Discriminator",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(e) => Some(epd_name(*e)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "security_header_type",
        display_name: "Security Header Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => Some(security_header_type_name(*s)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "message_type",
        display_name: "Message Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(m) => Some(mm_message_type_name(*m)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new(
        "message_authentication_code",
        "Message Authentication Code",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U8).optional(),
    FieldDescriptor::new("plain_nas_message", "Plain NAS Message", FieldType::Object).optional(),
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8).optional(),
    FieldDescriptor::new(
        "procedure_transaction_identity",
        "Procedure Transaction Identity",
        FieldType::U8,
    )
    .optional(),
];

/// Push parsed 5G NAS PDU fields into the given [`DissectBuffer`].
///
/// This is the primary entry point for NGAP IE 38 (NAS-PDU) parsing.
/// Returns `true` if fields were pushed (structured parse succeeded),
/// or `false` if the data is too short / unknown EPD.
///
/// 3GPP TS 24.501, Section 8.
pub fn push_nas_pdu<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.is_empty() {
        return false;
    }

    let epd = data[0];
    match epd {
        EPD_5GMM => push_5gmm(buf, data, offset),
        EPD_5GSM => push_5gsm(buf, data, offset),
        _ => false,
    }
}

/// Push 5GMM fields into the buffer.
///
/// 3GPP TS 24.501, Section 8.2.
fn push_5gmm<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() < MIN_5GMM_SIZE {
        return false;
    }

    let security_header_type = data[1] & 0x0F;

    if security_header_type == 0 {
        push_5gmm_plain(buf, data, offset)
    } else {
        push_5gmm_security_protected(buf, data, offset, security_header_type)
    }
}

/// Push a plain (not security-protected) 5GMM message.
///
/// 3GPP TS 24.501, Section 8.2.
fn push_5gmm_plain<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() < MIN_5GMM_SIZE {
        return false;
    }

    let message_type = data[2];

    buf.push_field(&FD_EPD, FieldValue::U8(data[0]), offset..offset + 1);
    buf.push_field(
        &FD_SECURITY_HEADER_TYPE,
        FieldValue::U8(0),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &FD_MM_MESSAGE_TYPE,
        FieldValue::U8(message_type),
        offset + 2..offset + 3,
    );
    true
}

/// Push a security-protected 5GMM message.
///
/// 3GPP TS 24.501, Section 9.9.
fn push_5gmm_security_protected<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    security_header_type: u8,
) -> bool {
    if data.len() < MIN_SECURITY_PROTECTED_SIZE {
        return false;
    }

    let mac = read_be_u32(data, 2).unwrap_or_default();
    let seq = data[6];

    buf.push_field(&FD_EPD, FieldValue::U8(data[0]), offset..offset + 1);
    buf.push_field(
        &FD_SECURITY_HEADER_TYPE,
        FieldValue::U8(security_header_type),
        offset + 1..offset + 2,
    );
    buf.push_field(&FD_MAC, FieldValue::U32(mac), offset + 2..offset + 6);
    buf.push_field(
        &FD_SEQUENCE_NUMBER,
        FieldValue::U8(seq),
        offset + 6..offset + 7,
    );

    // Bytes 7+: Plain NAS message (starts with EPD again).
    let inner_data = &data[7..];
    let inner_offset = offset + 7;
    if !inner_data.is_empty() {
        let obj_idx = buf.begin_container(
            &FD_PLAIN_NAS,
            FieldValue::Object(0..0),
            inner_offset..offset + data.len(),
        );
        let ok = push_nas_pdu(buf, inner_data, inner_offset);
        if !ok {
            // Could not parse inner NAS — store raw bytes as a fallback field.
            buf.push_field(
                &FD_PLAIN_NAS,
                FieldValue::Bytes(inner_data),
                inner_offset..offset + data.len(),
            );
        }
        buf.end_container(obj_idx);
    }

    true
}

/// Push 5GSM fields into the buffer.
///
/// 3GPP TS 24.501, Section 8.3.
fn push_5gsm<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    if data.len() < MIN_5GSM_SIZE {
        return false;
    }

    let pdu_session_id = data[1];
    let pti = data[2];
    let message_type = data[3];

    buf.push_field(&FD_EPD, FieldValue::U8(data[0]), offset..offset + 1);
    buf.push_field(
        &FD_PDU_SESSION_ID,
        FieldValue::U8(pdu_session_id),
        offset + 1..offset + 2,
    );
    buf.push_field(&FD_PTI, FieldValue::U8(pti), offset + 2..offset + 3);
    buf.push_field(
        &FD_SM_MESSAGE_TYPE,
        FieldValue::U8(message_type),
        offset + 3..offset + 4,
    );
    true
}

/// 5G NAS (Non-Access Stratum) dissector.
///
/// Parses 5GS Mobility Management and Session Management messages.
/// Typically invoked via NGAP NAS-PDU IE, but can also be used standalone
/// via the registry factory.
///
/// 3GPP TS 24.501: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>
pub struct Nas5gDissector;

impl Dissector for Nas5gDissector {
    fn name(&self) -> &'static str {
        "5G NAS"
    }

    fn short_name(&self) -> &'static str {
        "NAS-5G"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.is_empty() {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        }

        let epd = data[0];

        buf.begin_layer(
            "NAS-5G",
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );

        match epd {
            EPD_5GMM => {
                if data.len() < MIN_5GMM_SIZE {
                    buf.end_layer();
                    return Err(PacketError::Truncated {
                        expected: MIN_5GMM_SIZE,
                        actual: data.len(),
                    });
                }

                let security_header_type = data[1] & 0x0F;
                buf.push_field(
                    &FIELD_DESCRIPTORS[0],
                    FieldValue::U8(epd),
                    offset..offset + 1,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[1],
                    FieldValue::U8(security_header_type),
                    offset + 1..offset + 2,
                );

                if security_header_type == 0 {
                    let message_type = data[2];
                    buf.push_field(
                        &FIELD_DESCRIPTORS[2],
                        FieldValue::U8(message_type),
                        offset + 2..offset + 3,
                    );
                } else if data.len() >= MIN_SECURITY_PROTECTED_SIZE {
                    let mac = read_be_u32(data, 2)?;
                    let seq = data[6];
                    buf.push_field(
                        &FIELD_DESCRIPTORS[3],
                        FieldValue::U32(mac),
                        offset + 2..offset + 6,
                    );
                    buf.push_field(
                        &FIELD_DESCRIPTORS[4],
                        FieldValue::U8(seq),
                        offset + 6..offset + 7,
                    );

                    // Parse inner plain NAS if present.
                    if data.len() > 7 {
                        let obj_idx = buf.begin_container(
                            &FIELD_DESCRIPTORS[5],
                            FieldValue::Object(0..0),
                            offset + 7..offset + data.len(),
                        );
                        push_nas_pdu(buf, &data[7..], offset + 7);
                        buf.end_container(obj_idx);
                    }
                }
            }
            EPD_5GSM => {
                if data.len() < MIN_5GSM_SIZE {
                    buf.end_layer();
                    return Err(PacketError::Truncated {
                        expected: MIN_5GSM_SIZE,
                        actual: data.len(),
                    });
                }

                buf.push_field(
                    &FIELD_DESCRIPTORS[0],
                    FieldValue::U8(epd),
                    offset..offset + 1,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[6],
                    FieldValue::U8(data[1]),
                    offset + 1..offset + 2,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[7],
                    FieldValue::U8(data[2]),
                    offset + 2..offset + 3,
                );
                buf.push_field(
                    &FD_SM_MESSAGE_TYPE,
                    FieldValue::U8(data[3]),
                    offset + 3..offset + 4,
                );
            }
            _ => {
                buf.end_layer();
                return Err(PacketError::InvalidHeader(
                    "unknown extended protocol discriminator",
                ));
            }
        }

        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # 3GPP TS 24.501 Coverage
    //!
    //! | Spec Section | Description                  | Test                              |
    //! |--------------|------------------------------|-----------------------------------|
    //! | 8.2          | Plain 5GMM message           | parse_plain_5gmm_registration_request |
    //! | 8.2          | Security protected 5GMM      | parse_security_protected_5gmm     |
    //! | 8.3          | 5GSM message                 | parse_5gsm_pdu_session_establishment |
    //! | 9.3          | Security header type         | parse_security_protected_5gmm     |
    //! | 8.2          | push_nas_pdu plain           | push_nas_pdu_plain_5gmm           |
    //! | 8.3          | push_nas_pdu 5GSM            | push_nas_pdu_5gsm                 |
    //! |              | Empty data                   | push_nas_pdu_empty                |
    //! |              | Unknown EPD                  | push_nas_pdu_unknown_epd          |
    //! |              | Truncated 5GMM               | push_nas_pdu_truncated_5gmm       |
    //! |              | Truncated 5GSM               | push_nas_pdu_truncated_5gsm       |

    use super::*;

    #[test]
    fn push_nas_pdu_plain_5gmm() {
        // Plain 5GMM Registration Request
        let data = [
            0x7E, // EPD: 5GMM
            0x00, // Security header: plain
            0x41, // Message type: Registration request
            0xAA, // Dummy IE data
        ];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 0);
        assert!(ok);
        assert_eq!(buf.fields().len(), 3);
        assert_eq!(buf.fields()[0].name(), "extended_protocol_discriminator");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0x7E));
        assert_eq!(buf.fields()[1].name(), "security_header_type");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(0));
        assert_eq!(buf.fields()[2].name(), "message_type");
        assert_eq!(buf.fields()[2].value, FieldValue::U8(0x41));

        // Check display_fn for message type.
        let display_fn = buf.fields()[2].descriptor.display_fn.unwrap();
        assert_eq!(
            display_fn(&buf.fields()[2].value, buf.fields()),
            Some("Registration request")
        );
    }

    #[test]
    fn push_nas_pdu_5gsm() {
        // 5GSM PDU session establishment request
        let data = [
            0x2E, // EPD: 5GSM
            0x01, // PDU session ID
            0x00, // PTI
            0xC1, // Message type: PDU session establishment request
            0xBB, // Dummy IE data
        ];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 10);
        assert!(ok);
        assert_eq!(buf.fields().len(), 4);
        assert_eq!(buf.fields()[0].name(), "extended_protocol_discriminator");
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0x2E));
        assert_eq!(buf.fields()[1].name(), "pdu_session_id");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(0x01));
        assert_eq!(buf.fields()[2].name(), "procedure_transaction_identity");
        assert_eq!(buf.fields()[2].value, FieldValue::U8(0x00));
        assert_eq!(buf.fields()[3].name(), "message_type");
        assert_eq!(buf.fields()[3].value, FieldValue::U8(0xC1));
        // Verify offset tracking.
        assert_eq!(buf.fields()[0].range, 10..11);
        assert_eq!(buf.fields()[3].range, 13..14);
    }

    #[test]
    fn push_security_protected_5gmm() {
        // Security-protected 5GMM: integrity protected, wrapping a plain
        // Registration request.
        let data = [
            0x7E, // EPD: 5GMM
            0x01, // Security header: integrity protected
            0x00, 0x00, 0x00, 0x01, // MAC = 1
            0x05, // Sequence number = 5
            // Inner plain NAS:
            0x7E, // EPD: 5GMM
            0x00, // Security header: plain
            0x41, // Message type: Registration request
        ];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 0);
        assert!(ok);
        assert_eq!(buf.fields()[0].value, FieldValue::U8(0x7E));
        assert_eq!(buf.fields()[1].name(), "security_header_type");
        assert_eq!(buf.fields()[1].value, FieldValue::U8(1));
        assert_eq!(buf.fields()[2].name(), "message_authentication_code");
        assert_eq!(buf.fields()[2].value, FieldValue::U32(1));
        assert_eq!(buf.fields()[3].name(), "sequence_number");
        assert_eq!(buf.fields()[3].value, FieldValue::U8(5));
        assert_eq!(buf.fields()[4].name(), "plain_nas_message");
        // Inner message should be a container Object.
        if let FieldValue::Object(ref range) = buf.fields()[4].value {
            let inner = buf.nested_fields(range);
            let mt = inner.iter().find(|f| f.name() == "message_type").unwrap();
            assert_eq!(mt.value, FieldValue::U8(0x41));
        } else {
            panic!("expected inner Object");
        }
    }

    #[test]
    fn push_nas_pdu_empty() {
        let data: &[u8] = &[];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, data, 0);
        assert!(!ok);
    }

    #[test]
    fn push_nas_pdu_unknown_epd() {
        let data = [0x99, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 0);
        assert!(!ok);
    }

    #[test]
    fn push_nas_pdu_truncated_5gmm() {
        // Only EPD + security header, missing message type.
        let data = [0x7E, 0x00];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 0);
        assert!(!ok);
    }

    #[test]
    fn push_nas_pdu_truncated_5gsm() {
        // Only 3 bytes, 5GSM needs 4.
        let data = [0x2E, 0x01, 0x00];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 0);
        assert!(!ok);
    }

    #[test]
    fn parse_plain_5gmm_registration_request() {
        let data = [0x7E, 0x00, 0x41];
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 3);

        let layer = buf.layer_by_name("NAS-5G").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "extended_protocol_discriminator")
                .unwrap()
                .value,
            FieldValue::U8(0x7E)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "extended_protocol_discriminator_name"),
            Some("5GS mobility management")
        );
        assert_eq!(
            buf.field_by_name(layer, "message_type").unwrap().value,
            FieldValue::U8(0x41)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Registration request")
        );
    }

    #[test]
    fn parse_5gsm_pdu_session_establishment() {
        let data = [0x2E, 0x01, 0x00, 0xC1];
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 4);

        let layer = buf.layer_by_name("NAS-5G").unwrap();
        assert_eq!(
            buf.field_by_name(layer, "pdu_session_id").unwrap().value,
            FieldValue::U8(0x01)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("PDU session establishment request")
        );
    }

    #[test]
    fn dissect_truncated_5gmm() {
        let data = [0x7E, 0x00];
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 0);
        assert!(matches!(result, Err(PacketError::Truncated { .. })));
    }

    #[test]
    fn dissect_unknown_epd() {
        let data = [0x99, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 0);
        assert!(matches!(result, Err(PacketError::InvalidHeader(_))));
    }

    #[test]
    fn field_descriptors_accessible() {
        let d = Nas5gDissector;
        assert_eq!(d.field_descriptors().len(), 8);
    }
}
