//! 5G NAS (Non-Access Stratum) dissector.
//!
//! Parses 5GS Mobility Management (5GMM) and 5GS Session Management (5GSM)
//! messages as defined in 3GPP TS 24.501. Typically carried inside NGAP
//! NAS-PDU Information Elements.
//!
//! ## References
//! - 3GPP TS 24.501: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>
//! - 3GPP TS 24.007, Section 11.2 — Extended Protocol Discriminator
//!
//! After the header, the information elements of the message are decoded
//! into an `information_elements` array (TS 24.501, Sections 8.2, 8.3 and
//! 9.11). An N1 SM payload container of a UL or DL NAS transport message is
//! decoded as a nested 5GSM message.

#![deny(missing_docs)]

mod ie;
pub mod message_type;
mod messages;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
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
pub(crate) const EPD_5GSM: u8 = 0x2E;

/// Minimum message size: EPD (1) + security header / PDU session ID (1) +
/// message type (1) = 3 bytes for plain 5GMM. 5GSM requires 4 bytes.
const MIN_5GMM_SIZE: usize = 3;

/// Minimum 5GSM message size: EPD (1) + PDU session ID (1) + PTI (1) +
/// message type (1) = 4 bytes.
const MIN_5GSM_SIZE: usize = 4;

/// Security-protected 5GMM message minimum: EPD (1) + security header (1) +
/// MAC (4) + sequence number (1) = 7 bytes. The plain 5GS NAS message
/// starts at octet 8.
///
/// 3GPP TS 24.501, Section 9.1.1, Figure 9.1.1.2.
const MIN_SECURITY_PROTECTED_SIZE: usize = 7;

/// Offset of the plain 5GS NAS message (octet 8) in a security protected
/// 5GS NAS message.
///
/// 3GPP TS 24.501, Section 9.1.1, Figure 9.1.1.2.
const SECURITY_PROTECTED_PAYLOAD_OFFSET: usize = 7;

/// Security header type: plain 5GS NAS message, not security protected.
///
/// 3GPP TS 24.501, Section 9.3, Table 9.3.1.
const SHT_PLAIN: u8 = 0;

/// Security header type: integrity protected.
///
/// 3GPP TS 24.501, Section 9.3, Table 9.3.1.
const SHT_INTEGRITY_PROTECTED: u8 = 1;

/// Security header type: integrity protected with new 5G NAS security
/// context.
///
/// 3GPP TS 24.501, Section 9.3, Table 9.3.1.
const SHT_INTEGRITY_PROTECTED_NEW_CONTEXT: u8 = 3;

/// Security header type: integrity protected and ciphered with new 5G NAS
/// security context.
///
/// 3GPP TS 24.501, Section 9.3, Table 9.3.1.
const SHT_INTEGRITY_PROTECTED_AND_CIPHERED_NEW_CONTEXT: u8 = 4;

// ── Field descriptors for 5GMM plain messages ──────────────────────────

pub(crate) static FD_EPD: FieldDescriptor = FieldDescriptor {
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

static FD_CIPHERED_NAS: FieldDescriptor = FieldDescriptor::new(
    "ciphered_nas_message",
    "Ciphered NAS Message",
    FieldType::Bytes,
)
.optional();

static FD_RAW_NAS: FieldDescriptor =
    FieldDescriptor::new("raw_nas_message", "Raw NAS Message", FieldType::Bytes).optional();

// ── Field descriptors for 5GSM messages ────────────────────────────────

pub(crate) static FD_PDU_SESSION_ID: FieldDescriptor =
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U8);

pub(crate) static FD_PTI: FieldDescriptor = FieldDescriptor::new(
    "procedure_transaction_identity",
    "Procedure Transaction Identity",
    FieldType::U8,
);

pub(crate) static FD_SM_MESSAGE_TYPE: FieldDescriptor = FieldDescriptor {
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
    FieldDescriptor::new(
        "ciphered_nas_message",
        "Ciphered NAS Message",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("raw_nas_message", "Raw NAS Message", FieldType::Bytes).optional(),
    ie::FD_INFORMATION_ELEMENTS,
    ie::FD_UNDECODED_OCTETS,
    ie::FD_MISSING_MANDATORY_IE,
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

    match security_header_type {
        SHT_PLAIN => push_5gmm_plain(buf, data, offset),
        SHT_INTEGRITY_PROTECTED..=SHT_INTEGRITY_PROTECTED_AND_CIPHERED_NEW_CONTEXT => {
            push_5gmm_security_protected(buf, data, offset, security_header_type)
        }
        _ => {
            buf.push_field(&FD_EPD, FieldValue::U8(data[0]), offset..offset + 1);
            buf.push_field(
                &FD_SECURITY_HEADER_TYPE,
                FieldValue::U8(security_header_type),
                offset + 1..offset + 2,
            );
            push_reserved_sht_body(buf, data, offset);
            true
        }
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
    push_5gmm_body(buf, data, offset);
    true
}

/// Push the IEs of a plain 5GMM message (octet 4 onwards).
///
/// 3GPP TS 24.501, Section 8.2. The body of a message type without an IE
/// table is kept as raw bytes.
fn push_5gmm_body<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let body = &data[MIN_5GMM_SIZE..];
    match messages::mm_message_ies(data[2]) {
        Some(ies) => ie::push_message_ies(buf, body, offset + MIN_5GMM_SIZE, ies, true),
        None => push_raw_body(buf, body, offset + MIN_5GMM_SIZE),
    }
}

/// Push the IEs of a 5GSM message (octet 5 onwards).
///
/// 3GPP TS 24.501, Section 8.3. The body of a message type without an IE
/// table is kept as raw bytes.
fn push_5gsm_body<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let body = &data[MIN_5GSM_SIZE..];
    match messages::sm_message_ies(data[3]) {
        // A 5GSM message never carries another NAS message.
        Some(ies) => ie::push_message_ies(buf, body, offset + MIN_5GSM_SIZE, ies, false),
        None => push_raw_body(buf, body, offset + MIN_5GSM_SIZE),
    }
}

/// Push the body of a message type without an IE table as
/// `undecoded_octets`.
fn push_raw_body<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], offset: usize) {
    if !body.is_empty() {
        buf.push_field(
            &ie::FD_UNDECODED_OCTETS,
            FieldValue::Bytes(body),
            offset..offset + body.len(),
        );
    }
}

/// Push a security-protected 5GMM message.
///
/// 3GPP TS 24.501, Section 9.1.1, Figure 9.1.1.2.
fn push_5gmm_security_protected<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    security_header_type: u8,
) -> bool {
    if data.len() < MIN_SECURITY_PROTECTED_SIZE {
        return false;
    }

    buf.push_field(&FD_EPD, FieldValue::U8(data[0]), offset..offset + 1);
    buf.push_field(
        &FD_SECURITY_HEADER_TYPE,
        FieldValue::U8(security_header_type),
        offset + 1..offset + 2,
    );
    push_security_protected_body(buf, data, offset, security_header_type);

    true
}

/// Push the MAC, the sequence number and the plain 5GS NAS message part
/// (octet 8 onwards) of a security protected 5GMM message.
///
/// The caller has already pushed the EPD and the security header type and
/// checked that `data` holds at least [`MIN_SECURITY_PROTECTED_SIZE`] bytes.
///
/// 3GPP TS 24.501, Section 4.4.5 — <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>:
/// "the sender shall cipher the plain 5GS NAS message portion of the
/// security protected 5GS NAS message (see figure 9.1.1.2), i.e. octet 8
/// and all subsequent octets". Also: "If the "null ciphering algorithm"
/// 5G-EA0 has been selected as a ciphering algorithm, the NAS messages with
/// the security header indicating ciphering are regarded as ciphered."
///
/// So for the ciphered security header types (Table 9.3.1: 2 and 4) the
/// payload is reported as opaque bytes and never parsed as a NAS message.
fn push_security_protected_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    security_header_type: u8,
) {
    let Ok(mac) = read_be_u32(data, 2) else {
        return;
    };
    buf.push_field(&FD_MAC, FieldValue::U32(mac), offset + 2..offset + 6);
    buf.push_field(
        &FD_SEQUENCE_NUMBER,
        FieldValue::U8(data[6]),
        offset + 6..offset + 7,
    );

    let payload = &data[SECURITY_PROTECTED_PAYLOAD_OFFSET..];
    if payload.is_empty() {
        return;
    }
    let payload_offset = offset + SECURITY_PROTECTED_PAYLOAD_OFFSET;
    let payload_range = payload_offset..offset + data.len();

    match security_header_type {
        SHT_INTEGRITY_PROTECTED | SHT_INTEGRITY_PROTECTED_NEW_CONTEXT => {
            // Integrity protected only (types 1 and 3): octet 8 onwards is
            // the plain 5GS NAS message in clear text.
            let obj_idx = buf.begin_container(
                &FD_PLAIN_NAS,
                FieldValue::Object(0..0),
                payload_range.clone(),
            );
            if !push_plain_nas_message(buf, payload, payload_offset) {
                // Could not parse inner NAS — store raw bytes as a fallback field.
                buf.push_field(&FD_RAW_NAS, FieldValue::Bytes(payload), payload_range);
            }
            buf.end_container(obj_idx);
        }
        _ => {
            // Integrity protected and ciphered (types 2 and 4). Anything
            // not known to be clear text is kept opaque.
            buf.push_field(&FD_CIPHERED_NAS, FieldValue::Bytes(payload), payload_range);
        }
    }
}

/// Push the plain 5GS NAS message carried in octet 8 onwards of a security
/// protected 5GS NAS message.
///
/// Returns `false` when `data` is not a plain 5GS NAS message, including a
/// 5GMM message that is itself security protected. Such a message is never
/// decoded, which also bounds the nesting depth.
///
/// 3GPP TS 24.501, Section 9.1.1 — <https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/>:
/// a security protected 5GS NAS message consists of "plain 5GS NAS message,
/// as defined in item 1".
fn push_plain_nas_message<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    match data.first() {
        Some(&EPD_5GMM) => {
            data.len() >= MIN_5GMM_SIZE
                && data[1] & 0x0F == SHT_PLAIN
                && push_5gmm_plain(buf, data, offset)
        }
        Some(&EPD_5GSM) => push_5gsm(buf, data, offset),
        _ => false,
    }
}

/// Push the octets after the security header type of a 5GMM message whose
/// security header type is reserved.
///
/// 3GPP TS 24.501, Section 9.3, Table 9.3.1: "All other values are
/// reserved." The layout of the rest of the message is not defined, so it
/// is kept as raw bytes.
fn push_reserved_sht_body<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let rest = &data[2..];
    if !rest.is_empty() {
        buf.push_field(
            &FD_RAW_NAS,
            FieldValue::Bytes(rest),
            offset + 2..offset + data.len(),
        );
    }
}

/// Push 5GSM fields into the buffer.
///
/// 3GPP TS 24.501, Section 8.3.
pub(crate) fn push_5gsm<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
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
    push_5gsm_body(buf, data, offset);
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

/// Specification references for the 5G NAS dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 24.501",
        "Non-Access-Stratum (NAS) protocol for 5G System (5GS); Stage 3",
        "https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/",
    ),
    SpecReference::new(
        "3GPP TS 24.007",
        "Mobile radio interface signalling layer 3; General aspects",
        "https://www.3gpp.org/ftp/Specs/archive/24_series/24.007/",
    ),
];

impl Dissector for Nas5gDissector {
    fn name(&self) -> &'static str {
        "5G NAS"
    }

    fn short_name(&self) -> &'static str {
        "NAS-5G"
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
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
                // 3GPP TS 24.501, Section 9.1.1, Figure 9.1.1.2: a security
                // protected message carries a MAC and a sequence number.
                if (SHT_INTEGRITY_PROTECTED..=SHT_INTEGRITY_PROTECTED_AND_CIPHERED_NEW_CONTEXT)
                    .contains(&security_header_type)
                    && data.len() < MIN_SECURITY_PROTECTED_SIZE
                {
                    buf.end_layer();
                    return Err(PacketError::Truncated {
                        expected: MIN_SECURITY_PROTECTED_SIZE,
                        actual: data.len(),
                    });
                }

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

                match security_header_type {
                    SHT_PLAIN => {
                        buf.push_field(
                            &FIELD_DESCRIPTORS[2],
                            FieldValue::U8(data[2]),
                            offset + 2..offset + 3,
                        );
                        push_5gmm_body(buf, data, offset);
                    }
                    SHT_INTEGRITY_PROTECTED..=SHT_INTEGRITY_PROTECTED_AND_CIPHERED_NEW_CONTEXT => {
                        push_security_protected_body(buf, data, offset, security_header_type);
                    }
                    _ => push_reserved_sht_body(buf, data, offset),
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
                push_5gsm_body(buf, data, offset);
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
    //! | 4.4.5, 9.3   | Type 1: inner plain decoded  | push_security_protected_5gmm      |
    //! | 4.4.5, 9.3   | Type 3: inner plain decoded  | push_integrity_new_context_decodes_inner |
    //! | 4.4.5, 9.3   | Type 2: payload is ciphered  | push_ciphered_5gmm_not_decoded    |
    //! | 4.4.5, 9.3   | Type 4: payload is ciphered  | push_ciphered_new_context_not_decoded |
    //! | 4.4.5, 9.3   | Ciphered, no payload octets  | push_ciphered_without_payload     |
    //! | 9.3          | Reserved security header type | push_reserved_security_header_type |
    //! | 9.1.1        | Inner message must be plain  | push_nested_security_protected_not_decoded |
    //! | 9.1.1        | Inner plain 5GSM decoded     | push_integrity_protected_inner_5gsm_decoded |
    //! | 9.1.1        | Truncated inner 5GMM kept raw | push_integrity_protected_truncated_inner_5gmm_kept_raw |
    //! | 9.1.1        | Deep nesting, no recursion   | push_deeply_nested_security_protected_does_not_overflow |
    //! | 9.1.1        | Dissector: deep nesting      | dissect_nested_security_protected_not_recursed |
    //! | 9.1.1        | Dissector: truncated header  | dissect_truncated_security_protected_5gmm |
    //! | 4.4.5, 9.3   | Dissector: type 2 ciphered   | dissect_ciphered_5gmm_not_decoded |
    //! | 4.4.5, 9.3   | Dissector: type 4 ciphered   | dissect_ciphered_new_context_not_decoded |
    //! | 4.4.5, 9.3   | Dissector: type 1 decoded    | dissect_integrity_protected_decodes_inner |
    //! | 9.3          | Dissector: inner not parsable | dissect_integrity_protected_unparsable_inner |
    //! | 9.3          | Dissector: reserved type     | dissect_reserved_security_header_type |
    //! | 8.2          | push_nas_pdu plain           | push_nas_pdu_plain_5gmm           |
    //! | 8.3          | push_nas_pdu 5GSM            | push_nas_pdu_5gsm                 |
    //! |              | Empty data                   | push_nas_pdu_empty                |
    //! |              | Unknown EPD                  | push_nas_pdu_unknown_epd          |
    //! |              | Truncated 5GMM               | push_nas_pdu_truncated_5gmm       |
    //! |              | Truncated 5GSM               | push_nas_pdu_truncated_5gsm       |

    use super::*;
    use packet_dissector_core::field::Field;

    #[test]
    fn push_nas_pdu_plain_5gmm() {
        // Plain 5GMM Registration Request
        let data = [
            0x7E, // EPD: 5GMM
            0x00, // Security header: plain
            0x41, // Message type: Registration request
        ];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 0);
        assert!(ok);
        // No octets after the header: the mandatory IEs are reported as
        // missing.
        assert_eq!(buf.fields().len(), 4);
        assert_eq!(buf.fields()[3].name(), "missing_mandatory_ie");
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
        ];
        let mut buf = DissectBuffer::new();
        let ok = push_nas_pdu(&mut buf, &data, 10);
        assert!(ok);
        // No octets after the header: the mandatory IE is reported as
        // missing.
        assert_eq!(buf.fields().len(), 5);
        assert_eq!(buf.fields()[4].name(), "missing_mandatory_ie");
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

    /// Security protected 5GMM header (EPD, security header type, MAC,
    /// sequence number) followed by `payload`.
    fn security_protected(sht: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0x7E, sht, 0x12, 0x34, 0x56, 0x78, 0x03];
        data.extend_from_slice(payload);
        data
    }

    /// Assert that a security protected message was reported with its
    /// payload as an opaque `ciphered_nas_message` and nothing decoded.
    fn assert_ciphered(fields: &[Field<'_>], sht: u8, payload: &[u8], offset: usize) {
        let names: Vec<_> = fields.iter().map(|f| f.name()).collect();
        assert_eq!(
            names,
            [
                "extended_protocol_discriminator",
                "security_header_type",
                "message_authentication_code",
                "sequence_number",
                "ciphered_nas_message",
            ]
        );
        assert_eq!(fields[1].value, FieldValue::U8(sht));
        assert_eq!(fields[2].value, FieldValue::U32(0x1234_5678));
        assert_eq!(fields[3].value, FieldValue::U8(3));
        assert_eq!(fields[4].value, FieldValue::Bytes(payload));
        assert_eq!(fields[4].range, offset + 7..offset + 7 + payload.len());
    }

    #[test]
    fn push_ciphered_5gmm_not_decoded() {
        // TS 24.501, 4.4.5: octet 8 onwards is ciphered. A first
        // ciphertext octet of 0x2e or 0x7e must not be taken as an EPD.
        for payload in [
            &[0x2e, 0x9a, 0x41, 0xc7, 0x55][..],
            &[0x7e, 0x00, 0x41, 0x01][..],
            &[0x99, 0x01][..],
        ] {
            let data = security_protected(0x02, payload);
            let mut buf = DissectBuffer::new();
            assert!(push_nas_pdu(&mut buf, &data, 20));
            assert_ciphered(buf.fields(), 2, payload, 20);
        }
    }

    #[test]
    fn push_ciphered_new_context_not_decoded() {
        for payload in [&[0x7e, 0x00, 0x5e][..], &[0x2e, 0x01, 0x00, 0xc1][..]] {
            let data = security_protected(0x04, payload);
            let mut buf = DissectBuffer::new();
            assert!(push_nas_pdu(&mut buf, &data, 0));
            assert_ciphered(buf.fields(), 4, payload, 0);
        }
    }

    #[test]
    fn push_ciphered_without_payload() {
        let data = security_protected(0x02, &[]);
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 0));
        assert_eq!(buf.fields().len(), 4);
        assert!(
            buf.fields()
                .iter()
                .all(|f| f.name() != "ciphered_nas_message")
        );
    }

    #[test]
    fn push_integrity_new_context_decodes_inner() {
        // Type 3 (integrity protected with new 5G NAS security context)
        // is not ciphered, so the inner Security mode command is decoded.
        let data = security_protected(0x03, &[0x7e, 0x00, 0x5d]);
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 0));
        assert_eq!(buf.fields()[4].name(), "plain_nas_message");
        let FieldValue::Object(ref range) = buf.fields()[4].value else {
            panic!("expected inner Object");
        };
        let inner = buf.nested_fields(range);
        let mt = inner.iter().find(|f| f.name() == "message_type").unwrap();
        assert_eq!(mt.value, FieldValue::U8(0x5d));
        assert!(
            buf.fields()
                .iter()
                .all(|f| f.name() != "ciphered_nas_message")
        );
    }

    #[test]
    fn push_reserved_security_header_type() {
        // TS 24.501, Table 9.3.1: "All other values are reserved." The
        // layout after octet 2 is unknown, so it is kept as raw bytes.
        let data = [0x7E, 0x05, 0x2e, 0x01, 0x00, 0xc1];
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 4));
        let names: Vec<_> = buf.fields().iter().map(|f| f.name()).collect();
        assert_eq!(
            names,
            [
                "extended_protocol_discriminator",
                "security_header_type",
                "raw_nas_message",
            ]
        );
        assert_eq!(buf.fields()[1].value, FieldValue::U8(5));
        assert_eq!(buf.fields()[2].value, FieldValue::Bytes(&data[2..]));
        assert_eq!(buf.fields()[2].range, 6..10);
    }

    /// `depth` integrity protected headers, each wrapping the next, around a
    /// plain Registration request.
    fn deeply_nested_security_protected(depth: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(depth * 7 + 3);
        for _ in 0..depth {
            data.extend_from_slice(&[0x7E, 0x01, 0, 0, 0, 0, 0]);
        }
        data.extend_from_slice(&[0x7E, 0x00, 0x41]);
        data
    }

    #[test]
    fn push_nested_security_protected_not_decoded() {
        // TS 24.501, 9.1.1: octet 8 onwards of a security protected message
        // is a "plain 5GS NAS message, as defined in item 1". An inner
        // security protected 5GMM message is not valid there and is kept as
        // raw bytes.
        let inner = security_protected(0x01, &[0x7e, 0x00, 0x41]);
        let data = security_protected(0x01, &inner);
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 0));
        assert_eq!(buf.fields()[4].name(), "plain_nas_message");
        let FieldValue::Object(ref range) = buf.fields()[4].value else {
            panic!("expected inner Object");
        };
        let nested = buf.nested_fields(range);
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].name(), "raw_nas_message");
        assert_eq!(nested[0].value, FieldValue::Bytes(&inner));
        assert_eq!(nested[0].range, 7..data.len());
    }

    #[test]
    fn push_integrity_protected_inner_5gsm_decoded() {
        // A plain 5GSM message is a "plain 5GS NAS message" (TS 24.501,
        // 9.1.1 item 1), so it is decoded. PDU session release complete has
        // no mandatory IE after the header.
        let data = security_protected(0x01, &[0x2e, 0x05, 0x01, 0xd4]);
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 0));
        let FieldValue::Object(ref range) = buf.fields()[4].value else {
            panic!("expected inner Object");
        };
        let nested = buf.nested_fields(range);
        let names: Vec<_> = nested.iter().map(|f| f.name()).collect();
        assert_eq!(
            names,
            [
                "extended_protocol_discriminator",
                "pdu_session_id",
                "procedure_transaction_identity",
                "message_type",
            ]
        );
        assert_eq!(nested[1].value, FieldValue::U8(0x05));
        assert_eq!(nested[3].value, FieldValue::U8(0xd4));
    }

    #[test]
    fn push_integrity_protected_truncated_inner_5gmm_kept_raw() {
        let data = security_protected(0x01, &[0x7e, 0x00]);
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 0));
        let FieldValue::Object(ref range) = buf.fields()[4].value else {
            panic!("expected inner Object");
        };
        let nested = buf.nested_fields(range);
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].name(), "raw_nas_message");
        assert_eq!(nested[0].value, FieldValue::Bytes(&[0x7e, 0x00]));
    }

    #[test]
    fn push_deeply_nested_security_protected_does_not_overflow() {
        let data = deeply_nested_security_protected(10_000);
        let mut buf = DissectBuffer::new();
        assert!(push_nas_pdu(&mut buf, &data, 0));
        assert_eq!(buf.fields().len(), 6);
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

    /// Fields of the NAS-5G layer, in order.
    fn layer_fields<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> &'a [Field<'pkt>] {
        let layer = buf.layer_by_name("NAS-5G").unwrap();
        buf.layer_fields(layer)
    }

    #[test]
    fn dissect_ciphered_5gmm_not_decoded() {
        let payload = [0x2e, 0x9a, 0x41, 0xc7, 0x55];
        let data = security_protected(0x02, &payload);
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 14).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert_ciphered(layer_fields(&buf), 2, &payload, 14);
    }

    #[test]
    fn dissect_ciphered_new_context_not_decoded() {
        let payload = [0x7e, 0x00, 0x5e];
        let data = security_protected(0x04, &payload);
        let mut buf = DissectBuffer::new();
        Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_ciphered(layer_fields(&buf), 4, &payload, 0);
    }

    #[test]
    fn dissect_integrity_protected_unparsable_inner() {
        // The inner octets do not start with a known EPD: keep them as raw
        // bytes instead of dropping them.
        let payload = [0x99, 0x01, 0x02];
        let data = security_protected(0x01, &payload);
        let mut buf = DissectBuffer::new();
        Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("NAS-5G").unwrap();
        let plain = buf.field_by_name(layer, "plain_nas_message").unwrap();
        let FieldValue::Object(ref range) = plain.value else {
            panic!("expected inner Object");
        };
        let inner = buf.nested_fields(range);
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].name(), "raw_nas_message");
        assert_eq!(inner[0].descriptor.field_type, FieldType::Bytes);
        assert_eq!(inner[0].value, FieldValue::Bytes(&payload));
    }

    #[test]
    fn dissect_integrity_protected_decodes_inner() {
        let data = security_protected(0x01, &[0x7e, 0x00, 0x67]);
        let mut buf = DissectBuffer::new();
        Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = buf.layer_by_name("NAS-5G").unwrap();
        let plain = buf.field_by_name(layer, "plain_nas_message").unwrap();
        let FieldValue::Object(ref range) = plain.value else {
            panic!("expected inner Object");
        };
        let inner = buf.nested_fields(range);
        let mt = inner.iter().find(|f| f.name() == "message_type").unwrap();
        assert_eq!(mt.value, FieldValue::U8(0x67));
    }

    #[test]
    fn dissect_reserved_security_header_type() {
        let data = [0x7E, 0x0f, 0x7e, 0x00, 0x41];
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        let fields = layer_fields(&buf);
        let names: Vec<_> = fields.iter().map(|f| f.name()).collect();
        assert_eq!(
            names,
            [
                "extended_protocol_discriminator",
                "security_header_type",
                "raw_nas_message",
            ]
        );
        assert_eq!(fields[2].value, FieldValue::Bytes(&data[2..]));
    }

    #[test]
    fn dissect_truncated_security_protected_5gmm() {
        // Security protected header needs 7 octets (Figure 9.1.1.2).
        for data in [&[0x7E, 0x02, 0x12, 0x34][..], &[0x7E, 0x01, 0, 0, 0, 0][..]] {
            let mut buf = DissectBuffer::new();
            let result = Nas5gDissector.dissect(data, &mut buf, 0);
            assert!(
                matches!(
                    result,
                    Err(PacketError::Truncated {
                        expected: 7,
                        actual
                    }) if actual == data.len()
                ),
                "{data:02x?}: {result:?}"
            );
        }
    }

    #[test]
    fn dissect_nested_security_protected_not_recursed() {
        let data = deeply_nested_security_protected(10_000);
        let mut buf = DissectBuffer::new();
        let result = Nas5gDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
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
        assert_eq!(d.field_descriptors().len(), 13);
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = Nas5gDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }
}
