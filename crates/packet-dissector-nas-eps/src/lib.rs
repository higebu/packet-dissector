//! EPS NAS (Non-Access Stratum) dissector.
//!
//! Parses EPS Mobility Management (EMM) and EPS Session Management (ESM)
//! messages as defined in 3GPP TS 24.301. Typically carried inside the S1AP
//! NAS-PDU IE.
//!
//! ## References
//! - 3GPP TS 24.301: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>
//! - 3GPP TS 24.007, Section 11.2.3.1.1 — Protocol discriminator:
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.007/>
//! - 3GPP TS 24.008 (IEs referenced by TS 24.301):
//!   <https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/>
//!
//! After the header, the information elements of the message are decoded
//! into an `information_elements` array (TS 24.301, Sections 8.2, 8.3 and
//! 9.9). An ESM message container is decoded as a nested ESM message.
//! Ciphered NAS messages are kept as opaque octets.

#![deny(missing_docs)]

mod ie;
mod messages;
pub mod names;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use names::{
    emm_message_type_name, esm_message_type_name, protocol_discriminator_name,
    security_header_type_name,
};

/// Protocol discriminator: EPS session management messages.
///
/// 3GPP TS 24.007, Section 11.2.3.1.1, Table 11.2.
const PD_ESM: u8 = 0x2;

/// Protocol discriminator: EPS mobility management messages.
///
/// 3GPP TS 24.007, Section 11.2.3.1.1, Table 11.2.
const PD_EMM: u8 = 0x7;

/// Plain EMM message header: security header type / protocol discriminator
/// (1) and message type (1).
///
/// 3GPP TS 24.301, Section 9.1, Figure 9.1.1.
const EMM_HEADER_SIZE: usize = 2;

/// Plain ESM message header: EPS bearer identity / protocol discriminator
/// (1), procedure transaction identity (1) and message type (1).
///
/// 3GPP TS 24.301, Section 9.1, Figure 9.1.1.
const ESM_HEADER_SIZE: usize = 3;

/// Security protected NAS message header: security header type / protocol
/// discriminator (1), message authentication code (4) and sequence number
/// (1). The NAS message starts at octet 7.
///
/// 3GPP TS 24.301, Section 9.1, Figure 9.1.2.
const SECURITY_HEADER_SIZE: usize = 6;

/// SERVICE REQUEST message: security header type / protocol discriminator
/// (1), KSI and sequence number (1) and short MAC (2).
///
/// 3GPP TS 24.301, Section 8.2.25, Table 8.2.25.1.
const SERVICE_REQUEST_SIZE: usize = 4;

/// Message type of CONTROL PLANE SERVICE REQUEST.
///
/// 3GPP TS 24.301, Section 9.8, Table 9.8.1.
const MT_CONTROL_PLANE_SERVICE_REQUEST: u8 = 0x4d;

// Security header types — 3GPP TS 24.301, Section 9.3.1, Table 9.3.1.

/// Plain NAS message, not security protected.
const SHT_PLAIN: u8 = 0;
/// Integrity protected.
const SHT_INTEGRITY_PROTECTED: u8 = 1;
/// Integrity protected with new EPS security context.
const SHT_INTEGRITY_PROTECTED_NEW_CONTEXT: u8 = 3;
/// Integrity protected and partially ciphered NAS message.
const SHT_PARTIALLY_CIPHERED: u8 = 5;
/// Security header for the EMM TRANSPORT message.
const SHT_EMM_TRANSPORT: u8 = 0b1011;
/// Security header for the SERVICE REQUEST message ("1101" to "1111"
/// "shall be interpreted as '1100'").
const SHT_SERVICE_REQUEST: u8 = 0b1100;

const FD_SECURITY_HEADER_TYPE: usize = 0;
const FD_PROTOCOL_DISCRIMINATOR: usize = 1;
const FD_EPS_BEARER_IDENTITY: usize = 2;
const FD_PTI: usize = 3;
const FD_MESSAGE_TYPE: usize = 4;
const FD_MAC: usize = 5;
const FD_SEQUENCE_NUMBER: usize = 6;
const FD_KSI: usize = 7;
const FD_SHORT_MAC: usize = 8;
const FD_PLAIN_NAS_MESSAGE: usize = 9;
const FD_CIPHERED_NAS_MESSAGE: usize = 10;
const FD_RAW_NAS_MESSAGE: usize = 11;

/// Top-level fields of an EPS NAS message. The same fields are pushed for a
/// NAS message nested in a `plain_nas_message` or `esm_message` object.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new(
        "security_header_type",
        "Security Header Type",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(s) => security_header_type_name(*s),
        _ => None,
    }),
    FieldDescriptor::new(
        "protocol_discriminator",
        "Protocol Discriminator",
        FieldType::U8,
    )
    .with_display_fn(|v, _| match v {
        FieldValue::U8(p) => protocol_discriminator_name(*p),
        _ => None,
    }),
    FieldDescriptor::new("eps_bearer_identity", "EPS Bearer Identity", FieldType::U8).optional(),
    FieldDescriptor::new(
        "procedure_transaction_identity",
        "Procedure Transaction Identity",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, siblings| {
            let pd = siblings
                .iter()
                .find(|f| f.name() == "protocol_discriminator")
                .and_then(|f| f.value.as_u8())?;
            match (pd, v) {
                (PD_EMM, FieldValue::U8(m)) => emm_message_type_name(*m),
                (PD_ESM, FieldValue::U8(m)) => esm_message_type_name(*m),
                _ => None,
            }
        }),
    FieldDescriptor::new(
        "message_authentication_code",
        "Message Authentication Code",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U8).optional(),
    FieldDescriptor::new(
        "nas_key_set_identifier",
        "NAS Key Set Identifier",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("short_mac", "Short MAC", FieldType::U16).optional(),
    FieldDescriptor::new("plain_nas_message", "Plain NAS Message", FieldType::Object).optional(),
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

fn push<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: usize,
    value: FieldValue<'pkt>,
    range: core::ops::Range<usize>,
) {
    buf.push_field(&FIELD_DESCRIPTORS[fd], value, range);
}

/// Returns the minimum length of an EPS NAS message with this first octet,
/// or `None` if the protocol discriminator is neither EMM nor ESM.
fn min_len(first: u8) -> Option<usize> {
    match (first & 0x0f, first >> 4) {
        (PD_ESM, _) => Some(ESM_HEADER_SIZE),
        (PD_EMM, SHT_PLAIN) => Some(EMM_HEADER_SIZE),
        (PD_EMM, SHT_INTEGRITY_PROTECTED..=SHT_PARTIALLY_CIPHERED | SHT_EMM_TRANSPORT) => {
            Some(SECURITY_HEADER_SIZE)
        }
        (PD_EMM, SHT_SERVICE_REQUEST..) => Some(SERVICE_REQUEST_SIZE),
        // Reserved security header types: octet 1 only.
        (PD_EMM, _) => Some(1),
        _ => None,
    }
}

/// Push parsed EPS NAS message fields into the given [`DissectBuffer`].
///
/// This is the entry point for NAS messages embedded in other protocols
/// (e.g. the S1AP NAS-PDU IE). Returns `true` if fields were pushed, or
/// `false` (with nothing pushed) if the data is too short for its header
/// or the protocol discriminator is neither EMM nor ESM.
///
/// 3GPP TS 24.301, Section 9.1.
pub fn push_nas_pdu<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    match data.first().and_then(|&b| min_len(b)) {
        Some(min) if data.len() >= min => {
            push_message(buf, data, offset);
            true
        }
        _ => false,
    }
}

/// Push a NAS message whose length was checked against [`min_len`].
fn push_message<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    if data[0] & 0x0f == PD_ESM {
        push_esm(buf, data, offset);
    } else {
        push_emm(buf, data, offset);
    }
}

/// Returns `true` if `data` holds at least a plain ESM message header.
pub(crate) fn is_esm_message(data: &[u8]) -> bool {
    data.len() >= ESM_HEADER_SIZE && data[0] & 0x0f == PD_ESM
}

/// Push a plain ESM message (checked by [`is_esm_message`]).
///
/// 3GPP TS 24.301, Section 8.3 and Figure 9.1.1: EPS bearer identity in
/// bits 5 to 8 of octet 1 (Section 9.3.2), procedure transaction identity
/// in octet 2 (Section 9.4), message type in octet 3.
pub(crate) fn push_esm<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let o1 = offset..offset + 1;
    push(
        buf,
        FD_PROTOCOL_DISCRIMINATOR,
        FieldValue::U8(PD_ESM),
        o1.clone(),
    );
    push(
        buf,
        FD_EPS_BEARER_IDENTITY,
        FieldValue::U8(data[0] >> 4),
        o1,
    );
    push(buf, FD_PTI, FieldValue::U8(data[1]), offset + 1..offset + 2);
    push(
        buf,
        FD_MESSAGE_TYPE,
        FieldValue::U8(data[2]),
        offset + 2..offset + 3,
    );
    let body = &data[ESM_HEADER_SIZE..];
    let body_offset = offset + ESM_HEADER_SIZE;
    match messages::esm_message_ies(data[2]) {
        // An ESM message never carries an ESM message container.
        Some(ies) => ie::push_message_ies(buf, body, body_offset, ies, false),
        None => push_undecoded(buf, body, body_offset),
    }
}

/// Push an EMM message whose length was checked against [`min_len`].
///
/// 3GPP TS 24.301, Sections 9.1 and 9.3.1.
fn push_emm<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let sht = data[0] >> 4;
    push_emm_header(buf, sht, offset);
    match sht {
        SHT_PLAIN => push_emm_plain_body(buf, data, offset, true),
        SHT_INTEGRITY_PROTECTED..=SHT_PARTIALLY_CIPHERED | SHT_EMM_TRANSPORT => {
            push_security_protected(buf, data, offset, sht);
        }
        SHT_SERVICE_REQUEST.. => push_service_request(buf, data, offset),
        _ => {
            // Table 9.3.1: "All other values are reserved." The layout of
            // the rest of the message is not defined.
            let rest = &data[1..];
            if !rest.is_empty() {
                push(
                    buf,
                    FD_RAW_NAS_MESSAGE,
                    FieldValue::Bytes(rest),
                    offset + 1..offset + data.len(),
                );
            }
        }
    }
}

/// Push octet 1 of an EMM message: security header type and protocol
/// discriminator (TS 24.301, Section 9.1).
fn push_emm_header(buf: &mut DissectBuffer<'_>, sht: u8, offset: usize) {
    let o1 = offset..offset + 1;
    push(
        buf,
        FD_SECURITY_HEADER_TYPE,
        FieldValue::U8(sht),
        o1.clone(),
    );
    push(buf, FD_PROTOCOL_DISCRIMINATOR, FieldValue::U8(PD_EMM), o1);
}

/// Push the message type and IEs of a plain EMM message (header already
/// pushed).
///
/// `allow_esm` is `false` for a partially ciphered message, whose ESM
/// message container value is ciphered (TS 24.301, Section 4.4.5).
fn push_emm_plain_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    allow_esm: bool,
) {
    let message_type = data[1];
    push(
        buf,
        FD_MESSAGE_TYPE,
        FieldValue::U8(message_type),
        offset + 1..offset + 2,
    );
    let body = &data[EMM_HEADER_SIZE..];
    let body_offset = offset + EMM_HEADER_SIZE;
    match messages::emm_message_ies(message_type, body) {
        Some(ies) => ie::push_message_ies(buf, body, body_offset, ies, allow_esm),
        None => push_undecoded(buf, body, body_offset),
    }
}

/// Push the body of a message type without an IE table.
fn push_undecoded<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], offset: usize) {
    if !body.is_empty() {
        buf.push_field(
            &ie::FD_UNDECODED_OCTETS,
            FieldValue::Bytes(body),
            offset..offset + body.len(),
        );
    }
}

/// Push the MAC, sequence number and NAS message part (octet 7 onwards) of
/// a security protected NAS message or an EMM TRANSPORT message.
///
/// 3GPP TS 24.301, Section 4.4.5 — "If a NAS message needs to be sent
/// ciphered, the sender shall cipher the NAS message portion of the
/// security protected NAS message (see figure 9.1.2), i.e. octet 7 and all
/// subsequent octets" and "If the "null ciphering algorithm" EEA0 has been
/// selected as a ciphering algorithm, the NAS messages with the security
/// header indicating ciphering are regarded as ciphered." The EMM
/// TRANSPORT data container is ciphered the same way, and a partially
/// ciphered CONTROL PLANE SERVICE REQUEST keeps its header in clear text
/// but ciphers "the value part of the ESM message container IE or the value
/// part of the NAS message container".
fn push_security_protected<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    sht: u8,
) {
    let mac = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    push(buf, FD_MAC, FieldValue::U32(mac), offset + 1..offset + 5);
    push(
        buf,
        FD_SEQUENCE_NUMBER,
        FieldValue::U8(data[5]),
        offset + 5..offset + 6,
    );
    let payload = &data[SECURITY_HEADER_SIZE..];
    if payload.is_empty() {
        return;
    }
    let payload_offset = offset + SECURITY_HEADER_SIZE;
    let payload_range = payload_offset..offset + data.len();
    let allow_esm = match sht {
        SHT_INTEGRITY_PROTECTED | SHT_INTEGRITY_PROTECTED_NEW_CONTEXT => true,
        // Table 9.3.1 NOTE 4 — "This codepoint may be used only for a
        // CONTROL PLANE SERVICE REQUEST message."
        SHT_PARTIALLY_CIPHERED
            if payload.get(..2) == Some(&[PD_EMM, MT_CONTROL_PLANE_SERVICE_REQUEST]) =>
        {
            false
        }
        SHT_PARTIALLY_CIPHERED => {
            push(
                buf,
                FD_RAW_NAS_MESSAGE,
                FieldValue::Bytes(payload),
                payload_range,
            );
            return;
        }
        _ => {
            // Types 2 ("Integrity protected and ciphered") and 4 ("Integrity
            // protected and ciphered with new EPS security context"), and the
            // EMM TRANSPORT data container.
            push(
                buf,
                FD_CIPHERED_NAS_MESSAGE,
                FieldValue::Bytes(payload),
                payload_range,
            );
            return;
        }
    };
    if !is_plain_nas_message(payload) {
        push(
            buf,
            FD_RAW_NAS_MESSAGE,
            FieldValue::Bytes(payload),
            payload_range,
        );
        return;
    }
    let obj = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_PLAIN_NAS_MESSAGE],
        FieldValue::Object(0..0),
        payload_range,
    );
    if payload[0] & 0x0f == PD_ESM {
        push_esm(buf, payload, payload_offset);
    } else {
        push_emm_header(buf, SHT_PLAIN, payload_offset);
        push_emm_plain_body(buf, payload, payload_offset, allow_esm);
    }
    buf.end_container(obj);
}

/// Returns `true` if `data` is a plain NAS message: an ESM message or an
/// EMM message with security header type 0.
///
/// 3GPP TS 24.301, Section 9.1 — a security protected NAS message ends with
/// a "plain NAS message, as defined in item 1". A security protected message
/// nested in another is never decoded, which also bounds the nesting depth.
fn is_plain_nas_message(data: &[u8]) -> bool {
    is_esm_message(data) || (data.len() >= EMM_HEADER_SIZE && data[0] == PD_EMM)
}

/// Push the SERVICE REQUEST message after octet 1.
///
/// 3GPP TS 24.301, Section 8.2.25 and Section 9.9.3.19: octet 2 is the KSI
/// (bits 6 to 8) and the sequence number (bits 1 to 5); octets 3 and 4 are
/// the short MAC (Section 9.9.3.28).
fn push_service_request<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    let o2 = offset + 1..offset + 2;
    push(buf, FD_KSI, FieldValue::U8(data[1] >> 5), o2.clone());
    push(buf, FD_SEQUENCE_NUMBER, FieldValue::U8(data[1] & 0x1f), o2);
    push(
        buf,
        FD_SHORT_MAC,
        FieldValue::U16(u16::from_be_bytes([data[2], data[3]])),
        offset + 2..offset + 4,
    );
    // The message is exactly 4 octets; anything after the short MAC has no
    // defined meaning.
    push_undecoded(
        buf,
        &data[SERVICE_REQUEST_SIZE..],
        offset + SERVICE_REQUEST_SIZE,
    );
}

/// EPS NAS (Non-Access Stratum) dissector.
///
/// Parses EPS Mobility Management and EPS Session Management messages.
/// Typically invoked through the S1AP NAS-PDU IE, but can also be used
/// standalone via the registry factory.
///
/// 3GPP TS 24.301: <https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/>
pub struct NasEpsDissector;

/// Specification references for the EPS NAS dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "3GPP TS 24.301",
        "Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS); Stage 3",
        "https://www.3gpp.org/ftp/Specs/archive/24_series/24.301/",
    ),
    SpecReference::new(
        "3GPP TS 24.007",
        "Mobile radio interface signalling layer 3; General aspects",
        "https://www.3gpp.org/ftp/Specs/archive/24_series/24.007/",
    ),
    SpecReference::new(
        "3GPP TS 24.008",
        "Mobile radio interface Layer 3 specification; Core network protocols; Stage 3",
        "https://www.3gpp.org/ftp/Specs/archive/24_series/24.008/",
    ),
];

impl Dissector for NasEpsDissector {
    fn name(&self) -> &'static str {
        "EPS NAS"
    }

    fn short_name(&self) -> &'static str {
        "NAS-EPS"
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
        let Some(&first) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };
        let Some(min) = min_len(first) else {
            return Err(PacketError::InvalidFieldValue {
                field: "protocol_discriminator",
                value: u32::from(first & 0x0f),
            });
        };
        if data.len() < min {
            return Err(PacketError::Truncated {
                expected: min,
                actual: data.len(),
            });
        }
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        push_message(buf, data, offset);
        buf.end_layer();
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests;
