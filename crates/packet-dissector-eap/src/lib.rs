//! EAP (Extensible Authentication Protocol) and EAPOL (IEEE 802.1X) dissectors.
//!
//! [`EapDissector`] decodes one EAP packet ([RFC 3748, Section 4]) into an
//! `EAP` layer, and [`parse_eap`] pushes the same fields into whatever layer
//! or container is open, so that carriers embedding EAP in an attribute
//! (RADIUS EAP-Message, Diameter EAP-Payload, IKEv2 EAP payload) can reuse
//! it. [`EapolDissector`] decodes the EAPOL header (IEEE Std 802.1X-2020,
//! clause 11.3) and hands an EAPOL-EAP body to [`EapDissector`].
//!
//! Type-specific decoding:
//!
//! - Identity (1), Notification (2), Legacy Nak (3) and the Expanded Type
//!   header (254) — [RFC 3748, Section 5];
//! - EAP-TLS (13), EAP-TTLS (21) and PEAP (25) flags, TLS Message Length and
//!   TLS data — [RFC 5216, Section 3.1]; [RFC 5281, Section 9.1];
//! - EAP-SIM (18), EAP-AKA (23) and EAP-AKA' (50) subtype and attributes —
//!   [RFC 4186, Section 8.1]; [RFC 4187, Section 8.1]; [RFC 9048, Section 3].
//!
//! Other method types keep their Type-Data as raw bytes.
//!
//! [RFC 3748, Section 4]: https://www.rfc-editor.org/rfc/rfc3748#section-4
//! [RFC 3748, Section 5]: https://www.rfc-editor.org/rfc/rfc3748#section-5
//! [RFC 5216, Section 3.1]: https://www.rfc-editor.org/rfc/rfc5216#section-3.1
//! [RFC 5281, Section 9.1]: https://www.rfc-editor.org/rfc/rfc5281#section-9.1
//! [RFC 4186, Section 8.1]: https://www.rfc-editor.org/rfc/rfc4186#section-8.1
//! [RFC 4187, Section 8.1]: https://www.rfc-editor.org/rfc/rfc4187#section-8.1
//! [RFC 9048, Section 3]: https://www.rfc-editor.org/rfc/rfc9048#section-3
//!
//! ## References
//! - RFC 3748 (EAP): <https://www.rfc-editor.org/rfc/rfc3748>
//! - RFC 5247 (EAP Key Management Framework, updates RFC 3748): <https://www.rfc-editor.org/rfc/rfc5247>
//! - RFC 7057 (Update to the EAP Applicability Statement, updates RFC 3748): <https://www.rfc-editor.org/rfc/rfc7057>
//! - RFC 6696 (EAP Re-authentication Protocol, Codes 5 and 6): <https://www.rfc-editor.org/rfc/rfc6696>
//! - RFC 5216 (EAP-TLS): <https://www.rfc-editor.org/rfc/rfc5216>
//! - RFC 9190 (EAP-TLS 1.3): <https://www.rfc-editor.org/rfc/rfc9190>
//! - RFC 5281 (EAP-TTLSv0): <https://www.rfc-editor.org/rfc/rfc5281>
//! - RFC 4186 (EAP-SIM): <https://www.rfc-editor.org/rfc/rfc4186>
//! - RFC 4187 (EAP-AKA): <https://www.rfc-editor.org/rfc/rfc4187>
//! - RFC 9048 (EAP-AKA', updates RFC 4187): <https://www.rfc-editor.org/rfc/rfc9048>
//! - IANA EAP Registry: <https://www.iana.org/assignments/eap-numbers>
//! - IANA EAP-SIM/EAP-AKA Registry: <https://www.iana.org/assignments/eapsimaka-numbers>
//! - IEEE Std 802.1X-2020 (EAPOL): <https://standards.ieee.org/ieee/802.1X/7345/>

#![deny(missing_docs)]

mod eapol;

pub use eapol::EapolDissector;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Size of the EAP header: Code, Identifier and Length.
/// RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>
pub const HEADER_SIZE: usize = 4;

// EAP Codes — RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>
const CODE_REQUEST: u8 = 1;
const CODE_RESPONSE: u8 = 2;

// EAP method Types — IANA "Method Types" —
// <https://www.iana.org/assignments/eap-numbers>
const TYPE_IDENTITY: u8 = 1;
const TYPE_NOTIFICATION: u8 = 2;
const TYPE_LEGACY_NAK: u8 = 3;
const TYPE_TLS: u8 = 13;
const TYPE_SIM: u8 = 18;
const TYPE_TTLS: u8 = 21;
const TYPE_AKA: u8 = 23;
const TYPE_PEAP: u8 = 25;
const TYPE_AKA_PRIME: u8 = 50;
const TYPE_EXPANDED: u8 = 254;

/// Expanded Type header after the Type octet: Vendor-Id (3) + Vendor-Type (4).
/// RFC 3748, Section 5.7 — <https://www.rfc-editor.org/rfc/rfc3748#section-5.7>
const EXPANDED_HEADER_SIZE: usize = 7;

// TLS-based method flags — RFC 5216, Section 3.1 —
// <https://www.rfc-editor.org/rfc/rfc5216#section-3.1>
const TLS_FLAG_LENGTH_INCLUDED: u8 = 0x80;
/// Version bits of the EAP-TTLS and PEAP flags octet.
/// RFC 5281, Section 9.1 — <https://www.rfc-editor.org/rfc/rfc5281#section-9.1>
const TLS_VERSION_MASK: u8 = 0x07;
/// Size of the TLS Message Length field.
const TLS_MESSAGE_LENGTH_SIZE: usize = 4;

/// EAP-SIM / EAP-AKA header after the Type octet: Subtype (1) + Reserved (2).
/// RFC 4187, Section 8.1 — <https://www.rfc-editor.org/rfc/rfc4187#section-8.1>
const SIM_AKA_HEADER_SIZE: usize = 3;
/// EAP-SIM / EAP-AKA attribute Length unit.
/// RFC 4187, Section 8.1 — "Indicates the length of this attribute in
/// multiples of 4 bytes." — <https://www.rfc-editor.org/rfc/rfc4187#section-8.1>
const SIM_AKA_ATTR_UNIT: usize = 4;

/// Returns the name of an EAP Code.
///
/// RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>;
/// RFC 6696, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc6696#section-5.3>.
pub fn code_name(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("Request"),
        2 => Some("Response"),
        3 => Some("Success"),
        4 => Some("Failure"),
        5 => Some("Initiate"),
        6 => Some("Finish"),
        _ => None,
    }
}

/// Returns the name of an EAP method Type.
///
/// IANA "Method Types" — <https://www.iana.org/assignments/eap-numbers>;
/// RFC 3748, Section 5 — <https://www.rfc-editor.org/rfc/rfc3748#section-5>.
pub fn type_name(eap_type: u8) -> Option<&'static str> {
    match eap_type {
        1 => Some("Identity"),
        2 => Some("Notification"),
        3 => Some("Legacy Nak"),
        4 => Some("MD5-Challenge"),
        5 => Some("One-Time Password (OTP)"),
        6 => Some("Generic Token Card (GTC)"),
        13 => Some("EAP-TLS"),
        17 => Some("EAP-Cisco Wireless"),
        18 => Some("EAP-SIM"),
        21 => Some("EAP-TTLS"),
        23 => Some("EAP-AKA"),
        25 => Some("PEAP"),
        26 => Some("MS-EAP-Authentication"),
        29 => Some("EAP-MSCHAP-V2"),
        43 => Some("EAP-FAST"),
        46 => Some("EAP-PAX"),
        47 => Some("EAP-PSK"),
        48 => Some("EAP-SAKE"),
        49 => Some("EAP-IKEv2"),
        50 => Some("EAP-AKA'"),
        51 => Some("EAP-GPSK"),
        52 => Some("EAP-pwd"),
        53 => Some("EAP-EKE Version 1"),
        54 => Some("PT-EAP"),
        55 => Some("TEAP"),
        56 => Some("EAP-NOOB"),
        57 => Some("EAP-EDHOC"),
        254 => Some("Expanded Type"),
        255 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of an EAP-SIM / EAP-AKA Subtype.
///
/// IANA "EAP-AKA and EAP-SIM Subtypes" —
/// <https://www.iana.org/assignments/eapsimaka-numbers>; RFC 4187,
/// Section 11 — <https://www.rfc-editor.org/rfc/rfc4187#section-11>.
pub fn sim_aka_subtype_name(subtype: u8) -> Option<&'static str> {
    match subtype {
        1 => Some("AKA-Challenge"),
        2 => Some("AKA-Authentication-Reject"),
        4 => Some("AKA-Synchronization-Failure"),
        5 => Some("AKA-Identity"),
        10 => Some("SIM-Start"),
        11 => Some("SIM-Challenge"),
        12 => Some("Notification"),
        13 => Some("Re-authentication"),
        14 => Some("Client-Error"),
        _ => None,
    }
}

/// Returns the name of an EAP-SIM / EAP-AKA attribute type.
///
/// IANA "EAP-AKA and EAP-SIM Attributes" —
/// <https://www.iana.org/assignments/eapsimaka-numbers>; RFC 4187,
/// Section 11 — <https://www.rfc-editor.org/rfc/rfc4187#section-11>; RFC 9048,
/// Section 3 — <https://www.rfc-editor.org/rfc/rfc9048#section-3>.
pub fn sim_aka_attribute_name(attr_type: u8) -> Option<&'static str> {
    match attr_type {
        1 => Some("AT_RAND"),
        2 => Some("AT_AUTN"),
        3 => Some("AT_RES"),
        4 => Some("AT_AUTS"),
        6 => Some("AT_PADDING"),
        7 => Some("AT_NONCE_MT"),
        10 => Some("AT_PERMANENT_ID_REQ"),
        11 => Some("AT_MAC"),
        12 => Some("AT_NOTIFICATION"),
        13 => Some("AT_ANY_ID_REQ"),
        14 => Some("AT_IDENTITY"),
        15 => Some("AT_VERSION_LIST"),
        16 => Some("AT_SELECTED_VERSION"),
        17 => Some("AT_FULLAUTH_ID_REQ"),
        19 => Some("AT_COUNTER"),
        20 => Some("AT_COUNTER_TOO_SMALL"),
        21 => Some("AT_NONCE_S"),
        22 => Some("AT_CLIENT_ERROR_CODE"),
        23 => Some("AT_KDF_INPUT"),
        24 => Some("AT_KDF"),
        129 => Some("AT_IV"),
        130 => Some("AT_ENCR_DATA"),
        132 => Some("AT_NEXT_PSEUDONYM"),
        133 => Some("AT_NEXT_REAUTH_ID"),
        134 => Some("AT_CHECKCODE"),
        135 => Some("AT_RESULT_IND"),
        136 => Some("AT_BIDDING"),
        137 => Some("AT_IPMS_IND"),
        138 => Some("AT_IPMS_RES"),
        139 => Some("AT_TRUST_IND"),
        140 => Some("AT_SHORT_NAME_FOR_NETWORK"),
        141 => Some("AT_FULL_NAME_FOR_NETWORK"),
        142 => Some("AT_RQSI_IND"),
        143 => Some("AT_RQSI_RES"),
        144 => Some("AT_TWAN_CONN_MODE"),
        145 => Some("AT_VIRTUAL_NETWORK_ID"),
        146 => Some("AT_VIRTUAL_NETWORK_REQ"),
        147 => Some("AT_CONNECTIVITY_TYPE"),
        148 => Some("AT_HANDOVER_INDICATION"),
        149 => Some("AT_HANDOVER_SESSION_ID"),
        150 => Some("AT_MN_SERIAL_ID"),
        151 => Some("AT_DEVICE_IDENTITY"),
        152 => Some("AT_PUB_ECDHE"),
        153 => Some("AT_KDF_FS"),
        _ => None,
    }
}

/// Returns the names of the L, M and S bits of a TLS-based method flags
/// octet.
///
/// RFC 5216, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc5216#section-3.1>
fn tls_flags_name(flags: u8) -> &'static str {
    match flags >> 5 {
        0b000 => "None",
        0b001 => "Start",
        0b010 => "More fragments",
        0b011 => "More fragments, Start",
        0b100 => "Length included",
        0b101 => "Length included, Start",
        0b110 => "Length included, More fragments",
        _ => "Length included, More fragments, Start",
    }
}

const FD_CODE: usize = 0;
const FD_IDENTIFIER: usize = 1;
const FD_LENGTH: usize = 2;
const FD_TYPE: usize = 3;
const FD_IDENTITY: usize = 4;
const FD_NOTIFICATION: usize = 5;
const FD_DESIRED_TYPES: usize = 6;
const FD_VENDOR_ID: usize = 7;
const FD_VENDOR_TYPE: usize = 8;
const FD_FLAGS: usize = 9;
const FD_TLS_VERSION: usize = 10;
const FD_TLS_MESSAGE_LENGTH: usize = 11;
const FD_TLS_DATA: usize = 12;
const FD_SUBTYPE: usize = 13;
const FD_RESERVED: usize = 14;
const FD_ATTRIBUTES: usize = 15;
const FD_TYPE_DATA: usize = 16;

/// One desired authentication Type of a Legacy Nak.
/// RFC 3748, Section 5.3.1 — <https://www.rfc-editor.org/rfc/rfc3748#section-5.3.1>
static DESIRED_TYPE_FIELDS: &[FieldDescriptor] =
    &[
        FieldDescriptor::new("type", "Desired Type", FieldType::U8).with_display_fn(
            |v, _| match v {
                FieldValue::U8(t) => type_name(*t),
                _ => None,
            },
        ),
    ];

const FD_ATTR_TYPE: usize = 0;
const FD_ATTR_LENGTH: usize = 1;
const FD_ATTR_VALUE: usize = 2;

/// Fields of one EAP-SIM / EAP-AKA attribute.
/// RFC 4187, Section 8.1 — <https://www.rfc-editor.org/rfc/rfc4187#section-8.1>
static ATTRIBUTE_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Attribute Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => sim_aka_attribute_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// One EAP-SIM / EAP-AKA attribute; its label resolves to the attribute name.
static FD_ATTRIBUTE: FieldDescriptor =
    FieldDescriptor::new("attribute", "Attribute", FieldType::Object)
        .with_children(ATTRIBUTE_CHILD_FIELDS)
        .with_display_fn(|v, children| match v {
            FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
                ("type", FieldValue::U8(t)) => sim_aka_attribute_name(*t),
                _ => None,
            }),
            _ => None,
        });

/// Field descriptors of an EAP packet.
///
/// Used both for the `EAP` layer and by carriers that embed an EAP packet
/// in a container field through [`parse_eap`].
///
/// RFC 3748, Sections 4 and 5 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>
pub static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "Code", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(c) => code_name(*c),
        _ => None,
    }),
    FieldDescriptor::new("identifier", "Identifier", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("type", "Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("identity", "Identity", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("notification", "Notification", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("desired_types", "Desired Types", FieldType::Array)
        .optional()
        .with_children(DESIRED_TYPE_FIELDS),
    FieldDescriptor::new("vendor_id", "Vendor-Id", FieldType::U32).optional(),
    FieldDescriptor::new("vendor_type", "Vendor-Type", FieldType::U32).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(f) => Some(tls_flags_name(*f)),
            _ => None,
        }),
    FieldDescriptor::new("tls_version", "Version", FieldType::U8).optional(),
    FieldDescriptor::new("tls_message_length", "TLS Message Length", FieldType::U32).optional(),
    FieldDescriptor::new("tls_data", "TLS Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(s) => sim_aka_subtype_name(*s),
            _ => None,
        }),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U16).optional(),
    FieldDescriptor::new("attributes", "Attributes", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_ATTRIBUTE)),
    FieldDescriptor::new("type_data", "Type-Data", FieldType::Bytes).optional(),
];

/// Specification references for the EAP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 3748",
        "Extensible Authentication Protocol (EAP)",
        "https://www.rfc-editor.org/rfc/rfc3748",
    ),
    SpecReference::new(
        "RFC 5247",
        "Extensible Authentication Protocol (EAP) Key Management Framework",
        "https://www.rfc-editor.org/rfc/rfc5247",
    ),
    SpecReference::new(
        "RFC 7057",
        "Update to the Extensible Authentication Protocol (EAP) Applicability Statement for Application Bridging for Federated Access Beyond Web (ABFAB)",
        "https://www.rfc-editor.org/rfc/rfc7057",
    ),
    SpecReference::new(
        "RFC 6696",
        "EAP Extensions for the EAP Re-authentication Protocol (ERP)",
        "https://www.rfc-editor.org/rfc/rfc6696",
    ),
    SpecReference::new(
        "RFC 5216",
        "The EAP-TLS Authentication Protocol",
        "https://www.rfc-editor.org/rfc/rfc5216",
    ),
    SpecReference::new(
        "RFC 9190",
        "EAP-TLS 1.3: Using the Extensible Authentication Protocol with TLS 1.3",
        "https://www.rfc-editor.org/rfc/rfc9190",
    ),
    SpecReference::new(
        "RFC 5281",
        "Extensible Authentication Protocol Tunneled Transport Layer Security Authenticated Protocol Version 0 (EAP-TTLSv0)",
        "https://www.rfc-editor.org/rfc/rfc5281",
    ),
    SpecReference::new(
        "RFC 4186",
        "Extensible Authentication Protocol Method for Global System for Mobile Communications (GSM) Subscriber Identity Modules (EAP-SIM)",
        "https://www.rfc-editor.org/rfc/rfc4186",
    ),
    SpecReference::new(
        "RFC 4187",
        "Extensible Authentication Protocol Method for 3rd Generation Authentication and Key Agreement (EAP-AKA)",
        "https://www.rfc-editor.org/rfc/rfc4187",
    ),
    SpecReference::new(
        "RFC 9048",
        "Improved Extensible Authentication Protocol Method for 3GPP Mobile Network Authentication and Key Agreement (EAP-AKA')",
        "https://www.rfc-editor.org/rfc/rfc9048",
    ),
];

/// Decode one EAP packet and push its fields into the open layer or
/// container, using [`FIELD_DESCRIPTORS`].
///
/// `data` starts at the Code field and may extend past the packet (data link
/// padding); `offset` is the absolute position of `data[0]` in the packet.
/// Returns the EAP Length, i.e. the number of octets of `data` that belong
/// to the packet.
///
/// On error nothing is pushed, so a carrier can fall back to showing the
/// raw value.
///
/// # Errors
///
/// - [`PacketError::Truncated`] when `data` is shorter than the header or
///   than the Length field — RFC 3748, Section 4: "A message with the Length
///   field set to a value larger than the number of received octets MUST be
///   silently discarded."
/// - [`PacketError::InvalidHeader`] when Length is smaller than the header,
///   or when method Type-Data is malformed.
///
/// RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>
pub fn parse_eap<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<usize, PacketError> {
    let length = eap_length(data)?;
    push_eap_with_rollback(&data[..length], offset, buf)?;
    Ok(length)
}

/// Push a validated EAP packet (`data` is exactly Length octets), removing
/// every field pushed so far if the Type-Data turns out to be malformed.
fn push_eap_with_rollback<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let mark = buf.field_count() as usize;
    let result = push_eap(data, offset, buf);
    if result.is_err() {
        buf.truncate_fields(mark);
    }
    result
}

/// Descriptor of an optional `eap` Object holding an EAP packet embedded in
/// a carrier attribute (RADIUS EAP-Message, Diameter EAP-Payload, IKEv2 EAP
/// payload). Its children are [`FIELD_DESCRIPTORS`].
pub const EAP_OBJECT_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("eap", "EAP", FieldType::Object)
        .optional()
        .with_children(FIELD_DESCRIPTORS);

/// Push `data` as an Object (`descriptor`, normally a copy of
/// [`EAP_OBJECT_DESCRIPTOR`]) holding the decoded EAP packet.
///
/// A carrier value holds exactly one EAP packet and no padding, so `data`
/// must be exactly as long as its EAP Length. Returns `false` and pushes
/// nothing otherwise, or when the packet is malformed, so the carrier keeps
/// only its raw value.
pub fn push_eap_object<'pkt>(
    descriptor: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> bool {
    let idx = buf.begin_container(
        descriptor,
        FieldValue::Object(0..0),
        offset..offset + data.len(),
    );
    match parse_eap(data, offset, buf) {
        Ok(length) if length == data.len() => {
            buf.end_container(idx);
            true
        }
        _ => {
            buf.truncate_fields(idx as usize);
            false
        }
    }
}

/// Validate the EAP header and return the Length field.
///
/// RFC 3748, Section 4 — "Octets outside the range of the Length field
/// should be treated as Data Link Layer padding and MUST be ignored upon
/// reception.  A message with the Length field set to a value larger than
/// the number of received octets MUST be silently discarded."
/// <https://www.rfc-editor.org/rfc/rfc3748#section-4>
fn eap_length(data: &[u8]) -> Result<usize, PacketError> {
    if data.len() < HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }
    let length = usize::from(read_be_u16(data, 2)?);
    if length < HEADER_SIZE {
        return Err(PacketError::InvalidHeader("EAP Length smaller than header"));
    }
    if length > data.len() {
        return Err(PacketError::Truncated {
            expected: length,
            actual: data.len(),
        });
    }
    Ok(length)
}

/// Push the fields of an EAP packet whose header [`eap_length`] has
/// validated; `data` is exactly Length octets.
fn push_eap<'pkt>(
    data: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let length = data.len();
    let code = data[0];
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_CODE],
        FieldValue::U8(code),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_IDENTIFIER],
        FieldValue::U8(data[1]),
        offset + 1..offset + 2,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LENGTH],
        FieldValue::U16(length as u16),
        offset + 2..offset + 4,
    );

    let body = &data[HEADER_SIZE..];
    let body_offset = offset + HEADER_SIZE;
    if body.is_empty() {
        return Ok(());
    }
    if code == CODE_REQUEST || code == CODE_RESPONSE {
        // RFC 3748, Section 4.1 — Requests and Responses carry a Type field
        // followed by Type-Data.
        // <https://www.rfc-editor.org/rfc/rfc3748#section-4.1>
        let eap_type = body[0];
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE],
            FieldValue::U8(eap_type),
            body_offset..body_offset + 1,
        );
        push_type_data(eap_type, &body[1..], body_offset + 1, buf)?;
    } else {
        // Success and Failure carry no Data (RFC 3748, Section 4.2 —
        // <https://www.rfc-editor.org/rfc/rfc3748#section-4.2>); other Codes
        // (e.g. RFC 6696 Initiate/Finish —
        // <https://www.rfc-editor.org/rfc/rfc6696#section-5.3>) are kept raw.
        push_raw(body, body_offset, buf);
    }
    Ok(())
}

/// Push `data` as raw Type-Data, if any.
fn push_raw<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    if !data.is_empty() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TYPE_DATA],
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
    }
}

/// Decode the Type-Data of a Request or Response.
///
/// RFC 3748, Section 5 — <https://www.rfc-editor.org/rfc/rfc3748#section-5>
fn push_type_data<'pkt>(
    eap_type: u8,
    td: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    match eap_type {
        // RFC 3748, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc3748#section-5.1>
        TYPE_IDENTITY => buf.push_field(
            &FIELD_DESCRIPTORS[FD_IDENTITY],
            FieldValue::Bytes(td),
            offset..offset + td.len(),
        ),
        // RFC 3748, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc3748#section-5.2>
        TYPE_NOTIFICATION => buf.push_field(
            &FIELD_DESCRIPTORS[FD_NOTIFICATION],
            FieldValue::Bytes(td),
            offset..offset + td.len(),
        ),
        // RFC 3748, Section 5.3.1 — "one or more authentication Types"
        // <https://www.rfc-editor.org/rfc/rfc3748#section-5.3.1>
        TYPE_LEGACY_NAK if !td.is_empty() => {
            let idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_DESIRED_TYPES],
                FieldValue::Array(0..0),
                offset..offset + td.len(),
            );
            for (i, t) in td.iter().enumerate() {
                buf.push_field(
                    &DESIRED_TYPE_FIELDS[0],
                    FieldValue::U8(*t),
                    offset + i..offset + i + 1,
                );
            }
            buf.end_container(idx);
        }
        TYPE_EXPANDED => push_expanded(td, offset, buf)?,
        TYPE_TLS | TYPE_TTLS | TYPE_PEAP => push_tls(eap_type, td, offset, buf)?,
        TYPE_SIM | TYPE_AKA | TYPE_AKA_PRIME => push_sim_aka(td, offset, buf)?,
        _ => push_raw(td, offset, buf),
    }
    Ok(())
}

/// Expanded Type: Vendor-Id, Vendor-Type and Vendor data (kept raw; an
/// Expanded Nak lists its desired types there).
///
/// RFC 3748, Sections 5.3.2 and 5.7 —
/// <https://www.rfc-editor.org/rfc/rfc3748#section-5.7>
fn push_expanded<'pkt>(
    td: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if td.len() < EXPANDED_HEADER_SIZE {
        return Err(PacketError::InvalidHeader("EAP Expanded Type truncated"));
    }
    // "The Vendor-Id is 3 octets" — RFC 3748, Section 5.7 —
    // <https://www.rfc-editor.org/rfc/rfc3748#section-5.7>
    let vendor_id = u32::from_be_bytes([0, td[0], td[1], td[2]]);
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VENDOR_ID],
        FieldValue::U32(vendor_id),
        offset..offset + 3,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VENDOR_TYPE],
        FieldValue::U32(read_be_u32(td, 3)?),
        offset + 3..offset + EXPANDED_HEADER_SIZE,
    );
    push_raw(
        &td[EXPANDED_HEADER_SIZE..],
        offset + EXPANDED_HEADER_SIZE,
        buf,
    );
    Ok(())
}

/// EAP-TLS, EAP-TTLS and PEAP: Flags, optional TLS Message Length and TLS
/// data. EAP-TTLS and PEAP carry a version in the low three flag bits.
///
/// RFC 5216, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc5216#section-3.1>;
/// RFC 5281, Section 9.1 — <https://www.rfc-editor.org/rfc/rfc5281#section-9.1>
fn push_tls<'pkt>(
    eap_type: u8,
    td: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    let Some(&flags) = td.first() else {
        return Ok(());
    };
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_FLAGS],
        FieldValue::U8(flags),
        offset..offset + 1,
    );
    if eap_type != TYPE_TLS {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TLS_VERSION],
            FieldValue::U8(flags & TLS_VERSION_MASK),
            offset..offset + 1,
        );
    }
    let mut pos = 1;
    // RFC 5216, Section 3.1 — "The TLS Message Length field is four octets,
    // and is present only if the L bit is set."
    // <https://www.rfc-editor.org/rfc/rfc5216#section-3.1>
    if flags & TLS_FLAG_LENGTH_INCLUDED != 0 {
        if td.len() < pos + TLS_MESSAGE_LENGTH_SIZE {
            return Err(PacketError::InvalidHeader(
                "EAP TLS Message Length truncated",
            ));
        }
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TLS_MESSAGE_LENGTH],
            FieldValue::U32(read_be_u32(td, pos)?),
            offset + pos..offset + pos + TLS_MESSAGE_LENGTH_SIZE,
        );
        pos += TLS_MESSAGE_LENGTH_SIZE;
    }
    if pos < td.len() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TLS_DATA],
            FieldValue::Bytes(&td[pos..]),
            offset + pos..offset + td.len(),
        );
    }
    Ok(())
}

/// EAP-SIM, EAP-AKA and EAP-AKA': Subtype, Reserved and attributes.
///
/// RFC 4186, Section 8.1 — <https://www.rfc-editor.org/rfc/rfc4186#section-8.1>;
/// RFC 4187, Section 8.1 — <https://www.rfc-editor.org/rfc/rfc4187#section-8.1>
fn push_sim_aka<'pkt>(
    td: &'pkt [u8],
    offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError> {
    if td.len() < SIM_AKA_HEADER_SIZE {
        push_raw(td, offset, buf);
        return Ok(());
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_SUBTYPE],
        FieldValue::U8(td[0]),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_RESERVED],
        FieldValue::U16(read_be_u16(td, 1)?),
        offset + 1..offset + SIM_AKA_HEADER_SIZE,
    );
    if td.len() == SIM_AKA_HEADER_SIZE {
        return Ok(());
    }
    let array_idx = buf.begin_container(
        &FIELD_DESCRIPTORS[FD_ATTRIBUTES],
        FieldValue::Array(0..0),
        offset + SIM_AKA_HEADER_SIZE..offset + td.len(),
    );
    let mut pos = SIM_AKA_HEADER_SIZE;
    while pos < td.len() {
        // RFC 4187, Section 8.1 — Length "Indicates the length of this
        // attribute in multiples of 4 bytes. ... The length includes the
        // Attribute Type and Length bytes."
        // <https://www.rfc-editor.org/rfc/rfc4187#section-8.1>
        let attr_len = td
            .get(pos + 1)
            .map_or(0, |l| usize::from(*l) * SIM_AKA_ATTR_UNIT);
        if attr_len == 0 || pos + attr_len > td.len() {
            return Err(PacketError::InvalidHeader(
                "EAP-SIM/AKA attribute length is invalid",
            ));
        }
        let start = offset + pos;
        let obj_idx = buf.begin_container(
            &FD_ATTRIBUTE,
            FieldValue::Object(0..0),
            start..start + attr_len,
        );
        buf.push_field(
            &ATTRIBUTE_CHILD_FIELDS[FD_ATTR_TYPE],
            FieldValue::U8(td[pos]),
            start..start + 1,
        );
        buf.push_field(
            &ATTRIBUTE_CHILD_FIELDS[FD_ATTR_LENGTH],
            FieldValue::U8(td[pos + 1]),
            start + 1..start + 2,
        );
        buf.push_field(
            &ATTRIBUTE_CHILD_FIELDS[FD_ATTR_VALUE],
            FieldValue::Bytes(&td[pos + 2..pos + attr_len]),
            start + 2..start + attr_len,
        );
        buf.end_container(obj_idx);
        pos += attr_len;
    }
    buf.end_container(array_idx);
    Ok(())
}

/// EAP dissector.
///
/// Produces an `EAP` layer covering the Length octets of the packet.
/// RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>
pub struct EapDissector;

impl Dissector for EapDissector {
    fn name(&self) -> &'static str {
        "Extensible Authentication Protocol"
    }

    fn short_name(&self) -> &'static str {
        "EAP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let length = eap_length(data)?;
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + length,
        );
        if let Err(e) = push_eap_with_rollback(&data[..length], offset, buf) {
            buf.pop_layer();
            return Err(e);
        }
        buf.end_layer();
        Ok(DissectResult::new(length, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    // # RFC 3748 (EAP) Coverage
    //
    // | RFC Section | Description                               | Test                                   |
    // |-------------|-------------------------------------------|----------------------------------------|
    // | 4           | Header (Code, Identifier, Length)         | identity_request                       |
    // | 4           | Octets past Length are padding            | identity_response_with_padding         |
    // | 4           | Length larger than received octets        | length_exceeds_data                    |
    // | 4           | Length smaller than header                | length_below_header                    |
    // | 4           | Header truncated                          | truncated_header                       |
    // | 4           | Unknown Code keeps Data raw               | unknown_code_raw_data                  |
    // | 4.1         | Request without Type                      | request_without_type                   |
    // | 4.2         | Success / Failure (4 octets)              | success_and_failure                    |
    // | 5.1         | Identity                                  | identity_request                       |
    // | 5.2         | Notification                              | notification_request                   |
    // | 5.3.1       | Legacy Nak desired types                  | legacy_nak                             |
    // | 5.3.2, 5.7  | Expanded Nak / Expanded Type header       | expanded_nak                           |
    // | 5.7         | Expanded Type truncated                   | expanded_type_truncated                |
    // | 5           | Other method keeps Type-Data raw          | md5_challenge_raw                      |
    // | —           | parse_eap pushes nothing on error         | parse_eap_error_pushes_nothing         |
    // | —           | EAP object inside a carrier               | push_eap_object_in_carrier             |
    // | —           | Name tables                               | name_tables                            |
    //
    // # RFC 5216 (EAP-TLS) / RFC 5281 (EAP-TTLS) Coverage
    //
    // | RFC Section | Description                               | Test                                   |
    // |-------------|-------------------------------------------|----------------------------------------|
    // | 5216 3.1    | Start (S flag), no data                   | tls_start                              |
    // | 5216 3.1    | L and M flags, TLS Message Length         | tls_fragment_with_length               |
    // | 5216 3.1    | L flag without room for the length        | tls_length_flag_truncated              |
    // | 5216 3.1    | Fragment ACK (no flags octet data)        | tls_ack_without_data                   |
    // | 5281 9.1    | TTLS / PEAP version bits                  | ttls_version_bits                      |
    //
    // # RFC 4186 / RFC 4187 / RFC 9048 (EAP-SIM / AKA / AKA') Coverage
    //
    // | RFC Section | Description                               | Test                                   |
    // |-------------|-------------------------------------------|----------------------------------------|
    // | 4187 8.1    | AKA-Challenge with AT_RAND/AT_AUTN/AT_MAC | aka_challenge                          |
    // | 4186 8.1    | SIM-Start subtype                         | sim_start                              |
    // | 9048 3      | AKA' with AT_KDF                          | aka_prime_kdf                          |
    // | 4187 8.1    | Attribute Length 0                        | aka_attribute_zero_length              |
    // | 4187 8.1    | Attribute past end of packet              | aka_attribute_overrun                  |
    // | 4187 8.1    | Type-Data shorter than subtype header     | aka_short_header_raw                   |

    fn dissect(raw: &[u8]) -> (DissectResult, DissectBuffer<'_>) {
        let mut buf = DissectBuffer::new();
        let r = EapDissector.dissect(raw, &mut buf, 0).unwrap();
        (r, buf)
    }

    fn value<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a FieldValue<'a>> {
        let layer = &buf.layers()[0];
        buf.field_by_name(layer, name).map(|f| &f.value)
    }

    fn array_children<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> &'a [Field<'a>] {
        let Some(FieldValue::Array(r)) = value(buf, name) else {
            panic!("{name} must be an Array");
        };
        buf.nested_fields(r)
    }

    #[test]
    fn identity_request() {
        let raw: &[u8] = &[0x01, 0x07, 0x00, 0x05, 0x01];
        let (r, buf) = dissect(raw);
        assert_eq!(r.bytes_consumed, 5);
        assert_eq!(r.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "EAP");
        assert_eq!(layer.range, 0..5);
        assert_eq!(buf.field_u8(layer, "code"), Some(1));
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Request")
        );
        assert_eq!(buf.field_u8(layer, "identifier"), Some(7));
        assert_eq!(buf.field_u16(layer, "length"), Some(5));
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("Identity")
        );
        assert_eq!(value(&buf, "identity"), Some(&FieldValue::Bytes(&[])));
    }

    #[test]
    fn identity_response_with_padding() {
        let mut raw = vec![0x02, 0x07, 0x00, 0x0A, 0x01];
        raw.extend_from_slice(b"alice");
        raw.extend_from_slice(&[0u8; 10]);
        let (r, buf) = dissect(&raw);
        assert_eq!(r.bytes_consumed, 10);
        assert_eq!(buf.layers()[0].range, 0..10);
        assert_eq!(value(&buf, "identity"), Some(&FieldValue::Bytes(b"alice")));
    }

    #[test]
    fn notification_request() {
        let raw: &[u8] = &[0x01, 0x01, 0x00, 0x08, 0x02, b'h', b'e', b'y'];
        let (_, buf) = dissect(raw);
        assert_eq!(
            value(&buf, "notification"),
            Some(&FieldValue::Bytes(b"hey"))
        );
    }

    #[test]
    fn legacy_nak() {
        // Response/Nak asking for EAP-TLS or PEAP.
        let raw: &[u8] = &[0x02, 0x02, 0x00, 0x07, 0x03, 13, 25];
        let (_, buf) = dissect(raw);
        let types = array_children(&buf, "desired_types");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].value, FieldValue::U8(13));
        assert_eq!(types[1].value, FieldValue::U8(25));
        assert_eq!(
            types[1].descriptor.display_fn.unwrap()(&types[1].value, types),
            Some("PEAP")
        );
    }

    #[test]
    fn expanded_nak() {
        // RFC 3748, Section 5.3.2 (https://www.rfc-editor.org/rfc/rfc3748#section-5.3.2):
        // Type 254, Vendor-Id 0, Vendor-Type 3,
        // followed by one desired expanded type (Vendor-Id 0, Type 13).
        let raw: &[u8] = &[
            0x02, 0x03, 0x00, 0x14, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, //
            0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D,
        ];
        let (_, buf) = dissect(raw);
        assert_eq!(value(&buf, "type"), Some(&FieldValue::U8(254)));
        assert_eq!(value(&buf, "vendor_id"), Some(&FieldValue::U32(0)));
        assert_eq!(value(&buf, "vendor_type"), Some(&FieldValue::U32(3)));
        assert_eq!(
            value(&buf, "type_data"),
            Some(&FieldValue::Bytes(&raw[12..]))
        );
    }

    #[test]
    fn expanded_type_truncated() {
        let raw: &[u8] = &[0x01, 0x03, 0x00, 0x08, 0xFE, 0x00, 0x01, 0x37];
        let mut buf = DissectBuffer::new();
        let err = EapDissector.dissect(raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("EAP Expanded Type truncated")
        );
        assert!(buf.layers().is_empty());
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn md5_challenge_raw() {
        let raw: &[u8] = &[0x01, 0x04, 0x00, 0x07, 0x04, 0x01, 0xAA];
        let (_, buf) = dissect(raw);
        assert_eq!(
            value(&buf, "type_data"),
            Some(&FieldValue::Bytes(&[0x01, 0xAA]))
        );
    }

    #[test]
    fn success_and_failure() {
        for (code, name) in [(3u8, "Success"), (4, "Failure")] {
            let raw = [code, 0x09, 0x00, 0x04];
            let (r, buf) = dissect(&raw);
            assert_eq!(r.bytes_consumed, 4);
            let layer = &buf.layers()[0];
            assert_eq!(buf.resolve_display_name(layer, "code_name"), Some(name));
            assert!(buf.field_by_name(layer, "type").is_none());
        }
    }

    #[test]
    fn unknown_code_raw_data() {
        let raw: &[u8] = &[0x05, 0x01, 0x00, 0x06, 0x01, 0x00];
        let (_, buf) = dissect(raw);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "code_name"),
            Some("Initiate")
        );
        assert!(buf.field_by_name(layer, "type").is_none());
        assert_eq!(
            value(&buf, "type_data"),
            Some(&FieldValue::Bytes(&[0x01, 0x00]))
        );
    }

    #[test]
    fn request_without_type() {
        let raw: &[u8] = &[0x01, 0x01, 0x00, 0x04];
        let (_, buf) = dissect(raw);
        assert!(value(&buf, "type").is_none());
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        let err = EapDissector
            .dissect(&[0x01, 0x02], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 2
            }
        );
    }

    #[test]
    fn length_exceeds_data() {
        let mut buf = DissectBuffer::new();
        let err = EapDissector
            .dissect(&[0x02, 0x01, 0x00, 0x09, 0x01, b'a'], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 9,
                actual: 6
            }
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn length_below_header() {
        let mut buf = DissectBuffer::new();
        let err = EapDissector
            .dissect(&[0x03, 0x01, 0x00, 0x02], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("EAP Length smaller than header")
        );
    }

    #[test]
    fn tls_start() {
        // EAP-TLS Start: flags 0x20 (S).
        let raw: &[u8] = &[0x01, 0x05, 0x00, 0x06, 0x0D, 0x20];
        let (_, buf) = dissect(raw);
        let layer = &buf.layers()[0];
        assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(0x20)));
        assert_eq!(buf.resolve_display_name(layer, "flags_name"), Some("Start"));
        assert!(value(&buf, "tls_message_length").is_none());
        assert!(value(&buf, "tls_data").is_none());
        assert!(value(&buf, "tls_version").is_none());
    }

    #[test]
    fn tls_fragment_with_length() {
        // L + M: TLS Message Length 0x00000400, 3 octets of TLS data.
        let raw: &[u8] = &[
            0x02, 0x06, 0x00, 0x0D, 0x0D, 0xC0, 0x00, 0x00, 0x04, 0x00, 0x16, 0x03, 0x01,
        ];
        let (_, buf) = dissect(raw);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "flags_name"),
            Some("Length included, More fragments")
        );
        assert_eq!(
            value(&buf, "tls_message_length"),
            Some(&FieldValue::U32(1024))
        );
        assert_eq!(
            value(&buf, "tls_data"),
            Some(&FieldValue::Bytes(&[0x16, 0x03, 0x01]))
        );
        let data = buf.field_by_name(layer, "tls_data").unwrap();
        assert_eq!(data.range, 10..13);
    }

    #[test]
    fn tls_length_flag_truncated() {
        let raw: &[u8] = &[0x02, 0x06, 0x00, 0x08, 0x0D, 0x80, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        let err = EapDissector.dissect(raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("EAP TLS Message Length truncated")
        );
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn tls_ack_without_data() {
        // A Response with Type only (no flags octet) keeps nothing else.
        let raw: &[u8] = &[0x02, 0x06, 0x00, 0x05, 0x0D];
        let (_, buf) = dissect(raw);
        assert!(value(&buf, "flags").is_none());
    }

    #[test]
    fn ttls_version_bits() {
        for t in [TYPE_TTLS, TYPE_PEAP] {
            let raw = [0x01, 0x05, 0x00, 0x06, t, 0x21];
            let (_, buf) = dissect(&raw);
            assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(0x21)));
            assert_eq!(value(&buf, "tls_version"), Some(&FieldValue::U8(1)));
        }
    }

    #[test]
    fn aka_challenge() {
        // RFC 4187, Section 9.3 (https://www.rfc-editor.org/rfc/rfc4187#section-9.3)
        // EAP-Request/AKA-Challenge with AT_RAND,
        // AT_AUTN and AT_MAC (each 20 octets: type, length 5, 2 reserved, 16).
        let mut raw = vec![0x01, 0x21, 0x00, 0x44, 0x17, 0x01, 0x00, 0x00];
        for t in [1u8, 2, 11] {
            raw.extend_from_slice(&[t, 5, 0, 0]);
            raw.extend_from_slice(&[t; 16]);
        }
        assert_eq!(raw.len(), 0x44);
        let (_, buf) = dissect(&raw);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("EAP-AKA")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "subtype_name"),
            Some("AKA-Challenge")
        );
        assert_eq!(value(&buf, "reserved"), Some(&FieldValue::U16(0)));
        let attrs = array_children(&buf, "attributes");
        let objects: Vec<_> = attrs
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(r) => Some(buf.nested_fields(r)),
                _ => None,
            })
            .collect();
        assert_eq!(objects.len(), 3);
        assert_eq!(objects[0][0].value, FieldValue::U8(1));
        assert_eq!(objects[0][1].value, FieldValue::U8(5));
        assert_eq!(objects[0][2].value.as_bytes().unwrap().len(), 18);
        assert_eq!(objects[2][0].value, FieldValue::U8(11));
        assert_eq!(objects[0][2].range, 10..28);
        let idx = buf
            .fields()
            .iter()
            .position(|f| f.name() == "attribute")
            .unwrap() as u32;
        assert_eq!(buf.resolve_container_display_name(idx), Some("AT_RAND"));
    }

    #[test]
    fn sim_start() {
        // EAP-Request/SIM-Start with AT_VERSION_LIST (version 1).
        let raw: &[u8] = &[
            0x01, 0x02, 0x00, 0x10, 0x12, 0x0A, 0x00, 0x00, 0x0F, 0x02, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x00,
        ];
        let (_, buf) = dissect(raw);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "subtype_name"),
            Some("SIM-Start")
        );
        assert_eq!(array_children(&buf, "attributes").len(), 4);
    }

    #[test]
    fn aka_prime_kdf() {
        // EAP-AKA' AKA-Challenge with AT_KDF 1 (RFC 9048, Section 3.2 —
        // https://www.rfc-editor.org/rfc/rfc9048#section-3.2).
        let raw: &[u8] = &[
            0x01, 0x03, 0x00, 0x0C, 0x32, 0x01, 0x00, 0x00, 0x18, 0x01, 0x00, 0x01,
        ];
        let (_, buf) = dissect(raw);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "type_name"),
            Some("EAP-AKA'")
        );
        let attrs = array_children(&buf, "attributes");
        assert_eq!(attrs[1].value, FieldValue::U8(24));
    }

    #[test]
    fn aka_attribute_zero_length() {
        let raw: &[u8] = &[
            0x01, 0x03, 0x00, 0x0C, 0x17, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let err = EapDissector.dissect(raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("EAP-SIM/AKA attribute length is invalid")
        );
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn aka_attribute_overrun() {
        let raw: &[u8] = &[
            0x01, 0x03, 0x00, 0x0C, 0x17, 0x01, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00,
        ];
        let mut buf = DissectBuffer::new();
        let err = EapDissector.dissect(raw, &mut buf, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("EAP-SIM/AKA attribute length is invalid")
        );
    }

    #[test]
    fn aka_short_header_raw() {
        let raw: &[u8] = &[0x02, 0x03, 0x00, 0x07, 0x17, 0x05, 0x00];
        let (_, buf) = dissect(raw);
        assert!(value(&buf, "subtype").is_none());
        assert_eq!(
            value(&buf, "type_data"),
            Some(&FieldValue::Bytes(&[0x05, 0x00]))
        );
    }

    #[test]
    fn parse_eap_error_pushes_nothing() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Carrier", None, &[], 0..10);
        let err = parse_eap(&[0x02, 0x01, 0x00, 0x09], 6, &mut buf).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
        assert!(buf.fields().is_empty());

        // Success: fields go into the open layer, with absolute ranges.
        let n = parse_eap(&[0x03, 0x01, 0x00, 0x04, 0xFF], 6, &mut buf).unwrap();
        buf.end_layer();
        assert_eq!(n, 4);
        let layer = &buf.layers()[0];
        let code = buf.field_by_name(layer, "code").unwrap();
        assert_eq!(code.range, 6..7);
    }

    #[test]
    fn push_eap_object_in_carrier() {
        static FD: FieldDescriptor = EAP_OBJECT_DESCRIPTOR;
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Carrier", None, &[], 0..20);
        assert!(push_eap_object(
            &FD,
            &[0x02, 0x07, 0x00, 0x05, 0x01],
            10,
            &mut buf
        ));
        // Malformed, or not exactly one EAP packet (a carrier value has no
        // padding): nothing, not even the container, is pushed.
        let before = buf.fields().len();
        assert!(!push_eap_object(
            &FD,
            &[0x02, 0x07, 0x00, 0x09],
            10,
            &mut buf
        ));
        assert!(!push_eap_object(
            &FD,
            &[0x03, 0x07, 0x00, 0x04, 0xFF],
            10,
            &mut buf
        ));
        assert_eq!(buf.fields().len(), before);
        buf.end_layer();

        let obj = &buf.fields()[0];
        assert_eq!(obj.name(), "eap");
        assert_eq!(obj.range, 10..15);
        let FieldValue::Object(r) = &obj.value else {
            panic!("eap must be an Object");
        };
        assert_eq!(
            buf.resolve_nested_display_name(r, "type_name"),
            Some("Identity")
        );
        let children = EAP_OBJECT_DESCRIPTOR.children.unwrap();
        assert_eq!(children.len(), FIELD_DESCRIPTORS.len());
        assert!(
            children
                .iter()
                .zip(FIELD_DESCRIPTORS)
                .all(|(a, b)| a.name == b.name)
        );
        const { assert!(EAP_OBJECT_DESCRIPTOR.optional) };
    }

    #[test]
    fn name_tables() {
        assert_eq!(code_name(6), Some("Finish"));
        assert_eq!(code_name(7), None);
        for (t, n) in [
            (5u8, "One-Time Password (OTP)"),
            (6, "Generic Token Card (GTC)"),
            (17, "EAP-Cisco Wireless"),
            (26, "MS-EAP-Authentication"),
            (29, "EAP-MSCHAP-V2"),
            (43, "EAP-FAST"),
            (46, "EAP-PAX"),
            (47, "EAP-PSK"),
            (48, "EAP-SAKE"),
            (49, "EAP-IKEv2"),
            (51, "EAP-GPSK"),
            (52, "EAP-pwd"),
            (53, "EAP-EKE Version 1"),
            (54, "PT-EAP"),
            (55, "TEAP"),
            (56, "EAP-NOOB"),
            (57, "EAP-EDHOC"),
            (255, "Experimental"),
        ] {
            assert_eq!(type_name(t), Some(n));
        }
        assert_eq!(type_name(0), None);
        for (s, n) in [
            (2u8, "AKA-Authentication-Reject"),
            (4, "AKA-Synchronization-Failure"),
            (5, "AKA-Identity"),
            (11, "SIM-Challenge"),
            (12, "Notification"),
            (13, "Re-authentication"),
            (14, "Client-Error"),
        ] {
            assert_eq!(sim_aka_subtype_name(s), Some(n));
        }
        assert_eq!(sim_aka_subtype_name(3), None);
        for a in [
            3u8, 4, 6, 7, 10, 12, 13, 14, 16, 17, 19, 20, 21, 22, 23, 129, 130, 132, 133, 134, 135,
            136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
            153,
        ] {
            assert!(sim_aka_attribute_name(a).is_some(), "attribute {a}");
        }
        assert_eq!(sim_aka_attribute_name(5), None);
        for (f, n) in [
            (0x00u8, "None"),
            (0x40, "More fragments"),
            (0x60, "More fragments, Start"),
            (0x80, "Length included"),
            (0xA0, "Length included, Start"),
            (0xE0, "Length included, More fragments, Start"),
        ] {
            assert_eq!(tls_flags_name(f), n);
        }
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(EapDissector.name(), "Extensible Authentication Protocol");
        assert_eq!(EapDissector.short_name(), "EAP");
        assert!(std::ptr::eq(
            EapDissector.field_descriptors(),
            FIELD_DESCRIPTORS
        ));
        assert_eq!(EapDissector.references()[0].id, "RFC 3748");
        assert_eq!(EapDissector.layer(), Some(ProtocolLayer::Link));
    }
}
