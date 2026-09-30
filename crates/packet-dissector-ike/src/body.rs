//! IKE payload body decoding.
//!
//! Decodes the bodies of the cleartext IKEv2 payloads (RFC 7296, Sections
//! 3.3-3.15; RFC 7383, Section 2.5) and of the IKEv1 / ISAKMP payloads
//! (RFC 2408, Sections 3.4-3.16; RFC 2407, Section 4.6). Every decoded field
//! is emitted in addition to the raw `payload_data`. Malformed or truncated
//! bodies are decoded as far as their lengths are consistent and never panic.
//!
//! ## References
//! - RFC 7296, Section 3: <https://www.rfc-editor.org/rfc/rfc7296#section-3>
//! - RFC 7383, Section 2.5 (Encrypted Fragment): <https://www.rfc-editor.org/rfc/rfc7383#section-2.5>
//! - RFC 7427, Section 4 (SIGNATURE_HASH_ALGORITHMS): <https://www.rfc-editor.org/rfc/rfc7427#section-4>
//! - RFC 2408, Section 3 (ISAKMP payloads): <https://www.rfc-editor.org/rfc/rfc2408#section-3>
//! - RFC 2407, Sections 4.5-4.6 (IPsec DOI): <https://www.rfc-editor.org/rfc/rfc2407#section-4.5>
//! - RFC 2409, Appendix A (IKEv1 attribute classes): <https://www.rfc-editor.org/rfc/rfc2409#appendix-A>

use packet_dissector_core::field::{DisplayFn, Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::lookup::ip_protocol_name;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv4_addr, read_ipv6_addr};

use crate::names::{
    auth_method_name, cert_encoding_name, cfg_attribute_name, cfg_type_name, encr_transform_name,
    gcauth_transform_name, hash_algorithm_name, id_type_name, integ_transform_name, ke_method_name,
    kwa_transform_name, notify_error_name, notify_status_name, prf_transform_name,
    protocol_id_name, sn_transform_name, transform_attribute_name, transform_type_name,
    ts_type_name, v1_ah_transform_name, v1_doi_name, v1_encapsulation_mode_name,
    v1_esp_transform_name, v1_group_description_name, v1_group_type_name, v1_ike_attribute_name,
    v1_ike_auth_method_name, v1_ike_encryption_name, v1_ike_hash_name, v1_ike_life_type_name,
    v1_ipcomp_transform_name, v1_ipsec_attribute_name, v1_ipsec_auth_algorithm_name,
    v1_ipsec_id_type_name, v1_ipsec_life_type_name, v1_ipsec_notify_status_name,
    v1_isakmp_transform_name, v1_notify_error_name, v1_notify_status_name, v1_protocol_id_name,
};

// ---------------------------------------------------------------------------
// Sibling helpers and display functions
// ---------------------------------------------------------------------------

/// Own (non-nested) fields of an Object: the flat child slice also holds
/// the descendants of nested containers, which come after the scalars that
/// the display functions look at.
fn own_fields<'a, 'pkt>(fields: &'a [Field<'pkt>]) -> impl Iterator<Item = &'a Field<'pkt>> {
    fields
        .iter()
        .take_while(|f| !matches!(f.value, FieldValue::Array(_) | FieldValue::Object(_)))
}

fn own_u8(fields: &[Field<'_>], name: &str) -> Option<u8> {
    own_fields(fields).find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U8(v)) if n == name => Some(*v),
        _ => None,
    })
}

fn own_u16(fields: &[Field<'_>], name: &str) -> Option<u16> {
    own_fields(fields).find_map(|f| match (f.name(), &f.value) {
        (n, FieldValue::U16(v)) if n == name => Some(*v),
        _ => None,
    })
}

fn u8_of(v: &FieldValue<'_>) -> Option<u8> {
    match v {
        FieldValue::U8(x) => Some(*x),
        _ => None,
    }
}

fn u16_of(v: &FieldValue<'_>) -> Option<u16> {
    match v {
        FieldValue::U16(x) => Some(*x),
        _ => None,
    }
}

fn d_protocol_v2(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    protocol_id_name(u8_of(v)?)
}
fn d_protocol_v1(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_protocol_id_name(u8_of(v)?)
}
fn d_transform_type(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    transform_type_name(u8_of(v)?)
}

/// RFC 7296, Section 3.3.2 — the Transform ID is interpreted per Transform
/// Type (IANA "Transform Type N - ... Transform IDs"; types 6-12 are the
/// RFC 9370 additional key exchanges, which share the type 4 IDs).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.2>
fn d_transform_id_v2(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let id = u16_of(v)?;
    match own_u8(siblings, "transform_type")? {
        1 => encr_transform_name(id),
        2 => prf_transform_name(id),
        3 => integ_transform_name(id),
        4 | 6..=12 => ke_method_name(id),
        5 => sn_transform_name(id),
        13 => kwa_transform_name(id),
        14 => gcauth_transform_name(id),
        _ => None,
    }
}

/// RFC 2407, Section 4.4 — the Transform ID is interpreted per Protocol ID.
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.4>
fn d_tid_isakmp(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_isakmp_transform_name(u8::try_from(u16_of(v)?).ok()?)
}
fn d_tid_ah(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_ah_transform_name(u8::try_from(u16_of(v)?).ok()?)
}
fn d_tid_esp(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_esp_transform_name(u8::try_from(u16_of(v)?).ok()?)
}
fn d_tid_ipcomp(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_ipcomp_transform_name(u8::try_from(u16_of(v)?).ok()?)
}

fn d_attr_type_v2(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    transform_attribute_name(u16_of(v)?)
}
fn d_attr_type_v1_ike(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_ike_attribute_name(u16_of(v)?)
}
fn d_attr_type_v1_ipsec(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_ipsec_attribute_name(u16_of(v)?)
}

/// RFC 2409, Appendix A — basic attribute values of the IKE SA.
/// <https://www.rfc-editor.org/rfc/rfc2409#appendix-A>
fn d_attr_value_v1_ike(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let val = u16_of(v)?;
    match own_u16(siblings, "attribute_type")? {
        1 => v1_ike_encryption_name(val),
        2 => v1_ike_hash_name(val),
        3 => v1_ike_auth_method_name(val),
        4 => v1_group_description_name(val),
        5 => v1_group_type_name(val),
        11 => v1_ike_life_type_name(val),
        _ => None,
    }
}

/// RFC 2407, Section 4.5 — basic attribute values of the IPsec SA.
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.5>
fn d_attr_value_v1_ipsec(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let val = u16_of(v)?;
    match own_u16(siblings, "attribute_type")? {
        1 => v1_ipsec_life_type_name(val),
        3 => v1_group_description_name(val),
        4 => v1_encapsulation_mode_name(val),
        5 => v1_ipsec_auth_algorithm_name(val),
        _ => None,
    }
}

fn d_dh_group(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    ke_method_name(u16_of(v)?)
}
fn d_id_type_v2(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    id_type_name(u8_of(v)?)
}
fn d_id_type_v1(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    v1_ipsec_id_type_name(u8_of(v)?)
}
fn d_ip_protocol(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    ip_protocol_name(u8_of(v)?)
}
fn d_cert_encoding(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    cert_encoding_name(u8_of(v)?)
}
fn d_auth_method(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    auth_method_name(u8_of(v)?)
}

/// RFC 7296, Section 3.10.1 — "Types in the range 0 - 16383 are intended
/// for reporting errors."
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.10.1>
fn d_notify_v2(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    let t = u16_of(v)?;
    if t < 16384 {
        notify_error_name(t)
    } else {
        notify_status_name(t)
    }
}

/// RFC 2408, Section 3.14.1 (errors 1-8191, status 16384-24575) and
/// RFC 2407, Section 4.6.3 (IPsec DOI status 24576-32767).
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.14.1>
fn d_notify_v1(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    let t = u16_of(v)?;
    v1_notify_error_name(t)
        .or_else(|| v1_notify_status_name(t))
        .or_else(|| v1_ipsec_notify_status_name(t))
}

fn d_doi(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    match v {
        FieldValue::U32(x) => v1_doi_name(*x),
        _ => None,
    }
}
fn d_ts_type(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    ts_type_name(u8_of(v)?)
}
fn d_cfg_type(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    cfg_type_name(u8_of(v)?)
}
fn d_cfg_attr(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    cfg_attribute_name(u16_of(v)?)
}
fn d_hash_algorithm(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
    hash_algorithm_name(u16_of(v)?)
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

const fn opt(name: &'static str, display: &'static str, ty: FieldType) -> FieldDescriptor {
    FieldDescriptor::new(name, display, ty).optional()
}

const fn named(
    name: &'static str,
    display: &'static str,
    ty: FieldType,
    f: DisplayFn,
) -> FieldDescriptor {
    FieldDescriptor::new(name, display, ty)
        .optional()
        .with_display_fn(f)
}

const fn object(name: &'static str, display: &'static str) -> FieldDescriptor {
    FieldDescriptor::new(name, display, FieldType::Object)
}

/// Data attribute fields (RFC 7296, Section 3.3.5; RFC 2408, Section 3.3).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.5>
const fn attribute_fields(type_fn: DisplayFn, value_fn: Option<DisplayFn>) -> [FieldDescriptor; 4] {
    [
        opt("attribute_format", "Attribute Format (AF)", FieldType::U8),
        named("attribute_type", "Attribute Type", FieldType::U16, type_fn),
        opt("attribute_length", "Attribute Length", FieldType::U16),
        FieldDescriptor {
            name: "attribute_value",
            display_name: "Attribute Value",
            field_type: FieldType::Any,
            optional: true,
            children: None,
            display_fn: value_fn,
            format_fn: None,
        },
    ]
}

static ATTR_V2: [FieldDescriptor; 4] = attribute_fields(d_attr_type_v2, None);
static ATTR_V1_IKE: [FieldDescriptor; 4] =
    attribute_fields(d_attr_type_v1_ike, Some(d_attr_value_v1_ike));
static ATTR_V1_IPSEC: [FieldDescriptor; 4] =
    attribute_fields(d_attr_type_v1_ipsec, Some(d_attr_value_v1_ipsec));

const AFD_FORMAT: usize = 0;
const AFD_TYPE: usize = 1;
const AFD_LENGTH: usize = 2;
const AFD_VALUE: usize = 3;

static FD_ATTRIBUTE: FieldDescriptor = object("attribute", "Attribute");
static FD_TRANSFORM: FieldDescriptor = object("transform", "Transform");
static FD_PROPOSAL: FieldDescriptor = object("proposal", "Proposal");
static FD_TS: FieldDescriptor = object("traffic_selector", "Traffic Selector");

/// Transform fields shared by IKEv2 (Transform Substructure, RFC 7296,
/// Section 3.3.2 — <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.2>)
/// and IKEv1 (Transform Payload, RFC 2408, Section 3.6 —
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.6>). IKEv2 emits
/// `transform_type`, IKEv1 emits `transform_number`; one copy exists per
/// registry so that the Transform ID and attributes resolve correctly.
const fn transform_fields(
    tid: Option<DisplayFn>,
    attrs: &'static [FieldDescriptor],
) -> [FieldDescriptor; 5] {
    [
        opt("transform_length", "Transform Length", FieldType::U16),
        named(
            "transform_type",
            "Transform Type",
            FieldType::U8,
            d_transform_type,
        ),
        opt("transform_number", "Transform #", FieldType::U8),
        FieldDescriptor {
            name: "transform_id",
            display_name: "Transform ID",
            field_type: FieldType::U16,
            optional: true,
            children: None,
            display_fn: tid,
            format_fn: None,
        },
        opt("attributes", "Transform Attributes", FieldType::Array).with_children(attrs),
    ]
}

static TRANSFORM_V2: [FieldDescriptor; 5] = transform_fields(Some(d_transform_id_v2), &ATTR_V2);
static TRANSFORM_V1_ISAKMP: [FieldDescriptor; 5] =
    transform_fields(Some(d_tid_isakmp), &ATTR_V1_IKE);
static TRANSFORM_V1_AH: [FieldDescriptor; 5] = transform_fields(Some(d_tid_ah), &ATTR_V1_IPSEC);
static TRANSFORM_V1_ESP: [FieldDescriptor; 5] = transform_fields(Some(d_tid_esp), &ATTR_V1_IPSEC);
static TRANSFORM_V1_IPCOMP: [FieldDescriptor; 5] =
    transform_fields(Some(d_tid_ipcomp), &ATTR_V1_IPSEC);
static TRANSFORM_V1_OTHER: [FieldDescriptor; 5] = transform_fields(None, &ATTR_V1_IPSEC);

const TFD_LENGTH: usize = 0;
const TFD_TYPE: usize = 1;
const TFD_NUMBER: usize = 2;
const TFD_ID: usize = 3;
const TFD_ATTRIBUTES: usize = 4;

/// Proposal Substructure (RFC 7296, Section 3.3.1) / Proposal Payload
/// (RFC 2408, Section 3.5).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.1>
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.5>
const fn proposal_fields(
    proto: DisplayFn,
    transforms: &'static [FieldDescriptor],
) -> [FieldDescriptor; 7] {
    [
        opt("proposal_length", "Proposal Length", FieldType::U16),
        opt("proposal_number", "Proposal Number", FieldType::U8),
        named("protocol_id", "Protocol ID", FieldType::U8, proto),
        opt("spi_size", "SPI Size", FieldType::U8),
        opt("num_transforms", "Number of Transforms", FieldType::U8),
        opt("spi", "SPI", FieldType::Bytes),
        opt("transforms", "Transforms", FieldType::Array).with_children(transforms),
    ]
}

static PROPOSAL_V2: [FieldDescriptor; 7] = proposal_fields(d_protocol_v2, &TRANSFORM_V2);
static PROPOSAL_V1: [FieldDescriptor; 7] = proposal_fields(d_protocol_v1, &TRANSFORM_V1_ESP);

const PRFD_LENGTH: usize = 0;
const PRFD_NUMBER: usize = 1;
const PRFD_PROTOCOL: usize = 2;
const PRFD_SPI_SIZE: usize = 3;
const PRFD_NUM_TRANSFORMS: usize = 4;
const PRFD_SPI: usize = 5;
const PRFD_TRANSFORMS: usize = 6;

/// Traffic Selector (RFC 7296, Section 3.13.1).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.13.1>
static TS_FIELDS: [FieldDescriptor; 8] = [
    named("ts_type", "TS Type", FieldType::U8, d_ts_type),
    named(
        "ip_protocol",
        "IP Protocol ID",
        FieldType::U8,
        d_ip_protocol,
    ),
    opt("selector_length", "Selector Length", FieldType::U16),
    opt("start_port", "Start Port", FieldType::U16),
    opt("end_port", "End Port", FieldType::U16),
    opt("starting_address", "Starting Address", FieldType::Any),
    opt("ending_address", "Ending Address", FieldType::Any),
    opt("selector_data", "Selector Data", FieldType::Bytes),
];

/// Configuration Attribute (RFC 7296, Section 3.15.1).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.15.1>
static CFG_ATTR: [FieldDescriptor; 4] = attribute_fields(d_cfg_attr, None);

static FD_HASH_ALGORITHM: FieldDescriptor =
    FieldDescriptor::new("hash_algorithm", "Hash Algorithm", FieldType::U16)
        .with_display_fn(d_hash_algorithm);
static FD_SPI_ITEM: FieldDescriptor = FieldDescriptor::new("spi", "SPI", FieldType::Bytes);

/// Child descriptors of a payload Object: the generic payload header
/// (indices 0-3) followed by the union of all decoded body fields.
pub(crate) static PAYLOAD_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "payload_type",
        display_name: "Payload Type",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(t) => crate::payload_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("critical", "Critical", FieldType::U8).optional(),
    FieldDescriptor::new("payload_length", "Payload Length", FieldType::U16),
    FieldDescriptor::new("payload_data", "Payload Data", FieldType::Bytes).optional(),
    // RFC 2408, Section 3.4 / RFC 2407, Section 4.6.1 (IKEv1 SA, Notify, Delete)
    // <https://www.rfc-editor.org/rfc/rfc2408#section-3.4>
    named("doi", "Domain of Interpretation", FieldType::U32, d_doi),
    opt("situation", "Situation", FieldType::U32),
    // RFC 7296, Section 3.3 / RFC 2408, Section 3.5
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.3>
    opt("proposals", "Proposals", FieldType::Array).with_children(&PROPOSAL_V2),
    // RFC 7296, Section 3.4 (also INVALID_KE_PAYLOAD data, Section 3.10.1)
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.4>
    named(
        "dh_group",
        "Key Exchange Method",
        FieldType::U16,
        d_dh_group,
    ),
    opt("key_exchange_data", "Key Exchange Data", FieldType::Bytes),
    // RFC 7296, Section 3.5 / RFC 2407, Section 4.6.2
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.5>
    named("id_type", "ID Type", FieldType::U8, d_id_type_v2),
    named(
        "id_protocol_id",
        "Protocol ID",
        FieldType::U8,
        d_ip_protocol,
    ),
    opt("id_port", "Port", FieldType::U16),
    opt("identification", "Identification Data", FieldType::Any),
    // RFC 7296, Sections 3.6-3.7 / RFC 2408, Sections 3.9-3.10
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.6>
    named(
        "cert_encoding",
        "Certificate Encoding",
        FieldType::U8,
        d_cert_encoding,
    ),
    opt("certificate_data", "Certificate Data", FieldType::Bytes),
    // RFC 7296, Section 3.8
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.8>
    named("auth_method", "Auth Method", FieldType::U8, d_auth_method),
    opt(
        "authentication_data",
        "Authentication Data",
        FieldType::Bytes,
    ),
    // RFC 7296, Section 3.9 / RFC 2408, Section 3.13
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.9>
    opt("nonce", "Nonce Data", FieldType::Bytes),
    // RFC 7296, Sections 3.10-3.11 / RFC 2408, Sections 3.14-3.15
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.10>
    named("protocol_id", "Protocol ID", FieldType::U8, d_protocol_v2),
    opt("spi_size", "SPI Size", FieldType::U8),
    named(
        "notify_type",
        "Notify Message Type",
        FieldType::U16,
        d_notify_v2,
    ),
    opt("spi", "SPI", FieldType::Bytes),
    opt("notification_data", "Notification Data", FieldType::Bytes),
    // RFC 7427, Section 4 — SIGNATURE_HASH_ALGORITHMS
    // <https://www.rfc-editor.org/rfc/rfc7427#section-4>
    opt("hash_algorithms", "Hash Algorithms", FieldType::Array)
        .with_children(core::slice::from_ref(&FD_HASH_ALGORITHM)),
    opt("num_spis", "Number of SPIs", FieldType::U16),
    opt("spis", "SPIs", FieldType::Array).with_children(core::slice::from_ref(&FD_SPI_ITEM)),
    // RFC 7296, Section 3.12 / RFC 2408, Section 3.16
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.12>
    opt("vendor_id", "Vendor ID", FieldType::Bytes),
    // RFC 7296, Section 3.13
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.13>
    opt("num_ts", "Number of TSs", FieldType::U8),
    opt("traffic_selectors", "Traffic Selectors", FieldType::Array).with_children(&TS_FIELDS),
    // RFC 7296, Section 3.15
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.15>
    named("cfg_type", "CFG Type", FieldType::U8, d_cfg_type),
    opt("attributes", "Configuration Attributes", FieldType::Array).with_children(&CFG_ATTR),
    // RFC 7383, Section 2.5
    // <https://www.rfc-editor.org/rfc/rfc7383#section-2.5>
    opt("fragment_number", "Fragment Number", FieldType::U16),
    opt("total_fragments", "Total Fragments", FieldType::U16),
    // RFC 7296, Section 3.16
    // <https://www.rfc-editor.org/rfc/rfc7296#section-3.16>
    #[cfg(feature = "eap")]
    packet_dissector_eap::EAP_OBJECT_DESCRIPTOR,
];

pub(crate) const PFD_PAYLOAD_TYPE: usize = 0;
pub(crate) const PFD_CRITICAL: usize = 1;
pub(crate) const PFD_PAYLOAD_LENGTH: usize = 2;
pub(crate) const PFD_PAYLOAD_DATA: usize = 3;
const PFD_DOI: usize = 4;
const PFD_SITUATION: usize = 5;
const PFD_PROPOSALS: usize = 6;
const PFD_DH_GROUP: usize = 7;
const PFD_KE_DATA: usize = 8;
const PFD_ID_TYPE: usize = 9;
const PFD_ID_PROTOCOL: usize = 10;
const PFD_ID_PORT: usize = 11;
const PFD_IDENTIFICATION: usize = 12;
const PFD_CERT_ENCODING: usize = 13;
const PFD_CERT_DATA: usize = 14;
const PFD_AUTH_METHOD: usize = 15;
const PFD_AUTH_DATA: usize = 16;
const PFD_NONCE: usize = 17;
const PFD_PROTOCOL_ID: usize = 18;
const PFD_SPI_SIZE: usize = 19;
const PFD_NOTIFY_TYPE: usize = 20;
const PFD_SPI: usize = 21;
const PFD_NOTIFY_DATA: usize = 22;
const PFD_HASH_ALGORITHMS: usize = 23;
const PFD_NUM_SPIS: usize = 24;
const PFD_SPIS: usize = 25;
const PFD_VENDOR_ID: usize = 26;
const PFD_NUM_TS: usize = 27;
const PFD_TRAFFIC_SELECTORS: usize = 28;
const PFD_CFG_TYPE: usize = 29;
const PFD_CFG_ATTRIBUTES: usize = 30;
const PFD_FRAGMENT_NUMBER: usize = 31;
const PFD_TOTAL_FRAGMENTS: usize = 32;
#[cfg(feature = "eap")]
const PFD_EAP: usize = 33;

// IKEv1 variants of payload fields whose values use different registries.
static V1_PROPOSALS: FieldDescriptor =
    opt("proposals", "Proposals", FieldType::Array).with_children(&PROPOSAL_V1);
static V1_ID_TYPE: FieldDescriptor = named("id_type", "ID Type", FieldType::U8, d_id_type_v1);
static V1_CERT_ENCODING: FieldDescriptor =
    opt("cert_encoding", "Certificate Encoding", FieldType::U8);
static V1_PROTOCOL_ID: FieldDescriptor =
    named("protocol_id", "Protocol ID", FieldType::U8, d_protocol_v1);
static V1_NOTIFY_TYPE: FieldDescriptor = named(
    "notify_type",
    "Notify Message Type",
    FieldType::U16,
    d_notify_v1,
);

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Push `data[start..end]` (relative to `data`, absolute base `off`).
fn push<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    value: FieldValue<'pkt>,
    off: usize,
    start: usize,
    end: usize,
) {
    buf.push_field(fd, value, off + start..off + end);
}

fn u16_at(data: &[u8], pos: usize) -> u16 {
    read_be_u16(data, pos).unwrap_or_default()
}

/// Decode the body of one payload. `body` excludes the 4-octet generic
/// payload header and starts at absolute offset `off`.
pub(crate) fn decode_body<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    major_version: u8,
    payload_type: u8,
    body: &'pkt [u8],
    off: usize,
) {
    let f = PAYLOAD_CHILDREN;
    match (major_version, payload_type) {
        (2, 33) => decode_sa_proposals(buf, true, body, off, 0, &f[PFD_PROPOSALS]),
        (2, 34) => decode_v2_ke(buf, body, off),
        (2, 35 | 36) => decode_id(buf, false, body, off),
        (2, 37 | 38) => decode_cert(buf, &f[PFD_CERT_ENCODING], body, off),
        (2, 39) => decode_v2_auth(buf, body, off),
        (2, 40) | (1, 10) => push_rest(buf, &f[PFD_NONCE], body, off, 0),
        (2, 41) => decode_v2_notify(buf, body, off),
        (2, 42) => decode_delete(buf, &f[PFD_PROTOCOL_ID], body, off, 0),
        (2, 43) | (1, 13) => push_rest(buf, &f[PFD_VENDOR_ID], body, off, 0),
        (2, 44 | 45) => decode_v2_ts(buf, body, off),
        (2, 47) => decode_v2_cp(buf, body, off),
        (2, 53) => decode_v2_skf(buf, body, off),
        // RFC 7296, Section 3.16 — "The payload type for an EAP payload is
        // forty-eight (48)."; the EAP Message follows the generic payload
        // header. <https://www.rfc-editor.org/rfc/rfc7296#section-3.16>
        #[cfg(feature = "eap")]
        (2, 48) => {
            packet_dissector_eap::push_eap_object(&f[PFD_EAP], body, off, buf);
        }
        (1, 1) => decode_v1_sa(buf, body, off),
        (1, 4) => push_rest(buf, &f[PFD_KE_DATA], body, off, 0),
        (1, 5) => decode_id(buf, true, body, off),
        (1, 6 | 7) => decode_cert(buf, &V1_CERT_ENCODING, body, off),
        (1, 11) => decode_v1_notify(buf, body, off),
        (1, 12) => decode_v1_delete(buf, body, off),
        _ => {}
    }
}

/// Push `body[from..]` as `fd` when it is not empty.
fn push_rest<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    off: usize,
    from: usize,
) {
    if from < body.len() {
        push(
            buf,
            fd,
            FieldValue::Bytes(&body[from..]),
            off,
            from,
            body.len(),
        );
    }
}

/// RFC 7296, Section 3.4 — "Diffie-Hellman Group Num (2 octets)",
/// RESERVED (2), Key Exchange Data.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.4>
fn decode_v2_ke<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    push(
        buf,
        &f[PFD_DH_GROUP],
        FieldValue::U16(u16_at(body, 0)),
        off,
        0,
        2,
    );
    push_rest(buf, &f[PFD_KE_DATA], body, off, 4);
}

/// Type identification data by ID Type: ID_IPV4_ADDR (1), ID_FQDN (2),
/// ID_RFC822_ADDR / ID_USER_FQDN (3) and ID_IPV6_ADDR (5) share their values
/// in IKEv2 (RFC 7296, Section 3.5) and the IPsec DOI (RFC 2407,
/// Section 4.6.2.1).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.5>
fn identification(id_type: u8, data: &[u8]) -> FieldValue<'_> {
    match (id_type, data.len()) {
        (1, 4) => FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
        (5, 16) => FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default()),
        (2 | 3, _) => match core::str::from_utf8(data) {
            Ok(s) => FieldValue::Str(s),
            Err(_) => FieldValue::Bytes(data),
        },
        _ => FieldValue::Bytes(data),
    }
}

/// RFC 7296, Section 3.5 — ID Type (1), RESERVED (3), Identification Data.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.5>
/// RFC 2407, Section 4.6.2 — ID Type (1), Protocol ID (1), Port (2),
/// Identification Data.
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.6.2>
fn decode_id<'pkt>(buf: &mut DissectBuffer<'pkt>, v1: bool, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    let id_type = body[0];
    let type_fd = if v1 { &V1_ID_TYPE } else { &f[PFD_ID_TYPE] };
    push(buf, type_fd, FieldValue::U8(id_type), off, 0, 1);
    if v1 {
        push(buf, &f[PFD_ID_PROTOCOL], FieldValue::U8(body[1]), off, 1, 2);
        push(
            buf,
            &f[PFD_ID_PORT],
            FieldValue::U16(u16_at(body, 2)),
            off,
            2,
            4,
        );
    }
    if body.len() > 4 {
        let value = identification(id_type, &body[4..]);
        push(buf, &f[PFD_IDENTIFICATION], value, off, 4, body.len());
    }
}

/// RFC 7296, Sections 3.6-3.7 / RFC 2408, Sections 3.9-3.10 — Encoding (1)
/// followed by the certificate (authority) data.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.6>
fn decode_cert<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    encoding_fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    off: usize,
) {
    if body.is_empty() {
        return;
    }
    push(buf, encoding_fd, FieldValue::U8(body[0]), off, 0, 1);
    push_rest(buf, &PAYLOAD_CHILDREN[PFD_CERT_DATA], body, off, 1);
}

/// RFC 7296, Section 3.8 — Auth Method (1), RESERVED (3), Authentication Data.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.8>
fn decode_v2_auth<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    push(buf, &f[PFD_AUTH_METHOD], FieldValue::U8(body[0]), off, 0, 1);
    push_rest(buf, &f[PFD_AUTH_DATA], body, off, 4);
}

/// Push Protocol ID, SPI Size, Notify Message Type and SPI starting at
/// `base`, returning the offset of the notification data, or `None` if the
/// SPI does not fit.
fn push_notify_header<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    protocol_fd: &'static FieldDescriptor,
    type_fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    off: usize,
    base: usize,
) -> Option<usize> {
    let f = PAYLOAD_CHILDREN;
    let spi_size = body[base + 1] as usize;
    push(
        buf,
        protocol_fd,
        FieldValue::U8(body[base]),
        off,
        base,
        base + 1,
    );
    push(
        buf,
        &f[PFD_SPI_SIZE],
        FieldValue::U8(body[base + 1]),
        off,
        base + 1,
        base + 2,
    );
    push(
        buf,
        type_fd,
        FieldValue::U16(u16_at(body, base + 2)),
        off,
        base + 2,
        base + 4,
    );
    let spi_end = base + 4 + spi_size;
    if spi_end > body.len() {
        return None;
    }
    if spi_size > 0 {
        push(
            buf,
            &f[PFD_SPI],
            FieldValue::Bytes(&body[base + 4..spi_end]),
            off,
            base + 4,
            spi_end,
        );
    }
    Some(spi_end)
}

/// Notify Message Type INVALID_KE_PAYLOAD (RFC 7296, Section 3.10.1).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.10.1>
const NOTIFY_INVALID_KE_PAYLOAD: u16 = 17;
/// Notify Message Type SIGNATURE_HASH_ALGORITHMS (RFC 7427, Section 4).
/// <https://www.rfc-editor.org/rfc/rfc7427#section-4>
const NOTIFY_SIGNATURE_HASH_ALGORITHMS: u16 = 16431;

/// RFC 7296, Section 3.10 — Protocol ID (1), SPI Size (1), Notify Message
/// Type (2), SPI, Notification Data.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.10>
fn decode_v2_notify<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    let Some(data_start) =
        push_notify_header(buf, &f[PFD_PROTOCOL_ID], &f[PFD_NOTIFY_TYPE], body, off, 0)
    else {
        return;
    };
    push_rest(buf, &f[PFD_NOTIFY_DATA], body, off, data_start);
    let data = &body[data_start..];
    match u16_at(body, 2) {
        // RFC 7296, Section 1.3 — "There are two octets of data associated
        // with this notification: the accepted Diffie-Hellman group number
        // in big endian order."
        // <https://www.rfc-editor.org/rfc/rfc7296#section-1.3>
        NOTIFY_INVALID_KE_PAYLOAD if data.len() == 2 => {
            push(
                buf,
                &f[PFD_DH_GROUP],
                FieldValue::U16(u16_at(data, 0)),
                off,
                data_start,
                data_start + 2,
            );
        }
        // RFC 7427, Section 4 — "The Notification Data field contains the
        // list of 16-bit hash algorithm identifiers".
        // <https://www.rfc-editor.org/rfc/rfc7427#section-4>
        NOTIFY_SIGNATURE_HASH_ALGORITHMS if !data.is_empty() && data.len() % 2 == 0 => {
            let idx = buf.begin_container(
                &f[PFD_HASH_ALGORITHMS],
                FieldValue::Array(0..0),
                off + data_start..off + body.len(),
            );
            for (i, chunk) in data.chunks_exact(2).enumerate() {
                let at = data_start + 2 * i;
                push(
                    buf,
                    &FD_HASH_ALGORITHM,
                    FieldValue::U16(u16_at(chunk, 0)),
                    off,
                    at,
                    at + 2,
                );
            }
            buf.end_container(idx);
        }
        _ => {}
    }
}

/// RFC 2408, Section 3.14 — DOI (4), Protocol-ID (1), SPI Size (1), Notify
/// Message Type (2), SPI, Notification Data.
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.14>
fn decode_v1_notify<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 8 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    push(
        buf,
        &f[PFD_DOI],
        FieldValue::U32(read_be_u32(body, 0).unwrap_or_default()),
        off,
        0,
        4,
    );
    if let Some(data_start) =
        push_notify_header(buf, &V1_PROTOCOL_ID, &V1_NOTIFY_TYPE, body, off, 4)
    {
        push_rest(buf, &f[PFD_NOTIFY_DATA], body, off, data_start);
    }
}

/// Delete payload body starting at `base`: Protocol ID (1), SPI Size (1),
/// Num of SPIs (2), SPIs.
/// RFC 7296, Section 3.11 — <https://www.rfc-editor.org/rfc/rfc7296#section-3.11>
/// RFC 2408, Section 3.15 — <https://www.rfc-editor.org/rfc/rfc2408#section-3.15>
fn decode_delete<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    protocol_fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    off: usize,
    base: usize,
) {
    if body.len() < base + 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    let spi_size = body[base + 1] as usize;
    let num = u16_at(body, base + 2);
    push(
        buf,
        protocol_fd,
        FieldValue::U8(body[base]),
        off,
        base,
        base + 1,
    );
    push(
        buf,
        &f[PFD_SPI_SIZE],
        FieldValue::U8(body[base + 1]),
        off,
        base + 1,
        base + 2,
    );
    push(
        buf,
        &f[PFD_NUM_SPIS],
        FieldValue::U16(num),
        off,
        base + 2,
        base + 4,
    );
    let count = (body.len() - base - 4)
        .checked_div(spi_size)
        .map_or(0, |fit| core::cmp::min(num as usize, fit));
    if count == 0 {
        return;
    }
    let spis = &body[base + 4..base + 4 + count * spi_size];
    let idx = buf.begin_container(
        &f[PFD_SPIS],
        FieldValue::Array(0..0),
        off + base + 4..off + base + 4 + spis.len(),
    );
    for (i, spi) in spis.chunks_exact(spi_size).enumerate() {
        let at = base + 4 + i * spi_size;
        push(
            buf,
            &FD_SPI_ITEM,
            FieldValue::Bytes(spi),
            off,
            at,
            at + spi_size,
        );
    }
    buf.end_container(idx);
}

/// RFC 2408, Section 3.15 — DOI (4) followed by the common Delete fields.
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.15>
fn decode_v1_delete<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 8 {
        return;
    }
    let doi = read_be_u32(body, 0).unwrap_or_default();
    push(
        buf,
        &PAYLOAD_CHILDREN[PFD_DOI],
        FieldValue::U32(doi),
        off,
        0,
        4,
    );
    decode_delete(buf, &V1_PROTOCOL_ID, body, off, 4);
}

/// Traffic selector types with a fixed layout (RFC 7296, Section 3.13.1).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.13.1>
const TS_IPV4_ADDR_RANGE: u8 = 7;
const TS_IPV6_ADDR_RANGE: u8 = 8;

/// RFC 7296, Section 3.13 — Number of TSs (1), RESERVED (3), Traffic
/// Selectors; Section 3.13.1 — TS Type (1), IP Protocol ID (1), Selector
/// Length (2), Start Port (2), End Port (2), Starting / Ending Address.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.13>
fn decode_v2_ts<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    push(buf, &f[PFD_NUM_TS], FieldValue::U8(body[0]), off, 0, 1);
    let idx = buf.begin_container(
        &f[PFD_TRAFFIC_SELECTORS],
        FieldValue::Array(0..0),
        off + 4..off + body.len(),
    );
    let mut pos = 4;
    while pos + 4 <= body.len() {
        let ts_type = body[pos];
        let len = u16_at(body, pos + 2) as usize;
        if len < 4 || pos + len > body.len() {
            break;
        }
        let obj = buf.begin_container(&FD_TS, FieldValue::Object(0..0), off + pos..off + pos + len);
        push(
            buf,
            &TS_FIELDS[0],
            FieldValue::U8(ts_type),
            off,
            pos,
            pos + 1,
        );
        // Octet 1 is the IP Protocol ID only for the address range types;
        // e.g. TS_SECLABEL (RFC 9478, Section 2.1) has a RESERVED octet.
        // <https://www.rfc-editor.org/rfc/rfc9478#section-2.1>
        if matches!(ts_type, TS_IPV4_ADDR_RANGE | TS_IPV6_ADDR_RANGE) {
            push(
                buf,
                &TS_FIELDS[1],
                FieldValue::U8(body[pos + 1]),
                off,
                pos + 1,
                pos + 2,
            );
        }
        push(
            buf,
            &TS_FIELDS[2],
            FieldValue::U16(len as u16),
            off,
            pos + 2,
            pos + 4,
        );
        let addr_len = match (ts_type, len) {
            (TS_IPV4_ADDR_RANGE, 16) => 4,
            (TS_IPV6_ADDR_RANGE, 40) => 16,
            _ => 0,
        };
        if addr_len > 0 {
            push(
                buf,
                &TS_FIELDS[3],
                FieldValue::U16(u16_at(body, pos + 4)),
                off,
                pos + 4,
                pos + 6,
            );
            push(
                buf,
                &TS_FIELDS[4],
                FieldValue::U16(u16_at(body, pos + 6)),
                off,
                pos + 6,
                pos + 8,
            );
            for (i, fd) in [&TS_FIELDS[5], &TS_FIELDS[6]].into_iter().enumerate() {
                let at = pos + 8 + i * addr_len;
                let value = if addr_len == 4 {
                    FieldValue::Ipv4Addr(read_ipv4_addr(body, at).unwrap_or_default())
                } else {
                    FieldValue::Ipv6Addr(read_ipv6_addr(body, at).unwrap_or_default())
                };
                push(buf, fd, value, off, at, at + addr_len);
            }
        } else if len > 4 {
            push(
                buf,
                &TS_FIELDS[7],
                FieldValue::Bytes(&body[pos + 4..pos + len]),
                off,
                pos + 4,
                pos + len,
            );
        }
        buf.end_container(obj);
        pos += len;
    }
    buf.end_container(idx);
}

/// Configuration attribute value, typed for the address attributes of
/// RFC 7296, Section 3.15.1 (INTERNAL_IP4_ADDRESS / NETMASK / DNS / NBNS /
/// DHCP and INTERNAL_IP6_DNS / DHCP).
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.15.1>
fn cfg_value(attr_type: u16, data: &[u8]) -> FieldValue<'_> {
    match (attr_type, data.len()) {
        (1 | 2 | 3 | 4 | 6, 4) => FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default()),
        (10 | 12, 16) => FieldValue::Ipv6Addr(read_ipv6_addr(data, 0).unwrap_or_default()),
        _ => FieldValue::Bytes(data),
    }
}

/// RFC 7296, Section 3.15 — CFG Type (1), RESERVED (3), Configuration
/// Attributes; Section 3.15.1 — R bit + Attribute Type (15 bits), Length
/// (2), Value.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.15>
fn decode_v2_cp<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    push(buf, &f[PFD_CFG_TYPE], FieldValue::U8(body[0]), off, 0, 1);
    let idx = buf.begin_container(
        &f[PFD_CFG_ATTRIBUTES],
        FieldValue::Array(0..0),
        off + 4..off + body.len(),
    );
    let mut pos = 4;
    while pos + 4 <= body.len() {
        let attr_type = u16_at(body, pos) & 0x7fff;
        let len = u16_at(body, pos + 2) as usize;
        if pos + 4 + len > body.len() {
            break;
        }
        let obj = buf.begin_container(
            &FD_ATTRIBUTE,
            FieldValue::Object(0..0),
            off + pos..off + pos + 4 + len,
        );
        push(
            buf,
            &CFG_ATTR[AFD_TYPE],
            FieldValue::U16(attr_type),
            off,
            pos,
            pos + 2,
        );
        push(
            buf,
            &CFG_ATTR[AFD_LENGTH],
            FieldValue::U16(len as u16),
            off,
            pos + 2,
            pos + 4,
        );
        if len > 0 {
            let value = cfg_value(attr_type, &body[pos + 4..pos + 4 + len]);
            push(
                buf,
                &CFG_ATTR[AFD_VALUE],
                value,
                off,
                pos + 4,
                pos + 4 + len,
            );
        }
        buf.end_container(obj);
        pos += 4 + len;
    }
    buf.end_container(idx);
}

/// RFC 7383, Section 2.5 — Fragment Number (2), Total Fragments (2), then
/// the IV, encrypted content and ICV.
/// <https://www.rfc-editor.org/rfc/rfc7383#section-2.5>
fn decode_v2_skf<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    push(
        buf,
        &f[PFD_FRAGMENT_NUMBER],
        FieldValue::U16(u16_at(body, 0)),
        off,
        0,
        2,
    );
    push(
        buf,
        &f[PFD_TOTAL_FRAGMENTS],
        FieldValue::U16(u16_at(body, 2)),
        off,
        2,
        4,
    );
}

/// IPsec DOI (RFC 2407, Section 4.2).
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.2>
const DOI_IPSEC: u32 = 1;
/// SIT_SECRECY | SIT_INTEGRITY (RFC 2407, Section 4.6.1): when set, labeled
/// domain fields follow the Situation and the proposals cannot be located.
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.6.1>
const SIT_LABELED: u32 = 0x06;

/// RFC 2408, Section 3.4 — DOI (4), Situation (variable), Proposal payloads.
/// RFC 2407, Section 4.6.1 — the IPsec DOI Situation is 4 octets.
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.6.1>
fn decode_v1_sa<'pkt>(buf: &mut DissectBuffer<'pkt>, body: &'pkt [u8], off: usize) {
    if body.len() < 4 {
        return;
    }
    let f = PAYLOAD_CHILDREN;
    let doi = read_be_u32(body, 0).unwrap_or_default();
    push(buf, &f[PFD_DOI], FieldValue::U32(doi), off, 0, 4);
    if doi != DOI_IPSEC || body.len() < 8 {
        return;
    }
    let situation = read_be_u32(body, 4).unwrap_or_default();
    push(
        buf,
        &f[PFD_SITUATION],
        FieldValue::U32(situation),
        off,
        4,
        8,
    );
    if situation & SIT_LABELED == 0 {
        decode_sa_proposals(buf, false, body, off, 8, &V1_PROPOSALS);
    }
}

/// Transform descriptors for an IKEv1 proposal (RFC 2407, Section 4.4).
/// <https://www.rfc-editor.org/rfc/rfc2407#section-4.4>
fn v1_transform_fields(protocol_id: u8) -> &'static [FieldDescriptor; 5] {
    match protocol_id {
        1 => &TRANSFORM_V1_ISAKMP,
        2 => &TRANSFORM_V1_AH,
        3 => &TRANSFORM_V1_ESP,
        4 => &TRANSFORM_V1_IPCOMP,
        _ => &TRANSFORM_V1_OTHER,
    }
}

/// Decode the proposals of an SA payload starting at `base`.
///
/// IKEv2: Proposal Substructure (RFC 7296, Section 3.3.1) — Last Substruc
/// (1), RESERVED (1), Proposal Length (2), Proposal Num (1), Protocol ID
/// (1), SPI Size (1), Num Transforms (1), SPI, Transforms.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.1>
///
/// IKEv1: Proposal Payload (RFC 2408, Section 3.5) with the same layout,
/// the first octet being Next Payload.
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.5>
fn decode_sa_proposals<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    v2: bool,
    body: &'pkt [u8],
    off: usize,
    base: usize,
    array_fd: &'static FieldDescriptor,
) {
    let fields = if v2 { &PROPOSAL_V2 } else { &PROPOSAL_V1 };
    let idx = buf.begin_container(
        array_fd,
        FieldValue::Array(0..0),
        off + base..off + body.len(),
    );
    let mut pos = base;
    while pos + 8 <= body.len() {
        let len = u16_at(body, pos + 2) as usize;
        let spi_size = body[pos + 6] as usize;
        if len < 8 + spi_size || pos + len > body.len() {
            break;
        }
        let protocol_id = body[pos + 5];
        let obj = buf.begin_container(
            &FD_PROPOSAL,
            FieldValue::Object(0..0),
            off + pos..off + pos + len,
        );
        push(
            buf,
            &fields[PRFD_LENGTH],
            FieldValue::U16(len as u16),
            off,
            pos + 2,
            pos + 4,
        );
        push(
            buf,
            &fields[PRFD_NUMBER],
            FieldValue::U8(body[pos + 4]),
            off,
            pos + 4,
            pos + 5,
        );
        push(
            buf,
            &fields[PRFD_PROTOCOL],
            FieldValue::U8(protocol_id),
            off,
            pos + 5,
            pos + 6,
        );
        push(
            buf,
            &fields[PRFD_SPI_SIZE],
            FieldValue::U8(body[pos + 6]),
            off,
            pos + 6,
            pos + 7,
        );
        push(
            buf,
            &fields[PRFD_NUM_TRANSFORMS],
            FieldValue::U8(body[pos + 7]),
            off,
            pos + 7,
            pos + 8,
        );
        let spi_end = pos + 8 + spi_size;
        if spi_size > 0 {
            push(
                buf,
                &fields[PRFD_SPI],
                FieldValue::Bytes(&body[pos + 8..spi_end]),
                off,
                pos + 8,
                spi_end,
            );
        }
        let tfields = if v2 {
            &TRANSFORM_V2
        } else {
            v1_transform_fields(protocol_id)
        };
        decode_transforms(
            buf,
            v2,
            tfields,
            &fields[PRFD_TRANSFORMS],
            body,
            off,
            spi_end,
            pos + len,
        );
        buf.end_container(obj);
        pos += len;
    }
    buf.end_container(idx);
}

/// Decode the transforms in `body[start..end]`.
///
/// IKEv2: RFC 7296, Section 3.3.2 — Last Substruc (1), RESERVED (1),
/// Transform Length (2), Transform Type (1), RESERVED (1), Transform ID (2),
/// Transform Attributes.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.2>
///
/// IKEv1: RFC 2408, Section 3.6 — Next Payload (1), RESERVED (1), Payload
/// Length (2), Transform # (1), Transform-Id (1), RESERVED2 (2), SA
/// Attributes.
/// <https://www.rfc-editor.org/rfc/rfc2408#section-3.6>
#[allow(clippy::too_many_arguments)]
fn decode_transforms<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    v2: bool,
    tfields: &'static [FieldDescriptor; 5],
    array_fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    off: usize,
    start: usize,
    end: usize,
) {
    let idx = buf.begin_container(array_fd, FieldValue::Array(0..0), off + start..off + end);
    let mut pos = start;
    while pos + 8 <= end {
        let len = u16_at(body, pos + 2) as usize;
        if len < 8 || pos + len > end {
            break;
        }
        let obj = buf.begin_container(
            &FD_TRANSFORM,
            FieldValue::Object(0..0),
            off + pos..off + pos + len,
        );
        push(
            buf,
            &tfields[TFD_LENGTH],
            FieldValue::U16(len as u16),
            off,
            pos + 2,
            pos + 4,
        );
        if v2 {
            push(
                buf,
                &tfields[TFD_TYPE],
                FieldValue::U8(body[pos + 4]),
                off,
                pos + 4,
                pos + 5,
            );
            push(
                buf,
                &tfields[TFD_ID],
                FieldValue::U16(u16_at(body, pos + 6)),
                off,
                pos + 6,
                pos + 8,
            );
        } else {
            push(
                buf,
                &tfields[TFD_NUMBER],
                FieldValue::U8(body[pos + 4]),
                off,
                pos + 4,
                pos + 5,
            );
            let id = u16::from(body[pos + 5]);
            push(
                buf,
                &tfields[TFD_ID],
                FieldValue::U16(id),
                off,
                pos + 5,
                pos + 6,
            );
        }
        if len > 8 {
            decode_attributes(
                buf,
                v2,
                &tfields[TFD_ATTRIBUTES],
                body,
                off,
                pos + 8,
                pos + len,
            );
        }
        buf.end_container(obj);
        pos += len;
    }
    buf.end_container(idx);
}

/// Decode data attributes in `body[start..end]`.
///
/// RFC 7296, Section 3.3.5 / RFC 2408, Section 3.3 — AF bit + Attribute
/// Type (15 bits); with AF = 1 (TV) the next 2 octets are the value,
/// otherwise (TLV) a 2-octet length and the value follow.
/// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.5>
fn decode_attributes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    v2: bool,
    array_fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    off: usize,
    start: usize,
    end: usize,
) {
    // Every attributes descriptor carries its attribute field set.
    let Some(afields) = array_fd.children else {
        return;
    };
    let idx = buf.begin_container(array_fd, FieldValue::Array(0..0), off + start..off + end);
    let mut pos = start;
    while pos + 4 <= end {
        let raw = u16_at(body, pos);
        let tv = raw & 0x8000 != 0;
        let value_len = if tv {
            2
        } else {
            u16_at(body, pos + 2) as usize
        };
        let value_start = if tv { pos + 2 } else { pos + 4 };
        if value_start + value_len > end {
            break;
        }
        let obj = buf.begin_container(
            &FD_ATTRIBUTE,
            FieldValue::Object(0..0),
            off + pos..off + value_start + value_len,
        );
        push(
            buf,
            &afields[AFD_FORMAT],
            FieldValue::U8(u8::from(tv)),
            off,
            pos,
            pos + 1,
        );
        push(
            buf,
            &afields[AFD_TYPE],
            FieldValue::U16(raw & 0x7fff),
            off,
            pos,
            pos + 2,
        );
        let value = &body[value_start..value_start + value_len];
        let typed = if tv {
            FieldValue::U16(u16_at(value, 0))
        } else {
            push(
                buf,
                &afields[AFD_LENGTH],
                FieldValue::U16(value_len as u16),
                off,
                pos + 2,
                pos + 4,
            );
            // RFC 2409, Appendix A — variable length IKEv1 values such as
            // Life Duration are integers of any length.
            // <https://www.rfc-editor.org/rfc/rfc2409#appendix-A>
            match value_len {
                1..=4 if !v2 => {
                    FieldValue::U32(value.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)))
                }
                5..=8 if !v2 => {
                    FieldValue::U64(value.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
                }
                _ => FieldValue::Bytes(value),
            }
        };
        if value_len > 0 {
            push(
                buf,
                &afields[AFD_VALUE],
                typed,
                off,
                value_start,
                value_start + value_len,
            );
        }
        buf.end_container(obj);
        pos = value_start + value_len;
    }
    buf.end_container(idx);
}

#[cfg(test)]
mod tests {
    //! # RFC 7296 / RFC 2408 payload body coverage
    //!
    //! | RFC Section         | Description                          | Test                                  |
    //! |---------------------|--------------------------------------|---------------------------------------|
    //! | 7296 §3.3           | SA / Proposal / Transform / Attrs    | v2_sa_proposal_transforms             |
    //! | 7296 §3.3.1         | Proposal with SPI (ESP)              | v2_sa_esp_proposal_with_spi           |
    //! | 7296 §3.3           | Malformed proposal lengths           | v2_sa_malformed_proposal              |
    //! | 7296 §3.4           | Key Exchange                         | v2_key_exchange                       |
    //! | 7296 §3.5           | Identification (IPv4/FQDN/IPv6/other)| v2_identification                     |
    //! | 7296 §3.6-3.7       | CERT / CERTREQ                       | v2_cert_and_certreq                   |
    //! | 7296 §3.8           | Authentication                       | v2_auth                               |
    //! | 7296 §3.9           | Nonce                                | v2_nonce_and_vendor_id                |
    //! | 7296 §3.10          | Notify (NAT-D, INVALID_KE, SPI)      | v2_notify                             |
    //! | 7427 §4             | SIGNATURE_HASH_ALGORITHMS            | v2_notify_signature_hash_algorithms   |
    //! | 7296 §3.11          | Delete                               | v2_delete                             |
    //! | 7296 §3.12          | Vendor ID                            | v2_nonce_and_vendor_id                |
    //! | 7296 §3.13          | Traffic Selectors (IPv4/IPv6/other)  | v2_traffic_selectors                  |
    //! | 7296 §3.15          | Configuration                        | v2_configuration                      |
    //! | 7383 §2.5           | Encrypted Fragment (SKF)             | v2_encrypted_fragment                 |
    //! | 2408 §3.4-3.6       | IKEv1 SA / Proposal / Transform      | v1_sa_main_mode                       |
    //! | 2407 §4.5           | IKEv1 IPsec SA attributes (ESP)      | v1_sa_quick_mode_esp                  |
    //! | 2408 §3.7, 3.13     | IKEv1 KE / Nonce                     | v1_ke_nonce_id                        |
    //! | 2407 §4.6.2         | IKEv1 Identification                 | v1_ke_nonce_id                        |
    //! | 2408 §3.14          | IKEv1 Notification                   | v1_notification                       |
    //! | 2408 §3.15-3.16     | IKEv1 Delete / Vendor ID             | v1_delete_and_vendor_id               |
    //! | 7296 §3.16          | EAP payload decoded as EAP (eap)     | v2_eap_payload                        |
    //! | —                   | Truncated bodies do not panic        | truncated_bodies_do_not_panic         |

    use crate::IkeDissector;
    use core::ops::Range;
    use packet_dissector_core::dissector::Dissector;
    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::DissectBuffer;

    /// Build an IKE message of `major` version whose payload chain is
    /// `payloads` (type, body).
    fn message(major: u8, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (i, (_, b)) in payloads.iter().enumerate() {
            let next = payloads.get(i + 1).map(|p| p.0).unwrap_or(0);
            body.push(next);
            body.push(0);
            body.extend_from_slice(&((b.len() + 4) as u16).to_be_bytes());
            body.extend_from_slice(b);
        }
        let mut data = vec![0x11; 8];
        data.extend_from_slice(&[0; 8]);
        data.push(payloads.first().map(|p| p.0).unwrap_or(0));
        data.push(major << 4);
        data.push(if major == 2 { 34 } else { 2 });
        data.push(if major == 2 { 0x08 } else { 0 });
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&((28 + body.len()) as u32).to_be_bytes());
        data.extend_from_slice(&body);
        data
    }

    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut buf = DissectBuffer::new();
        IkeDissector.dissect(data, &mut buf, 0).unwrap();
        buf
    }

    /// Own (non-nested) fields of an Object or Array range.
    fn own<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, range: &Range<u32>) -> Vec<&'a Field<'pkt>> {
        let mut out = Vec::new();
        let mut idx = range.start;
        while idx < range.end {
            let f = &buf.fields()[idx as usize];
            out.push(f);
            idx = match &f.value {
                FieldValue::Array(r) | FieldValue::Object(r) => r.end,
                _ => idx + 1,
            };
        }
        out
    }

    fn get<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        r: &Range<u32>,
        name: &str,
    ) -> &'a FieldValue<'pkt> {
        &own(buf, r)
            .into_iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("field {name} not found"))
            .value
    }

    fn has(buf: &DissectBuffer<'_>, r: &Range<u32>, name: &str) -> bool {
        own(buf, r).iter().any(|f| f.name() == name)
    }

    /// Display name of the own field `name` of the Object `r`.
    fn display(buf: &DissectBuffer<'_>, r: &Range<u32>, name: &str) -> Option<&'static str> {
        let f = own(buf, r).into_iter().find(|f| f.name() == name)?;
        (f.descriptor.display_fn?)(&f.value, buf.nested_fields(r))
    }

    /// Object ranges of the Array field `name` of `r`.
    fn objects(buf: &DissectBuffer<'_>, r: &Range<u32>, name: &str) -> Vec<Range<u32>> {
        let FieldValue::Array(a) = get(buf, r, name) else {
            panic!("{name} is not an Array");
        };
        own(buf, a)
            .into_iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(o.clone()),
                _ => None,
            })
            .collect()
    }

    /// Object range of the `n`-th payload.
    fn payload(buf: &DissectBuffer<'_>, n: usize) -> Range<u32> {
        let layer = &buf.layers()[0];
        let FieldValue::Array(a) = &buf.field_by_name(layer, "payloads").unwrap().value else {
            panic!("no payloads");
        };
        let objs: Vec<_> = own(buf, a)
            .into_iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(o) => Some(o.clone()),
                _ => None,
            })
            .collect();
        objs[n].clone()
    }

    fn v2_attr_tv(t: u16, v: u16) -> Vec<u8> {
        let mut a = (0x8000 | t).to_be_bytes().to_vec();
        a.extend_from_slice(&v.to_be_bytes());
        a
    }

    /// IKEv2 transform substructure (RFC 7296, Section 3.3.2).
    /// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.2>
    fn v2_transform(last: bool, ttype: u8, id: u16, attrs: &[u8]) -> Vec<u8> {
        let mut t = vec![if last { 0 } else { 3 }, 0];
        t.extend_from_slice(&((8 + attrs.len()) as u16).to_be_bytes());
        t.push(ttype);
        t.push(0);
        t.extend_from_slice(&id.to_be_bytes());
        t.extend_from_slice(attrs);
        t
    }

    /// IKEv2 proposal substructure (RFC 7296, Section 3.3.1).
    /// <https://www.rfc-editor.org/rfc/rfc7296#section-3.3.1>
    fn v2_proposal(last: bool, num: u8, proto: u8, spi: &[u8], transforms: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = transforms.concat();
        let mut p = vec![if last { 0 } else { 2 }, 0];
        p.extend_from_slice(&((8 + spi.len() + body.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[num, proto, spi.len() as u8, transforms.len() as u8]);
        p.extend_from_slice(spi);
        p.extend_from_slice(&body);
        p
    }

    #[cfg(feature = "eap")]
    #[test]
    fn v2_eap_payload() {
        // RFC 7296, Section 3.16 — the EAP payload carries one EAP message.
        // <https://www.rfc-editor.org/rfc/rfc7296#section-3.16>
        let data = message(2, &[(48, vec![0x01, 0x05, 0x00, 0x05, 0x01])]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        let FieldValue::Object(eap) = get(&buf, &p, "eap") else {
            panic!("eap must be an Object");
        };
        assert_eq!(
            buf.resolve_nested_display_name(eap, "code_name"),
            Some("Request")
        );
        assert_eq!(
            buf.resolve_nested_display_name(eap, "type_name"),
            Some("Identity")
        );

        // A malformed EAP message keeps only the raw payload data.
        let data = message(2, &[(48, vec![0x01, 0x05, 0x00, 0x09, 0x01])]);
        let buf = dissect(&data);
        assert!(!has(&buf, &payload(&buf, 0), "eap"));
    }

    #[test]
    fn v2_sa_proposal_transforms() {
        let sa = v2_proposal(
            true,
            1,
            1,
            &[],
            &[
                v2_transform(false, 1, 12, &v2_attr_tv(14, 256)),
                v2_transform(false, 2, 5, &[]),
                v2_transform(false, 3, 12, &[]),
                v2_transform(true, 4, 31, &[]),
            ],
        );
        let data = message(2, &[(33, sa)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        let props = objects(&buf, &p, "proposals");
        assert_eq!(props.len(), 1);
        assert_eq!(*get(&buf, &props[0], "proposal_number"), FieldValue::U8(1));
        assert_eq!(*get(&buf, &props[0], "protocol_id"), FieldValue::U8(1));
        assert_eq!(display(&buf, &props[0], "protocol_id"), Some("IKE"));
        assert_eq!(*get(&buf, &props[0], "num_transforms"), FieldValue::U8(4));
        assert!(!has(&buf, &props[0], "spi"));
        let ts = objects(&buf, &props[0], "transforms");
        assert_eq!(ts.len(), 4);
        assert_eq!(
            display(&buf, &ts[0], "transform_type"),
            Some("Encryption Algorithm (ENCR)")
        );
        assert_eq!(display(&buf, &ts[0], "transform_id"), Some("ENCR_AES_CBC"));
        assert_eq!(
            display(&buf, &ts[1], "transform_id"),
            Some("PRF_HMAC_SHA2_256")
        );
        assert_eq!(
            display(&buf, &ts[2], "transform_id"),
            Some("AUTH_HMAC_SHA2_256_128")
        );
        assert_eq!(display(&buf, &ts[3], "transform_id"), Some("Curve25519"));
        let attrs = objects(&buf, &ts[0], "attributes");
        assert_eq!(attrs.len(), 1);
        assert_eq!(*get(&buf, &attrs[0], "attribute_type"), FieldValue::U16(14));
        assert_eq!(
            display(&buf, &attrs[0], "attribute_type"),
            Some("Key Length (in bits)")
        );
        assert_eq!(*get(&buf, &attrs[0], "attribute_format"), FieldValue::U8(1));
        assert_eq!(
            *get(&buf, &attrs[0], "attribute_value"),
            FieldValue::U16(256)
        );
    }

    #[test]
    fn v2_sa_esp_proposal_with_spi() {
        // TLV attribute (AF = 0) with a 3-octet value.
        let mut tlv = 18u16.to_be_bytes().to_vec();
        tlv.extend_from_slice(&3u16.to_be_bytes());
        tlv.extend_from_slice(&[1, 2, 3]);
        let sa = v2_proposal(
            true,
            1,
            3,
            &[0xde, 0xad, 0xbe, 0xef],
            &[
                v2_transform(false, 1, 20, &tlv),
                v2_transform(true, 5, 1, &[]),
            ],
        );
        let data = message(2, &[(33, sa)]);
        let buf = dissect(&data);
        let props = objects(&buf, &payload(&buf, 0), "proposals");
        assert_eq!(display(&buf, &props[0], "protocol_id"), Some("ESP"));
        assert_eq!(
            *get(&buf, &props[0], "spi"),
            FieldValue::Bytes(&[0xde, 0xad, 0xbe, 0xef])
        );
        let ts = objects(&buf, &props[0], "transforms");
        assert_eq!(
            display(&buf, &ts[1], "transform_id"),
            Some("Partially Transmitted 64-bit Sequential Numbers")
        );
        let attrs = objects(&buf, &ts[0], "attributes");
        assert_eq!(*get(&buf, &attrs[0], "attribute_format"), FieldValue::U8(0));
        assert_eq!(
            *get(&buf, &attrs[0], "attribute_length"),
            FieldValue::U16(3)
        );
        assert_eq!(
            *get(&buf, &attrs[0], "attribute_value"),
            FieldValue::Bytes(&[1, 2, 3])
        );
    }

    #[test]
    fn v2_sa_malformed_proposal() {
        // Proposal length larger than the payload: nothing decoded, no panic.
        let mut sa = v2_proposal(true, 1, 1, &[], &[v2_transform(true, 1, 12, &[])]);
        sa[2] = 0xff;
        let data = message(2, &[(33, sa)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert!(objects(&buf, &p, "proposals").is_empty());
        // Transform length too small: the proposal is kept without transforms.
        let mut sa = v2_proposal(true, 1, 1, &[], &[v2_transform(true, 1, 12, &[])]);
        sa[10] = 0;
        sa[11] = 2;
        let data = message(2, &[(33, sa)]);
        let buf = dissect(&data);
        let props = objects(&buf, &payload(&buf, 0), "proposals");
        assert!(objects(&buf, &props[0], "transforms").is_empty());
    }

    #[test]
    fn v2_key_exchange() {
        // Issue example: KE, group 31 (Curve25519), 32-byte key.
        let mut ke = vec![0x00, 0x1f, 0x00, 0x00];
        ke.extend_from_slice(&[0xab; 32]);
        let data = message(2, &[(34, ke)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(*get(&buf, &p, "dh_group"), FieldValue::U16(31));
        assert_eq!(display(&buf, &p, "dh_group"), Some("Curve25519"));
        assert_eq!(
            *get(&buf, &p, "key_exchange_data"),
            FieldValue::Bytes(&[0xab; 32])
        );
        // payload_data is kept.
        assert!(has(&buf, &p, "payload_data"));
    }

    #[test]
    fn v2_identification() {
        let data = message(
            2,
            &[
                (35, vec![1, 0, 0, 0, 192, 0, 2, 1]),
                (36, [vec![2, 0, 0, 0], b"vpn.example".to_vec()].concat()),
                (
                    35,
                    [
                        vec![5, 0, 0, 0],
                        vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    ]
                    .concat(),
                ),
                (35, vec![11, 0, 0, 0, 0xaa, 0xbb]),
                (35, vec![1, 0, 0, 0, 192, 0]),
            ],
        );
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(display(&buf, &p, "id_type"), Some("ID_IPV4_ADDR"));
        assert_eq!(
            *get(&buf, &p, "identification"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        let p = payload(&buf, 1);
        assert_eq!(
            *get(&buf, &p, "identification"),
            FieldValue::Str("vpn.example")
        );
        let p = payload(&buf, 2);
        assert!(matches!(
            get(&buf, &p, "identification"),
            FieldValue::Ipv6Addr(_)
        ));
        let p = payload(&buf, 3);
        assert_eq!(
            *get(&buf, &p, "identification"),
            FieldValue::Bytes(&[0xaa, 0xbb])
        );
        // ID_IPV4_ADDR with a wrong length stays raw.
        let p = payload(&buf, 4);
        assert_eq!(
            *get(&buf, &p, "identification"),
            FieldValue::Bytes(&[192, 0])
        );
    }

    #[test]
    fn v2_cert_and_certreq() {
        let data = message(2, &[(37, vec![4, 0x30, 0x82]), (38, vec![4, 0x11, 0x22])]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(
            display(&buf, &p, "cert_encoding"),
            Some("X.509 Certificate - Signature")
        );
        assert_eq!(
            *get(&buf, &p, "certificate_data"),
            FieldValue::Bytes(&[0x30, 0x82])
        );
        let p = payload(&buf, 1);
        assert_eq!(
            *get(&buf, &p, "certificate_data"),
            FieldValue::Bytes(&[0x11, 0x22])
        );
    }

    #[test]
    fn v2_auth() {
        let data = message(2, &[(39, vec![2, 0, 0, 0, 1, 2, 3, 4])]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(
            display(&buf, &p, "auth_method"),
            Some("Shared Key Message Integrity Code")
        );
        assert_eq!(
            *get(&buf, &p, "authentication_data"),
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
    }

    #[test]
    fn v2_nonce_and_vendor_id() {
        let data = message(2, &[(40, vec![7; 16]), (43, b"strongSwan".to_vec())]);
        let buf = dissect(&data);
        assert_eq!(
            *get(&buf, &payload(&buf, 0), "nonce"),
            FieldValue::Bytes(&[7; 16])
        );
        assert_eq!(
            *get(&buf, &payload(&buf, 1), "vendor_id"),
            FieldValue::Bytes(b"strongSwan")
        );
    }

    #[test]
    fn v2_notify() {
        let mut natd = vec![0, 0];
        natd.extend_from_slice(&16388u16.to_be_bytes());
        natd.extend_from_slice(&[0x5a; 20]);
        let mut invalid_ke = vec![0, 0];
        invalid_ke.extend_from_slice(&17u16.to_be_bytes());
        invalid_ke.extend_from_slice(&19u16.to_be_bytes());
        let mut rekey = vec![3, 4];
        rekey.extend_from_slice(&16393u16.to_be_bytes());
        rekey.extend_from_slice(&[1, 2, 3, 4]);
        let data = message(2, &[(41, natd), (41, invalid_ke), (41, rekey)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(*get(&buf, &p, "notify_type"), FieldValue::U16(16388));
        assert_eq!(
            display(&buf, &p, "notify_type"),
            Some("NAT_DETECTION_SOURCE_IP")
        );
        assert_eq!(
            *get(&buf, &p, "notification_data"),
            FieldValue::Bytes(&[0x5a; 20])
        );
        assert!(!has(&buf, &p, "spi"));
        let p = payload(&buf, 1);
        assert_eq!(display(&buf, &p, "notify_type"), Some("INVALID_KE_PAYLOAD"));
        assert_eq!(*get(&buf, &p, "dh_group"), FieldValue::U16(19));
        let p = payload(&buf, 2);
        assert_eq!(display(&buf, &p, "protocol_id"), Some("ESP"));
        assert_eq!(*get(&buf, &p, "spi"), FieldValue::Bytes(&[1, 2, 3, 4]));
        assert_eq!(display(&buf, &p, "notify_type"), Some("REKEY_SA"));
    }

    #[test]
    fn v2_notify_signature_hash_algorithms() {
        let mut n = vec![0, 0];
        n.extend_from_slice(&16431u16.to_be_bytes());
        n.extend_from_slice(&[0, 2, 0, 3, 0, 4]);
        let data = message(2, &[(41, n)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        let FieldValue::Array(a) = get(&buf, &p, "hash_algorithms") else {
            panic!("hash_algorithms");
        };
        let items = own(&buf, a);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, FieldValue::U16(2));
        assert_eq!(
            (items[0].descriptor.display_fn.unwrap())(&items[0].value, &[]),
            Some("SHA2-256")
        );
    }

    #[test]
    fn v2_delete() {
        let mut d = vec![3, 4];
        d.extend_from_slice(&2u16.to_be_bytes());
        d.extend_from_slice(&[1, 1, 1, 1, 2, 2, 2, 2]);
        let data = message(2, &[(42, d)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(display(&buf, &p, "protocol_id"), Some("ESP"));
        assert_eq!(*get(&buf, &p, "num_spis"), FieldValue::U16(2));
        let FieldValue::Array(a) = get(&buf, &p, "spis") else {
            panic!("spis");
        };
        let spis = own(&buf, a);
        assert_eq!(spis.len(), 2);
        assert_eq!(spis[1].value, FieldValue::Bytes(&[2, 2, 2, 2]));

        // Num of SPIs = 0 with trailing octets: no SPIs container.
        let data = message(2, &[(42, vec![3, 4, 0, 0, 1, 2])]);
        let buf = dissect(&data);
        assert!(!has(&buf, &payload(&buf, 0), "spis"));
    }

    #[test]
    fn v2_traffic_selectors() {
        let mut ts = vec![3, 0, 0, 0];
        // TS_IPV4_ADDR_RANGE, TCP, 0-65535, 10.0.0.0-10.0.0.255
        ts.extend_from_slice(&[7, 6, 0, 16, 0, 0, 0xff, 0xff, 10, 0, 0, 0, 10, 0, 0, 255]);
        // TS_IPV6_ADDR_RANGE, any
        ts.extend_from_slice(&[8, 0, 0, 40, 0, 0, 0xff, 0xff]);
        ts.extend_from_slice(&[0; 16]);
        ts.extend_from_slice(&[0xff; 16]);
        // TS_SECLABEL (10): raw selector data
        ts.extend_from_slice(&[10, 0, 0, 6, 0xaa, 0xbb]);
        let data = message(2, &[(44, ts)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(*get(&buf, &p, "num_ts"), FieldValue::U8(3));
        let sels = objects(&buf, &p, "traffic_selectors");
        assert_eq!(sels.len(), 3);
        assert_eq!(
            display(&buf, &sels[0], "ts_type"),
            Some("TS_IPV4_ADDR_RANGE")
        );
        assert_eq!(display(&buf, &sels[0], "ip_protocol"), Some("TCP"));
        assert_eq!(*get(&buf, &sels[0], "end_port"), FieldValue::U16(0xffff));
        assert_eq!(
            *get(&buf, &sels[0], "starting_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 0])
        );
        assert_eq!(
            *get(&buf, &sels[0], "ending_address"),
            FieldValue::Ipv4Addr([10, 0, 0, 255])
        );
        assert_eq!(
            *get(&buf, &sels[1], "ending_address"),
            FieldValue::Ipv6Addr([0xff; 16])
        );
        assert_eq!(
            *get(&buf, &sels[2], "selector_data"),
            FieldValue::Bytes(&[0xaa, 0xbb])
        );
        // TS_SECLABEL has no IP Protocol ID.
        assert!(!has(&buf, &sels[2], "ip_protocol"));
    }

    #[test]
    fn v2_configuration() {
        let mut cp = vec![1, 0, 0, 0];
        cp.extend_from_slice(&[0, 1, 0, 0]); // INTERNAL_IP4_ADDRESS, empty
        cp.extend_from_slice(&[0, 3, 0, 4, 8, 8, 8, 8]); // INTERNAL_IP4_DNS
        cp.extend_from_slice(&[0, 7, 0, 2, 1, 2]); // APPLICATION_VERSION
        let data = message(2, &[(47, cp)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(display(&buf, &p, "cfg_type"), Some("CFG_REQUEST"));
        let attrs = objects(&buf, &p, "attributes");
        assert_eq!(attrs.len(), 3);
        assert_eq!(
            display(&buf, &attrs[0], "attribute_type"),
            Some("INTERNAL_IP4_ADDRESS")
        );
        assert!(!has(&buf, &attrs[0], "attribute_value"));
        assert_eq!(
            display(&buf, &attrs[1], "attribute_type"),
            Some("INTERNAL_IP4_DNS")
        );
        assert_eq!(
            *get(&buf, &attrs[1], "attribute_value"),
            FieldValue::Ipv4Addr([8, 8, 8, 8])
        );
        assert_eq!(
            *get(&buf, &attrs[2], "attribute_value"),
            FieldValue::Bytes(&[1, 2])
        );
    }

    #[test]
    fn v2_encrypted_fragment() {
        let data = message(2, &[(53, vec![0, 2, 0, 5, 0xee, 0xee])]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(*get(&buf, &p, "fragment_number"), FieldValue::U16(2));
        assert_eq!(*get(&buf, &p, "total_fragments"), FieldValue::U16(5));
    }

    /// IKEv1 transform payload (RFC 2408, Section 3.6).
    /// <https://www.rfc-editor.org/rfc/rfc2408#section-3.6>
    fn v1_transform(last: bool, num: u8, id: u8, attrs: &[u8]) -> Vec<u8> {
        let mut t = vec![if last { 0 } else { 3 }, 0];
        t.extend_from_slice(&((8 + attrs.len()) as u16).to_be_bytes());
        t.extend_from_slice(&[num, id, 0, 0]);
        t.extend_from_slice(attrs);
        t
    }

    /// IKEv1 SA payload body with one proposal (RFC 2408, Sections 3.4-3.5).
    /// <https://www.rfc-editor.org/rfc/rfc2408#section-3.4>
    fn v1_sa(proto: u8, spi: &[u8], transforms: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = transforms.concat();
        let mut sa = 1u32.to_be_bytes().to_vec(); // DOI IPSEC
        sa.extend_from_slice(&1u32.to_be_bytes()); // SIT_IDENTITY_ONLY
        sa.extend_from_slice(&[0, 0]);
        sa.extend_from_slice(&((8 + spi.len() + body.len()) as u16).to_be_bytes());
        sa.extend_from_slice(&[1, proto, spi.len() as u8, transforms.len() as u8]);
        sa.extend_from_slice(spi);
        sa.extend_from_slice(&body);
        sa
    }

    #[test]
    fn v1_sa_main_mode() {
        let mut attrs = Vec::new();
        attrs.extend(v2_attr_tv(1, 7)); // Encryption: AES-CBC
        attrs.extend(v2_attr_tv(2, 2)); // Hash: SHA
        attrs.extend(v2_attr_tv(3, 1)); // Auth: pre-shared key
        attrs.extend(v2_attr_tv(4, 2)); // Group 2
        attrs.extend(v2_attr_tv(11, 1)); // Life Type: seconds
        attrs.extend_from_slice(&[0, 12, 0, 4, 0, 0, 0x70, 0x80]); // Life Duration 28800
        attrs.extend_from_slice(&[0, 12, 0, 2, 0x70, 0x80]); // 2-octet Life Duration
        attrs.extend_from_slice(&[0, 12, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0]); // 8-octet
        attrs.extend_from_slice(&[0, 16, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]); // 9-octet: raw
        let sa = v1_sa(1, &[], &[v1_transform(true, 1, 1, &attrs)]);
        let data = message(1, &[(1, sa)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(display(&buf, &p, "doi"), Some("IPSEC"));
        assert_eq!(*get(&buf, &p, "situation"), FieldValue::U32(1));
        let props = objects(&buf, &p, "proposals");
        assert_eq!(
            display(&buf, &props[0], "protocol_id"),
            Some("PROTO_ISAKMP")
        );
        let ts = objects(&buf, &props[0], "transforms");
        assert_eq!(*get(&buf, &ts[0], "transform_number"), FieldValue::U8(1));
        assert_eq!(display(&buf, &ts[0], "transform_id"), Some("KEY_IKE"));
        let a = objects(&buf, &ts[0], "attributes");
        assert_eq!(a.len(), 9);
        assert_eq!(*get(&buf, &a[6], "attribute_value"), FieldValue::U32(28800));
        assert_eq!(
            *get(&buf, &a[7], "attribute_value"),
            FieldValue::U64(1 << 32)
        );
        assert!(matches!(
            get(&buf, &a[8], "attribute_value"),
            FieldValue::Bytes(_)
        ));
        assert_eq!(
            display(&buf, &a[0], "attribute_type"),
            Some("Encryption Algorithm")
        );
        assert_eq!(display(&buf, &a[0], "attribute_value"), Some("AES-CBC"));
        assert_eq!(display(&buf, &a[1], "attribute_value"), Some("SHA"));
        assert_eq!(
            display(&buf, &a[2], "attribute_value"),
            Some("pre-shared key")
        );
        assert_eq!(
            display(&buf, &a[3], "attribute_value"),
            Some("alternate 1024-bit MODP group")
        );
        assert_eq!(display(&buf, &a[4], "attribute_value"), Some("seconds"));
        assert_eq!(
            display(&buf, &a[5], "attribute_type"),
            Some("Life Duration")
        );
        assert_eq!(*get(&buf, &a[5], "attribute_value"), FieldValue::U32(28800));
    }

    #[test]
    fn v1_sa_quick_mode_esp() {
        let mut attrs = Vec::new();
        attrs.extend(v2_attr_tv(4, 1)); // Encapsulation Mode: Tunnel
        attrs.extend(v2_attr_tv(5, 2)); // Authentication Algorithm: HMAC-SHA
        let sa = v1_sa(3, &[9, 9, 9, 9], &[v1_transform(true, 1, 12, &attrs)]);
        let data = message(1, &[(1, sa)]);
        let buf = dissect(&data);
        let props = objects(&buf, &payload(&buf, 0), "proposals");
        assert_eq!(
            display(&buf, &props[0], "protocol_id"),
            Some("PROTO_IPSEC_ESP")
        );
        assert_eq!(
            *get(&buf, &props[0], "spi"),
            FieldValue::Bytes(&[9, 9, 9, 9])
        );
        let ts = objects(&buf, &props[0], "transforms");
        assert_eq!(display(&buf, &ts[0], "transform_id"), Some("ESP_AES-CBC"));
        let a = objects(&buf, &ts[0], "attributes");
        assert_eq!(
            display(&buf, &a[0], "attribute_type"),
            Some("Encapsulation Mode")
        );
        assert_eq!(display(&buf, &a[0], "attribute_value"), Some("Tunnel"));
        assert_eq!(display(&buf, &a[1], "attribute_value"), Some("HMAC-SHA"));
    }

    #[test]
    fn v1_ke_nonce_id() {
        let data = message(
            1,
            &[
                (4, vec![0x42; 8]),
                (10, vec![0x24; 16]),
                (5, vec![1, 17, 0x01, 0xf4, 192, 0, 2, 1]),
            ],
        );
        let buf = dissect(&data);
        assert_eq!(
            *get(&buf, &payload(&buf, 0), "key_exchange_data"),
            FieldValue::Bytes(&[0x42; 8])
        );
        assert_eq!(
            *get(&buf, &payload(&buf, 1), "nonce"),
            FieldValue::Bytes(&[0x24; 16])
        );
        let p = payload(&buf, 2);
        assert_eq!(display(&buf, &p, "id_type"), Some("ID_IPV4_ADDR"));
        assert_eq!(*get(&buf, &p, "id_protocol_id"), FieldValue::U8(17));
        assert_eq!(*get(&buf, &p, "id_port"), FieldValue::U16(500));
        assert_eq!(
            *get(&buf, &p, "identification"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
    }

    #[test]
    fn v1_notification() {
        let mut n = 1u32.to_be_bytes().to_vec();
        n.extend_from_slice(&[1, 16]);
        n.extend_from_slice(&24578u16.to_be_bytes());
        n.extend_from_slice(&[0x33; 16]);
        let mut e = 1u32.to_be_bytes().to_vec();
        e.extend_from_slice(&[1, 0]);
        e.extend_from_slice(&14u16.to_be_bytes());
        let data = message(1, &[(11, n), (11, e)]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(display(&buf, &p, "doi"), Some("IPSEC"));
        assert_eq!(display(&buf, &p, "notify_type"), Some("INITIAL-CONTACT"));
        assert_eq!(*get(&buf, &p, "spi"), FieldValue::Bytes(&[0x33; 16]));
        let p = payload(&buf, 1);
        assert_eq!(display(&buf, &p, "notify_type"), Some("NO-PROPOSAL-CHOSEN"));
    }

    #[test]
    fn v1_delete_and_vendor_id() {
        let mut d = 1u32.to_be_bytes().to_vec();
        d.extend_from_slice(&[3, 4]);
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&[5, 6, 7, 8]);
        let data = message(1, &[(12, d), (13, vec![0xaf; 16])]);
        let buf = dissect(&data);
        let p = payload(&buf, 0);
        assert_eq!(display(&buf, &p, "protocol_id"), Some("PROTO_IPSEC_ESP"));
        assert_eq!(*get(&buf, &p, "num_spis"), FieldValue::U16(1));
        assert_eq!(
            *get(&buf, &payload(&buf, 1), "vendor_id"),
            FieldValue::Bytes(&[0xaf; 16])
        );
    }

    #[test]
    fn truncated_bodies_do_not_panic() {
        // Every payload type with every body length up to 12 octets.
        for major in [1u8, 2] {
            for ptype in (1..=21).chain(33..=54) {
                for len in 0..12 {
                    let body: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
                    let data = message(major, &[(ptype, body)]);
                    let mut buf = DissectBuffer::new();
                    IkeDissector.dissect(&data, &mut buf, 0).unwrap();
                }
            }
        }
    }
}
