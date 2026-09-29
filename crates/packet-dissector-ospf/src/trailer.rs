//! Data appended after the OSPF packet (outside `packet_length`): the
//! OSPFv2 cryptographic digest, the LLS data block, and the OSPFv3
//! Authentication Trailer.
//!
//! ## References
//! - RFC 2328, Appendix D.3: <https://www.rfc-editor.org/rfc/rfc2328#appendix-D.3>
//! - RFC 5613, Section 2: <https://www.rfc-editor.org/rfc/rfc5613#section-2>
//! - RFC 7166, Section 4.1: <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u64};

use crate::tlv::{TLVS_DESCRIPTOR, TlvContext, UNPARSED_DESCRIPTOR, push_tlvs};

/// LLS data block header size (Checksum + LLS Data Length).
///
/// RFC 5613, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc5613#section-2.2>
const LLS_HEADER_SIZE: usize = 4;

/// Fixed part of the OSPFv3 Authentication Trailer.
///
/// RFC 7166, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>
/// "including both the 16-octet fixed header and the variable-length
/// message digest"
const AUTH_TRAILER_HEADER_SIZE: usize = 16;

/// Field descriptor indices for [`LLS_FIELDS`].
const FD_LLS_CHECKSUM: usize = 0;
const FD_LLS_DATA_LENGTH: usize = 1;

/// Child fields of the `lls` object.
static LLS_FIELDS: [FieldDescriptor; 4] = [
    FieldDescriptor::new("checksum", "Checksum", FieldType::U16),
    FieldDescriptor::new("lls_data_length", "LLS Data Length", FieldType::U16),
    TLVS_DESCRIPTOR,
    UNPARSED_DESCRIPTOR,
];

/// Descriptor for the LLS data block object.
pub(crate) const LLS_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("lls", "LLS Data Block", FieldType::Object)
        .optional()
        .with_children(&LLS_FIELDS);

/// Field descriptor indices for [`AUTH_TRAILER_FIELDS`].
const FD_AT_AUTH_TYPE: usize = 0;
const FD_AT_AUTH_DATA_LEN: usize = 1;
const FD_AT_SA_ID: usize = 2;
const FD_AT_CRYPTO_SEQUENCE_NUMBER: usize = 3;
const FD_AT_AUTH_DATA: usize = 4;

/// Child fields of the OSPFv3 `auth_trailer` object.
static AUTH_TRAILER_FIELDS: [FieldDescriptor; 5] = [
    FieldDescriptor::new("auth_type", "Authentication Type", FieldType::U16).with_display_fn(
        |v, _| match v {
            // RFC 7166, Section 4.1: "1 - HMAC Cryptographic Authentication"
            // <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>
            FieldValue::U16(1) => Some("HMAC Cryptographic Authentication"),
            _ => None,
        },
    ),
    FieldDescriptor::new("auth_data_len", "Auth Data Len", FieldType::U16),
    FieldDescriptor::new("sa_id", "Security Association ID", FieldType::U16),
    FieldDescriptor::new(
        "crypto_sequence_number",
        "Cryptographic Sequence Number",
        FieldType::U64,
    ),
    FieldDescriptor::new("auth_data", "Authentication Data", FieldType::Bytes),
];

/// Descriptor for the OSPFv3 Authentication Trailer object.
pub(crate) const AUTH_TRAILER_DESCRIPTOR: FieldDescriptor =
    FieldDescriptor::new("auth_trailer", "Authentication Trailer", FieldType::Object)
        .optional()
        .with_children(&AUTH_TRAILER_FIELDS);

/// Pushes the LLS data block at the start of `data`, if one fits.
///
/// Returns the number of octets consumed (0 when the block is absent or its
/// declared length overruns `data`).
///
/// RFC 5613, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc5613#section-2.2>
/// "The 16-bit LLS Data Length field contains the length (in 32-bit
/// words) of the LLS block including the header and payload."
pub(crate) fn push_lls<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    descriptor: &'static FieldDescriptor,
) -> usize {
    let Ok(words) = read_be_u16(data, 2) else {
        return 0;
    };
    let len = words as usize * 4;
    if len < LLS_HEADER_SIZE || len > data.len() {
        return 0;
    }
    let idx = buf.begin_container(descriptor, FieldValue::Object(0..0), offset..offset + len);
    buf.push_field(
        &LLS_FIELDS[FD_LLS_CHECKSUM],
        FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        offset..offset + 2,
    );
    buf.push_field(
        &LLS_FIELDS[FD_LLS_DATA_LENGTH],
        FieldValue::U16(words),
        offset + 2..offset + 4,
    );
    push_tlvs(
        buf,
        &data[LLS_HEADER_SIZE..len],
        offset + LLS_HEADER_SIZE,
        TlvContext::Lls,
    );
    buf.end_container(idx);
    len
}

/// Returns the length of an OSPFv3 Authentication Trailer at the start of
/// `data`, or `None` if the fixed part does not fit or its Auth Data Len is
/// inconsistent.
///
/// RFC 7166, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>
pub(crate) fn auth_trailer_len(data: &[u8]) -> Option<usize> {
    if data.len() < AUTH_TRAILER_HEADER_SIZE {
        return None;
    }
    let len = read_be_u16(data, 2).ok()? as usize;
    (AUTH_TRAILER_HEADER_SIZE..=data.len())
        .contains(&len)
        .then_some(len)
}

/// Pushes an OSPFv3 Authentication Trailer of `len` octets (as returned by
/// [`auth_trailer_len`]).
///
/// RFC 7166, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc7166#section-4.1>
pub(crate) fn push_auth_trailer<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    len: usize,
    offset: usize,
    descriptor: &'static FieldDescriptor,
) {
    let idx = buf.begin_container(descriptor, FieldValue::Object(0..0), offset..offset + len);
    buf.push_field(
        &AUTH_TRAILER_FIELDS[FD_AT_AUTH_TYPE],
        FieldValue::U16(read_be_u16(data, 0).unwrap_or_default()),
        offset..offset + 2,
    );
    buf.push_field(
        &AUTH_TRAILER_FIELDS[FD_AT_AUTH_DATA_LEN],
        FieldValue::U16(len as u16),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &AUTH_TRAILER_FIELDS[FD_AT_SA_ID],
        FieldValue::U16(read_be_u16(data, 6).unwrap_or_default()),
        offset + 6..offset + 8,
    );
    buf.push_field(
        &AUTH_TRAILER_FIELDS[FD_AT_CRYPTO_SEQUENCE_NUMBER],
        FieldValue::U64(read_be_u64(data, 8).unwrap_or_default()),
        offset + 8..offset + 16,
    );
    buf.push_field(
        &AUTH_TRAILER_FIELDS[FD_AT_AUTH_DATA],
        FieldValue::Bytes(&data[AUTH_TRAILER_HEADER_SIZE..len]),
        offset + AUTH_TRAILER_HEADER_SIZE..offset + len,
    );
    buf.end_container(idx);
}
