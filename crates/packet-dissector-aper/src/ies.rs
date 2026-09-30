//! Decoders for the IE types that XnAP, F1AP and E1AP define identically
//! (up to the names of their components): constrained integers,
//! ENUMERATED values, PrintableString names, OCTET STRING containers,
//! `Cause`, `PLMN-Identity` / `NR-CGI` and the GTP tunnel endpoint of the
//! UP transport layer information.
//!
//! Each `push_*` function decodes a complete IE value (an open type) and
//! returns `false`, without pushing anything, when the value is malformed;
//! the caller then keeps the raw value.
//!
//! ## References
//! - ITU-T Rec. X.691 (02/2021): <https://www.itu.int/rec/T-REC-X.691>
//! - 3GPP TS 38.423 (XnAP), Section 9.3.5:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.423/>
//! - 3GPP TS 38.473 (F1AP), Section 9.4.5:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.473/>
//! - 3GPP TS 37.483 (E1AP), Section 9.4.5:
//!   <https://www.3gpp.org/ftp/Specs/archive/37_series/37.483/>
//! - 3GPP TS 38.414 (NG-U transport), Section 5.1:
//!   <https://www.3gpp.org/ftp/Specs/archive/38_series/38.414/>

use core::ops::Range;

use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::helpers::{
    ensure_consumed, read_aligned_octets, read_bit_string_field, read_sequence_preamble, shift,
    skip_protocol_ie_single_container, skip_sequence_tail,
};
use crate::reader::AperReader;

// ── Field descriptors ──────────────────────────────────────────────────

/// `cause_group` — the Cause CHOICE index.
pub static FD_CAUSE_GROUP: FieldDescriptor =
    FieldDescriptor::new("cause_group", "Cause Group", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(g) => Some(cause_group_name(*g)),
            _ => None,
        },
    );

/// `cause_value` — the ENUMERATED value of the Cause group.
pub static FD_CAUSE_VALUE: FieldDescriptor =
    FieldDescriptor::new("cause_value", "Cause Value", FieldType::U8).optional();

/// `plmn_identity` — raw `PLMN-Identity` octets.
pub static FD_PLMN_IDENTITY: FieldDescriptor =
    FieldDescriptor::new("plmn_identity", "PLMN Identity", FieldType::Bytes);

/// `nr_cell_identity` — the 36-bit NR cell identity.
pub static FD_NR_CELL_IDENTITY: FieldDescriptor =
    FieldDescriptor::new("nr_cell_identity", "NR Cell Identity", FieldType::U64);

/// `up_tnl_choice` — the UP transport layer information CHOICE index.
pub static FD_UP_TNL_CHOICE: FieldDescriptor = FieldDescriptor::new(
    "up_tnl_choice",
    "UP Transport Layer Information Choice",
    FieldType::U8,
)
.with_display_fn(|v, _| match v {
    FieldValue::U8(0) => Some("gTPTunnel"),
    FieldValue::U8(_) => Some("choice-extension"),
    _ => None,
});

/// `ipv4_address` of a transport layer address.
pub static FD_IPV4_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv4_address", "IPv4 Address", FieldType::Ipv4Addr).optional();

/// `ipv6_address` of a transport layer address.
pub static FD_IPV6_ADDRESS: FieldDescriptor =
    FieldDescriptor::new("ipv6_address", "IPv6 Address", FieldType::Ipv6Addr).optional();

/// Raw transport layer address of any other length.
pub static FD_TRANSPORT_LAYER_ADDRESS: FieldDescriptor = FieldDescriptor::new(
    "transport_layer_address",
    "Transport Layer Address",
    FieldType::Bytes,
)
.optional();

/// `gtp_teid` — the GTP-U tunnel endpoint identifier.
pub static FD_GTP_TEID: FieldDescriptor =
    FieldDescriptor::new("gtp_teid", "GTP-TEID", FieldType::U32).optional();

/// Returns a human-readable name for the Cause CHOICE index.
///
/// XnAP, F1AP and E1AP all define `Cause ::= CHOICE { radioNetwork,
/// transport, protocol, misc, choice-extension }` (3GPP TS 38.423, Section
/// 9.3.5; TS 38.473, Section 9.4.5; TS 37.483, Section 9.4.5).
pub fn cause_group_name(group: u8) -> &'static str {
    match group {
        0 => "radioNetwork",
        1 => "transport",
        2 => "protocol",
        3 => "misc",
        4 => "choice-extension",
        _ => "Unknown",
    }
}

// ── Scalars ────────────────────────────────────────────────────────────

/// Decodes `INTEGER (0..ub)` and pushes it as `desc`, whose field type
/// (U8, U16, U32 or U64) must hold `ub`.
///
/// ITU-T Rec. X.691, Section 11.5.7 (constrained whole number: a
/// bit-field, one or two octet-aligned octets, or the indefinite length
/// case above 64K).
pub fn push_unsigned<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    ub: u64,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mut r = AperReader::new(data);
    let Ok(value) = r.read_constrained_whole_number(0, ub) else {
        return false;
    };
    if ensure_consumed(&r, data).is_err() {
        return false;
    }
    let value = match desc.field_type {
        FieldType::U8 => u8::try_from(value).ok().map(FieldValue::U8),
        FieldType::U16 => u16::try_from(value).ok().map(FieldValue::U16),
        FieldType::U32 => u32::try_from(value).ok().map(FieldValue::U32),
        FieldType::U64 => Some(FieldValue::U64(value)),
        _ => None,
    };
    let Some(value) = value else {
        return false;
    };
    buf.push_field(desc, value, shift(r.byte_range_since(0), offset));
    true
}

/// Decodes `INTEGER (0..ub, ...)` (an extensible constraint) and pushes
/// it as `desc` (U8, U16 or U32).
///
/// ITU-T Rec. X.691, Section 13.2.6: an extension bit, then the root value
/// as a constrained whole number, or, for a value outside the root, an
/// unconstrained whole number (Section 11.8: an octet-aligned length
/// determinant, then the two's-complement octets). Negative extension
/// values are not decoded.
pub fn push_extensible_unsigned<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    ub: u64,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let decode = || -> Result<u64, PacketError> {
        let mut r = AperReader::new(data);
        let value = read_extensible_integer(&mut r, 0, ub)?;
        ensure_consumed(&r, data)?;
        Ok(value)
    };
    let Ok(value) = decode() else {
        return false;
    };
    let value = match desc.field_type {
        FieldType::U8 => u8::try_from(value).ok().map(FieldValue::U8),
        FieldType::U16 => u16::try_from(value).ok().map(FieldValue::U16),
        FieldType::U32 => u32::try_from(value).ok().map(FieldValue::U32),
        _ => None,
    };
    let Some(value) = value else {
        return false;
    };
    buf.push_field(desc, value, offset..offset + data.len());
    true
}

/// Reads `INTEGER (lb..ub, ...)` at the reader's position (see
/// [`push_extensible_unsigned`]).
pub fn read_extensible_integer(
    r: &mut AperReader<'_>,
    lb: u64,
    ub: u64,
) -> Result<u64, PacketError> {
    if !r.read_bit()? {
        return r.read_constrained_whole_number(lb, ub);
    }
    let len = r.read_length(0, None)?;
    if !(1..=8).contains(&len) {
        return Err(PacketError::InvalidHeader(
            "INTEGER extension value length unsupported",
        ));
    }
    let octets = r.read_octets(len as usize)?;
    if octets[0] & 0x80 != 0 {
        return Err(PacketError::InvalidHeader("negative INTEGER value"));
    }
    Ok(octets
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// Decodes an ENUMERATED value with `root_count` root values and pushes
/// its index in the full enumeration list (extension values follow the
/// root) as the U8 field `desc`.
///
/// ITU-T Rec. X.691, Section 14.
pub fn push_enumerated<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    root_count: u64,
    extensible: bool,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let mut r = AperReader::new(data);
    let Some(value) = r
        .read_enumerated(root_count, extensible)
        .ok()
        .and_then(|v| u8::try_from(v).ok())
    else {
        return false;
    };
    if ensure_consumed(&r, data).is_err() {
        return false;
    }
    buf.push_field(
        desc,
        FieldValue::U8(value),
        shift(r.byte_range_since(0), offset),
    );
    true
}

/// Decodes `PrintableString (SIZE (lb..ub, ...))` and pushes it as the Str
/// field `desc`.
///
/// ITU-T Rec. X.691, Section 30.5: an extension bit for the size
/// constraint, the length (a constrained whole number in the root, an
/// unconstrained length determinant otherwise), then the characters as
/// octet-aligned 8-bit values (the effective size constraint exceeds two
/// characters). PrintableString characters are ASCII (ITU-T Rec. X.680,
/// Section 41.4), so a value that is not valid UTF-8 is not decoded.
pub fn push_printable_string<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    lb: u64,
    ub: u64,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let decode = || -> Result<(&'pkt [u8], Range<usize>), PacketError> {
        let mut r = AperReader::new(data);
        let len = if r.read_bit()? {
            r.read_length(0, None)?
        } else {
            r.read_length(lb, Some(ub))?
        };
        let chars = read_aligned_octets(&mut r, len as usize)?;
        ensure_consumed(&r, data)?;
        Ok(chars)
    };
    let Ok((chars, range)) = decode() else {
        return false;
    };
    let Ok(s) = core::str::from_utf8(chars) else {
        return false;
    };
    buf.push_field(desc, FieldValue::Str(s), shift(range, offset));
    true
}

/// Decodes an OCTET STRING without size constraint (e.g. an RRC
/// container) and pushes its contents as the Bytes field `desc`.
///
/// ITU-T Rec. X.691, Section 17.8: an unconstrained length determinant,
/// then the octet-aligned contents.
pub fn push_octet_string<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let decode = || -> Result<(&'pkt [u8], Range<usize>), PacketError> {
        let mut r = AperReader::new(data);
        let len = r.read_length(0, None)?;
        let octets = read_aligned_octets(&mut r, len as usize)?;
        ensure_consumed(&r, data)?;
        Ok(octets)
    };
    let Ok((octets, range)) = decode() else {
        return false;
    };
    buf.push_field(desc, FieldValue::Bytes(octets), shift(range, offset));
    true
}

// ── Structured values ──────────────────────────────────────────────────

/// Pushes the Object `desc` holding the fields that `f` pushes while
/// reading from `r`; the object's range covers the octets `f` read.
pub fn push_object<'pkt, F>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    r: &mut AperReader<'pkt>,
    offset: usize,
    f: F,
) -> Result<(), PacketError>
where
    F: FnOnce(&mut DissectBuffer<'pkt>, &mut AperReader<'pkt>) -> Result<(), PacketError>,
{
    let start = r.bit_position();
    let idx = buf.begin_container(desc, FieldValue::Object(0..0), offset..offset);
    f(buf, r)?;
    if let Some(field) = buf.field_mut(idx as usize) {
        field.range = shift(r.byte_range_since(start), offset);
    }
    buf.end_container(idx);
    Ok(())
}

/// Reads a `SEQUENCE (SIZE (lb..ub)) OF` and pushes it as the Array
/// `desc`, calling `item` once per element.
///
/// ITU-T Rec. X.691, Section 20.6: the count is a constrained length
/// (Section 11.9.4.1); the elements follow without padding.
pub fn push_sequence_of<'pkt, F>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    r: &mut AperReader<'pkt>,
    offset: usize,
    lb: u64,
    ub: u64,
    mut item: F,
) -> Result<(), PacketError>
where
    F: FnMut(&mut DissectBuffer<'pkt>, &mut AperReader<'pkt>) -> Result<(), PacketError>,
{
    let start = r.bit_position();
    let idx = buf.begin_container(desc, FieldValue::Array(0..0), offset..offset);
    let count = r.read_length(lb, Some(ub))?;
    for _ in 0..count {
        item(buf, r)?;
    }
    if let Some(field) = buf.field_mut(idx as usize) {
        field.range = shift(r.byte_range_since(start), offset);
    }
    buf.end_container(idx);
    Ok(())
}

/// Decodes a complete IE value with `f`; on any error the fields pushed
/// so far are removed and `false` is returned, so that the caller keeps
/// the raw value.
pub fn push_value_with<'pkt, F>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], f: F) -> bool
where
    F: FnOnce(&mut DissectBuffer<'pkt>, &mut AperReader<'pkt>) -> Result<(), PacketError>,
{
    let mark = buf.field_count() as usize;
    let mut r = AperReader::new(data);
    let ok = f(buf, &mut r).is_ok() && ensure_consumed(&r, data).is_ok();
    if !ok {
        buf.truncate_fields(mark);
    }
    ok
}

/// Reads an `INTEGER (lb..ub, ...)` and pushes it as the U8 field `desc`.
pub fn push_small_integer(
    buf: &mut DissectBuffer<'_>,
    desc: &'static FieldDescriptor,
    r: &mut AperReader<'_>,
    offset: usize,
    lb: u64,
    ub: u64,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let value = read_extensible_integer(r, lb, ub)?;
    let value = u8::try_from(value).map_err(|_| PacketError::InvalidHeader("INTEGER too large"))?;
    buf.push_field(
        desc,
        FieldValue::U8(value),
        shift(r.byte_range_since(start), offset),
    );
    Ok(())
}

/// Reads a constrained `INTEGER (lb..ub)` with `ub` at most 255 and pushes
/// it as the U8 field `desc`.
pub fn push_constrained_u8(
    buf: &mut DissectBuffer<'_>,
    desc: &'static FieldDescriptor,
    r: &mut AperReader<'_>,
    offset: usize,
    lb: u64,
    ub: u64,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let value = r.read_constrained_whole_number(lb, ub)?;
    let value = u8::try_from(value).map_err(|_| PacketError::InvalidHeader("INTEGER too large"))?;
    buf.push_field(
        desc,
        FieldValue::U8(value),
        shift(r.byte_range_since(start), offset),
    );
    Ok(())
}

/// Reads an ENUMERATED value (see [`push_enumerated`]) and pushes it as
/// the U8 field `desc`.
pub fn push_enumerated_field(
    buf: &mut DissectBuffer<'_>,
    desc: &'static FieldDescriptor,
    r: &mut AperReader<'_>,
    offset: usize,
    root_count: u64,
    extensible: bool,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let value = r.read_enumerated(root_count, extensible)?;
    let value =
        u8::try_from(value).map_err(|_| PacketError::InvalidHeader("ENUMERATED too large"))?;
    buf.push_field(
        desc,
        FieldValue::U8(value),
        shift(r.byte_range_since(start), offset),
    );
    Ok(())
}

// ── Cause ──────────────────────────────────────────────────────────────

/// A decoded Cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cause {
    /// CHOICE index (see [`cause_group_name`]).
    pub group: u8,
    /// Byte range of the CHOICE index.
    pub group_range: Range<usize>,
    /// The ENUMERATED value of the group with its byte range, absent for
    /// `choice-extension`.
    pub value: Option<(u8, Range<usize>)>,
}

/// Reads a Cause at the reader's position.
///
/// `Cause ::= CHOICE { radioNetwork, transport, protocol, misc,
/// choice-extension }`: a 3-bit index (five alternatives, no extension
/// marker, ITU-T Rec. X.691, Section 23), then the extensible ENUMERATED
/// value of the group (Section 14), whose root sizes are `root_counts`.
/// For `choice-extension` the ProtocolIE-SingleContainer is skipped.
pub fn read_cause(r: &mut AperReader<'_>, root_counts: &[u64; 4]) -> Result<Cause, PacketError> {
    let start = r.bit_position();
    let group = r.read_choice_index(5, false)?;
    let group_range = r.byte_range_since(start);
    let value = match root_counts.get(group as usize) {
        Some(&root_count) => {
            let start = r.bit_position();
            let value = u8::try_from(r.read_enumerated(root_count, true)?)
                .map_err(|_| PacketError::InvalidHeader("Cause value out of range"))?;
            Some((value, r.byte_range_since(start)))
        }
        None => {
            skip_protocol_ie_single_container(r)?;
            None
        }
    };
    // `group` is at most 4 (3-bit constrained whole number 0..4).
    Ok(Cause {
        group: group as u8,
        group_range,
        value,
    })
}

/// Pushes `cause_group` and, if present, `cause_value`.
pub fn push_cause_fields(buf: &mut DissectBuffer<'_>, cause: &Cause, offset: usize) {
    buf.push_field(
        &FD_CAUSE_GROUP,
        FieldValue::U8(cause.group),
        shift(cause.group_range.clone(), offset),
    );
    if let Some((value, ref range)) = cause.value {
        buf.push_field(
            &FD_CAUSE_VALUE,
            FieldValue::U8(value),
            shift(range.clone(), offset),
        );
    }
}

/// Decodes a Cause IE value (see [`read_cause`]).
pub fn push_cause<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    root_counts: &[u64; 4],
    data: &'pkt [u8],
    offset: usize,
) -> bool {
    let decode = || -> Result<Cause, PacketError> {
        let mut r = AperReader::new(data);
        let cause = read_cause(&mut r, root_counts)?;
        ensure_consumed(&r, data)?;
        Ok(cause)
    };
    let Ok(cause) = decode() else {
        return false;
    };
    push_cause_fields(buf, &cause, offset);
    true
}

// ── Cell identities ────────────────────────────────────────────────────

/// A decoded NR-CGI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrCgi<'a> {
    /// `PLMN-Identity` octets.
    pub plmn: &'a [u8],
    /// Byte range of the PLMN identity.
    pub plmn_range: Range<usize>,
    /// 36-bit NR cell identity.
    pub cell_identity: u64,
    /// Byte range of the cell identity.
    pub cell_identity_range: Range<usize>,
}

/// Reads an NR-CGI at the reader's position.
///
/// `NR-CGI ::= SEQUENCE { PLMN-Identity (OCTET STRING (SIZE(3))), BIT
/// STRING (SIZE(36)), iE-Extensions OPTIONAL, ... }` — 3GPP TS 38.423,
/// Section 9.3.5 (NR-CGI); TS 38.473, Section 9.4.5 (NRCGI); TS 37.483,
/// Section 9.4.5 (NR-CGI). ITU-T Rec. X.691, Sections 16.10, 17.7, 19.
pub fn read_nr_cgi<'a>(r: &mut AperReader<'a>) -> Result<NrCgi<'a>, PacketError> {
    let (extended, has_ie_extensions) = read_sequence_preamble(r)?;
    let (plmn, plmn_range) = read_aligned_octets(r, 3)?;
    let (cell_identity, cell_identity_range) = read_bit_string_field(r, 36)?;
    skip_sequence_tail(r, extended, has_ie_extensions)?;
    Ok(NrCgi {
        plmn,
        plmn_range,
        cell_identity,
        cell_identity_range,
    })
}

/// Pushes `plmn_identity` and `nr_cell_identity`.
pub fn push_nr_cgi_fields<'pkt>(buf: &mut DissectBuffer<'pkt>, cgi: &NrCgi<'pkt>, offset: usize) {
    buf.push_field(
        &FD_PLMN_IDENTITY,
        FieldValue::Bytes(cgi.plmn),
        shift(cgi.plmn_range.clone(), offset),
    );
    buf.push_field(
        &FD_NR_CELL_IDENTITY,
        FieldValue::U64(cgi.cell_identity),
        shift(cgi.cell_identity_range.clone(), offset),
    );
}

/// Decodes an NR-CGI IE value (see [`read_nr_cgi`]).
pub fn push_nr_cgi<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let decode = || -> Result<NrCgi<'pkt>, PacketError> {
        let mut r = AperReader::new(data);
        let cgi = read_nr_cgi(&mut r)?;
        ensure_consumed(&r, data)?;
        Ok(cgi)
    };
    let Ok(cgi) = decode() else {
        return false;
    };
    push_nr_cgi_fields(buf, &cgi, offset);
    true
}

// ── UP transport layer information ─────────────────────────────────────

/// Upper bound of `TransportLayerAddress ::= BIT STRING (SIZE(1..160,
/// ...))`.
const TRANSPORT_LAYER_ADDRESS_MAX_BITS: u64 = 160;

/// A decoded UP transport layer information CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpTnl<'a> {
    /// CHOICE index: 0 for the GTP tunnel, 1 for `choice-extension`.
    pub choice: u8,
    /// Byte range of the CHOICE index.
    pub choice_range: Range<usize>,
    /// Transport layer address: bit length, octets and byte range.
    pub address: Option<(u64, &'a [u8], Range<usize>)>,
    /// GTP-TEID and its byte range.
    pub teid: Option<(u32, Range<usize>)>,
}

/// Reads a UP transport layer information CHOICE at the reader's position.
///
/// XnAP `UPTransportLayerInformation ::= CHOICE { gtpTunnel
/// GTPtunnelTransportLayerInformation, choice-extension }` (3GPP TS
/// 38.423, Section 9.3.5), F1AP `UPTransportLayerInformation ::= CHOICE {
/// gTPTunnel GTPTunnel, choice-extension }` (TS 38.473, Section 9.4.5) and
/// E1AP `UP-TNL-Information ::= CHOICE { gTPTunnel GTPTunnel,
/// choice-extension }` (TS 37.483, Section 9.4.5): a 1-bit index, then
/// `SEQUENCE { TransportLayerAddress (BIT STRING (SIZE(1..160, ...))),
/// GTP-TEID (OCTET STRING (SIZE(4))), iE-Extensions OPTIONAL, ... }`.
///
/// ITU-T Rec. X.691, Sections 16.11 (variable-size BIT STRING: an
/// extension bit, a constrained length, then octet-aligned bits since the
/// upper bound exceeds 16) and 17.7 (fixed-size OCTET STRING above two
/// octets, octet-aligned).
pub fn read_up_tnl<'a>(r: &mut AperReader<'a>) -> Result<UpTnl<'a>, PacketError> {
    let choice_start = r.bit_position();
    // Two alternatives, no extension marker: one bit.
    let choice = r.read_choice_index(2, false)? as u8;
    let choice_range = r.byte_range_since(choice_start);
    if choice != 0 {
        skip_protocol_ie_single_container(r)?;
        return Ok(UpTnl {
            choice,
            choice_range,
            address: None,
            teid: None,
        });
    }
    let (extended, ie_extensions) = read_sequence_preamble(r)?;
    if r.read_bit()? {
        return Err(PacketError::InvalidHeader(
            "TransportLayerAddress size extension",
        ));
    }
    let bits = r.read_length(1, Some(TRANSPORT_LAYER_ADDRESS_MAX_BITS))?;
    let (address, address_range) = read_aligned_octets(r, bits.div_ceil(8) as usize)?;
    let (teid, teid_range) = read_aligned_octets(r, 4)?;
    let teid = u32::from_be_bytes([teid[0], teid[1], teid[2], teid[3]]);
    skip_sequence_tail(r, extended, ie_extensions)?;
    Ok(UpTnl {
        choice,
        choice_range,
        address: Some((bits, address, address_range)),
        teid: Some((teid, teid_range)),
    })
}

/// Pushes the fields of a decoded UP transport layer information.
///
/// The transport layer address is an IPv4 address (32 bits), an IPv6
/// address (128 bits) or both, IPv4 first (160 bits) — 3GPP TS 38.414,
/// Section 5.1 — and raw bytes otherwise.
pub fn push_up_tnl_fields<'pkt>(buf: &mut DissectBuffer<'pkt>, tnl: &UpTnl<'pkt>, offset: usize) {
    buf.push_field(
        &FD_UP_TNL_CHOICE,
        FieldValue::U8(tnl.choice),
        shift(tnl.choice_range.clone(), offset),
    );
    if let Some((bits, address, ref range)) = tnl.address {
        let range = shift(range.clone(), offset);
        let v4 = |a: &[u8]| FieldValue::Ipv4Addr([a[0], a[1], a[2], a[3]]);
        let v6 = |a: &[u8]| {
            let mut v = [0u8; 16];
            v.copy_from_slice(a);
            FieldValue::Ipv6Addr(v)
        };
        match bits {
            32 => buf.push_field(&FD_IPV4_ADDRESS, v4(address), range),
            128 => buf.push_field(&FD_IPV6_ADDRESS, v6(address), range),
            160 => {
                let s = range.start;
                buf.push_field(&FD_IPV4_ADDRESS, v4(&address[..4]), s..s + 4);
                buf.push_field(&FD_IPV6_ADDRESS, v6(&address[4..]), s + 4..s + 20);
            }
            _ => buf.push_field(
                &FD_TRANSPORT_LAYER_ADDRESS,
                FieldValue::Bytes(address),
                range,
            ),
        }
    }
    if let Some((teid, ref range)) = tnl.teid {
        buf.push_field(
            &FD_GTP_TEID,
            FieldValue::U32(teid),
            shift(range.clone(), offset),
        );
    }
}

/// Reads a UP transport layer information and pushes it as the Object
/// `desc`.
pub fn push_up_tnl_object<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    desc: &'static FieldDescriptor,
    r: &mut AperReader<'pkt>,
    offset: usize,
) -> Result<(), PacketError> {
    let start = r.bit_position();
    let tnl = read_up_tnl(r)?;
    let obj = buf.begin_container(
        desc,
        FieldValue::Object(0..0),
        shift(r.byte_range_since(start), offset),
    );
    push_up_tnl_fields(buf, &tnl, offset);
    buf.end_container(obj);
    Ok(())
}

/// Decodes a UP transport layer information IE value (see
/// [`read_up_tnl`]).
pub fn push_up_tnl<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) -> bool {
    let decode = || -> Result<UpTnl<'pkt>, PacketError> {
        let mut r = AperReader::new(data);
        let tnl = read_up_tnl(&mut r)?;
        ensure_consumed(&r, data)?;
        Ok(tnl)
    };
    let Ok(tnl) = decode() else {
        return false;
    };
    push_up_tnl_fields(buf, &tnl, offset);
    true
}

#[cfg(test)]
mod tests {
    //! # Common 3GPP IE Decoder Coverage
    //!
    //! Test vectors were produced by an independent APER encoder (pycrate
    //! `E1AP_IEs`); the types are identical in XnAP and F1AP.
    //!
    //! | Section               | Description                              | Test                               |
    //! |-----------------------|------------------------------------------|------------------------------------|
    //! | X.691 11.5.7.4        | INTEGER, indefinite length case          | unsigned_indefinite_length         |
    //! | X.691 11.5.7          | INTEGER, trailing octets / wrong type    | unsigned_rejects_malformed         |
    //! | X.691 13.2.6          | Extensible INTEGER (TransactionID)       | extensible_unsigned                |
    //! | X.691 13.2.6          | Extensible INTEGER, extension value      | extensible_unsigned_extension      |
    //! | X.691 13.2.6          | Extensible INTEGER, malformed            | extensible_unsigned_malformed      |
    //! | X.691 14              | ENUMERATED (CNSupport)                   | enumerated_value                   |
    //! | X.691 30.5            | PrintableString name                     | printable_string                   |
    //! | X.691 30.5            | PrintableString, extended size           | printable_string_extended_size     |
    //! | X.691 30.5            | PrintableString, malformed               | printable_string_malformed         |
    //! | X.691 17.8            | Unconstrained OCTET STRING               | octet_string                       |
    //! | TS 37.483 9.4.5       | Cause, root value                        | cause_root                         |
    //! | TS 37.483 9.4.5       | Cause, extension value                   | cause_extension_value              |
    //! | TS 37.483 9.4.5       | Cause, choice-extension                  | cause_choice_extension             |
    //! | TS 37.483 9.4.5       | Cause, malformed                         | cause_malformed                    |
    //! | TS 37.483 9.4.5       | NR-CGI                                   | nr_cgi                             |
    //! | TS 38.414 5.1         | GTP tunnel, IPv4                         | up_tnl_ipv4                        |
    //! | TS 38.414 5.1         | GTP tunnel, IPv6                         | up_tnl_ipv6                        |
    //! | TS 38.414 5.1         | GTP tunnel, IPv4 and IPv6                | up_tnl_dual_stack                  |
    //! | TS 38.414 5.1         | GTP tunnel, other address length         | up_tnl_other_length                |
    //! | TS 37.483 9.4.5       | UP-TNL-Information choice-extension      | up_tnl_choice_extension            |
    //! | X.691 16.11           | Address size extension rejected          | up_tnl_size_extension_rejected     |
    //! | —                     | UP TNL as an object                      | up_tnl_object                      |
    //! | —                     | Cause group names                        | cause_group_names                  |

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Test vector with a `'static` lifetime, so that a buffer can be
    /// reused across several values.
    fn hex_static(s: &str) -> &'static [u8] {
        hex(s).leak()
    }

    fn pushed<'a>(buf: &'a DissectBuffer<'a>) -> Vec<(&'static str, FieldValue<'a>)> {
        buf.fields()
            .iter()
            .map(|f| (f.name(), f.value.clone()))
            .collect()
    }

    static FD_U64: FieldDescriptor = FieldDescriptor::new("v", "V", FieldType::U64);
    static FD_U32: FieldDescriptor = FieldDescriptor::new("v", "V", FieldType::U32);
    static FD_U16: FieldDescriptor = FieldDescriptor::new("v", "V", FieldType::U16);
    static FD_U8: FieldDescriptor = FieldDescriptor::new("v", "V", FieldType::U8);
    static FD_STR: FieldDescriptor = FieldDescriptor::new("v", "V", FieldType::Str);
    static FD_BYTES: FieldDescriptor = FieldDescriptor::new("v", "V", FieldType::Bytes);
    static FD_OBJ: FieldDescriptor = FieldDescriptor::new("o", "O", FieldType::Object);

    /// E1AP root sizes of CauseRadioNetwork, CauseTransport, CauseProtocol
    /// and CauseMisc (TS 37.483 v19.4.0, Section 9.4.5).
    const E1AP_CAUSE: [u64; 4] = [25, 2, 7, 5];

    #[test]
    fn unsigned_indefinite_length() {
        // GNB-CU-UP-ID ::= INTEGER (0..68719476735).
        let data = hex("800fffffffff");
        let mut buf = DissectBuffer::new();
        assert!(push_unsigned(&mut buf, &FD_U64, 68_719_476_735, &data, 10));
        assert_eq!(pushed(&buf), [("v", FieldValue::U64(68_719_476_735))]);
        assert_eq!(buf.fields()[0].range, 10..16);

        // GNB-CU-CP-UE-E1AP-ID ::= INTEGER (0..4294967295).
        let data = hex("c012345678");
        let mut buf = DissectBuffer::new();
        assert!(push_unsigned(&mut buf, &FD_U32, 4_294_967_295, &data, 0));
        assert_eq!(pushed(&buf), [("v", FieldValue::U32(0x1234_5678))]);

        let data = hex("0102");
        let mut buf = DissectBuffer::new();
        assert!(push_unsigned(&mut buf, &FD_U16, 65535, &data, 0));
        assert_eq!(pushed(&buf), [("v", FieldValue::U16(0x0102))]);
    }

    #[test]
    fn unsigned_rejects_malformed() {
        let mut buf = DissectBuffer::new();
        assert!(!push_unsigned(
            &mut buf,
            &FD_U32,
            4_294_967_295,
            hex_static("c01234567800"),
            0
        ));
        assert!(!push_unsigned(
            &mut buf,
            &FD_U32,
            4_294_967_295,
            hex_static("c0"),
            0
        ));
        // A U8 descriptor cannot hold the value.
        assert!(!push_unsigned(
            &mut buf,
            &FD_U8,
            65535,
            hex_static("0102"),
            0
        ));
        // A Str descriptor is not an integer type.
        assert!(!push_unsigned(&mut buf, &FD_STR, 255, hex_static("01"), 0));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn extensible_unsigned() {
        // TransactionID ::= INTEGER (0..255, ...), value 5.
        let data = hex("0005");
        let mut buf = DissectBuffer::new();
        assert!(push_extensible_unsigned(&mut buf, &FD_U8, 255, &data, 3));
        assert_eq!(pushed(&buf), [("v", FieldValue::U8(5))]);
        assert_eq!(buf.fields()[0].range, 3..5);

        // A U16 and U32 descriptor hold the value too.
        assert!(push_extensible_unsigned(&mut buf, &FD_U16, 255, &data, 0));
        assert!(push_extensible_unsigned(&mut buf, &FD_U32, 255, &data, 0));
        // A U64 descriptor is not supported.
        assert!(!push_extensible_unsigned(&mut buf, &FD_U64, 255, &data, 0));
    }

    #[test]
    fn extensible_unsigned_extension() {
        // SRBID ::= INTEGER (0..3, ..., 4 | 5 | 6), value 4 (pycrate
        // `F1AP_IEs`).
        let mut buf = DissectBuffer::new();
        assert!(push_extensible_unsigned(
            &mut buf,
            &FD_U8,
            3,
            hex_static("800104"),
            0
        ));
        assert_eq!(pushed(&buf), [("v", FieldValue::U8(4))]);
        // SRBID 2, in the root.
        assert!(push_extensible_unsigned(
            &mut buf,
            &FD_U8,
            3,
            hex_static("40"),
            0
        ));
        assert_eq!(buf.fields()[1].value, FieldValue::U8(2));
    }

    #[test]
    fn extensible_unsigned_malformed() {
        let mut buf = DissectBuffer::new();
        // Trailing octet.
        assert!(!push_extensible_unsigned(
            &mut buf,
            &FD_U8,
            255,
            hex_static("000500"),
            0
        ));
        // Negative extension value.
        assert!(!push_extensible_unsigned(
            &mut buf,
            &FD_U8,
            3,
            hex_static("8001ff"),
            0
        ));
        // Zero-length and over-long extension values.
        assert!(!push_extensible_unsigned(
            &mut buf,
            &FD_U8,
            3,
            hex_static("8000"),
            0
        ));
        assert!(!push_extensible_unsigned(
            &mut buf,
            &FD_U32,
            3,
            hex_static("8009000000000000000001"),
            0
        ));
        // U8 cannot hold 256..65535 values.
        assert!(!push_extensible_unsigned(
            &mut buf,
            &FD_U8,
            65535,
            hex_static("00000100"),
            0
        ));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn enumerated_value() {
        // CNSupport ::= ENUMERATED { c-epc, c-5gc, both, ... }, value both.
        let mut buf = DissectBuffer::new();
        assert!(push_enumerated(
            &mut buf,
            &FD_U8,
            3,
            true,
            hex_static("40"),
            0
        ));
        assert_eq!(pushed(&buf), [("v", FieldValue::U8(2))]);
        assert!(!push_enumerated(
            &mut buf,
            &FD_U8,
            3,
            true,
            hex_static("4000"),
            0
        ));
        assert!(!push_enumerated(
            &mut buf,
            &FD_U8,
            3,
            false,
            hex_static("c0"),
            0
        ));
    }

    #[test]
    fn printable_string() {
        // GNB-CU-UP-Name ::= PrintableString (SIZE(1..150, ...)).
        let data = hex("030063752d75702d31");
        let mut buf = DissectBuffer::new();
        assert!(push_printable_string(&mut buf, &FD_STR, 1, 150, &data, 100));
        assert_eq!(pushed(&buf), [("v", FieldValue::Str("cu-up-1"))]);
        assert_eq!(buf.fields()[0].range, 102..109);
    }

    #[test]
    fn printable_string_extended_size() {
        // Extension bit set: unconstrained length (octet-aligned) 2.
        let data = hex("80024142");
        let mut buf = DissectBuffer::new();
        assert!(push_printable_string(&mut buf, &FD_STR, 1, 150, &data, 0));
        assert_eq!(pushed(&buf), [("v", FieldValue::Str("AB"))]);
    }

    #[test]
    fn printable_string_malformed() {
        let mut buf = DissectBuffer::new();
        // Truncated characters.
        assert!(!push_printable_string(
            &mut buf,
            &FD_STR,
            1,
            150,
            hex_static("030063"),
            0
        ));
        // Not valid UTF-8.
        assert!(!push_printable_string(
            &mut buf,
            &FD_STR,
            1,
            150,
            hex_static("0000ff"),
            0
        ));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn octet_string() {
        let mut buf = DissectBuffer::new();
        assert!(push_octet_string(
            &mut buf,
            &FD_BYTES,
            hex_static("03aabbcc"),
            7
        ));
        assert_eq!(
            pushed(&buf),
            [("v", FieldValue::Bytes(&[0xaa, 0xbb, 0xcc]))]
        );
        assert_eq!(buf.fields()[0].range, 8..11);
        assert!(!push_octet_string(
            &mut buf,
            &FD_BYTES,
            hex_static("04aabbcc"),
            0
        ));
        assert!(!push_octet_string(
            &mut buf,
            &FD_BYTES,
            hex_static("02aabbcc"),
            0
        ));
    }

    #[test]
    fn cause_root() {
        // misc: unspecified (4).
        let mut buf = DissectBuffer::new();
        assert!(push_cause(&mut buf, &E1AP_CAUSE, hex_static("68"), 0));
        assert_eq!(
            pushed(&buf),
            [
                ("cause_group", FieldValue::U8(3)),
                ("cause_value", FieldValue::U8(4))
            ]
        );
    }

    #[test]
    fn cause_extension_value() {
        // radioNetwork: ue-dl-max-IP-data-rate-reason (first extension, 25).
        let mut buf = DissectBuffer::new();
        assert!(push_cause(&mut buf, &E1AP_CAUSE, hex_static("1000"), 0));
        assert_eq!(
            pushed(&buf),
            [
                ("cause_group", FieldValue::U8(0)),
                ("cause_value", FieldValue::U8(25))
            ]
        );
        // transport: unknown-TNL-address-for-IAB (2).
        let mut buf = DissectBuffer::new();
        assert!(push_cause(&mut buf, &E1AP_CAUSE, hex_static("3000"), 0));
        assert_eq!(buf.fields()[1].value, FieldValue::U8(2));
    }

    #[test]
    fn cause_choice_extension() {
        // Index 4 (100), padding, ProtocolIE-SingleContainer: id 1,
        // criticality ignore, one-octet value.
        let mut buf = DissectBuffer::new();
        assert!(push_cause(
            &mut buf,
            &E1AP_CAUSE,
            hex_static("800001400100"),
            0
        ));
        assert_eq!(pushed(&buf), [("cause_group", FieldValue::U8(4))]);
    }

    #[test]
    fn cause_malformed() {
        let mut buf = DissectBuffer::new();
        // Index 5 is out of range.
        assert!(!push_cause(&mut buf, &E1AP_CAUSE, hex_static("a0"), 0));
        // Trailing octet.
        assert!(!push_cause(&mut buf, &E1AP_CAUSE, hex_static("6800"), 0));
        // Extension value too large for a u8 (normally small long form).
        assert!(!push_cause(
            &mut buf,
            &E1AP_CAUSE,
            hex_static("18010fff"),
            0
        ));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn nr_cgi() {
        let data = hex("0000f1101234567890");
        let mut buf = DissectBuffer::new();
        assert!(push_nr_cgi(&mut buf, &data, 0));
        assert_eq!(
            pushed(&buf),
            [
                ("plmn_identity", FieldValue::Bytes(&[0x00, 0xf1, 0x10])),
                ("nr_cell_identity", FieldValue::U64(0x1_2345_6789))
            ]
        );
        assert_eq!(buf.fields()[1].range, 4..9);
        assert!(!push_nr_cgi(&mut buf, &data[..8], 0));
    }

    #[test]
    fn up_tnl_ipv4() {
        let data = hex("01f0c0a8000112345678");
        let mut buf = DissectBuffer::new();
        assert!(push_up_tnl(&mut buf, &data, 0));
        assert_eq!(
            pushed(&buf),
            [
                ("up_tnl_choice", FieldValue::U8(0)),
                ("ipv4_address", FieldValue::Ipv4Addr([192, 168, 0, 1])),
                ("gtp_teid", FieldValue::U32(0x1234_5678))
            ]
        );
        assert_eq!(buf.fields()[1].range, 2..6);
        assert_eq!(buf.fields()[2].range, 6..10);
    }

    #[test]
    fn up_tnl_ipv6() {
        let data = hex("07f08000000000000000000000000000000100000001");
        let mut buf = DissectBuffer::new();
        assert!(push_up_tnl(&mut buf, &data, 0));
        let mut v6 = [0u8; 16];
        v6[0] = 0x80;
        v6[15] = 0x01;
        assert_eq!(buf.fields()[1].value, FieldValue::Ipv6Addr(v6));
        assert_eq!(buf.fields()[2].value, FieldValue::U32(1));
    }

    #[test]
    fn up_tnl_dual_stack() {
        let data = hex("09f00a0000010000000000000000000000000000000100000002");
        let mut buf = DissectBuffer::new();
        assert!(push_up_tnl(&mut buf, &data, 0));
        assert_eq!(buf.fields()[1].value, FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(buf.fields()[1].range, 2..6);
        assert_eq!(buf.fields()[2].name(), "ipv6_address");
        assert_eq!(buf.fields()[2].range, 6..22);
        assert_eq!(buf.fields()[3].value, FieldValue::U32(2));
    }

    #[test]
    fn up_tnl_other_length() {
        let data = hex("0170abcdef00000003");
        let mut buf = DissectBuffer::new();
        assert!(push_up_tnl(&mut buf, &data, 0));
        assert_eq!(
            buf.fields()[1].value,
            FieldValue::Bytes(&[0xab, 0xcd, 0xef])
        );
    }

    #[test]
    fn up_tnl_choice_extension() {
        let data = hex("800001400100");
        let mut buf = DissectBuffer::new();
        assert!(push_up_tnl(&mut buf, &data, 0));
        assert_eq!(pushed(&buf), [("up_tnl_choice", FieldValue::U8(1))]);
    }

    #[test]
    fn up_tnl_size_extension_rejected() {
        let mut buf = DissectBuffer::new();
        assert!(!push_up_tnl(&mut buf, hex_static("10"), 0));
        assert!(!push_up_tnl(&mut buf, hex_static("01f0c0a80001123456"), 0));
        assert!(buf.fields().is_empty());
    }

    #[test]
    fn up_tnl_object() {
        let data = hex("01f0c0a8000112345678");
        let mut buf = DissectBuffer::new();
        let mut r = AperReader::new(&data);
        push_up_tnl_object(&mut buf, &FD_OBJ, &mut r, 20).unwrap();
        assert_eq!(buf.fields()[0].value, FieldValue::Object(1..4));
        assert_eq!(buf.fields()[0].range, 20..30);
        let mut r = AperReader::new(&data[..4]);
        assert!(push_up_tnl_object(&mut buf, &FD_OBJ, &mut r, 0).is_err());
    }

    #[test]
    fn cause_group_names() {
        assert_eq!(cause_group_name(0), "radioNetwork");
        assert_eq!(cause_group_name(1), "transport");
        assert_eq!(cause_group_name(2), "protocol");
        assert_eq!(cause_group_name(3), "misc");
        assert_eq!(cause_group_name(4), "choice-extension");
        assert_eq!(cause_group_name(5), "Unknown");
        let f = |v| (FD_CAUSE_GROUP.display_fn.unwrap())(&v, &[]);
        assert_eq!(f(FieldValue::U8(1)), Some("transport"));
        assert_eq!(f(FieldValue::U16(1)), None);
        let g = |v| (FD_UP_TNL_CHOICE.display_fn.unwrap())(&v, &[]);
        assert_eq!(g(FieldValue::U8(0)), Some("gTPTunnel"));
        assert_eq!(g(FieldValue::U8(1)), Some("choice-extension"));
        assert_eq!(g(FieldValue::U16(1)), None);
    }
}
