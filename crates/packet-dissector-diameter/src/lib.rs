//! Diameter base protocol (RFC 6733) dissector with vendor application support.
//!
//! Parses the Diameter message header (20 bytes) and AVPs.
//! Each AVP is represented as an element in an Array of Objects.
//!
//! ## Supported Applications
//! - Diameter Base Protocol (RFC 6733, Application-ID 0)
//! - NASREQ (RFC 7155, Application-ID 1)
//! - Diameter Credit-Control (RFC 8506, which obsoletes RFC 4006, Application-ID 4)
//! - Diameter EAP (RFC 4072, Application-ID 5); with the `eap` feature the
//!   EAP-Payload and EAP-Reissued-Payload values are decoded as EAP
//! - 3GPP STa (TS 29.273, Application-ID 16777250)
//! - 3GPP Cx (TS 29.229, Application-ID 16777216) — IMS HSS
//! - 3GPP Sh (TS 29.329, Application-ID 16777217) — User Profile
//! - 3GPP Zh (TS 29.109, Application-ID 16777221) — GBA
//! - 3GPP Rx (TS 29.214, Application-ID 16777236) — QoS Authorization
//! - 3GPP Gx (TS 29.212, Application-ID 16777238) — Policy and Charging Control
//! - 3GPP S6a/S6d (TS 29.272, Application-ID 16777251) — MME/SGSN–HSS
//! - 3GPP S13/S13' (TS 29.272, Application-ID 16777252) — ME Identity Check
//! - 3GPP SWm (TS 29.273, Application-ID 16777264) — Non-3GPP Access
//! - 3GPP SWx (TS 29.273, Application-ID 16777265) — Non-3GPP Access Registration
//! - 3GPP S6b (TS 29.273, Application-ID 16777272) — Non-3GPP Access
//! - 3GPP S7a/S7d (TS 29.272, Application-ID 16777308) — VCSG
//!
//! ## References
//! - RFC 6733: <https://www.rfc-editor.org/rfc/rfc6733>
//! - RFC 4006: <https://www.rfc-editor.org/rfc/rfc4006>
//! - RFC 8506: <https://www.rfc-editor.org/rfc/rfc8506>
//! - RFC 7155: <https://www.rfc-editor.org/rfc/rfc7155>
//! - RFC 4072: <https://www.rfc-editor.org/rfc/rfc4072>
//! - RFC 5905 (NTP; referenced by RFC 6733 for `Time`): <https://www.rfc-editor.org/rfc/rfc5905>
//! - RFC 4330, Section 3 (SNTP era rule for `Time`, obsoleted by RFC 5905): <https://www.rfc-editor.org/rfc/rfc4330#section-3>
//! - IANA AAA Parameters: <https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xhtml>
//! - 3GPP TS 29.061: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.061/>
//! - 3GPP TS 29.212: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.212/>
//! - 3GPP TS 29.214: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.214/>
//! - 3GPP TS 29.229: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.229/>
//! - 3GPP TS 29.272: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.272/>
//! - 3GPP TS 29.273: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.273/>
//! - 3GPP TS 29.329: <https://www.3gpp.org/ftp/Specs/archive/29_series/29.329/>
//! - 3GPP TS 32.299: <https://www.3gpp.org/ftp/Specs/archive/32_series/32.299/>
//!
//! `Integer64`, `Float32` and `Float64` AVP values are emitted as raw bytes
//! because `FieldValue` has no signed 64-bit or floating-point variant.

#![deny(missing_docs)]

mod avp;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    Field, FieldDescriptor, FieldType, FieldValue, FormatContext, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{
    read_be_i32, read_be_u16, read_be_u24, read_be_u32, read_be_u64, read_ipv4_addr, read_ipv6_addr,
};

use avp::{
    AVP_CODE_EXPERIMENTAL_RESULT_CODE, AVP_CODE_RESULT_CODE, AvpType, application_name,
    command_name, enum_value_name, experimental_result_code_name, lookup_avp, result_code_name,
};

/// Diameter message header size (RFC 6733, Section 3).
const HEADER_SIZE: usize = 20;

/// Command Flags bit: Request (R).
const FLAG_REQUEST: u8 = 0x80;
/// Command Flags bit: Proxiable (P).
const FLAG_PROXIABLE: u8 = 0x40;
/// Command Flags bit: Error (E).
const FLAG_ERROR: u8 = 0x20;
/// Command Flags bit: Potentially re-transmitted (T).
const FLAG_RETRANSMIT: u8 = 0x10;

/// Minimum AVP header size without Vendor-ID (RFC 6733, Section 4.1).
const MIN_AVP_HEADER: usize = 8;

/// AVP Flags bit: Vendor-ID present (V).
///
/// RFC 6733, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc6733#section-4.1>
const AVP_FLAG_VENDOR: u8 = 0x80;
/// AVP Flags bit: Mandatory (M).
const AVP_FLAG_MANDATORY: u8 = 0x40;
/// AVP Flags bit: Protected (P). RFC 6733, Section 4.1 — "The 'P' bit has
/// been reserved for future usage of end-to-end security."
/// <https://www.rfc-editor.org/rfc/rfc6733#section-4.1>
const AVP_FLAG_PROTECTED: u8 = 0x20;

/// Maximum recursion depth for Grouped AVPs (stack overflow guard).
const MAX_GROUPED_DEPTH: usize = 8;

// ---------------------------------------------------------------------------
// Field descriptor indices for [`FIELD_DESCRIPTORS`].
// ---------------------------------------------------------------------------

const FD_VERSION: usize = 0;
const FD_MESSAGE_LENGTH: usize = 1;
const FD_COMMAND_FLAGS: usize = 2;
const FD_IS_REQUEST: usize = 3;
const FD_IS_PROXIABLE: usize = 4;
const FD_IS_ERROR: usize = 5;
const FD_IS_RETRANSMIT: usize = 6;
const FD_COMMAND_CODE: usize = 7;
const FD_APPLICATION_ID: usize = 8;
const FD_HOP_BY_HOP_ID: usize = 9;
const FD_END_TO_END_ID: usize = 10;
const FD_AVPS: usize = 11;

/// Field descriptor indices for [`AVP_CHILD_FIELDS`].
const FD_AVP_CODE: usize = 0;
const FD_AVP_FLAGS: usize = 1;
const FD_AVP_LENGTH: usize = 2;
const FD_AVP_VENDOR_ID: usize = 3;
const FD_AVP_NAME: usize = 4;
const FD_AVP_VALUE: usize = 5;
const FD_AVP_FLAG_VENDOR: usize = 6;
const FD_AVP_FLAG_MANDATORY: usize = 7;
const FD_AVP_FLAG_PROTECTED: usize = 8;
#[cfg(feature = "eap")]
const FD_AVP_EAP: usize = 9;

/// Return the `U32` value of the AVP header field called `name`.
///
/// `fields` is the flat child slice of an AVP Object, which also contains
/// the descendants of a Grouped value. The AVP's own header fields come
/// before its first nested container, so the scan stops there; otherwise a
/// `vendor_id` of a nested AVP would be picked up for a vendor-less parent.
fn child_u32(fields: &[Field<'_>], name: &str) -> Option<u32> {
    fields
        .iter()
        .take_while(|f| !matches!(f.value, FieldValue::Array(_) | FieldValue::Object(_)))
        .find_map(|f| match (f.name(), &f.value) {
            (n, FieldValue::U32(v)) if n == name => Some(*v),
            _ => None,
        })
}

/// Resolve the display name of an AVP `value` from its sibling `code` and
/// optional `vendor_id`.
fn avp_value_name(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let code = child_u32(siblings, "code")?;
    let vendor_id = child_u32(siblings, "vendor_id").unwrap_or(0);
    match v {
        FieldValue::U32(rc) if vendor_id == 0 && code == AVP_CODE_RESULT_CODE => {
            Some(result_code_name(*rc))
        }
        FieldValue::U32(rc) if vendor_id == 0 && code == AVP_CODE_EXPERIMENTAL_RESULT_CODE => {
            let name = experimental_result_code_name(*rc);
            if name != "Unknown" { Some(name) } else { None }
        }
        // RFC 6733, Section 4.3.1 — Enumerated is derived from Integer32.
        // <https://www.rfc-editor.org/rfc/rfc6733#section-4.3.1>
        FieldValue::I32(e) => enum_value_name(vendor_id, code, *e),
        _ => None,
    }
}

/// Seconds between the NTP era 0 epoch (1900-01-01) and the Unix epoch.
const NTP_UNIX_OFFSET: i64 = 2_208_988_800;

/// Format a Diameter `Time` value (NTP seconds) as an RFC 3339 UTC string.
///
/// RFC 6733, Section 4.3.1 — "The string MUST contain four octets, in the
/// same format as the first four bytes are in the NTP timestamp format."
/// "On 6h 28m 16s UTC, 7 February 2036, the time value will overflow.
/// Simple Network Time Protocol (SNTP) [RFC5905] describes a procedure to
/// extend the time to 2104. This procedure MUST be supported by all
/// Diameter nodes."
/// <https://www.rfc-editor.org/rfc/rfc6733#section-4.3.1>
///
/// The SNTP procedure is the era rule of RFC 4330, Section 3 (carried into
/// RFC 5905): if the most significant bit is 0, the time is in the range
/// 2036-2104, counted from 6h 28m 16s UTC on 7 February 2036.
/// <https://www.rfc-editor.org/rfc/rfc4330#section-3>
fn format_ntp_time(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let FieldValue::U32(secs) = value else {
        return w.write_all(b"\"\"");
    };
    let era = if secs & 0x8000_0000 != 0 {
        0
    } else {
        1i64 << 32
    };
    let unix = i64::from(*secs) + era - NTP_UNIX_OFFSET;
    let days = unix.div_euclid(86_400);
    let rem = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    write!(
        w,
        "\"{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z\"",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Convert days since 1970-01-01 to a proleptic Gregorian (year, month, day).
///
/// Howard Hinnant's `civil_from_days` algorithm —
/// <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `value` descriptor used for `Time` AVPs, rendering NTP seconds as an
/// RFC 3339 timestamp at serialization time. The raw `U32` is kept.
static FD_AVP_VALUE_TIME: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::U32).with_format_fn(format_ntp_time);

/// Container descriptor for a parsed AVP entry.
///
/// `display_fn` resolves the outer container's label to the AVP name
/// (e.g. "Origin-Host") by looking up the inner `code` and optional
/// `vendor_id` fields.
static FD_AVP: FieldDescriptor = FieldDescriptor {
    name: "avp",
    display_name: "AVP",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| {
        let FieldValue::Object(_) = v else {
            return None;
        };
        let code = child_u32(children, "code")?;
        let vendor_id = child_u32(children, "vendor_id").unwrap_or(0);
        lookup_avp(vendor_id, code).map(|def| def.name)
    }),
    format_fn: None,
};

/// Child fields for a parsed AVP entry.
static AVP_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("code", "AVP Code", FieldType::U32),
    FieldDescriptor::new("flags", "AVP Flags", FieldType::U8),
    FieldDescriptor::new("length", "AVP Length", FieldType::U32),
    FieldDescriptor::new("vendor_id", "Vendor-ID", FieldType::U32).optional(),
    FieldDescriptor::new("name", "AVP Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // The declared type is `Bytes` as a baseline, but `parse_avp_value()`
    // emits the actual typed variant (U32, Str, Ipv4Addr, etc.) at runtime
    // based on the AVP definition. This is intentional: a single descriptor
    // cannot express the polymorphic value space of all Diameter AVP types.
    FieldDescriptor {
        name: "value",
        display_name: "Value",
        field_type: FieldType::Bytes,
        optional: false,
        children: None,
        display_fn: Some(avp_value_name),
        format_fn: None,
    },
    // RFC 6733, Section 4.1 — AVP Flags "V", "M" and "P" bits.
    // <https://www.rfc-editor.org/rfc/rfc6733#section-4.1>
    FieldDescriptor::new("flag_vendor", "Vendor-Specific Flag", FieldType::U8),
    FieldDescriptor::new("flag_mandatory", "Mandatory Flag", FieldType::U8),
    FieldDescriptor::new("flag_protected", "Protected Flag", FieldType::U8),
    // RFC 4072, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc4072#section-4.1.1>
    #[cfg(feature = "eap")]
    packet_dissector_eap::EAP_OBJECT_DESCRIPTOR,
];

/// EAP-Payload AVP code.
/// RFC 4072, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc4072#section-4.1.1>
#[cfg(feature = "eap")]
const AVP_CODE_EAP_PAYLOAD: u32 = 462;
/// EAP-Reissued-Payload AVP code.
/// RFC 4072, Section 4.1.2 — <https://www.rfc-editor.org/rfc/rfc4072#section-4.1.2>
#[cfg(feature = "eap")]
const AVP_CODE_EAP_REISSUED_PAYLOAD: u32 = 463;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("message_length", "Message Length", FieldType::U32),
    FieldDescriptor::new("command_flags", "Command Flags", FieldType::U8),
    FieldDescriptor::new("is_request", "Request", FieldType::U8),
    FieldDescriptor::new("is_proxiable", "Proxiable", FieldType::U8),
    FieldDescriptor::new("is_error", "Error", FieldType::U8),
    FieldDescriptor::new("is_retransmit", "Potentially Re-transmitted", FieldType::U8),
    FieldDescriptor {
        name: "command_code",
        display_name: "Command Code",
        field_type: FieldType::U32,
        optional: false,
        children: None,
        display_fn: Some(|v, siblings| {
            let FieldValue::U32(code) = v else {
                return None;
            };
            let is_request = siblings
                .iter()
                .find(|f| f.name() == "is_request")
                .and_then(|f| match &f.value {
                    FieldValue::U8(v) => Some(*v != 0),
                    _ => None,
                })
                .unwrap_or(false);
            Some(command_name(*code, is_request))
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "application_id",
        display_name: "Application-ID",
        field_type: FieldType::U32,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U32(id) => Some(application_name(*id)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("hop_by_hop_id", "Hop-by-Hop Identifier", FieldType::U32),
    FieldDescriptor::new("end_to_end_id", "End-to-End Identifier", FieldType::U32),
    FieldDescriptor::new("avps", "AVPs", FieldType::Array)
        .optional()
        .with_children(AVP_CHILD_FIELDS),
];

/// Parse raw AVP data bytes into a typed `FieldValue` based on the AVP type,
/// pushing fields directly into the buffer for Grouped AVPs.
///
/// RFC 6733, Sections 4.2–4.4 — Basic AVP Data Formats.
fn parse_avp_value<'pkt>(
    avp_type: AvpType,
    data: &'pkt [u8],
    data_offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) -> FieldValue<'pkt> {
    match avp_type {
        // RFC 6733, Section 4.2 — Integer32: 32-bit signed.
        AvpType::Integer32 | AvpType::Enumerated if data.len() == 4 => {
            FieldValue::I32(read_be_i32(data, 0).unwrap_or_default())
        }
        // RFC 6733, Section 4.2 — Unsigned32; Section 4.3.1 — Time (NTP
        // seconds, same wire format, rendered by `format_ntp_time`).
        AvpType::Unsigned32 | AvpType::Time if data.len() == 4 => {
            FieldValue::U32(read_be_u32(data, 0).unwrap_or_default())
        }
        // RFC 6733, Section 4.2 — Unsigned64: 64-bit unsigned.
        AvpType::Unsigned64 if data.len() == 8 => {
            FieldValue::U64(read_be_u64(data, 0).unwrap_or_default())
        }
        // RFC 6733, Section 4.3.1 — UTF8String, DiameterIdentity, DiameterURI.
        AvpType::UTF8String | AvpType::DiameterIdentity | AvpType::DiameterURI => {
            // Zero-copy: borrow directly as bytes (use Bytes since data may not be valid UTF-8).
            match core::str::from_utf8(data) {
                Ok(s) => FieldValue::Str(s),
                Err(_) => FieldValue::Bytes(data),
            }
        }
        // RFC 6733, Section 4.3.1 — Address: 2-byte address family + address bytes.
        AvpType::Address if data.len() >= 2 => {
            let family = read_be_u16(data, 0).unwrap_or_default();
            match (family, data.len()) {
                // IPv4: family=1, 4 address bytes.
                (1, 6) => FieldValue::Ipv4Addr(read_ipv4_addr(data, 2).unwrap_or_default()),
                // IPv6: family=2, 16 address bytes.
                (2, 18) => FieldValue::Ipv6Addr(read_ipv6_addr(data, 2).unwrap_or_default()),
                _ => FieldValue::Bytes(data),
            }
        }
        // RFC 6733, Section 4.4 — Grouped AVP: contains a sequence of AVPs.
        AvpType::Grouped if depth < MAX_GROUPED_DEPTH => {
            // Push a placeholder Array and fill it with nested AVPs.
            let array_idx = buf.begin_container(
                &AVP_CHILD_FIELDS[FD_AVP_VALUE],
                FieldValue::Array(0..0),
                data_offset..data_offset + data.len(),
            );
            parse_avps(data, data_offset, depth + 1, buf);
            buf.end_container(array_idx);
            // Return a sentinel — the actual value was pushed by begin_container.
            // The caller should NOT push this return value.
            FieldValue::Array(0..0) // sentinel
        }
        // RFC 7155, Section 4.4.10.5.1 — Framed-IP-Address: an IPv4 address
        // carried in an OctetString.
        // <https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.1>
        AvpType::Ipv4OctetString if data.len() == 4 => {
            FieldValue::Ipv4Addr(read_ipv4_addr(data, 0).unwrap_or_default())
        }
        // Integer64 and unexpected lengths stay raw bytes.
        _ => FieldValue::Bytes(data),
    }
}

/// Parse a slice of AVP bytes, pushing fields into the buffer.
///
/// `avp_data` is the raw bytes containing AVPs.
/// `buf_offset` is the absolute byte position of `avp_data[0]` in the original packet.
/// `depth` tracks recursion for grouped AVPs.
fn parse_avps<'pkt>(
    avp_data: &'pkt [u8],
    buf_offset: usize,
    depth: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    let mut pos = 0;

    while pos + MIN_AVP_HEADER <= avp_data.len() {
        let avp_code = read_be_u32(avp_data, pos).unwrap_or_default();
        let avp_flags = avp_data[pos + 4];
        let has_vendor = (avp_flags & AVP_FLAG_VENDOR) != 0;

        // AVP Length includes header bytes but NOT padding bytes (RFC 6733, Section 4.1).
        let avp_length = read_be_u24(avp_data, pos + 5).unwrap_or_default() as usize;

        let min_length = if has_vendor { 12 } else { 8 };
        if avp_length < min_length || pos + avp_length > avp_data.len() {
            break;
        }

        let (vendor_id, data_start) = if has_vendor {
            let v = read_be_u32(avp_data, pos + 8).unwrap_or_default();
            (Some(v), pos + 12)
        } else {
            (None, pos + 8)
        };

        let data_end = pos + avp_length;
        let data_slice = &avp_data[data_start..data_end];

        let abs = buf_offset + pos;
        let avp_range = abs..buf_offset + data_end;

        let obj_idx = buf.begin_container(&FD_AVP, FieldValue::Object(0..0), avp_range);

        buf.push_field(
            &AVP_CHILD_FIELDS[FD_AVP_CODE],
            FieldValue::U32(avp_code),
            abs..abs + 4,
        );
        buf.push_field(
            &AVP_CHILD_FIELDS[FD_AVP_FLAGS],
            FieldValue::U8(avp_flags),
            abs + 4..abs + 5,
        );
        for (fd, bit) in [
            (FD_AVP_FLAG_VENDOR, AVP_FLAG_VENDOR),
            (FD_AVP_FLAG_MANDATORY, AVP_FLAG_MANDATORY),
            (FD_AVP_FLAG_PROTECTED, AVP_FLAG_PROTECTED),
        ] {
            buf.push_field(
                &AVP_CHILD_FIELDS[fd],
                FieldValue::U8(u8::from(avp_flags & bit != 0)),
                abs + 4..abs + 5,
            );
        }
        buf.push_field(
            &AVP_CHILD_FIELDS[FD_AVP_LENGTH],
            FieldValue::U32(avp_length as u32),
            abs + 5..abs + 8,
        );

        if let Some(vid) = vendor_id {
            buf.push_field(
                &AVP_CHILD_FIELDS[FD_AVP_VENDOR_ID],
                FieldValue::U32(vid),
                abs + 8..abs + 12,
            );
        }

        let effective_vendor = vendor_id.unwrap_or(0);
        let avp_def = lookup_avp(effective_vendor, avp_code);

        if let Some(def) = avp_def {
            buf.push_field(
                &AVP_CHILD_FIELDS[FD_AVP_NAME],
                FieldValue::Str(def.name),
                abs..abs + 4,
            );
        }

        let data_range = buf_offset + data_start..buf_offset + data_end;

        // For Grouped AVPs, parse_avp_value pushes directly into the buffer.
        // For other types, we push the value as a field.
        let is_grouped =
            avp_def.is_some_and(|d| d.avp_type == AvpType::Grouped) && depth < MAX_GROUPED_DEPTH;
        if is_grouped {
            // parse_avp_value will push the Array container and its children directly
            parse_avp_value(
                AvpType::Grouped,
                data_slice,
                buf_offset + data_start,
                depth,
                buf,
            );
        } else {
            let typed_value = avp_def
                .map(|def| {
                    parse_avp_value(
                        def.avp_type,
                        data_slice,
                        buf_offset + data_start,
                        depth,
                        buf,
                    )
                })
                .unwrap_or_else(|| FieldValue::Bytes(data_slice));
            let descriptor = if avp_def.is_some_and(|d| d.avp_type == AvpType::Time)
                && matches!(typed_value, FieldValue::U32(_))
            {
                &FD_AVP_VALUE_TIME
            } else {
                &AVP_CHILD_FIELDS[FD_AVP_VALUE]
            };
            buf.push_field(descriptor, typed_value, data_range);
            // RFC 4072, Sections 4.1.1 and 4.1.2 — the value is an EAP packet.
            // <https://www.rfc-editor.org/rfc/rfc4072#section-4.1.1>
            #[cfg(feature = "eap")]
            if effective_vendor == 0
                && matches!(
                    avp_code,
                    AVP_CODE_EAP_PAYLOAD | AVP_CODE_EAP_REISSUED_PAYLOAD
                )
            {
                packet_dissector_eap::push_eap_object(
                    &AVP_CHILD_FIELDS[FD_AVP_EAP],
                    data_slice,
                    buf_offset + data_start,
                    buf,
                );
            }
        }

        buf.end_container(obj_idx);

        // RFC 6733, Section 4.1 — AVP data padded to 4-byte boundary.
        // The Length field does NOT include padding bytes.
        let padded = (avp_length + 3) & !3;
        pos += padded;
    }
}

/// Diameter dissector.
pub struct DiameterDissector;

/// Specification references for the Diameter dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 6733",
        "Diameter Base Protocol",
        "https://www.rfc-editor.org/rfc/rfc6733",
    ),
    SpecReference::new(
        "RFC 4006",
        "Diameter Credit-Control Application",
        "https://www.rfc-editor.org/rfc/rfc4006",
    ),
    SpecReference::new(
        "RFC 8506",
        "Diameter Credit-Control Application",
        "https://www.rfc-editor.org/rfc/rfc8506",
    ),
    SpecReference::new(
        "RFC 7155",
        "Diameter Network Access Server Application",
        "https://www.rfc-editor.org/rfc/rfc7155",
    ),
    SpecReference::new(
        "RFC 4072",
        "Diameter Extensible Authentication Protocol (EAP) Application",
        "https://www.rfc-editor.org/rfc/rfc4072",
    ),
    SpecReference::new(
        "3GPP TS 29.061",
        "Interworking between the Public Land Mobile Network (PLMN) supporting packet based services and Packet Data Networks (PDN)",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.061/",
    ),
    SpecReference::new(
        "3GPP TS 29.212",
        "Policy and Charging Control (PCC); Reference points",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.212/",
    ),
    SpecReference::new(
        "3GPP TS 29.214",
        "Policy and Charging Control over Rx reference point",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.214/",
    ),
    SpecReference::new(
        "3GPP TS 29.229",
        "Cx and Dx interfaces based on the Diameter protocol; Protocol details",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.229/",
    ),
    SpecReference::new(
        "3GPP TS 29.272",
        "Evolved Packet System (EPS); Mobility Management Entity (MME) and Serving GPRS Support Node (SGSN) related interfaces based on Diameter protocol",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.272/",
    ),
    SpecReference::new(
        "3GPP TS 29.273",
        "Evolved Packet System (EPS); 3GPP EPS AAA interfaces",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.273/",
    ),
    SpecReference::new(
        "3GPP TS 29.329",
        "Sh Interface based on the Diameter protocol; Protocol details",
        "https://www.3gpp.org/ftp/Specs/archive/29_series/29.329/",
    ),
    SpecReference::new(
        "3GPP TS 32.299",
        "Telecommunication management; Charging management; Diameter charging applications",
        "https://www.3gpp.org/ftp/Specs/archive/32_series/32.299/",
    ),
];

impl Dissector for DiameterDissector {
    fn name(&self) -> &'static str {
        "Diameter"
    }

    fn short_name(&self) -> &'static str {
        "Diameter"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // RFC 6733, Section 3 — Diameter Header (20 bytes minimum).
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Octet 0: Version — MUST be 1.
        let version = data[0];
        if version != 1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }

        // Octets 1–3: Message Length (24-bit big-endian, includes header).
        let message_length = read_be_u24(data, 1)? as usize;
        if message_length < HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "Diameter message length less than header size",
            ));
        }
        if message_length > data.len() {
            return Err(PacketError::Truncated {
                expected: message_length,
                actual: data.len(),
            });
        }
        // RFC 6733, Section 3 — Message Length MUST be a multiple of 4.
        if message_length % 4 != 0 {
            return Err(PacketError::InvalidHeader(
                "Diameter message length is not 4-byte aligned",
            ));
        }

        // Octet 4: Command Flags.
        let command_flags = data[4];
        let is_request = (command_flags & FLAG_REQUEST) != 0;
        let is_proxiable = (command_flags & FLAG_PROXIABLE) != 0;
        let is_error = (command_flags & FLAG_ERROR) != 0;
        let is_retransmit = (command_flags & FLAG_RETRANSMIT) != 0;

        // Octets 5–7: Command Code (24-bit big-endian).
        let command_code = read_be_u24(data, 5)?;

        // Octets 8–11: Application-ID.
        let application_id = read_be_u32(data, 8)?;

        // Octets 12–15: Hop-by-Hop Identifier.
        let hop_by_hop_id = read_be_u32(data, 12)?;

        // Octets 16–19: End-to-End Identifier.
        let end_to_end_id = read_be_u32(data, 16)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + message_length,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_LENGTH],
            FieldValue::U32(message_length as u32),
            offset + 1..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_COMMAND_FLAGS],
            FieldValue::U8(command_flags),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IS_REQUEST],
            FieldValue::U8(u8::from(is_request)),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IS_PROXIABLE],
            FieldValue::U8(u8::from(is_proxiable)),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IS_ERROR],
            FieldValue::U8(u8::from(is_error)),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_IS_RETRANSMIT],
            FieldValue::U8(u8::from(is_retransmit)),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_COMMAND_CODE],
            FieldValue::U32(command_code),
            offset + 5..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_APPLICATION_ID],
            FieldValue::U32(application_id),
            offset + 8..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HOP_BY_HOP_ID],
            FieldValue::U32(hop_by_hop_id),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_END_TO_END_ID],
            FieldValue::U32(end_to_end_id),
            offset + 16..offset + 20,
        );

        // RFC 6733, Section 4 — Parse AVPs that follow the 20-byte header.
        let avp_slice = &data[HEADER_SIZE..message_length];
        if !avp_slice.is_empty() {
            let array_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_AVPS],
                FieldValue::Array(0..0),
                offset + HEADER_SIZE..offset + message_length,
            );
            parse_avps(avp_slice, offset + HEADER_SIZE, 0, buf);
            buf.end_container(array_idx);

            // If no AVPs were actually parsed, remove the empty array.
            let arr = &buf.fields()[array_idx as usize];
            if let FieldValue::Array(ref r) = arr.value {
                if r.start == r.end {
                    buf.truncate_fields(array_idx as usize);
                }
            }
        }

        buf.end_layer();

        Ok(DissectResult::new(message_length, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 6733 (Diameter) Coverage
    //!
    //! | Spec Section         | Description                          | Test                                     |
    //! |----------------------|--------------------------------------|------------------------------------------|
    //! | RFC 6733 §3          | Header fields and command flags      | parse_cer_basic, parse_command_flags     |
    //! | RFC 6733 §3          | Version / length validation          | parse_invalid_version, parse_message_length_* |
    //! | RFC 6733 §3.1        | Command codes                        | parse_all_command_codes                  |
    //! | RFC 6733 §4.1        | AVP header, padding, Vendor-ID       | parse_avp_no_vendor, parse_avp_padding, parse_avp_with_vendor |
    //! | RFC 6733 §4.1        | AVP flags V/M/P split                | parse_avp_flag_bits                      |
    //! | RFC 6733 §4.2        | Basic AVP data formats               | parse_avp_unsigned32, parse_avp_unsigned64, parse_avp_integer32, parse_avp_octet_string |
    //! | RFC 6733 §4.3.1      | Address / UTF8String                 | parse_avp_address_ipv4, parse_avp_address_ipv6, parse_avp_utf8_string |
    //! | RFC 6733 §4.3.1      | Time (NTP seconds, RFC 3339 output)  | parse_avp_time, parse_avp_time_formatted |
    //! | RFC 6733 §4.3.1      | Enumerated value names               | parse_enumerated_value_names             |
    //! | RFC 6733 §4.4        | Grouped AVPs                         | parse_avp_grouped, parse_avp_grouped_nested |
    //! | RFC 6733 §7.1        | Result-Code names                    | parse_avp_result_code_name               |
    //! | RFC 8506 §8          | Credit-Control AVP names             | parse_new_base_avp_names                 |
    //! | RFC 7155 §4.4.10.5.1 | Framed-IP-Address                    | parse_nasreq_framed_ip_address           |
    //! | RFC 4072 §3, §4.1    | Diameter-EAP command, EAP AVPs       | parse_diameter_eap_command_and_applications, parse_new_base_avp_names |
    //! | RFC 4072 §4.1.1-4.1.2| EAP-Payload decoded as EAP (eap)     | parse_eap_payload_decoded, parse_eap_payload_with_vendor_id_zero, parse_eap_payload_malformed_and_vendor_avp_stay_raw |
    //! | TS 29.061 §16a.5     | Gi/SGi 3GPP AVPs                     | parse_3gpp_gi_avps                       |
    //! | TS 29.272 §7.4       | Experimental-Result-Code names       | parse_experimental_result_code_annotation |
    //! | —                    | Truncated / malformed AVPs           | parse_truncated_avp, parse_avp_length_too_small |

    use super::*;

    /// Build a minimal valid Diameter header with no AVPs.
    /// RFC 6733, Section 3: Version=1, Length=20, Flags, Code, AppId, HbH, E2E.
    fn make_header(flags: u8, command_code: u32, app_id: u32, hbh: u32, e2e: u32) -> Vec<u8> {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0] = 1; // version
        data[3] = 0x14; // message_length = 20
        data[4] = flags;
        data[5] = ((command_code >> 16) & 0xFF) as u8;
        data[6] = ((command_code >> 8) & 0xFF) as u8;
        data[7] = (command_code & 0xFF) as u8;
        data[8..12].copy_from_slice(&app_id.to_be_bytes());
        data[12..16].copy_from_slice(&hbh.to_be_bytes());
        data[16..20].copy_from_slice(&e2e.to_be_bytes());
        data
    }

    fn dissect(data: &[u8]) -> Result<(DissectResult, DissectBuffer<'_>), PacketError> {
        let mut buf = DissectBuffer::new();
        let d = DiameterDissector;
        let result = d.dissect(data, &mut buf, 0)?;
        Ok((result, buf))
    }

    fn dissect_err(data: &[u8]) -> PacketError {
        let mut buf = DissectBuffer::new();
        DiameterDissector.dissect(data, &mut buf, 0).unwrap_err()
    }

    fn get_field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        let layer = buf.layers().first()?;
        buf.field_by_name(layer, name).map(|f| &f.value)
    }

    // ── Header parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_cer_basic() {
        // CER: command_code=257, flags=0x80 (Request), app_id=0, hbh=1, e2e=2
        let data = make_header(FLAG_REQUEST, 257, 0, 1, 2);
        let (result, buf) = dissect(&data).unwrap();

        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(get_field(&buf, "version"), Some(&FieldValue::U8(1)));
        assert_eq!(get_field(&buf, "command_code"), Some(&FieldValue::U32(257)));
        assert_eq!(get_field(&buf, "is_request"), Some(&FieldValue::U8(1)));
        assert_eq!(get_field(&buf, "is_proxiable"), Some(&FieldValue::U8(0)));
        assert_eq!(get_field(&buf, "is_error"), Some(&FieldValue::U8(0)));
        assert_eq!(get_field(&buf, "is_retransmit"), Some(&FieldValue::U8(0)));
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Capabilities-Exchange-Request")
        );
        assert_eq!(get_field(&buf, "hop_by_hop_id"), Some(&FieldValue::U32(1)));
        assert_eq!(get_field(&buf, "end_to_end_id"), Some(&FieldValue::U32(2)));
    }

    #[test]
    fn parse_invalid_version() {
        let mut data = make_header(FLAG_REQUEST, 257, 0, 0, 0);
        data[0] = 2; // wrong version
        assert!(matches!(
            dissect_err(&data),
            PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            }
        ));
    }

    #[test]
    fn parse_truncated_header() {
        let data = vec![0x01, 0x00, 0x00]; // only 3 bytes
        assert!(matches!(
            dissect_err(&data),
            PacketError::Truncated {
                expected: 20,
                actual: 3
            }
        ));
    }

    #[test]
    fn parse_message_length_too_small() {
        let mut data = make_header(0, 257, 0, 0, 0);
        // Set message_length = 10 (< HEADER_SIZE=20)
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x0A;
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_message_length_exceeds_data() {
        let mut data = make_header(0, 257, 0, 0, 0);
        // Set message_length = 100 but data is only 20 bytes
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x64;
        assert!(matches!(
            dissect_err(&data),
            PacketError::Truncated { expected: 100, .. }
        ));
    }

    #[test]
    fn parse_message_length_not_aligned() {
        // 21 bytes: valid bounds but not a multiple of 4.
        let mut data = vec![0u8; 21];
        data[0] = 1; // version
        data[3] = 21; // message_length = 21
        assert!(matches!(dissect_err(&data), PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_command_flags() {
        // All flags set: R=1, P=1, E=1, T=1
        let flags = FLAG_REQUEST | FLAG_PROXIABLE | FLAG_ERROR | FLAG_RETRANSMIT;
        let data = make_header(flags, 280, 0, 0, 0);
        let (_, buf) = dissect(&data).unwrap();

        assert_eq!(get_field(&buf, "is_request"), Some(&FieldValue::U8(1)));
        assert_eq!(get_field(&buf, "is_proxiable"), Some(&FieldValue::U8(1)));
        assert_eq!(get_field(&buf, "is_error"), Some(&FieldValue::U8(1)));
        assert_eq!(get_field(&buf, "is_retransmit"), Some(&FieldValue::U8(1)));
        assert_eq!(
            get_field(&buf, "command_flags"),
            Some(&FieldValue::U8(flags))
        );
    }

    #[test]
    fn parse_answer_flag() {
        // No R flag → Answer
        let data = make_header(0, 257, 0, 0, 0);
        let (_, buf) = dissect(&data).unwrap();
        assert_eq!(get_field(&buf, "is_request"), Some(&FieldValue::U8(0)));
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Capabilities-Exchange-Answer")
        );
    }

    #[test]
    fn parse_empty_message() {
        // Valid header, message_length=20, no AVPs
        let data = make_header(FLAG_REQUEST, 280, 0, 0xABCD, 0x1234);
        let (result, buf) = dissect(&data).unwrap();
        assert_eq!(result.bytes_consumed, HEADER_SIZE);
        assert_eq!(get_field(&buf, "application_id"), Some(&FieldValue::U32(0)));
        assert_eq!(
            get_field(&buf, "hop_by_hop_id"),
            Some(&FieldValue::U32(0xABCD))
        );
        assert_eq!(
            get_field(&buf, "end_to_end_id"),
            Some(&FieldValue::U32(0x1234))
        );
    }

    #[test]
    fn parse_all_command_codes() {
        for (code, req_name, ans_name) in [
            (
                257,
                "Capabilities-Exchange-Request",
                "Capabilities-Exchange-Answer",
            ),
            (258, "Re-Auth-Request", "Re-Auth-Answer"),
            (271, "Accounting-Request", "Accounting-Answer"),
            (274, "Abort-Session-Request", "Abort-Session-Answer"),
            (
                275,
                "Session-Termination-Request",
                "Session-Termination-Answer",
            ),
            (280, "Device-Watchdog-Request", "Device-Watchdog-Answer"),
            (282, "Disconnect-Peer-Request", "Disconnect-Peer-Answer"),
        ] {
            let req_data = make_header(FLAG_REQUEST, code, 0, 0, 0);
            let (_, buf) = dissect(&req_data).unwrap();
            let layer = buf.layers().first().unwrap();
            assert_eq!(
                buf.resolve_display_name(layer, "command_code_name"),
                Some(req_name),
                "code {code} request"
            );

            let ans_data = make_header(0, code, 0, 0, 0);
            let (_, buf) = dissect(&ans_data).unwrap();
            let layer = buf.layers().first().unwrap();
            assert_eq!(
                buf.resolve_display_name(layer, "command_code_name"),
                Some(ans_name),
                "code {code} answer"
            );
        }
    }

    // ── AVP loop helpers ────────────────────────────────────────────────────

    /// Build a minimal Diameter message with a single AVP appended.
    ///
    /// The message_length in the header is set correctly.
    fn make_message_with_avp(avp: &[u8]) -> Vec<u8> {
        let total = HEADER_SIZE + avp.len();
        let mut buf = make_header(FLAG_REQUEST, 257, 0, 1, 2);
        buf[1] = ((total >> 16) & 0xFF) as u8;
        buf[2] = ((total >> 8) & 0xFF) as u8;
        buf[3] = (total & 0xFF) as u8;
        buf.extend_from_slice(avp);
        buf
    }

    /// Build a bare AVP header (no vendor, 4-byte-aligned data).
    fn make_avp(code: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let avp_length = 8 + data.len();
        let padded = (avp_length + 3) & !3;
        let mut buf = Vec::with_capacity(padded);
        buf.extend_from_slice(&code.to_be_bytes());
        buf.push(flags);
        buf.push(((avp_length >> 16) & 0xFF) as u8);
        buf.push(((avp_length >> 8) & 0xFF) as u8);
        buf.push((avp_length & 0xFF) as u8);
        buf.extend_from_slice(data);
        buf.resize(padded, 0);
        buf
    }

    /// Build an AVP header with Vendor-ID.
    fn make_vendor_avp(code: u32, flags: u8, vendor_id: u32, data: &[u8]) -> Vec<u8> {
        let avp_length = 12 + data.len();
        let padded = (avp_length + 3) & !3;
        let mut buf = Vec::with_capacity(padded);
        buf.extend_from_slice(&code.to_be_bytes());
        buf.push(flags | AVP_FLAG_VENDOR);
        buf.push(((avp_length >> 16) & 0xFF) as u8);
        buf.push(((avp_length >> 8) & 0xFF) as u8);
        buf.push((avp_length & 0xFF) as u8);
        buf.extend_from_slice(&vendor_id.to_be_bytes());
        buf.extend_from_slice(data);
        buf.resize(padded, 0);
        buf
    }

    /// Get the AVP array range from the buffer.
    fn get_avps_range<'a>(buf: &'a DissectBuffer<'_>) -> Option<&'a core::ops::Range<u32>> {
        let layer = buf.layers().first()?;
        let field = buf.field_by_name(layer, "avps")?;
        match &field.value {
            FieldValue::Array(r) => Some(r),
            _ => None,
        }
    }

    /// Get a field value from an AVP Object at the given index in the array.
    /// Only considers immediate child Objects (skips nested descendants).
    fn avp_field_at<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        array_range: &core::ops::Range<u32>,
        avp_index: usize,
        name: &str,
    ) -> Option<&'a FieldValue<'pkt>> {
        let mut count = 0;
        let mut idx = array_range.start;
        while idx < array_range.end {
            let field = &buf.fields()[idx as usize];
            if let FieldValue::Object(ref obj_range) = field.value {
                if count == avp_index {
                    let obj_fields = buf.nested_fields(obj_range);
                    return obj_fields
                        .iter()
                        .find(|f| f.name() == name)
                        .map(|f| &f.value);
                }
                count += 1;
                idx = obj_range.end;
            } else {
                idx += 1;
            }
        }
        None
    }

    /// Count immediate child Objects in an Array (skip nested descendants).
    fn count_avps(buf: &DissectBuffer<'_>, array_range: &core::ops::Range<u32>) -> usize {
        let mut count = 0;
        let mut idx = array_range.start;
        while idx < array_range.end {
            let field = &buf.fields()[idx as usize];
            if let FieldValue::Object(ref obj_range) = field.value {
                count += 1;
                idx = obj_range.end; // skip past this object's children
            } else {
                idx += 1;
            }
        }
        count
    }

    // ── AVP parsing tests ───────────────────────────────────────────────────

    #[test]
    fn avp_container_resolves_to_avp_name() {
        // Origin-Host (264) — base protocol AVP, no vendor-id.
        let avp = make_avp(264, 0x40, b"test");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();

        let avps_range = get_avps_range(&buf).unwrap().clone();
        let children = buf.nested_fields(&avps_range);
        let (offset, object) = children
            .iter()
            .enumerate()
            .find(|(_, f)| matches!(f.value, FieldValue::Object(_)))
            .expect("AVP Object must be present");
        assert_eq!(object.descriptor.display_name, "AVP");
        let avp_idx = avps_range.start + offset as u32;
        assert_eq!(
            buf.resolve_container_display_name(avp_idx),
            Some("Origin-Host"),
        );
    }

    #[test]
    fn parse_avp_no_vendor() {
        // Origin-Host (264) with 4 bytes of data "test"
        let avp = make_avp(264, 0x40, b"test");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();

        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(count_avps(&buf, avps), 1);
        assert_eq!(
            avp_field_at(&buf, avps, 0, "code"),
            Some(&FieldValue::U32(264))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "flags"),
            Some(&FieldValue::U8(0x40))
        );
        assert_eq!(avp_field_at(&buf, avps, 0, "vendor_id"), None); // no vendor
        // Origin-Host (264) has type DiameterIdentity → Str
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Str("test"))
        );
    }

    #[test]
    fn parse_avp_with_vendor() {
        let avp = make_vendor_avp(1, 0xC0, 10415, b"data");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();

        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(count_avps(&buf, avps), 1);
        assert_eq!(
            avp_field_at(&buf, avps, 0, "vendor_id"),
            Some(&FieldValue::U32(10415))
        );
    }

    #[test]
    fn parse_avp_padding() {
        // "abc" is 3 bytes — padded to 4. The 4th byte (0x00) must NOT appear in value.
        let avp = make_avp(264, 0x40, b"abc");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();

        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(count_avps(&buf, avps), 1);
        // Origin-Host (264) has type DiameterIdentity → Str (padding excluded)
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Str("abc"))
        );
    }

    #[test]
    fn parse_multiple_avps() {
        let mut msg_avps = make_avp(264, 0x40, b"host.example.com");
        msg_avps.extend(make_avp(296, 0x40, b"example.com"));
        let data = make_message_with_avp(&msg_avps);
        let (_, buf) = dissect(&data).unwrap();

        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(count_avps(&buf, avps), 2);
        assert_eq!(
            avp_field_at(&buf, avps, 0, "code"),
            Some(&FieldValue::U32(264))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 1, "code"),
            Some(&FieldValue::U32(296))
        );
    }

    #[test]
    fn parse_truncated_avp() {
        // AVP header truncated to 6 bytes (< MIN_AVP_HEADER=8), padded to 8 for alignment.
        let mut data = make_header(FLAG_REQUEST, 257, 0, 1, 2);
        let truncated_avp = &[0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x00]; // 6 meaningful + 2 pad
        let total = HEADER_SIZE + truncated_avp.len(); // 28 (4-byte aligned)
        data[1] = 0;
        data[2] = 0;
        data[3] = total as u8;
        data.extend_from_slice(truncated_avp);
        let (_, buf) = dissect(&data).unwrap();
        // No avps field expected since truncated AVP is skipped.
        assert!(get_avps_range(&buf).is_none());
    }

    #[test]
    fn parse_avp_length_too_small() {
        // AVP with avp_length=4 (< 8 minimum for no-vendor AVP) — loop should stop.
        let mut avp = make_avp(264, 0x40, b"data");
        // Overwrite length bytes to 4 (too small).
        avp[5] = 0x00;
        avp[6] = 0x00;
        avp[7] = 0x04;
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        assert!(get_avps_range(&buf).is_none());
    }

    #[test]
    fn parse_no_avps_when_empty() {
        let data = make_header(FLAG_REQUEST, 257, 0, 1, 2);
        let (_, buf) = dissect(&data).unwrap();
        assert!(get_avps_range(&buf).is_none());
    }

    // ── Typed AVP value tests ───────────────────────────────────────────────

    #[test]
    fn parse_avp_unsigned32() {
        // Vendor-Id (266): Unsigned32, value = 10415
        let val: u32 = 10415;
        let avp = make_avp(266, 0x40, &val.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::U32(10415))
        );
    }

    #[test]
    fn parse_avp_unsigned64() {
        // Accounting-Sub-Session-Id (287): Unsigned64
        let val: u64 = 0x0102030405060708;
        let avp = make_avp(287, 0x40, &val.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::U64(val))
        );
    }

    #[test]
    fn parse_avp_integer32() {
        // Auth-Request-Type (274): Enumerated (mapped to I32)
        let val: i32 = -1;
        let avp = make_avp(274, 0x40, &val.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::I32(-1))
        );
    }

    #[test]
    fn parse_avp_utf8_string() {
        // Session-Id (263): UTF8String
        let avp = make_avp(263, 0x40, b"host.realm;12345678;1");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Str("host.realm;12345678;1"))
        );
    }

    #[test]
    fn parse_avp_address_ipv4() {
        // Host-IP-Address (257): Address — family=1 (IPv4) + 4 bytes
        let mut addr_data = vec![0x00, 0x01]; // family = 1 (IPv4)
        addr_data.extend_from_slice(&[192, 0, 2, 1]);
        let avp = make_avp(257, 0x40, &addr_data);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Ipv4Addr([192, 0, 2, 1]))
        );
    }

    #[test]
    fn parse_avp_address_ipv6() {
        // Host-IP-Address (257): Address — family=2 (IPv6) + 16 bytes
        let mut addr_data = vec![0x00, 0x02]; // family = 2 (IPv6)
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        addr_data.extend_from_slice(&ipv6);
        let avp = make_avp(257, 0x40, &addr_data);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Ipv6Addr(ipv6))
        );
    }

    #[test]
    fn parse_avp_time() {
        // Event-Timestamp (55): Time — 32-bit NTP seconds
        let ts: u32 = 3829000000;
        let avp = make_avp(55, 0x40, &ts.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::U32(ts))
        );
    }

    #[test]
    fn parse_avp_result_code_name() {
        // Result-Code (268): Unsigned32 + display_fn resolves name
        let rc: u32 = 2001; // DIAMETER_SUCCESS
        let avp = make_avp(268, 0x40, &rc.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::U32(2001))
        );
        // Resolve display name through the Object's fields
        let children = buf.nested_fields(avps);
        let obj = children.iter().find(|f| f.value.is_object()).unwrap();
        if let FieldValue::Object(ref obj_range) = obj.value {
            assert_eq!(
                buf.resolve_nested_display_name(obj_range, "value_name"),
                Some("DIAMETER_SUCCESS")
            );
        }
    }

    #[test]
    fn parse_avp_grouped() {
        // Vendor-Specific-Application-Id (260): Grouped
        // Inner AVPs: Vendor-Id (266, U32=10415) + Auth-Application-Id (258, U32=16777238)
        let inner1 = make_avp(266, 0x40, &10415u32.to_be_bytes());
        let inner2 = make_avp(258, 0x40, &16777238u32.to_be_bytes());
        let mut grouped_data = inner1;
        grouped_data.extend(inner2);
        let avp = make_avp(260, 0x40, &grouped_data);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();

        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(count_avps(&buf, avps), 1);
        // The grouped AVP value should be an Array of child AVPs in the flat buffer.
        match avp_field_at(&buf, avps, 0, "value") {
            Some(FieldValue::Array(inner_range)) => {
                assert_eq!(count_avps(&buf, inner_range), 2);
                assert_eq!(
                    avp_field_at(&buf, inner_range, 0, "code"),
                    Some(&FieldValue::U32(266))
                );
                assert_eq!(
                    avp_field_at(&buf, inner_range, 1, "code"),
                    Some(&FieldValue::U32(258))
                );
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }

    #[test]
    fn parse_avp_unknown() {
        // Unknown AVP code: falls back to raw Bytes.
        let avp = make_avp(9999, 0x00, b"rawdata");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Bytes(b"rawdata"))
        );
        // Unknown AVP has no "name" field.
        assert_eq!(avp_field_at(&buf, avps, 0, "name"), None);
    }

    #[test]
    fn parse_avp_vendor_specific() {
        // Vendor-specific AVP with vendor_id=10415 (3GPP), unknown code=9999 → raw bytes.
        let avp = make_vendor_avp(9999, 0xC0, 10415, b"\x00\x01\x02\x03");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "vendor_id"),
            Some(&FieldValue::U32(10415))
        );
        // Unknown 3GPP AVP code → Bytes
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Bytes(b"\x00\x01\x02\x03"))
        );
    }

    #[test]
    fn parse_avp_grouped_nested() {
        // Nested grouped: outer wraps inner Vendor-Specific-Application-Id (260).
        // Inner grouped (260) wraps Vendor-Id (266).
        let innermost = make_avp(266, 0x40, &10415u32.to_be_bytes());
        let inner_grouped = make_avp(260, 0x40, &innermost);
        let outer_grouped = make_avp(297, 0x40, &inner_grouped); // Experimental-Result (297)
        let data = make_message_with_avp(&outer_grouped);
        let (_, buf) = dissect(&data).unwrap();

        let avps = get_avps_range(&buf).unwrap();
        // outer_grouped (Experimental-Result) → children[0] = inner_grouped
        match avp_field_at(&buf, avps, 0, "value") {
            Some(FieldValue::Array(level1)) => {
                assert_eq!(count_avps(&buf, level1), 1);
                // Inner AVP (Vendor-Specific-App-Id) has a "value" which is a Grouped Array
                match avp_field_at(&buf, level1, 0, "value") {
                    Some(FieldValue::Array(level2)) => {
                        assert_eq!(count_avps(&buf, level2), 1);
                        assert_eq!(
                            avp_field_at(&buf, level2, 0, "code"),
                            Some(&FieldValue::U32(266))
                        );
                    }
                    other => panic!("level2 expected Array, got {other:?}"),
                }
            }
            other => panic!("level1 expected Array, got {other:?}"),
        }
    }

    #[test]
    fn parse_avp_octet_string() {
        // Class (25): OctetString — arbitrary bytes.
        let raw = b"\xDE\xAD\xBE\xEF";
        let avp = make_avp(25, 0x40, raw);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Bytes(raw))
        );
    }

    // ── Command code tests ──────────────────────────────────────────────────

    #[test]
    fn parse_unknown_command_code() {
        let data = make_header(FLAG_REQUEST, 9999, 0, 0, 0);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Unknown")
        );
    }

    // ── 3GPP TS 29.272 S6a/S6d tests ───────────────────────────────────────

    #[test]
    fn parse_s6a_ulr_header() {
        // ULR: command_code=316, flags=0xC0 (Request+Proxiable), app_id=16777251
        let data = make_header(FLAG_REQUEST | FLAG_PROXIABLE, 316, 16777251, 100, 200);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Update-Location-Request")
        );
        assert_eq!(
            get_field(&buf, "application_id"),
            Some(&FieldValue::U32(16777251))
        );
        assert_eq!(
            buf.resolve_display_name(layer, "application_id_name"),
            Some("3GPP S6a/S6d")
        );
    }

    #[test]
    fn parse_s6a_aia_header() {
        // AIA: command_code=318, flags=0x40 (Proxiable, no Request), app_id=16777251
        let data = make_header(FLAG_PROXIABLE, 318, 16777251, 100, 200);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Authentication-Information-Answer")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "application_id_name"),
            Some("3GPP S6a/S6d")
        );
    }

    #[test]
    fn parse_application_name_base() {
        // Base protocol CER: app_id=0
        let data = make_header(FLAG_REQUEST, 257, 0, 1, 2);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "application_id_name"),
            Some("Diameter Common Messages")
        );
    }

    #[test]
    fn parse_3gpp_vendor_avp_name() {
        // Visited-PLMN-Id (code=1407, vendor_id=10415): OctetString
        let plmn = b"\x09\xF1\x07"; // MCC=901, MNC=70
        let avp = make_vendor_avp(1407, 0xC0, 10415, plmn);
        // Build S6a ULR message (316, Request+Proxiable, app_id=16777251)
        let mut data = make_header(FLAG_REQUEST | FLAG_PROXIABLE, 316, 16777251, 1, 2);
        let total = HEADER_SIZE + avp.len();
        // Round up to 4-byte boundary for message length
        let total_aligned = (total + 3) & !3;
        data[1] = ((total_aligned >> 16) & 0xFF) as u8;
        data[2] = ((total_aligned >> 8) & 0xFF) as u8;
        data[3] = (total_aligned & 0xFF) as u8;
        data.extend_from_slice(&avp);
        // Pad to 4-byte boundary
        while data.len() < total_aligned {
            data.push(0);
        }

        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(count_avps(&buf, avps), 1);
        assert_eq!(
            avp_field_at(&buf, avps, 0, "code"),
            Some(&FieldValue::U32(1407))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "vendor_id"),
            Some(&FieldValue::U32(10415))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "name"),
            Some(&FieldValue::Str("Visited-PLMN-Id"))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Bytes(plmn))
        );
    }

    #[test]
    fn parse_experimental_result_code_annotation() {
        // Experimental-Result-Code (298): Unsigned32, value=5420
        // TS 29.272 — DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION
        let rc: u32 = 5420;
        let avp = make_avp(298, 0x40, &rc.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::U32(5420))
        );
        // Resolve display name through the Object's fields
        let children = buf.nested_fields(avps);
        let obj = children.iter().find(|f| f.value.is_object()).unwrap();
        if let FieldValue::Object(ref obj_range) = obj.value {
            assert_eq!(
                buf.resolve_nested_display_name(obj_range, "value_name"),
                Some("DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION")
            );
        }
    }

    /// Return the Object range of the `index`-th top-level AVP.
    fn avp_obj_range(buf: &DissectBuffer<'_>, index: usize) -> core::ops::Range<u32> {
        let avps = get_avps_range(buf).unwrap().clone();
        let mut count = 0;
        let mut idx = avps.start;
        while idx < avps.end {
            if let FieldValue::Object(ref r) = buf.fields()[idx as usize].value {
                if count == index {
                    return r.clone();
                }
                count += 1;
                idx = r.end;
            } else {
                idx += 1;
            }
        }
        panic!("AVP {index} not found");
    }

    /// Run the `format_fn` of the `value` field of the first AVP.
    fn format_first_value(buf: &DissectBuffer<'_>) -> String {
        let obj = avp_obj_range(buf, 0);
        let field = buf
            .nested_fields(&obj)
            .iter()
            .find(|f| f.name() == "value")
            .unwrap();
        let ctx = packet_dissector_core::field::FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        (field.descriptor.format_fn.expect("format_fn"))(&field.value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn parse_avp_flag_bits() {
        // RFC 6733, Section 4.1 — V (0x80), M (0x40), P (0x20).
        // <https://www.rfc-editor.org/rfc/rfc6733#section-4.1>
        let avp = make_vendor_avp(1407, 0x40 | 0x20, 10415, b"\x09\xF1\x07");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "flags"),
            Some(&FieldValue::U8(0xE0))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "flag_vendor"),
            Some(&FieldValue::U8(1))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "flag_mandatory"),
            Some(&FieldValue::U8(1))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "flag_protected"),
            Some(&FieldValue::U8(1))
        );

        let avp = make_avp(264, 0x00, b"test");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        for name in ["flag_vendor", "flag_mandatory", "flag_protected"] {
            assert_eq!(avp_field_at(&buf, avps, 0, name), Some(&FieldValue::U8(0)));
        }
    }

    #[test]
    fn parse_avp_time_formatted() {
        // RFC 6733, Section 4.3.1 — NTP seconds since 1900-01-01.
        // <https://www.rfc-editor.org/rfc/rfc6733#section-4.3.1>
        // 3_913_056_000 = 2024-01-01T00:00:00Z.
        let avp = make_avp(55, 0x40, &3_913_056_000u32.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        assert_eq!(format_first_value(&buf), "\"2024-01-01T00:00:00Z\"");

        // MSB clear: era 1, counted from 2036-02-07T06:28:16Z (RFC 4330,
        // Section 3, referenced by RFC 6733, Section 4.3.1).
        // <https://www.rfc-editor.org/rfc/rfc4330#section-3>
        let avp = make_avp(55, 0x40, &1u32.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        assert_eq!(format_first_value(&buf), "\"2036-02-07T06:28:17Z\"");
    }

    #[test]
    fn parse_enumerated_value_names() {
        // RFC 8506, Section 8.3 — CC-Request-Type (416) = INITIAL_REQUEST (1).
        // <https://www.rfc-editor.org/rfc/rfc8506#section-8.3>
        let avp = make_avp(416, 0x40, &1u32.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let obj = avp_obj_range(&buf, 0);
        assert_eq!(
            avp_field_at(&buf, get_avps_range(&buf).unwrap(), 0, "value"),
            Some(&FieldValue::I32(1))
        );
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("INITIAL_REQUEST")
        );

        // RFC 6733, Section 8.11 — Auth-Session-State (277) = NO_STATE_MAINTAINED (1).
        // <https://www.rfc-editor.org/rfc/rfc6733#section-8.11>
        let avp = make_avp(277, 0x40, &1u32.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let obj = avp_obj_range(&buf, 0);
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("NO_STATE_MAINTAINED")
        );

        // 3GPP TS 29.212, clause 5.3.31 — RAT-Type (1032) = EUTRAN (1004).
        let avp = make_vendor_avp(1032, 0x80, 10415, &1004u32.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let obj = avp_obj_range(&buf, 0);
        assert_eq!(
            buf.resolve_nested_display_name(&obj, "value_name"),
            Some("EUTRAN")
        );

        // Unknown enumeration value: no name.
        let avp = make_avp(416, 0x40, &99u32.to_be_bytes());
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let obj = avp_obj_range(&buf, 0);
        assert_eq!(buf.resolve_nested_display_name(&obj, "value_name"), None);
    }

    #[test]
    fn grouped_avp_name_ignores_nested_vendor_id() {
        // RFC 8506, Section 8.16 — Multiple-Services-Credit-Control (456,
        // vendor 0) carrying a 3GPP AVP (RAT-Type, vendor 10415). The parent
        // label and value names must come from the parent's own header.
        // <https://www.rfc-editor.org/rfc/rfc8506#section-8.16>
        let inner = make_vendor_avp(1032, 0x80, 10415, &1004u32.to_be_bytes());
        let avp = make_avp(456, 0x40, &inner);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps_range = get_avps_range(&buf).unwrap().clone();
        let children = buf.nested_fields(&avps_range);
        let offset = children.iter().position(|f| f.value.is_object()).unwrap();
        assert_eq!(
            buf.resolve_container_display_name(avps_range.start + offset as u32),
            Some("Multiple-Services-Credit-Control")
        );
    }

    #[test]
    fn parse_nasreq_framed_ip_address() {
        // RFC 7155, Section 4.4.10.5.1 — Framed-IP-Address (8), IPv4 in an
        // OctetString.
        // <https://www.rfc-editor.org/rfc/rfc7155#section-4.4.10.5.1>
        let avp = make_avp(8, 0x40, &[10, 0, 0, 1]);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "name"),
            Some(&FieldValue::Str("Framed-IP-Address"))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Ipv4Addr([10, 0, 0, 1]))
        );
        // Not 4 octets: raw bytes.
        let avp = make_avp(8, 0x40, &[10, 0, 0, 1, 2, 3, 4, 5]);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Bytes(&[10, 0, 0, 1, 2, 3, 4, 5]))
        );
    }

    #[test]
    fn parse_new_base_avp_names() {
        let cases: &[(u32, &str)] = &[
            (30, "Called-Station-Id"),
            (31, "Calling-Station-Id"),
            (413, "CC-Money"),
            (430, "Final-Unit-Indication"),
            (431, "Granted-Service-Unit"),
            (445, "Unit-Value"),
            (446, "Used-Service-Unit"),
            (448, "Validity-Time"),
            (449, "Final-Unit-Action"),
            (456, "Multiple-Services-Credit-Control"),
            (458, "User-Equipment-Info"),
            (462, "EAP-Payload"),
            (463, "EAP-Reissued-Payload"),
            (464, "EAP-Master-Session-Key"),
            (465, "Accounting-EAP-Auth-Method"),
        ];
        for (code, name) in cases {
            let avp = make_avp(*code, 0x40, &[0, 0, 0, 1]);
            let data = make_message_with_avp(&avp);
            let (_, buf) = dissect(&data).unwrap();
            let avps = get_avps_range(&buf).unwrap();
            assert_eq!(
                avp_field_at(&buf, avps, 0, "name"),
                Some(&FieldValue::Str(name)),
                "AVP {code}"
            );
        }
    }

    #[cfg(feature = "eap")]
    #[test]
    fn parse_eap_payload_decoded() {
        // RFC 4072, Section 4.1.1 — EAP-Payload carries an EAP packet; 4.1.2
        // EAP-Reissued-Payload too.
        // https://www.rfc-editor.org/rfc/rfc4072#section-4.1.1
        for code in [462u32, 463] {
            let avp = make_avp(code, 0x40, &[0x01, 0x03, 0x00, 0x05, 0x01]);
            let data = make_message_with_avp(&avp);
            let (_, buf) = dissect(&data).unwrap();
            let avps = get_avps_range(&buf).unwrap();
            assert!(avp_field_at(&buf, avps, 0, "value").is_some());
            let eap = avp_field_at(&buf, avps, 0, "eap").unwrap();
            assert!(matches!(eap, FieldValue::Object(_)), "AVP {code}");
            let eap = eap.as_container_range().unwrap();
            assert_eq!(
                buf.resolve_nested_display_name(eap, "code_name"),
                Some("Request")
            );
            assert_eq!(
                buf.resolve_nested_display_name(eap, "type_name"),
                Some("Identity")
            );
        }
    }

    #[cfg(feature = "eap")]
    #[test]
    fn parse_eap_payload_with_vendor_id_zero() {
        // V bit set with Vendor-Id 0 is the IETF AVP (named EAP-Payload), so
        // it is decoded too.
        let avp = make_vendor_avp(462, 0x40, 0, &[0x03, 0x04, 0x00, 0x04]);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "name"),
            Some(&FieldValue::Str("EAP-Payload"))
        );
        assert!(matches!(
            avp_field_at(&buf, avps, 0, "eap"),
            Some(FieldValue::Object(_))
        ));
    }

    #[cfg(feature = "eap")]
    #[test]
    fn parse_eap_payload_malformed_and_vendor_avp_stay_raw() {
        // Malformed EAP (Length 9 > 5 octets): raw value only.
        let avp = make_avp(462, 0x40, &[0x01, 0x03, 0x00, 0x09, 0x01]);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert!(avp_field_at(&buf, avps, 0, "eap").is_none());
        // A 3GPP vendor AVP with code 462 is not EAP-Payload.
        let avp = make_vendor_avp(462, 0x80, 10415, &[0x01, 0x03, 0x00, 0x05, 0x01]);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert!(avp_field_at(&buf, avps, 0, "eap").is_none());
    }

    #[test]
    fn parse_3gpp_gi_avps() {
        // TS 29.061, clause 16a.5 — 3GPP-RAT-Type (21, vendor 10415).
        let avp = make_vendor_avp(21, 0x80, 10415, &[0x06]);
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "name"),
            Some(&FieldValue::Str("3GPP-RAT-Type"))
        );
        // 3GPP-IMSI (1) is a UTF8String.
        let avp = make_vendor_avp(1, 0x80, 10415, b"001010123456789");
        let data = make_message_with_avp(&avp);
        let (_, buf) = dissect(&data).unwrap();
        let avps = get_avps_range(&buf).unwrap();
        assert_eq!(
            avp_field_at(&buf, avps, 0, "name"),
            Some(&FieldValue::Str("3GPP-IMSI"))
        );
        assert_eq!(
            avp_field_at(&buf, avps, 0, "value"),
            Some(&FieldValue::Str("001010123456789"))
        );
    }

    #[test]
    fn parse_diameter_eap_command_and_applications() {
        // RFC 4072, Section 3.1 / 3.2 — Diameter-EAP-Request/Answer (268).
        // <https://www.rfc-editor.org/rfc/rfc4072#section-3>
        let data = make_header(FLAG_REQUEST | FLAG_PROXIABLE, 268, 5, 1, 2);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Diameter-EAP-Request")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "application_id_name"),
            Some("Diameter EAP")
        );
        let data = make_header(FLAG_PROXIABLE, 268, 16777250, 1, 2);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "command_code_name"),
            Some("Diameter-EAP-Answer")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "application_id_name"),
            Some("3GPP STa")
        );
        let data = make_header(FLAG_REQUEST, 265, 1, 1, 2);
        let (_, buf) = dissect(&data).unwrap();
        let layer = buf.layers().first().unwrap();
        assert_eq!(
            buf.resolve_display_name(layer, "application_id_name"),
            Some("NASREQ")
        );
    }

    /// Every dissector in this crate must cite the specifications it
    /// implements and declare where it sits in the dissection stack.
    #[test]
    fn references_and_layer_are_populated() {
        fn assert_layer_and_references(dissector: &dyn Dissector) {
            let references = dissector.references();
            assert!(!references.is_empty());
            for reference in references {
                assert!(!reference.id.is_empty());
                assert!(!reference.title.is_empty());
                assert!(
                    reference.url.starts_with("https://"),
                    "{} url must start with https://",
                    reference.id
                );
            }
            assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
        }

        assert_layer_and_references(&DiameterDissector);
    }
}
