//! NTP (Network Time Protocol) dissector.
//!
//! ## References
//! - RFC 5905 (NTPv4): <https://www.rfc-editor.org/rfc/rfc5905>
//! - RFC 7822 (Extension Fields update): <https://www.rfc-editor.org/rfc/rfc7822>
//! - RFC 8573 (AES-CMAC for NTP): <https://www.rfc-editor.org/rfc/rfc8573>
//! - RFC 9109 (Port Randomization): <https://www.rfc-editor.org/rfc/rfc9109>
//! - RFC 9748 (IANA Registry updates): <https://www.rfc-editor.org/rfc/rfc9748>
//! - RFC 9769 (Interleaved Modes): <https://www.rfc-editor.org/rfc/rfc9769>
//! - RFC 9327 (Control Messages, mode 6; Historic):
//!   <https://www.rfc-editor.org/rfc/rfc9327>
//!
//! The layout is selected by the Mode field:
//!
//! - Modes 0-5: the 48-octet fixed NTPv4 header (RFC 5905, Section 7.3).
//!   Extension fields and MACs after the header are not dissected.
//! - Mode 6: the NTP Control Message header and data (RFC 9327, Section 2).
//! - Mode 7: "reserved for private use" (RFC 5905, Section 7.3); only the
//!   Version and Mode are decoded and the rest is kept as raw data.

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_be_u64};

/// Format NTP reference_id: stratum 0-1 as ASCII code, stratum 2+ as IPv4 address.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>:
/// for stratum 0 the field is a 4-character ASCII "kiss code" (KoD); for
/// stratum 1 it is a left-justified, zero-padded ASCII identifier of the
/// reference clock (e.g., "GPS", "PPS"); for stratum 2+ it is an IPv4
/// address (or the first four octets of the MD5 hash of an IPv6 address).
fn format_ntp_ref_id(
    value: &FieldValue<'_>,
    _ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes = match value {
        FieldValue::Bytes(b) if b.len() == 4 => *b,
        _ => return w.write_all(b"\"\""),
    };
    // If all bytes are printable ASCII (0x20..=0x7E) or null padding, treat as ASCII code.
    if bytes.iter().all(|&b| b == 0 || (0x20..=0x7E).contains(&b)) {
        let s: String = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        write!(w, "\"{s}\"")
    } else {
        write!(w, "\"{}.{}.{}.{}\"", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// NTP fixed header size in bytes.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>:
/// "The NTP packet is a UDP datagram [RFC0768]. ... The packet consists of an
/// integral number of 32-bit (4 octet) words in network byte order."  The
/// fixed header is 12 words (48 octets).
const HEADER_SIZE: usize = 48;

/// NTP Control Message header size in bytes.
///
/// RFC 9327, Section 2 — <https://www.rfc-editor.org/rfc/rfc9327#section-2>,
/// Figure 1: three 32-bit words precede the Data field.
const CONTROL_HEADER_SIZE: usize = 12;

/// Mode value for NTP control messages.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
const MODE_CONTROL: u8 = 6;

/// Mode value reserved for private use.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
const MODE_PRIVATE: u8 = 7;

/// Returns the meaning of an NTP control message operation code.
///
/// RFC 9327, Section 2, Table 1 —
/// <https://www.rfc-editor.org/rfc/rfc9327#section-2>.
fn control_opcode_name(opcode: u8) -> &'static str {
    // Verbatim from RFC 9327, Table 1.
    //   <https://www.rfc-editor.org/rfc/rfc9327>
    match opcode {
        1 => "read status command/response",
        2 => "read variables command/response",
        3 => "write variables command/response",
        4 => "read clock variables command/response",
        5 => "write clock variables command/response",
        6 => "set trap address/port command/response",
        7 => "trap response",
        8 => "runtime configuration command/response",
        9 => "export configuration to file command/response",
        10 => "retrieve remote address stats command/response",
        11 => "retrieve ordered list command/response",
        12 => "request client-specific nonce command/response",
        31 => "unset trap address/port command/response",
        _ => "reserved",
    }
}

/// Returns a human-readable name for the Leap Indicator value.
///
/// RFC 5905, Section 7.3, Figure 9 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn leap_indicator_name(li: u8) -> &'static str {
    // Verbatim from RFC 5905, Figure 9.
    match li {
        0 => "no warning",
        1 => "last minute of the day has 61 seconds",
        2 => "last minute of the day has 59 seconds",
        3 => "unknown (clock unsynchronized)",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Mode value.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn mode_name(mode: u8) -> &'static str {
    // Verbatim from RFC 5905, Figure 10.
    match mode {
        0 => "reserved",
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "NTP control message",
        7 => "reserved for private use",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Stratum value.
///
/// RFC 5905, Section 7.3, Figure 11 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn stratum_name(stratum: u8) -> &'static str {
    // Verbatim from RFC 5905, Figure 11. Stratum 0 is also referred to as
    // "Kiss-o'-Death" in Section 7.4 when carried in a received packet.
    match stratum {
        0 => "unspecified or invalid",
        1 => "primary server",
        2..=15 => "secondary server",
        16 => "unsynchronized",
        _ => "reserved",
    }
}

/// Returns a human-readable name for a Kiss-o'-Death code.
///
/// RFC 5905, Section 7.4, Figure 13 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.4>.
///
/// Per RFC 9748, codes beginning with "X" are reserved for experimental use;
/// the registry is maintained by IANA with a Specification Required policy
/// (<https://www.rfc-editor.org/rfc/rfc9748>).
pub fn kod_name(code: &str) -> Option<&'static str> {
    // Verbatim meanings from RFC 5905, Figure 13.
    match code {
        "ACST" => Some("The association belongs to a unicast server"),
        "AUTH" => Some("Server authentication failed"),
        "AUTO" => Some("Autokey sequence failed"),
        "BCST" => Some("The association belongs to a broadcast server"),
        "CRYP" => Some("Cryptographic authentication or identification failed"),
        "DENY" => Some("Access denied by remote server"),
        "DROP" => Some("Lost peer in symmetric mode"),
        "RSTR" => Some("Access denied due to local policy"),
        "INIT" => Some("The association has not yet synchronized for the first time"),
        "MCST" => Some("The association belongs to a dynamically discovered server"),
        "NKEY" => Some("No key found. Either the key was never installed or is not trusted"),
        "RATE" => Some(
            "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold",
        ),
        "RMOT" => Some("Alteration of association from a remote host running ntpdc"),
        "STEP" => Some(
            "A step change in system time has occurred, but the association has not yet resynchronized",
        ),
        _ => None,
    }
}

/// Index constants for `FIELD_DESCRIPTORS`.
const FD_LEAP_INDICATOR: usize = 0;
const FD_VERSION: usize = 1;
const FD_MODE: usize = 2;
const FD_STRATUM: usize = 3;
const FD_POLL: usize = 4;
const FD_PRECISION: usize = 5;
const FD_ROOT_DELAY: usize = 6;
const FD_ROOT_DISPERSION: usize = 7;
const FD_REFERENCE_ID: usize = 8;
const FD_REFERENCE_TIMESTAMP: usize = 9;
const FD_ORIGIN_TIMESTAMP: usize = 10;
const FD_RECEIVE_TIMESTAMP: usize = 11;
const FD_TRANSMIT_TIMESTAMP: usize = 12;
// RFC 9327, Section 2 — NTP Control Message (mode 6) fields.
//   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
const FD_RESPONSE: usize = 13;
const FD_ERROR: usize = 14;
const FD_MORE: usize = 15;
const FD_OPCODE: usize = 16;
const FD_SEQUENCE: usize = 17;
const FD_STATUS: usize = 18;
const FD_ASSOCIATION_ID: usize = 19;
const FD_OFFSET: usize = 20;
const FD_COUNT: usize = 21;
const FD_DATA: usize = 22;
const FD_PADDING: usize = 23;
const FD_AUTHENTICATOR: usize = 24;

/// Layer name used for every NTP mode.
const SHORT_NAME: &str = "NTP";

/// NTP dissector.
pub struct NtpDissector;

/// Specification references for the NTP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 5905",
        "Network Time Protocol Version 4: Protocol and Algorithms Specification",
        "https://www.rfc-editor.org/rfc/rfc5905",
    ),
    SpecReference::new(
        "RFC 7822",
        "Network Time Protocol Version 4 (NTPv4) Extension Fields",
        "https://www.rfc-editor.org/rfc/rfc7822",
    ),
    SpecReference::new(
        "RFC 8573",
        "Message Authentication Code for the Network Time Protocol",
        "https://www.rfc-editor.org/rfc/rfc8573",
    ),
    SpecReference::new(
        "RFC 9109",
        "Network Time Protocol Version 4: Port Randomization",
        "https://www.rfc-editor.org/rfc/rfc9109",
    ),
    SpecReference::new(
        "RFC 9748",
        "Updating the NTP Registries",
        "https://www.rfc-editor.org/rfc/rfc9748",
    ),
    SpecReference::new(
        "RFC 9769",
        "NTP Interleaved Modes",
        "https://www.rfc-editor.org/rfc/rfc9769",
    ),
    SpecReference::new(
        "RFC 9327",
        "Control Messages Protocol for Use with Network Time Protocol Version 4",
        "https://www.rfc-editor.org/rfc/rfc9327",
    ),
];

/// Field descriptors for the NTP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "leap_indicator",
        display_name: "Leap Indicator",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(li) => Some(leap_indicator_name(*li)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("version", "Version Number", FieldType::U8),
    FieldDescriptor {
        name: "mode",
        display_name: "Mode",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(m) => Some(mode_name(*m)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "stratum",
        display_name: "Stratum",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => Some(stratum_name(*s)),
            _ => None,
        }),
        format_fn: None,
    },
    // Fields below are present for modes 0-5 only (RFC 5905, Section 7.3).
    //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
    FieldDescriptor::new("poll", "Poll Interval", FieldType::I32).optional(),
    FieldDescriptor::new("precision", "Precision", FieldType::I32).optional(),
    FieldDescriptor::new("root_delay", "Root Delay", FieldType::U32).optional(),
    FieldDescriptor::new("root_dispersion", "Root Dispersion", FieldType::U32).optional(),
    FieldDescriptor::new("reference_id", "Reference ID", FieldType::Bytes)
        .optional()
        .with_format_fn(format_ntp_ref_id),
    FieldDescriptor::new("reference_timestamp", "Reference Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("origin_timestamp", "Origin Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("receive_timestamp", "Receive Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("transmit_timestamp", "Transmit Timestamp", FieldType::U64).optional(),
    // Fields below are present for mode 6 only (RFC 9327, Section 2).
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    FieldDescriptor::new("response", "Response Bit", FieldType::U8).optional(),
    FieldDescriptor::new("error", "Error Bit", FieldType::U8).optional(),
    FieldDescriptor::new("more", "More Bit", FieldType::U8).optional(),
    FieldDescriptor {
        name: "opcode",
        display_name: "Operation Code",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(op) => Some(control_opcode_name(*op)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("sequence", "Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("status", "Status", FieldType::U16).optional(),
    FieldDescriptor::new("association_id", "Association ID", FieldType::U16).optional(),
    FieldDescriptor::new("offset", "Offset", FieldType::U16).optional(),
    FieldDescriptor::new("count", "Count", FieldType::U16).optional(),
    // Mode 6 Data, or the raw body of a mode 7 message.
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
    FieldDescriptor::new("authenticator", "Authenticator", FieldType::Bytes).optional(),
];

impl Dissector for NtpDissector {
    fn name(&self) -> &'static str {
        "Network Time Protocol"
    }

    fn short_name(&self) -> &'static str {
        SHORT_NAME
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
        let Some(&first_byte) = data.first() else {
            return Err(PacketError::Truncated {
                expected: 1,
                actual: 0,
            });
        };

        // RFC 5905, Section 7.3 — first octet: LI (2 bits) | VN (3 bits) | Mode (3 bits).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let li = (first_byte >> 6) & 0x03;
        let vn = (first_byte >> 3) & 0x07;
        let mode = first_byte & 0x07;

        match mode {
            MODE_CONTROL => return dissect_control(data, buf, offset, li, vn, mode),
            MODE_PRIVATE => return dissect_private(data, buf, offset, vn, mode),
            _ => {}
        }

        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let stratum = data[1];
        // RFC 5905, Section 7.3 — Poll and Precision are signed 8-bit integers
        // (log2 seconds).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let poll = data[2] as i8 as i32;
        let precision = data[3] as i8 as i32;

        // RFC 5905, Section 6 (Figure 3, "NTP Short Format"): Root Delay and
        // Root Dispersion are each a 16-bit unsigned seconds field followed by
        // a 16-bit fraction field, i.e. unsigned 16.16 fixed-point.
        // https://www.rfc-editor.org/rfc/rfc5905#section-6
        let root_delay = read_be_u32(data, 4)?;
        let root_dispersion = read_be_u32(data, 8)?;

        // RFC 5905, Section 6 (Figure 4, "NTP Timestamp Format"): 32-bit
        // unsigned seconds plus 32-bit fraction. A value of zero is a special
        // case representing unknown or unsynchronized time (Section 7.3).
        // https://www.rfc-editor.org/rfc/rfc5905#section-6
        let reference_ts = read_be_u64(data, 16)?;
        let origin_ts = read_be_u64(data, 24)?;
        let receive_ts = read_be_u64(data, 32)?;
        let transmit_ts = read_be_u64(data, 40)?;

        buf.begin_layer(
            SHORT_NAME,
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
        push_first_octet(buf, offset, Some(li), vn, mode);
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_STRATUM],
            FieldValue::U8(stratum),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_POLL],
            FieldValue::I32(poll),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PRECISION],
            FieldValue::I32(precision),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_DELAY],
            FieldValue::U32(root_delay),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROOT_DISPERSION],
            FieldValue::U32(root_dispersion),
            offset + 8..offset + 12,
        );
        // For stratum 0 (KoD) and stratum 1 (primary), Reference ID is a
        // four-character ASCII string. For stratum 2+, it is implementation-
        // dependent (commonly an IPv4 address — RFC 5905, Section 7.3).
        // Store raw bytes; formatted by format_ntp_ref_id via format_fn.
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REFERENCE_ID],
            FieldValue::Bytes(&data[12..16]),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REFERENCE_TIMESTAMP],
            FieldValue::U64(reference_ts),
            offset + 16..offset + 24,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ORIGIN_TIMESTAMP],
            FieldValue::U64(origin_ts),
            offset + 24..offset + 32,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_RECEIVE_TIMESTAMP],
            FieldValue::U64(receive_ts),
            offset + 32..offset + 40,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TRANSMIT_TIMESTAMP],
            FieldValue::U64(transmit_ts),
            offset + 40..offset + 48,
        );
        buf.end_layer();

        Ok(DissectResult::new(HEADER_SIZE, DispatchHint::End))
    }
}

/// Pushes the LI / VN / Mode fields of the first octet.
///
/// RFC 5905, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>.
fn push_first_octet<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    li: Option<u8>,
    vn: u8,
    mode: u8,
) {
    if let Some(li) = li {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LEAP_INDICATOR],
            FieldValue::U8(li),
            offset..offset + 1,
        );
    }
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_VERSION],
        FieldValue::U8(vn),
        offset..offset + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_MODE],
        FieldValue::U8(mode),
        offset..offset + 1,
    );
}

/// Dissects an NTP Control Message (mode 6).
///
/// RFC 9327, Section 2 — <https://www.rfc-editor.org/rfc/rfc9327#section-2>.
fn dissect_control<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    li: u8,
    vn: u8,
    mode: u8,
) -> Result<DissectResult, PacketError> {
    if data.len() < CONTROL_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: CONTROL_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // RFC 9327, Section 2, Figure 1 — second octet: R | E | M | opcode (5 bits).
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let byte1 = data[1];
    let response = (byte1 >> 7) & 0x01;
    let error = (byte1 >> 6) & 0x01;
    let more = (byte1 >> 5) & 0x01;
    let opcode = byte1 & 0x1F;
    let sequence = read_be_u16(data, 2)?;
    let status = read_be_u16(data, 4)?;
    let association_id = read_be_u16(data, 6)?;
    let data_offset = read_be_u16(data, 8)?;
    // RFC 9327, Section 2 — "Count: This is a 16-bit unsigned integer
    // indicating the length of the data field, in octets."
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let count = read_be_u16(data, 10)?;

    let data_end = CONTROL_HEADER_SIZE + count as usize;
    if data.len() < data_end {
        return Err(PacketError::Truncated {
            expected: data_end,
            actual: data.len(),
        });
    }

    // RFC 9327, Section 2 — "Padding (optional): Contains zero to 3 octets
    // with a value of zero, as needed to ensure the overall control message
    // size is a multiple of 4 octets." Anything after the padding is the
    // optional Authenticator.
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let padding_end = (data_end + (4 - data_end % 4) % 4).min(data.len());
    let total = data.len();

    buf.begin_layer(SHORT_NAME, None, FIELD_DESCRIPTORS, offset..offset + total);
    push_first_octet(buf, offset, Some(li), vn, mode);
    for (fd, value) in [
        (FD_RESPONSE, response),
        (FD_ERROR, error),
        (FD_MORE, more),
        (FD_OPCODE, opcode),
    ] {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            FieldValue::U8(value),
            offset + 1..offset + 2,
        );
    }
    for (fd, value, pos) in [
        (FD_SEQUENCE, sequence, 2),
        (FD_STATUS, status, 4),
        (FD_ASSOCIATION_ID, association_id, 6),
        (FD_OFFSET, data_offset, 8),
        (FD_COUNT, count, 10),
    ] {
        buf.push_field(
            &FIELD_DESCRIPTORS[fd],
            FieldValue::U16(value),
            offset + pos..offset + pos + 2,
        );
    }
    for (fd, range) in [
        (FD_DATA, CONTROL_HEADER_SIZE..data_end),
        (FD_PADDING, data_end..padding_end),
        (FD_AUTHENTICATOR, padding_end..total),
    ] {
        if !range.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[fd],
                FieldValue::Bytes(&data[range.clone()]),
                offset + range.start..offset + range.end,
            );
        }
    }
    buf.end_layer();

    Ok(DissectResult::new(total, DispatchHint::End))
}

/// Dissects a mode 7 message.
///
/// RFC 5905, Section 7.3, Figure 10 —
/// <https://www.rfc-editor.org/rfc/rfc5905#section-7.3> — mode 7 is
/// "reserved for private use". The format used by implementations (e.g.
/// ntpd's `ntpdc`) is not specified in an RFC and reuses the LI bits, so
/// only VN and Mode are decoded; the remaining octets are raw data.
fn dissect_private<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    vn: u8,
    mode: u8,
) -> Result<DissectResult, PacketError> {
    let total = data.len();
    buf.begin_layer(SHORT_NAME, None, FIELD_DESCRIPTORS, offset..offset + total);
    push_first_octet(buf, offset, None, vn, mode);
    if total > 1 {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA],
            FieldValue::Bytes(&data[1..]),
            offset + 1..offset + total,
        );
    }
    buf.end_layer();

    Ok(DissectResult::new(total, DispatchHint::End))
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 5905 Coverage
    //
    // | RFC Section | Description                                  | Test                                |
    // |-------------|----------------------------------------------|-------------------------------------|
    // | 6           | NTP Short Format (unsigned 16.16)            | test_root_delay_is_unsigned         |
    // | 7.3         | Header: LI, VN, Mode bit layout              | test_parse_client_request           |
    // | 7.3         | VN field width (3 bits)                      | test_version_number_field_width     |
    // | 7.3, Fig. 9 | Leap Indicator values                        | test_leap_indicator_values          |
    // | 7.3, Fig. 10| Mode values                                  | test_mode_values                    |
    // | 7.3, Fig. 11| Stratum values                               | test_stratum_ranges                 |
    // | 7.3         | Poll (signed log2 s), Precision              | test_parse_server_response          |
    // | 7.3         | Root Delay, Root Dispersion                  | test_parse_server_response          |
    // | 7.3         | Reference ID (ASCII, stratum 1)              | test_parse_stratum_1_primary        |
    // | 7.3         | Reference ID (IPv4, stratum >= 2)            | test_reference_id_ipv4_formatting   |
    // | 7.3         | Reference ID ASCII formatting                | test_reference_id_ascii_formatting  |
    // | 7.3         | Reference, Origin, Receive, Transmit TSes    | test_parse_server_response          |
    // | 7.4, Fig. 13| Kiss-o'-Death reference ID (all codes)       | test_all_kod_codes_from_rfc_figure_13 |
    // | 7.4         | Kiss-o'-Death packet (stratum 0)             | test_parse_stratum_0_kod            |
    // | 7.4         | KoD code lookup                              | test_kod_name_lookup                |
    // | 7.3         | Dissection at non-zero offset                | test_dissect_with_offset            |
    // | ---         | Truncated header                             | test_truncated_packet               |
    // | ---         | Field descriptor count / naming              | test_field_descriptors              |
    // | 7.3, Fig. 10| Mode 7 (reserved for private use)            | test_parse_mode7_private            |
    // | ---         | Empty payload                                | test_empty_packet                   |
    //
    // # RFC 9327 (NTP Control Messages) Coverage
    //
    // | RFC Section | Description                                  | Test                                |
    // |-------------|----------------------------------------------|-------------------------------------|
    // | 2           | Header: R/E/M bits, opcode, sequence         | test_parse_mode6_request            |
    // | 2           | Status, Association ID, Offset, Count        | test_parse_mode6_response           |
    // | 2, Table 1  | Operation code names                         | test_mode6_opcode_names             |
    // | 2           | Data (count octets)                          | test_parse_mode6_response           |
    // | 2           | Padding and Authenticator                    | test_parse_mode6_padding_and_authenticator |
    // | 2           | Truncated header (< 12 octets)               | test_mode6_truncated_header         |
    // | 2           | Truncated data (< 12 + count octets)         | test_mode6_truncated_data           |

    /// Build a minimal NTP packet with the given parameters.
    #[allow(clippy::too_many_arguments)]
    fn build_ntp(
        li: u8,
        vn: u8,
        mode: u8,
        stratum: u8,
        poll: i8,
        precision: i8,
        root_delay: u32,
        root_dispersion: u32,
        ref_id: [u8; 4],
        ref_ts: u64,
        origin_ts: u64,
        recv_ts: u64,
        xmit_ts: u64,
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(HEADER_SIZE);
        pkt.push((li << 6) | (vn << 3) | mode);
        pkt.push(stratum);
        pkt.push(poll as u8);
        pkt.push(precision as u8);
        pkt.extend_from_slice(&root_delay.to_be_bytes());
        pkt.extend_from_slice(&root_dispersion.to_be_bytes());
        pkt.extend_from_slice(&ref_id);
        pkt.extend_from_slice(&ref_ts.to_be_bytes());
        pkt.extend_from_slice(&origin_ts.to_be_bytes());
        pkt.extend_from_slice(&recv_ts.to_be_bytes());
        pkt.extend_from_slice(&xmit_ts.to_be_bytes());
        pkt
    }

    #[test]
    fn test_parse_client_request() {
        // NTPv4 client request: LI=0, VN=4, Mode=3
        let data = build_ntp(
            0,
            4,
            3,
            0,
            6,
            -20,
            0,
            0,
            [0; 4],
            0,
            0,
            0,
            0xDEAD_BEEF_CAFE_BABE,
        );
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "NTP");

        assert_eq!(
            buf.field_by_name(layer, "leap_indicator").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "leap_indicator_name"),
            Some("no warning")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(buf.resolve_display_name(layer, "mode_name"), Some("client"));
        assert_eq!(
            buf.field_by_name(layer, "stratum").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "poll").unwrap().value,
            FieldValue::I32(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "precision").unwrap().value,
            FieldValue::I32(-20)
        );
        assert_eq!(
            buf.field_by_name(layer, "transmit_timestamp")
                .unwrap()
                .value,
            FieldValue::U64(0xDEAD_BEEF_CAFE_BABE)
        );
    }

    #[test]
    fn test_parse_server_response() {
        // NTPv4 server response: LI=0, VN=4, Mode=4, Stratum=2
        let data = build_ntp(
            0,
            4,
            4,
            2,
            6,
            -24,
            0x0000_0100, // root delay
            0x0000_0200, // root dispersion
            [192, 168, 1, 1],
            0x1122_3344_5566_7788,
            0xAABB_CCDD_EEFF_0011,
            0x2233_4455_6677_8899,
            0x3344_5566_7788_99AA,
        );
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(buf.resolve_display_name(layer, "mode_name"), Some("server"));
        assert_eq!(
            buf.field_by_name(layer, "stratum").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("secondary server")
        );
        assert_eq!(
            buf.field_by_name(layer, "precision").unwrap().value,
            FieldValue::I32(-24)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_delay").unwrap().value,
            FieldValue::U32(0x0000_0100)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_dispersion").unwrap().value,
            FieldValue::U32(0x0000_0200)
        );
        // Stratum 2: reference ID stored as raw bytes
        assert_eq!(
            buf.field_by_name(layer, "reference_id").unwrap().value,
            FieldValue::Bytes(&[192, 168, 1, 1])
        );
        assert_eq!(
            buf.field_by_name(layer, "reference_timestamp")
                .unwrap()
                .value,
            FieldValue::U64(0x1122_3344_5566_7788)
        );
        assert_eq!(
            buf.field_by_name(layer, "origin_timestamp").unwrap().value,
            FieldValue::U64(0xAABB_CCDD_EEFF_0011)
        );
        assert_eq!(
            buf.field_by_name(layer, "receive_timestamp").unwrap().value,
            FieldValue::U64(0x2233_4455_6677_8899)
        );
        assert_eq!(
            buf.field_by_name(layer, "transmit_timestamp")
                .unwrap()
                .value,
            FieldValue::U64(0x3344_5566_7788_99AA)
        );
    }

    #[test]
    fn test_parse_stratum_0_kod() {
        // KoD packet: Stratum=0, Reference ID="RATE"
        let data = build_ntp(3, 4, 4, 0, 6, -20, 0, 0, *b"RATE", 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "leap_indicator").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "leap_indicator_name"),
            Some("unknown (clock unsynchronized)")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("unspecified or invalid")
        );
        assert_eq!(
            buf.field_by_name(layer, "reference_id").unwrap().value,
            FieldValue::Bytes(b"RATE")
        );
    }

    #[test]
    fn test_parse_stratum_1_primary() {
        // Primary server: Stratum=1, Reference ID="GPS\0"
        let data = build_ntp(0, 4, 4, 1, 4, -18, 0, 0, *b"GPS\0", 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("primary server")
        );
        // Raw bytes including trailing NUL
        assert_eq!(
            buf.field_by_name(layer, "reference_id").unwrap().value,
            FieldValue::Bytes(b"GPS\0")
        );
    }

    #[test]
    fn test_truncated_packet() {
        let data = [0u8; 47]; // 47 < 48
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 48);
                assert_eq!(actual, 47);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    /// Build an NTP control message (RFC 9327, Section 2).
    ///   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    #[allow(clippy::too_many_arguments)]
    fn build_mode6(
        vn: u8,
        rem_op: u8,
        seq: u16,
        status: u16,
        assoc: u16,
        off: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![(vn << 3) | 6, rem_op];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&status.to_be_bytes());
        pkt.extend_from_slice(&assoc.to_be_bytes());
        pkt.extend_from_slice(&off.to_be_bytes());
        pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        pkt.extend_from_slice(data);
        pkt
    }

    #[test]
    fn test_parse_mode6_request() {
        // `ntpq -c rv` request: LI=0, VN=2, Mode=6, opcode 2 (READVAR), seq 1.
        let data = [0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 42).unwrap();
        assert_eq!(result.bytes_consumed, 12);
        assert!(matches!(result.next, DispatchHint::End));

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "NTP");
        assert_eq!(layer.range, 42..54);
        assert_eq!(
            buf.field_by_name(layer, "leap_indicator").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(6)
        );
        for (name, v) in [("response", 0), ("error", 0), ("more", 0)] {
            let f = buf.field_by_name(layer, name).unwrap();
            assert_eq!(f.value, FieldValue::U8(v), "{name}");
            assert_eq!(f.range, 43..44, "{name}");
        }
        assert_eq!(
            buf.field_by_name(layer, "opcode").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "opcode_name"),
            Some("read variables command/response")
        );
        let seq = buf.field_by_name(layer, "sequence").unwrap();
        assert_eq!(seq.value, FieldValue::U16(1));
        assert_eq!(seq.range, 44..46);
        assert_eq!(
            buf.field_by_name(layer, "count").unwrap().value,
            FieldValue::U16(0)
        );
        assert!(buf.field_by_name(layer, "data").is_none());
        assert!(buf.field_by_name(layer, "stratum").is_none());
        assert!(buf.field_by_name(layer, "transmit_timestamp").is_none());
    }

    #[test]
    fn test_parse_mode6_response() {
        let text = b"version=\"ntpd 4.2.8p15\", processor=\"x86_64\", system=\"Linux\", leap=00";
        assert_eq!(text.len(), 68);
        // R=1, E=0, M=0, opcode 2; status 0x0618.
        let data = build_mode6(2, 0x82, 1, 0x0618, 0, 0, text);
        assert_eq!(data.len(), 80);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 80);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "response").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "status").unwrap().value,
            FieldValue::U16(0x0618)
        );
        assert_eq!(
            buf.field_by_name(layer, "association_id").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "offset").unwrap().value,
            FieldValue::U16(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "count").unwrap().value,
            FieldValue::U16(68)
        );
        let d = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(d.value, FieldValue::Bytes(text));
        assert_eq!(d.range, 12..80);
        assert!(buf.field_by_name(layer, "padding").is_none());
        assert!(buf.field_by_name(layer, "authenticator").is_none());
        assert!(buf.field_by_name(layer, "stratum").is_none());
    }

    #[test]
    fn test_parse_mode6_padding_and_authenticator() {
        // E=1, M=1, opcode 1; 5 data octets, 3 octets of padding and a
        // 20-octet authenticator (key ID + MD5 digest).
        let mut data = build_mode6(2, 0xE1, 9, 0, 3, 16, b"abcde");
        data.extend_from_slice(&[0, 0, 0]);
        data.extend_from_slice(&[0x5A; 20]);
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 40);

        let layer = &buf.layers()[0];
        for name in ["response", "error", "more"] {
            assert_eq!(
                buf.field_by_name(layer, name).unwrap().value,
                FieldValue::U8(1),
                "{name}"
            );
        }
        assert_eq!(
            buf.resolve_display_name(layer, "opcode_name"),
            Some("read status command/response")
        );
        assert_eq!(
            buf.field_by_name(layer, "offset").unwrap().value,
            FieldValue::U16(16)
        );
        let pad = buf.field_by_name(layer, "padding").unwrap();
        assert_eq!(pad.value, FieldValue::Bytes(&[0, 0, 0]));
        assert_eq!(pad.range, 17..20);
        let auth = buf.field_by_name(layer, "authenticator").unwrap();
        assert_eq!(auth.value, FieldValue::Bytes(&[0x5A; 20]));
        assert_eq!(auth.range, 20..40);
    }

    #[test]
    fn test_mode6_opcode_names() {
        let expected = [
            (0, "reserved"),
            (3, "write variables command/response"),
            (4, "read clock variables command/response"),
            (5, "write clock variables command/response"),
            (6, "set trap address/port command/response"),
            (7, "trap response"),
            (8, "runtime configuration command/response"),
            (9, "export configuration to file command/response"),
            (10, "retrieve remote address stats command/response"),
            (11, "retrieve ordered list command/response"),
            (12, "request client-specific nonce command/response"),
            (13, "reserved"),
            (30, "reserved"),
            (31, "unset trap address/port command/response"),
        ];
        for (op, name) in expected {
            assert_eq!(control_opcode_name(op), name, "opcode {op}");
        }
    }

    #[test]
    fn test_mode6_truncated_header() {
        let data = [0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let err = NtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 11
            }
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn test_mode6_truncated_data() {
        let mut data = build_mode6(2, 0x82, 1, 0, 0, 0, &[b'x'; 10]);
        data.truncate(15);
        let mut buf = DissectBuffer::new();
        let err = NtpDissector.dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 22,
                actual: 15
            }
        ));
    }

    #[test]
    fn test_parse_mode7_private() {
        // RFC 5905, Section 7.3, Figure 10 — mode 7 is "reserved for private
        // use"; only VN and Mode are interpreted.
        //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
        let data = [0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(7)
        );
        let d = buf.field_by_name(layer, "data").unwrap();
        assert_eq!(d.value, FieldValue::Bytes(&data[1..]));
        assert_eq!(d.range, 1..8);
        assert!(buf.field_by_name(layer, "leap_indicator").is_none());
        assert!(buf.field_by_name(layer, "stratum").is_none());

        // A lone first octet is still a valid (empty) private message.
        let mut buf = DissectBuffer::new();
        let result = NtpDissector.dissect(&data[..1], &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 1);
        assert!(buf.field_by_name(&buf.layers()[0], "data").is_none());
    }

    #[test]
    fn test_empty_packet() {
        let mut buf = DissectBuffer::new();
        let err = NtpDissector.dissect(&[], &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn test_field_descriptors() {
        let descriptors = NtpDissector.field_descriptors();
        assert_eq!(descriptors.len(), 25);
        assert_eq!(descriptors[0].name, "leap_indicator");
        assert_eq!(
            descriptors[FD_TRANSMIT_TIMESTAMP].name,
            "transmit_timestamp"
        );
        assert_eq!(descriptors[descriptors.len() - 1].name, "authenticator");
        // Only VN and Mode are present in every mode.
        for (i, d) in descriptors.iter().enumerate() {
            assert_eq!(d.optional, i != FD_VERSION && i != FD_MODE, "{}", d.name);
        }
    }

    #[test]
    fn test_dissect_with_offset() {
        // Verify byte ranges use absolute offsets
        let data = build_ntp(0, 4, 3, 0, 6, -20, 0, 0, [0; 4], 0, 0, 0, 0);
        let offset = 42; // simulate preceding headers
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, offset..offset + HEADER_SIZE);
        assert_eq!(
            buf.field_by_name(layer, "transmit_timestamp")
                .unwrap()
                .range,
            offset + 40..offset + 48
        );
    }

    #[test]
    fn test_mode_values() {
        // Test all mode values
        for mode in 0..=7 {
            let data = build_ntp(0, 4, mode, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "mode").unwrap().value,
                FieldValue::U8(mode)
            );
            // Ensure mode_name is present and non-empty
            let mode_display = buf.resolve_display_name(layer, "mode_name");
            assert!(mode_display.is_some());
            assert!(!mode_display.unwrap().is_empty());
        }
    }

    #[test]
    fn test_leap_indicator_values() {
        for li in 0..=3 {
            let data = build_ntp(li, 4, 3, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "leap_indicator").unwrap().value,
                FieldValue::U8(li)
            );
        }
    }

    #[test]
    fn test_stratum_ranges() {
        // Stratum 16 = Unsynchronized
        let data = build_ntp(0, 4, 4, 16, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "stratum_name"),
            Some("unsynchronized")
        );

        // Stratum 17 = Reserved
        let data = build_ntp(0, 4, 4, 17, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "stratum_name"),
            Some("reserved")
        );
    }

    #[test]
    fn test_kod_name_lookup() {
        // Descriptions are verbatim from RFC 5905, Figure 13.
        assert_eq!(kod_name("DENY"), Some("Access denied by remote server"));
        assert_eq!(
            kod_name("RATE"),
            Some(
                "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold"
            )
        );
        assert_eq!(kod_name("XXXX"), None);
    }

    #[test]
    fn test_root_delay_is_unsigned() {
        // RFC 5905, Section 6 (Figure 3 — NTP Short Format) defines Root Delay
        // as a 16-bit unsigned seconds field and a 16-bit fraction field, so
        // high-bit values must decode as large positive numbers, not as
        // negative values.
        // https://www.rfc-editor.org/rfc/rfc5905#section-6
        let data = build_ntp(
            0,
            4,
            4,
            2,
            6,
            -24,
            0xFFFF_FFFF, // root delay: max unsigned 16.16
            0xFFFF_FFFF, // root dispersion: max unsigned 16.16
            [0; 4],
            0,
            0,
            0,
            0,
        );
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "root_delay").unwrap().value,
            FieldValue::U32(0xFFFF_FFFF)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_dispersion").unwrap().value,
            FieldValue::U32(0xFFFF_FFFF)
        );
    }

    #[test]
    fn test_version_number_field_width() {
        // RFC 5905, Section 7.3: VN is a 3-bit integer, so values 0..=7 must
        // round-trip through the dissector. This guards against accidental
        // masking changes.
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        for vn in 0u8..=7 {
            let data = build_ntp(0, vn, 3, 0, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
            let mut buf = DissectBuffer::new();
            NtpDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "version").unwrap().value,
                FieldValue::U8(vn)
            );
        }
    }

    /// Helper: call `format_ntp_ref_id` with an empty `FormatContext`.
    fn call_ref_id_format(value: &FieldValue<'_>) -> Vec<u8> {
        let ctx = FormatContext {
            packet_data: &[],
            scratch: &[],
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out: Vec<u8> = Vec::new();
        format_ntp_ref_id(value, &ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn test_reference_id_ipv4_formatting() {
        // Stratum >= 2 encodes Reference ID as an IPv4 address
        // (RFC 5905, Section 7.3).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let bytes = [10u8, 0, 0, 42];
        let out = call_ref_id_format(&FieldValue::Bytes(&bytes));
        assert_eq!(out, b"\"10.0.0.42\"");
    }

    #[test]
    fn test_reference_id_ascii_formatting() {
        // Stratum 0/1 encode Reference ID as a 4-character ASCII code
        // (RFC 5905, Section 7.3 / Section 7.4 — KoD codes).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.4
        let bytes = *b"GPS\0";
        let out = call_ref_id_format(&FieldValue::Bytes(&bytes));
        assert_eq!(out, b"\"GPS\"");
    }

    #[test]
    fn test_all_kod_codes_from_rfc_figure_13() {
        // Every KoD code from RFC 5905, Figure 13 must resolve to a
        // non-empty description. This guards against entries being removed.
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.4
        const CODES: &[&str] = &[
            "ACST", "AUTH", "AUTO", "BCST", "CRYP", "DENY", "DROP", "RSTR", "INIT", "MCST", "NKEY",
            "RATE", "RMOT", "STEP",
        ];
        for code in CODES {
            assert!(
                kod_name(code).is_some_and(|s| !s.is_empty()),
                "KoD code {code} missing description"
            );
        }
    }

    #[test]
    fn references_and_layer_are_populated() {
        let dissector = NtpDissector;
        let references = dissector.references();
        assert!(!references.is_empty());
        for reference in references {
            assert!(!reference.id.is_empty());
            assert!(reference.url.starts_with("https://"));
        }
        assert_eq!(dissector.layer(), Some(ProtocolLayer::Application));
    }
}
