//! NTP (Network Time Protocol) dissector.
//!
//! ## References
//! - RFC 5905 (NTPv4): <https://www.rfc-editor.org/rfc/rfc5905>
//! - RFC 7822 (Extension Fields update): <https://www.rfc-editor.org/rfc/rfc7822>
//! - RFC 8573 (AES-CMAC for NTP): <https://www.rfc-editor.org/rfc/rfc8573>
//! - RFC 9109 (Port Randomization): <https://www.rfc-editor.org/rfc/rfc9109>
//! - RFC 9748 (IANA Registry updates): <https://www.rfc-editor.org/rfc/rfc9748>
//! - RFC 9769 (Interleaved Modes): <https://www.rfc-editor.org/rfc/rfc9769>
//!
//! Only the 48-octet fixed NTPv4 header (RFC 5905, Section 7.3) is dissected;
//! extension fields and MACs are left to higher layers.

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u32, read_be_u64};

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

/// NTP dissector.
pub struct NtpDissector;

/// Field descriptors for the NTP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "leap_indicator",
        display_name: "Leap Indicator",
        field_type: FieldType::U8,
        optional: false,
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
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => Some(stratum_name(*s)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("poll", "Poll Interval", FieldType::I32),
    FieldDescriptor::new("precision", "Precision", FieldType::I32),
    FieldDescriptor::new("root_delay", "Root Delay", FieldType::U32),
    FieldDescriptor::new("root_dispersion", "Root Dispersion", FieldType::U32),
    FieldDescriptor::new("reference_id", "Reference ID", FieldType::Bytes)
        .with_format_fn(format_ntp_ref_id),
    FieldDescriptor::new("reference_timestamp", "Reference Timestamp", FieldType::U64),
    FieldDescriptor::new("origin_timestamp", "Origin Timestamp", FieldType::U64),
    FieldDescriptor::new("receive_timestamp", "Receive Timestamp", FieldType::U64),
    FieldDescriptor::new("transmit_timestamp", "Transmit Timestamp", FieldType::U64),
];

impl Dissector for NtpDissector {
    fn name(&self) -> &'static str {
        "Network Time Protocol"
    }

    fn short_name(&self) -> &'static str {
        "NTP"
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
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 5905, Section 7.3 — first octet: LI (2 bits) | VN (3 bits) | Mode (3 bits).
        // https://www.rfc-editor.org/rfc/rfc5905#section-7.3
        let first_byte = data[0];
        let li = (first_byte >> 6) & 0x03;
        let vn = (first_byte >> 3) & 0x07;
        let mode = first_byte & 0x07;

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
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + HEADER_SIZE,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LEAP_INDICATOR],
            FieldValue::U8(li),
            offset..offset + 1,
        );
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

    #[test]
    fn test_field_descriptors() {
        let descriptors = NtpDissector.field_descriptors();
        assert_eq!(descriptors.len(), 13);
        assert_eq!(descriptors[0].name, "leap_indicator");
        assert_eq!(
            descriptors[descriptors.len() - 1].name,
            "transmit_timestamp"
        );
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
}
