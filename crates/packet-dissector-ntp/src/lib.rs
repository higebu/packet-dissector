//! NTP (Network Time Protocol) dissector.
//!
//! ## References
//! - RFC 5905: <https://www.rfc-editor.org/rfc/rfc5905>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_i32, read_be_u32, read_be_u64};

/// Format NTP reference_id: stratum 0-1 as ASCII code, stratum 2+ as IPv4 address.
///
/// RFC 5905, Section 7.3: for stratum 0-1 the field is a 4-character ASCII
/// string (e.g., "GPS", "PPS"); for stratum 2+ it is an IPv4 address.
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

/// NTP fixed header size in bytes (RFC 5905, Section 7.3).
const HEADER_SIZE: usize = 48;

/// Returns a human-readable name for the Leap Indicator value.
///
/// RFC 5905, Section 7.3 — LI (Leap Indicator).
fn leap_indicator_name(li: u8) -> &'static str {
    match li {
        0 => "No warning",
        1 => "Last minute of the day has 61 seconds",
        2 => "Last minute of the day has 59 seconds",
        3 => "Unknown (clock not synchronized)",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Mode value.
///
/// RFC 5905, Section 7.3 — Mode.
fn mode_name(mode: u8) -> &'static str {
    match mode {
        0 => "Reserved",
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "NTP Control Message",
        7 => "Reserved for Private Use",
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Stratum value.
///
/// RFC 5905, Section 7.3 — Stratum.
fn stratum_name(stratum: u8) -> &'static str {
    match stratum {
        0 => "Kiss-o'-Death",
        1 => "Primary",
        2..=15 => "Secondary",
        16 => "Unsynchronized",
        _ => "Reserved",
    }
}

/// Returns a human-readable name for a Kiss-o'-Death code.
///
/// RFC 5905, Section 7.4 — Kiss-o'-Death codes.
pub fn kod_name(code: &str) -> Option<&'static str> {
    match code {
        "ACST" => Some("Unicast server"),
        "AUTH" => Some("Server authentication failed"),
        "AUTO" => Some("Autokey sequence failed"),
        "BCST" => Some("Broadcast server"),
        "CRYP" => Some("Cryptographic authentication failed"),
        "DENY" => Some("Access denied by remote server"),
        "DROP" => Some("Lost peer in symmetric mode"),
        "RSTR" => Some("Access denied due to local policy"),
        "INIT" => Some("Association not yet synchronized"),
        "MCST" => Some("Dynamically discovered server"),
        "NKEY" => Some("No key found"),
        "RATE" => Some("Rate exceeded"),
        "RMOT" => Some("Remote host alteration"),
        "STEP" => Some("Step change in system time"),
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
    FieldDescriptor::new("root_delay", "Root Delay", FieldType::I32),
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

        // RFC 5905, Section 7.3 — first octet: LI (2 bits) | VN (3 bits) | Mode (3 bits)
        let first_byte = data[0];
        let li = (first_byte >> 6) & 0x03;
        let vn = (first_byte >> 3) & 0x07;
        let mode = first_byte & 0x07;

        let stratum = data[1];
        // Poll and Precision are signed 8-bit integers (log₂ seconds)
        let poll = data[2] as i8 as i32;
        let precision = data[3] as i8 as i32;

        // RFC 5905, Section 7.3 — Root Delay is a signed 16.16 fixed-point value
        let root_delay = read_be_i32(data, 4)?;
        // RFC 5905, Section 7.3 — Root Dispersion is an unsigned 16.16 fixed-point value
        let root_dispersion = read_be_u32(data, 8)?;

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
            FieldValue::I32(root_delay),
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
        // Store raw bytes; formatting is deferred to format_fn.
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
    // | RFC Section | Description                        | Test                          |
    // |-------------|------------------------------------|-------------------------------|
    // | 7.3         | Header: LI, VN, Mode               | test_parse_client_request     |
    // | 7.3         | Header: Stratum, Poll, Precision   | test_parse_server_response    |
    // | 7.3         | Header: Root Delay, Root Dispersion| test_parse_server_response    |
    // | 7.3         | Header: Reference ID (ASCII)       | test_parse_stratum_1_primary  |
    // | 7.3         | Header: Reference ID (IPv4)        | test_parse_server_response    |
    // | 7.3         | Header: Timestamps                 | test_parse_server_response    |
    // | 7.4         | Kiss-o'-Death reference ID         | test_parse_stratum_0_kod      |
    // | ---         | Truncated header                   | test_truncated_packet         |

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
            Some("No warning")
        );
        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "mode").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(buf.resolve_display_name(layer, "mode_name"), Some("Client"));
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
        assert_eq!(buf.resolve_display_name(layer, "mode_name"), Some("Server"));
        assert_eq!(
            buf.field_by_name(layer, "stratum").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("Secondary")
        );
        assert_eq!(
            buf.field_by_name(layer, "precision").unwrap().value,
            FieldValue::I32(-24)
        );
        assert_eq!(
            buf.field_by_name(layer, "root_delay").unwrap().value,
            FieldValue::I32(0x0000_0100)
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
            Some("Unknown (clock not synchronized)")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "stratum_name"),
            Some("Kiss-o'-Death")
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
            Some("Primary")
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
            Some("Unsynchronized")
        );

        // Stratum 17 = Reserved
        let data = build_ntp(0, 4, 4, 17, 0, 0, 0, 0, [0; 4], 0, 0, 0, 0);
        let mut buf = DissectBuffer::new();
        NtpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "stratum_name"),
            Some("Reserved")
        );
    }

    #[test]
    fn test_kod_name_lookup() {
        assert_eq!(kod_name("RATE"), Some("Rate exceeded"));
        assert_eq!(kod_name("DENY"), Some("Access denied by remote server"));
        assert_eq!(kod_name("XXXX"), None);
    }
}
