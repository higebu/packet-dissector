//! BFD (Bidirectional Forwarding Detection) dissector.
//!
//! ## References
//! - RFC 5880: <https://www.rfc-editor.org/rfc/rfc5880>
//! - RFC 5881 (BFD for IPv4/IPv6 single hop): <https://www.rfc-editor.org/rfc/rfc5881>
//! - RFC 5883 (BFD Multihop): <https://www.rfc-editor.org/rfc/rfc5883>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

/// Minimum BFD Control packet size without authentication
/// (RFC 5880, Section 4.1).
const MIN_HEADER_SIZE: usize = 24;

/// Minimum BFD Control packet size with authentication
/// (RFC 5880, Section 4.1).
const MIN_HEADER_SIZE_WITH_AUTH: usize = 26;

/// Returns a human-readable name for the Diagnostic (Diag) field value.
///
/// RFC 5880, Section 4.1 — Diagnostic values:
///   "0 -- No Diagnostic
///    1 -- Control Detection Time Expired
///    2 -- Echo Function Failed
///    3 -- Neighbor Signaled Session Down
///    4 -- Forwarding Plane Reset
///    5 -- Path Down
///    6 -- Concatenated Path Down
///    7 -- Administratively Down
///    8 -- Reverse Concatenated Path Down
///    9-31 -- Reserved for future use"
fn diagnostic_name(diag: u8) -> &'static str {
    match diag {
        0 => "No Diagnostic",
        1 => "Control Detection Time Expired",
        2 => "Echo Function Failed",
        3 => "Neighbor Signaled Session Down",
        4 => "Forwarding Plane Reset",
        5 => "Path Down",
        6 => "Concatenated Path Down",
        7 => "Administratively Down",
        8 => "Reverse Concatenated Path Down",
        _ => "Reserved",
    }
}

/// Returns a human-readable name for the State (Sta) field value.
///
/// RFC 5880, Section 4.1 — State values:
///   "0 -- AdminDown
///    1 -- Down
///    2 -- Init
///    3 -- Up"
fn state_name(state: u8) -> &'static str {
    match state {
        0 => "AdminDown",
        1 => "Down",
        2 => "Init",
        3 => "Up",
        // State is a 2-bit field so only 0-3 are possible.
        _ => unreachable!(),
    }
}

/// Returns a human-readable name for the Authentication Type value.
///
/// RFC 5880, Section 4.2 — Authentication Type values:
///   "0 - Reserved
///    1 - Simple Password
///    2 - Keyed MD5
///    3 - Meticulous Keyed MD5
///    4 - Keyed SHA1
///    5 - Meticulous Keyed SHA1"
fn auth_type_name(auth_type: u8) -> &'static str {
    match auth_type {
        0 => "Reserved",
        1 => "Simple Password",
        2 => "Keyed MD5",
        3 => "Meticulous Keyed MD5",
        4 => "Keyed SHA1",
        5 => "Meticulous Keyed SHA1",
        _ => "Reserved",
    }
}

/// BFD dissector.
pub struct BfdDissector;

/// Field descriptors for the BFD dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor {
        name: "diagnostic",
        display_name: "Diagnostic",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(d) => Some(diagnostic_name(*d)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "state",
        display_name: "State",
        field_type: FieldType::U8,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(s) => Some(state_name(*s)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("poll", "Poll", FieldType::U8),
    FieldDescriptor::new("final", "Final", FieldType::U8),
    FieldDescriptor::new(
        "control_plane_independent",
        "Control Plane Independent",
        FieldType::U8,
    ),
    FieldDescriptor::new("auth_present", "Authentication Present", FieldType::U8),
    FieldDescriptor::new("demand", "Demand", FieldType::U8),
    FieldDescriptor::new("multipoint", "Multipoint", FieldType::U8),
    FieldDescriptor::new("detect_mult", "Detect Multiplier", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("my_discriminator", "My Discriminator", FieldType::U32),
    FieldDescriptor::new("your_discriminator", "Your Discriminator", FieldType::U32),
    FieldDescriptor::new(
        "desired_min_tx_interval",
        "Desired Min TX Interval",
        FieldType::U32,
    ),
    FieldDescriptor::new(
        "required_min_rx_interval",
        "Required Min RX Interval",
        FieldType::U32,
    ),
    FieldDescriptor::new(
        "required_min_echo_rx_interval",
        "Required Min Echo RX Interval",
        FieldType::U32,
    ),
    // Authentication fields (optional — only present when A bit is set)
    FieldDescriptor {
        name: "auth_type",
        display_name: "Auth Type",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(a) => Some(auth_type_name(*a)),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("auth_data", "Auth Data", FieldType::Bytes).optional(),
];

/// Index constants for `FIELD_DESCRIPTORS`.
const FD_VERSION: usize = 0;
const FD_DIAGNOSTIC: usize = 1;
const FD_STATE: usize = 2;
const FD_POLL: usize = 3;
const FD_FINAL: usize = 4;
const FD_CONTROL_PLANE_INDEPENDENT: usize = 5;
const FD_AUTH_PRESENT: usize = 6;
const FD_DEMAND: usize = 7;
const FD_MULTIPOINT: usize = 8;
const FD_DETECT_MULT: usize = 9;
const FD_LENGTH: usize = 10;
const FD_MY_DISCRIMINATOR: usize = 11;
const FD_YOUR_DISCRIMINATOR: usize = 12;
const FD_DESIRED_MIN_TX_INTERVAL: usize = 13;
const FD_REQUIRED_MIN_RX_INTERVAL: usize = 14;
const FD_REQUIRED_MIN_ECHO_RX_INTERVAL: usize = 15;
// Authentication fields (optional — only present when A bit is set)
const FD_AUTH_TYPE: usize = 16;
const FD_AUTH_DATA: usize = 17;

impl Dissector for BfdDissector {
    fn name(&self) -> &'static str {
        "Bidirectional Forwarding Detection"
    }

    fn short_name(&self) -> &'static str {
        "BFD"
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
        if data.len() < MIN_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 5880, Section 4.1 — first octet: Vers (3 bits) | Diag (5 bits)
        let byte0 = data[0];
        let version = (byte0 >> 5) & 0x07;
        let diagnostic = byte0 & 0x1F;

        // RFC 5880, Section 4.1 — second octet: Sta (2) | P | F | C | A | D | M
        let byte1 = data[1];
        let state = (byte1 >> 6) & 0x03;
        let poll = (byte1 >> 5) & 0x01;
        let final_flag = (byte1 >> 4) & 0x01;
        let control_plane_independent = (byte1 >> 3) & 0x01;
        let auth_present = (byte1 >> 2) & 0x01;
        let demand = (byte1 >> 1) & 0x01;
        let multipoint = byte1 & 0x01;

        let detect_mult = data[2];

        // RFC 5880, Section 4.1 — "The length of the BFD Control packet, in
        // bytes."
        let length_u8 = data[3];
        let length = length_u8 as usize;
        if length < MIN_HEADER_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: length_u8 as u32,
            });
        }
        if data.len() < length {
            return Err(PacketError::Truncated {
                expected: length,
                actual: data.len(),
            });
        }

        let my_discriminator = read_be_u32(data, 4)?;
        let your_discriminator = read_be_u32(data, 8)?;
        let desired_min_tx = read_be_u32(data, 12)?;
        let required_min_rx = read_be_u32(data, 16)?;
        let required_min_echo_rx = read_be_u32(data, 20)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + length,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DIAGNOSTIC],
            FieldValue::U8(diagnostic),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_STATE],
            FieldValue::U8(state),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_POLL],
            FieldValue::U8(poll),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_FINAL],
            FieldValue::U8(final_flag),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_CONTROL_PLANE_INDEPENDENT],
            FieldValue::U8(control_plane_independent),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_AUTH_PRESENT],
            FieldValue::U8(auth_present),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DEMAND],
            FieldValue::U8(demand),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MULTIPOINT],
            FieldValue::U8(multipoint),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DETECT_MULT],
            FieldValue::U8(detect_mult),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U8(length_u8),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MY_DISCRIMINATOR],
            FieldValue::U32(my_discriminator),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_YOUR_DISCRIMINATOR],
            FieldValue::U32(your_discriminator),
            offset + 8..offset + 12,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DESIRED_MIN_TX_INTERVAL],
            FieldValue::U32(desired_min_tx),
            offset + 12..offset + 16,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REQUIRED_MIN_RX_INTERVAL],
            FieldValue::U32(required_min_rx),
            offset + 16..offset + 20,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_REQUIRED_MIN_ECHO_RX_INTERVAL],
            FieldValue::U32(required_min_echo_rx),
            offset + 20..offset + 24,
        );

        // RFC 5880, Section 4.2 — Optional Authentication Section
        if auth_present == 1 {
            if length < MIN_HEADER_SIZE_WITH_AUTH {
                return Err(PacketError::InvalidHeader(
                    "BFD auth present but length is less than minimum with auth",
                ));
            }
            let auth_type = data[24];
            let auth_len = data[25] as usize;

            // RFC 5880, Section 4.2 — Optional Authentication Section
            // Each authentication type has a minimum length including the
            // Type and Length bytes themselves. Enforce these minima to
            // avoid accepting malformed auth sections with missing fields
            // such as the Key ID or fixed MD5/SHA1 fields.
            let min_auth_len = match auth_type {
                1 => 3,      // Simple Password: Type(1) + Length(1) + Password(>=1)
                2 | 3 => 24, // Keyed MD5 / Meticulous Keyed MD5
                4 | 5 => 28, // Keyed SHA1 / Meticulous Keyed SHA1
                _ => 3,      // Unknown types: require at least one auth data byte
            };

            if auth_len < min_auth_len {
                return Err(PacketError::InvalidHeader(
                    "BFD auth length is less than minimum for auth type",
                ));
            }
            let auth_end = 24 + auth_len;
            if auth_end > length {
                return Err(PacketError::InvalidHeader(
                    "BFD auth section exceeds packet length",
                ));
            }

            buf.push_field(
                &FIELD_DESCRIPTORS[FD_AUTH_TYPE],
                FieldValue::U8(auth_type),
                offset + 24..offset + 25,
            );
            if auth_len > 2 {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_AUTH_DATA],
                    FieldValue::Bytes(&data[26..auth_end]),
                    offset + 26..offset + auth_end,
                );
            }
        }

        buf.end_layer();

        Ok(DissectResult::new(length, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 5880 Coverage
    //
    // | RFC Section | Description                          | Test                              |
    // |-------------|--------------------------------------|-----------------------------------|
    // | 4.1         | Header: Version, Diagnostic          | test_parse_basic_up               |
    // | 4.1         | Header: State, flags                 | test_parse_all_flags_set          |
    // | 4.1         | Header: Detect Mult, Length           | test_parse_basic_up               |
    // | 4.1         | Header: Discriminators               | test_parse_basic_up               |
    // | 4.1         | Header: Interval fields              | test_parse_basic_up               |
    // | 4.1         | All diagnostic codes                 | test_diagnostic_codes             |
    // | 4.1         | All state values                     | test_state_values                 |
    // | 4.2         | Auth section (Simple Password)       | test_parse_with_auth_simple       |
    // | 4.2         | Auth section (Keyed SHA1)            | test_parse_with_auth_sha1         |
    // | ---         | Truncated header (< 24 bytes)        | test_truncated_packet             |
    // | ---         | Invalid length (< 24)                | test_invalid_length_field         |
    // | ---         | Auth present but truncated           | test_auth_present_but_truncated   |
    // | ---         | Offset handling                      | test_dissect_with_offset          |
    // | ---         | Field descriptors                    | test_field_descriptors            |

    /// Build a minimal BFD Control packet.
    #[allow(clippy::too_many_arguments)]
    fn build_bfd(
        version: u8,
        diagnostic: u8,
        state: u8,
        poll: u8,
        final_f: u8,
        cpi: u8,
        auth: u8,
        demand: u8,
        multipoint: u8,
        detect_mult: u8,
        length: u8,
        my_disc: u32,
        your_disc: u32,
        desired_min_tx: u32,
        required_min_rx: u32,
        required_min_echo_rx: u32,
    ) -> Vec<u8> {
        let byte0 = (version << 5) | (diagnostic & 0x1F);
        let byte1 = (state << 6)
            | (poll << 5)
            | (final_f << 4)
            | (cpi << 3)
            | (auth << 2)
            | (demand << 1)
            | multipoint;
        let mut pkt = Vec::with_capacity(length as usize);
        pkt.push(byte0);
        pkt.push(byte1);
        pkt.push(detect_mult);
        pkt.push(length);
        pkt.extend_from_slice(&my_disc.to_be_bytes());
        pkt.extend_from_slice(&your_disc.to_be_bytes());
        pkt.extend_from_slice(&desired_min_tx.to_be_bytes());
        pkt.extend_from_slice(&required_min_rx.to_be_bytes());
        pkt.extend_from_slice(&required_min_echo_rx.to_be_bytes());
        pkt
    }

    /// Build a BFD Control packet with an authentication section.
    #[allow(clippy::too_many_arguments)]
    fn build_bfd_with_auth(
        version: u8,
        diagnostic: u8,
        state: u8,
        detect_mult: u8,
        my_disc: u32,
        your_disc: u32,
        auth_type: u8,
        auth_data: &[u8],
    ) -> Vec<u8> {
        let auth_len = 2 + auth_data.len();
        let total_len = 24 + auth_len;
        let mut pkt = build_bfd(
            version,
            diagnostic,
            state,
            0,
            0,
            0,
            1, // auth present
            0,
            0,
            detect_mult,
            total_len as u8,
            my_disc,
            your_disc,
            1_000_000,
            1_000_000,
            0,
        );
        pkt.push(auth_type);
        pkt.push(auth_len as u8);
        pkt.extend_from_slice(auth_data);
        pkt
    }

    #[test]
    fn test_parse_basic_up() {
        // BFD v1, State=Up, Diag=No Diagnostic, Detect Mult=3, Length=24
        let data = build_bfd(
            1,         // version
            0,         // diagnostic: No Diagnostic
            3,         // state: Up
            0,         // poll
            0,         // final
            0,         // cpi
            0,         // auth
            0,         // demand
            0,         // multipoint
            3,         // detect mult
            24,        // length
            0x0001,    // my discriminator
            0x0002,    // your discriminator
            1_000_000, // desired min tx (1s)
            1_000_000, // required min rx (1s)
            0,         // required min echo rx
        );
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "BFD");

        assert_eq!(
            buf.field_by_name(layer, "version").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "diagnostic").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "diagnostic_name"),
            Some("No Diagnostic")
        );
        assert_eq!(
            buf.field_by_name(layer, "state").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(buf.resolve_display_name(layer, "state_name"), Some("Up"));
        assert_eq!(
            buf.field_by_name(layer, "poll").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "final").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "control_plane_independent")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_present").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "demand").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "multipoint").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "detect_mult").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            buf.field_by_name(layer, "length").unwrap().value,
            FieldValue::U8(24)
        );
        assert_eq!(
            buf.field_by_name(layer, "my_discriminator").unwrap().value,
            FieldValue::U32(0x0001)
        );
        assert_eq!(
            buf.field_by_name(layer, "your_discriminator")
                .unwrap()
                .value,
            FieldValue::U32(0x0002)
        );
        assert_eq!(
            buf.field_by_name(layer, "desired_min_tx_interval")
                .unwrap()
                .value,
            FieldValue::U32(1_000_000)
        );
        assert_eq!(
            buf.field_by_name(layer, "required_min_rx_interval")
                .unwrap()
                .value,
            FieldValue::U32(1_000_000)
        );
        assert_eq!(
            buf.field_by_name(layer, "required_min_echo_rx_interval")
                .unwrap()
                .value,
            FieldValue::U32(0)
        );
    }

    #[test]
    fn test_parse_all_flags_set() {
        // All flag bits set: P=1, F=1, C=1, A=1, D=1, M=1
        // Auth present requires auth section, so include a minimal one.
        let mut data = build_bfd(
            1, 7, // Administratively Down
            0, // AdminDown
            1, // poll
            1, // final
            1, // cpi
            1, // auth present
            1, // demand
            1, // multipoint
            5, // detect mult
            28, 0xAABBCCDD, 0x11223344, 500_000, 500_000, 100_000,
        );
        // Append minimal auth: type=1 (Simple Password), len=4, 2 bytes data
        data.push(1); // auth type
        data.push(4); // auth len (2 header + 2 data)
        data.push(0x41); // 'A'
        data.push(0x42); // 'B'

        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "poll").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "final").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "control_plane_independent")
                .unwrap()
                .value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "demand").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "multipoint").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "auth_type_name"),
            Some("Simple Password")
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_data").unwrap().value,
            FieldValue::Bytes(&[0x41, 0x42])
        );
    }

    #[test]
    fn test_diagnostic_codes() {
        for diag in 0..=8 {
            let data = build_bfd(
                1, diag, 3, 0, 0, 0, 0, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
            );
            let mut buf = DissectBuffer::new();
            BfdDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "diagnostic").unwrap().value,
                FieldValue::U8(diag)
            );
            if let Some(name) = buf.resolve_display_name(layer, "diagnostic_name") {
                assert!(!name.is_empty());
                assert_ne!(name, "Reserved");
            } else {
                panic!("diagnostic_name should be Str");
            }
        }
        // Reserved value
        let data = build_bfd(
            1, 9, 3, 0, 0, 0, 0, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "diagnostic_name"),
            Some("Reserved")
        );
    }

    #[test]
    fn test_state_values() {
        let names = ["AdminDown", "Down", "Init", "Up"];
        for state in 0..=3u8 {
            let data = build_bfd(
                1, 0, state, 0, 0, 0, 0, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
            );
            let mut buf = DissectBuffer::new();
            BfdDissector.dissect(&data, &mut buf, 0).unwrap();
            let layer = &buf.layers()[0];
            assert_eq!(
                buf.field_by_name(layer, "state").unwrap().value,
                FieldValue::U8(state)
            );
            assert_eq!(
                buf.resolve_display_name(layer, "state_name"),
                Some(names[state as usize])
            );
        }
    }

    #[test]
    fn test_parse_with_auth_simple() {
        // Simple Password authentication: type=1, key_id=1, password="secret"
        let auth_data = [1, b's', b'e', b'c', b'r', b'e', b't']; // key_id + password
        let data = build_bfd_with_auth(1, 0, 3, 3, 0x1000, 0x2000, 1, &auth_data);
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "auth_present").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "auth_type_name"),
            Some("Simple Password")
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_data").unwrap().value,
            FieldValue::Bytes(&auth_data)
        );
    }

    #[test]
    fn test_parse_with_auth_sha1() {
        // Keyed SHA1 authentication: type=4, key_id=1, reserved=0, seq=1, hash=20 bytes
        let mut auth_data = vec![1, 0, 0, 0]; // key_id, reserved, reserved, reserved
        auth_data.extend_from_slice(&1u32.to_be_bytes()); // sequence number
        auth_data.extend_from_slice(&[0xAA; 20]); // SHA1 hash (20 bytes)
        let data = build_bfd_with_auth(1, 0, 3, 3, 0x1000, 0x2000, 4, &auth_data);
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "auth_type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "auth_type_name"),
            Some("Keyed SHA1")
        );
    }

    #[test]
    fn test_truncated_packet() {
        let data = [0u8; 23]; // 23 < 24
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 24);
                assert_eq!(actual, 23);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn test_invalid_length_field() {
        // Length field set to 20, which is < MIN_HEADER_SIZE (24)
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 0, 0, 0, 3, 20, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "length");
                assert_eq!(value, 20);
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_present_but_truncated() {
        // Auth bit set but length is only 24 (needs at least 26)
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 1, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("auth present"));
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_dissect_with_offset() {
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 0, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let offset = 42; // simulate preceding headers
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, offset).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, offset..offset + 24);
        assert_eq!(
            buf.field_by_name(layer, "required_min_echo_rx_interval")
                .unwrap()
                .range,
            offset + 20..offset + 24
        );
    }

    #[test]
    fn test_field_descriptors() {
        let descriptors = BfdDissector.field_descriptors();
        assert_eq!(descriptors.len(), 18);
        assert_eq!(descriptors[0].name, "version");
        assert_eq!(descriptors[descriptors.len() - 1].name, "auth_data");
        // Check optional fields
        assert!(!descriptors[0].optional); // version
        assert!(descriptors[16].optional); // auth_type
        assert!(descriptors[17].optional); // auth_data
    }

    #[test]
    fn test_length_exceeds_data() {
        // Length field says 30 but only 24 bytes of data
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 0, 0, 0, 3, 30, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::Truncated { expected, actual } => {
                assert_eq!(expected, 30);
                assert_eq!(actual, 24);
            }
            other => panic!("Expected Truncated, got {other:?}"),
        }
    }
}
