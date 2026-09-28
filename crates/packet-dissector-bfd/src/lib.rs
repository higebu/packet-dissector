//! BFD (Bidirectional Forwarding Detection) dissector.
//!
//! ## References
//! - RFC 5880 (BFD base specification): <https://www.rfc-editor.org/rfc/rfc5880>
//! - RFC 5881 (BFD for IPv4/IPv6 single hop): <https://www.rfc-editor.org/rfc/rfc5881>
//! - RFC 5883 (BFD Multihop): <https://www.rfc-editor.org/rfc/rfc5883>
//! - RFC 7419 (BFD Common Interval Support; updates RFC 5880):
//!   <https://www.rfc-editor.org/rfc/rfc7419>
//! - RFC 7880 (Seamless BFD; updates RFC 5880):
//!   <https://www.rfc-editor.org/rfc/rfc7880>
//! - RFC 8562 (BFD for Multipoint Networks; updates RFC 5880, redefines the
//!   Multipoint (M) bit): <https://www.rfc-editor.org/rfc/rfc8562>
//! - RFC 9747 (Unaffiliated BFD Echo; updates RFC 5880):
//!   <https://www.rfc-editor.org/rfc/rfc9747>
//! - RFC 7130 (BFD on LAG Interfaces, Micro-BFD):
//!   <https://www.rfc-editor.org/rfc/rfc7130>
//! - RFC 7881 (S-BFD for IPv4, IPv6, and MPLS):
//!   <https://www.rfc-editor.org/rfc/rfc7881>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

/// BFD protocol version defined by RFC 5880, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.1>
const BFD_VERSION: u8 = 1;

/// Minimum BFD Control packet size without authentication.
/// RFC 5880, Section 6.8.6 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6>
const MIN_HEADER_SIZE: usize = 24;

/// Minimum BFD Control packet size with authentication.
/// RFC 5880, Section 6.8.6 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6>
const MIN_HEADER_SIZE_WITH_AUTH: usize = 26;

/// Fixed Auth Len for Keyed MD5 / Meticulous Keyed MD5.
/// RFC 5880, Section 4.3 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.3>
const AUTH_LEN_MD5: usize = 24;

/// Fixed Auth Len for Keyed SHA1 / Meticulous Keyed SHA1.
/// RFC 5880, Section 4.4 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.4>
const AUTH_LEN_SHA1: usize = 28;

/// Minimum Auth Len for Simple Password (Type + Len + Key ID + 1-byte
/// password). RFC 5880, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.2>
const MIN_AUTH_LEN_SIMPLE_PASSWORD: usize = 4;

/// Maximum Auth Len for Simple Password (Type + Len + Key ID + 16-byte
/// password). RFC 5880, Section 6.7.2 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-6.7.2>
const MAX_AUTH_LEN_SIMPLE_PASSWORD: usize = 19;

/// Offset of the Auth Key ID octet within the Control packet.
/// RFC 5880, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.2>
const AUTH_KEY_ID_OFFSET: usize = 26;

/// Offset of the Sequence Number in the Keyed MD5 / SHA1 sections.
/// RFC 5880, Sections 4.3 and 4.4 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.3>
const AUTH_SEQUENCE_OFFSET: usize = 28;

/// Offset of the Auth Key/Digest or Auth Key/Hash in the Keyed MD5 / SHA1
/// sections. RFC 5880, Sections 4.3 and 4.4 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.3>
const AUTH_DIGEST_OFFSET: usize = 32;

/// Minimum Auth Len for an unknown authentication type (Type + Len + at
/// least one byte of authentication data).
const MIN_AUTH_LEN_UNKNOWN: usize = 3;

/// Returns a human-readable name for the Diagnostic (Diag) field value.
///
/// RFC 5880, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.1> — Diagnostic values:
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
/// RFC 5880, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.1> — State values:
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
/// RFC 5880, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.2> — Authentication Type
/// values:
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
    FieldDescriptor::new("auth_len", "Auth Len", FieldType::U8).optional(),
    FieldDescriptor::new("auth_key_id", "Auth Key ID", FieldType::U8).optional(),
    FieldDescriptor::new("password", "Password", FieldType::Bytes).optional(),
    FieldDescriptor::new("auth_reserved", "Reserved", FieldType::U8).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32).optional(),
    FieldDescriptor::new("digest", "Auth Key/Digest", FieldType::Bytes).optional(),
    FieldDescriptor::new("hash", "Auth Key/Hash", FieldType::Bytes).optional(),
    // BFD Echo only (RFC 5880, Section 5): opaque payload that is not a
    // Control packet. Excluded from `CONTROL_FIELD_DESCRIPTORS`.
    //   <https://www.rfc-editor.org/rfc/rfc5880#section-5>
    FieldDescriptor::new("payload", "Payload", FieldType::Bytes).optional(),
];

/// Field descriptors produced by [`BfdDissector`]: every entry of
/// `FIELD_DESCRIPTORS` except the Echo-only `payload`.
static CONTROL_FIELD_DESCRIPTORS: &[FieldDescriptor] =
    FIELD_DESCRIPTORS.split_at(FD_ECHO_PAYLOAD).0;

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
const FD_AUTH_LEN: usize = 18;
const FD_AUTH_KEY_ID: usize = 19;
const FD_PASSWORD: usize = 20;
const FD_AUTH_RESERVED: usize = 21;
const FD_SEQUENCE_NUMBER: usize = 22;
const FD_DIGEST: usize = 23;
const FD_HASH: usize = 24;
// BFD Echo only.
const FD_ECHO_PAYLOAD: usize = 25;

/// Specification references for the BFD dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 5880",
        "Bidirectional Forwarding Detection (BFD)",
        "https://www.rfc-editor.org/rfc/rfc5880",
    ),
    SpecReference::new(
        "RFC 5881",
        "Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop)",
        "https://www.rfc-editor.org/rfc/rfc5881",
    ),
    SpecReference::new(
        "RFC 5883",
        "Bidirectional Forwarding Detection (BFD) for Multihop Paths",
        "https://www.rfc-editor.org/rfc/rfc5883",
    ),
    SpecReference::new(
        "RFC 7419",
        "Common Interval Support in Bidirectional Forwarding Detection",
        "https://www.rfc-editor.org/rfc/rfc7419",
    ),
    SpecReference::new(
        "RFC 7880",
        "Seamless Bidirectional Forwarding Detection (S-BFD)",
        "https://www.rfc-editor.org/rfc/rfc7880",
    ),
    SpecReference::new(
        "RFC 8562",
        "Bidirectional Forwarding Detection (BFD) for Multipoint Networks",
        "https://www.rfc-editor.org/rfc/rfc8562",
    ),
    SpecReference::new(
        "RFC 9747",
        "Unaffiliated Bidirectional Forwarding Detection (BFD) Echo",
        "https://www.rfc-editor.org/rfc/rfc9747",
    ),
    SpecReference::new(
        "RFC 7130",
        "Bidirectional Forwarding Detection (BFD) on Link Aggregation Group (LAG) Interfaces",
        "https://www.rfc-editor.org/rfc/rfc7130",
    ),
    SpecReference::new(
        "RFC 7881",
        "Seamless Bidirectional Forwarding Detection (S-BFD) for IPv4, IPv6, and MPLS",
        "https://www.rfc-editor.org/rfc/rfc7881",
    ),
];

impl Dissector for BfdDissector {
    fn name(&self) -> &'static str {
        "Bidirectional Forwarding Detection"
    }

    fn short_name(&self) -> &'static str {
        "BFD"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        CONTROL_FIELD_DESCRIPTORS
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
        dissect_control(
            data,
            buf,
            offset,
            CONTROL_SHORT_NAME,
            CONTROL_FIELD_DESCRIPTORS,
        )
    }
}

/// Dissects a BFD Control packet (RFC 5880, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.1>).
///
/// `layer_name` and `descriptors` identify the calling dissector, so the
/// pushed layer matches its `short_name()` and `field_descriptors()`.
fn dissect_control<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    layer_name: &'static str,
    descriptors: &'static [FieldDescriptor],
) -> Result<DissectResult, PacketError> {
    if data.len() < MIN_HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: MIN_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // RFC 5880, Section 4.1 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-4.1> — first octet:
    // Vers (3 bits) | Diag (5 bits).
    let byte0 = data[0];
    let version = (byte0 >> 5) & 0x07;
    let diagnostic = byte0 & 0x1F;

    // RFC 5880, Section 6.8.6 #1 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6> — "If the
    // version number is not correct (1), the packet MUST be discarded."
    if version != BFD_VERSION {
        return Err(PacketError::InvalidFieldValue {
            field: "version",
            value: u32::from(version),
        });
    }

    // RFC 5880, Section 4.1 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-4.1> — second octet:
    // Sta (2) | P | F | C | A | D | M.
    let byte1 = data[1];
    let state = (byte1 >> 6) & 0x03;
    let poll = (byte1 >> 5) & 0x01;
    let final_flag = (byte1 >> 4) & 0x01;
    let control_plane_independent = (byte1 >> 3) & 0x01;
    let auth_present = (byte1 >> 2) & 0x01;
    let demand = (byte1 >> 1) & 0x01;
    // RFC 5880 originally reserved the M bit as zero; RFC 8562, Section
    // 4.2 — <https://www.rfc-editor.org/rfc/rfc8562#section-4.2> — updates
    // RFC 5880 to set M=1 on MultipointHead sessions, so either value is
    // accepted here.
    let multipoint = byte1 & 0x01;

    let detect_mult = data[2];
    // RFC 5880, Section 6.8.6 #4 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6> — "If the
    // Detect Mult field is zero, the packet MUST be discarded."
    if detect_mult == 0 {
        return Err(PacketError::InvalidFieldValue {
            field: "detect_mult",
            value: 0,
        });
    }

    // RFC 5880, Section 4.1 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-4.1> — "The length
    // of the BFD Control packet, in bytes."
    let length_u8 = data[3];
    let length = length_u8 as usize;
    // RFC 5880, Section 6.8.6 #2 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6> — Length
    // below the minimum (24 without auth, 26 with auth) MUST be
    // discarded. The auth variant is enforced below once the A bit is
    // known.
    if length < MIN_HEADER_SIZE {
        return Err(PacketError::InvalidFieldValue {
            field: "length",
            value: length_u8 as u32,
        });
    }
    // RFC 5880, Section 6.8.6 #3 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6> — "If the
    // Length field is greater than the payload of the encapsulating
    // protocol, the packet MUST be discarded."
    if data.len() < length {
        return Err(PacketError::Truncated {
            expected: length,
            actual: data.len(),
        });
    }

    let my_discriminator = read_be_u32(data, 4)?;
    // RFC 5880, Section 6.8.6 #6 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6> — "If the My
    // Discriminator field is zero, the packet MUST be discarded."
    if my_discriminator == 0 {
        return Err(PacketError::InvalidFieldValue {
            field: "my_discriminator",
            value: 0,
        });
    }
    let your_discriminator = read_be_u32(data, 8)?;
    let desired_min_tx = read_be_u32(data, 12)?;
    let required_min_rx = read_be_u32(data, 16)?;
    let required_min_echo_rx = read_be_u32(data, 20)?;

    buf.begin_layer(layer_name, None, descriptors, offset..offset + length);
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

    // RFC 5880, Section 4.2 —
    // <https://www.rfc-editor.org/rfc/rfc5880#section-4.2> — Optional
    // Authentication Section.
    if auth_present == 1 {
        // RFC 5880, Section 6.8.6 #2 —
        // <https://www.rfc-editor.org/rfc/rfc5880#section-6.8.6> — when
        // the A bit is set, the minimum correct Length is 26.
        if length < MIN_HEADER_SIZE_WITH_AUTH {
            return Err(PacketError::InvalidHeader(
                "BFD auth present but length is less than minimum with auth",
            ));
        }
        let auth_type = data[24];
        let auth_len = data[25] as usize;

        // RFC 5880, Sections 4.2–4.4 and 6.7.2–6.7.4 — each authentication
        // type has a fixed Auth Len or a bounded range, including the Type
        // and Length bytes themselves. Packets outside it "MUST be
        // discarded", so they are rejected here rather than shown with
        // mis-sized password / digest / hash fields.
        //   - Simple Password (Section 6.7.2 —
        //     <https://www.rfc-editor.org/rfc/rfc5880#section-6.7.2>):
        //     "The Auth Len field MUST be set to the proper length (4 to 19
        //     bytes)."
        //   - Keyed / Meticulous Keyed MD5 (Section 6.7.3 —
        //     <https://www.rfc-editor.org/rfc/rfc5880#section-6.7.3>):
        //     "If the Auth Len field is not equal to 24, the packet MUST be
        //     discarded."
        //   - Keyed / Meticulous Keyed SHA1 (Section 6.7.4 —
        //     <https://www.rfc-editor.org/rfc/rfc5880#section-6.7.4>):
        //     "If the Auth Len field is not equal to 28, the packet MUST be
        //     discarded."
        //   - Unknown types: at least one byte of data after Type and Len.
        let valid_auth_len = match auth_type {
            1 => MIN_AUTH_LEN_SIMPLE_PASSWORD..=MAX_AUTH_LEN_SIMPLE_PASSWORD,
            2 | 3 => AUTH_LEN_MD5..=AUTH_LEN_MD5,
            4 | 5 => AUTH_LEN_SHA1..=AUTH_LEN_SHA1,
            _ => MIN_AUTH_LEN_UNKNOWN..=usize::from(u8::MAX),
        };

        if !valid_auth_len.contains(&auth_len) {
            return Err(PacketError::InvalidHeader(
                "BFD auth length is invalid for auth type",
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
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_AUTH_LEN],
            FieldValue::U8(data[25]),
            offset + 25..offset + 26,
        );
        match auth_type {
            // RFC 5880, Section 4.2 —
            // <https://www.rfc-editor.org/rfc/rfc5880#section-4.2> —
            // Simple Password: Auth Key ID followed by the password.
            1 => {
                push_auth_key_id(buf, data, offset);
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_PASSWORD],
                    FieldValue::Bytes(&data[AUTH_KEY_ID_OFFSET + 1..auth_end]),
                    offset + AUTH_KEY_ID_OFFSET + 1..offset + auth_end,
                );
            }
            // RFC 5880, Section 4.3 —
            // <https://www.rfc-editor.org/rfc/rfc5880#section-4.3> —
            // Keyed MD5 / Meticulous Keyed MD5: Auth Key ID, Reserved,
            // Sequence Number, Auth Key/Digest.
            // RFC 5880, Section 4.4 —
            // <https://www.rfc-editor.org/rfc/rfc5880#section-4.4> —
            // Keyed SHA1 / Meticulous Keyed SHA1: same layout with an
            // Auth Key/Hash.
            2..=5 => {
                push_auth_key_id(buf, data, offset);
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_AUTH_RESERVED],
                    FieldValue::U8(data[AUTH_KEY_ID_OFFSET + 1]),
                    offset + AUTH_KEY_ID_OFFSET + 1..offset + AUTH_SEQUENCE_OFFSET,
                );
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
                    FieldValue::U32(read_be_u32(data, AUTH_SEQUENCE_OFFSET)?),
                    offset + AUTH_SEQUENCE_OFFSET..offset + AUTH_DIGEST_OFFSET,
                );
                let fd = if auth_type <= 3 { FD_DIGEST } else { FD_HASH };
                buf.push_field(
                    &FIELD_DESCRIPTORS[fd],
                    FieldValue::Bytes(&data[AUTH_DIGEST_OFFSET..auth_end]),
                    offset + AUTH_DIGEST_OFFSET..offset + auth_end,
                );
            }
            // Unknown Auth Type: the body format is not defined, so it
            // is kept as raw bytes.
            _ => {
                buf.push_field(
                    &FIELD_DESCRIPTORS[FD_AUTH_DATA],
                    FieldValue::Bytes(&data[26..auth_end]),
                    offset + 26..offset + auth_end,
                );
            }
        }
    }

    buf.end_layer();

    Ok(DissectResult::new(length, DispatchHint::End))
}

/// Pushes the Auth Key ID octet shared by all defined authentication types.
///
/// RFC 5880, Sections 4.2–4.4 —
/// <https://www.rfc-editor.org/rfc/rfc5880#section-4.2>
fn push_auth_key_id<'pkt>(buf: &mut DissectBuffer<'pkt>, data: &'pkt [u8], offset: usize) {
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_AUTH_KEY_ID],
        FieldValue::U8(data[AUTH_KEY_ID_OFFSET]),
        offset + AUTH_KEY_ID_OFFSET..offset + AUTH_KEY_ID_OFFSET + 1,
    );
}

/// Layer name used for BFD Control packets.
const CONTROL_SHORT_NAME: &str = "BFD";

/// Layer name used for BFD Echo packets (hyphenated like other variant
/// names such as `GTPv1-U`).
const ECHO_SHORT_NAME: &str = "BFD-Echo";

/// BFD Echo dissector (UDP port 3785).
///
/// RFC 5880, Section 5 — <https://www.rfc-editor.org/rfc/rfc5880#section-5> —
/// "The payload of a BFD Echo packet is a local matter, since only the
/// sending system ever processes the content." RFC 9747, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc9747#section-2> — "the Unaffiliated
/// BFD Echo packet reuses the format of the BFD Control packet defined in
/// \[RFC5880\]".
///
/// Every packet produces one `BFD-Echo` layer. When the payload validates
/// as a Control packet, the layer carries the Control fields; otherwise it
/// carries a single opaque `payload` field. An Echo packet never produces
/// an error.
pub struct BfdEchoDissector;

impl Dissector for BfdEchoDissector {
    fn name(&self) -> &'static str {
        "Bidirectional Forwarding Detection Echo"
    }

    fn short_name(&self) -> &'static str {
        ECHO_SHORT_NAME
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
        let layer_count = buf.layers().len();
        let field_count = buf.fields().len();
        if let Ok(result) = dissect_control(data, buf, offset, ECHO_SHORT_NAME, FIELD_DESCRIPTORS) {
            return Ok(result);
        }
        // Not a valid Control packet: roll back anything the Control
        // dissector pushed before it failed.
        while buf.layers().len() > layer_count {
            buf.pop_layer();
        }
        buf.truncate_fields(field_count);

        buf.begin_layer(
            ECHO_SHORT_NAME,
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ECHO_PAYLOAD],
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
        buf.end_layer();

        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # RFC 5880 Coverage
    //
    // | RFC Section | Description                                | Test                              |
    // |-------------|--------------------------------------------|-----------------------------------|
    // | 4.1         | Header: Version, Diagnostic                | test_parse_basic_up               |
    // | 4.1         | Header: State, flags                       | test_parse_all_flags_set          |
    // | 4.1         | Header: Detect Mult, Length                | test_parse_basic_up               |
    // | 4.1         | Header: Discriminators                     | test_parse_basic_up               |
    // | 4.1         | Header: Interval fields                    | test_parse_basic_up               |
    // | 4.1         | All diagnostic codes                       | test_diagnostic_codes             |
    // | 4.1         | All state values                           | test_state_values                 |
    // | 4.1         | Multipoint (M) bit set (RFC 8562 update)   | test_parse_multipoint_bit_set     |
    // | 4.2         | Auth section (Simple Password)             | test_parse_with_auth_simple       |
    // | 4.2         | Auth section (Keyed MD5)                   | test_parse_with_auth_md5          |
    // | 4.2         | Auth section (Keyed SHA1)                  | test_parse_with_auth_sha1         |
    // | 4.2         | Simple Password too short (< 4) rejected   | test_simple_password_too_short    |
    // | 4.2         | Keyed MD5 wrong length rejected            | test_md5_wrong_length             |
    // | 4.2         | Keyed SHA1 wrong length rejected           | test_sha1_wrong_length            |
    // | 6.7.2-6.7.4 | Auth Len above fixed / maximum rejected    | test_auth_len_above_fixed_or_maximum_rejected |
    // | 4.2         | Auth section (unknown type, raw data)      | test_parse_with_auth_unknown_type |
    // | 4.3         | Keyed MD5 fields split                     | test_parse_with_auth_md5          |
    // | 4.3, 4.4    | Meticulous MD5 / SHA1 fields split         | test_parse_with_auth_meticulous_md5_and_sha1 |
    // | 4.4         | Keyed SHA1 fields split                    | test_parse_with_auth_sha1         |
    // | 5           | Echo: opaque payload                       | echo_opaque_payload               |
    // | 5           | Echo: non-Control payload (version 0)      | echo_payload_with_invalid_version |
    // | 5           | Echo: Control-like payload rolled back     | echo_control_with_bad_auth_rolls_back |
    // | 5           | Echo: field descriptors                    | echo_field_descriptors            |
    // | 6.8.6 #1    | Version != 1 rejected                      | test_invalid_version              |
    // | 6.8.6 #2    | Invalid length (< 24)                      | test_invalid_length_field         |
    // | 6.8.6 #3    | Length > payload                           | test_length_exceeds_data          |
    // | 6.8.6 #2    | Auth present but length < 26               | test_auth_present_but_truncated   |
    // | 6.8.6 #4    | Detect Mult == 0 rejected                  | test_detect_mult_zero             |
    // | 6.8.6 #6    | My Discriminator == 0 rejected             | test_my_discriminator_zero        |
    // | ---         | Truncated header (< 24 bytes)              | test_truncated_packet             |
    // | ---         | Auth section exceeds length                | test_auth_section_exceeds_length  |
    // | ---         | Offset handling                            | test_dissect_with_offset          |
    // | ---         | Field descriptors                          | test_field_descriptors            |
    //
    // # RFC 9747 Coverage
    //
    // | RFC Section | Description                                | Test                              |
    // |-------------|--------------------------------------------|-----------------------------------|
    // | 2           | Unaffiliated Echo in Control format        | echo_unaffiliated_control_format  |

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
            buf.field_by_name(layer, "auth_key_id").unwrap().value,
            FieldValue::U8(0x41)
        );
        assert_eq!(
            buf.field_by_name(layer, "password").unwrap().value,
            FieldValue::Bytes(&[0x42])
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
            buf.field_by_name(layer, "auth_len").unwrap().value,
            FieldValue::U8(9)
        );
        let key_id = buf.field_by_name(layer, "auth_key_id").unwrap();
        assert_eq!(key_id.value, FieldValue::U8(1));
        assert_eq!(key_id.range, 26..27);
        let password = buf.field_by_name(layer, "password").unwrap();
        assert_eq!(password.value, FieldValue::Bytes(b"secret"));
        assert_eq!(password.range, 27..33);
        assert!(buf.field_by_name(layer, "auth_data").is_none());
        assert!(buf.field_by_name(layer, "sequence_number").is_none());
    }

    #[test]
    fn test_parse_with_auth_sha1() {
        // RFC 5880, Section 4.4 — Keyed SHA1: type=4, auth_len=28, key_id=1,
        // reserved=0, seq=1, hash=20 bytes
        //   <https://www.rfc-editor.org/rfc/rfc5880#section-4.4>
        let mut auth_data = vec![1, 0]; // key_id, reserved
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
        assert_eq!(
            buf.field_by_name(layer, "auth_len").unwrap().value,
            FieldValue::U8(28)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_key_id").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_reserved").unwrap().value,
            FieldValue::U8(0)
        );
        let seq = buf.field_by_name(layer, "sequence_number").unwrap();
        assert_eq!(seq.value, FieldValue::U32(1));
        assert_eq!(seq.range, 28..32);
        let hash = buf.field_by_name(layer, "hash").unwrap();
        assert_eq!(hash.value, FieldValue::Bytes(&[0xAA; 20]));
        assert_eq!(hash.range, 32..52);
        assert!(buf.field_by_name(layer, "digest").is_none());
        assert!(buf.field_by_name(layer, "auth_data").is_none());
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
        assert_eq!(descriptors.len(), 25);
        assert_eq!(descriptors[0].name, "version");
        assert_eq!(descriptors[FD_AUTH_DATA].name, "auth_data");
        assert_eq!(descriptors[descriptors.len() - 1].name, "hash");
        // Check optional fields
        assert!(!descriptors[0].optional); // version
        assert!(descriptors[FD_AUTH_TYPE..].iter().all(|d| d.optional));
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

    #[test]
    fn test_invalid_version() {
        // RFC 5880, Section 6.8.6 #1 — "If the version number is not correct
        // (1), the packet MUST be discarded."
        let data = build_bfd(
            0, 0, 3, 0, 0, 0, 0, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "version");
                assert_eq!(value, 0);
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }

        // Version 2 must also be rejected.
        let data = build_bfd(
            2, 0, 3, 0, 0, 0, 0, 0, 0, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "version");
                assert_eq!(value, 2);
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_mult_zero() {
        // RFC 5880, Section 6.8.6 #4 — "If the Detect Mult field is zero, the
        // packet MUST be discarded."
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "detect_mult");
                assert_eq!(value, 0);
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn test_my_discriminator_zero() {
        // RFC 5880, Section 6.8.6 #6 — "If the My Discriminator field is zero,
        // the packet MUST be discarded."
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 0, 0, 0, 3, 24, 0, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&data, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidFieldValue { field, value } => {
                assert_eq!(field, "my_discriminator");
                assert_eq!(value, 0);
            }
            other => panic!("Expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_multipoint_bit_set() {
        // RFC 5880 originally required M to be zero; RFC 8562, Section 4.2 —
        // <https://www.rfc-editor.org/rfc/rfc8562#section-4.2> — redefines M=1
        // for MultipointHead sessions. The dissector therefore accepts M=1.
        let data = build_bfd(
            1, 0, 3, 0, 0, 0, 0, 0, 1, 3, 24, 1, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "multipoint").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn test_simple_password_too_short() {
        // RFC 5880, Section 4.2 — Simple Password Auth Len range is 4-19
        // (Type + Len + Key ID + 1-16 password bytes). Auth Len == 3 is
        // malformed (no password bytes).
        let mut pkt = build_bfd(
            1, 0, 3, 0, 0, 0, 1, 0, 0, 3, 27, 1, 0, 1_000_000, 1_000_000, 0,
        );
        pkt.push(1); // auth type: Simple Password
        pkt.push(3); // auth len: illegal, below minimum 4
        pkt.push(1); // key id
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&pkt, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("auth length"), "unexpected message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_with_auth_md5() {
        // Keyed MD5: type=2, auth_len=24, key_id=1, reserved=0, 4-byte seq,
        // 16-byte digest.
        let mut auth_data = vec![1, 0]; // key_id, reserved
        auth_data.extend_from_slice(&42u32.to_be_bytes()); // sequence number
        auth_data.extend_from_slice(&[0xBB; 16]); // MD5 digest
        let data = build_bfd_with_auth(1, 0, 3, 3, 0x1000, 0x2000, 2, &auth_data);
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "auth_type").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "auth_type_name"),
            Some("Keyed MD5")
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_len").unwrap().value,
            FieldValue::U8(24)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_key_id").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_reserved").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(42)
        );
        let digest = buf.field_by_name(layer, "digest").unwrap();
        assert_eq!(digest.value, FieldValue::Bytes(&[0xBB; 16]));
        assert_eq!(digest.range, 32..48);
        assert!(buf.field_by_name(layer, "hash").is_none());
    }

    #[test]
    fn test_parse_with_auth_meticulous_md5_and_sha1() {
        // RFC 5880, Sections 4.3 and 4.4 — Meticulous variants share the
        // Keyed layouts.
        //   <https://www.rfc-editor.org/rfc/rfc5880#section-4.3>
        let mut md5 = vec![7, 0];
        md5.extend_from_slice(&5u32.to_be_bytes());
        md5.extend_from_slice(&[0x11; 16]);
        let data = build_bfd_with_auth(1, 0, 3, 3, 0x1000, 0x2000, 3, &md5);
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "digest").unwrap().value,
            FieldValue::Bytes(&[0x11; 16])
        );

        let mut sha1 = vec![7, 0];
        sha1.extend_from_slice(&6u32.to_be_bytes());
        sha1.extend_from_slice(&[0x22; 20]);
        let data = build_bfd_with_auth(1, 0, 3, 3, 0x1000, 0x2000, 5, &sha1);
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "hash").unwrap().value,
            FieldValue::Bytes(&[0x22; 20])
        );
    }

    #[test]
    fn test_parse_with_auth_unknown_type() {
        // Unknown Auth Type: the body format is not defined, so it is kept
        // as raw bytes after the Auth Type and Auth Len octets.
        let data = build_bfd_with_auth(1, 0, 3, 3, 0x1000, 0x2000, 9, &[1, 2, 3]);
        let mut buf = DissectBuffer::new();
        BfdDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "auth_len").unwrap().value,
            FieldValue::U8(5)
        );
        assert_eq!(
            buf.field_by_name(layer, "auth_data").unwrap().value,
            FieldValue::Bytes(&[1, 2, 3])
        );
        assert!(buf.field_by_name(layer, "auth_key_id").is_none());
    }

    #[test]
    fn echo_opaque_payload() {
        // RFC 5880, Section 5 — the Echo payload is a local matter. An
        // 8-byte vendor payload must not be treated as an error.
        //   <https://www.rfc-editor.org/rfc/rfc5880#section-5>
        let data = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A];
        let mut buf = DissectBuffer::new();
        let result = BfdEchoDissector.dissect(&data, &mut buf, 42).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert!(matches!(result.next, DispatchHint::End));
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, BfdEchoDissector.short_name());
        assert_eq!(layer.range, 42..50);
        let payload = buf.field_by_name(layer, "payload").unwrap();
        assert_eq!(payload.value, FieldValue::Bytes(&data));
        assert_eq!(payload.range, 42..50);
        assert_eq!(buf.fields().len(), 1);
    }

    #[test]
    fn echo_payload_with_invalid_version() {
        // 24 bytes whose version bits are 0: not a Control packet.
        let data: Vec<u8> = (0..24u8)
            .map(|i| [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][i as usize % 8])
            .collect();
        let mut buf = DissectBuffer::new();
        let result = BfdEchoDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(buf.layers().len(), 1);
        assert_eq!(buf.layers()[0].name, BfdEchoDissector.short_name());
    }

    #[test]
    fn echo_unaffiliated_control_format() {
        // RFC 9747, Section 2 — Unaffiliated BFD Echo packets reuse the
        // Control packet format on UDP port 3785.
        //   <https://www.rfc-editor.org/rfc/rfc9747#section-2>
        let data = build_bfd(
            1, 0, 1, 0, 0, 0, 0, 0, 0, 3, 24, 0x1234, 0, 1_000_000, 1_000_000, 0,
        );
        let mut buf = DissectBuffer::new();
        let result = BfdEchoDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        // The layer name is the dissector's short_name (Dissector trait
        // contract), whichever form the Echo payload takes.
        assert_eq!(layer.name, BfdEchoDissector.short_name());
        assert_eq!(layer.display_name, None);
        assert!(std::ptr::eq(
            layer.field_descriptors,
            BfdEchoDissector.field_descriptors()
        ));
        assert_eq!(
            buf.field_by_name(layer, "my_discriminator").unwrap().value,
            FieldValue::U32(0x1234)
        );
        assert!(buf.field_by_name(layer, "payload").is_none());
    }

    #[test]
    fn echo_control_with_bad_auth_rolls_back() {
        // Control header validates but the auth section does not: the
        // partially pushed Control layer must be discarded and the payload
        // shown as opaque Echo data.
        let mut pkt = build_bfd(
            1, 0, 3, 0, 0, 0, 1, 0, 0, 3, 28, 1, 0, 1_000_000, 1_000_000, 0,
        );
        pkt.extend_from_slice(&[1, 10, 1, b'x']);
        let mut buf = DissectBuffer::new();
        buf.begin_layer("UDP", None, &[], 0..8);
        buf.end_layer();
        let fields_before = buf.fields().len();
        let result = BfdEchoDissector.dissect(&pkt, &mut buf, 8).unwrap();
        assert_eq!(result.bytes_consumed, 28);
        assert_eq!(buf.layers().len(), 2);
        let layer = &buf.layers()[1];
        assert_eq!(layer.name, BfdEchoDissector.short_name());
        assert_eq!(buf.fields().len(), fields_before + 1);
        assert_eq!(
            buf.field_by_name(layer, "payload").unwrap().value,
            FieldValue::Bytes(&pkt)
        );
    }

    #[test]
    fn echo_field_descriptors() {
        // Echo layers carry either the Control fields or an opaque payload,
        // so the Echo schema is the Control schema plus `payload`.
        let fds = BfdEchoDissector.field_descriptors();
        let control = BfdDissector.field_descriptors();
        assert_eq!(fds.len(), control.len() + 1);
        assert!(fds.iter().zip(control).all(|(a, b)| a.name == b.name));
        assert_eq!(fds[fds.len() - 1].name, "payload");
        assert!(fds[fds.len() - 1].optional);
        assert!(control.iter().all(|d| d.name != "payload"));
        // Short names follow the hyphenated variant convention (GTPv1-U).
        assert_eq!(BfdEchoDissector.short_name(), "BFD-Echo");
        assert!(!BfdEchoDissector.name().is_empty());
    }

    #[test]
    fn test_md5_wrong_length() {
        // Keyed MD5 requires Auth Len == 24. Using 20 must be rejected.
        let mut pkt = build_bfd(
            1, 0, 3, 0, 0, 0, 1, 0, 0, 3, 44, 1, 0, 1_000_000, 1_000_000, 0,
        );
        pkt.push(2); // auth type: Keyed MD5
        pkt.push(20); // illegal: below required 24
        pkt.extend_from_slice(&[0u8; 18]); // fill remaining bytes
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&pkt, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("auth length"), "unexpected message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_sha1_wrong_length() {
        // Keyed SHA1 requires Auth Len == 28. Using 24 must be rejected.
        let mut pkt = build_bfd(
            1, 0, 3, 0, 0, 0, 1, 0, 0, 3, 48, 1, 0, 1_000_000, 1_000_000, 0,
        );
        pkt.push(4); // auth type: Keyed SHA1
        pkt.push(24); // illegal: below required 28
        pkt.extend_from_slice(&[0u8; 22]); // fill remaining bytes
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&pkt, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("auth length"), "unexpected message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_len_above_fixed_or_maximum_rejected() {
        // RFC 5880, Section 6.7.3 — "If the Auth Len field is not equal to
        // 24, the packet MUST be discarded." Section 6.7.4 — the same with
        // 28. Section 6.7.2 — Simple Password Auth Len is 4 to 19 bytes.
        //   <https://www.rfc-editor.org/rfc/rfc5880#section-6.7.3>
        for (auth_type, auth_len) in [(1u8, 20u8), (2, 40), (3, 25), (4, 32), (5, 29)] {
            let total = 24 + auth_len as usize;
            let mut pkt = build_bfd(
                1,
                0,
                3,
                0,
                0,
                0,
                1,
                0,
                0,
                3,
                total as u8,
                1,
                0,
                1_000_000,
                1_000_000,
                0,
            );
            pkt.push(auth_type);
            pkt.push(auth_len);
            pkt.extend_from_slice(&vec![0u8; auth_len as usize - 2]);
            let mut buf = DissectBuffer::new();
            match BfdDissector.dissect(&pkt, &mut buf, 0).unwrap_err() {
                PacketError::InvalidHeader(msg) => {
                    assert!(msg.contains("auth length"), "unexpected message: {msg}");
                }
                other => panic!("type {auth_type}: expected InvalidHeader, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_auth_section_exceeds_length() {
        // Auth Len extends beyond the packet length field.
        let mut pkt = build_bfd(
            1, 0, 3, 0, 0, 0, 1, 0, 0, 3, 28, 1, 0, 1_000_000, 1_000_000, 0,
        );
        pkt.push(1); // auth type: Simple Password
        pkt.push(10); // auth len: 10, but only 4 bytes available (24..28)
        pkt.push(1);
        pkt.push(b'x');
        let mut buf = DissectBuffer::new();
        let result = BfdDissector.dissect(&pkt, &mut buf, 0);
        match result.unwrap_err() {
            PacketError::InvalidHeader(msg) => {
                assert!(msg.contains("exceeds"), "unexpected message: {msg}");
            }
            other => panic!("Expected InvalidHeader, got {other:?}"),
        }
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

        assert_layer_and_references(&BfdDissector);
        assert_layer_and_references(&BfdEchoDissector);
    }
}
