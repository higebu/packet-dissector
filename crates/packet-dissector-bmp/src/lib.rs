//! BMP (BGP Monitoring Protocol) dissector.
//!
//! Decodes one BMP message: the common header, the per-peer header and the
//! body of every message type. BGP messages carried in Route Monitoring,
//! Peer Up, Peer Down and Route Mirroring messages are dissected with
//! [`packet_dissector_bgp::BgpDissector`] and appended as `BGP` layers after
//! the `BMP` layer.
//!
//! BMP has no assigned port: "The passive party is configured to listen on
//! a particular TCP port" (RFC 7854, Section 3.2 —
//! <https://www.rfc-editor.org/rfc/rfc7854#section-3.2>), so the dissector
//! is only available by decode-as name.
//!
//! ## References
//! - RFC 7854 (BMP): <https://www.rfc-editor.org/rfc/rfc7854>
//! - RFC 8671 (Support for Adj-RIB-Out in BMP): <https://www.rfc-editor.org/rfc/rfc8671>
//! - RFC 9069 (Support for Local RIB in BMP): <https://www.rfc-editor.org/rfc/rfc9069>
//! - RFC 9515 (Revision to Registration Procedures for Multiple BMP Registries): <https://www.rfc-editor.org/rfc/rfc9515>
//! - RFC 9736 (BMP Peer Up Message Namespace): <https://www.rfc-editor.org/rfc/rfc9736>
//! - RFC 9972 (Advanced BMP Statistics Types): <https://www.rfc-editor.org/rfc/rfc9972>
//! - IANA BMP Parameters: <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml>

#![deny(missing_docs)]

use core::ops::Range;

use packet_dissector_bgp::{AsNumberSize, BgpDissector};
use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u32, read_be_u64};

/// Common header size: Version (1), Message Length (4), Message Type (1).
/// RFC 7854, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.1>
const COMMON_HEADER_SIZE: usize = 6;

/// Per-peer header size: Peer Type (1), Peer Flags (1), Peer Distinguisher
/// (8), Peer Address (16), Peer AS (4), Peer BGP ID (4), Timestamp (8).
/// RFC 7854, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.2>
const PER_PEER_HEADER_SIZE: usize = 42;

/// BMP version: "This is set to '3' for all messages defined in this
/// specification." RFC 7854, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.1>
const VERSION_3: u8 = 3;

/// Message types. RFC 7854, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.1>
const MSG_ROUTE_MONITORING: u8 = 0;
const MSG_STATISTICS_REPORT: u8 = 1;
const MSG_PEER_DOWN: u8 = 2;
const MSG_PEER_UP: u8 = 3;
const MSG_INITIATION: u8 = 4;
const MSG_TERMINATION: u8 = 5;
const MSG_ROUTE_MIRRORING: u8 = 6;

/// Peer types 0-2 (RFC 7854, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.2>) and 3 (RFC 9069,
/// Section 4.1 — <https://www.rfc-editor.org/rfc/rfc9069#section-4.1>).
const PEER_TYPE_LOCAL_INSTANCE: u8 = 2;
const PEER_TYPE_LOC_RIB: u8 = 3;

/// Peer Flags for peer types 0-2: V, L, A (RFC 7854, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.2>) and O
/// (RFC 8671, Section 4 — <https://www.rfc-editor.org/rfc/rfc8671#section-4>).
const FLAG_V: u8 = 0x80;
const FLAG_L: u8 = 0x40;
const FLAG_A: u8 = 0x20;
const FLAG_O: u8 = 0x10;

/// Peer Flags for the Loc-RIB Instance Peer type: F.
/// RFC 9069, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc9069#section-4.2>
const FLAG_F: u8 = 0x80;

/// Peer Up fixed part: Local Address (16), Local Port (2), Remote Port (2).
/// RFC 7854, Section 4.10 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.10>
const PEER_UP_FIXED_SIZE: usize = 20;

/// Information / Stat / Route Mirroring TLV header: Type (2), Length (2).
/// RFC 7854, Sections 4.4, 4.7 and 4.8 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.4>
const TLV_HEADER_SIZE: usize = 4;

/// Peer Down reason codes that carry a BGP NOTIFICATION PDU, an FSM event
/// code, or TLVs. RFC 7854, Section 4.9 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.9>; RFC 9069,
/// Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9069#section-5.3>
const PEER_DOWN_LOCAL_NOTIFICATION: u8 = 1;
const PEER_DOWN_LOCAL_FSM_EVENT: u8 = 2;
const PEER_DOWN_REMOTE_NOTIFICATION: u8 = 3;
const PEER_DOWN_LOCAL_TLV: u8 = 6;

/// Route Mirroring TLV types. RFC 7854, Section 4.7 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.7>
const MIRRORING_TLV_BGP_MESSAGE: u16 = 0;
const MIRRORING_TLV_INFORMATION: u16 = 1;

/// Termination Message TLV type "Reason". RFC 7854, Section 4.5 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.5>
const TERMINATION_TLV_REASON: u16 = 1;

/// BGP message header size and marker. RFC 4271, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc4271#section-4.1>
const BGP_HEADER_SIZE: usize = 19;
const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// Maximum number of BGP messages one BMP message carries: the sent and
/// received OPEN of a Peer Up (RFC 7854, Section 4.10 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.10>).
const MAX_BGP_MESSAGES: usize = 2;

/// Returns the name of a BMP message type.
///
/// IANA BMP Message Types —
/// <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#message-types>
fn message_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Route Monitoring"),
        1 => Some("Statistics Report"),
        2 => Some("Peer Down Notification"),
        3 => Some("Peer Up Notification"),
        4 => Some("Initiation"),
        5 => Some("Termination"),
        6 => Some("Route Mirroring"),
        251..=254 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a BMP peer type.
///
/// IANA BMP Peer Types —
/// <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-types>
fn peer_type_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Global Instance Peer"),
        1 => Some("RD Instance Peer"),
        2 => Some("Local Instance Peer"),
        3 => Some("Loc-RIB Instance Peer"),
        251..=254 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a Peer Down reason code.
///
/// IANA BMP Peer Down Reason Codes —
/// <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-down-reason-codes>
fn peer_down_reason_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Local system closed, NOTIFICATION PDU follows"),
        2 => Some("Local system closed, FSM Event follows"),
        3 => Some("Remote system closed, NOTIFICATION PDU follows"),
        4 => Some("Remote system closed, no data"),
        5 => Some("Peer de-configured"),
        6 => Some("Local system closed, TLV data follows"),
        251..=254 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a statistics type.
///
/// IANA BMP Statistics Types —
/// <https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#statistics-types>
/// (RFC 7854, Section 4.8; RFC 8671, Section 5; RFC 9972, Section 3).
///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.8>
///   <https://www.rfc-editor.org/rfc/rfc8671#section-5>
///   <https://www.rfc-editor.org/rfc/rfc9972#section-3>
fn stat_type_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("Number of prefixes rejected by inbound policy"),
        1 => Some("Number of (known) duplicate prefix advertisements"),
        2 => Some("Number of (known) duplicate withdraws"),
        3 => Some("Number of updates invalidated due to CLUSTER_LIST loop"),
        4 => Some("Number of updates invalidated due to AS_PATH loop"),
        5 => Some("Number of updates invalidated due to ORIGINATOR_ID"),
        6 => Some(
            "Number of updates invalidated due to a loop found in AS_CONFED_SEQUENCE or AS_CONFED_SET",
        ),
        7 => Some("Number of routes in Adj-RIBs-In"),
        8 => Some("Number of routes in Loc-RIB"),
        9 => Some("Number of routes in per-AFI/SAFI Adj-RIB-In"),
        10 => Some("Number of routes in per-AFI/SAFI Loc-RIB"),
        11 => Some("Number of updates subjected to treat-as-withdraw"),
        12 => Some("Number of prefixes subjected to treat-as-withdraw"),
        13 => Some("Number of duplicate update messages received"),
        14 => Some("Number of routes in pre-policy Adj-RIB-Out"),
        15 => Some("Number of routes in post-policy Adj-RIB-Out"),
        16 => Some("Number of routes in per-AFI/SAFI pre-policy Adj-RIB-Out"),
        17 => Some("Number of routes in per-AFI/SAFI post-policy Adj-RIB-Out"),
        18 => Some("Number of routes currently in the pre-policy Adj-RIB-In"),
        19 => Some("Number of routes currently in the per-AFI/SAFI pre-policy Adj-RIB-In"),
        20 => Some("Number of routes currently in the post-policy Adj-RIB-In"),
        21 => Some("Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In"),
        22 => Some(
            "Number of routes currently in the per-AFI/SAFI pre-policy Adj-RIB-In rejected by an inbound policy",
        ),
        23 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In accepted by an inbound policy",
        ),
        24 => Some("Number of routes currently in per-AFI/SAFI selected as primary route"),
        25 => Some("Number of routes currently in per-AFI/SAFI selected as a backup route"),
        26 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In or Loc-RIB suppressed by a configured route-damping policy",
        ),
        27 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In or Loc-RIB marked as stale by Graceful Restart",
        ),
        28 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In or Loc-RIB marked as stale by Long-Lived Graceful Restart",
        ),
        29 => Some(
            "Number of routes currently in the post-policy Adj-RIB-In left before exceeding the received-route threshold",
        ),
        30 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In left before exceeding the received-route threshold",
        ),
        31 => Some(
            "Number of routes currently in the post-policy Adj-RIB-In or Loc-RIB left before exceeding a license-customized route threshold",
        ),
        32 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In or Loc-RIB left before exceeding a license-customized route threshold",
        ),
        33 => Some(
            "Number of routes currently in the pre-policy Adj-RIB-In rejected due to exceeding the maximum AS_PATH length",
        ),
        34 => Some(
            "Number of routes currently in the per-AFI/SAFI pre-policy Adj-RIB-In rejected due to exceeding the maximum AS_PATH length",
        ),
        35 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In invalidated after verifying the route origin ASN through ROA of RPKI",
        ),
        36 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In validated after verifying the route origin ASN through ROA of RPKI",
        ),
        37 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-In whose RPKI route origin validation state is NotFound",
        ),
        38 => Some(
            "Number of routes currently in the per-AFI/SAFI pre-policy Adj-RIB-Out rejected by an outbound policy",
        ),
        39 => Some(
            "Number of routes currently in the pre-policy Adj-RIB-Out filtered due to AS_PATH length exceeding the locally configured maximum",
        ),
        40 => Some(
            "Number of routes currently in the per-AFI/SAFI pre-policy Adj-RIB-Out filtered due to AS_PATH length exceeding the locally configured maximum",
        ),
        41 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-Out invalidated after verifying the route origin ASN through ROA of RPKI",
        ),
        42 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-Out validated after verifying the route origin ASN through ROA of RPKI",
        ),
        43 => Some(
            "Number of routes currently in the per-AFI/SAFI post-policy Adj-RIB-Out whose RPKI route origin validation state is NotFound",
        ),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of an Initiation Information TLV type.
///
/// RFC 9736, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc9736#section-3.1>;
/// IANA BMP Initiation Information TLVs.
fn initiation_tlv_type_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("String"),
        1 => Some("sysDescr"),
        2 => Some("sysName"),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a Peer Up Information TLV type.
///
/// RFC 9736, Section 3.3 — <https://www.rfc-editor.org/rfc/rfc9736#section-3.3>;
/// IANA BMP Peer Up Message TLVs.
fn peer_up_tlv_type_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("String"),
        3 => Some("VRF/Table Name"),
        4 => Some("Admin Label"),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a Peer Down Information TLV type.
///
/// RFC 9069, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9069#section-5.3>
fn peer_down_tlv_type_name(v: u16) -> Option<&'static str> {
    match v {
        3 => Some("VRF/Table Name"),
        _ => None,
    }
}

/// Returns the name of a Termination Message TLV type.
///
/// RFC 7854, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.5>
fn termination_tlv_type_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("String"),
        1 => Some("Reason"),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a Termination Message reason code.
///
/// RFC 7854, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.5>;
/// IANA BMP Termination Message Reason Codes.
fn termination_reason_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("Administratively closed"),
        1 => Some("Unspecified reason"),
        2 => Some("Out of resources"),
        3 => Some("Redundant connection"),
        4 => Some("Permanently administratively closed"),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a Route Mirroring TLV type.
///
/// RFC 7854, Section 4.7 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.7>
fn mirroring_tlv_type_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("BGP Message"),
        1 => Some("Information"),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Returns the name of a Route Mirroring Information code.
///
/// RFC 7854, Section 4.7 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.7>
fn mirroring_information_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("Errored PDU"),
        1 => Some("Messages Lost"),
        65531..=65534 => Some("Experimental"),
        _ => None,
    }
}

/// Resolves the name of a TLV object from its `type` child.
fn tlv_object_name(
    children: &[packet_dissector_core::field::Field<'_>],
    name_fn: fn(u16) -> Option<&'static str>,
) -> Option<&'static str> {
    children.iter().find_map(|f| match (f.name(), &f.value) {
        ("type", FieldValue::U16(t)) => name_fn(*t),
        _ => None,
    })
}

/// Declares a TLV `type` descriptor whose display name comes from `$name_fn`.
macro_rules! tlv_type_descriptor {
    ($display:literal, $name_fn:path) => {
        FieldDescriptor::new("type", $display, FieldType::U16).with_display_fn(|v, _| match v {
            FieldValue::U16(t) => $name_fn(*t),
            _ => None,
        })
    };
}

/// Declares a TLV object descriptor whose display name comes from `$name_fn`
/// applied to its `type` child.
macro_rules! tlv_object_descriptor {
    ($name:literal, $display:literal, $name_fn:path) => {
        FieldDescriptor::new($name, $display, FieldType::Object).with_display_fn(|v, children| {
            match v {
                FieldValue::Object(_) => tlv_object_name(children, $name_fn),
                _ => None,
            }
        })
    };
}

/// TLV Length (RFC 7854, Section 4.4 —
/// <https://www.rfc-editor.org/rfc/rfc7854#section-4.4>).
const TLV_LENGTH: FieldDescriptor = FieldDescriptor::new("length", "Length", FieldType::U16);

/// A string TLV value (UTF-8 or ASCII text, RFC 9736, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc9736#section-2>).
const TLV_STRING: FieldDescriptor = FieldDescriptor::new("string", "String", FieldType::Bytes)
    .optional()
    .with_format_fn(format_utf8_lossy);

/// A TLV value that is not decoded.
const TLV_VALUE: FieldDescriptor =
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional();

/// Child descriptors of an Initiation Information TLV.
/// RFC 7854, Section 4.4; RFC 9736, Section 3.1.
///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.4>
///   <https://www.rfc-editor.org/rfc/rfc9736#section-3.1>
static INITIATION_TLV_CHILDREN: [FieldDescriptor; 4] = [
    tlv_type_descriptor!("Information Type", initiation_tlv_type_name),
    TLV_LENGTH,
    TLV_STRING,
    TLV_VALUE,
];

/// Child descriptors of a Peer Up Information TLV.
/// RFC 9736, Section 3.3.
///   <https://www.rfc-editor.org/rfc/rfc9736#section-3.3>
static PEER_UP_TLV_CHILDREN: [FieldDescriptor; 4] = [
    tlv_type_descriptor!("Information Type", peer_up_tlv_type_name),
    TLV_LENGTH,
    TLV_STRING,
    TLV_VALUE,
];

/// Child descriptors of a Peer Down Information TLV.
/// RFC 9069, Section 5.3.
///   <https://www.rfc-editor.org/rfc/rfc9069#section-5.3>
static PEER_DOWN_TLV_CHILDREN: [FieldDescriptor; 4] = [
    tlv_type_descriptor!("Information Type", peer_down_tlv_type_name),
    TLV_LENGTH,
    TLV_STRING,
    TLV_VALUE,
];

/// Child descriptors of a Termination Message TLV.
/// RFC 7854, Section 4.5.
///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.5>
static TERMINATION_TLV_CHILDREN: [FieldDescriptor; 5] = [
    tlv_type_descriptor!("Information Type", termination_tlv_type_name),
    TLV_LENGTH,
    TLV_STRING,
    FieldDescriptor::new("reason", "Reason", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(r) => termination_reason_name(*r),
            _ => None,
        }),
    TLV_VALUE,
];

/// Child descriptors of a Route Mirroring TLV.
/// RFC 7854, Section 4.7.
///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.7>
static MIRRORING_TLV_CHILDREN: [FieldDescriptor; 4] = [
    tlv_type_descriptor!("Type", mirroring_tlv_type_name),
    TLV_LENGTH,
    FieldDescriptor::new("information_code", "Information Code", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(c) => mirroring_information_name(*c),
            _ => None,
        }),
    TLV_VALUE,
];

/// Child descriptors of a Stats Report counter.
/// RFC 7854, Section 4.8 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.8>
static STAT_CHILDREN: [FieldDescriptor; 7] = [
    tlv_type_descriptor!("Stat Type", stat_type_name),
    FieldDescriptor::new("length", "Stat Len", FieldType::U16),
    FieldDescriptor::new("counter", "32-bit Counter", FieldType::U32).optional(),
    FieldDescriptor::new("afi", "AFI", FieldType::U16).optional(),
    FieldDescriptor::new("safi", "SAFI", FieldType::U8).optional(),
    FieldDescriptor::new("gauge", "64-bit Gauge", FieldType::U64).optional(),
    TLV_VALUE,
];

static INITIATION_TLV: FieldDescriptor =
    tlv_object_descriptor!("tlv", "Information TLV", initiation_tlv_type_name)
        .with_children(&INITIATION_TLV_CHILDREN);
static PEER_UP_TLV: FieldDescriptor =
    tlv_object_descriptor!("tlv", "Information TLV", peer_up_tlv_type_name)
        .with_children(&PEER_UP_TLV_CHILDREN);
static PEER_DOWN_TLV: FieldDescriptor =
    tlv_object_descriptor!("tlv", "Information TLV", peer_down_tlv_type_name)
        .with_children(&PEER_DOWN_TLV_CHILDREN);
static TERMINATION_TLV: FieldDescriptor =
    tlv_object_descriptor!("tlv", "Information TLV", termination_tlv_type_name)
        .with_children(&TERMINATION_TLV_CHILDREN);
static MIRRORING_TLV: FieldDescriptor =
    tlv_object_descriptor!("tlv", "Route Mirroring TLV", mirroring_tlv_type_name)
        .with_children(&MIRRORING_TLV_CHILDREN);
static STAT: FieldDescriptor =
    tlv_object_descriptor!("stat", "Stat", stat_type_name).with_children(&STAT_CHILDREN);

/// Field descriptor indices into [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_MESSAGE_LENGTH: usize = 1;
const FD_MESSAGE_TYPE: usize = 2;
const FD_PEER_TYPE: usize = 3;
const FD_PEER_FLAGS: usize = 4;
const FD_V_FLAG: usize = 5;
const FD_L_FLAG: usize = 6;
const FD_A_FLAG: usize = 7;
const FD_O_FLAG: usize = 8;
const FD_F_FLAG: usize = 9;
const FD_PEER_DISTINGUISHER: usize = 10;
const FD_PEER_ADDRESS: usize = 11;
const FD_PEER_AS: usize = 12;
const FD_PEER_BGP_ID: usize = 13;
const FD_TIMESTAMP_SEC: usize = 14;
const FD_TIMESTAMP_USEC: usize = 15;
const FD_STATS_COUNT: usize = 16;
const FD_STATS: usize = 17;
const FD_PEER_DOWN_REASON: usize = 18;
const FD_FSM_EVENT_CODE: usize = 19;
const FD_LOCAL_ADDRESS: usize = 20;
const FD_LOCAL_PORT: usize = 21;
const FD_REMOTE_PORT: usize = 22;
const FD_INITIATION_TLVS: usize = 23;
const FD_PEER_UP_TLVS: usize = 24;
const FD_PEER_DOWN_TLVS: usize = 25;
const FD_TERMINATION_TLVS: usize = 26;
const FD_ROUTE_MIRRORING_TLVS: usize = 27;
const FD_BGP_MESSAGE: usize = 28;
const FD_DATA: usize = 29;

/// Field descriptors for the BMP dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 7854, Section 4.1 — Common Header
    //   https://www.rfc-editor.org/rfc/rfc7854#section-4.1
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("message_length", "Message Length", FieldType::U32),
    FieldDescriptor::new("message_type", "Message Type", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(t) => message_type_name(*t),
            _ => None,
        }
    }),
    // RFC 7854, Section 4.2 — Per-Peer Header
    //   https://www.rfc-editor.org/rfc/rfc7854#section-4.2
    FieldDescriptor::new("peer_type", "Peer Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => peer_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("peer_flags", "Peer Flags", FieldType::U8).optional(),
    FieldDescriptor::new("v_flag", "V Flag (IPv6)", FieldType::U8).optional(),
    FieldDescriptor::new("l_flag", "L Flag (Post-policy)", FieldType::U8).optional(),
    FieldDescriptor::new("a_flag", "A Flag (2-byte AS_PATH)", FieldType::U8).optional(),
    FieldDescriptor::new("o_flag", "O Flag (Adj-RIB-Out)", FieldType::U8).optional(),
    FieldDescriptor::new("f_flag", "F Flag (Filtered)", FieldType::U8).optional(),
    FieldDescriptor::new("peer_distinguisher", "Peer Distinguisher", FieldType::Bytes).optional(),
    // Ipv4Addr or Ipv6Addr per the V flag; raw bytes for other peer types.
    FieldDescriptor::new("peer_address", "Peer Address", FieldType::Any).optional(),
    FieldDescriptor::new("peer_as", "Peer AS", FieldType::U32).optional(),
    FieldDescriptor::new("peer_bgp_id", "Peer BGP ID", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("timestamp_sec", "Timestamp (seconds)", FieldType::U32).optional(),
    FieldDescriptor::new("timestamp_usec", "Timestamp (microseconds)", FieldType::U32).optional(),
    // RFC 7854, Section 4.8 — Stats Reports
    //   https://www.rfc-editor.org/rfc/rfc7854#section-4.8
    FieldDescriptor::new("stats_count", "Stats Count", FieldType::U32).optional(),
    FieldDescriptor::new("stats", "Stats", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&STAT)),
    // RFC 7854, Section 4.9 — Peer Down Notification
    //   https://www.rfc-editor.org/rfc/rfc7854#section-4.9
    FieldDescriptor::new("reason", "Reason", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(r) => peer_down_reason_name(*r),
            _ => None,
        }),
    FieldDescriptor::new("fsm_event_code", "FSM Event Code", FieldType::U16).optional(),
    // RFC 7854, Section 4.10 — Peer Up Notification
    // Ipv4Addr or Ipv6Addr per the V flag; raw bytes for other peer types.
    //   https://www.rfc-editor.org/rfc/rfc7854#section-4.10
    FieldDescriptor::new("local_address", "Local Address", FieldType::Any).optional(),
    FieldDescriptor::new("local_port", "Local Port", FieldType::U16).optional(),
    FieldDescriptor::new("remote_port", "Remote Port", FieldType::U16).optional(),
    // TLV lists: RFC 7854, Sections 4.3-4.5 and 4.7; RFC 9736, Section 3;
    // RFC 9069, Section 5.3
    //   https://www.rfc-editor.org/rfc/rfc7854#section-4.3
    //   https://www.rfc-editor.org/rfc/rfc9736#section-3
    //   https://www.rfc-editor.org/rfc/rfc9069#section-5.3
    FieldDescriptor::new("information_tlvs", "Information TLVs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&INITIATION_TLV)),
    FieldDescriptor::new("peer_up_tlvs", "Information TLVs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&PEER_UP_TLV)),
    FieldDescriptor::new("peer_down_tlvs", "Information TLVs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&PEER_DOWN_TLV)),
    FieldDescriptor::new("termination_tlvs", "Information TLVs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&TERMINATION_TLV)),
    FieldDescriptor::new(
        "route_mirroring_tlvs",
        "Route Mirroring TLVs",
        FieldType::Array,
    )
    .optional()
    .with_children(core::slice::from_ref(&MIRRORING_TLV)),
    // An embedded BGP message whose header is not a valid BGP header
    // (RFC 4271, Section 4.1), or that the BGP dissector rejects, kept as
    // raw bytes.
    //   https://www.rfc-editor.org/rfc/rfc4271#section-4.1
    FieldDescriptor::new("bgp_message", "BGP Message", FieldType::Bytes).optional(),
    // Octets of the message that are not decoded.
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Specification references for the BMP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 7854",
        "BGP Monitoring Protocol (BMP)",
        "https://www.rfc-editor.org/rfc/rfc7854",
    ),
    SpecReference::new(
        "RFC 8671",
        "Support for Adj-RIB-Out in the BGP Monitoring Protocol (BMP)",
        "https://www.rfc-editor.org/rfc/rfc8671",
    ),
    SpecReference::new(
        "RFC 9069",
        "Support for Local RIB in the BGP Monitoring Protocol (BMP)",
        "https://www.rfc-editor.org/rfc/rfc9069",
    ),
    SpecReference::new(
        "RFC 9515",
        "Revision to Registration Procedures for Multiple BMP Registries",
        "https://www.rfc-editor.org/rfc/rfc9515",
    ),
    SpecReference::new(
        "RFC 9736",
        "The BGP Monitoring Protocol (BMP) Peer Up Message Namespace",
        "https://www.rfc-editor.org/rfc/rfc9736",
    ),
    SpecReference::new(
        "RFC 9972",
        "Advanced BGP Monitoring Protocol (BMP) Statistics Types",
        "https://www.rfc-editor.org/rfc/rfc9972",
    ),
    SpecReference::new(
        "IANA BMP Parameters",
        "BGP Monitoring Protocol (BMP) Parameters",
        "https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml",
    ),
];

/// How an address field of the per-peer header or Peer Up is encoded.
#[derive(Clone, Copy)]
enum AddressFamily {
    /// IPv4 in the last 4 of 16 octets (V flag 0).
    Ipv4,
    /// IPv6 (V flag 1, or the zero-filled Loc-RIB address).
    Ipv6,
    /// A peer type whose flags are not defined: raw octets.
    Unknown,
}

/// The parts of the per-peer header needed to decode the message body.
#[derive(Clone, Copy)]
struct PeerInfo {
    family: AddressFamily,
    /// AS number size of the AS_PATH in Route Monitoring UPDATEs.
    as_size: Option<AsNumberSize>,
}

/// BGP messages found in a BMP message, dissected after the BMP layer.
struct BgpMessages {
    ranges: [Range<usize>; MAX_BGP_MESSAGES],
    len: usize,
}

impl BgpMessages {
    fn new() -> Self {
        Self {
            ranges: [0..0, 0..0],
            len: 0,
        }
    }

    /// Records the BGP message at `range` of the BMP message. Returns
    /// `false` when the list is full.
    fn push(&mut self, range: Range<usize>) -> bool {
        if self.len == MAX_BGP_MESSAGES {
            return false;
        }
        self.ranges[self.len] = range;
        self.len += 1;
        true
    }
}

/// Returns the length of the BGP message at the start of `data` when its
/// header is valid: a Marker of all ones and a Length of at least the header
/// size that fits in `data` (RFC 4271, Section 4.1 —
/// <https://www.rfc-editor.org/rfc/rfc4271#section-4.1>).
fn bgp_message_len(data: &[u8]) -> Option<usize> {
    if data.len() < BGP_HEADER_SIZE || data[..16] != BGP_MARKER {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([data[16], data[17]]));
    (BGP_HEADER_SIZE..=data.len()).contains(&len).then_some(len)
}

/// Pushes one 16-octet address field decoded per `family`.
fn push_address<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    bytes: &'pkt [u8],
    family: AddressFamily,
    offset: usize,
) {
    let value = match family {
        // "It is 4 bytes long if an IPv4 address is carried in this field
        // (with the 12 most significant bytes zero-filled)" (RFC 7854,
        // Section 4.2).
        AddressFamily::Ipv4 => FieldValue::Ipv4Addr([bytes[12], bytes[13], bytes[14], bytes[15]]),
        AddressFamily::Ipv6 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[..16]);
            FieldValue::Ipv6Addr(addr)
        }
        AddressFamily::Unknown => FieldValue::Bytes(&bytes[..16]),
    };
    buf.push_field(descriptor, value, offset..offset + 16);
}

/// Pushes the per-peer header at `msg[COMMON_HEADER_SIZE..]`.
///
/// RFC 7854, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.2>
fn push_per_peer_header<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    offset: usize,
) -> Result<PeerInfo, PacketError> {
    let base = COMMON_HEADER_SIZE;
    let abs = offset + base;
    let peer_type = msg[base];
    let flags = msg[base + 1];
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_TYPE],
        FieldValue::U8(peer_type),
        abs..abs + 1,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_FLAGS],
        FieldValue::U8(flags),
        abs + 1..abs + 2,
    );

    let bit = |mask: u8| FieldValue::U8(u8::from(flags & mask != 0));
    let info = if peer_type <= PEER_TYPE_LOCAL_INSTANCE {
        // Flags for peer types 0-2: V, L, A (RFC 7854, Section 4.2) and O
        // (RFC 8671, Section 4 — https://www.rfc-editor.org/rfc/rfc8671#section-4).
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.2
        for (fd, mask) in [
            (FD_V_FLAG, FLAG_V),
            (FD_L_FLAG, FLAG_L),
            (FD_A_FLAG, FLAG_A),
            (FD_O_FLAG, FLAG_O),
        ] {
            buf.push_field(&FIELD_DESCRIPTORS[fd], bit(mask), abs + 1..abs + 2);
        }
        PeerInfo {
            family: if flags & FLAG_V != 0 {
                AddressFamily::Ipv6
            } else {
                AddressFamily::Ipv4
            },
            // "The A flag, if set to 1, indicates that the message is
            // formatted using the legacy 2-byte AS_PATH format.  If set to 0,
            // the message is formatted using the 4-byte AS_PATH format"
            // (RFC 7854, Section 4.2).
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.2
            as_size: Some(if flags & FLAG_A != 0 {
                AsNumberSize::TwoOctet
            } else {
                AsNumberSize::FourOctet
            }),
        }
    } else if peer_type == PEER_TYPE_LOC_RIB {
        // RFC 9069, Section 4.2 — the F flag
        //   https://www.rfc-editor.org/rfc/rfc9069#section-4.2
        buf.push_field(&FIELD_DESCRIPTORS[FD_F_FLAG], bit(FLAG_F), abs + 1..abs + 2);
        PeerInfo {
            // "Peer Address:  Zero-filled." (RFC 9069, Section 5.1 —
            // https://www.rfc-editor.org/rfc/rfc9069#section-5.1)
            family: AddressFamily::Ipv6,
            // "Loc-RIB Route Monitoring messages MUST use a 4-byte ASN
            // encoding" (RFC 9069, Section 5.4.1 —
            // https://www.rfc-editor.org/rfc/rfc9069#section-5.4.1).
            as_size: Some(AsNumberSize::FourOctet),
        }
    } else {
        PeerInfo {
            family: AddressFamily::Unknown,
            as_size: None,
        }
    };

    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_DISTINGUISHER],
        FieldValue::Bytes(&msg[base + 2..base + 10]),
        abs + 2..abs + 10,
    );
    push_address(
        buf,
        &FIELD_DESCRIPTORS[FD_PEER_ADDRESS],
        &msg[base + 10..base + 26],
        info.family,
        abs + 10,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_AS],
        FieldValue::U32(read_be_u32(msg, base + 26)?),
        abs + 26..abs + 30,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_BGP_ID],
        FieldValue::Ipv4Addr([
            msg[base + 30],
            msg[base + 31],
            msg[base + 32],
            msg[base + 33],
        ]),
        abs + 30..abs + 34,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TIMESTAMP_SEC],
        FieldValue::U32(read_be_u32(msg, base + 34)?),
        abs + 34..abs + 38,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_TIMESTAMP_USEC],
        FieldValue::U32(read_be_u32(msg, base + 38)?),
        abs + 38..abs + 42,
    );
    Ok(info)
}

/// Pushes the undecoded octets `msg[start..]` as `data`, if any.
fn push_rest<'pkt>(buf: &mut DissectBuffer<'pkt>, msg: &'pkt [u8], start: usize, offset: usize) {
    if start < msg.len() {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_DATA],
            FieldValue::Bytes(&msg[start..]),
            offset + start..offset + msg.len(),
        );
    }
}

/// Records the BGP message at `msg[start..end]` for dissection after the
/// BMP layer and returns the offset just past it. When the octets do not
/// start with a valid BGP header they are kept as `bgp_message` and `None`
/// is returned.
fn take_bgp_message<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    start: usize,
    end: usize,
    offset: usize,
    bgp: &mut BgpMessages,
) -> Option<usize> {
    match bgp_message_len(&msg[start..end]) {
        Some(len) if bgp.push(start..start + len) => Some(start + len),
        _ => {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_BGP_MESSAGE],
                FieldValue::Bytes(&msg[start..end]),
                offset + start..offset + end,
            );
            None
        }
    }
}

/// The TLV lists of the BMP message types.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TlvList {
    /// Initiation Information TLVs (RFC 9736, Section 3.1).
    ///   <https://www.rfc-editor.org/rfc/rfc9736#section-3.1>
    Initiation,
    /// Peer Up Information TLVs (RFC 9736, Section 3.3).
    ///   <https://www.rfc-editor.org/rfc/rfc9736#section-3.3>
    PeerUp,
    /// Peer Down Information TLVs (RFC 9069, Section 5.3).
    ///   <https://www.rfc-editor.org/rfc/rfc9069#section-5.3>
    PeerDown,
    /// Termination Message TLVs (RFC 7854, Section 4.5).
    ///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.5>
    Termination,
    /// Route Mirroring TLVs (RFC 7854, Section 4.7).
    ///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.7>
    RouteMirroring,
    /// Stats Report counters (RFC 7854, Section 4.8).
    ///   <https://www.rfc-editor.org/rfc/rfc7854#section-4.8>
    Stats,
}

impl TlvList {
    /// `(array, element, children)` descriptors of the list.
    fn descriptors(
        self,
    ) -> (
        &'static FieldDescriptor,
        &'static FieldDescriptor,
        &'static [FieldDescriptor],
    ) {
        match self {
            Self::Initiation => (
                &FIELD_DESCRIPTORS[FD_INITIATION_TLVS],
                &INITIATION_TLV,
                &INITIATION_TLV_CHILDREN,
            ),
            Self::PeerUp => (
                &FIELD_DESCRIPTORS[FD_PEER_UP_TLVS],
                &PEER_UP_TLV,
                &PEER_UP_TLV_CHILDREN,
            ),
            Self::PeerDown => (
                &FIELD_DESCRIPTORS[FD_PEER_DOWN_TLVS],
                &PEER_DOWN_TLV,
                &PEER_DOWN_TLV_CHILDREN,
            ),
            Self::Termination => (
                &FIELD_DESCRIPTORS[FD_TERMINATION_TLVS],
                &TERMINATION_TLV,
                &TERMINATION_TLV_CHILDREN,
            ),
            Self::RouteMirroring => (
                &FIELD_DESCRIPTORS[FD_ROUTE_MIRRORING_TLVS],
                &MIRRORING_TLV,
                &MIRRORING_TLV_CHILDREN,
            ),
            Self::Stats => (&FIELD_DESCRIPTORS[FD_STATS], &STAT, &STAT_CHILDREN),
        }
    }

    /// Whether a TLV of type `t` carries a string.
    fn is_string(self, t: u16) -> bool {
        match self {
            // RFC 9736, Section 3.1: String, sysDescr, sysName.
            //   https://www.rfc-editor.org/rfc/rfc9736#section-3.1
            Self::Initiation => t <= 2,
            // RFC 9736, Section 3.3: String, VRF/Table Name, Admin Label.
            //   https://www.rfc-editor.org/rfc/rfc9736#section-3.3
            Self::PeerUp => matches!(t, 0 | 3 | 4),
            // RFC 9069, Section 5.3: VRF/Table Name.
            //   https://www.rfc-editor.org/rfc/rfc9069#section-5.3
            Self::PeerDown => t == 3,
            // RFC 7854, Section 4.5: String.
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.5
            Self::Termination => t == 0,
            Self::RouteMirroring | Self::Stats => false,
        }
    }
}

/// Looks up a child descriptor of a TLV list by name.
fn child(children: &'static [FieldDescriptor], name: &str) -> Option<&'static FieldDescriptor> {
    children.iter().find(|d| d.name == name)
}

/// Pushes the value of one TLV of `list`.
fn push_tlv_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    list: TlvList,
    children: &'static [FieldDescriptor],
    t: u16,
    value: &'pkt [u8],
    abs: usize,
) {
    let range = abs..abs + value.len();
    let decoded = match (list, t, value.len()) {
        (_, _, _) if list.is_string(t) => {
            child(children, "string").map(|d| (d, FieldValue::Bytes(value)))
        }
        // RFC 7854, Section 4.5 — "The Information field contains a 2-byte
        // code indicating the reason that the connection was terminated."
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.5
        (TlvList::Termination, TERMINATION_TLV_REASON, 2) => child(children, "reason")
            .map(|d| (d, FieldValue::U16(u16::from_be_bytes([value[0], value[1]])))),
        // RFC 7854, Section 4.7 — "Information.  A 2-byte code that provides
        // information about the mirrored message or message stream."
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.7
        (TlvList::RouteMirroring, MIRRORING_TLV_INFORMATION, 2) => {
            child(children, "information_code")
                .map(|d| (d, FieldValue::U16(u16::from_be_bytes([value[0], value[1]]))))
        }
        // RFC 7854, Section 4.8 — a 32-bit Counter or a 64-bit Gauge; RFC
        // 9972, Section 3.1 — "a 2-byte AFI, a 1-byte SAFI, and a 64-bit
        // Gauge" for the per-AFI/SAFI statistics.
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.8
        //   https://www.rfc-editor.org/rfc/rfc9972#section-3.1
        (TlvList::Stats, _, 4) => child(children, "counter").map(|d| {
            (
                d,
                FieldValue::U32(u32::from_be_bytes([value[0], value[1], value[2], value[3]])),
            )
        }),
        (TlvList::Stats, _, 8) => child(children, "gauge")
            .and_then(|d| read_be_u64(value, 0).ok().map(|g| (d, FieldValue::U64(g)))),
        (TlvList::Stats, _, 11) => {
            if let (Some(afi), Some(safi)) = (child(children, "afi"), child(children, "safi")) {
                buf.push_field(
                    afi,
                    FieldValue::U16(u16::from_be_bytes([value[0], value[1]])),
                    abs..abs + 2,
                );
                buf.push_field(safi, FieldValue::U8(value[2]), abs + 2..abs + 3);
            }
            if let (Some(gauge), Ok(g)) = (child(children, "gauge"), read_be_u64(value, 3)) {
                buf.push_field(gauge, FieldValue::U64(g), abs + 3..abs + 11);
            }
            return;
        }
        _ => None,
    };
    let (descriptor, v) = match decoded {
        Some(d) => d,
        None if value.is_empty() => return,
        // "A BMP implementation MUST ignore unrecognized stat types on
        // receipt, and likewise MUST ignore unexpected data in the Stat
        // Data field" (RFC 7854, Section 4.8): keep it undecoded.
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.8
        None => (value_descriptor(children), FieldValue::Bytes(value)),
    };
    buf.push_field(descriptor, v, range);
}

/// The `value` child of a TLV list: the last of its children.
fn value_descriptor(children: &'static [FieldDescriptor]) -> &'static FieldDescriptor {
    &children[children.len() - 1]
}

/// Returns the end of the TLVs (2-octet Type, 2-octet Length) that fit
/// completely in `msg[start..]`.
fn complete_tlvs_end(msg: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos + TLV_HEADER_SIZE <= msg.len() {
        let len = usize::from(u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]));
        let end = pos + TLV_HEADER_SIZE + len;
        if end > msg.len() {
            break;
        }
        pos = end;
    }
    pos
}

/// Pushes the TLVs of `list` in `msg[start..]`. A BGP Message TLV of a Route
/// Mirroring message is recorded in `bgp`. TLVs that overrun the message
/// end the list; their octets are pushed as `data`.
fn push_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    start: usize,
    offset: usize,
    list: TlvList,
    bgp: &mut BgpMessages,
) {
    // The TLVs that fit in the message; octets after them are `data`.
    let tlvs_end = complete_tlvs_end(msg, start);
    if tlvs_end == start {
        push_rest(buf, msg, start, offset);
        return;
    }
    let (array, element, children) = list.descriptors();
    let array_idx = buf.begin_container(
        array,
        FieldValue::Array(0..0),
        offset + start..offset + tlvs_end,
    );
    let mut pos = start;
    while pos < tlvs_end {
        let t = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]));
        let value_start = pos + TLV_HEADER_SIZE;
        let end = value_start + len;
        let abs = offset + pos;
        let obj_idx = buf.begin_container(element, FieldValue::Object(0..0), abs..offset + end);
        buf.push_field(&children[0], FieldValue::U16(t), abs..abs + 2);
        buf.push_field(&children[1], FieldValue::U16(len as u16), abs + 2..abs + 4);
        let value = &msg[value_start..end];
        if list == TlvList::RouteMirroring && t == MIRRORING_TLV_BGP_MESSAGE {
            // "BGP Message.  A BGP PDU." (RFC 7854, Section 4.7): dissected as
            // a BGP layer after the BMP layer when its header is valid.
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.7
            let recorded = bgp_message_len(value) == Some(len) && bgp.push(value_start..end);
            if !recorded && !value.is_empty() {
                buf.push_field(
                    value_descriptor(children),
                    FieldValue::Bytes(value),
                    offset + value_start..offset + end,
                );
            }
        } else {
            push_tlv_value(buf, list, children, t, value, offset + value_start);
        }
        buf.end_container(obj_idx);
        pos = end;
    }
    buf.end_container(array_idx);
    push_rest(buf, msg, pos, offset);
}

/// Pushes the body of a Peer Up Notification at `msg[start..]`.
///
/// RFC 7854, Section 4.10 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.10>
fn push_peer_up<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    start: usize,
    offset: usize,
    family: AddressFamily,
    bgp: &mut BgpMessages,
) {
    if msg.len() < start + PEER_UP_FIXED_SIZE {
        push_rest(buf, msg, start, offset);
        return;
    }
    push_address(
        buf,
        &FIELD_DESCRIPTORS[FD_LOCAL_ADDRESS],
        &msg[start..start + 16],
        family,
        offset + start,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_LOCAL_PORT],
        FieldValue::U16(u16::from_be_bytes([msg[start + 16], msg[start + 17]])),
        offset + start + 16..offset + start + 18,
    );
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_REMOTE_PORT],
        FieldValue::U16(u16::from_be_bytes([msg[start + 18], msg[start + 19]])),
        offset + start + 18..offset + start + 20,
    );
    // Sent OPEN Message, then Received OPEN Message.
    let mut pos = start + PEER_UP_FIXED_SIZE;
    for _ in 0..2 {
        match take_bgp_message(buf, msg, pos, msg.len(), offset, bgp) {
            Some(end) => pos = end,
            // Without a valid OPEN the Information TLVs cannot be located.
            None => return,
        }
    }
    // "Its presence or absence can be inferred by inspection of the Message
    // Length in the common header." (RFC 9736, Section 3.2)
    //   https://www.rfc-editor.org/rfc/rfc9736#section-3.2
    push_tlvs(buf, msg, pos, offset, TlvList::PeerUp, bgp);
}

/// Pushes the body of a Peer Down Notification at `msg[start..]`.
///
/// RFC 7854, Section 4.9 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.9>;
/// RFC 9069, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9069#section-5.3>
fn push_peer_down<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    start: usize,
    offset: usize,
    bgp: &mut BgpMessages,
) {
    let Some(&reason) = msg.get(start) else {
        return;
    };
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_PEER_DOWN_REASON],
        FieldValue::U8(reason),
        offset + start..offset + start + 1,
    );
    let data = start + 1;
    match reason {
        PEER_DOWN_LOCAL_NOTIFICATION | PEER_DOWN_REMOTE_NOTIFICATION if data < msg.len() => {
            if let Some(end) = take_bgp_message(buf, msg, data, msg.len(), offset, bgp) {
                push_rest(buf, msg, end, offset);
            }
        }
        // "Following the reason code is a 2-byte field containing the code
        // corresponding to the Finite State Machine (FSM) Event"
        PEER_DOWN_LOCAL_FSM_EVENT if data + 2 <= msg.len() => {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_FSM_EVENT_CODE],
                FieldValue::U16(u16::from_be_bytes([msg[data], msg[data + 1]])),
                offset + data..offset + data + 2,
            );
            push_rest(buf, msg, data + 2, offset);
        }
        // "Following the reason is data in TLV format." (RFC 9069, Section 5.3)
        //   https://www.rfc-editor.org/rfc/rfc9069#section-5.3
        PEER_DOWN_LOCAL_TLV => push_tlvs(buf, msg, data, offset, TlvList::PeerDown, bgp),
        _ => push_rest(buf, msg, data, offset),
    }
}

/// Pushes the body of a Stats Report at `msg[start..]`.
///
/// RFC 7854, Section 4.8 — <https://www.rfc-editor.org/rfc/rfc7854#section-4.8>
fn push_stats<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    start: usize,
    offset: usize,
    bgp: &mut BgpMessages,
) {
    let Ok(count) = read_be_u32(msg, start) else {
        push_rest(buf, msg, start, offset);
        return;
    };
    buf.push_field(
        &FIELD_DESCRIPTORS[FD_STATS_COUNT],
        FieldValue::U32(count),
        offset + start..offset + start + 4,
    );
    push_tlvs(buf, msg, start + 4, offset, TlvList::Stats, bgp);
}

/// Removes the layers and fields pushed after `layers` / `fields`.
fn roll_back(buf: &mut DissectBuffer<'_>, layers: usize, fields: usize) {
    while buf.layers().len() > layers {
        buf.pop_layer();
    }
    buf.truncate_fields(fields);
}

/// Dissects one recorded BGP message as a `BGP` layer. A message the BGP
/// dissector rejects is rolled back; returns whether it was accepted.
fn push_bgp_layer<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    range: &Range<usize>,
    offset: usize,
    as_size: Option<AsNumberSize>,
) -> bool {
    let (layers, fields) = (buf.layers().len(), buf.fields().len());
    let accepted = BgpDissector
        .dissect_message(&msg[range.clone()], buf, offset + range.start, as_size)
        .is_ok();
    if !accepted {
        roll_back(buf, layers, fields);
    }
    accepted
}

/// Appends the BGP messages recorded in `bgp` as `BGP` layers after the BMP
/// layer, which must be the last layer.
///
/// A message the BGP dissector rejects keeps its octets as `bgp_message` in
/// the BMP layer. The BMP layer can only take more fields while it is the
/// last layer, so when a message is rejected every BGP layer is rolled back,
/// the rejected messages are added to the BMP layer, and the accepted ones
/// are dissected again (dissection is deterministic).
fn push_bgp_layers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    offset: usize,
    bgp: &BgpMessages,
    as_size: Option<AsNumberSize>,
) {
    let ranges = &bgp.ranges[..bgp.len];
    let (layers, fields) = (buf.layers().len(), buf.fields().len());
    let mut accepted = [true; MAX_BGP_MESSAGES];
    for (ok, range) in accepted.iter_mut().zip(ranges) {
        *ok = push_bgp_layer(buf, msg, range, offset, as_size);
    }
    if accepted[..ranges.len()].iter().all(|&ok| ok) {
        return;
    }
    roll_back(buf, layers, fields);
    for (_, range) in accepted.iter().zip(ranges).filter(|(ok, _)| !**ok) {
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BGP_MESSAGE],
            FieldValue::Bytes(&msg[range.clone()]),
            offset + range.start..offset + range.end,
        );
    }
    // Extends the field range of the BMP layer over the fields just pushed.
    buf.end_layer();
    for (_, range) in accepted.iter().zip(ranges).filter(|(ok, _)| **ok) {
        push_bgp_layer(buf, msg, range, offset, as_size);
    }
}

/// BMP (BGP Monitoring Protocol) dissector.
///
/// Dissects one BMP message per call and returns its Message Length as
/// `bytes_consumed`, so a TCP stream of BMP messages is framed by the TCP
/// reassembly layer. A message longer than `data` is reported as
/// [`PacketError::Truncated`] before anything is pushed.
///
/// Embedded BGP messages are appended as `BGP` layers after the `BMP` layer.
/// A BGP message that does not start with a valid BGP header, or that the
/// BGP dissector rejects, is kept as the raw `bgp_message` field instead.
pub struct BmpDissector;

impl Dissector for BmpDissector {
    fn name(&self) -> &'static str {
        "BGP Monitoring Protocol"
    }

    fn short_name(&self) -> &'static str {
        "BMP"
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

    /// BGP: encapsulated BGP messages are appended as `BGP` layers.
    fn visit_sub_dissectors(&self, visit: &mut dyn FnMut(&dyn Dissector)) {
        visit(&BgpDissector);
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < COMMON_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: COMMON_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // RFC 7854, Section 4.1 — Common Header
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.1
        let version = data[0];
        if version != VERSION_3 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        let length = read_be_u32(data, 1)?;
        let msg_len = length as usize;
        if msg_len < COMMON_HEADER_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "message_length",
                value: length,
            });
        }
        if data.len() < msg_len {
            return Err(PacketError::Truncated {
                expected: msg_len,
                actual: data.len(),
            });
        }
        let msg_type = data[5];
        let msg = &data[..msg_len];

        // "The per-peer header follows the common header for most BMP
        // messages" (RFC 7854, Section 4.2): all but Initiation and
        // Termination (Sections 4.3 and 4.5).
        //   https://www.rfc-editor.org/rfc/rfc7854#section-4.2
        let has_per_peer_header = matches!(
            msg_type,
            MSG_ROUTE_MONITORING
                | MSG_STATISTICS_REPORT
                | MSG_PEER_DOWN
                | MSG_PEER_UP
                | MSG_ROUTE_MIRRORING
        );
        let body = if has_per_peer_header {
            COMMON_HEADER_SIZE + PER_PEER_HEADER_SIZE
        } else {
            COMMON_HEADER_SIZE
        };
        if msg_len < body {
            return Err(PacketError::InvalidHeader(
                "BMP message length too short for the per-peer header",
            ));
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + msg_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_LENGTH],
            FieldValue::U32(length),
            offset + 1..offset + 5,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_MESSAGE_TYPE],
            FieldValue::U8(msg_type),
            offset + 5..offset + 6,
        );

        let peer = if has_per_peer_header {
            Some(push_per_peer_header(buf, msg, offset)?)
        } else {
            None
        };
        let family = peer.map_or(AddressFamily::Unknown, |p| p.family);

        let mut bgp = BgpMessages::new();
        let mut as_size = None;
        match msg_type {
            // RFC 7854, Section 4.6 — "Following the common BMP header and
            // per-peer header is a BGP Update PDU."
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.6
            MSG_ROUTE_MONITORING => {
                if body < msg_len {
                    if let Some(end) = take_bgp_message(buf, msg, body, msg_len, offset, &mut bgp) {
                        push_rest(buf, msg, end, offset);
                    }
                }
                // The A flag "has no significance when used with route
                // mirroring messages" (RFC 7854, Section 4.2), so it is only
                // applied here.
                //   https://www.rfc-editor.org/rfc/rfc7854#section-4.2
                as_size = peer.and_then(|p| p.as_size);
            }
            MSG_STATISTICS_REPORT => push_stats(buf, msg, body, offset, &mut bgp),
            MSG_PEER_DOWN => push_peer_down(buf, msg, body, offset, &mut bgp),
            MSG_PEER_UP => push_peer_up(buf, msg, body, offset, family, &mut bgp),
            // RFC 7854, Section 4.3 — Initiation Message
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.3
            MSG_INITIATION => push_tlvs(buf, msg, body, offset, TlvList::Initiation, &mut bgp),
            // RFC 7854, Section 4.5 — Termination Message
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.5
            MSG_TERMINATION => push_tlvs(buf, msg, body, offset, TlvList::Termination, &mut bgp),
            // RFC 7854, Section 4.7 — Route Mirroring
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.7
            MSG_ROUTE_MIRRORING => {
                push_tlvs(buf, msg, body, offset, TlvList::RouteMirroring, &mut bgp);
            }
            // "A BMP implementation MUST ignore unrecognized message types
            // upon receipt." (RFC 7854, Section 4.1)
            //   https://www.rfc-editor.org/rfc/rfc7854#section-4.1
            _ => push_rest(buf, msg, body, offset),
        }
        buf.end_layer();
        push_bgp_layers(buf, msg, offset, &bgp, as_size);

        Ok(DissectResult::new(msg_len, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 7854 (BMP) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.1 | Common header | `parse_initiation` |
    //! | 4.1 | Version other than 3 rejected | `reject_unsupported_version` |
    //! | 4.1 | Message Length below the header size rejected | `reject_short_message_length` |
    //! | 4.1 | Message longer than the data is Truncated | `truncated_message`, `truncated_common_header` |
    //! | 4.1 | One message per call; bytes after it are left alone | `consumes_one_message` |
    //! | 4.1 | Unrecognized message type kept as data | `unknown_message_type` |
    //! | 4.2 | Per-peer header (IPv4 peer, flags, timestamp) | `parse_route_monitoring_ipv4` |
    //! | 4.2 | Per-peer header (IPv6 peer, V flag, RD instance) | `parse_route_monitoring_ipv6_peer` |
    //! | 4.2 | A flag selects the AS_PATH AS number size | `route_monitoring_a_flag_selects_as_size` |
    //! | 4.2 | Message too short for the per-peer header | `reject_missing_per_peer_header` |
    //! | 4.2 | Unknown peer type: address kept raw | `unknown_peer_type` |
    //! | 4.3, 4.4 | Initiation with String, sysDescr, sysName | `parse_initiation` |
    //! | 4.5 | Termination with String and Reason | `parse_termination` |
    //! | 4.6 | Route Monitoring carries a BGP UPDATE | `parse_route_monitoring_ipv4` |
    //! | 4.6 | Invalid BGP header kept as raw bytes | `route_monitoring_invalid_bgp_header` |
    //! | 4.6 | BGP message rejected by the BGP dissector kept as raw bytes | `route_monitoring_rejected_bgp_rolled_back`, `peer_up_rejected_received_open_kept_raw` |
    //! | 4.6 | Octets after the BGP UPDATE kept as data | `route_monitoring_trailing_octets_kept_as_data` |
    //! | 4.1 | Field and layer ranges are absolute | `offsets_are_absolute` |
    //! | 4.7 | Route Mirroring Information and BGP Message TLVs | `parse_route_mirroring` |
    //! | 4.7 | Route Mirroring BGP Message TLV with an invalid header | `route_mirroring_invalid_bgp_message` |
    //! | 4.8 | Stats Report counters and gauges | `parse_stats_report` |
    //! | 4.8 | Stats Report too short for Stats Count | `stats_report_without_count` |
    //! | 4.8 | Stats Report with a tail shorter than a TLV header | `stats_report_short_tail_is_data` |
    //! | 4.9 | Peer Down with NOTIFICATION | `parse_peer_down_notification` |
    //! | 4.9 | Peer Down with FSM Event code | `parse_peer_down_fsm_event` |
    //! | 4.9 | Peer Down without data | `parse_peer_down_no_data` |
    //! | 4.10 | Peer Up with sent and received OPEN | `parse_peer_up` |
    //! | 4.10 | Peer Up with an invalid OPEN | `peer_up_invalid_open` |
    //! | 4.10 | Peer Up shorter than its fixed part | `peer_up_truncated_fixed_part` |
    //! | 4.4 | TLV overrunning the message kept as data | `tlv_overrun_kept_as_data` |
    //! | 4.1-4.10 | Code point names (IANA BMP Parameters) | `registry_names` |
    //!
    //! # RFC 8671 (Adj-RIB-Out) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4 | O flag | `parse_route_monitoring_ipv6_peer` |
    //! | 5 | Adj-RIB-Out statistics types | `parse_stats_report` |
    //!
    //! # RFC 9069 (Loc-RIB) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.1, 4.2 | Loc-RIB Instance Peer type and F flag | `parse_loc_rib_route_monitoring` |
    //! | 5.4.1 | Loc-RIB Route Monitoring uses 4-byte ASNs | `parse_loc_rib_route_monitoring` |
    //! | 5.3 | Peer Down reason 6 with VRF/Table Name TLV | `parse_peer_down_tlv` |
    //!
    //! # RFC 9736 (Peer Up Namespace) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 3.1 | Initiation Information TLV names | `parse_initiation` |
    //! | 3.3 | Peer Up Information TLVs (String, VRF/Table Name, Admin Label) | `parse_peer_up` |
    //!
    //! # RFC 9972 (Statistics) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 3.1 | Per-AFI/SAFI statistic (AFI, SAFI, 64-bit Gauge) | `parse_stats_report` |

    use super::*;
    use packet_dissector_core::field::Field;
    use packet_dissector_core::packet::Layer;

    /// Common header: version 3, length, type.
    fn common_header(msg_type: u8, total_len: usize) -> Vec<u8> {
        let mut v = vec![3];
        v.extend_from_slice(&(total_len as u32).to_be_bytes());
        v.push(msg_type);
        v
    }

    /// Per-peer header with the given type, flags and 16-octet address.
    fn per_peer_header(peer_type: u8, flags: u8, address: [u8; 16], peer_as: u32) -> Vec<u8> {
        let mut v = vec![peer_type, flags];
        v.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 100]); // Peer Distinguisher
        v.extend_from_slice(&address);
        v.extend_from_slice(&peer_as.to_be_bytes());
        v.extend_from_slice(&[192, 0, 2, 1]); // Peer BGP ID
        v.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // seconds
        v.extend_from_slice(&123_456u32.to_be_bytes()); // microseconds
        v
    }

    fn ipv4_mapped(addr: [u8; 4]) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[12..].copy_from_slice(&addr);
        a
    }

    /// Builds a BMP message from its type and the bytes after the common
    /// header.
    fn bmp(msg_type: u8, rest: &[u8]) -> Vec<u8> {
        let mut v = common_header(msg_type, COMMON_HEADER_SIZE + rest.len());
        v.extend_from_slice(rest);
        v
    }

    /// A BGP message with the given type and body.
    fn bgp(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF; 16];
        v.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
        v.push(msg_type);
        v.extend_from_slice(body);
        v
    }

    /// A BGP UPDATE with the given path attributes and no NLRI.
    fn bgp_update(attrs: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend_from_slice(attrs);
        bgp(2, &body)
    }

    /// An UPDATE whose AS_PATH is valid both as 4-octet AS_SEQUENCE
    /// { 65538, 16842755 } and as 2-octet AS_SEQUENCE { 1, 2 } + AS_SET { 3 }.
    fn ambiguous_update() -> Vec<u8> {
        let as_path = [2, 2, 0, 1, 0, 2, 1, 1, 0, 3];
        let mut attrs = vec![0x40, 2, as_path.len() as u8];
        attrs.extend_from_slice(&as_path);
        bgp_update(&attrs)
    }

    /// A BGP OPEN with no optional parameters.
    fn bgp_open(my_as: u16) -> Vec<u8> {
        let mut body = vec![4];
        body.extend_from_slice(&my_as.to_be_bytes());
        body.extend_from_slice(&180u16.to_be_bytes());
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.push(0);
        bgp(1, &body)
    }

    fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = BmpDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    fn bmp_layer<'a>(buf: &'a DissectBuffer<'_>) -> &'a Layer {
        buf.layer_by_name("BMP").unwrap()
    }

    fn value<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> &'a FieldValue<'pkt> {
        &buf.field_by_name(bmp_layer(buf), name)
            .unwrap_or_else(|| panic!("field {name} missing"))
            .value
    }

    /// The objects of the TLV array `name`.
    fn tlvs<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Vec<&'a [Field<'pkt>]> {
        let FieldValue::Array(range) = value(buf, name) else {
            panic!("{name} is not an array");
        };
        buf.nested_fields(range)
            .iter()
            .filter_map(|f| match &f.value {
                FieldValue::Object(r) => Some(buf.nested_fields(r)),
                _ => None,
            })
            .collect()
    }

    fn child_value<'a, 'pkt>(fields: &'a [Field<'pkt>], name: &str) -> &'a FieldValue<'pkt> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("child {name} missing"))
            .value
    }

    fn child_display(fields: &[Field<'_>], name: &str) -> Option<&'static str> {
        let f = fields.iter().find(|f| f.name() == name)?;
        (f.descriptor.display_fn?)(&f.value, fields)
    }

    fn layer_names(buf: &DissectBuffer<'_>) -> Vec<&'static str> {
        buf.layers().iter().map(|l| l.name).collect()
    }

    /// AS numbers of the first AS_PATH segment of the BGP layer.
    fn bgp_as_path(buf: &DissectBuffer<'_>) -> Vec<u32> {
        let bgp = buf.layer_by_name("BGP").unwrap();
        let fields = buf.layer_fields(bgp);
        let seg = fields
            .iter()
            .position(|f| f.name() == "as_numbers")
            .expect("as_numbers");
        let FieldValue::Array(r) = &fields[seg].value else {
            panic!()
        };
        buf.nested_fields(r)
            .iter()
            .filter_map(|f| f.value.as_u32())
            .collect()
    }

    #[test]
    fn parse_initiation() {
        let mut rest = tlv(1, b"Example OS 1.0");
        rest.extend(tlv(2, b"router1"));
        rest.extend(tlv(0, b"hello"));
        let data = bmp(MSG_INITIATION, &rest);
        let (buf, result) = dissect(&data);

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        assert_eq!(layer_names(&buf), ["BMP"]);
        let layer = bmp_layer(&buf);
        assert_eq!(layer.range, 0..data.len());
        assert_eq!(*value(&buf, "version"), FieldValue::U8(3));
        assert_eq!(
            *value(&buf, "message_length"),
            FieldValue::U32(data.len() as u32)
        );
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Initiation")
        );
        assert!(buf.field_by_name(layer, "peer_type").is_none());

        let tlvs = tlvs(&buf, "information_tlvs");
        assert_eq!(tlvs.len(), 3);
        assert_eq!(child_display(tlvs[0], "type"), Some("sysDescr"));
        assert_eq!(
            *child_value(tlvs[0], "string"),
            FieldValue::Bytes(b"Example OS 1.0")
        );
        assert_eq!(child_display(tlvs[1], "type"), Some("sysName"));
        assert_eq!(
            *child_value(tlvs[1], "string"),
            FieldValue::Bytes(b"router1")
        );
        assert_eq!(child_display(tlvs[2], "type"), Some("String"));
        assert_eq!(*child_value(tlvs[2], "length"), FieldValue::U16(5));
    }

    #[test]
    fn parse_termination() {
        let mut rest = tlv(0, b"bye");
        rest.extend(tlv(1, &[0, 4]));
        rest.extend(tlv(65531, &[1]));
        let data = bmp(MSG_TERMINATION, &rest);
        let (buf, _) = dissect(&data);
        let tlvs = tlvs(&buf, "termination_tlvs");
        assert_eq!(tlvs.len(), 3);
        assert_eq!(*child_value(tlvs[0], "string"), FieldValue::Bytes(b"bye"));
        assert_eq!(child_display(tlvs[1], "type"), Some("Reason"));
        assert_eq!(*child_value(tlvs[1], "reason"), FieldValue::U16(4));
        assert_eq!(
            child_display(tlvs[1], "reason"),
            Some("Permanently administratively closed")
        );
        assert_eq!(child_display(tlvs[2], "type"), Some("Experimental"));
        assert_eq!(*child_value(tlvs[2], "value"), FieldValue::Bytes(&[1]));
    }

    #[test]
    fn parse_route_monitoring_ipv4() {
        let mut rest = per_peer_header(0, 0x40, ipv4_mapped([198, 51, 100, 1]), 65001);
        let update = ambiguous_update();
        rest.extend_from_slice(&update);
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, result) = dissect(&data);

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(layer_names(&buf), ["BMP", "BGP"]);
        let layer = bmp_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Route Monitoring")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "peer_type_name"),
            Some("Global Instance Peer")
        );
        assert_eq!(*value(&buf, "peer_flags"), FieldValue::U8(0x40));
        assert_eq!(*value(&buf, "v_flag"), FieldValue::U8(0));
        assert_eq!(*value(&buf, "l_flag"), FieldValue::U8(1));
        assert_eq!(*value(&buf, "a_flag"), FieldValue::U8(0));
        assert_eq!(*value(&buf, "o_flag"), FieldValue::U8(0));
        assert!(buf.field_by_name(layer, "f_flag").is_none());
        assert_eq!(
            *value(&buf, "peer_distinguisher"),
            FieldValue::Bytes(&[0, 0, 0, 1, 0, 0, 0, 100])
        );
        let addr = buf.field_by_name(layer, "peer_address").unwrap();
        assert_eq!(addr.value, FieldValue::Ipv4Addr([198, 51, 100, 1]));
        assert_eq!(addr.range, 16..32);
        assert_eq!(*value(&buf, "peer_as"), FieldValue::U32(65001));
        assert_eq!(
            *value(&buf, "peer_bgp_id"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert_eq!(
            *value(&buf, "timestamp_sec"),
            FieldValue::U32(1_700_000_000)
        );
        assert_eq!(*value(&buf, "timestamp_usec"), FieldValue::U32(123_456));

        let bgp = buf.layer_by_name("BGP").unwrap();
        assert_eq!(bgp.range, 48..data.len());
        assert_eq!(buf.resolve_display_name(bgp, "type_name"), Some("UPDATE"));
        // A flag 0: "the message is formatted using the 4-byte AS_PATH format".
        assert_eq!(bgp_as_path(&buf), [65538, 16_842_755]);
    }

    #[test]
    fn route_monitoring_a_flag_selects_as_size() {
        let mut rest = per_peer_header(0, FLAG_A, ipv4_mapped([198, 51, 100, 1]), 65001);
        rest.extend_from_slice(&ambiguous_update());
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(*value(&buf, "a_flag"), FieldValue::U8(1));
        assert_eq!(bgp_as_path(&buf), [1, 2]);
    }

    #[test]
    fn parse_route_monitoring_ipv6_peer() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut rest = per_peer_header(1, FLAG_V | FLAG_O, addr, 64512);
        rest.extend_from_slice(&ambiguous_update());
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "peer_type_name"),
            Some("RD Instance Peer")
        );
        assert_eq!(*value(&buf, "v_flag"), FieldValue::U8(1));
        assert_eq!(*value(&buf, "o_flag"), FieldValue::U8(1));
        assert_eq!(*value(&buf, "peer_address"), FieldValue::Ipv6Addr(addr));
    }

    #[test]
    fn parse_loc_rib_route_monitoring() {
        let mut rest = per_peer_header(3, FLAG_F, [0; 16], 65000);
        rest.extend_from_slice(&ambiguous_update());
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "peer_type_name"),
            Some("Loc-RIB Instance Peer")
        );
        assert_eq!(*value(&buf, "f_flag"), FieldValue::U8(1));
        assert!(buf.field_by_name(layer, "v_flag").is_none());
        assert_eq!(*value(&buf, "peer_address"), FieldValue::Ipv6Addr([0; 16]));
        assert_eq!(bgp_as_path(&buf), [65538, 16_842_755]);
    }

    #[test]
    fn unknown_peer_type() {
        let mut rest = per_peer_header(251, FLAG_A, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&ambiguous_update());
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "peer_type_name"),
            Some("Experimental")
        );
        assert!(buf.field_by_name(layer, "a_flag").is_none());
        assert_eq!(
            *value(&buf, "peer_address"),
            FieldValue::Bytes(&ipv4_mapped([192, 0, 2, 9]))
        );
        // No AS number size is known: inferred as 4-octet.
        assert_eq!(bgp_as_path(&buf), [65538, 16_842_755]);
    }

    #[test]
    fn route_monitoring_invalid_bgp_header() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        let mut update = ambiguous_update();
        update[0] = 0;
        rest.extend_from_slice(&update);
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(layer_names(&buf), ["BMP"]);
        let f = buf.field_by_name(bmp_layer(&buf), "bgp_message").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&update));
        assert_eq!(f.range, 48..data.len());
    }

    #[test]
    fn route_monitoring_rejected_bgp_rolled_back() {
        // A 19-octet UPDATE: a valid header, but shorter than the minimum
        // UPDATE (RFC 4271, Section 4.3), so the BGP dissector rejects it.
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&bgp(2, &[]));
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(layer_names(&buf), ["BMP"]);
        let layer = bmp_layer(&buf);
        assert_eq!(layer.field_range.end as usize, buf.fields().len());
        let f = buf.field_by_name(layer, "bgp_message").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&data[48..]));
        assert_eq!(f.range, 48..data.len());
    }

    #[test]
    fn peer_up_rejected_received_open_kept_raw() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 2]), 65002);
        rest.extend_from_slice(&ipv4_mapped([192, 0, 2, 1]));
        rest.extend_from_slice(&[0, 179, 0xC3, 0x50]);
        let sent = bgp_open(65001);
        // A header-only OPEN: valid BGP header, rejected by the BGP dissector.
        let received = bgp(1, &[]);
        rest.extend_from_slice(&sent);
        rest.extend_from_slice(&received);
        rest.extend(tlv(0, b"peer"));
        let data = bmp(MSG_PEER_UP, &rest);
        let (buf, _) = dissect(&data);

        assert_eq!(layer_names(&buf), ["BMP", "BGP"]);
        let layer = bmp_layer(&buf);
        let second = 48 + PEER_UP_FIXED_SIZE + sent.len();
        let f = buf.field_by_name(layer, "bgp_message").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&received));
        assert_eq!(f.range, second..second + received.len());
        assert_eq!(tlvs(&buf, "peer_up_tlvs").len(), 1);
        // The sent OPEN is still a BGP layer, after every BMP field.
        let open = buf.layer_by_name("BGP").unwrap();
        assert_eq!(open.range, second - sent.len()..second);
        assert_eq!(layer.field_range.end, open.field_range.start);
        assert_eq!(
            buf.field_by_name(open, "my_as").unwrap().value,
            FieldValue::U16(65001)
        );
    }

    #[test]
    fn route_monitoring_trailing_octets_kept_as_data() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&ambiguous_update());
        rest.extend_from_slice(&[0xAB, 0xCD]);
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(layer_names(&buf), ["BMP", "BGP"]);
        assert_eq!(*value(&buf, "data"), FieldValue::Bytes(&[0xAB, 0xCD]));
    }

    #[test]
    fn parse_stats_report() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&5u32.to_be_bytes());
        rest.extend(tlv(0, &7u32.to_be_bytes()));
        rest.extend(tlv(7, &1_000_000u64.to_be_bytes()));
        let mut afi_safi = vec![0, 2, 1];
        afi_safi.extend_from_slice(&42u64.to_be_bytes());
        rest.extend(tlv(16, &afi_safi));
        rest.extend(tlv(9999, &[1, 2, 3]));
        rest.extend(tlv(8, &[]));
        let data = bmp(MSG_STATISTICS_REPORT, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(*value(&buf, "stats_count"), FieldValue::U32(5));
        let stats = tlvs(&buf, "stats");
        assert_eq!(stats.len(), 5);
        assert_eq!(
            child_display(stats[0], "type"),
            Some("Number of prefixes rejected by inbound policy")
        );
        assert_eq!(*child_value(stats[0], "counter"), FieldValue::U32(7));
        assert_eq!(*child_value(stats[1], "gauge"), FieldValue::U64(1_000_000));
        assert_eq!(
            child_display(stats[2], "type"),
            Some("Number of routes in per-AFI/SAFI pre-policy Adj-RIB-Out")
        );
        assert_eq!(*child_value(stats[2], "afi"), FieldValue::U16(2));
        assert_eq!(*child_value(stats[2], "safi"), FieldValue::U8(1));
        assert_eq!(*child_value(stats[2], "gauge"), FieldValue::U64(42));
        assert_eq!(child_display(stats[3], "type"), None);
        assert_eq!(
            *child_value(stats[3], "value"),
            FieldValue::Bytes(&[1, 2, 3])
        );
        assert_eq!(stats[4].len(), 2);
    }

    #[test]
    fn stats_report_short_tail_is_data() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&1u32.to_be_bytes());
        rest.extend_from_slice(&[0, 7]);
        let data = bmp(MSG_STATISTICS_REPORT, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert!(buf.field_by_name(layer, "stats").is_none());
        assert_eq!(*value(&buf, "data"), FieldValue::Bytes(&[0, 7]));
    }

    #[test]
    fn stats_report_without_count() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&[0, 0]);
        let data = bmp(MSG_STATISTICS_REPORT, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert!(buf.field_by_name(layer, "stats_count").is_none());
        assert_eq!(*value(&buf, "data"), FieldValue::Bytes(&[0, 0]));
    }

    #[test]
    fn parse_peer_down_notification() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.push(PEER_DOWN_REMOTE_NOTIFICATION);
        let notification = bgp(3, &[6, 2]); // Cease / Administrative Shutdown
        rest.extend_from_slice(&notification);
        let data = bmp(MSG_PEER_DOWN, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert_eq!(*value(&buf, "reason"), FieldValue::U8(3));
        assert_eq!(
            buf.resolve_display_name(layer, "reason_name"),
            Some("Remote system closed, NOTIFICATION PDU follows")
        );
        assert_eq!(layer_names(&buf), ["BMP", "BGP"]);
        let bgp_layer = buf.layer_by_name("BGP").unwrap();
        assert_eq!(bgp_layer.range, 49..data.len());
        assert_eq!(
            buf.resolve_display_name(bgp_layer, "type_name"),
            Some("NOTIFICATION")
        );
    }

    #[test]
    fn parse_peer_down_fsm_event() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&[PEER_DOWN_LOCAL_FSM_EVENT, 0, 18]);
        let data = bmp(MSG_PEER_DOWN, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(*value(&buf, "fsm_event_code"), FieldValue::U16(18));
        assert_eq!(layer_names(&buf), ["BMP"]);
    }

    #[test]
    fn parse_peer_down_no_data() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.push(4);
        let data = bmp(MSG_PEER_DOWN, &rest);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "reason_name"),
            Some("Remote system closed, no data")
        );
        assert!(buf.field_by_name(layer, "data").is_none());

        // A Peer Down that ends before its reason code.
        let rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        let data = bmp(MSG_PEER_DOWN, &rest);
        let (buf, _) = dissect(&data);
        assert!(buf.field_by_name(bmp_layer(&buf), "reason").is_none());
    }

    #[test]
    fn parse_peer_down_tlv() {
        let mut rest = per_peer_header(3, 0, [0; 16], 65000);
        rest.push(PEER_DOWN_LOCAL_TLV);
        rest.extend(tlv(3, b"global"));
        let data = bmp(MSG_PEER_DOWN, &rest);
        let (buf, _) = dissect(&data);
        let tlvs = tlvs(&buf, "peer_down_tlvs");
        assert_eq!(tlvs.len(), 1);
        assert_eq!(child_display(tlvs[0], "type"), Some("VRF/Table Name"));
        assert_eq!(
            *child_value(tlvs[0], "string"),
            FieldValue::Bytes(b"global")
        );
    }

    #[test]
    fn parse_peer_up() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 2]), 65002);
        rest.extend_from_slice(&ipv4_mapped([192, 0, 2, 1]));
        rest.extend_from_slice(&179u16.to_be_bytes());
        rest.extend_from_slice(&50000u16.to_be_bytes());
        let sent = bgp_open(65001);
        let received = bgp_open(65002);
        rest.extend_from_slice(&sent);
        rest.extend_from_slice(&received);
        rest.extend(tlv(0, b"peer"));
        rest.extend(tlv(3, b"global"));
        rest.extend(tlv(4, b"label"));
        let data = bmp(MSG_PEER_UP, &rest);
        let (buf, result) = dissect(&data);

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(layer_names(&buf), ["BMP", "BGP", "BGP"]);
        let layer = bmp_layer(&buf);
        assert_eq!(
            buf.resolve_display_name(layer, "message_type_name"),
            Some("Peer Up Notification")
        );
        assert_eq!(
            *value(&buf, "local_address"),
            FieldValue::Ipv4Addr([192, 0, 2, 1])
        );
        assert_eq!(*value(&buf, "local_port"), FieldValue::U16(179));
        assert_eq!(*value(&buf, "remote_port"), FieldValue::U16(50000));

        let opens: Vec<_> = buf.layers().iter().filter(|l| l.name == "BGP").collect();
        let first = 48 + PEER_UP_FIXED_SIZE;
        assert_eq!(opens[0].range, first..first + sent.len());
        assert_eq!(
            opens[1].range,
            first + sent.len()..first + sent.len() + received.len()
        );
        assert_eq!(
            buf.field_by_name(opens[0], "my_as").unwrap().value,
            FieldValue::U16(65001)
        );
        assert_eq!(
            buf.field_by_name(opens[1], "my_as").unwrap().value,
            FieldValue::U16(65002)
        );

        let tlvs = tlvs(&buf, "peer_up_tlvs");
        assert_eq!(tlvs.len(), 3);
        assert_eq!(child_display(tlvs[0], "type"), Some("String"));
        assert_eq!(child_display(tlvs[1], "type"), Some("VRF/Table Name"));
        assert_eq!(child_display(tlvs[2], "type"), Some("Admin Label"));
        assert_eq!(*child_value(tlvs[2], "string"), FieldValue::Bytes(b"label"));
        // The TLV object is named after its type.
        let array = buf.field_by_name(layer, "peer_up_tlvs").unwrap();
        let FieldValue::Array(r) = &array.value else {
            panic!()
        };
        assert_eq!(buf.resolve_container_display_name(r.start), Some("String"));
    }

    #[test]
    fn peer_up_invalid_open() {
        let mut rest = per_peer_header(0, FLAG_V, [0x20; 16], 65002);
        rest.extend_from_slice(&[0x20; 16]);
        rest.extend_from_slice(&[0, 179, 0, 1]);
        let mut sent = bgp_open(65001);
        sent[3] = 0;
        rest.extend_from_slice(&sent);
        let data = bmp(MSG_PEER_UP, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(layer_names(&buf), ["BMP"]);
        assert_eq!(
            *value(&buf, "local_address"),
            FieldValue::Ipv6Addr([0x20; 16])
        );
        assert_eq!(*value(&buf, "bgp_message"), FieldValue::Bytes(&sent));
        assert!(buf.field_by_name(bmp_layer(&buf), "peer_up_tlvs").is_none());
    }

    #[test]
    fn peer_up_truncated_fixed_part() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&[1, 2, 3]);
        let data = bmp(MSG_PEER_UP, &rest);
        let (buf, _) = dissect(&data);
        assert!(buf.field_by_name(bmp_layer(&buf), "local_port").is_none());
        assert_eq!(*value(&buf, "data"), FieldValue::Bytes(&[1, 2, 3]));
    }

    #[test]
    fn parse_route_mirroring() {
        let mut rest = per_peer_header(0, FLAG_A, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend(tlv(1, &[0, 0]));
        let update = ambiguous_update();
        rest.extend(tlv(0, &update));
        let data = bmp(MSG_ROUTE_MIRRORING, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(layer_names(&buf), ["BMP", "BGP"]);
        let tlvs = tlvs(&buf, "route_mirroring_tlvs");
        assert_eq!(tlvs.len(), 2);
        assert_eq!(child_display(tlvs[0], "type"), Some("Information"));
        assert_eq!(
            child_display(tlvs[0], "information_code"),
            Some("Errored PDU")
        );
        assert_eq!(child_display(tlvs[1], "type"), Some("BGP Message"));
        assert!(tlvs[1].iter().all(|f| f.name() != "value"));
        let bgp_layer = buf.layer_by_name("BGP").unwrap();
        assert_eq!(bgp_layer.range, data.len() - update.len()..data.len());
        // The A flag has no significance for Route Mirroring: inferred.
        assert_eq!(bgp_as_path(&buf), [65538, 16_842_755]);
    }

    #[test]
    fn route_mirroring_invalid_bgp_message() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend(tlv(0, &[1, 2, 3]));
        rest.extend(tlv(0, &[]));
        let data = bmp(MSG_ROUTE_MIRRORING, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(layer_names(&buf), ["BMP"]);
        let tlvs = tlvs(&buf, "route_mirroring_tlvs");
        assert_eq!(
            *child_value(tlvs[0], "value"),
            FieldValue::Bytes(&[1, 2, 3])
        );
        assert_eq!(tlvs[1].len(), 2);
    }

    #[test]
    fn tlv_overrun_kept_as_data() {
        let mut rest = tlv(2, b"r1");
        rest.extend_from_slice(&[0, 1, 0, 9, b'x']);
        let data = bmp(MSG_INITIATION, &rest);
        let (buf, _) = dissect(&data);
        assert_eq!(tlvs(&buf, "information_tlvs").len(), 1);
        let array = buf
            .field_by_name(bmp_layer(&buf), "information_tlvs")
            .unwrap();
        assert_eq!(array.range, 6..12);
        let f = buf.field_by_name(bmp_layer(&buf), "data").unwrap();
        assert_eq!(f.value, FieldValue::Bytes(&[0, 1, 0, 9, b'x']));
        assert_eq!(f.range, 12..17);
    }

    #[test]
    fn unknown_message_type() {
        let data = bmp(200, &[1, 2, 3]);
        let (buf, _) = dissect(&data);
        let layer = bmp_layer(&buf);
        assert_eq!(buf.resolve_display_name(layer, "message_type_name"), None);
        assert_eq!(*value(&buf, "data"), FieldValue::Bytes(&[1, 2, 3]));
    }

    #[test]
    fn consumes_one_message() {
        let mut data = bmp(MSG_INITIATION, &tlv(2, b"r1"));
        let first = data.len();
        data.extend_from_slice(&bmp(MSG_TERMINATION, &tlv(1, &[0, 0])));
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, first);
        assert_eq!(layer_names(&buf), ["BMP"]);
    }

    #[test]
    fn truncated_common_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            BmpDissector.dissect(&[3, 0, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 6,
                actual: 3
            })
        );
    }

    #[test]
    fn truncated_message() {
        let data = bmp(MSG_INITIATION, &tlv(2, b"router1"));
        let mut buf = DissectBuffer::new();
        assert_eq!(
            BmpDissector.dissect(&data[..10], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: data.len(),
                actual: 10
            })
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn reject_unsupported_version() {
        let mut data = bmp(MSG_INITIATION, &[]);
        data[0] = 1;
        let mut buf = DissectBuffer::new();
        assert_eq!(
            BmpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            })
        );
    }

    #[test]
    fn reject_short_message_length() {
        let data = [3, 0, 0, 0, 5, 4];
        let mut buf = DissectBuffer::new();
        assert_eq!(
            BmpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "message_length",
                value: 5
            })
        );
    }

    #[test]
    fn reject_missing_per_peer_header() {
        let data = bmp(MSG_ROUTE_MONITORING, &[0; 10]);
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            BmpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn offsets_are_absolute() {
        let mut rest = per_peer_header(0, 0, ipv4_mapped([192, 0, 2, 9]), 1);
        rest.extend_from_slice(&ambiguous_update());
        let data = bmp(MSG_ROUTE_MONITORING, &rest);
        let mut buf = DissectBuffer::new();
        BmpDissector.dissect(&data, &mut buf, 100).unwrap();
        assert_eq!(buf.layers()[0].range, 100..100 + data.len());
        assert_eq!(buf.layers()[1].range, 148..100 + data.len());
    }

    #[test]
    fn registry_names() {
        // IANA BMP Parameters: every assigned code point has a name.
        assert!((0..=6).all(|t| message_type_name(t).is_some()));
        assert_eq!(message_type_name(251), Some("Experimental"));
        assert_eq!(message_type_name(255), None);
        assert!((0..=3).all(|t| peer_type_name(t).is_some()));
        assert_eq!(peer_type_name(254), Some("Experimental"));
        assert_eq!(peer_type_name(4), None);
        assert!((1..=6).all(|r| peer_down_reason_name(r).is_some()));
        assert_eq!(peer_down_reason_name(252), Some("Experimental"));
        assert_eq!(peer_down_reason_name(0), None);
        assert!((0..=43).all(|t| stat_type_name(t).is_some()));
        assert_eq!(stat_type_name(44), None);
        assert_eq!(stat_type_name(65531), Some("Experimental"));
        assert_eq!(initiation_tlv_type_name(3), None);
        assert_eq!(initiation_tlv_type_name(65534), Some("Experimental"));
        assert_eq!(peer_up_tlv_type_name(1), None);
        assert_eq!(peer_up_tlv_type_name(65533), Some("Experimental"));
        assert_eq!(peer_down_tlv_type_name(0), None);
        assert_eq!(termination_tlv_type_name(2), None);
        assert!((0..=4).all(|r| termination_reason_name(r).is_some()));
        assert_eq!(termination_reason_name(65531), Some("Experimental"));
        assert_eq!(termination_reason_name(5), None);
        assert_eq!(mirroring_tlv_type_name(65532), Some("Experimental"));
        assert_eq!(mirroring_tlv_type_name(2), None);
        assert_eq!(mirroring_information_name(1), Some("Messages Lost"));
        assert_eq!(mirroring_information_name(65531), Some("Experimental"));
        assert_eq!(mirroring_information_name(2), None);
    }

    #[test]
    fn field_descriptor_names_are_unique() {
        let mut names: Vec<_> = FIELD_DESCRIPTORS.iter().map(|d| d.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FIELD_DESCRIPTORS.len());
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(BmpDissector.name(), "BGP Monitoring Protocol");
        assert_eq!(BmpDissector.short_name(), "BMP");
        assert_eq!(BmpDissector.layer(), Some(ProtocolLayer::Application));
        assert_eq!(BmpDissector.references()[0].id, "RFC 7854");
        assert_eq!(BmpDissector.field_descriptors().len(), FD_DATA + 1);
    }

    #[test]
    fn visit_sub_dissectors_lists_embedded_layers() {
        let mut names = Vec::new();
        BmpDissector.visit_sub_dissectors(&mut |d| names.push(d.short_name()));
        assert_eq!(names, ["BGP"]);
    }
}
