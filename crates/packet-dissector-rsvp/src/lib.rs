//! RSVP (Resource ReSerVation Protocol) and RSVP-TE dissector.
//!
//! Decodes the RSVP common header and walks the object list of every
//! message type. Objects are decoded from one table keyed by (Class-Num,
//! C-Type); other objects keep their contents as raw bytes. Decoded objects
//! cover RSVP (RFC 2205, with IntServ Flowspec and Tspec
//! per RFC 2210), RSVP-TE (RFC 3209: LSP tunnel sessions and senders,
//! LABEL, LABEL_REQUEST, EXPLICIT_ROUTE, RECORD_ROUTE, SESSION_ATTRIBUTE,
//! HELLO), fast reroute (RFC 4090) and refresh reduction (RFC 2961).
//!
//! RSVP messages are carried directly in IP with protocol number 46.
//!
//! ## References
//! - RFC 2205 (RSVP Version 1 Functional Specification): <https://www.rfc-editor.org/rfc/rfc2205>
//! - RFC 2210 (The Use of RSVP with IETF Integrated Services): <https://www.rfc-editor.org/rfc/rfc2210>
//! - RFC 2961 (RSVP Refresh Overhead Reduction Extensions): <https://www.rfc-editor.org/rfc/rfc2961>
//! - RFC 3209 (RSVP-TE: Extensions to RSVP for LSP Tunnels): <https://www.rfc-editor.org/rfc/rfc3209>
//! - RFC 3473 (GMPLS Signaling RSVP-TE Extensions — Label subobject): <https://www.rfc-editor.org/rfc/rfc3473>
//! - RFC 3477 (Signalling Unnumbered Links in RSVP-TE): <https://www.rfc-editor.org/rfc/rfc3477>
//! - RFC 4090 (Fast Reroute Extensions to RSVP-TE for LSP Tunnels): <https://www.rfc-editor.org/rfc/rfc4090>
//! - IANA RSVP Parameters: <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// Common header size: Vers/Flags (1), Msg Type (1), RSVP Checksum (2),
/// Send_TTL (1), Reserved (1), RSVP Length (2).
/// RFC 2205, Section 3.1.1 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1.1>
const HEADER_SIZE: usize = 8;

/// Object header size: Length (2), Class-Num (1), C-Type (1).
/// RFC 2205, Section 3.1.2 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1.2>
const OBJECT_HEADER_SIZE: usize = 4;

/// "Protocol version number.  This is version 1."
/// RFC 2205, Section 3.1.1 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1.1>
const VERSION_1: u8 = 1;

/// Object Class-Nums decoded by this dissector. RFC 2205, Appendix A —
/// <https://www.rfc-editor.org/rfc/rfc2205#appendix-A>; RFC 3209,
/// Section 4 — <https://www.rfc-editor.org/rfc/rfc3209#section-4>; RFC
/// 2961, Sections 4.2, 4.3 and 5.1 —
/// <https://www.rfc-editor.org/rfc/rfc2961#section-4.2>; RFC 4090,
/// Section 4 — <https://www.rfc-editor.org/rfc/rfc4090#section-4>
const CLASS_SESSION: u8 = 1;
const CLASS_RSVP_HOP: u8 = 3;
const CLASS_TIME_VALUES: u8 = 5;
const CLASS_ERROR_SPEC: u8 = 6;
const CLASS_SCOPE: u8 = 7;
const CLASS_STYLE: u8 = 8;
const CLASS_FLOWSPEC: u8 = 9;
const CLASS_FILTER_SPEC: u8 = 10;
const CLASS_SENDER_TEMPLATE: u8 = 11;
const CLASS_SENDER_TSPEC: u8 = 12;
const CLASS_RESV_CONFIRM: u8 = 15;
const CLASS_LABEL: u8 = 16;
const CLASS_LABEL_REQUEST: u8 = 19;
const CLASS_EXPLICIT_ROUTE: u8 = 20;
const CLASS_RECORD_ROUTE: u8 = 21;
const CLASS_HELLO: u8 = 22;
const CLASS_MESSAGE_ID: u8 = 23;
const CLASS_MESSAGE_ID_ACK: u8 = 24;
const CLASS_MESSAGE_ID_LIST: u8 = 25;
const CLASS_DETOUR: u8 = 63;
const CLASS_FAST_REROUTE: u8 = 205;
const CLASS_SESSION_ATTRIBUTE: u8 = 207;

/// IntServ parameter IDs: token bucket Tspec and Guaranteed service RSpec.
/// RFC 2210, Sections 3.1 and 3.3 — <https://www.rfc-editor.org/rfc/rfc2210#section-3.1>
const PARAM_TOKEN_BUCKET: u8 = 127;
const PARAM_GUARANTEED_RSPEC: u8 = 130;

/// Bundle message type: "12 = Bundle". RFC 2961, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc2961#section-3.1>
const MSG_BUNDLE: u8 = 12;

/// Returns the name of an RSVP message type.
///
/// IANA RSVP Message Types —
/// <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml#rsvp-parameters-2>
fn message_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Path"),
        2 => Some("Resv"),
        3 => Some("PathErr"),
        4 => Some("ResvErr"),
        5 => Some("PathTear"),
        6 => Some("ResvTear"),
        7 => Some("ResvConf"),
        8 => Some("DREQ"),
        9 => Some("DREP"),
        10 => Some("ResvTearConfirm"),
        12 => Some("Bundle"),
        13 => Some("ACK"),
        15 => Some("Srefresh"),
        20 => Some("Hello"),
        21 => Some("Notify Message"),
        25 => Some("Integrity Challenge"),
        26 => Some("Integrity Response"),
        30 => Some("RecoveryPath"),
        66 => Some("DSBM_willing"),
        67 => Some("I_AM_DSBM"),
        _ => None,
    }
}

/// Returns the name of an object Class-Num.
///
/// IANA RSVP Class Names, Class Numbers, and Class Types —
/// <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml#rsvp-parameters-4>
fn class_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("NULL"),
        1 => Some("SESSION"),
        3 => Some("RSVP_HOP"),
        4 => Some("INTEGRITY"),
        5 => Some("TIME_VALUES"),
        6 => Some("ERROR_SPEC"),
        7 => Some("SCOPE"),
        8 => Some("STYLE"),
        9 => Some("FLOWSPEC"),
        10 => Some("FILTER_SPEC"),
        11 => Some("SENDER_TEMPLATE"),
        12 => Some("SENDER_TSPEC"),
        13 => Some("ADSPEC"),
        14 => Some("POLICY_DATA"),
        15 => Some("RESV_CONFIRM"),
        16 => Some("RSVP_LABEL"),
        17 => Some("HOP_COUNT"),
        18 => Some("STRICT_SOURCE_ROUTE"),
        19 => Some("LABEL_REQUEST"),
        20 => Some("EXPLICIT_ROUTE"),
        21 => Some("ROUTE_RECORD (also known as RECORD_ROUTE)"),
        22 => Some("HELLO"),
        23 => Some("MESSAGE_ID"),
        24 => Some("MESSAGE_ID_ACK"),
        25 => Some("MESSAGE_ID_LIST"),
        30 => Some("DIAGNOSTIC"),
        31 => Some("ROUTE"),
        32 => Some("DIAG_RESPONSE"),
        33 => Some("DIAG_SELECT"),
        34 => Some("RECOVERY_LABEL"),
        35 => Some("UPSTREAM_LABEL"),
        36 => Some("LABEL_SET"),
        37 => Some("PROTECTION"),
        38 => Some("PRIMARY_PATH_ROUTE"),
        42 => Some("DSBM IP ADDRESS"),
        43 => Some("SBM_PRIORITY"),
        44 => Some("DSBM TIMER INTERVALS"),
        45 => Some("SBM_INFO"),
        50 => Some("S2L_SUB_LSP"),
        63 => Some("DETOUR"),
        64 => Some("CHALLENGE"),
        65 => Some("DIFF-SERV"),
        66 => Some("CLASSTYPE"),
        67 => Some("LSP_REQUIRED_ATTRIBUTES"),
        120 => Some("UPSTREAM_FLOWSPEC"),
        121 => Some("UPSTREAM_TSPEC"),
        122 => Some("UPSTREAM_ADSPEC"),
        128 => Some("NODE_CHAR"),
        129 => Some("SUGGESTED_LABEL"),
        130 => Some("ACCEPTABLE_LABEL_SET"),
        131 => Some("RESTART_CAP"),
        132 => Some("SESSION-OF-INTEREST"),
        133 => Some("LINK_CAPABILITY"),
        134 => Some("Capability Object"),
        135 => Some("CONDITIONS"),
        161 => Some("RSVP_HOP_L2"),
        162 => Some("LAN_NHOP_L2"),
        163 => Some("LAN_NHOP_L3"),
        164 => Some("LAN_LOOPBACK"),
        165 => Some("TCLASS"),
        192 => Some("SESSION_ASSOC"),
        193 => Some("LSP_TUNNEL_INTERFACE_ID"),
        194 => Some("USER_ERROR_SPEC"),
        195 => Some("NOTIFY_REQUEST"),
        196 => Some("ADMIN_STATUS"),
        197 => Some("LSP_ATTRIBUTES"),
        198 => Some("ALARM_SPEC"),
        199 => Some("ASSOCIATION"),
        200 => Some("SECONDARY_EXPLICIT_ROUTE"),
        201 => Some("SECONDARY_RECORD_ROUTE"),
        202 => Some("CALL ATTRIBUTES"),
        203 => Some("REVERSE_LSP"),
        204 => Some("S2L_SUB_LSP_FRAG"),
        205 => Some("FAST_REROUTE"),
        207 => Some("SESSION_ATTRIBUTE"),
        225 => Some("DCLASS"),
        226 => Some("PACKETCABLE EXTENSIONS"),
        227 => Some("ATM_SERVICECLASS"),
        228 => Some("CALL_OPS (ASON)"),
        229 => Some("GENERALIZED_UNI"),
        230 => Some("CALL_ID"),
        231 => Some("3GPP2_Object"),
        232 => Some("EXCLUDE_ROUTE"),
        248 => Some("PCN"),
        252..=255 => Some("Reserved for Private Use"),
        _ => None,
    }
}

/// Returns the name of the C-Type `ctype` of the object class `class`.
///
/// IANA RSVP Class Types or C-Types —
/// <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml>
fn c_type_name(class: u8, ctype: u8) -> Option<&'static str> {
    match (class, ctype) {
        (1, 1) => Some("IPv4"),
        (1, 2) => Some("IPv6"),
        (1, 3) => Some("IPv4/GPI"),
        (1, 4) => Some("IPv6/GPI"),
        (1, 6) => Some("tagged_tunnel_IPv4"),
        (1, 7) => Some("LSP Tunnel IPv4"),
        (1, 8) => Some("LSP Tunnel IPv6"),
        (1, 9) => Some("RSVP-Aggregate-IP4"),
        (1, 10) => Some("RSVP-Aggregate-IP6"),
        (1, 11) => Some("UNI_IPv4_Session object"),
        (1, 12) => Some("UNI_IPv6 SESSION object (ASON)"),
        (1, 13) => Some("P2MP_LSP_TUNNEL_IPv4"),
        (1, 14) => Some("P2MP_LSP_TUNNEL_IPv6"),
        (1, 15) => Some("ENNI_IPv4 SESSION object (ASON)"),
        (1, 16) => Some("ENNI_IPv6 SESSION object (ASON)"),
        (1, 17) => Some("GENERIC-AGGREGATE-IP4"),
        (1, 18) => Some("GENERIC-AGGREGATE-IP6"),
        (1, 19) => Some("VPN-IPv4"),
        (1, 20) => Some("VPN-IPv6"),
        (1, 21) => Some("AGGREGATE-VPN-IPv4"),
        (1, 22) => Some("AGGREGATE-VPN-IPv6"),
        (1, 23) => Some("GENERIC-AGGREGATE-VPN-IPv4"),
        (1, 24) => Some("GENERIC-AGGREGATE-VPN-IPv6"),
        (3, 1) => Some("IPv4"),
        (3, 2) => Some("IPv6"),
        (3, 3) => Some("IPv4 IF_ID RSVP_HOP"),
        (3, 4) => Some("IPv6 IF_ID RSVP_HOP"),
        (3, 5) => Some("VPN-IPv4"),
        (3, 6) => Some("VPN-IPv6"),
        (4, 1) => Some("Type 1 Integrity Value"),
        (5, 1) => Some("Type 1 Time Value"),
        (6, 1) => Some("IPv4"),
        (6, 2) => Some("IPv6"),
        (6, 3) => Some("IPv4 IF_ID ERROR_SPEC"),
        (6, 4) => Some("IPv6 IF_ID ERROR_SPEC"),
        (7, 1) => Some("IPv4"),
        (7, 2) => Some("IPv6"),
        (8, 1) => Some("Type 1 Style"),
        (9, 2) => Some("Int-serv Flowspec"),
        (9, 3) => Some("Deprecated"),
        (9, 4) => Some("SONET/SDH FLOWSPEC"),
        (9, 5) => Some("G.709"),
        (9, 6) => Some("Ethernet SENDER_TSPEC"),
        (9, 7) => Some("OTN-TDM"),
        (9, 8) => Some("SSON FLOWSPEC"),
        (10, 1) => Some("IPv4"),
        (10, 2) => Some("IPv6"),
        (10, 3) => Some("IPv6 Flow Label"),
        (10, 4) => Some("IPv4/GPI"),
        (10, 5) => Some("IPv6/GPI"),
        (10, 6) => Some("tagged_tunnel_IPv4"),
        (10, 7) => Some("LSP Tunnel IPv4"),
        (10, 8) => Some("LSP Tunnel IPv6"),
        (10, 9) => Some("RSVP-Aggregate-IP4"),
        (10, 10) => Some("RSVP-Aggregate-IP6"),
        (10, 12) => Some("P2MP LSP_IPv4"),
        (10, 13) => Some("P2MP LSP_IPv6"),
        (10, 14) => Some("VPN-IPv4"),
        (10, 15) => Some("VPN-IPv6"),
        (10, 16) => Some("AGGREGATE-VPN-IPv4"),
        (10, 17) => Some("AGGREGATE-VPN-IPv6"),
        (11, 1) => Some("IPv4"),
        (11, 2) => Some("IPv6"),
        (11, 3) => Some("IPv6 Flow Label"),
        (11, 4) => Some("IPv4/GPI"),
        (11, 5) => Some("IPv6/GPI"),
        (11, 6) => Some("tagged_tunnel_IPv4"),
        (11, 7) => Some("LSP Tunnel IPv4"),
        (11, 8) => Some("LSP Tunnel IPv6"),
        (11, 9) => Some("RSVP-Aggregate-IP4"),
        (11, 10) => Some("RSVP-Aggregate-IP6"),
        (11, 12) => Some("P2MP_LSP_TUNNEL_IPv4"),
        (11, 13) => Some("P2MP_LSP_TUNNEL_IPv6"),
        (11, 14) => Some("VPN-IPv4"),
        (11, 15) => Some("VPN-IPv6"),
        (11, 16) => Some("AGGREGATE-VPN-IPv4"),
        (11, 17) => Some("AGGREGATE-VPN-IPv6"),
        (12, 2) => Some("Int-serv"),
        (12, 3) => Some("Deprecated"),
        (12, 4) => Some("SONET/SDH SENDER_TSPEC"),
        (12, 5) => Some("G.709"),
        (12, 6) => Some("Ethernet SENDER_TSPEC"),
        (12, 7) => Some("OTN-TDM"),
        (12, 8) => Some("SSON SENDER_TSPEC"),
        (13, 2) => Some("Int-serv"),
        (14, 1) => Some("Type 1 policy data"),
        (15, 1) => Some("IPv4"),
        (15, 2) => Some("IPv6"),
        (16, 1) => Some("Type 1 Label"),
        (16, 2) => Some("Generalized_Label"),
        (16, 3) => Some("Waveband_Switching_Label C-Type"),
        (16, 4) => Some("Generalized Channel_Set"),
        (17, 1) => Some("IPv4"),
        (18, 1) => Some("Default"),
        (19, 1) => Some("Without Label Range"),
        (19, 2) => Some("With ATM Label Range"),
        (19, 3) => Some("With Frame Relay Label Range"),
        (19, 4) => Some("Generalized_Label_Request"),
        (19, 5) => Some("Generalized Channel_Set"),
        (20, 1) => Some("Type 1 Explicit Route"),
        (21, 1) => Some("Type 1 Route Record"),
        (22, 1) => Some("Request"),
        (22, 2) => Some("Acknowledgment"),
        (23, 1) => Some("Type 1 Message ID"),
        (24, 1) => Some("MESSAGE_ID_ACK"),
        (24, 2) => Some("MESSAGE_ID_NACK"),
        (25, 1) => Some("Message ID list"),
        (25, 2) => Some("IPv4 Message ID Source list"),
        (25, 3) => Some("IPv6 Message ID Source list"),
        (25, 4) => Some("IPv4 Message ID Multicast list"),
        (25, 5) => Some("IPv6 Message ID Multicast list"),
        (30, 1) => Some("IPv4"),
        (30, 2) => Some("IPv6"),
        (31, 1) => Some("IPv4"),
        (31, 2) => Some("IPv6"),
        (32, 1) => Some("IPv4"),
        (32, 2) => Some("IPv6"),
        (33, 1) => Some("Type 1 Diagnostic Select"),
        (36, 1) => Some("Type 1 Label_set"),
        (37, 1) => Some("Type 1 Protection"),
        (37, 2) => Some("Type 2"),
        (37, 3) => Some("Egress Protection"),
        (38, 1) => Some("Type 1 Primary Path Route"),
        (42, 1) => Some("IPv4"),
        (42, 2) => Some("IPv6"),
        (43, 1) => Some("default"),
        (44, 1) => Some("default"),
        (45, 1) => Some("Media Type"),
        (50, 1) => Some("S2L_SUB_LSP_IPv4"),
        (50, 2) => Some("S2L_SUB_LSP_IPv6"),
        (63, 7) => Some("IPv4"),
        (63, 8) => Some("IPv6"),
        (64, 1) => Some("Type 1 Challenge Value"),
        (65, 1) => Some("Diff-Serv object for an E-LSP"),
        (65, 2) => Some("Diff-Serv object for an L-LSP"),
        (66, 1) => Some("Type 1"),
        (67, 1) => Some("LSP Required Attributes TLVs"),
        (131, 1) => Some("Type 1 Restart capabilities"),
        (132, 1) => Some("GENERIC-AGG-IP4-SOI"),
        (132, 2) => Some("GENERIC-AGG-IP6-SOI"),
        (133, 1) => Some("(TE Link Capabilities)"),
        (134, 1) => Some("Capability Object"),
        (135, 1) => Some("CONDITIONS"),
        (161, 1) => Some("IEEE Canonical Address"),
        (162, 1) => Some("IEEE Canonical Address"),
        (163, 1) => Some("IPv4"),
        (163, 2) => Some("IPv6"),
        (164, 1) => Some("IPv4"),
        (164, 2) => Some("IPv6"),
        (193, 1) => Some("Forward/Reverse Interface ID"),
        (193, 2) => Some("IPv4 interface identifier with target"),
        (193, 3) => Some("IPv6 interface identifier with target"),
        (193, 4) => Some("Unnumbered interface with target"),
        (194, 1) => Some("User-Defined Error"),
        (195, 1) => Some("IPv4 Notify Request"),
        (195, 2) => Some("IPv6 Notify Request"),
        (196, 1) => Some("Type 1 Admin status"),
        (197, 1) => Some("LSP Attributes TLVs"),
        (198, 1) => Some("Type 1 RESERVED"),
        (198, 2) => Some("Type 2 RESERVED"),
        (198, 3) => Some("IPv4 IF_ID ALARM_SPEC"),
        (198, 4) => Some("IPv6 IF_ID ALARM_SPEC"),
        (199, 1) => Some("Type 1 IPv4 Association"),
        (199, 2) => Some("Type 2 IPv6 Association"),
        (199, 3) => Some("Type 3 IPv4 Extended Association"),
        (199, 4) => Some("Type 4 IPv6 Extended Association"),
        (200, 2) => Some("P2MP SECONDARY_EXPLICIT_ROUTE"),
        (201, 2) => Some("P2MP SECONDARY_RECORD_ROUTE"),
        (202, 1) => Some("Call Attributes"),
        (203, 1) => Some("REVERSE_LSP"),
        (204, 1) => Some("S2L_SUB_LSP_FRAG"),
        (205, 1) => Some("Type 1"),
        (205, 7) => Some("Type 7 RESERVED"),
        (207, 1) => Some("LSP_TUNNEL_RA"),
        (207, 7) => Some("LSP Tunnel"),
        (226, 1) => Some("Reverse-Rspec"),
        (226, 2) => Some("Reverse-Session"),
        (226, 3) => Some("Reverse-Sender-Template"),
        (226, 4) => Some("Reverse-Sender-Tspec"),
        (226, 5) => Some("Forward-Rspec"),
        (226, 6) => Some("Component-Tspec"),
        (226, 7) => Some("Resource-ID"),
        (226, 8) => Some("Gate-ID"),
        (226, 9) => Some("Commit-Entity"),
        (227, 1) => Some("ATM Service class"),
        (228, 1) => Some("Type 1 CALL_OPS"),
        (229, 1) => Some("Type 1 Generalized UNI"),
        (230, 1) => Some("Operator specific"),
        (230, 2) => Some("Globally unique"),
        (231, 1) => Some("Component"),
        (232, 1) => Some("EXCLUDE_ROUTE"),
        (248, 1) => Some("RSVP-AGGREGATE-IPv4-PCN-request"),
        (248, 2) => Some("RSVP-AGGREGATE-IPv6-PCN-request"),
        (248, 3) => Some("RSVP-AGGREGATE-IPv4-PCN-response"),
        (248, 4) => Some("RSVP-AGGREGATE-IPv6-PCN-response"),
        _ => None,
    }
}

/// Returns the name of an ERROR_SPEC Error Code.
///
/// IANA RSVP Error Codes —
/// <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml#rsvp-parameters-99>
fn error_code_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("Confirmation"),
        1 => Some("Admission Control Failure"),
        2 => Some("Policy Control Failure"),
        3 => Some("No path information for this Resv message."),
        4 => Some("No sender information for this Resv message."),
        5 => Some("Conflicting reservation style"),
        6 => Some("Unknown reservation style"),
        7 => Some("Conflicting dest ports"),
        8 => Some("Conflicting sender ports"),
        12 => Some("Service preempted"),
        13 => Some("Unknown object class"),
        14 => Some("Unknown object C-Type"),
        20 => Some("Reserved for API"),
        21 => Some("Traffic Control Error"),
        22 => Some("Traffic Control System error"),
        23 => Some("RSVP System Error"),
        24 => Some("Routing Problem"),
        25 => Some("Notify Error"),
        26 => Some("NEW-AGGREGATE-NEEDED"),
        27 => Some("Diffserv Error"),
        28 => Some("Diff-Serv-aware TE Error"),
        29 => Some("Unknown Attributes TLV"),
        30 => Some("Unknown Attributes Bit"),
        31 => Some("Alarms"),
        32 => Some("Call Management"),
        33 => Some("User Error Spec"),
        34 => Some("Reroute"),
        35 => Some("Handover Procedure Failure"),
        36 => Some("Unrecoverable Receiver Proxy Error"),
        37 => Some("RSVP over MPLS Problem"),
        38 => Some("LSP Hierarchy Issue"),
        39 => Some("VCAT Call Management"),
        40 => Some("OAM Problem"),
        41 => Some("Duplicate TLV"),
        42 => Some("Duplicate sub-TLV"),
        43 => Some("RTM_SET TLV Absent"),
        44 => Some("FRR Bypass Assignment Error"),
        252..=255 => Some("Reserved for Private Use"),
        _ => None,
    }
}

/// Returns the name of an EXPLICIT_ROUTE subobject type.
///
/// IANA RSVP Subobject types —
/// <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml#rsvp-parameters-25>
fn ero_subobject_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IPv4 prefix"),
        2 => Some("IPv6 prefix"),
        3 => Some("Label"),
        4 => Some("Unnumbered Interface ID"),
        5 => Some("4-byte AS number"),
        6 => Some("OSPF Area ID"),
        7 => Some("IS-IS Area ID"),
        32 => Some("Autonomous system number"),
        33 => Some("Explicit Exclusion Route subobject (EXRS)"),
        35 => Some("Hop Attributes"),
        36 => Some("SR-ERO"),
        38 => Some("IPv4 Diversity"),
        39 => Some("IPv6 Diversity"),
        40 => Some("SRv6-ERO (PCEP-specific)"),
        64 => Some("Path Key with 32-bit PCE ID"),
        65 => Some("Path Key with 128-bit PCE ID"),
        _ => None,
    }
}

/// Returns the name of a ROUTE_RECORD subobject type.
///
/// IANA RSVP Subobject types —
/// <https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml#rsvp-parameters-27>
fn rro_subobject_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IPv4 address"),
        2 => Some("IPv6 address"),
        3 => Some("Label"),
        4 => Some("Unnumbered Interface ID"),
        5 => Some("RRO Attributes"),
        34 => Some("SRLG sub-object"),
        35 => Some("Hop Attributes"),
        36 => Some("SR-RRO"),
        38 => Some("BYPASS_ASSIGNMENT IPv4 subobject"),
        39 => Some("BYPASS_ASSIGNMENT IPv6 subobject"),
        40 => Some("SRv6-RRO (PCEP-specific)"),
        64 => Some("Path Key with 32-bit PCE ID"),
        65 => Some("Path Key with 128-bit PCE ID"),
        _ => None,
    }
}

/// Returns the name of a STYLE object's reservation style: the sharing
/// control and sender selection control bits (the low 5 bits of the Option
/// Vector).
///
/// RFC 2205, Appendix A.7 — <https://www.rfc-editor.org/rfc/rfc2205#appendix-A.7>
fn style_name(option_vector: u32) -> Option<&'static str> {
    match option_vector & 0x1F {
        0b10001 => Some("Wildcard-Filter (WF)"),
        0b01010 => Some("Fixed-Filter (FF)"),
        0b10010 => Some("Shared-Explicit (SE)"),
        _ => None,
    }
}

/// Returns the name of an Integrated Services service number.
///
/// IANA Integrated Services Parameters —
/// <https://www.iana.org/assignments/int-serv/int-serv.xhtml>
fn service_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Default/Global Information"),
        2 => Some("Guaranteed"),
        5 => Some("Controlled Load"),
        _ => None,
    }
}

/// Returns the name of an Integrated Services parameter ID.
///
/// RFC 2210, Sections 3.1 and 3.3 — <https://www.rfc-editor.org/rfc/rfc2210#section-3.1>
fn parameter_name(v: u8) -> Option<&'static str> {
    match v {
        PARAM_TOKEN_BUCKET => Some("Token Bucket Tspec"),
        PARAM_GUARANTEED_RSPEC => Some("Guaranteed Service RSpec"),
        _ => None,
    }
}

/// Element of an address list (SCOPE).
static ADDRESS_ELEMENT: FieldDescriptor =
    FieldDescriptor::new("address", "Address", FieldType::Any);

/// Element of a Message_Identifier list (MESSAGE_ID_LIST).
static MESSAGE_ID_ELEMENT: FieldDescriptor =
    FieldDescriptor::new("message_id", "Message_Identifier", FieldType::U32);

/// Child descriptors of a DETOUR (PLR_ID, Avoid_Node_ID) pair.
/// RFC 4090, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc4090#section-4.2>
static DETOUR_CHILDREN: [FieldDescriptor; 2] = [
    FieldDescriptor::new("plr_id", "PLR_ID", FieldType::Any),
    FieldDescriptor::new("avoid_node_id", "Avoid_Node_ID", FieldType::Any),
];

static DETOUR_ELEMENT: FieldDescriptor =
    FieldDescriptor::new("detour", "Detour", FieldType::Object).with_children(&DETOUR_CHILDREN);

/// Child field indices of an IntServ parameter.
const P_ID: usize = 0;
const P_FLAGS: usize = 1;
const P_LENGTH: usize = 2;
const P_TOKEN_BUCKET_RATE: usize = 3;
const P_TOKEN_BUCKET_SIZE: usize = 4;
const P_PEAK_DATA_RATE: usize = 5;
const P_MIN_POLICED_UNIT: usize = 6;
const P_MAX_PACKET_SIZE: usize = 7;
const P_RATE: usize = 8;
const P_SLACK_TERM: usize = 9;
const P_VALUE: usize = 10;

/// Child descriptors of an IntServ parameter. Rates and sizes are IEEE
/// single-precision floats, kept as their 4 octets.
///
/// RFC 2210, Sections 3.1 and 3.3 — <https://www.rfc-editor.org/rfc/rfc2210#section-3.1>
static PARAMETER_CHILDREN: [FieldDescriptor; 11] = [
    FieldDescriptor::new("id", "Parameter ID", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(p) => parameter_name(*p),
        _ => None,
    }),
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new("length", "Length (words)", FieldType::U16),
    FieldDescriptor::new(
        "token_bucket_rate",
        "Token Bucket Rate [r]",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new(
        "token_bucket_size",
        "Token Bucket Size [b]",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("peak_data_rate", "Peak Data Rate [p]", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "min_policed_unit",
        "Minimum Policed Unit [m]",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("max_packet_size", "Maximum Packet Size [M]", FieldType::U32).optional(),
    FieldDescriptor::new("rate", "Rate [R]", FieldType::Bytes).optional(),
    FieldDescriptor::new("slack_term", "Slack Term [S]", FieldType::U32).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static PARAMETER: FieldDescriptor =
    FieldDescriptor::new("parameter", "Parameter", FieldType::Object)
        .with_children(&PARAMETER_CHILDREN)
        .with_display_fn(|v, children| match v {
            FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
                ("id", FieldValue::U8(p)) => parameter_name(*p),
                _ => None,
            }),
            _ => None,
        });

/// Child field indices of an EXPLICIT_ROUTE / RECORD_ROUTE subobject.
const S_LOOSE: usize = 0;
const S_TYPE: usize = 1;
const S_LENGTH: usize = 2;
const S_ADDRESS: usize = 3;
const S_PREFIX_LENGTH: usize = 4;
const S_FLAGS: usize = 5;
const S_C_TYPE: usize = 6;
const S_LABEL: usize = 7;
const S_AS_NUMBER: usize = 8;
const S_ROUTER_ID: usize = 9;
const S_INTERFACE_ID: usize = 10;
const S_VALUE: usize = 11;

/// Returns the name of a subobject type: EXPLICIT_ROUTE subobjects carry
/// the `loose` bit, RECORD_ROUTE subobjects do not.
fn subobject_name(
    t: u8,
    siblings: &[packet_dissector_core::field::Field<'_>],
) -> Option<&'static str> {
    if siblings.iter().any(|f| f.name() == "loose") {
        ero_subobject_name(t)
    } else {
        rro_subobject_name(t)
    }
}

/// Child descriptors of an EXPLICIT_ROUTE / RECORD_ROUTE subobject.
///
/// RFC 3209, Sections 4.3.3 and 4.4.1 — <https://www.rfc-editor.org/rfc/rfc3209#section-4.3.3>;
/// RFC 3473, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc3473#section-5.1>;
/// RFC 3477, Sections 4 and 5 — <https://www.rfc-editor.org/rfc/rfc3477#section-4>
static SUBOBJECT_CHILDREN: [FieldDescriptor; 12] = [
    FieldDescriptor::new("loose", "Loose (L)", FieldType::U8).optional(),
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, siblings| match v {
        FieldValue::U8(t) => subobject_name(*t, siblings),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("address", "Address", FieldType::Any).optional(),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("c_type", "C-Type", FieldType::U8).optional(),
    FieldDescriptor::new("label", "Label", FieldType::U32).optional(),
    FieldDescriptor::new("as_number", "AS Number", FieldType::U16).optional(),
    FieldDescriptor::new("router_id", "Router ID", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("interface_id", "Interface ID", FieldType::U32).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static SUBOBJECT: FieldDescriptor =
    FieldDescriptor::new("subobject", "Subobject", FieldType::Object)
        .with_children(&SUBOBJECT_CHILDREN)
        .with_display_fn(|v, children| match v {
            FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
                ("type", FieldValue::U8(t)) => subobject_name(*t, children),
                _ => None,
            }),
            _ => None,
        });

/// Child field indices of an object.
const O_LENGTH: usize = 0;
const O_CLASS_NUM: usize = 1;
const O_C_TYPE: usize = 2;
const O_ADDRESS: usize = 3;
const O_PROTOCOL_ID: usize = 4;
const O_SESSION_FLAGS: usize = 5;
const O_PORT: usize = 6;
const O_TUNNEL_ID: usize = 7;
const O_EXTENDED_TUNNEL_ID: usize = 8;
const O_LSP_ID: usize = 9;
const O_LIH: usize = 10;
const O_REFRESH_PERIOD: usize = 11;
const O_ERROR_FLAGS: usize = 12;
const O_ERROR_CODE: usize = 13;
const O_ERROR_VALUE: usize = 14;
const O_ADDRESSES: usize = 15;
const O_OPTION_VECTOR: usize = 16;
const O_LABEL: usize = 17;
const O_L3PID: usize = 18;
const O_SUBOBJECTS: usize = 19;
const O_SOURCE_INSTANCE: usize = 20;
const O_DESTINATION_INSTANCE: usize = 21;
const O_MESSAGE_FLAGS: usize = 22;
const O_EPOCH: usize = 23;
const O_MESSAGE_ID: usize = 24;
const O_MESSAGE_IDS: usize = 25;
const O_EXCLUDE_ANY: usize = 26;
const O_INCLUDE_ANY: usize = 27;
const O_INCLUDE_ALL: usize = 28;
const O_SETUP_PRIORITY: usize = 29;
const O_HOLDING_PRIORITY: usize = 30;
const O_SESSION_ATTRIBUTE_FLAGS: usize = 31;
const O_NAME_LENGTH: usize = 32;
const O_SESSION_NAME: usize = 33;
const O_HOP_LIMIT: usize = 34;
const O_FRR_FLAGS: usize = 35;
const O_BANDWIDTH: usize = 36;
const O_DETOURS: usize = 37;
const O_INTSERV_VERSION: usize = 38;
const O_INTSERV_LENGTH: usize = 39;
const O_SERVICE_NUMBER: usize = 40;
const O_SERVICE_LENGTH: usize = 41;
const O_PARAMETERS: usize = 42;
const O_VALUE: usize = 43;

/// Child descriptors of an object: the object header and the union of the
/// contents decoded by [`push_object_value`].
///
/// RFC 2205, Section 3.1.2 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1.2>
static OBJECT_CHILDREN: [FieldDescriptor; 44] = [
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("class_num", "Class-Num", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(c) => class_name(*c),
        _ => None,
    }),
    FieldDescriptor::new("c_type", "C-Type", FieldType::U8).with_display_fn(|v, siblings| {
        let FieldValue::U8(t) = v else {
            return None;
        };
        let class = siblings
            .iter()
            .find(|f| f.name() == "class_num")
            .and_then(|f| f.value.as_u8())?;
        c_type_name(class, *t)
    }),
    FieldDescriptor::new("address", "Address", FieldType::Any).optional(),
    FieldDescriptor::new("protocol_id", "Protocol Id", FieldType::U8).optional(),
    FieldDescriptor::new("session_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("port", "Port", FieldType::U16).optional(),
    FieldDescriptor::new("tunnel_id", "Tunnel ID", FieldType::U16).optional(),
    FieldDescriptor::new("extended_tunnel_id", "Extended Tunnel ID", FieldType::Any).optional(),
    FieldDescriptor::new("lsp_id", "LSP ID", FieldType::U16).optional(),
    FieldDescriptor::new("lih", "Logical Interface Handle", FieldType::U32).optional(),
    FieldDescriptor::new("refresh_period", "Refresh Period (ms)", FieldType::U32).optional(),
    FieldDescriptor::new("error_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("error_code", "Error Code", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(c) => error_code_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("error_value", "Error Value", FieldType::U16).optional(),
    FieldDescriptor::new("addresses", "Addresses", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&ADDRESS_ELEMENT)),
    FieldDescriptor::new("option_vector", "Option Vector", FieldType::U32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U32(o) => style_name(*o),
            _ => None,
        }),
    FieldDescriptor::new("label", "Label", FieldType::U32).optional(),
    FieldDescriptor::new("l3pid", "L3PID", FieldType::U16).optional(),
    FieldDescriptor::new("subobjects", "Subobjects", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&SUBOBJECT)),
    FieldDescriptor::new("source_instance", "Src_Instance", FieldType::U32).optional(),
    FieldDescriptor::new("destination_instance", "Dst_Instance", FieldType::U32).optional(),
    FieldDescriptor::new("message_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("epoch", "Epoch", FieldType::U32).optional(),
    FieldDescriptor::new("message_id", "Message_Identifier", FieldType::U32).optional(),
    FieldDescriptor::new("message_ids", "Message_Identifiers", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&MESSAGE_ID_ELEMENT)),
    FieldDescriptor::new("exclude_any", "Exclude-any", FieldType::U32).optional(),
    FieldDescriptor::new("include_any", "Include-any", FieldType::U32).optional(),
    FieldDescriptor::new("include_all", "Include-all", FieldType::U32).optional(),
    FieldDescriptor::new("setup_priority", "Setup Priority", FieldType::U8).optional(),
    FieldDescriptor::new("holding_priority", "Holding Priority", FieldType::U8).optional(),
    FieldDescriptor::new("session_attribute_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("name_length", "Name Length", FieldType::U8).optional(),
    FieldDescriptor::new("session_name", "Session Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("hop_limit", "Hop-limit", FieldType::U8).optional(),
    FieldDescriptor::new("frr_flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new(
        "bandwidth",
        "Bandwidth (IEEE float, bytes/s)",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("detours", "Detours", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&DETOUR_ELEMENT)),
    FieldDescriptor::new("intserv_version", "Version", FieldType::U8).optional(),
    FieldDescriptor::new("intserv_length", "Overall Length (words)", FieldType::U16).optional(),
    FieldDescriptor::new("service_number", "Service Number", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(s) => service_name(*s),
            _ => None,
        }),
    FieldDescriptor::new(
        "service_length",
        "Service Data Length (words)",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new("parameters", "Parameters", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&PARAMETER)),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static OBJECT: FieldDescriptor = FieldDescriptor::new("object", "Object", FieldType::Object)
    .with_children(&OBJECT_CHILDREN)
    .with_display_fn(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("class_num", FieldValue::U8(c)) => class_name(*c),
            _ => None,
        }),
        _ => None,
    });

/// Field descriptor indices into [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_FLAGS: usize = 1;
const FD_REFRESH_REDUCTION_CAPABLE: usize = 2;
const FD_MESSAGE_TYPE: usize = 3;
const FD_CHECKSUM: usize = 4;
const FD_SEND_TTL: usize = 5;
const FD_RESERVED: usize = 6;
const FD_LENGTH: usize = 7;
const FD_OBJECTS: usize = 8;
const FD_DATA: usize = 9;

/// Field descriptors for the RSVP dissector.
///
/// RFC 2205, Section 3.1.1 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1.1>;
/// RFC 2961, Section 2 — <https://www.rfc-editor.org/rfc/rfc2961#section-2>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Vers", FieldType::U8),
    FieldDescriptor::new("flags", "Flags", FieldType::U8),
    FieldDescriptor::new(
        "refresh_reduction_capable",
        "Refresh (overhead) reduction capable",
        FieldType::U8,
    ),
    FieldDescriptor::new("message_type", "Msg Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => message_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("checksum", "RSVP Checksum", FieldType::U16),
    FieldDescriptor::new("send_ttl", "Send_TTL", FieldType::U8),
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8),
    FieldDescriptor::new("length", "RSVP Length", FieldType::U16),
    FieldDescriptor::new("objects", "Objects", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&OBJECT)),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Specification references for the RSVP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 2205",
        "Resource ReSerVation Protocol (RSVP) -- Version 1 Functional Specification",
        "https://www.rfc-editor.org/rfc/rfc2205",
    ),
    SpecReference::new(
        "RFC 2210",
        "The Use of RSVP with IETF Integrated Services",
        "https://www.rfc-editor.org/rfc/rfc2210",
    ),
    SpecReference::new(
        "RFC 2961",
        "RSVP Refresh Overhead Reduction Extensions",
        "https://www.rfc-editor.org/rfc/rfc2961",
    ),
    SpecReference::new(
        "RFC 3209",
        "RSVP-TE: Extensions to RSVP for LSP Tunnels",
        "https://www.rfc-editor.org/rfc/rfc3209",
    ),
    SpecReference::new(
        "RFC 3473",
        "Generalized Multi-Protocol Label Switching (GMPLS) Signaling Resource ReserVation Protocol-Traffic Engineering (RSVP-TE) Extensions",
        "https://www.rfc-editor.org/rfc/rfc3473",
    ),
    SpecReference::new(
        "RFC 3477",
        "Signalling Unnumbered Links in Resource ReSerVation Protocol - Traffic Engineering (RSVP-TE)",
        "https://www.rfc-editor.org/rfc/rfc3477",
    ),
    SpecReference::new(
        "RFC 4090",
        "Fast Reroute Extensions to RSVP-TE for LSP Tunnels",
        "https://www.rfc-editor.org/rfc/rfc4090",
    ),
    SpecReference::new(
        "IANA RSVP Parameters",
        "Resource Reservation Protocol (RSVP) Parameters",
        "https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml",
    ),
];

fn u16_at(data: &[u8], pos: usize) -> u16 {
    read_be_u16(data, pos).unwrap_or_default()
}

fn u32_at(data: &[u8], pos: usize) -> u32 {
    read_be_u32(data, pos).unwrap_or_default()
}

/// Returns a 4- or 16-octet address as an IPv4 / IPv6 value.
fn address(bytes: &[u8]) -> FieldValue<'_> {
    if let Ok(a) = <[u8; 4]>::try_from(bytes) {
        FieldValue::Ipv4Addr(a)
    } else if let Ok(a) = <[u8; 16]>::try_from(bytes) {
        FieldValue::Ipv6Addr(a)
    } else {
        FieldValue::Bytes(bytes)
    }
}

/// Pushes `items`, each a `(descriptor index, from, to, value)` of an
/// object's contents starting at absolute offset `offset`.
fn push_items<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    items: &[(usize, usize, usize, FieldValue<'pkt>)],
) {
    for (fd, from, to, value) in items {
        buf.push_field(
            &OBJECT_CHILDREN[*fd],
            value.clone(),
            offset + from..offset + to,
        );
    }
}

/// Pushes `v` as the array `descriptor` of `size`-octet items, each pushed
/// by `push`, then any remainder as `value`.
fn push_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    v: &'pkt [u8],
    offset: usize,
    size: usize,
    mut push: impl FnMut(&mut DissectBuffer<'pkt>, &'pkt [u8], usize),
) {
    let end = v.len() - v.len() % size;
    if end > 0 {
        let array = buf.begin_container(descriptor, FieldValue::Array(0..0), offset..offset + end);
        for (i, item) in v[..end].chunks_exact(size).enumerate() {
            push(buf, item, offset + i * size);
        }
        buf.end_container(array);
    }
    if end < v.len() {
        buf.push_field(
            &OBJECT_CHILDREN[O_VALUE],
            FieldValue::Bytes(&v[end..]),
            offset + end..offset + v.len(),
        );
    }
}

/// Pushes the contents of an EXPLICIT_ROUTE (`explicit`) or RECORD_ROUTE
/// object: a series of subobjects, each with a Length that is the total
/// length of the subobject in bytes and "MUST always be a multiple of 4,
/// and at least 4" (RFC 3209, Section 4.4.1; Section 4.3.3 has the same
/// rule for EXPLICIT_ROUTE). Subobjects that do not fit are kept as
/// `value`.
///
/// RFC 3209, Sections 4.3.3 and 4.4.1 — <https://www.rfc-editor.org/rfc/rfc3209#section-4.3.3>,
/// <https://www.rfc-editor.org/rfc/rfc3209#section-4.4.1>
fn push_subobjects<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    v: &'pkt [u8],
    offset: usize,
    explicit: bool,
) {
    let mut end = 0;
    while end + 2 <= v.len() {
        let len = usize::from(v[end + 1]);
        if len < 4 || len % 4 != 0 || end + len > v.len() {
            break;
        }
        end += len;
    }
    if end > 0 {
        let c = &SUBOBJECT_CHILDREN;
        let array = buf.begin_container(
            &OBJECT_CHILDREN[O_SUBOBJECTS],
            FieldValue::Array(0..0),
            offset..offset + end,
        );
        let mut pos = 0;
        while pos < end {
            let len = usize::from(v[pos + 1]);
            let s = &v[pos..pos + len];
            let a = offset + pos;
            let r = |from: usize, to: usize| a + from..a + to;
            let obj = buf.begin_container(&SUBOBJECT, FieldValue::Object(0..0), a..a + len);
            // ERO: |L|    Type     |     Length    | (RFC 3209, Section 4.3.3)
            //   https://www.rfc-editor.org/rfc/rfc3209#section-4.3.3
            let t = if explicit {
                buf.push_field(&c[S_LOOSE], FieldValue::U8(s[0] >> 7), r(0, 1));
                s[0] & 0x7F
            } else {
                s[0]
            };
            buf.push_field(&c[S_TYPE], FieldValue::U8(t), r(0, 1));
            buf.push_field(&c[S_LENGTH], FieldValue::U8(s[1]), r(1, 2));
            match (t, len) {
                // IPv4 / IPv6 prefix: address, Prefix Length, then Reserved
                // (ERO) or Flags (RRO).
                (1, 8) | (2, 20) => {
                    let n = len - 4;
                    buf.push_field(&c[S_ADDRESS], address(&s[2..2 + n]), r(2, 2 + n));
                    buf.push_field(
                        &c[S_PREFIX_LENGTH],
                        FieldValue::U8(s[2 + n]),
                        r(2 + n, 3 + n),
                    );
                    if !explicit {
                        buf.push_field(&c[S_FLAGS], FieldValue::U8(s[3 + n]), r(3 + n, 4 + n));
                    }
                }
                // Label: |U| Reserved / Flags | C-Type | Contents of Label
                // Object (RFC 3473, Section 5.1; RFC 3209, Section 4.4.1.3).
                //   https://www.rfc-editor.org/rfc/rfc3473#section-5.1
                //   https://www.rfc-editor.org/rfc/rfc3209#section-4.4.1.3
                (3, 8) => {
                    buf.push_field(&c[S_FLAGS], FieldValue::U8(s[2]), r(2, 3));
                    buf.push_field(&c[S_C_TYPE], FieldValue::U8(s[3]), r(3, 4));
                    buf.push_field(&c[S_LABEL], FieldValue::U32(u32_at(s, 4)), r(4, 8));
                }
                // Unnumbered Interface ID: Reserved (ERO) or Flags and
                // Reserved (RRO), Router ID, Interface ID (RFC 3477,
                // Sections 4 and 5).
                //   https://www.rfc-editor.org/rfc/rfc3477#section-4
                (4, 12) => {
                    if !explicit {
                        buf.push_field(&c[S_FLAGS], FieldValue::U8(s[2]), r(2, 3));
                    }
                    buf.push_field(
                        &c[S_ROUTER_ID],
                        FieldValue::Ipv4Addr([s[4], s[5], s[6], s[7]]),
                        r(4, 8),
                    );
                    buf.push_field(&c[S_INTERFACE_ID], FieldValue::U32(u32_at(s, 8)), r(8, 12));
                }
                // Autonomous system number (RFC 3209, Section 4.3.3.4).
                //   https://www.rfc-editor.org/rfc/rfc3209#section-4.3.3.4
                (32, 4) if explicit => {
                    buf.push_field(&c[S_AS_NUMBER], FieldValue::U16(u16_at(s, 2)), r(2, 4));
                }
                _ => buf.push_field(&c[S_VALUE], FieldValue::Bytes(&s[2..]), r(2, len)),
            }
            buf.end_container(obj);
            pos += len;
        }
        buf.end_container(array);
    }
    if end < v.len() {
        buf.push_field(
            &OBJECT_CHILDREN[O_VALUE],
            FieldValue::Bytes(&v[end..]),
            offset + end..offset + v.len(),
        );
    }
}

/// Pushes the contents of an IntServ FLOWSPEC or SENDER_TSPEC object: the
/// message header, the service header and its parameters.
///
/// RFC 2210, Sections 3.1-3.3 — <https://www.rfc-editor.org/rfc/rfc2210#section-3.1>
fn push_intserv<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], offset: usize) {
    if v.len() < 8 {
        push_items(buf, offset, &[(O_VALUE, 0, v.len(), FieldValue::Bytes(v))]);
        return;
    }
    // | Vers  | Reserved | Overall length | Service | 0|Reserved | Length of service data |
    push_items(
        buf,
        offset,
        &[
            (O_INTSERV_VERSION, 0, 1, FieldValue::U8(v[0] >> 4)),
            (O_INTSERV_LENGTH, 2, 4, FieldValue::U16(u16_at(v, 2))),
            (O_SERVICE_NUMBER, 4, 5, FieldValue::U8(v[4])),
            (O_SERVICE_LENGTH, 6, 8, FieldValue::U16(u16_at(v, 6))),
        ],
    );
    let service_end = (8 + 4 * usize::from(u16_at(v, 6))).min(v.len());
    let mut end = 8;
    while end + 4 <= service_end {
        let next = end + 4 + 4 * usize::from(u16_at(v, end + 2));
        if next > service_end {
            break;
        }
        end = next;
    }
    if end > 8 {
        let c = &PARAMETER_CHILDREN;
        let array = buf.begin_container(
            &OBJECT_CHILDREN[O_PARAMETERS],
            FieldValue::Array(0..0),
            offset + 8..offset + end,
        );
        let mut pos = 8;
        while pos < end {
            let id = v[pos];
            let len = 4 * usize::from(u16_at(v, pos + 2));
            let p = &v[pos + 4..pos + 4 + len];
            let a = offset + pos;
            let r = |from: usize, to: usize| a + 4 + from..a + 4 + to;
            let obj = buf.begin_container(&PARAMETER, FieldValue::Object(0..0), a..a + 4 + len);
            buf.push_field(&c[P_ID], FieldValue::U8(id), a..a + 1);
            buf.push_field(&c[P_FLAGS], FieldValue::U8(v[pos + 1]), a + 1..a + 2);
            buf.push_field(
                &c[P_LENGTH],
                FieldValue::U16(u16_at(v, pos + 2)),
                a + 2..a + 4,
            );
            match (id, len) {
                // Token Bucket Rate [r], Token Bucket Size [b], Peak Data Rate
                // [p] (32-bit IEEE floating point numbers), Minimum Policed
                // Unit [m], Maximum Packet Size [M] (RFC 2210, Section 3.1).
                //   https://www.rfc-editor.org/rfc/rfc2210#section-3.1
                (PARAM_TOKEN_BUCKET, 20) => {
                    buf.push_field(
                        &c[P_TOKEN_BUCKET_RATE],
                        FieldValue::Bytes(&p[0..4]),
                        r(0, 4),
                    );
                    buf.push_field(
                        &c[P_TOKEN_BUCKET_SIZE],
                        FieldValue::Bytes(&p[4..8]),
                        r(4, 8),
                    );
                    buf.push_field(&c[P_PEAK_DATA_RATE], FieldValue::Bytes(&p[8..12]), r(8, 12));
                    buf.push_field(
                        &c[P_MIN_POLICED_UNIT],
                        FieldValue::U32(u32_at(p, 12)),
                        r(12, 16),
                    );
                    buf.push_field(
                        &c[P_MAX_PACKET_SIZE],
                        FieldValue::U32(u32_at(p, 16)),
                        r(16, 20),
                    );
                }
                // Rate [R] (32-bit IEEE floating point number), Slack Term [S]
                // (RFC 2210, Section 3.3).
                //   https://www.rfc-editor.org/rfc/rfc2210#section-3.3
                (PARAM_GUARANTEED_RSPEC, 8) => {
                    buf.push_field(&c[P_RATE], FieldValue::Bytes(&p[0..4]), r(0, 4));
                    buf.push_field(&c[P_SLACK_TERM], FieldValue::U32(u32_at(p, 4)), r(4, 8));
                }
                (_, 0) => {}
                _ => buf.push_field(&c[P_VALUE], FieldValue::Bytes(p), r(0, len)),
            }
            buf.end_container(obj);
            pos += 4 + len;
        }
        buf.end_container(array);
    }
    if end < v.len() {
        push_items(
            buf,
            offset,
            &[(O_VALUE, end, v.len(), FieldValue::Bytes(&v[end..]))],
        );
    }
}

/// Pushes the contents `v` of an object of class `class` and C-Type
/// `ctype`, starting at absolute offset `offset`. This is the table of
/// decoded objects: other (Class-Num, C-Type) pairs, or contents of an
/// unexpected length, keep their contents as `value`.
///
/// RFC 2205, Appendix A — <https://www.rfc-editor.org/rfc/rfc2205#appendix-A>;
/// RFC 3209, Sections 4.1-4.7 and 5.1 — <https://www.rfc-editor.org/rfc/rfc3209#section-4>;
/// RFC 2961, Sections 4.2, 4.3 and 5.1 — <https://www.rfc-editor.org/rfc/rfc2961#section-4.2>;
/// RFC 4090, Sections 4.1 and 4.2 — <https://www.rfc-editor.org/rfc/rfc4090#section-4.1>
fn push_object_value<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    class: u8,
    ctype: u8,
    v: &'pkt [u8],
    offset: usize,
) {
    let n = v.len();
    match (class, ctype, n) {
        // SESSION IPv4 / IPv6: DestAddress, Protocol Id, Flags, DstPort
        // (RFC 2205, Appendix A.1).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.1
        (CLASS_SESSION, 1, 8) | (CLASS_SESSION, 2, 20) => {
            let a = n - 4;
            push_items(
                buf,
                offset,
                &[
                    (O_ADDRESS, 0, a, address(&v[..a])),
                    (O_PROTOCOL_ID, a, a + 1, FieldValue::U8(v[a])),
                    (O_SESSION_FLAGS, a + 1, a + 2, FieldValue::U8(v[a + 1])),
                    (O_PORT, a + 2, a + 4, FieldValue::U16(u16_at(v, a + 2))),
                ],
            );
        }
        // LSP_TUNNEL_IPv4 / IPv6 SESSION: Tunnel end point address, MUST be
        // zero, Tunnel ID, Extended Tunnel ID (RFC 3209, Sections 4.6.1.1
        // and 4.6.1.2).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-4.6.1.1
        (CLASS_SESSION, 7, 12) | (CLASS_SESSION, 8, 36) => {
            let a = if ctype == 7 { 4 } else { 16 };
            push_items(
                buf,
                offset,
                &[
                    (O_ADDRESS, 0, a, address(&v[..a])),
                    (O_TUNNEL_ID, a + 2, a + 4, FieldValue::U16(u16_at(v, a + 2))),
                    (O_EXTENDED_TUNNEL_ID, a + 4, n, address(&v[a + 4..])),
                ],
            );
        }
        // RSVP_HOP IPv4 / IPv6: Next/Previous Hop Address, Logical Interface
        // Handle (RFC 2205, Appendix A.2).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.2
        (CLASS_RSVP_HOP, 1, 8) | (CLASS_RSVP_HOP, 2, 20) => {
            let a = n - 4;
            push_items(
                buf,
                offset,
                &[
                    (O_ADDRESS, 0, a, address(&v[..a])),
                    (O_LIH, a, n, FieldValue::U32(u32_at(v, a))),
                ],
            );
        }
        // TIME_VALUES: Refresh Period R (RFC 2205, Appendix A.4).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.4
        (CLASS_TIME_VALUES, 1, 4) => {
            push_items(
                buf,
                offset,
                &[(O_REFRESH_PERIOD, 0, 4, FieldValue::U32(u32_at(v, 0)))],
            );
        }
        // ERROR_SPEC IPv4 / IPv6: Error Node Address, Flags, Error Code, Error
        // Value (RFC 2205, Appendix A.5).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.5
        (CLASS_ERROR_SPEC, 1, 8) | (CLASS_ERROR_SPEC, 2, 20) => {
            let a = n - 4;
            push_items(
                buf,
                offset,
                &[
                    (O_ADDRESS, 0, a, address(&v[..a])),
                    (O_ERROR_FLAGS, a, a + 1, FieldValue::U8(v[a])),
                    (O_ERROR_CODE, a + 1, a + 2, FieldValue::U8(v[a + 1])),
                    (
                        O_ERROR_VALUE,
                        a + 2,
                        a + 4,
                        FieldValue::U16(u16_at(v, a + 2)),
                    ),
                ],
            );
        }
        // SCOPE List IPv4 / IPv6 (RFC 2205, Appendix A.6).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.6
        (CLASS_SCOPE, 1 | 2, _) => {
            let size = if ctype == 1 { 4 } else { 16 };
            push_list(
                buf,
                &OBJECT_CHILDREN[O_ADDRESSES],
                v,
                offset,
                size,
                |buf, item, at| {
                    buf.push_field(&ADDRESS_ELEMENT, address(item), at..at + item.len());
                },
            );
        }
        // STYLE: Flags, Option Vector (RFC 2205, Appendix A.7).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.7
        (CLASS_STYLE, 1, 4) => {
            push_items(
                buf,
                offset,
                &[(
                    O_OPTION_VECTOR,
                    1,
                    4,
                    FieldValue::U32(u32_at(v, 0) & 0x00FF_FFFF),
                )],
            );
        }
        // Int-serv FLOWSPEC / SENDER_TSPEC (RFC 2210, Section 3).
        //   https://www.rfc-editor.org/rfc/rfc2210#section-3
        (CLASS_FLOWSPEC, 2, _) | (CLASS_SENDER_TSPEC, 2, _) => push_intserv(buf, v, offset),
        // FILTER_SPEC / SENDER_TEMPLATE IPv4 / IPv6: SrcAddress, SrcPort
        // (RFC 2205, Appendices A.9 and A.10).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.9
        (CLASS_FILTER_SPEC | CLASS_SENDER_TEMPLATE, 1, 8)
        | (CLASS_FILTER_SPEC | CLASS_SENDER_TEMPLATE, 2, 20) => {
            let a = n - 4;
            push_items(
                buf,
                offset,
                &[
                    (O_ADDRESS, 0, a, address(&v[..a])),
                    (O_PORT, a + 2, a + 4, FieldValue::U16(u16_at(v, a + 2))),
                ],
            );
        }
        // LSP_TUNNEL_IPv4 / IPv6 SENDER_TEMPLATE and FILTER_SPEC: sender
        // address, MUST be zero, LSP ID (RFC 3209, Sections 4.6.2 and 4.6.3).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-4.6.2
        (CLASS_FILTER_SPEC | CLASS_SENDER_TEMPLATE, 7, 8)
        | (CLASS_FILTER_SPEC | CLASS_SENDER_TEMPLATE, 8, 20) => {
            let a = n - 4;
            push_items(
                buf,
                offset,
                &[
                    (O_ADDRESS, 0, a, address(&v[..a])),
                    (O_LSP_ID, a + 2, a + 4, FieldValue::U16(u16_at(v, a + 2))),
                ],
            );
        }
        // RESV_CONFIRM IPv4 / IPv6: Receiver Address (RFC 2205, Appendix
        // A.14).
        //   https://www.rfc-editor.org/rfc/rfc2205#appendix-A.14
        (CLASS_RESV_CONFIRM, 1, 4) | (CLASS_RESV_CONFIRM, 2, 16) => {
            push_items(buf, offset, &[(O_ADDRESS, 0, n, address(v))]);
        }
        // LABEL (RFC 3209, Section 4.1.1).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-4.1.1
        (CLASS_LABEL, 1, 4) => push_items(
            buf,
            offset,
            &[(O_LABEL, 0, 4, FieldValue::U32(u32_at(v, 0)))],
        ),
        // LABEL_REQUEST without label range: Reserved, L3PID (RFC 3209,
        // Section 4.2.1).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-4.2.1
        (CLASS_LABEL_REQUEST, 1, 4) => {
            push_items(
                buf,
                offset,
                &[(O_L3PID, 2, 4, FieldValue::U16(u16_at(v, 2)))],
            );
        }
        (CLASS_EXPLICIT_ROUTE, 1, _) => push_subobjects(buf, v, offset, true),
        (CLASS_RECORD_ROUTE, 1, _) => push_subobjects(buf, v, offset, false),
        // HELLO REQUEST / ACK: Src_Instance, Dst_Instance (RFC 3209, Section
        // 5.1).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-5.1
        (CLASS_HELLO, 1 | 2, 8) => {
            push_items(
                buf,
                offset,
                &[
                    (O_SOURCE_INSTANCE, 0, 4, FieldValue::U32(u32_at(v, 0))),
                    (O_DESTINATION_INSTANCE, 4, 8, FieldValue::U32(u32_at(v, 4))),
                ],
            );
        }
        // MESSAGE_ID, MESSAGE_ID_ACK / NACK: Flags, Epoch, Message_Identifier
        // (RFC 2961, Sections 4.2 and 4.3).
        //   https://www.rfc-editor.org/rfc/rfc2961#section-4.2
        (CLASS_MESSAGE_ID, 1, 8) | (CLASS_MESSAGE_ID_ACK, 1 | 2, 8) => {
            push_items(
                buf,
                offset,
                &[
                    (O_MESSAGE_FLAGS, 0, 1, FieldValue::U8(v[0])),
                    (O_EPOCH, 1, 4, FieldValue::U32(u32_at(v, 0) & 0x00FF_FFFF)),
                    (O_MESSAGE_ID, 4, 8, FieldValue::U32(u32_at(v, 4))),
                ],
            );
        }
        // MESSAGE_ID LIST: Flags, Epoch, Message_Identifiers (RFC 2961,
        // Section 5.1).
        //   https://www.rfc-editor.org/rfc/rfc2961#section-5.1
        (CLASS_MESSAGE_ID_LIST, 1, _) if n >= 4 => {
            push_items(
                buf,
                offset,
                &[
                    (O_MESSAGE_FLAGS, 0, 1, FieldValue::U8(v[0])),
                    (O_EPOCH, 1, 4, FieldValue::U32(u32_at(v, 0) & 0x00FF_FFFF)),
                ],
            );
            push_list(
                buf,
                &OBJECT_CHILDREN[O_MESSAGE_IDS],
                &v[4..],
                offset + 4,
                4,
                |buf, item, at| {
                    buf.push_field(
                        &MESSAGE_ID_ELEMENT,
                        FieldValue::U32(u32_at(item, 0)),
                        at..at + 4,
                    );
                },
            );
        }
        // DETOUR IPv4 / IPv6: (PLR_ID, Avoid_Node_ID) pairs (RFC 4090,
        // Sections 4.2.1 and 4.2.2).
        //   https://www.rfc-editor.org/rfc/rfc4090#section-4.2.1
        (CLASS_DETOUR, 7 | 8, _) => {
            let size = if ctype == 7 { 4 } else { 16 };
            push_list(
                buf,
                &OBJECT_CHILDREN[O_DETOURS],
                v,
                offset,
                2 * size,
                |buf, item, at| {
                    let obj = buf.begin_container(
                        &DETOUR_ELEMENT,
                        FieldValue::Object(0..0),
                        at..at + 2 * size,
                    );
                    buf.push_field(&DETOUR_CHILDREN[0], address(&item[..size]), at..at + size);
                    buf.push_field(
                        &DETOUR_CHILDREN[1],
                        address(&item[size..]),
                        at + size..at + 2 * size,
                    );
                    buf.end_container(obj);
                },
            );
        }
        // FAST_REROUTE: Setup Prio, Hold Prio, Hop-limit, Flags (C-Type 1) or
        // Reserved (C-Type 7), Bandwidth, Include-any, Exclude-any and, for
        // C-Type 1, Include-all (RFC 4090, Section 4.1).
        //   https://www.rfc-editor.org/rfc/rfc4090#section-4.1
        (CLASS_FAST_REROUTE, 1, 20) | (CLASS_FAST_REROUTE, 7, 16) => {
            push_items(
                buf,
                offset,
                &[
                    (O_SETUP_PRIORITY, 0, 1, FieldValue::U8(v[0])),
                    (O_HOLDING_PRIORITY, 1, 2, FieldValue::U8(v[1])),
                    (O_HOP_LIMIT, 2, 3, FieldValue::U8(v[2])),
                ],
            );
            if ctype == 1 {
                push_items(buf, offset, &[(O_FRR_FLAGS, 3, 4, FieldValue::U8(v[3]))]);
            }
            push_items(
                buf,
                offset,
                &[
                    (O_BANDWIDTH, 4, 8, FieldValue::Bytes(&v[4..8])),
                    (O_INCLUDE_ANY, 8, 12, FieldValue::U32(u32_at(v, 8))),
                    (O_EXCLUDE_ANY, 12, 16, FieldValue::U32(u32_at(v, 12))),
                ],
            );
            if ctype == 1 {
                push_items(
                    buf,
                    offset,
                    &[(O_INCLUDE_ALL, 16, 20, FieldValue::U32(u32_at(v, 16)))],
                );
            }
        }
        // SESSION_ATTRIBUTE (LSP_TUNNEL_RA, C-Type 1): Exclude-any,
        // Include-any, Include-all, then as C-Type 7 (RFC 3209, Section
        // 4.7.2).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-4.7.2
        (CLASS_SESSION_ATTRIBUTE, 1, _) if n >= 16 => {
            push_items(
                buf,
                offset,
                &[
                    (O_EXCLUDE_ANY, 0, 4, FieldValue::U32(u32_at(v, 0))),
                    (O_INCLUDE_ANY, 4, 8, FieldValue::U32(u32_at(v, 4))),
                    (O_INCLUDE_ALL, 8, 12, FieldValue::U32(u32_at(v, 8))),
                ],
            );
            push_session_attribute(buf, &v[12..], offset + 12);
        }
        // SESSION_ATTRIBUTE (LSP_TUNNEL, C-Type 7): Setup Prio, Holding Prio,
        // Flags, Name Length, Session Name (RFC 3209, Section 4.7.1).
        //   https://www.rfc-editor.org/rfc/rfc3209#section-4.7.1
        (CLASS_SESSION_ATTRIBUTE, 7, _) if n >= 4 => push_session_attribute(buf, v, offset),
        (_, _, 0) => {}
        _ => push_items(buf, offset, &[(O_VALUE, 0, n, FieldValue::Bytes(v))]),
    }
}

/// Pushes the Setup Prio, Holding Prio, Flags, Name Length and Session
/// Name of a SESSION_ATTRIBUTE object. The name is padded to a four-octet
/// boundary; the padding is not shown.
///
/// RFC 3209, Section 4.7 — <https://www.rfc-editor.org/rfc/rfc3209#section-4.7>
fn push_session_attribute<'pkt>(buf: &mut DissectBuffer<'pkt>, v: &'pkt [u8], offset: usize) {
    let name_end = (4 + usize::from(v[3])).min(v.len());
    push_items(
        buf,
        offset,
        &[
            (O_SETUP_PRIORITY, 0, 1, FieldValue::U8(v[0])),
            (O_HOLDING_PRIORITY, 1, 2, FieldValue::U8(v[1])),
            (O_SESSION_ATTRIBUTE_FLAGS, 2, 3, FieldValue::U8(v[2])),
            (O_NAME_LENGTH, 3, 4, FieldValue::U8(v[3])),
            (
                O_SESSION_NAME,
                4,
                name_end,
                FieldValue::Bytes(&v[4..name_end]),
            ),
        ],
    );
}

/// Returns the end of the objects that fit completely in
/// `data[HEADER_SIZE..end]`. The object Length is "A 16-bit field
/// containing the total object length in bytes.  Must always be a multiple
/// of 4, and at least 4."
///
/// RFC 2205, Section 3.1.2 — <https://www.rfc-editor.org/rfc/rfc2205#section-3.1.2>
fn complete_objects_end(data: &[u8], end: usize) -> usize {
    let mut pos = HEADER_SIZE;
    while pos + OBJECT_HEADER_SIZE <= end {
        let len = usize::from(u16_at(data, pos));
        if len < OBJECT_HEADER_SIZE || len % 4 != 0 || pos + len > end {
            break;
        }
        pos += len;
    }
    pos
}

/// Records the sub-messages of a Bundle message in `data[HEADER_SIZE..end]`
/// as embedded payloads, each dissected as its own RSVP message, and
/// returns the end of the complete sub-messages. A sub-message is a
/// complete RSVP message: a common header whose RSVP Length covers it.
///
/// RFC 2961, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc2961#section-3.2>
fn bundle_sub_messages(
    buf: &mut DissectBuffer<'_>,
    data: &[u8],
    end: usize,
    offset: usize,
) -> usize {
    let mut pos = HEADER_SIZE;
    while pos + HEADER_SIZE <= end {
        let len = usize::from(u16_at(data, pos + 6));
        if len < HEADER_SIZE || pos + len > end {
            break;
        }
        buf.push_embedded_payload(
            offset + pos..offset + pos + len,
            DispatchHint::ByIpProtocol(46),
        );
        pos += len;
    }
    pos
}

/// RSVP dissector.
///
/// Decodes the common header and the object list of one RSVP message. The
/// message ends at its RSVP Length; objects that are malformed (a length
/// that is not a multiple of 4, below 4, or past the end of the message)
/// end the object list, and the rest of the message is kept as `data`. The
/// sub-messages of a Bundle message (RFC 2961, Section 3 —
/// <https://www.rfc-editor.org/rfc/rfc2961#section-3>) are recorded as
/// embedded payloads, so the registry dissects each one as an RSVP
/// message.
pub struct RsvpDissector;

impl Dissector for RsvpDissector {
    fn name(&self) -> &'static str {
        "Resource ReSerVation Protocol"
    }

    fn short_name(&self) -> &'static str {
        "RSVP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Network)
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
        // RFC 2205, Section 3.1.1 — Common Header
        //   https://www.rfc-editor.org/rfc/rfc2205#section-3.1.1
        let version = data[0] >> 4;
        if version != VERSION_1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        let length = u16_at(data, 6);
        let total = usize::from(length);
        if total < HEADER_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "length",
                value: u32::from(length),
            });
        }
        if data.len() < total {
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }
        let flags = data[0] & 0x0F;
        let msg_type = data[1];

        let d = FIELD_DESCRIPTORS;
        buf.begin_layer(self.short_name(), None, d, offset..offset + total);
        buf.push_field(&d[FD_VERSION], FieldValue::U8(version), offset..offset + 1);
        buf.push_field(&d[FD_FLAGS], FieldValue::U8(flags), offset..offset + 1);
        // "0x01: Refresh (overhead) reduction capable" (RFC 2961, Section 2 —
        // https://www.rfc-editor.org/rfc/rfc2961#section-2)
        buf.push_field(
            &d[FD_REFRESH_REDUCTION_CAPABLE],
            FieldValue::U8(flags & 0x01),
            offset..offset + 1,
        );
        buf.push_field(
            &d[FD_MESSAGE_TYPE],
            FieldValue::U8(msg_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &d[FD_CHECKSUM],
            FieldValue::U16(u16_at(data, 2)),
            offset + 2..offset + 4,
        );
        buf.push_field(
            &d[FD_SEND_TTL],
            FieldValue::U8(data[4]),
            offset + 4..offset + 5,
        );
        buf.push_field(
            &d[FD_RESERVED],
            FieldValue::U8(data[5]),
            offset + 5..offset + 6,
        );
        buf.push_field(
            &d[FD_LENGTH],
            FieldValue::U16(length),
            offset + 6..offset + 8,
        );

        // A Bundle message carries sub-messages rather than objects: "An
        // RSVP Bundle message must contain at least one sub-message." (RFC
        // 2961, Section 3.2 — https://www.rfc-editor.org/rfc/rfc2961#section-3.2)
        let bundle = msg_type == MSG_BUNDLE;
        let objects_end = if bundle {
            bundle_sub_messages(buf, data, total, offset)
        } else {
            complete_objects_end(data, total)
        };
        if !bundle && objects_end > HEADER_SIZE {
            let array = buf.begin_container(
                &d[FD_OBJECTS],
                FieldValue::Array(0..0),
                offset + HEADER_SIZE..offset + objects_end,
            );
            let c = &OBJECT_CHILDREN;
            let mut pos = HEADER_SIZE;
            while pos < objects_end {
                let len = usize::from(u16_at(data, pos));
                let class = data[pos + 2];
                let ctype = data[pos + 3];
                let a = offset + pos;
                let obj = buf.begin_container(&OBJECT, FieldValue::Object(0..0), a..a + len);
                buf.push_field(&c[O_LENGTH], FieldValue::U16(len as u16), a..a + 2);
                buf.push_field(&c[O_CLASS_NUM], FieldValue::U8(class), a + 2..a + 3);
                buf.push_field(&c[O_C_TYPE], FieldValue::U8(ctype), a + 3..a + 4);
                push_object_value(
                    buf,
                    class,
                    ctype,
                    &data[pos + OBJECT_HEADER_SIZE..pos + len],
                    a + OBJECT_HEADER_SIZE,
                );
                buf.end_container(obj);
                pos += len;
            }
            buf.end_container(array);
        }
        if objects_end < total {
            buf.push_field(
                &d[FD_DATA],
                FieldValue::Bytes(&data[objects_end..total]),
                offset + objects_end..offset + total,
            );
        }
        buf.end_layer();
        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 2205 (RSVP) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 3.1.1 | Common header | `parse_path_lsp_tunnel_ipv4` |
    //! | 3.1.1 | Version other than 1 rejected | `reject_unsupported_version` |
    //! | 3.1.1 | RSVP Length below the header size rejected | `reject_short_length` |
    //! | 3.1.1 | Message longer than the data is Truncated | `truncated_message`, `truncated_header` |
    //! | 3.1.1 | Octets after RSVP Length are not consumed | `consumes_rsvp_length` |
    //! | 3.1.2 | Object length not a multiple of 4, below 4, or past the message: rest kept as data | `malformed_object_lengths` |
    //! | 3.1.2 | Unknown object class kept as value; empty NULL object | `unknown_object_kept_as_value` |
    //! | A.1, A.2, A.4, A.9 | IPv4/UDP SESSION, RSVP_HOP, TIME_VALUES, FILTER_SPEC | `parse_resv_ipv4_udp` |
    //! | A.1, A.2, A.5, A.9, A.14 | IPv6 SESSION, RSVP_HOP, ERROR_SPEC, FILTER_SPEC, RESV_CONFIRM | `parse_ipv6_objects` |
    //! | A.5 | IPv4 ERROR_SPEC (PathErr) | `parse_patherr` |
    //! | A.6 | SCOPE list | `parse_resv_ipv4_udp` |
    //! | A.7 | STYLE (SE) | `parse_resv_label_rro` |
    //! | A.8, A.11 | Int-serv FLOWSPEC and SENDER_TSPEC | `parse_resv_label_rro`, `parse_path_lsp_tunnel_ipv4` |
    //!
    //! # RFC 2210 (IntServ) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 3.1 | Token bucket Tspec | `parse_path_lsp_tunnel_ipv4` |
    //! | 3.2 | Controlled-Load Flowspec | `parse_resv_label_rro` |
    //! | 3.3 | Guaranteed Flowspec (RSpec) | `parse_guaranteed_flowspec` |
    //!
    //! # RFC 3209 (RSVP-TE) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.1.1 | LABEL | `parse_resv_label_rro` |
    //! | 4.2.1 | LABEL_REQUEST without label range | `parse_path_lsp_tunnel_ipv4` |
    //! | 4.3.3 | EXPLICIT_ROUTE: strict / loose IPv4, AS, unknown subobject | `parse_path_lsp_tunnel_ipv4` |
    //! | 4.3.3, 4.4.1 | Subobject overrunning the object, or with a Length below 4 / not a multiple of 4 | `malformed_subobjects` |
    //! | 4.4.1 | RECORD_ROUTE: IPv4 with flags, Label, IPv6 | `parse_resv_label_rro` |
    //! | 4.6.1, 4.6.2, 4.6.3 | LSP_TUNNEL_IPv4 SESSION, SENDER_TEMPLATE and FILTER_SPEC | `parse_path_lsp_tunnel_ipv4`, `parse_resv_label_rro` |
    //! | 4.6.1.2, 4.6.2.2 | LSP_TUNNEL_IPv6 SESSION and SENDER_TEMPLATE | `parse_lsp_tunnel_ipv6` |
    //! | 4.7.1 | SESSION_ATTRIBUTE (LSP_TUNNEL) | `parse_path_lsp_tunnel_ipv4` |
    //! | 4.7.2 | SESSION_ATTRIBUTE (LSP_TUNNEL_RA) | `parse_session_attribute_ra` |
    //! | 5.1 | Hello REQUEST / ACK | `parse_hello` |
    //!
    //! # RFC 3477 (Unnumbered links) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4, 5 | Unnumbered Interface ID subobject in ERO and RRO | `parse_path_lsp_tunnel_ipv4`, `parse_resv_label_rro` |
    //!
    //! # RFC 4090 (Fast Reroute) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 4.1 | FAST_REROUTE C-Type 1 and legacy C-Type 7 | `parse_fast_reroute_detour` |
    //! | 4.2 | DETOUR IPv4 and IPv6 | `parse_fast_reroute_detour` |
    //!
    //! # RFC 2961 (Refresh Reduction) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 2 | Refresh-reduction-capable flag | `parse_refresh_reduction` |
    //! | 3.2 | Bundle sub-messages dispatched as RSVP messages | `bundle_sub_messages_are_embedded_payloads` |
    //! | 4.2, 4.3 | MESSAGE_ID, MESSAGE_ID_ACK / NACK | `parse_refresh_reduction` |
    //! | 5.1 | MESSAGE_ID LIST (Srefresh) | `parse_refresh_reduction` |

    use super::*;
    use packet_dissector_core::field::Field;

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = RsvpDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    fn direct<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        start: u32,
        end: u32,
    ) -> Vec<&'a Field<'pkt>> {
        let mut out = Vec::new();
        let mut i = start;
        while i < end {
            let f = &buf.fields()[i as usize];
            out.push(f);
            i = match &f.value {
                FieldValue::Array(c) | FieldValue::Object(c) => c.end.max(i + 1),
                _ => i + 1,
            };
        }
        out
    }

    fn children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        field: &Field<'pkt>,
    ) -> Vec<&'a Field<'pkt>> {
        let (FieldValue::Array(r) | FieldValue::Object(r)) = &field.value else {
            panic!("{} is not a container", field.name());
        };
        direct(buf, r.start, r.end)
    }

    fn top<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Option<&'a Field<'pkt>> {
        let l = &buf.layers()[0];
        direct(buf, l.field_range.start, l.field_range.end)
            .into_iter()
            .find(|f| f.name() == name)
    }

    fn child<'a, 'pkt>(fields: &[&'a Field<'pkt>], name: &str) -> &'a Field<'pkt> {
        fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("child {name} missing"))
    }

    fn has(fields: &[&Field<'_>], name: &str) -> bool {
        fields.iter().any(|f| f.name() == name)
    }

    /// Display name of the child `name` of an object, resolved against its
    /// siblings.
    fn display(fields: &[&Field<'_>], name: &str) -> Option<&'static str> {
        let f = child(fields, name);
        let siblings: Vec<Field<'_>> = fields.iter().map(|f| (*f).clone()).collect();
        (f.descriptor.display_fn?)(&f.value, &siblings)
    }

    /// The objects of the message, each as its list of direct children.
    fn objects<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<Vec<&'a Field<'pkt>>> {
        children(buf, top(buf, "objects").expect("objects"))
            .into_iter()
            .map(|o| children(buf, o))
            .collect()
    }

    fn items<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        obj: &[&'a Field<'pkt>],
        name: &str,
    ) -> Vec<Vec<&'a Field<'pkt>>> {
        children(buf, child(obj, name))
            .into_iter()
            .map(|o| children(buf, o))
            .collect()
    }

    fn object(class: u8, ctype: u8, contents: &[u8]) -> Vec<u8> {
        let mut v = ((4 + contents.len()) as u16).to_be_bytes().to_vec();
        v.push(class);
        v.push(ctype);
        v.extend_from_slice(contents);
        v
    }

    fn message(msg_type: u8, flags: u8, objects: &[u8]) -> Vec<u8> {
        let mut v = vec![0x10 | flags, msg_type, 0xAB, 0xCD, 255, 0];
        v.extend_from_slice(&((8 + objects.len()) as u16).to_be_bytes());
        v.extend_from_slice(objects);
        v
    }

    /// Int-serv token bucket Tspec (service 1) or Controlled-Load Flowspec
    /// (service 5) with r = b = p = 1.0 (0x3F800000), m = 20, M = 1500.
    fn intserv(service: u8) -> Vec<u8> {
        let mut v = vec![0x00, 0x00, 0, 7, service, 0, 0, 6, 127, 0, 0, 5];
        for _ in 0..3 {
            v.extend_from_slice(&[0x3F, 0x80, 0, 0]);
        }
        v.extend_from_slice(&20u32.to_be_bytes());
        v.extend_from_slice(&1500u32.to_be_bytes());
        v
    }

    fn lsp_session() -> Vec<u8> {
        object(CLASS_SESSION, 7, &[10, 0, 0, 9, 0, 0, 0, 1, 10, 0, 0, 1])
    }

    #[test]
    fn parse_path_lsp_tunnel_ipv4() {
        let mut o = lsp_session();
        o.extend(object(CLASS_RSVP_HOP, 1, &[10, 0, 0, 1, 0, 0, 0, 7]));
        o.extend(object(CLASS_TIME_VALUES, 1, &30000u32.to_be_bytes()));
        o.extend(object(CLASS_LABEL_REQUEST, 1, &[0, 0, 0x08, 0x00]));
        let mut ero = vec![0x01, 8, 10, 0, 0, 2, 32, 0]; // strict IPv4
        ero.extend_from_slice(&[0x81, 8, 10, 0, 0, 9, 32, 0]); // loose IPv4
        ero.extend_from_slice(&[0x20, 4, 0xFD, 0xE9]); // AS 65001
        ero.extend_from_slice(&[0x04, 12, 0, 0, 10, 0, 0, 3, 0, 0, 0, 5]); // unnumbered
        ero.extend_from_slice(&[0x40, 4, 1, 2]); // Path Key (not decoded)
        o.extend(object(CLASS_EXPLICIT_ROUTE, 1, &ero));
        o.extend(object(
            CLASS_SESSION_ATTRIBUTE,
            7,
            &[7, 7, 0x04, 4, b'l', b's', b'p', b'1'],
        ));
        o.extend(object(CLASS_SENDER_TEMPLATE, 7, &[10, 0, 0, 1, 0, 0, 0, 2]));
        o.extend(object(CLASS_SENDER_TSPEC, 2, &intserv(1)));
        let data = message(1, 0, &o);
        let (buf, result) = dissect(&data);

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        let l = &buf.layers()[0];
        assert_eq!(l.name, "RSVP");
        assert_eq!(l.range, 0..data.len());
        assert_eq!(top(&buf, "version").unwrap().value, FieldValue::U8(1));
        assert_eq!(
            top(&buf, "refresh_reduction_capable").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.resolve_display_name(l, "message_type_name"),
            Some("Path")
        );
        assert_eq!(
            top(&buf, "checksum").unwrap().value,
            FieldValue::U16(0xABCD)
        );
        assert_eq!(top(&buf, "send_ttl").unwrap().value, FieldValue::U8(255));
        assert_eq!(
            top(&buf, "length").unwrap().value,
            FieldValue::U16(data.len() as u16)
        );
        assert!(top(&buf, "data").is_none());

        let objs = objects(&buf);
        assert_eq!(objs.len(), 8);
        let s = &objs[0];
        assert_eq!(display(s, "class_num"), Some("SESSION"));
        assert_eq!(display(s, "c_type"), Some("LSP Tunnel IPv4"));
        assert_eq!(
            child(s, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 9])
        );
        assert_eq!(child(s, "tunnel_id").value, FieldValue::U16(1));
        assert_eq!(
            child(s, "extended_tunnel_id").value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(child(&objs[1], "lih").value, FieldValue::U32(7));
        assert_eq!(
            child(&objs[2], "refresh_period").value,
            FieldValue::U32(30000)
        );
        assert_eq!(child(&objs[3], "l3pid").value, FieldValue::U16(0x0800));

        let subs = items(&buf, &objs[4], "subobjects");
        assert_eq!(subs.len(), 5);
        assert_eq!(child(&subs[0], "loose").value, FieldValue::U8(0));
        assert_eq!(display(&subs[0], "type"), Some("IPv4 prefix"));
        assert_eq!(
            child(&subs[0], "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
        assert_eq!(child(&subs[0], "prefix_length").value, FieldValue::U8(32));
        assert!(!has(&subs[0], "flags"));
        assert_eq!(child(&subs[1], "loose").value, FieldValue::U8(1));
        assert_eq!(child(&subs[2], "as_number").value, FieldValue::U16(65001));
        assert_eq!(display(&subs[2], "type"), Some("Autonomous system number"));
        assert_eq!(
            child(&subs[3], "router_id").value,
            FieldValue::Ipv4Addr([10, 0, 0, 3])
        );
        assert_eq!(child(&subs[3], "interface_id").value, FieldValue::U32(5));
        assert_eq!(
            display(&subs[4], "type"),
            Some("Path Key with 32-bit PCE ID")
        );
        assert_eq!(child(&subs[4], "value").value, FieldValue::Bytes(&[1, 2]));

        let sa = &objs[5];
        assert_eq!(child(sa, "setup_priority").value, FieldValue::U8(7));
        assert_eq!(child(sa, "holding_priority").value, FieldValue::U8(7));
        assert_eq!(
            child(sa, "session_attribute_flags").value,
            FieldValue::U8(0x04)
        );
        assert_eq!(child(sa, "session_name").value, FieldValue::Bytes(b"lsp1"));
        assert_eq!(child(&objs[6], "lsp_id").value, FieldValue::U16(2));
        let tspec = &objs[7];
        assert_eq!(child(tspec, "intserv_length").value, FieldValue::U16(7));
        assert_eq!(
            display(tspec, "service_number"),
            Some("Default/Global Information")
        );
        let params = items(&buf, tspec, "parameters");
        assert_eq!(display(&params[0], "id"), Some("Token Bucket Tspec"));
        assert_eq!(
            child(&params[0], "token_bucket_rate").value,
            FieldValue::Bytes(&[0x3F, 0x80, 0, 0])
        );
        assert_eq!(
            child(&params[0], "min_policed_unit").value,
            FieldValue::U32(20)
        );
        assert_eq!(
            child(&params[0], "max_packet_size").value,
            FieldValue::U32(1500)
        );
    }

    #[test]
    fn parse_resv_label_rro() {
        let mut o = lsp_session();
        o.extend(object(CLASS_RSVP_HOP, 1, &[10, 0, 0, 2, 0, 0, 0, 0]));
        o.extend(object(CLASS_TIME_VALUES, 1, &30000u32.to_be_bytes()));
        o.extend(object(CLASS_STYLE, 1, &[0, 0, 0, 0x12]));
        o.extend(object(CLASS_FLOWSPEC, 2, &intserv(5)));
        o.extend(object(CLASS_FILTER_SPEC, 7, &[10, 0, 0, 1, 0, 0, 0, 2]));
        o.extend(object(CLASS_LABEL, 1, &16u32.to_be_bytes()));
        let mut rro = vec![0x01, 8, 10, 0, 0, 2, 32, 0x09]; // IPv4, flags
        rro.extend_from_slice(&[0x03, 8, 0x01, 1, 0, 0, 0, 16]); // Label, global
        rro.extend_from_slice(&[0x04, 12, 0x01, 0, 10, 0, 0, 3, 0, 0, 0, 5]); // unnumbered
        let mut v6 = vec![0x02, 20];
        v6.extend_from_slice(&[0x20; 16]);
        v6.extend_from_slice(&[128, 0]);
        rro.extend_from_slice(&v6);
        o.extend(object(CLASS_RECORD_ROUTE, 1, &rro));
        let data = message(2, 0, &o);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("Resv")
        );
        let objs = objects(&buf);
        assert_eq!(
            child(&objs[3], "option_vector").value,
            FieldValue::U32(0x12)
        );
        assert_eq!(
            display(&objs[3], "option_vector"),
            Some("Shared-Explicit (SE)")
        );
        assert_eq!(display(&objs[4], "service_number"), Some("Controlled Load"));
        assert_eq!(display(&objs[5], "class_num"), Some("FILTER_SPEC"));
        assert_eq!(child(&objs[6], "label").value, FieldValue::U32(16));
        let subs = items(&buf, &objs[7], "subobjects");
        assert_eq!(subs.len(), 4);
        assert!(!has(&subs[0], "loose"));
        assert_eq!(display(&subs[0], "type"), Some("IPv4 address"));
        assert_eq!(child(&subs[0], "flags").value, FieldValue::U8(0x09));
        assert_eq!(display(&subs[1], "type"), Some("Label"));
        assert_eq!(child(&subs[1], "flags").value, FieldValue::U8(1));
        assert_eq!(child(&subs[1], "c_type").value, FieldValue::U8(1));
        assert_eq!(child(&subs[1], "label").value, FieldValue::U32(16));
        assert_eq!(child(&subs[2], "flags").value, FieldValue::U8(1));
        assert_eq!(
            child(&subs[3], "address").value,
            FieldValue::Ipv6Addr([0x20; 16])
        );
        assert_eq!(child(&subs[3], "prefix_length").value, FieldValue::U8(128));
    }

    #[test]
    fn parse_resv_ipv4_udp() {
        let mut o = object(CLASS_SESSION, 1, &[224, 1, 1, 1, 17, 0x01, 0x13, 0x88]);
        o.extend(object(CLASS_RSVP_HOP, 1, &[10, 0, 0, 2, 0, 0, 0, 1]));
        o.extend(object(CLASS_SCOPE, 1, &[10, 0, 0, 1, 10, 0, 0, 3]));
        o.extend(object(CLASS_STYLE, 1, &[0, 0, 0, 0x11]));
        o.extend(object(
            CLASS_FILTER_SPEC,
            1,
            &[10, 0, 0, 1, 0, 0, 0x13, 0x89],
        ));
        let data = message(2, 0, &o);
        let (buf, _) = dissect(&data);
        let objs = objects(&buf);
        assert_eq!(display(&objs[0], "c_type"), Some("IPv4"));
        assert_eq!(
            child(&objs[0], "address").value,
            FieldValue::Ipv4Addr([224, 1, 1, 1])
        );
        assert_eq!(child(&objs[0], "protocol_id").value, FieldValue::U8(17));
        assert_eq!(child(&objs[0], "session_flags").value, FieldValue::U8(1));
        assert_eq!(child(&objs[0], "port").value, FieldValue::U16(5000));
        let scope = children(&buf, child(&objs[2], "addresses"));
        assert_eq!(scope[1].value, FieldValue::Ipv4Addr([10, 0, 0, 3]));
        assert_eq!(
            display(&objs[3], "option_vector"),
            Some("Wildcard-Filter (WF)")
        );
        assert_eq!(child(&objs[4], "port").value, FieldValue::U16(5001));
    }

    #[test]
    fn parse_ipv6_objects() {
        let a6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut session = a6.to_vec();
        session.extend_from_slice(&[17, 0, 0, 80]);
        let mut o = object(CLASS_SESSION, 2, &session);
        let mut hop = a6.to_vec();
        hop.extend_from_slice(&[0, 0, 0, 3]);
        o.extend(object(CLASS_RSVP_HOP, 2, &hop));
        let mut err = a6.to_vec();
        err.extend_from_slice(&[0x01, 2, 0, 5]);
        o.extend(object(CLASS_ERROR_SPEC, 2, &err));
        let mut filter = a6.to_vec();
        filter.extend_from_slice(&[0, 0, 0, 81]);
        o.extend(object(CLASS_FILTER_SPEC, 2, &filter));
        o.extend(object(CLASS_RESV_CONFIRM, 2, &a6));
        o.extend(object(CLASS_RESV_CONFIRM, 1, &[10, 0, 0, 5]));
        o.extend(object(CLASS_SCOPE, 2, &a6));
        let data = message(4, 0, &o);
        let (buf, _) = dissect(&data);
        let objs = objects(&buf);
        assert_eq!(child(&objs[0], "address").value, FieldValue::Ipv6Addr(a6));
        assert_eq!(child(&objs[0], "port").value, FieldValue::U16(80));
        assert_eq!(child(&objs[1], "lih").value, FieldValue::U32(3));
        assert_eq!(child(&objs[2], "error_code").value, FieldValue::U8(2));
        assert_eq!(
            display(&objs[2], "error_code"),
            Some("Policy Control Failure")
        );
        assert_eq!(child(&objs[3], "port").value, FieldValue::U16(81));
        assert_eq!(child(&objs[4], "address").value, FieldValue::Ipv6Addr(a6));
        assert_eq!(
            child(&objs[5], "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 5])
        );
        assert_eq!(children(&buf, child(&objs[6], "addresses")).len(), 1);
    }

    #[test]
    fn parse_patherr() {
        let mut o = lsp_session();
        o.extend(object(CLASS_ERROR_SPEC, 1, &[10, 0, 0, 2, 0x00, 24, 0, 5]));
        let data = message(3, 0, &o);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("PathErr")
        );
        let e = &objects(&buf)[1];
        assert_eq!(
            child(e, "address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
        assert_eq!(child(e, "error_flags").value, FieldValue::U8(0));
        assert_eq!(display(e, "error_code"), Some("Routing Problem"));
        assert_eq!(child(e, "error_value").value, FieldValue::U16(5));
    }

    #[test]
    fn parse_lsp_tunnel_ipv6() {
        let end = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let ext = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut session = end.to_vec();
        session.extend_from_slice(&[0, 0, 0, 3]);
        session.extend_from_slice(&ext);
        let mut o = object(CLASS_SESSION, 8, &session);
        let mut sender = ext.to_vec();
        sender.extend_from_slice(&[0, 0, 0, 4]);
        o.extend(object(CLASS_SENDER_TEMPLATE, 8, &sender));
        let data = message(1, 0, &o);
        let (buf, _) = dissect(&data);
        let objs = objects(&buf);
        assert_eq!(child(&objs[0], "address").value, FieldValue::Ipv6Addr(end));
        assert_eq!(child(&objs[0], "tunnel_id").value, FieldValue::U16(3));
        assert_eq!(
            child(&objs[0], "extended_tunnel_id").value,
            FieldValue::Ipv6Addr(ext)
        );
        assert_eq!(child(&objs[1], "address").value, FieldValue::Ipv6Addr(ext));
        assert_eq!(child(&objs[1], "lsp_id").value, FieldValue::U16(4));
    }

    #[test]
    fn parse_session_attribute_ra() {
        let mut ra = vec![0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4];
        ra.extend_from_slice(&[3, 3, 0x02, 6, b't', b'u', b'n', b'n', b'e', b'l', 0, 0]);
        let data = message(1, 0, &object(CLASS_SESSION_ATTRIBUTE, 1, &ra));
        let (buf, _) = dissect(&data);
        let sa = &objects(&buf)[0];
        assert_eq!(child(sa, "exclude_any").value, FieldValue::U32(1));
        assert_eq!(child(sa, "include_any").value, FieldValue::U32(2));
        assert_eq!(child(sa, "include_all").value, FieldValue::U32(4));
        assert_eq!(child(sa, "setup_priority").value, FieldValue::U8(3));
        assert_eq!(child(sa, "name_length").value, FieldValue::U8(6));
        assert_eq!(
            child(sa, "session_name").value,
            FieldValue::Bytes(b"tunnel")
        );

        // A Name Length past the object is cut at its end.
        let data = message(
            1,
            0,
            &object(CLASS_SESSION_ATTRIBUTE, 7, &[7, 7, 0, 20, b'a', b'b', 0, 0]),
        );
        let (buf, _) = dissect(&data);
        let sa = &objects(&buf)[0];
        assert_eq!(
            child(sa, "session_name").value,
            FieldValue::Bytes(&[b'a', b'b', 0, 0])
        );
    }

    #[test]
    fn parse_hello() {
        let mut o = object(CLASS_HELLO, 1, &[0, 0, 0, 1, 0, 0, 0, 0]);
        o.extend(object(CLASS_HELLO, 2, &[0, 0, 0, 2, 0, 0, 0, 1]));
        let data = message(20, 0, &o);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("Hello")
        );
        let objs = objects(&buf);
        assert_eq!(display(&objs[0], "c_type"), Some("Request"));
        assert_eq!(child(&objs[0], "source_instance").value, FieldValue::U32(1));
        assert_eq!(display(&objs[1], "c_type"), Some("Acknowledgment"));
        assert_eq!(
            child(&objs[1], "destination_instance").value,
            FieldValue::U32(1)
        );
    }

    #[test]
    fn parse_fast_reroute_detour() {
        let mut frr = vec![7, 7, 3, 0x02, 0x49, 0x74, 0x24, 0x00]; // bandwidth 1e6
        frr.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4]);
        let mut o = object(CLASS_FAST_REROUTE, 1, &frr);
        o.extend(object(CLASS_FAST_REROUTE, 7, &frr[..16]));
        o.extend(object(CLASS_DETOUR, 7, &[10, 0, 0, 1, 10, 0, 0, 2]));
        let mut d6 = [0x11; 16].to_vec();
        d6.extend_from_slice(&[0x22; 16]);
        o.extend(object(CLASS_DETOUR, 8, &d6));
        let data = message(1, 0, &o);
        let (buf, _) = dissect(&data);
        let objs = objects(&buf);
        assert_eq!(child(&objs[0], "hop_limit").value, FieldValue::U8(3));
        assert_eq!(child(&objs[0], "frr_flags").value, FieldValue::U8(0x02));
        assert_eq!(
            child(&objs[0], "bandwidth").value,
            FieldValue::Bytes(&[0x49, 0x74, 0x24, 0x00])
        );
        assert_eq!(child(&objs[0], "include_any").value, FieldValue::U32(1));
        assert_eq!(child(&objs[0], "exclude_any").value, FieldValue::U32(2));
        assert_eq!(child(&objs[0], "include_all").value, FieldValue::U32(4));
        assert!(!has(&objs[1], "frr_flags"));
        assert!(!has(&objs[1], "include_all"));
        let d = items(&buf, &objs[2], "detours");
        assert_eq!(
            child(&d[0], "plr_id").value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(
            child(&d[0], "avoid_node_id").value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
        let d = items(&buf, &objs[3], "detours");
        assert_eq!(
            child(&d[0], "avoid_node_id").value,
            FieldValue::Ipv6Addr([0x22; 16])
        );
    }

    #[test]
    fn parse_refresh_reduction() {
        let data = message(
            15,
            0x01,
            &object(
                CLASS_MESSAGE_ID_LIST,
                1,
                &[0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 2, 3],
            ),
        );
        let (buf, _) = dissect(&data);
        assert_eq!(
            top(&buf, "refresh_reduction_capable").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("Srefresh")
        );
        // The 13-octet contents make a malformed object: kept as data.
        assert!(top(&buf, "objects").is_none());

        let mut o = object(
            CLASS_MESSAGE_ID_LIST,
            1,
            &[0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 2],
        );
        o.extend(object(CLASS_MESSAGE_ID, 1, &[0x01, 0, 0, 9, 0, 0, 0, 5]));
        o.extend(object(CLASS_MESSAGE_ID_ACK, 2, &[0, 0, 0, 9, 0, 0, 0, 6]));
        let data = message(13, 0x01, &o);
        let (buf, _) = dissect(&data);
        let objs = objects(&buf);
        assert_eq!(child(&objs[0], "epoch").value, FieldValue::U32(9));
        let ids = children(&buf, child(&objs[0], "message_ids"));
        assert_eq!(ids[1].value, FieldValue::U32(2));
        assert_eq!(child(&objs[1], "message_flags").value, FieldValue::U8(1));
        assert_eq!(child(&objs[1], "message_id").value, FieldValue::U32(5));
        assert_eq!(display(&objs[2], "c_type"), Some("MESSAGE_ID_NACK"));
        assert_eq!(child(&objs[2], "message_id").value, FieldValue::U32(6));
    }

    #[test]
    fn parse_guaranteed_flowspec() {
        let mut g = vec![0x00, 0x00, 0, 10, 2, 0, 0, 9, 127, 0, 0, 5];
        g.extend_from_slice(&[0; 12]);
        g.extend_from_slice(&[0, 0, 0, 20, 0, 0, 5, 0xDC]);
        g.extend_from_slice(&[130, 0, 0, 2, 0x3F, 0x80, 0, 0, 0, 0, 0, 7]);
        let data = message(2, 0, &object(CLASS_FLOWSPEC, 2, &g));
        let (buf, _) = dissect(&data);
        let f = &objects(&buf)[0];
        assert_eq!(display(f, "service_number"), Some("Guaranteed"));
        let p = items(&buf, f, "parameters");
        assert_eq!(p.len(), 2);
        assert_eq!(display(&p[1], "id"), Some("Guaranteed Service RSpec"));
        assert_eq!(
            child(&p[1], "rate").value,
            FieldValue::Bytes(&[0x3F, 0x80, 0, 0])
        );
        assert_eq!(child(&p[1], "slack_term").value, FieldValue::U32(7));

        // An unknown parameter, a parameter overrunning the service data,
        // and contents shorter than the headers.
        let s = [0x00, 0x00, 0, 3, 1, 0, 0, 2, 200, 0, 0, 1, 1, 2, 3, 4];
        let data = message(1, 0, &object(CLASS_SENDER_TSPEC, 2, &s));
        let (buf, _) = dissect(&data);
        let p = items(&buf, &objects(&buf)[0], "parameters");
        assert_eq!(
            child(&p[0], "value").value,
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        let s = [0x00, 0x00, 0, 2, 1, 0, 0, 1, 127, 0, 0, 5];
        let data = message(1, 0, &object(CLASS_SENDER_TSPEC, 2, &s));
        let (buf, _) = dissect(&data);
        let t = &objects(&buf)[0];
        assert!(!has(t, "parameters"));
        assert_eq!(child(t, "value").value, FieldValue::Bytes(&[127, 0, 0, 5]));
        let data = message(1, 0, &object(CLASS_SENDER_TSPEC, 2, &[0, 0, 0, 0]));
        let (buf, _) = dissect(&data);
        assert_eq!(
            child(&objects(&buf)[0], "value").value,
            FieldValue::Bytes(&[0, 0, 0, 0])
        );
    }

    #[test]
    fn unknown_object_kept_as_value() {
        let mut o = object(253, 1, &[1, 2, 3, 4]);
        o.extend(object(0, 0, &[]));
        o.extend(object(CLASS_LABEL, 1, &[0, 0, 0, 1, 0, 0, 0, 2])); // unexpected length
        let data = message(1, 0, &o);
        let (buf, _) = dissect(&data);
        let objs = objects(&buf);
        assert_eq!(
            display(&objs[0], "class_num"),
            Some("Reserved for Private Use")
        );
        assert_eq!(
            child(&objs[0], "value").value,
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        assert_eq!(display(&objs[1], "class_num"), Some("NULL"));
        assert_eq!(objs[1].len(), 3);
        assert!(has(&objs[2], "value"));
    }

    #[test]
    fn malformed_object_lengths() {
        // Length not a multiple of 4.
        let mut o = lsp_session();
        o.extend_from_slice(&[0, 6, 1, 1, 0, 0, 0, 0]);
        let data = message(1, 0, &o);
        let (buf, _) = dissect(&data);
        assert_eq!(objects(&buf).len(), 1);
        assert_eq!(top(&buf, "data").unwrap().range, 24..32);
        // Length below 4, and past the message.
        for bad in [[0u8, 0, 1, 1], [0, 40, 1, 1]] {
            let mut o = lsp_session();
            o.extend_from_slice(&bad);
            let data = message(1, 0, &o);
            let (buf, _) = dissect(&data);
            assert_eq!(objects(&buf).len(), 1);
            assert_eq!(top(&buf, "data").unwrap().range, 24..28);
        }
    }

    #[test]
    fn malformed_subobjects() {
        let ero = [0x01, 8, 10, 0, 0, 2, 32, 0, 0x01, 12, 10, 0];
        let data = message(1, 0, &object(CLASS_EXPLICIT_ROUTE, 1, &ero));
        let (buf, _) = dissect(&data);
        let e = &objects(&buf)[0];
        assert_eq!(items(&buf, e, "subobjects").len(), 1);
        assert_eq!(
            child(e, "value").value,
            FieldValue::Bytes(&[0x01, 12, 10, 0])
        );
        // A Length below 4 or not a multiple of 4 ends the subobjects.
        for bad in [[0x05u8, 2, 0x01, 1], [0x05, 6, 0x01, 1]] {
            let mut ero = vec![0x20, 4, 0, 1];
            ero.extend_from_slice(&bad);
            let data = message(1, 0, &object(CLASS_EXPLICIT_ROUTE, 1, &ero));
            let (buf, _) = dissect(&data);
            let e = &objects(&buf)[0];
            assert_eq!(items(&buf, e, "subobjects").len(), 1);
            assert_eq!(child(e, "value").value, FieldValue::Bytes(&bad));
        }
        // A 4-octet subobject of an unknown type keeps its 2 content octets.
        let data = message(1, 0, &object(CLASS_RECORD_ROUTE, 1, &[0x06, 4, 1, 2]));
        let (buf, _) = dissect(&data);
        let s = items(&buf, &objects(&buf)[0], "subobjects");
        assert_eq!(child(&s[0], "value").value, FieldValue::Bytes(&[1, 2]));
    }

    #[test]
    fn bundle_sub_messages_are_embedded_payloads() {
        let inner = message(20, 0, &object(CLASS_HELLO, 1, &[0, 0, 0, 1, 0, 0, 0, 0]));
        let mut body = inner.clone();
        body.extend_from_slice(&inner);
        body.extend_from_slice(&[0x10, 20, 0, 0]); // truncated sub-message
        let data = message(12, 0x01, &body);
        let (buf, _) = dissect(&data);
        assert_eq!(
            buf.resolve_display_name(&buf.layers()[0], "message_type_name"),
            Some("Bundle")
        );
        assert!(top(&buf, "objects").is_none());
        let n = inner.len();
        let payloads: Vec<_> = buf
            .embedded_payloads()
            .iter()
            .map(|p| (p.range.clone(), p.next.clone()))
            .collect();
        assert_eq!(
            payloads,
            [
                (8..8 + n, DispatchHint::ByIpProtocol(46)),
                (8 + n..8 + 2 * n, DispatchHint::ByIpProtocol(46))
            ]
        );
        assert_eq!(top(&buf, "data").unwrap().range, 8 + 2 * n..data.len());
    }

    #[test]
    fn consumes_rsvp_length() {
        let mut data = message(20, 0, &object(CLASS_HELLO, 1, &[0, 0, 0, 1, 0, 0, 0, 0]));
        let len = data.len();
        data.extend_from_slice(&[0xEE; 6]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, len);
        assert_eq!(buf.layers()[0].range, 0..len);
        assert!(top(&buf, "data").is_none());
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RsvpDissector.dissect(&[0x10, 1, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn truncated_message() {
        let data = message(1, 0, &lsp_session());
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RsvpDissector.dissect(&data[..12], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: data.len(),
                actual: 12
            })
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn reject_unsupported_version() {
        let mut data = message(1, 0, &[]);
        data[0] = 0x20;
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RsvpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            })
        );
    }

    #[test]
    fn reject_short_length() {
        let data = [0x10, 1, 0, 0, 1, 0, 0, 4];
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RsvpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "length",
                value: 4
            })
        );
    }

    #[test]
    fn offsets_are_absolute() {
        let data = message(1, 0, &lsp_session());
        let mut buf = DissectBuffer::new();
        RsvpDissector.dissect(&data, &mut buf, 20).unwrap();
        assert_eq!(buf.layers()[0].range, 20..20 + data.len());
        let t = buf
            .fields()
            .iter()
            .find(|f| f.name() == "tunnel_id")
            .unwrap();
        assert_eq!(t.range, 20 + 18..20 + 20);
    }

    #[test]
    fn registry_names() {
        let named = |name: Option<&'static str>| name.is_none_or(|n| !n.is_empty());
        assert!((0..=255).all(|v| named(message_type_name(v)) && named(class_name(v))));
        assert!((0..=255).all(|v| named(error_code_name(v)) && named(ero_subobject_name(v))));
        assert!((0..=255).all(|v| named(rro_subobject_name(v)) && named(service_name(v))));
        assert!((0..=255).all(|c| (0..=255).all(|t| named(c_type_name(c, t)))));
        assert_eq!(message_type_name(11), None);
        assert_eq!(class_name(207), Some("SESSION_ATTRIBUTE"));
        assert_eq!(c_type_name(1, 7), Some("LSP Tunnel IPv4"));
        assert_eq!(c_type_name(1, 5), None);
        assert_eq!(style_name(0x0A), Some("Fixed-Filter (FF)"));
        assert_eq!(style_name(0), None);
        assert_eq!(parameter_name(1), None);
        assert_eq!(error_code_name(45), None);
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(RsvpDissector.name(), "Resource ReSerVation Protocol");
        assert_eq!(RsvpDissector.short_name(), "RSVP");
        assert_eq!(RsvpDissector.layer(), Some(ProtocolLayer::Network));
        assert_eq!(RsvpDissector.references()[0].id, "RFC 2205");
        assert_eq!(RsvpDissector.field_descriptors().len(), FD_DATA + 1);
    }
}
