//! LDP (Label Distribution Protocol) dissector.
//!
//! Decodes one LDP PDU: the PDU header and every message it carries, with
//! their TLVs. FEC TLVs are decoded for the Wildcard and Prefix FEC
//! elements and the PWid (128) and Generalized PWid (129) pseudowire FEC
//! elements.
//!
//! LDP runs over UDP port 646 (discovery Hellos) and TCP port 646
//! (sessions). On TCP one call dissects one PDU, so a stream is framed by
//! the TCP reassembly layer from the PDU Length.
//!
//! ## References
//! - RFC 5036 (LDP Specification): <https://www.rfc-editor.org/rfc/rfc5036>
//! - RFC 6720 (GTSM for LDP): <https://www.rfc-editor.org/rfc/rfc6720>
//! - RFC 7552 (Updates to LDP for IPv6): <https://www.rfc-editor.org/rfc/rfc7552>
//! - RFC 8077 (Pseudowire Setup and Maintenance Using LDP): <https://www.rfc-editor.org/rfc/rfc8077>
//! - IANA LDP Parameters: <https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml>
//! - IANA Pseudowire Name Spaces (PWE3): <https://www.iana.org/assignments/pwe3-parameters/pwe3-parameters.xhtml>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// LDP PDU header size: Version (2), PDU Length (2), LDP Identifier (6).
/// RFC 5036, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.1>
const PDU_HEADER_SIZE: usize = 10;

/// Octets of the PDU header not counted by PDU Length: "Two octet integer
/// specifying the total length of this PDU in octets, excluding the Version
/// and PDU Length fields."
/// RFC 5036, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.1>
const PDU_LENGTH_EXCLUDED: usize = 4;

/// Message header: U bit + Message Type (2), Message Length (2), Message
/// ID (4). RFC 5036, Section 3.5 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.5>
const MESSAGE_HEADER_SIZE: usize = 8;

/// TLV header: U, F bits + Type (2), Length (2).
/// RFC 5036, Section 3.3 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.3>
const TLV_HEADER_SIZE: usize = 4;

/// "This version of the specification specifies LDP protocol version 1."
/// RFC 5036, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.1>
const VERSION_1: u16 = 1;

/// TLV types decoded by this dissector. RFC 5036, Section 3.4 —
/// <https://www.rfc-editor.org/rfc/rfc5036#section-3.4>; RFC 7552,
/// Section 6.1.1 — <https://www.rfc-editor.org/rfc/rfc7552#section-6.1.1>;
/// RFC 8077, Sections 6.2.2.1, 6.2.2.2 and 6.3.2 —
/// <https://www.rfc-editor.org/rfc/rfc8077#section-6.2.2>
const TLV_FEC: u16 = 0x0100;
const TLV_ADDRESS_LIST: u16 = 0x0101;
const TLV_HOP_COUNT: u16 = 0x0103;
const TLV_PATH_VECTOR: u16 = 0x0104;
const TLV_GENERIC_LABEL: u16 = 0x0200;
const TLV_STATUS: u16 = 0x0300;
const TLV_EXTENDED_STATUS: u16 = 0x0301;
const TLV_COMMON_HELLO_PARAMETERS: u16 = 0x0400;
const TLV_IPV4_TRANSPORT_ADDRESS: u16 = 0x0401;
const TLV_CONFIGURATION_SEQUENCE_NUMBER: u16 = 0x0402;
const TLV_IPV6_TRANSPORT_ADDRESS: u16 = 0x0403;
const TLV_COMMON_SESSION_PARAMETERS: u16 = 0x0500;
const TLV_LABEL_REQUEST_MESSAGE_ID: u16 = 0x0600;
const TLV_DUAL_STACK_CAPABILITY: u16 = 0x0701;
const TLV_PW_STATUS: u16 = 0x096A;
const TLV_PW_INTERFACE_PARAMETERS: u16 = 0x096B;
const TLV_PW_GROUP_ID: u16 = 0x096C;

/// FEC element types. RFC 5036, Section 3.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc5036#section-3.4.1>; RFC 8077,
/// Sections 6.1 and 6.2.2 — <https://www.rfc-editor.org/rfc/rfc8077#section-6.1>
const FEC_WILDCARD: u8 = 0x01;
const FEC_PREFIX: u8 = 0x02;
const FEC_PWID: u8 = 0x80;
const FEC_GENERALIZED_PWID: u8 = 0x81;

/// Address families (IANA Address Family Numbers).
const AF_IPV4: u16 = 1;
const AF_IPV6: u16 = 2;

/// Interface Parameter sub-TLV types: Interface MTU and Interface
/// Description. RFC 8077, Section 6.4 —
/// <https://www.rfc-editor.org/rfc/rfc8077#section-6.4>
const SUB_TLV_MTU: u8 = 0x01;
const SUB_TLV_DESCRIPTION: u8 = 0x03;

/// Returns the name of an LDP message type. The vendor-private and
/// experimental ranges are from RFC 5036, Sections 3.6.1.2 and 3.6.2 —
/// <https://www.rfc-editor.org/rfc/rfc5036#section-3.6.1.2>.
///
/// IANA LDP Parameters —
/// <https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#ldp-namespaces-2>
fn message_type_name(v: u16) -> Option<&'static str> {
    match v {
        0x0001 => Some("Notification"),
        0x0100 => Some("Hello"),
        0x0200 => Some("Initialization"),
        0x0201 => Some("KeepAlive"),
        0x0202 => Some("Capability"),
        0x0300 => Some("Address"),
        0x0301 => Some("Address Withdraw"),
        0x0400 => Some("Label Mapping"),
        0x0401 => Some("Label Request"),
        0x0402 => Some("Label Withdraw"),
        0x0403 => Some("Label Release"),
        0x0404 => Some("Label Abort Request"),
        0x0500 => Some("Call Setup"),
        0x0501 => Some("Call Release"),
        0x0700 => Some("RG Connect Message"),
        0x0701 => Some("RG Disconnect Message"),
        0x0702 => Some("RG Notification Message"),
        0x0703 => Some("RG Application Data Message"),
        0x0704..=0x070F => Some("Reserved for future ICCP use"),
        0x3E00..=0x3EFF => Some("Reserved for Vendor-Private Extensions"),
        0x3F00..=0x3FFF => Some("Reserved for Experimental Extensions"),
        _ => None,
    }
}

/// Returns the name of an LDP TLV type.
///
/// IANA LDP Parameters —
/// <https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#ldp-namespaces-4>
fn tlv_type_name(v: u16) -> Option<&'static str> {
    match v {
        0x0001 => Some("Sequence Number TLV"),
        0x0100 => Some("FEC"),
        0x0101 => Some("Address List"),
        0x0103 => Some("Hop Count"),
        0x0104 => Some("Path Vector"),
        0x0200 => Some("Generic Label"),
        0x0201 => Some("ATM Label"),
        0x0202 => Some("Frame Relay Label"),
        0x0203 => Some("FT Protection TLV"),
        0x0204 => Some("LDP Upstream-Assigned Label TLV"),
        0x0205 => Some("LDP Upstream-Assigned Label Request TLV"),
        0x0206 => Some("Entropy Label Capability TLV"),
        0x0300 => Some("Status"),
        0x0301 => Some("Extended Status"),
        0x0302 => Some("Returned PDU"),
        0x0303 => Some("Returned Message"),
        0x0304 => Some("Returned TLVs"),
        0x0400 => Some("Common Hello Parameters"),
        0x0401 => Some("IPv4 Transport Address"),
        0x0402 => Some("Configuration Sequence Number"),
        0x0403 => Some("IPv6 Transport Address"),
        0x0404 => Some("MAC TLV"),
        0x0405 => Some("Cryptographic Authentication TLV"),
        0x0406 => Some("MAC Flush Parameters TLV"),
        0x0407 => Some("PBB B-MAC List Sub-TLV"),
        0x0408 => Some("PBB I-SID List Sub-TLV"),
        0x0500 => Some("Common Session Parameters"),
        0x0501 => Some("ATM Session Parameters"),
        0x0502 => Some("Frame Relay Session Parameters"),
        0x0503 => Some("FT Session TLV"),
        0x0504 => Some("FT Ack TLV"),
        0x0505 => Some("FT Cork TLV"),
        0x0506 => Some("Dynamic Capability Announcement"),
        0x0507 => Some("LDP Upstream Label Assignment Capability TLV"),
        0x0508 => Some("P2MP Capability Parameter"),
        0x0509 => Some("MP2MP Capability Parameter"),
        0x050A => Some("MBB Capability Parameter"),
        0x050B => Some("Typed Wildcard FEC Capability"),
        0x050C => Some("Multi-Topology Capability"),
        0x050D => Some("State Advertisement Control Capability"),
        0x050E => Some("MRT Capability TLV"),
        0x050F => Some("Targeted Application Capability"),
        0x0510 => Some("MT Multipoint Capability"),
        0x0600 => Some("Label Request Message ID"),
        0x0601 => Some("MTU TLV"),
        0x0603 => Some("Unrecognized Notification Capability"),
        0x0700 => Some("ICCP capability TLV"),
        0x0701 => Some("Dual-Stack capability"),
        0x0703 => Some("P2MP PW Capability TLV"),
        0x0800 => Some("Explicit Route TLV"),
        0x0801 => Some("Ipv4 Prefix ER-Hop TLV"),
        0x0802 => Some("Ipv6 Prefix ER-Hop TLV"),
        0x0803 => Some("Autonomous System Number ER-Hop TLV"),
        0x0804 => Some("LSP-ID ER-HOP TLV"),
        0x0805 => Some("L2 PW Address of Switching Point"),
        0x0810 => Some("Traffic Parameters TLV"),
        0x0820 => Some("Preemption TLV"),
        0x0821 => Some("LSPID TLV"),
        0x0822 => Some("Resource Class TLV"),
        0x0823 => Some("Route Pinning TLV"),
        0x0824 => Some("Generalized Label Request TLV"),
        0x0825 => Some("Generalized Label TLV"),
        0x0826 => Some("Upstream Label TLV"),
        0x0827 => Some("Label Set TLV"),
        0x0828 => Some("Waveband Label TLV"),
        0x0829 => Some("ER-Hop TLV"),
        0x082A => Some("Acceptable Label Set TLV"),
        0x082B => Some("Admin Status TLV"),
        0x082C => Some("Interface ID TLV"),
        0x082D => Some("IPV4 Interface ID TLV"),
        0x082E => Some("IPV6 Interface ID TLV"),
        0x082F => Some("IPv4 IF_ID Status TLV"),
        0x0830 => Some("IPv6 IF_ID Status TLV"),
        0x0831 => Some("Op-Sp Call ID TLV"),
        0x0832 => Some("GU Call ID TLV"),
        0x0833 => Some("Call Capability TLV"),
        0x0834 => Some("Crankback TLV"),
        0x0835 => Some("Protection TLV"),
        0x0836 => Some("LSP_TUNNEL_INTERFACE_ID TLV"),
        0x0837 => Some("Unnumbered Interface ID TLV"),
        0x0838 => Some("SONET/SDH Traffic Parameters TLV"),
        0x0901 => Some("Diff-Serv TLV"),
        0x0902 => Some("HSMP LSP Capability Parameter"),
        0x0960 => Some("IPv4 Source ID TLV"),
        0x0961 => Some("IPv6 Source ID TLV"),
        0x0962 => Some("NSAP Source ID TLV"),
        0x0963 => Some("IPv4 Destination ID TLV"),
        0x0964 => Some("IPv6 Destination ID TLV"),
        0x0965 => Some("NSAP Destination ID TLV"),
        0x0966 => Some("Egress Label TLV"),
        0x0967 => Some("Local Connection ID TLV"),
        0x0968 => Some("Diversity TLV"),
        0x0969 => Some("Contract ID TLV"),
        0x096A => Some("PW Status TLV"),
        0x096B => Some("PW Interface Parameters TLV"),
        0x096C => Some("PW Group ID TLV"),
        0x096D => Some("Pseudowire Switching Point PE TLV"),
        0x096E => Some("Bandwidth TLV"),
        0x096F => Some("LDP MP Status TLV Type"),
        0x0970 => Some("UNI Service Level TLV"),
        0x0971 => Some("Queue Request TLV"),
        0x0972 => Some("MP Node Protection Capability"),
        0x0973 => Some("PSN Tunnel Binding TLV"),
        0x0974 => Some("Egress Protection Capability"),
        0x3E00..=0x3EFF => Some("Reserved for Vendor-Private Extensions"),
        0x3F00..=0x3FFF => Some("Reserved for Experimental Extensions"),
        _ => None,
    }
}

/// Returns the name of a FEC element type.
///
/// IANA LDP Parameters —
/// <https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#fec-type>
fn fec_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Wildcard"),
        2 => Some("Prefix"),
        4 => Some("CR-LSP"),
        5 => Some("Typed Wildcard FEC Element"),
        6 => Some("P2MP"),
        7 => Some("MP2MP-up"),
        8 => Some("MP2MP-down"),
        9 => Some("HSMP-upstream"),
        10 => Some("HSMP-downstream"),
        128 => Some("PWid FEC Element"),
        129 => Some("Generalized PWid FEC Element"),
        130 => Some("P2MP PW Upstream FEC Element"),
        131 => Some("Protection FEC Element"),
        132 => Some("P2P PW Downstream FEC Element"),
        192..=255 => Some("Reserved for Private Use"),
        _ => None,
    }
}

/// Returns the name of a status code (the Status Data without the E and F bits).
///
/// IANA LDP Parameters —
/// <https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml#status-codes>
fn status_code_name(v: u32) -> Option<&'static str> {
    match v {
        0x00000000 => Some("Success"),
        0x00000001 => Some("Bad LDP Identifier"),
        0x00000002 => Some("Bad Protocol Version"),
        0x00000003 => Some("Bad PDU Length"),
        0x00000004 => Some("Unknown Message Type"),
        0x00000005 => Some("Bad Message Length"),
        0x00000006 => Some("Unknown TLV"),
        0x00000007 => Some("Bad TLV Length"),
        0x00000008 => Some("Malformed TLV Value"),
        0x00000009 => Some("Hold Timer Expired"),
        0x0000000A => Some("Shutdown"),
        0x0000000B => Some("Loop Detected"),
        0x0000000C => Some("Unknown FEC"),
        0x0000000D => Some("No Route"),
        0x0000000E => Some("No Label Resources"),
        0x0000000F => Some("Label Resources/Available"),
        0x00000010 => Some("Session Rejected/No Hello"),
        0x00000011 => Some("Session Rejected/Parameters Advertisement Mode"),
        0x00000012 => Some("Session Rejected/Parameters Max PDU Length"),
        0x00000013 => Some("Session Rejected/Parameters Label Range"),
        0x00000014 => Some("KeepAlive Timer Expired"),
        0x00000015 => Some("Label Request Aborted"),
        0x00000016 => Some("Missing Message Parameters"),
        0x00000017 => Some("Unsupported Address Family"),
        0x00000018 => Some("Session Rejected/Bad KeepAlive Time"),
        0x00000019 => Some("Internal Error"),
        0x0000001A => Some("No LDP Session"),
        0x0000001B => Some("Zero FT seqnum"),
        0x0000001C => Some("Unexpected TLV / Session Not FT"),
        0x0000001D => Some("Unexpected TLV / Label Not FT"),
        0x0000001E => Some("Missing FT Protection TLV"),
        0x0000001F => Some("FT ACK sequence error"),
        0x00000020 => Some("Temporary Shutdown"),
        0x00000021 => Some("FT Seq Numbers Exhausted"),
        0x00000022 => Some("FT Session parameters / changed"),
        0x00000023 => Some("Unexpected FT Cork TLV"),
        0x00000024 => Some("Illegal C-Bit"),
        0x00000025 => Some("Wrong C-Bit"),
        0x00000026 => Some("Incompatible bit-rate"),
        0x00000027 => Some("CEP-TDM mis-configuration"),
        0x00000028 => Some("PW Status"),
        0x0000002A => Some("Generic Misconfiguration Error"),
        0x0000002B => Some("Label Withdraw PW Status Method Not Supported"),
        0x0000002C => Some("IP Address of CE"),
        0x0000002D => Some("Attachment Circuit bound to different remote Attachment Circuit"),
        0x0000002E => Some("Unsupported Capability"),
        0x0000002F => Some("End-of-LIB"),
        0x00000030 => Some("Attachment Circuit bound to different PE"),
        0x00000031 => Some("Invalid Topology ID"),
        0x00000032 => Some("Transport Connection Mismatch"),
        0x00000033 => Some("Dual-Stack Noncompliance"),
        0x00000034 => Some("MRT Capability negotiated without MT Capability"),
        0x00000035 => Some("VCCV Type Error"),
        0x00000037 => Some("Bandwidth resources unavailable"),
        0x00000038 => Some("Resources Unavailable"),
        0x00000039 => Some("AII Unreachable"),
        0x0000003A => Some("PW Loop Detected"),
        0x0000003B => Some("Reject - unable to use the suggested tunnel/LSPs"),
        0x0000003C => Some("The C-bit or S-bit unknown"),
        0x00000040 => Some("LDP MP status"),
        0x0000004A => Some("IP Address Type Mismatch"),
        0x0000004B => Some("Wrong IP Address Type"),
        0x0000004C => Some("Session Rejected/Targeted Application Capability Mismatch"),
        0x00010001 => Some("Unknown ICCP RG"),
        0x00010002 => Some("ICCP Connection Count Exceeded"),
        0x00010003 => Some("ICCP Application Connection Count Exceeded"),
        0x00010004 => Some("ICCP Application not in RG"),
        0x00010005 => Some("Incompatible ICCP Protocol Version"),
        0x00010006 => Some("ICCP Rejected Message"),
        0x00010007 => Some("ICCP Administratively Disabled"),
        0x00010010 => Some("ICCP RG Removed"),
        0x00010011 => Some("ICCP Application Removed from RG"),
        0x01000001 => Some("Unexpected Diff-Serv TLV"),
        0x01000002 => Some("Unsupported PHB"),
        0x01000003 => Some("Invalid EXP<-->PHB mapping"),
        0x01000004 => Some("Unsupported PSC"),
        0x01000005 => Some("Per-LSP context allocation failure"),
        0x04000001 => Some("Bad Explicit Routing TLV Error"),
        0x04000002 => Some("Bad Strict Node Error"),
        0x04000003 => Some("Bad Loose Node Error"),
        0x04000004 => Some("Bad Initial ER-Hop Error"),
        0x04000005 => Some("Resource Unavailable"),
        0x04000006 => Some("Traffic Parameters Unavailable"),
        0x04000007 => Some("LSP Preempted"),
        0x04000008 => Some("Modify Request Not Supported"),
        0x04000009 => Some("Invalid SNP ID"),
        0x0400000A => Some("Calling Party busy"),
        0x0400000B => Some("Unavailable SNP ID"),
        0x0400000C => Some("Invalid SNPP ID"),
        0x0400000D => Some("Unavailable SNPP ID"),
        0x0400000E => Some("Failed to create SNC"),
        0x0400000F => Some("Failed to establish LC"),
        0x04000010 => Some("Invalid A End-User Name"),
        0x04000011 => Some("Invalid Z End-User Name"),
        0x04000012 => Some("Invalid CoS"),
        0x04000013 => Some("Unavailable CoS"),
        0x04000014 => Some("Invalid GoS"),
        0x04000015 => Some("Unavailable GoS"),
        0x04000016 => Some("Failed Security Check"),
        0x04000017 => Some("TimeOut"),
        0x04000018 => Some("Invalid Call Name"),
        0x04000019 => Some("Failed to Release SNC"),
        0x0400001A => Some("Failed to Free LC"),
        0x20000000 => Some("Unknown VPN ID"),
        0x20000001 => Some("Illegal C-Bit"),
        0x20000002 => Some("Wrong C-Bit"),
        0x20000003 => Some("E-Tree VLAN mapping not supported"),
        0x20000004 => Some("Leaf-to-Leaf PW released"),
        0x3F000000..=0x3FFFFFFF => Some("Reserved for Private Use"),
        _ => None,
    }
}

/// Returns the name of an address family.
///
/// IANA Address Family Numbers —
/// <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
fn address_family_name(v: u16) -> Option<&'static str> {
    match v {
        AF_IPV4 => Some("IPv4"),
        AF_IPV6 => Some("IPv6"),
        _ => None,
    }
}

/// Returns the name of a pseudowire type.
///
/// IANA MPLS Pseudowire Types —
/// <https://www.iana.org/assignments/pwe3-parameters/pwe3-parameters.xhtml#pwe3-parameters-2>
fn pw_type_name(v: u16) -> Option<&'static str> {
    match v {
        0x0001 => Some("Frame Relay DLCI ( Martini Mode )"),
        0x0002 => Some("ATM AAL5 SDU VCC transport"),
        0x0003 => Some("ATM transparent cell transport"),
        0x0004 => Some("Ethernet Tagged Mode"),
        0x0005 => Some("Ethernet"),
        0x0006 => Some("HDLC"),
        0x0007 => Some("PPP"),
        0x0008 => Some("SONET/SDH Circuit Emulation Service Over MPLS Encapsulation"),
        0x0009 => Some("ATM n-to-one VCC cell transport"),
        0x000A => Some("ATM n-to-one VPC cell transport"),
        0x000B => Some("IP Layer2 Transport"),
        0x000C => Some("ATM one-to-one VCC Cell Mode"),
        0x000D => Some("ATM one-to-one VPC Cell Mode"),
        0x000E => Some("ATM AAL5 PDU VCC transport"),
        0x000F => Some("Frame-Relay Port mode"),
        0x0010 => Some("SONET/SDH Circuit Emulation over Packet"),
        0x0011 => Some("Structure-agnostic E1 over Packet"),
        0x0012 => Some("Structure-agnostic T1 (DS1) over Packet"),
        0x0013 => Some("Structure-agnostic E3 over Packet"),
        0x0014 => Some("Structure-agnostic T3 (DS3) over Packet"),
        0x0015 => Some("CESoPSN basic mode"),
        0x0016 => Some("TDMoIP AAL1 Mode"),
        0x0017 => Some("CESoPSN TDM with CAS"),
        0x0018 => Some("TDMoIP AAL2 Mode"),
        0x0019 => Some("Frame Relay DLCI"),
        0x001A => Some("ROHC Transport Header-compressed Packets"),
        0x001B => Some("ECRTP Transport Header-compressed Packets"),
        0x001C => Some("IPHC Transport Header-compressed Packets"),
        0x001D => Some("cRTP Transport Header-compressed Packets"),
        0x001E => Some("ATM VP Virtual Trunk"),
        0x001F => Some("FC Port Mode"),
        0x1001 => Some("Proprietary pseudowire implementation carrying CLNP packets"),
        0x7FFF => Some("Wildcard"),
        _ => None,
    }
}

/// Returns the name of a pseudowire Interface Parameter sub-TLV type.
///
/// IANA Pseudowire Interface Parameters Sub-TLV types —
/// <https://www.iana.org/assignments/pwe3-parameters/pwe3-parameters.xhtml#pwe3-parameters-4>
fn interface_parameter_name(v: u8) -> Option<&'static str> {
    match v {
        0x01 => Some("Interface MTU in octets"),
        0x02 => Some("Maximum Number of concatenated ATM cells"),
        0x03 => Some("Optional Interface Description string"),
        0x04 => Some("CEP/TDM Payload Bytes"),
        0x05 => Some("CEP options"),
        0x06 => Some("Requested VLAN ID"),
        0x07 => Some("CEP/TDM bit-rate"),
        0x08 => Some("Frame-Relay DLCI Length"),
        0x09 => Some("Fragmentation indicator"),
        0x0A => Some("FCS retention indicator"),
        0x0B => Some("TDM options"),
        0x0C => Some("VCCV parameter"),
        0x0D => Some("ROHC over MPLS configuration"),
        0x0E => Some("Number of TDMoIP AAL1 cells per packet"),
        0x0F => Some("CRTP/ECRTP/IPHC HC over MPLS configuration"),
        0x10 => Some("TDMoIP AAL1 mode"),
        0x11 => Some("TDMoIP AAL2 Options"),
        0x16 => Some("Stack capability"),
        0x17 => Some("Flow Label"),
        0x18 => Some("PW Generic Protocol Flags"),
        0x19 => Some("VCCV Extended CV Parameter"),
        0x1A => Some("E-Tree"),
        0x1B => Some("Selective Tree Interface Parameter"),
        0xFD => Some("Zte optional Supplier private interface parameters"),
        _ => None,
    }
}

/// Returns the name of a Dual-Stack capability Transport Connection
/// Preference.
///
/// RFC 7552, Section 6.1.1 — <https://www.rfc-editor.org/rfc/rfc7552#section-6.1.1>
fn transport_preference_name(v: u8) -> Option<&'static str> {
    match v {
        0b0100 => Some("LDPoIPv4 connection"),
        0b0110 => Some("LDPoIPv6 connection"),
        _ => None,
    }
}

/// Resolves the name of a container from its `type` child with `name_fn`.
macro_rules! named_by_type {
    ($name:literal, $display:literal, $ty:ident, $name_fn:path) => {
        FieldDescriptor::new($name, $display, FieldType::Object).with_display_fn(|v, children| {
            match v {
                FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
                    ("type", FieldValue::$ty(t)) => $name_fn(*t),
                    _ => None,
                }),
                _ => None,
            }
        })
    };
}

/// Child field indices of an Interface Parameter sub-TLV.
const IP_TYPE: usize = 0;
const IP_LENGTH: usize = 1;
const IP_MTU: usize = 2;
const IP_DESCRIPTION: usize = 3;
const IP_VALUE: usize = 4;

/// Child descriptors of an Interface Parameter sub-TLV.
/// RFC 8077, Section 6.4 — <https://www.rfc-editor.org/rfc/rfc8077#section-6.4>
static INTERFACE_PARAMETER_CHILDREN: [FieldDescriptor; 5] = [
    FieldDescriptor::new("type", "Sub-TLV Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => interface_parameter_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("mtu", "Interface MTU", FieldType::U16).optional(),
    FieldDescriptor::new("description", "Interface Description", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static INTERFACE_PARAMETER: FieldDescriptor = named_by_type!(
    "interface_parameter",
    "Interface Parameter",
    U8,
    interface_parameter_name
)
.with_children(&INTERFACE_PARAMETER_CHILDREN);

/// Array of Interface Parameter sub-TLVs, used both in the PWid FEC element
/// and in the PW Interface Parameters TLV.
const INTERFACE_PARAMETERS: FieldDescriptor = FieldDescriptor::new(
    "interface_parameters",
    "Interface Parameters",
    FieldType::Array,
)
.optional()
.with_children(core::slice::from_ref(&INTERFACE_PARAMETER));

/// Child field indices of a FEC element.
const FE_TYPE: usize = 0;
const FE_ADDRESS_FAMILY: usize = 1;
const FE_PREFIX_LENGTH: usize = 2;
const FE_PREFIX: usize = 3;
const FE_C_BIT: usize = 4;
const FE_PW_TYPE: usize = 5;
const FE_PW_INFO_LENGTH: usize = 6;
const FE_GROUP_ID: usize = 7;
const FE_PW_ID: usize = 8;
const FE_INTERFACE_PARAMETERS: usize = 9;
const FE_AGI_TYPE: usize = 10;
const FE_AGI: usize = 11;
const FE_SAII_TYPE: usize = 12;
const FE_SAII: usize = 13;
const FE_TAII_TYPE: usize = 14;
const FE_TAII: usize = 15;
const FE_VALUE: usize = 16;

/// Child descriptors of a FEC element: the union of the Wildcard, Prefix,
/// PWid and Generalized PWid elements.
///
/// RFC 5036, Section 3.4.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.4.1>;
/// RFC 8077, Sections 6.1 and 6.2.2 — <https://www.rfc-editor.org/rfc/rfc8077#section-6.1>
static FEC_ELEMENT_CHILDREN: [FieldDescriptor; 17] = [
    FieldDescriptor::new("type", "FEC Element Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => fec_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("address_family", "Address Family", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(f) => address_family_name(*f),
            _ => None,
        }),
    FieldDescriptor::new("prefix_length", "PreLen", FieldType::U8).optional(),
    // Ipv4Addr or Ipv6Addr (padded with zeros); raw bytes for other families.
    FieldDescriptor::new("prefix", "Prefix", FieldType::Any).optional(),
    FieldDescriptor::new("c_bit", "Control Word (C)", FieldType::U8).optional(),
    FieldDescriptor::new("pw_type", "PW Type", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(t) => pw_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("pw_info_length", "PW Info Length", FieldType::U8).optional(),
    FieldDescriptor::new("group_id", "Group ID", FieldType::U32).optional(),
    FieldDescriptor::new("pw_id", "PW ID", FieldType::U32).optional(),
    INTERFACE_PARAMETERS,
    FieldDescriptor::new("agi_type", "AGI Type", FieldType::U8).optional(),
    FieldDescriptor::new("agi", "AGI Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("saii_type", "SAII Type", FieldType::U8).optional(),
    FieldDescriptor::new("saii", "SAII Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("taii_type", "TAII Type", FieldType::U8).optional(),
    FieldDescriptor::new("taii", "TAII Value", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static FEC_ELEMENT: FieldDescriptor =
    named_by_type!("fec_element", "FEC Element", U8, fec_type_name)
        .with_children(&FEC_ELEMENT_CHILDREN);

/// Child field indices of a TLV.
const T_U_BIT: usize = 0;
const T_F_BIT: usize = 1;
const T_TYPE: usize = 2;
const T_LENGTH: usize = 3;
const T_FEC_ELEMENTS: usize = 4;
const T_LABEL: usize = 5;
const T_ADDRESS_FAMILY: usize = 6;
const T_ADDRESSES: usize = 7;
const T_HOP_COUNT: usize = 8;
const T_LSR_IDS: usize = 9;
const T_STATUS_E_BIT: usize = 10;
const T_STATUS_F_BIT: usize = 11;
const T_STATUS_CODE: usize = 12;
const T_STATUS_MESSAGE_ID: usize = 13;
const T_STATUS_MESSAGE_TYPE: usize = 14;
const T_HOLD_TIME: usize = 15;
const T_TARGETED: usize = 16;
const T_REQUEST_TARGETED: usize = 17;
const T_GTSM: usize = 18;
const T_TRANSPORT_ADDRESS: usize = 19;
const T_CONFIGURATION_SEQUENCE_NUMBER: usize = 20;
const T_PROTOCOL_VERSION: usize = 21;
const T_KEEPALIVE_TIME: usize = 22;
const T_ADVERTISEMENT_DISCIPLINE: usize = 23;
const T_LOOP_DETECTION: usize = 24;
const T_PATH_VECTOR_LIMIT: usize = 25;
const T_MAX_PDU_LENGTH: usize = 26;
const T_RECEIVER_LSR_ID: usize = 27;
const T_RECEIVER_LABEL_SPACE: usize = 28;
const T_MESSAGE_ID: usize = 29;
const T_EXTENDED_STATUS: usize = 30;
const T_TRANSPORT_PREFERENCE: usize = 31;
const T_PW_STATUS: usize = 32;
const T_PW_GROUP_ID: usize = 33;
const T_INTERFACE_PARAMETERS: usize = 34;
const T_VENDOR_ID: usize = 35;
const T_VALUE: usize = 36;

/// Element descriptors of the address arrays.
static ADDRESS: FieldDescriptor = FieldDescriptor::new("address", "Address", FieldType::Any);
static LSR_ID: FieldDescriptor = FieldDescriptor::new("lsr_id", "LSR Id", FieldType::Ipv4Addr);

/// Child descriptors of a TLV: the TLV header and the union of the values
/// decoded by this dissector.
///
/// RFC 5036, Sections 3.3 and 3.4 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.3>
static TLV_CHILDREN: [FieldDescriptor; 37] = [
    FieldDescriptor::new("u_bit", "Unknown TLV (U)", FieldType::U8),
    FieldDescriptor::new("f_bit", "Forward Unknown TLV (F)", FieldType::U8),
    FieldDescriptor::new("type", "Type", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => tlv_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    // RFC 5036, Section 3.4.1 — FEC TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.4.1
    FieldDescriptor::new("fec_elements", "FEC Elements", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FEC_ELEMENT)),
    // RFC 5036, Section 3.4.2.1 — Generic Label TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.4.2.1
    FieldDescriptor::new("label", "Label", FieldType::U32).optional(),
    // RFC 5036, Section 3.4.3 — Address List TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.4.3
    FieldDescriptor::new("address_family", "Address Family", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(f) => address_family_name(*f),
            _ => None,
        }),
    FieldDescriptor::new("addresses", "Addresses", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&ADDRESS)),
    // RFC 5036, Sections 3.4.4 and 3.4.5 — Hop Count and Path Vector TLVs
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.4.4
    FieldDescriptor::new("hop_count", "HC Value", FieldType::U8).optional(),
    FieldDescriptor::new("lsr_ids", "LSR Ids", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&LSR_ID)),
    // RFC 5036, Section 3.4.6 — Status TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.4.6
    FieldDescriptor::new("status_e_bit", "Fatal Error (E)", FieldType::U8).optional(),
    FieldDescriptor::new("status_f_bit", "Forward (F)", FieldType::U8).optional(),
    FieldDescriptor::new("status_code", "Status Code", FieldType::U32)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U32(c) => status_code_name(*c),
            _ => None,
        }),
    FieldDescriptor::new("status_message_id", "Message ID", FieldType::U32).optional(),
    FieldDescriptor::new("status_message_type", "Message Type", FieldType::U16)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U16(t) => message_type_name(*t),
            _ => None,
        }),
    // RFC 5036, Section 3.5.2 — Common Hello Parameters TLV; RFC 6720,
    // Section 2.1 — G flag
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.5.2
    //   https://www.rfc-editor.org/rfc/rfc6720#section-2.1
    FieldDescriptor::new("hold_time", "Hold Time", FieldType::U16).optional(),
    FieldDescriptor::new("targeted", "Targeted Hello (T)", FieldType::U8).optional(),
    FieldDescriptor::new(
        "request_targeted",
        "Request Send Targeted Hellos (R)",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("gtsm", "GTSM (G)", FieldType::U8).optional(),
    // RFC 5036, Section 3.5.2 — IPv4 / IPv6 Transport Address TLVs
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.5.2
    FieldDescriptor::new("transport_address", "Transport Address", FieldType::Any).optional(),
    FieldDescriptor::new(
        "configuration_sequence_number",
        "Configuration Sequence Number",
        FieldType::U32,
    )
    .optional(),
    // RFC 5036, Section 3.5.3 — Common Session Parameters TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.5.3
    FieldDescriptor::new("protocol_version", "Protocol Version", FieldType::U16).optional(),
    FieldDescriptor::new("keepalive_time", "KeepAlive Time", FieldType::U16).optional(),
    FieldDescriptor::new(
        "advertisement_discipline",
        "Label Advertisement Discipline (A)",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(0) => Some("Downstream Unsolicited"),
        FieldValue::U8(1) => Some("Downstream On Demand"),
        _ => None,
    }),
    FieldDescriptor::new("loop_detection", "Loop Detection (D)", FieldType::U8).optional(),
    FieldDescriptor::new("path_vector_limit", "PVLim", FieldType::U8).optional(),
    FieldDescriptor::new("max_pdu_length", "Max PDU Length", FieldType::U16).optional(),
    FieldDescriptor::new("receiver_lsr_id", "Receiver LSR Id", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new(
        "receiver_label_space",
        "Receiver Label Space",
        FieldType::U16,
    )
    .optional(),
    // RFC 5036, Section 3.5.7 — Label Request Message ID TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.5.7
    FieldDescriptor::new("message_id", "Message ID", FieldType::U32).optional(),
    // RFC 5036, Section 3.5.1 — Extended Status TLV
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.5.1
    FieldDescriptor::new("extended_status", "Extended Status", FieldType::U32).optional(),
    // RFC 7552, Section 6.1.1 — Dual-Stack capability TLV
    //   https://www.rfc-editor.org/rfc/rfc7552#section-6.1.1
    FieldDescriptor::new(
        "transport_preference",
        "Transport Connection Preference (TR)",
        FieldType::U8,
    )
    .optional()
    .with_display_fn(|v, _| match v {
        FieldValue::U8(p) => transport_preference_name(*p),
        _ => None,
    }),
    // RFC 8077, Sections 6.3.2, 6.2.2.2 and 6.2.2.1 — PW Status, PW Group
    // ID and PW Interface Parameters TLVs
    //   https://www.rfc-editor.org/rfc/rfc8077#section-6.3.2
    //   https://www.rfc-editor.org/rfc/rfc8077#section-6.2.2.2
    FieldDescriptor::new("pw_status", "Status Code", FieldType::U32).optional(),
    FieldDescriptor::new("pw_group_id", "PW Group ID", FieldType::U32).optional(),
    INTERFACE_PARAMETERS,
    // RFC 5036, Sections 3.6.1.1 and 3.6.2 — Vendor ID / Experiment ID of
    // vendor-private and experimental TLVs
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.6.1.1
    FieldDescriptor::new("vendor_id", "Vendor ID / Experiment ID", FieldType::U32).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

static TLV: FieldDescriptor =
    named_by_type!("tlv", "TLV", U16, tlv_type_name).with_children(&TLV_CHILDREN);

/// Child field indices of a message.
const M_U_BIT: usize = 0;
const M_TYPE: usize = 1;
const M_LENGTH: usize = 2;
const M_MESSAGE_ID: usize = 3;
const M_VENDOR_ID: usize = 4;
const M_TLVS: usize = 5;
const M_DATA: usize = 6;

/// Child descriptors of a message.
/// RFC 5036, Section 3.5 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.5>
static MESSAGE_CHILDREN: [FieldDescriptor; 7] = [
    FieldDescriptor::new("u_bit", "Unknown Message (U)", FieldType::U8),
    FieldDescriptor::new("type", "Message Type", FieldType::U16).with_display_fn(|v, _| match v {
        FieldValue::U16(t) => message_type_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Message Length", FieldType::U16),
    FieldDescriptor::new("message_id", "Message ID", FieldType::U32),
    // RFC 5036, Sections 3.6.1.2 and 3.6.2 — Vendor ID / Experiment ID
    //   https://www.rfc-editor.org/rfc/rfc5036#section-3.6.1.2
    FieldDescriptor::new("vendor_id", "Vendor ID / Experiment ID", FieldType::U32).optional(),
    FieldDescriptor::new("tlvs", "Parameters", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&TLV)),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

static MESSAGE: FieldDescriptor =
    named_by_type!("message", "Message", U16, message_type_name).with_children(&MESSAGE_CHILDREN);

/// Field descriptor indices into [`FIELD_DESCRIPTORS`].
const FD_VERSION: usize = 0;
const FD_PDU_LENGTH: usize = 1;
const FD_LSR_ID: usize = 2;
const FD_LABEL_SPACE: usize = 3;
const FD_MESSAGES: usize = 4;
const FD_DATA: usize = 5;

/// Field descriptors for the LDP dissector.
///
/// RFC 5036, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.1>
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U16),
    FieldDescriptor::new("pdu_length", "PDU Length", FieldType::U16),
    FieldDescriptor::new("lsr_id", "LSR Id", FieldType::Ipv4Addr),
    FieldDescriptor::new("label_space", "Label Space Id", FieldType::U16),
    FieldDescriptor::new("messages", "Messages", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&MESSAGE)),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
];

/// Specification references for the LDP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 5036",
        "LDP Specification",
        "https://www.rfc-editor.org/rfc/rfc5036",
    ),
    SpecReference::new(
        "RFC 6720",
        "The Generalized TTL Security Mechanism (GTSM) for the Label Distribution Protocol (LDP)",
        "https://www.rfc-editor.org/rfc/rfc6720",
    ),
    SpecReference::new(
        "RFC 7552",
        "Updates to LDP for IPv6",
        "https://www.rfc-editor.org/rfc/rfc7552",
    ),
    SpecReference::new(
        "RFC 8077",
        "Pseudowire Setup and Maintenance Using the Label Distribution Protocol (LDP)",
        "https://www.rfc-editor.org/rfc/rfc8077",
    ),
    SpecReference::new(
        "IANA LDP Parameters",
        "Label Distribution Protocol (LDP) Parameters",
        "https://www.iana.org/assignments/ldp-namespaces/ldp-namespaces.xhtml",
    ),
    SpecReference::new(
        "IANA PWE3 Parameters",
        "Pseudowire Name Spaces (PWE3)",
        "https://www.iana.org/assignments/pwe3-parameters/pwe3-parameters.xhtml",
    ),
];

/// Reads a big-endian `u16` at a position the caller has bounds-checked.
fn u16_at(data: &[u8], pos: usize) -> u16 {
    read_be_u16(data, pos).unwrap_or_default()
}

/// Reads a big-endian `u32` at a position the caller has bounds-checked.
fn u32_at(data: &[u8], pos: usize) -> u32 {
    read_be_u32(data, pos).unwrap_or_default()
}

/// Returns the address `bytes` of `family` as a field value: IPv4 / IPv6
/// when the length matches, raw bytes otherwise.
fn address_value(family: u16, bytes: &[u8]) -> FieldValue<'_> {
    match (family, bytes.len()) {
        (AF_IPV4, 4) => FieldValue::Ipv4Addr([bytes[0], bytes[1], bytes[2], bytes[3]]),
        (AF_IPV6, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            FieldValue::Ipv6Addr(a)
        }
        _ => FieldValue::Bytes(bytes),
    }
}

/// Returns the length of the address of `family`.
fn address_len(family: u16) -> Option<usize> {
    match family {
        AF_IPV4 => Some(4),
        AF_IPV6 => Some(16),
        _ => None,
    }
}

/// Pushes the Interface Parameter sub-TLVs in `data` into the array
/// `descriptor`. "The Length field is defined as the length of the
/// interface parameter including the Sub-TLV Type and Length field itself."
/// Sub-TLVs that do not fit are kept in a trailing `value` element.
///
/// RFC 8077, Section 6.4 — <https://www.rfc-editor.org/rfc/rfc8077#section-6.4>
fn push_interface_parameters<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    data: &'pkt [u8],
    offset: usize,
) {
    if data.is_empty() {
        return;
    }
    let c = &INTERFACE_PARAMETER_CHILDREN;
    let array = buf.begin_container(
        descriptor,
        FieldValue::Array(0..0),
        offset..offset + data.len(),
    );
    let mut pos = 0;
    while pos < data.len() {
        let abs = offset + pos;
        let t = data[pos];
        let len = data.get(pos + 1).map_or(0, |&l| usize::from(l));
        let complete = len >= 2 && pos + len <= data.len();
        let end = if complete { pos + len } else { data.len() };
        let obj = buf.begin_container(
            &INTERFACE_PARAMETER,
            FieldValue::Object(0..0),
            abs..offset + end,
        );
        buf.push_field(&c[IP_TYPE], FieldValue::U8(t), abs..abs + 1);
        if pos + 1 < data.len() {
            buf.push_field(
                &c[IP_LENGTH],
                FieldValue::U8(data[pos + 1]),
                abs + 1..abs + 2,
            );
        }
        let value_start = (pos + 2).min(end);
        let value = &data[value_start..end];
        let r = offset + value_start..offset + end;
        match (t, complete, value.len()) {
            (SUB_TLV_MTU, true, 2) => {
                buf.push_field(&c[IP_MTU], FieldValue::U16(u16_at(value, 0)), r);
            }
            (SUB_TLV_DESCRIPTION, true, _) => {
                buf.push_field(&c[IP_DESCRIPTION], FieldValue::Bytes(value), r);
            }
            (_, _, 0) => {}
            _ => buf.push_field(&c[IP_VALUE], FieldValue::Bytes(value), r),
        }
        buf.end_container(obj);
        pos = end;
    }
    buf.end_container(array);
}

/// Returns the length of the FEC element at `data[pos..]`, or `None` when
/// its type is not decoded or it does not fit.
///
/// RFC 5036, Section 3.4.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.4.1>;
/// RFC 8077, Sections 6.1 and 6.2.2 — <https://www.rfc-editor.org/rfc/rfc8077#section-6.1>
fn fec_element_len(data: &[u8], pos: usize) -> Option<usize> {
    let len = match *data.get(pos)? {
        FEC_WILDCARD => 1,
        // |  Prefix (2)   |     Address Family            |     PreLen    |
        FEC_PREFIX => {
            let family = u16::from_be_bytes([*data.get(pos + 1)?, *data.get(pos + 2)?]);
            let prefix_len = usize::from(*data.get(pos + 3)?);
            let bytes = prefix_len.div_ceil(8);
            if address_len(family).is_some_and(|max| bytes > max) {
                return None;
            }
            4 + bytes
        }
        // |  PWid (0x80)  |C|         PW type             |PW info length |
        // Group ID, then "Length of the PW ID field and the Interface
        // Parameter Sub-TLV field in octets".
        FEC_PWID => 8 + usize::from(*data.get(pos + 3)?),
        // |Gen PWid (0x81)|C|         PW Type             |PW info length |
        // then AGI, SAII and TAII, each Type (1), Length (1), Value.
        // "The PW information length field contains the length of the
        // SAII, TAII, and AGI, combined in octets."
        FEC_GENERALIZED_PWID => 4 + usize::from(*data.get(pos + 3)?),
        _ => return None,
    };
    (pos + len <= data.len()).then_some(len)
}

/// Pushes the FEC element of length `len` at `data[pos..]`.
fn push_fec_element<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    len: usize,
    offset: usize,
) {
    let c = &FEC_ELEMENT_CHILDREN;
    let abs = offset + pos;
    let r = |from: usize, to: usize| offset + from..offset + to;
    let t = data[pos];
    let obj = buf.begin_container(&FEC_ELEMENT, FieldValue::Object(0..0), abs..abs + len);
    buf.push_field(&c[FE_TYPE], FieldValue::U8(t), abs..abs + 1);
    match t {
        FEC_PREFIX => {
            let family = u16_at(data, pos + 1);
            buf.push_field(
                &c[FE_ADDRESS_FAMILY],
                FieldValue::U16(family),
                r(pos + 1, pos + 3),
            );
            buf.push_field(
                &c[FE_PREFIX_LENGTH],
                FieldValue::U8(data[pos + 3]),
                r(pos + 3, pos + 4),
            );
            let prefix = &data[pos + 4..pos + len];
            // "padded to a byte boundary": shown as a full address.
            let value = match address_len(family) {
                Some(n) => {
                    let mut a = [0u8; 16];
                    a[..prefix.len()].copy_from_slice(prefix);
                    if n == 4 {
                        FieldValue::Ipv4Addr([a[0], a[1], a[2], a[3]])
                    } else {
                        FieldValue::Ipv6Addr(a)
                    }
                }
                None => FieldValue::Bytes(prefix),
            };
            buf.push_field(&c[FE_PREFIX], value, r(pos + 4, pos + len));
        }
        FEC_PWID | FEC_GENERALIZED_PWID => {
            let word = u16_at(data, pos + 1);
            buf.push_field(
                &c[FE_C_BIT],
                FieldValue::U8((word >> 15) as u8),
                r(pos + 1, pos + 2),
            );
            buf.push_field(
                &c[FE_PW_TYPE],
                FieldValue::U16(word & 0x7FFF),
                r(pos + 1, pos + 3),
            );
            buf.push_field(
                &c[FE_PW_INFO_LENGTH],
                FieldValue::U8(data[pos + 3]),
                r(pos + 3, pos + 4),
            );
            if t == FEC_PWID {
                buf.push_field(
                    &c[FE_GROUP_ID],
                    FieldValue::U32(u32_at(data, pos + 4)),
                    r(pos + 4, pos + 8),
                );
                if len >= 12 {
                    buf.push_field(
                        &c[FE_PW_ID],
                        FieldValue::U32(u32_at(data, pos + 8)),
                        r(pos + 8, pos + 12),
                    );
                    push_interface_parameters(
                        buf,
                        &c[FE_INTERFACE_PARAMETERS],
                        &data[pos + 12..pos + len],
                        offset + pos + 12,
                    );
                } else if len > 8 {
                    buf.push_field(
                        &c[FE_VALUE],
                        FieldValue::Bytes(&data[pos + 8..pos + len]),
                        r(pos + 8, pos + len),
                    );
                }
            } else {
                // AGI, SAII and TAII, each Type (1), Length (1), Value,
                // within the PW info length; octets that do not form them are
                // kept as `value`.
                let end = pos + len;
                let mut p = pos + 4;
                for (type_fd, value_fd) in [
                    (FE_AGI_TYPE, FE_AGI),
                    (FE_SAII_TYPE, FE_SAII),
                    (FE_TAII_TYPE, FE_TAII),
                ] {
                    let Some(&n) = data[..end].get(p + 1) else {
                        break;
                    };
                    let value_end = p + 2 + usize::from(n);
                    if value_end > end {
                        break;
                    }
                    buf.push_field(&c[type_fd], FieldValue::U8(data[p]), r(p, p + 1));
                    buf.push_field(
                        &c[value_fd],
                        FieldValue::Bytes(&data[p + 2..value_end]),
                        r(p + 2, value_end),
                    );
                    p = value_end;
                }
                if p < end {
                    buf.push_field(&c[FE_VALUE], FieldValue::Bytes(&data[p..end]), r(p, end));
                }
            }
        }
        _ => {}
    }
    buf.end_container(obj);
}

/// Pushes the value of a FEC TLV: the FEC elements that can be decoded,
/// then the rest as `value`.
///
/// RFC 5036, Section 3.4.1 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.4.1>
fn push_fec_tlv<'pkt>(buf: &mut DissectBuffer<'pkt>, value: &'pkt [u8], offset: usize) {
    let mut end = 0;
    while let Some(len) = fec_element_len(value, end) {
        end += len;
    }
    if end > 0 {
        let array = buf.begin_container(
            &TLV_CHILDREN[T_FEC_ELEMENTS],
            FieldValue::Array(0..0),
            offset..offset + end,
        );
        let mut pos = 0;
        while let Some(len) = fec_element_len(value, pos) {
            push_fec_element(buf, value, pos, len, offset);
            pos += len;
        }
        buf.end_container(array);
    }
    if end < value.len() {
        buf.push_field(
            &TLV_CHILDREN[T_VALUE],
            FieldValue::Bytes(&value[end..]),
            offset + end..offset + value.len(),
        );
    }
}

/// Pushes a list of fixed-size items as the array `descriptor` of
/// `element` values, then any remainder as `value`.
fn push_list<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    descriptor: &'static FieldDescriptor,
    element: &'static FieldDescriptor,
    value: &'pkt [u8],
    offset: usize,
    size: usize,
    make: fn(&'pkt [u8]) -> FieldValue<'pkt>,
) {
    let end = value.len() - value.len() % size;
    if end > 0 {
        let array = buf.begin_container(descriptor, FieldValue::Array(0..0), offset..offset + end);
        for (i, item) in value[..end].chunks_exact(size).enumerate() {
            let at = offset + i * size;
            buf.push_field(element, make(item), at..at + size);
        }
        buf.end_container(array);
    }
    if end < value.len() {
        buf.push_field(
            &TLV_CHILDREN[T_VALUE],
            FieldValue::Bytes(&value[end..]),
            offset + end..offset + value.len(),
        );
    }
}

/// Pushes the value of one TLV of type `t`.
///
/// RFC 5036, Section 3.4 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.4>
fn push_tlv_value<'pkt>(buf: &mut DissectBuffer<'pkt>, t: u16, value: &'pkt [u8], offset: usize) {
    let c = &TLV_CHILDREN;
    let r = |from: usize, to: usize| offset + from..offset + to;
    match (t, value.len()) {
        (TLV_FEC, _) => push_fec_tlv(buf, value, offset),
        // "This is a 20-bit label value represented as a 20-bit number in a
        // 4 octet field" (RFC 5036, Section 3.4.2.1 —
        // https://www.rfc-editor.org/rfc/rfc5036#section-3.4.2.1). LDP
        // speakers put the number in the low-order 20 bits (a label of 16
        // is 00 00 00 10), so the other 12 bits are masked off.
        (TLV_GENERIC_LABEL, 4) => {
            buf.push_field(
                &c[T_LABEL],
                FieldValue::U32(u32_at(value, 0) & 0x000F_FFFF),
                r(0, 4),
            );
        }
        // |        Address Family         |  Addresses...
        (TLV_ADDRESS_LIST, n) if n >= 2 => {
            let family = u16_at(value, 0);
            buf.push_field(&c[T_ADDRESS_FAMILY], FieldValue::U16(family), r(0, 2));
            match address_len(family) {
                Some(size) => push_list(
                    buf,
                    &c[T_ADDRESSES],
                    &ADDRESS,
                    &value[2..],
                    offset + 2,
                    size,
                    |b| address_value(if b.len() == 4 { AF_IPV4 } else { AF_IPV6 }, b),
                ),
                None if n > 2 => {
                    buf.push_field(&c[T_VALUE], FieldValue::Bytes(&value[2..]), r(2, n));
                }
                None => {}
            }
        }
        (TLV_HOP_COUNT, 1) => buf.push_field(&c[T_HOP_COUNT], FieldValue::U8(value[0]), r(0, 1)),
        (TLV_PATH_VECTOR, _) => push_list(buf, &c[T_LSR_IDS], &LSR_ID, value, offset, 4, |b| {
            FieldValue::Ipv4Addr([b[0], b[1], b[2], b[3]])
        }),
        // |U|F| Status (0x0300)| Length | Status Code | Message ID | Message Type |
        // Status Code: |E|F|                 Status Data                       |
        // (RFC 5036, Section 3.4.6 — https://www.rfc-editor.org/rfc/rfc5036#section-3.4.6)
        (TLV_STATUS, 10) => {
            let code = u32_at(value, 0);
            buf.push_field(
                &c[T_STATUS_E_BIT],
                FieldValue::U8((code >> 31) as u8),
                r(0, 1),
            );
            buf.push_field(
                &c[T_STATUS_F_BIT],
                FieldValue::U8(((code >> 30) & 1) as u8),
                r(0, 1),
            );
            buf.push_field(
                &c[T_STATUS_CODE],
                FieldValue::U32(code & 0x3FFF_FFFF),
                r(0, 4),
            );
            buf.push_field(
                &c[T_STATUS_MESSAGE_ID],
                FieldValue::U32(u32_at(value, 4)),
                r(4, 8),
            );
            buf.push_field(
                &c[T_STATUS_MESSAGE_TYPE],
                FieldValue::U16(u16_at(value, 8)),
                r(8, 10),
            );
        }
        // |      Hold Time                |T|R|G|   Reserved              |
        (TLV_COMMON_HELLO_PARAMETERS, 4) => {
            buf.push_field(&c[T_HOLD_TIME], FieldValue::U16(u16_at(value, 0)), r(0, 2));
            for (fd, shift) in [(T_TARGETED, 7), (T_REQUEST_TARGETED, 6), (T_GTSM, 5)] {
                buf.push_field(&c[fd], FieldValue::U8((value[2] >> shift) & 1), r(2, 3));
            }
        }
        (TLV_IPV4_TRANSPORT_ADDRESS, 4) | (TLV_IPV6_TRANSPORT_ADDRESS, 16) => {
            let family = if t == TLV_IPV4_TRANSPORT_ADDRESS {
                AF_IPV4
            } else {
                AF_IPV6
            };
            buf.push_field(
                &c[T_TRANSPORT_ADDRESS],
                address_value(family, value),
                r(0, value.len()),
            );
        }
        (TLV_CONFIGURATION_SEQUENCE_NUMBER, 4) => {
            buf.push_field(
                &c[T_CONFIGURATION_SEQUENCE_NUMBER],
                FieldValue::U32(u32_at(value, 0)),
                r(0, 4),
            );
        }
        // | Protocol Version | KeepAlive Time | A|D| Reserved | PVLim | Max PDU Length |
        // | Receiver LDP Identifier |
        (TLV_COMMON_SESSION_PARAMETERS, 14) => {
            buf.push_field(
                &c[T_PROTOCOL_VERSION],
                FieldValue::U16(u16_at(value, 0)),
                r(0, 2),
            );
            buf.push_field(
                &c[T_KEEPALIVE_TIME],
                FieldValue::U16(u16_at(value, 2)),
                r(2, 4),
            );
            buf.push_field(
                &c[T_ADVERTISEMENT_DISCIPLINE],
                FieldValue::U8(value[4] >> 7),
                r(4, 5),
            );
            buf.push_field(
                &c[T_LOOP_DETECTION],
                FieldValue::U8((value[4] >> 6) & 1),
                r(4, 5),
            );
            buf.push_field(&c[T_PATH_VECTOR_LIMIT], FieldValue::U8(value[5]), r(5, 6));
            buf.push_field(
                &c[T_MAX_PDU_LENGTH],
                FieldValue::U16(u16_at(value, 6)),
                r(6, 8),
            );
            buf.push_field(
                &c[T_RECEIVER_LSR_ID],
                FieldValue::Ipv4Addr([value[8], value[9], value[10], value[11]]),
                r(8, 12),
            );
            buf.push_field(
                &c[T_RECEIVER_LABEL_SPACE],
                FieldValue::U16(u16_at(value, 12)),
                r(12, 14),
            );
        }
        (TLV_LABEL_REQUEST_MESSAGE_ID, 4) => {
            buf.push_field(&c[T_MESSAGE_ID], FieldValue::U32(u32_at(value, 0)), r(0, 4));
        }
        (TLV_EXTENDED_STATUS, 4) => {
            buf.push_field(
                &c[T_EXTENDED_STATUS],
                FieldValue::U32(u32_at(value, 0)),
                r(0, 4),
            );
        }
        // |TR     |        Reserved       |     MBZ                       |
        (TLV_DUAL_STACK_CAPABILITY, 4) => {
            buf.push_field(
                &c[T_TRANSPORT_PREFERENCE],
                FieldValue::U8(value[0] >> 4),
                r(0, 1),
            );
        }
        (TLV_PW_STATUS, 4) => {
            buf.push_field(&c[T_PW_STATUS], FieldValue::U32(u32_at(value, 0)), r(0, 4))
        }
        (TLV_PW_GROUP_ID, 4) => buf.push_field(
            &c[T_PW_GROUP_ID],
            FieldValue::U32(u32_at(value, 0)),
            r(0, 4),
        ),
        (TLV_PW_INTERFACE_PARAMETERS, _) => {
            push_interface_parameters(buf, &c[T_INTERFACE_PARAMETERS], value, offset);
        }
        // Vendor-private and experimental TLVs start with a Vendor ID or an
        // Experiment ID (RFC 5036, Sections 3.6.1.1 and 3.6.2 —
        // https://www.rfc-editor.org/rfc/rfc5036#section-3.6.1.1).
        (0x3E00..=0x3FFF, n) if n >= 4 => {
            buf.push_field(&c[T_VENDOR_ID], FieldValue::U32(u32_at(value, 0)), r(0, 4));
            if n > 4 {
                buf.push_field(&c[T_VALUE], FieldValue::Bytes(&value[4..]), r(4, n));
            }
        }
        (_, 0) => {}
        _ => buf.push_field(&c[T_VALUE], FieldValue::Bytes(value), r(0, value.len())),
    }
}

/// Returns the end of the TLVs that fit completely in `data[start..end]`.
fn complete_tlvs_end(data: &[u8], start: usize, end: usize) -> usize {
    let mut pos = start;
    while pos + TLV_HEADER_SIZE <= end {
        let next = pos + TLV_HEADER_SIZE + usize::from(u16_at(data, pos + 2));
        if next > end {
            break;
        }
        pos = next;
    }
    pos
}

/// Pushes the message at `data[pos..end]`, whose header has been checked.
///
/// RFC 5036, Section 3.5 — <https://www.rfc-editor.org/rfc/rfc5036#section-3.5>
fn push_message<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    pos: usize,
    end: usize,
    offset: usize,
) {
    let c = &MESSAGE_CHILDREN;
    let abs = offset + pos;
    let word = u16_at(data, pos);
    let obj = buf.begin_container(&MESSAGE, FieldValue::Object(0..0), abs..offset + end);
    buf.push_field(
        &c[M_U_BIT],
        FieldValue::U8((word >> 15) as u8),
        abs..abs + 1,
    );
    buf.push_field(&c[M_TYPE], FieldValue::U16(word & 0x7FFF), abs..abs + 2);
    buf.push_field(
        &c[M_LENGTH],
        FieldValue::U16(u16_at(data, pos + 2)),
        abs + 2..abs + 4,
    );
    buf.push_field(
        &c[M_MESSAGE_ID],
        FieldValue::U32(u32_at(data, pos + 4)),
        abs + 4..abs + 8,
    );
    let mut start = pos + MESSAGE_HEADER_SIZE;
    // Vendor-private and experimental messages carry a Vendor ID or an
    // Experiment ID before their parameters (RFC 5036, Sections 3.6.1.2 and
    // 3.6.2 — https://www.rfc-editor.org/rfc/rfc5036#section-3.6.1.2).
    if (0x3E00..=0x3FFF).contains(&(word & 0x7FFF)) && start + 4 <= end {
        buf.push_field(
            &c[M_VENDOR_ID],
            FieldValue::U32(u32_at(data, start)),
            offset + start..offset + start + 4,
        );
        start += 4;
    }
    let tlvs_end = complete_tlvs_end(data, start, end);
    if tlvs_end > start {
        let t = &TLV_CHILDREN;
        let array = buf.begin_container(
            &c[M_TLVS],
            FieldValue::Array(0..0),
            offset + start..offset + tlvs_end,
        );
        let mut p = start;
        while p < tlvs_end {
            let word = u16_at(data, p);
            let len = usize::from(u16_at(data, p + 2));
            let a = offset + p;
            let tlv_type = word & 0x3FFF;
            let tlv =
                buf.begin_container(&TLV, FieldValue::Object(0..0), a..a + TLV_HEADER_SIZE + len);
            buf.push_field(&t[T_U_BIT], FieldValue::U8((word >> 15) as u8), a..a + 1);
            buf.push_field(
                &t[T_F_BIT],
                FieldValue::U8(((word >> 14) & 1) as u8),
                a..a + 1,
            );
            buf.push_field(&t[T_TYPE], FieldValue::U16(tlv_type), a..a + 2);
            buf.push_field(&t[T_LENGTH], FieldValue::U16(len as u16), a + 2..a + 4);
            let value_start = p + TLV_HEADER_SIZE;
            push_tlv_value(
                buf,
                tlv_type,
                &data[value_start..value_start + len],
                offset + value_start,
            );
            buf.end_container(tlv);
            p = value_start + len;
        }
        buf.end_container(array);
    }
    if tlvs_end < end {
        buf.push_field(
            &c[M_DATA],
            FieldValue::Bytes(&data[tlvs_end..end]),
            offset + tlvs_end..offset + end,
        );
    }
    buf.end_container(obj);
}

/// Returns the end of the complete messages in `data[PDU_HEADER_SIZE..end]`.
fn complete_messages_end(data: &[u8], end: usize) -> usize {
    let mut pos = PDU_HEADER_SIZE;
    while pos + MESSAGE_HEADER_SIZE <= end {
        // "Message Length: Specifies the cumulative length in octets of the
        // Message ID, Mandatory Parameters, and Optional Parameters."
        let len = usize::from(u16_at(data, pos + 2));
        let next = pos + 4 + len;
        if len < 4 || next > end {
            break;
        }
        pos = next;
    }
    pos
}

/// LDP dissector.
///
/// Dissects one LDP PDU per call and returns its total length (PDU Length
/// plus 4) as `bytes_consumed`. A PDU longer than `data` is reported as
/// [`PacketError::Truncated`] before anything is pushed. Messages and TLVs
/// that overrun their container are kept as raw `data`.
pub struct LdpDissector;

impl Dissector for LdpDissector {
    fn name(&self) -> &'static str {
        "Label Distribution Protocol"
    }

    fn short_name(&self) -> &'static str {
        "LDP"
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
        if data.len() < PDU_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: PDU_HEADER_SIZE,
                actual: data.len(),
            });
        }
        // RFC 5036, Section 3.1 — | Version | PDU Length | LDP Identifier |
        //   https://www.rfc-editor.org/rfc/rfc5036#section-3.1
        let version = u16_at(data, 0);
        if version != VERSION_1 {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        let pdu_length = u16_at(data, 2);
        let total = usize::from(pdu_length) + PDU_LENGTH_EXCLUDED;
        if total < PDU_HEADER_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "pdu_length",
                value: u32::from(pdu_length),
            });
        }
        if data.len() < total {
            return Err(PacketError::Truncated {
                expected: total,
                actual: data.len(),
            });
        }

        let d = FIELD_DESCRIPTORS;
        buf.begin_layer(self.short_name(), None, d, offset..offset + total);
        buf.push_field(&d[FD_VERSION], FieldValue::U16(version), offset..offset + 2);
        buf.push_field(
            &d[FD_PDU_LENGTH],
            FieldValue::U16(pdu_length),
            offset + 2..offset + 4,
        );
        // RFC 5036, Section 3.1 — "The first four octets identify the LSR
        // and MUST be a globally unique value" and the last two octets
        // identify a label space within the LSR.
        //   https://www.rfc-editor.org/rfc/rfc5036#section-3.1
        buf.push_field(
            &d[FD_LSR_ID],
            FieldValue::Ipv4Addr([data[4], data[5], data[6], data[7]]),
            offset + 4..offset + 8,
        );
        buf.push_field(
            &d[FD_LABEL_SPACE],
            FieldValue::U16(u16_at(data, 8)),
            offset + 8..offset + 10,
        );

        let messages_end = complete_messages_end(data, total);
        if messages_end > PDU_HEADER_SIZE {
            let array = buf.begin_container(
                &d[FD_MESSAGES],
                FieldValue::Array(0..0),
                offset + PDU_HEADER_SIZE..offset + messages_end,
            );
            let mut pos = PDU_HEADER_SIZE;
            while pos < messages_end {
                let end = pos + 4 + usize::from(u16_at(data, pos + 2));
                push_message(buf, data, pos, end, offset);
                pos = end;
            }
            buf.end_container(array);
        }
        if messages_end < total {
            buf.push_field(
                &d[FD_DATA],
                FieldValue::Bytes(&data[messages_end..total]),
                offset + messages_end..offset + total,
            );
        }
        buf.end_layer();
        Ok(DissectResult::new(total, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 5036 (LDP) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 3.1 | PDU header (version, PDU length, LDP Identifier) | `parse_link_hello` |
    //! | 3.1 | Version other than 1 rejected | `reject_unsupported_version` |
    //! | 3.1 | PDU Length below the header size rejected | `reject_short_pdu_length` |
    //! | 3.1 | PDU longer than the data is Truncated | `truncated_pdu`, `truncated_header` |
    //! | 3.1 | One PDU per call; bytes after it are left alone | `consumes_one_pdu` |
    //! | 3.1 | Several messages in one PDU | `two_messages_in_one_pdu` |
    //! | 3.3 | TLV header (U, F bits, type, length) | `parse_link_hello` |
    //! | 3.3 | TLV overrunning its message kept as data | `tlv_overrun_kept_as_data` |
    //! | 3.4.1 | FEC TLV with Prefix FEC elements (IPv4, IPv6, /0) | `parse_label_mapping_prefix` |
    //! | 3.4.1 | Wildcard FEC element | `parse_label_withdraw_wildcard` |
    //! | 3.4.1 | Unknown FEC element type kept as value | `unknown_fec_element_kept_as_value` |
    //! | 3.4.2.1 | Generic Label TLV | `parse_label_mapping_prefix` |
    //! | 3.4.3 | Address List TLV (Address message) | `parse_address_message` |
    //! | 3.4.4, 3.4.5 | Hop Count and Path Vector TLVs | `parse_label_mapping_prefix` |
    //! | 3.4.6 | Status TLV (Notification) | `parse_notification_status` |
    //! | 3.5 | Message header (U bit, type, length, Message ID) | `parse_link_hello` |
    //! | 3.5 | Message overrunning the PDU kept as data | `message_overrun_kept_as_data` |
    //! | 3.5.1 | Extended Status TLV | `parse_notification_status` |
    //! | 3.5.2 | Link Hello: Common Hello Parameters, IPv4 Transport Address, Configuration Sequence Number | `parse_link_hello` |
    //! | 3.5.2 | Targeted Hello (T and R bits), IPv6 Transport Address | `parse_targeted_hello_ipv6` |
    //! | 3.5.3 | Initialization: Common Session Parameters | `parse_initialization` |
    //! | 3.5.4 | KeepAlive | `two_messages_in_one_pdu` |
    //! | 3.5.7, 3.5.9 | Label Request Message ID TLV (Label Abort Request) | `parse_label_abort_request` |
    //! | 3.6.1.2 | Vendor-private message with Vendor ID | `vendor_private_message` |
    //! | 3.6.1.1, 3.6.2 | Vendor-private / experimental TLVs with Vendor / Experiment ID | `parse_label_abort_request` |
    //!
    //! # RFC 6720 (GTSM) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 2.1 | G flag in Common Hello Parameters | `parse_link_hello` |
    //!
    //! # RFC 7552 (LDP for IPv6) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 6.1.1 | Dual-Stack capability TLV | `parse_targeted_hello_ipv6` |
    //!
    //! # RFC 8077 (Pseudowires) Coverage
    //!
    //! | RFC Section | Description | Test |
    //! |-------------|-------------|------|
    //! | 6.1 | PWid FEC element with Interface Parameter sub-TLVs | `parse_label_mapping_pwid` |
    //! | 6.1 | PWid FEC element with PW info length 0 | `parse_pwid_wildcard` |
    //! | 6.2.2 | Generalized PWid FEC element (AGI, SAII, TAII) | `parse_label_mapping_generalized_pwid` |
    //! | 6.2.2.1, 6.2.2.2 | PW Interface Parameters and PW Group ID TLVs | `parse_label_mapping_generalized_pwid` |
    //! | 6.3.2 | PW Status TLV | `parse_label_mapping_generalized_pwid` |
    //! | 6.4 | Truncated Interface Parameter sub-TLV kept as value | `parse_label_mapping_pwid` |

    use super::*;
    use packet_dissector_core::field::Field;

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = LdpDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    /// Direct children of the container `field`.
    fn children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        field: &Field<'pkt>,
    ) -> Vec<&'a Field<'pkt>> {
        let (FieldValue::Array(r) | FieldValue::Object(r)) = &field.value else {
            panic!("{} is not a container", field.name());
        };
        direct(buf, r.start, r.end)
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

    fn display(buf: &DissectBuffer<'_>, field: &Field<'_>) -> Option<&'static str> {
        let siblings = match &field.value {
            FieldValue::Array(r) | FieldValue::Object(r) => buf.nested_fields(r),
            _ => &[],
        };
        (field.descriptor.display_fn?)(&field.value, siblings)
    }

    /// The messages of the PDU, each as its list of direct children.
    fn messages<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<Vec<&'a Field<'pkt>>> {
        let array = top(buf, "messages").expect("messages");
        children(buf, array)
            .into_iter()
            .map(|m| children(buf, m))
            .collect()
    }

    /// The TLVs of `message`, each as its list of direct children.
    fn tlvs<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        message: &[&'a Field<'pkt>],
    ) -> Vec<Vec<&'a Field<'pkt>>> {
        children(buf, child(message, "tlvs"))
            .into_iter()
            .map(|t| children(buf, t))
            .collect()
    }

    fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    fn message(t: u16, id: u32, tlvs: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&((4 + tlvs.len()) as u16).to_be_bytes());
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(tlvs);
        v
    }

    fn pdu(messages: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 1];
        v.extend_from_slice(&((6 + messages.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[10, 0, 0, 1, 0, 0]);
        v.extend_from_slice(messages);
        v
    }

    #[test]
    fn parse_link_hello() {
        let mut params = tlv(TLV_COMMON_HELLO_PARAMETERS, &[0, 15, 0x20, 0]); // G=1
        params.extend(tlv(TLV_IPV4_TRANSPORT_ADDRESS, &[10, 0, 0, 1]));
        params.extend(tlv(TLV_CONFIGURATION_SEQUENCE_NUMBER, &7u32.to_be_bytes()));
        let data = pdu(&message(0x0100, 1, &params));
        let (buf, result) = dissect(&data);

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        let l = &buf.layers()[0];
        assert_eq!(l.name, "LDP");
        assert_eq!(l.range, 0..data.len());
        assert_eq!(top(&buf, "version").unwrap().value, FieldValue::U16(1));
        assert_eq!(
            top(&buf, "pdu_length").unwrap().value,
            FieldValue::U16((data.len() - 4) as u16)
        );
        assert_eq!(
            top(&buf, "lsr_id").unwrap().value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(top(&buf, "label_space").unwrap().value, FieldValue::U16(0));

        let msgs = messages(&buf);
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(child(m, "u_bit").value, FieldValue::U8(0));
        assert_eq!(display(&buf, child(m, "type")), Some("Hello"));
        assert_eq!(child(m, "message_id").value, FieldValue::U32(1));
        let t = tlvs(&buf, m);
        assert_eq!(t.len(), 3);
        assert_eq!(
            display(&buf, child(&t[0], "type")),
            Some("Common Hello Parameters")
        );
        assert_eq!(child(&t[0], "u_bit").value, FieldValue::U8(0));
        assert_eq!(child(&t[0], "f_bit").value, FieldValue::U8(0));
        assert_eq!(child(&t[0], "hold_time").value, FieldValue::U16(15));
        assert_eq!(child(&t[0], "targeted").value, FieldValue::U8(0));
        assert_eq!(child(&t[0], "request_targeted").value, FieldValue::U8(0));
        assert_eq!(child(&t[0], "gtsm").value, FieldValue::U8(1));
        assert_eq!(
            child(&t[1], "transport_address").value,
            FieldValue::Ipv4Addr([10, 0, 0, 1])
        );
        assert_eq!(
            child(&t[2], "configuration_sequence_number").value,
            FieldValue::U32(7)
        );
    }

    #[test]
    fn parse_targeted_hello_ipv6() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut params = tlv(TLV_COMMON_HELLO_PARAMETERS, &[0, 45, 0xC0, 0]); // T=1, R=1
        params.extend(tlv(TLV_IPV6_TRANSPORT_ADDRESS, &addr));
        // U=1, F=0 Dual-Stack capability, TR = LDPoIPv6.
        params.extend(tlv(0x8000 | TLV_DUAL_STACK_CAPABILITY, &[0x60, 0, 0, 0]));
        let data = pdu(&message(0x0100, 2, &params));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        assert_eq!(child(&t[0], "targeted").value, FieldValue::U8(1));
        assert_eq!(child(&t[0], "request_targeted").value, FieldValue::U8(1));
        assert_eq!(
            child(&t[1], "transport_address").value,
            FieldValue::Ipv6Addr(addr)
        );
        assert_eq!(child(&t[2], "u_bit").value, FieldValue::U8(1));
        assert_eq!(
            child(&t[2], "type").value,
            FieldValue::U16(TLV_DUAL_STACK_CAPABILITY)
        );
        assert_eq!(
            display(&buf, child(&t[2], "transport_preference")),
            Some("LDPoIPv6 connection")
        );
    }

    #[test]
    fn parse_initialization() {
        let mut csp = vec![0, 1, 0, 180, 0x40, 0, 0x10, 0x00];
        csp.extend_from_slice(&[10, 0, 0, 2, 0, 0]);
        let data = pdu(&message(
            0x0200,
            3,
            &tlv(TLV_COMMON_SESSION_PARAMETERS, &csp),
        ));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(display(&buf, child(m, "type")), Some("Initialization"));
        let t = tlvs(&buf, m);
        let p = &t[0];
        assert_eq!(child(p, "protocol_version").value, FieldValue::U16(1));
        assert_eq!(child(p, "keepalive_time").value, FieldValue::U16(180));
        assert_eq!(
            child(p, "advertisement_discipline").value,
            FieldValue::U8(0)
        );
        assert_eq!(
            display(&buf, child(p, "advertisement_discipline")),
            Some("Downstream Unsolicited")
        );
        assert_eq!(child(p, "loop_detection").value, FieldValue::U8(1));
        assert_eq!(child(p, "path_vector_limit").value, FieldValue::U8(0));
        assert_eq!(child(p, "max_pdu_length").value, FieldValue::U16(4096));
        assert_eq!(
            child(p, "receiver_lsr_id").value,
            FieldValue::Ipv4Addr([10, 0, 0, 2])
        );
        assert_eq!(child(p, "receiver_label_space").value, FieldValue::U16(0));
    }

    #[test]
    fn two_messages_in_one_pdu() {
        let mut msgs = message(0x0201, 4, &[]);
        msgs.extend(message(0x0201, 5, &[]));
        let data = pdu(&msgs);
        let (buf, _) = dissect(&data);
        let m = messages(&buf);
        assert_eq!(m.len(), 2);
        assert_eq!(display(&buf, child(&m[1], "type")), Some("KeepAlive"));
        assert_eq!(child(&m[1], "message_id").value, FieldValue::U32(5));
        assert!(!has(&m[1], "tlvs"));
    }

    #[test]
    fn parse_label_mapping_prefix() {
        let mut fec = vec![FEC_PREFIX, 0, 1, 24, 10, 1, 2]; // 10.1.2.0/24
        fec.extend_from_slice(&[FEC_PREFIX, 0, 2, 32, 0x20, 0x01, 0x0d, 0xb8]); // 2001:db8::/32
        fec.extend_from_slice(&[FEC_PREFIX, 0, 1, 0]); // default route
        let mut params = tlv(TLV_FEC, &fec);
        params.extend(tlv(TLV_GENERIC_LABEL, &[0xFF, 0xF0, 0x3E, 0x80])); // high bits ignored
        params.extend(tlv(TLV_HOP_COUNT, &[3]));
        params.extend(tlv(TLV_PATH_VECTOR, &[10, 0, 0, 1, 10, 0, 0, 2]));
        let data = pdu(&message(0x0400, 6, &params));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(display(&buf, child(m, "type")), Some("Label Mapping"));
        let t = tlvs(&buf, m);
        let elements: Vec<_> = children(&buf, child(&t[0], "fec_elements"))
            .into_iter()
            .map(|e| children(&buf, e))
            .collect();
        assert_eq!(elements.len(), 3);
        assert_eq!(display(&buf, child(&elements[0], "type")), Some("Prefix"));
        assert_eq!(
            display(&buf, child(&elements[0], "address_family")),
            Some("IPv4")
        );
        assert_eq!(
            child(&elements[0], "prefix_length").value,
            FieldValue::U8(24)
        );
        assert_eq!(
            child(&elements[0], "prefix").value,
            FieldValue::Ipv4Addr([10, 1, 2, 0])
        );
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(
            child(&elements[1], "prefix").value,
            FieldValue::Ipv6Addr(v6)
        );
        assert_eq!(
            child(&elements[2], "prefix").value,
            FieldValue::Ipv4Addr([0; 4])
        );
        assert!(!has(&t[0], "value"));
        assert_eq!(child(&t[1], "label").value, FieldValue::U32(16000));
        assert_eq!(child(&t[2], "hop_count").value, FieldValue::U8(3));
        let ids = children(&buf, child(&t[3], "lsr_ids"));
        assert_eq!(ids[1].value, FieldValue::Ipv4Addr([10, 0, 0, 2]));
    }

    #[test]
    fn parse_label_withdraw_wildcard() {
        let mut params = tlv(TLV_FEC, &[FEC_WILDCARD]);
        params.extend(tlv(TLV_GENERIC_LABEL, &16u32.to_be_bytes()));
        let data = pdu(&message(0x0402, 8, &params));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(display(&buf, child(m, "type")), Some("Label Withdraw"));
        let t = tlvs(&buf, m);
        let elements = children(&buf, child(&t[0], "fec_elements"));
        assert_eq!(elements.len(), 1);
        assert_eq!(display(&buf, elements[0]), Some("Wildcard"));
    }

    #[test]
    fn unknown_fec_element_kept_as_value() {
        let fec = [FEC_PREFIX, 0, 1, 8, 10, 6, 1, 2, 3];
        let data = pdu(&message(0x0403, 9, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        assert_eq!(children(&buf, child(&t[0], "fec_elements")).len(), 1);
        assert_eq!(
            child(&t[0], "value").value,
            FieldValue::Bytes(&[6, 1, 2, 3])
        );

        // A prefix longer than the address, and an unknown family.
        let fec = [FEC_PREFIX, 0, 1, 40, 1, 2, 3, 4, 5];
        let data = pdu(&message(0x0403, 9, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        assert!(!has(&t[0], "fec_elements"));
        assert_eq!(child(&t[0], "value").value, FieldValue::Bytes(&fec));
        let fec = [FEC_PREFIX, 0, 99, 16, 1, 2];
        let data = pdu(&message(0x0403, 9, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert_eq!(child(&e, "prefix").value, FieldValue::Bytes(&[1, 2]));
    }

    #[test]
    fn parse_label_mapping_pwid() {
        // PWid, C=1, Ethernet, info length 4 + 4 (MTU) + 6 (description) + 3 (truncated).
        let mut fec = vec![FEC_PWID, 0x80, 0x05, 17];
        fec.extend_from_slice(&1u32.to_be_bytes()); // Group ID
        fec.extend_from_slice(&100u32.to_be_bytes()); // PW ID
        fec.extend_from_slice(&[SUB_TLV_MTU, 4, 0x05, 0xDC]);
        fec.extend_from_slice(&[SUB_TLV_DESCRIPTION, 6, b'a', b'c', b'1', b'0']);
        fec.extend_from_slice(&[0x0C, 9, 1]);
        let mut params = tlv(TLV_FEC, &fec);
        params.extend(tlv(TLV_GENERIC_LABEL, &[0, 1, 0, 0]));
        let data = pdu(&message(0x0400, 10, &params));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert_eq!(display(&buf, child(&e, "type")), Some("PWid FEC Element"));
        assert_eq!(child(&e, "c_bit").value, FieldValue::U8(1));
        assert_eq!(child(&e, "pw_type").value, FieldValue::U16(5));
        assert_eq!(display(&buf, child(&e, "pw_type")), Some("Ethernet"));
        assert_eq!(child(&e, "pw_info_length").value, FieldValue::U8(17));
        assert_eq!(child(&e, "group_id").value, FieldValue::U32(1));
        assert_eq!(child(&e, "pw_id").value, FieldValue::U32(100));
        let params: Vec<_> = children(&buf, child(&e, "interface_parameters"))
            .into_iter()
            .map(|p| children(&buf, p))
            .collect();
        assert_eq!(params.len(), 3);
        assert_eq!(child(&params[0], "mtu").value, FieldValue::U16(1500));
        assert_eq!(
            child(&params[1], "description").value,
            FieldValue::Bytes(b"ac10")
        );
        assert_eq!(
            display(&buf, child(&params[2], "type")),
            Some("VCCV parameter")
        );
        assert_eq!(child(&params[2], "value").value, FieldValue::Bytes(&[1]));
        assert_eq!(child(&t[1], "label").value, FieldValue::U32(65536));
    }

    #[test]
    fn parse_pwid_wildcard() {
        // PW info length 0: "it references all PWs using the specified Group ID".
        let mut fec = vec![FEC_PWID, 0x00, 0x05, 0];
        fec.extend_from_slice(&7u32.to_be_bytes());
        let data = pdu(&message(0x0402, 11, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert_eq!(child(&e, "group_id").value, FieldValue::U32(7));
        assert!(!has(&e, "pw_id"));

        // PW info length 2: shorter than a PW ID.
        let mut fec = vec![FEC_PWID, 0x00, 0x05, 2];
        fec.extend_from_slice(&7u32.to_be_bytes());
        fec.extend_from_slice(&[1, 2]);
        let data = pdu(&message(0x0402, 11, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert_eq!(child(&e, "value").value, FieldValue::Bytes(&[1, 2]));
    }

    #[test]
    fn parse_label_mapping_generalized_pwid() {
        let mut fec = vec![FEC_GENERALIZED_PWID, 0x00, 0x05, 14];
        fec.extend_from_slice(&[1, 4, 0, 0, 0, 1]); // AGI
        fec.extend_from_slice(&[2, 0]); // SAII (null)
        fec.extend_from_slice(&[2, 4, 10, 0, 0, 2]); // TAII
        let mut params = tlv(TLV_FEC, &fec);
        params.extend(tlv(TLV_GENERIC_LABEL, &[0, 0, 0, 20]));
        params.extend(tlv(
            TLV_PW_INTERFACE_PARAMETERS,
            &[SUB_TLV_MTU, 4, 0x05, 0xDC],
        ));
        params.extend(tlv(TLV_PW_GROUP_ID, &3u32.to_be_bytes()));
        params.extend(tlv(TLV_PW_STATUS, &[0, 0, 0, 0x02]));
        let data = pdu(&message(0x0400, 12, &params));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert_eq!(
            display(&buf, child(&e, "type")),
            Some("Generalized PWid FEC Element")
        );
        assert_eq!(child(&e, "agi_type").value, FieldValue::U8(1));
        assert_eq!(child(&e, "agi").value, FieldValue::Bytes(&[0, 0, 0, 1]));
        assert_eq!(child(&e, "saii").value, FieldValue::Bytes(&[]));
        assert_eq!(child(&e, "taii_type").value, FieldValue::U8(2));
        assert_eq!(child(&e, "taii").value, FieldValue::Bytes(&[10, 0, 0, 2]));
        let ip = children(&buf, child(&t[2], "interface_parameters"));
        assert_eq!(
            child(&children(&buf, ip[0]), "mtu").value,
            FieldValue::U16(1500)
        );
        assert_eq!(child(&t[3], "pw_group_id").value, FieldValue::U32(3));
        assert_eq!(child(&t[4], "pw_status").value, FieldValue::U32(2));

        // PW info length longer than the AGI, SAII and TAII: kept as value.
        let mut fec = vec![FEC_GENERALIZED_PWID, 0x00, 0x05, 9];
        fec.extend_from_slice(&[1, 0, 2, 0, 2, 0, 7, 7, 7]);
        let data = pdu(&message(0x0402, 13, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert_eq!(child(&e, "taii").value, FieldValue::Bytes(&[]));
        assert_eq!(child(&e, "value").value, FieldValue::Bytes(&[7, 7, 7]));
        // An AGI overrunning the PW info length.
        let fec = [FEC_GENERALIZED_PWID, 0x00, 0x05, 3, 1, 5, 0];
        let data = pdu(&message(0x0402, 13, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert!(!has(&e, "agi"));
        assert_eq!(child(&e, "value").value, FieldValue::Bytes(&[1, 5, 0]));

        // PW info length 0: only the header.
        let fec = [FEC_GENERALIZED_PWID, 0x00, 0x05, 0];
        let data = pdu(&message(0x0402, 13, &tlv(TLV_FEC, &fec)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let e = children(&buf, children(&buf, child(&t[0], "fec_elements"))[0]);
        assert!(!has(&e, "agi"));
    }

    #[test]
    fn parse_address_message() {
        let mut list = vec![0, 1];
        list.extend_from_slice(&[10, 0, 0, 1, 192, 0, 2, 1, 9]);
        let data = pdu(&message(0x0300, 14, &tlv(TLV_ADDRESS_LIST, &list)));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(display(&buf, child(m, "type")), Some("Address"));
        let t = tlvs(&buf, m);
        assert_eq!(display(&buf, child(&t[0], "address_family")), Some("IPv4"));
        let addrs = children(&buf, child(&t[0], "addresses"));
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[1].value, FieldValue::Ipv4Addr([192, 0, 2, 1]));
        assert_eq!(child(&t[0], "value").value, FieldValue::Bytes(&[9]));

        // IPv6 addresses, and an unknown family.
        let mut list = vec![0, 2];
        list.extend_from_slice(&[0xfe; 16]);
        let data = pdu(&message(0x0301, 15, &tlv(TLV_ADDRESS_LIST, &list)));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        let addrs = children(&buf, child(&t[0], "addresses"));
        assert_eq!(addrs[0].value, FieldValue::Ipv6Addr([0xfe; 16]));
        let data = pdu(&message(0x0301, 15, &tlv(TLV_ADDRESS_LIST, &[0, 99, 1, 2])));
        let (buf, _) = dissect(&data);
        let t = tlvs(&buf, &messages(&buf)[0]);
        assert_eq!(child(&t[0], "value").value, FieldValue::Bytes(&[1, 2]));
    }

    #[test]
    fn parse_notification_status() {
        let mut status = 0x8000_000Au32.to_be_bytes().to_vec(); // E=1, Shutdown
        status.extend_from_slice(&0u32.to_be_bytes());
        status.extend_from_slice(&0u16.to_be_bytes());
        let mut params = tlv(TLV_STATUS, &status);
        params.extend(tlv(TLV_EXTENDED_STATUS, &9u32.to_be_bytes()));
        params.extend(tlv(0x0302, &[1, 2])); // Returned PDU
        let data = pdu(&message(0x0001, 16, &params));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(display(&buf, child(m, "type")), Some("Notification"));
        let t = tlvs(&buf, m);
        assert_eq!(child(&t[0], "status_e_bit").value, FieldValue::U8(1));
        assert_eq!(child(&t[0], "status_f_bit").value, FieldValue::U8(0));
        assert_eq!(child(&t[0], "status_code").value, FieldValue::U32(10));
        assert_eq!(display(&buf, child(&t[0], "status_code")), Some("Shutdown"));
        assert_eq!(child(&t[0], "status_message_id").value, FieldValue::U32(0));
        assert_eq!(child(&t[1], "extended_status").value, FieldValue::U32(9));
        assert_eq!(display(&buf, child(&t[2], "type")), Some("Returned PDU"));
        assert_eq!(child(&t[2], "value").value, FieldValue::Bytes(&[1, 2]));
    }

    #[test]
    fn parse_label_abort_request() {
        let mut params = tlv(TLV_FEC, &[FEC_WILDCARD]);
        params.extend(tlv(TLV_LABEL_REQUEST_MESSAGE_ID, &77u32.to_be_bytes()));
        params.extend(tlv(0x3E01, &[])); // vendor-private, empty
        let mut vendor = 9u32.to_be_bytes().to_vec();
        vendor.push(0xAA);
        params.extend(tlv(0x3F02, &vendor)); // experimental
        let data = pdu(&message(0x0404, 17, &params));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(display(&buf, child(m, "type")), Some("Label Abort Request"));
        let t = tlvs(&buf, m);
        assert_eq!(child(&t[1], "message_id").value, FieldValue::U32(77));
        assert_eq!(t[2].len(), 4);
        assert_eq!(child(&t[3], "vendor_id").value, FieldValue::U32(9));
        assert_eq!(child(&t[3], "value").value, FieldValue::Bytes(&[0xAA]));
    }

    #[test]
    fn vendor_private_message() {
        let mut body = 9u32.to_be_bytes().to_vec(); // Vendor ID
        body.extend(tlv(TLV_HOP_COUNT, &[2]));
        let data = pdu(&message(0x3E01, 19, &body));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(
            display(&buf, child(m, "type")),
            Some("Reserved for Vendor-Private Extensions")
        );
        assert_eq!(child(m, "vendor_id").value, FieldValue::U32(9));
        assert_eq!(
            child(&tlvs(&buf, m)[0], "hop_count").value,
            FieldValue::U8(2)
        );
    }

    #[test]
    fn tlv_overrun_kept_as_data() {
        let mut params = tlv(TLV_HOP_COUNT, &[1]);
        params.extend_from_slice(&[0x01, 0x00, 0, 20, 1]);
        let data = pdu(&message(0x0400, 18, &params));
        let (buf, _) = dissect(&data);
        let m = &messages(&buf)[0];
        assert_eq!(tlvs(&buf, m).len(), 1);
        assert_eq!(
            child(m, "data").value,
            FieldValue::Bytes(&[0x01, 0x00, 0, 20, 1])
        );
        assert_eq!(child(m, "tlvs").range, 18..23);
    }

    #[test]
    fn message_overrun_kept_as_data() {
        let mut msgs = message(0x0201, 1, &[]);
        msgs.extend_from_slice(&[0x02, 0x01, 0, 40, 0, 0]);
        let data = pdu(&msgs);
        let (buf, _) = dissect(&data);
        assert_eq!(messages(&buf).len(), 1);
        assert_eq!(top(&buf, "data").unwrap().range, 18..24);

        // Only a truncated message: no messages array.
        let data = pdu(&[0x02, 0x01, 0, 2, 0, 0, 0, 0]);
        let (buf, _) = dissect(&data);
        assert!(top(&buf, "messages").is_none());
    }

    #[test]
    fn consumes_one_pdu() {
        let mut data = pdu(&message(0x0201, 1, &[]));
        let first = data.len();
        data.extend(pdu(&message(0x0201, 2, &[])));
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, first);
        assert_eq!(buf.layers().len(), 1);
    }

    #[test]
    fn truncated_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LdpDissector.dissect(&[0, 1, 0], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 10,
                actual: 3
            })
        );
    }

    #[test]
    fn truncated_pdu() {
        let data = pdu(&message(0x0201, 1, &[]));
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LdpDissector.dissect(&data[..12], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: data.len(),
                actual: 12
            })
        );
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn reject_unsupported_version() {
        let mut data = pdu(&[]);
        data[1] = 2;
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LdpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 2
            })
        );
    }

    #[test]
    fn reject_short_pdu_length() {
        let data = [0, 1, 0, 5, 10, 0, 0, 1, 0, 0];
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LdpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "pdu_length",
                value: 5
            })
        );
    }

    #[test]
    fn offsets_are_absolute() {
        let data = pdu(&message(0x0100, 1, &tlv(TLV_HOP_COUNT, &[1])));
        let mut buf = DissectBuffer::new();
        LdpDissector.dissect(&data, &mut buf, 42).unwrap();
        assert_eq!(buf.layers()[0].range, 42..42 + data.len());
        let hc = buf
            .fields()
            .iter()
            .find(|f| f.name() == "hop_count")
            .unwrap();
        assert_eq!(hc.range, 42 + 22..42 + 23);
    }

    #[test]
    fn registry_names() {
        assert_eq!(message_type_name(0x0202), Some("Capability"));
        assert_eq!(
            message_type_name(0x0705),
            Some("Reserved for future ICCP use")
        );
        assert_eq!(message_type_name(0x0002), None);
        assert_eq!(
            tlv_type_name(0x3F10),
            Some("Reserved for Experimental Extensions")
        );
        assert_eq!(tlv_type_name(0x0102), None);
        assert_eq!(fec_type_name(200), Some("Reserved for Private Use"));
        assert_eq!(fec_type_name(3), None);
        assert_eq!(
            status_code_name(0x3F00_0001),
            Some("Reserved for Private Use")
        );
        assert_eq!(status_code_name(0x29), None);
        assert_eq!(pw_type_name(0x7FFF), Some("Wildcard"));
        assert_eq!(pw_type_name(0x20), None);
        assert!(interface_parameter_name(0xFD).is_some());
        assert_eq!(interface_parameter_name(0x12), None);
        assert_eq!(
            transport_preference_name(0b0100),
            Some("LDPoIPv4 connection")
        );
        assert_eq!(transport_preference_name(0), None);
        assert_eq!(address_family_name(3), None);
    }

    #[test]
    fn registry_names_are_non_empty() {
        // Every IANA-assigned code point has a non-empty name.
        let named = |name: Option<&'static str>| name.is_none_or(|n| !n.is_empty());
        assert!((0..=0x3FFF).all(|t| named(message_type_name(t)) && named(tlv_type_name(t))));
        assert!((0..=255).all(|t| named(fec_type_name(t)) && named(interface_parameter_name(t))));
        assert!((0..=0x7FFF).all(|t| named(pw_type_name(t))));
        let status_ranges = [
            0..=0x4C,
            0x0001_0001..=0x0001_0011,
            0x0100_0001..=0x0100_0005,
            0x0400_0001..=0x0400_001A,
            0x2000_0000..=0x2000_0004,
            0x3F00_0000..=0x3F00_0001,
        ];
        let assigned = status_ranges
            .into_iter()
            .flatten()
            .filter(|&c| status_code_name(c).is_some())
            .count();
        // 108 assigned codes and the two private-use values probed.
        assert_eq!(assigned, 110);
    }

    #[test]
    fn dissector_metadata() {
        assert_eq!(LdpDissector.name(), "Label Distribution Protocol");
        assert_eq!(LdpDissector.short_name(), "LDP");
        assert_eq!(LdpDissector.layer(), Some(ProtocolLayer::Application));
        assert_eq!(LdpDissector.references()[0].id, "RFC 5036");
        assert_eq!(LdpDissector.field_descriptors().len(), FD_DATA + 1);
    }
}
