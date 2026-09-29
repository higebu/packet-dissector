//! DNS (Domain Name System) dissector.
//!
//! ## References
//! - RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035>
//! - RFC 3596 (AAAA record): <https://www.rfc-editor.org/rfc/rfc3596>
//! - RFC 4035 (DNSSEC, adds AD/CD flags): <https://www.rfc-editor.org/rfc/rfc4035>
//! - RFC 6891 (EDNS0, extends RCODE/UDP payload): <https://www.rfc-editor.org/rfc/rfc6891>
//! - RFC 7766 (DNS over TCP, updates §4.2.2): <https://www.rfc-editor.org/rfc/rfc7766>
//! - RFC 7828 (EDNS0 TCP Keepalive): <https://www.rfc-editor.org/rfc/rfc7828>
//! - RFC 2782 (SRV record): <https://www.rfc-editor.org/rfc/rfc2782>
//! - RFC 3403 (NAPTR record): <https://www.rfc-editor.org/rfc/rfc3403>
//! - RFC 4255 (SSHFP record): <https://www.rfc-editor.org/rfc/rfc4255>
//! - RFC 6672 (DNAME record): <https://www.rfc-editor.org/rfc/rfc6672>
//! - RFC 6698 (TLSA record): <https://www.rfc-editor.org/rfc/rfc6698>
//! - RFC 8659 (CAA record): <https://www.rfc-editor.org/rfc/rfc8659>
//! - RFC 4035 (DNSSEC records: DNSKEY, DS, RRSIG, NSEC): <https://www.rfc-editor.org/rfc/rfc4035>
//! - RFC 5155 (NSEC3): <https://www.rfc-editor.org/rfc/rfc5155>
//! - RFC 7344 (CDS/CDNSKEY records): <https://www.rfc-editor.org/rfc/rfc7344>
//! - RFC 9460 (SVCB/HTTPS records): <https://www.rfc-editor.org/rfc/rfc9460>
//! - RFC 9461 (SVCB "dohpath"): <https://www.rfc-editor.org/rfc/rfc9461>
//! - RFC 9848 (SVCB "ech"): <https://www.rfc-editor.org/rfc/rfc9848>
//! - RFC 5001 (EDNS NSID): <https://www.rfc-editor.org/rfc/rfc5001>
//! - RFC 6975 (EDNS DAU/DHU/N3U): <https://www.rfc-editor.org/rfc/rfc6975>
//! - RFC 7314 (EDNS EXPIRE): <https://www.rfc-editor.org/rfc/rfc7314>
//! - RFC 7830 (EDNS Padding): <https://www.rfc-editor.org/rfc/rfc7830>
//! - RFC 7871 (EDNS Client Subnet): <https://www.rfc-editor.org/rfc/rfc7871>
//! - RFC 7873 (DNS Cookies): <https://www.rfc-editor.org/rfc/rfc7873>
//! - RFC 8145 (EDNS edns-key-tag): <https://www.rfc-editor.org/rfc/rfc8145>
//! - RFC 8914 (Extended DNS Errors): <https://www.rfc-editor.org/rfc/rfc8914>
//! - RFC 9567 (DNS Error Reporting, Report-Channel): <https://www.rfc-editor.org/rfc/rfc9567>
//! - RFC 9660 (EDNS ZONEVERSION): <https://www.rfc-editor.org/rfc/rfc9660>
//! - RFC 4034 (DNSSEC RR formats, type bit maps): <https://www.rfc-editor.org/rfc/rfc4034>
//! - RFC 1876 (LOC record): <https://www.rfc-editor.org/rfc/rfc1876>
//! - RFC 2930 (TKEY record): <https://www.rfc-editor.org/rfc/rfc2930>
//! - RFC 4025 (IPSECKEY record): <https://www.rfc-editor.org/rfc/rfc4025>
//! - RFC 4398 (CERT record): <https://www.rfc-editor.org/rfc/rfc4398>
//! - RFC 4701 (DHCID record): <https://www.rfc-editor.org/rfc/rfc4701>
//! - RFC 7043 (EUI48/EUI64 records): <https://www.rfc-editor.org/rfc/rfc7043>
//! - RFC 7477 (CSYNC record): <https://www.rfc-editor.org/rfc/rfc7477>
//! - RFC 7553 (URI record): <https://www.rfc-editor.org/rfc/rfc7553>
//! - RFC 7929 (OPENPGPKEY record): <https://www.rfc-editor.org/rfc/rfc7929>
//! - RFC 8482 (HINFO answers to ANY): <https://www.rfc-editor.org/rfc/rfc8482>
//! - RFC 8945 (TSIG record): <https://www.rfc-editor.org/rfc/rfc8945>
//! - RFC 8976 (ZONEMD record): <https://www.rfc-editor.org/rfc/rfc8976>
//! - RFC 8490 (DNS Stateful Operations): <https://www.rfc-editor.org/rfc/rfc8490>
//! - RFC 2136 (DNS UPDATE): <https://www.rfc-editor.org/rfc/rfc2136>
//! - IANA DNS Parameters: <https://www.iana.org/assignments/dns-parameters/>
//!
//! ## UPDATE messages
//!
//! For opcode 5 (UPDATE), RFC 2136, Section 2 —
//! <https://www.rfc-editor.org/rfc/rfc2136#section-2> — renames the four
//! sections to Zone, Prerequisite, Update and Additional Data. The
//! dissector keeps the RFC 1035 field names, so in an UPDATE message
//! `questions` holds the Zone section, `answers` the Prerequisite section,
//! `authorities` the Update section and `additionals` the Additional Data
//! section.

#![deny(missing_docs)]

mod bitmap;
mod edns;
mod svcb;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    FieldDescriptor, FieldType, FieldValue, FormatContext, MacAddr, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

use bitmap::{FD_BITMAP_TYPE, push_type_bitmap};
#[cfg(test)]
use edns::{EDNS_OPT_TCP_KEEPALIVE, ede_info_code_name, edns_option_code_name};
use edns::{EDNS_OPTION_CHILD_FIELDS, parse_edns_options};
#[cfg(test)]
use svcb::svc_param_key_name;
use svcb::{SVC_PARAM_CHILD_FIELDS, push_svc_params};

/// DNS header size (fixed 12 bytes).
const HEADER_SIZE: usize = 12;

/// Returns a human-readable name for DNS QTYPE / TYPE values.
///
/// Names follow the IANA "Resource Record (RR) TYPEs" registry
/// (RFC 6895, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc6895#section-3.1>;
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>).
/// QTYPE 255 ("*") is named "ANY".
pub fn dns_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("A"),
        2 => Some("NS"),
        3 => Some("MD"),
        4 => Some("MF"),
        5 => Some("CNAME"),
        6 => Some("SOA"),
        7 => Some("MB"),
        8 => Some("MG"),
        9 => Some("MR"),
        10 => Some("NULL"),
        11 => Some("WKS"),
        12 => Some("PTR"),
        13 => Some("HINFO"),
        14 => Some("MINFO"),
        15 => Some("MX"),
        16 => Some("TXT"),
        17 => Some("RP"),
        18 => Some("AFSDB"),
        19 => Some("X25"),
        20 => Some("ISDN"),
        21 => Some("RT"),
        22 => Some("NSAP"),
        23 => Some("NSAP-PTR"),
        24 => Some("SIG"),
        25 => Some("KEY"),
        26 => Some("PX"),
        27 => Some("GPOS"),
        28 => Some("AAAA"),
        29 => Some("LOC"),
        30 => Some("NXT"),
        31 => Some("EID"),
        32 => Some("NIMLOC"),
        33 => Some("SRV"),
        34 => Some("ATMA"),
        35 => Some("NAPTR"),
        36 => Some("KX"),
        37 => Some("CERT"),
        38 => Some("A6"),
        39 => Some("DNAME"),
        40 => Some("SINK"),
        41 => Some("OPT"),
        42 => Some("APL"),
        43 => Some("DS"),
        44 => Some("SSHFP"),
        45 => Some("IPSECKEY"),
        46 => Some("RRSIG"),
        47 => Some("NSEC"),
        48 => Some("DNSKEY"),
        49 => Some("DHCID"),
        50 => Some("NSEC3"),
        51 => Some("NSEC3PARAM"),
        52 => Some("TLSA"),
        53 => Some("SMIMEA"),
        55 => Some("HIP"),
        56 => Some("NINFO"),
        57 => Some("RKEY"),
        58 => Some("TALINK"),
        59 => Some("CDS"),
        60 => Some("CDNSKEY"),
        61 => Some("OPENPGPKEY"),
        62 => Some("CSYNC"),
        63 => Some("ZONEMD"),
        64 => Some("SVCB"),
        65 => Some("HTTPS"),
        66 => Some("DSYNC"),
        67 => Some("HHIT"),
        68 => Some("BRID"),
        69 => Some("UNECE"),
        70 => Some("ISO"),
        99 => Some("SPF"),
        100 => Some("UINFO"),
        101 => Some("UID"),
        102 => Some("GID"),
        103 => Some("UNSPEC"),
        104 => Some("NID"),
        105 => Some("L32"),
        106 => Some("L64"),
        107 => Some("LP"),
        108 => Some("EUI48"),
        109 => Some("EUI64"),
        128 => Some("NXNAME"),
        249 => Some("TKEY"),
        250 => Some("TSIG"),
        251 => Some("IXFR"),
        252 => Some("AXFR"),
        253 => Some("MAILB"),
        254 => Some("MAILA"),
        255 => Some("ANY"),
        256 => Some("URI"),
        257 => Some("CAA"),
        258 => Some("AVC"),
        259 => Some("DOA"),
        260 => Some("AMTRELAY"),
        261 => Some("RESINFO"),
        262 => Some("WALLET"),
        263 => Some("CLA"),
        264 => Some("IPN"),
        32768 => Some("TA"),
        32769 => Some("DLV"),
        _ => None,
    }
}

/// Returns a human-readable name for DNS CLASS values.
///
/// RFC 1035, Section 3.2.4.
fn dns_class_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("IN"),
        3 => Some("CH"),
        4 => Some("HS"),
        255 => Some("ANY"),
        _ => None,
    }
}

/// Returns a human-readable name for DNS opcode values.
///
/// RFC 1035, Section 4.1.1 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1>;
/// RFC 1996 (NOTIFY) — <https://www.rfc-editor.org/rfc/rfc1996>;
/// RFC 2136 (UPDATE) — <https://www.rfc-editor.org/rfc/rfc2136>;
/// RFC 8490, Section 10.1 (DSO) — <https://www.rfc-editor.org/rfc/rfc8490#section-10.1>.
fn dns_opcode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("QUERY"),
        1 => Some("IQUERY"),
        2 => Some("STATUS"),
        4 => Some("NOTIFY"),
        5 => Some("UPDATE"),
        OPCODE_DSO => Some("DSO"),
        _ => None,
    }
}

/// Returns a human-readable name for DNS RCODE values.
///
/// Covers the 4-bit header RCODE (RFC 1035, Section 4.1.1 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1>) and the 12-bit
/// extended RCODE formed with the OPT pseudo-RR (RFC 6891, Section 6.1.3 —
/// <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3>). Names follow the
/// IANA "DNS RCODEs" registry
/// (<https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>).
/// Value 16 is BADVERS in the OPT RR and BADSIG in TSIG / TKEY RRs; this
/// function returns "BADVERS", the meaning for message RCODEs.
pub fn dns_rcode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("NOERROR"),
        1 => Some("FORMERR"),
        2 => Some("SERVFAIL"),
        3 => Some("NXDOMAIN"),
        4 => Some("NOTIMP"),
        5 => Some("REFUSED"),
        6 => Some("YXDOMAIN"),
        7 => Some("YXRRSET"),
        8 => Some("NXRRSET"),
        9 => Some("NOTAUTH"),
        10 => Some("NOTZONE"),
        11 => Some("DSOTYPENI"),
        16 => Some("BADVERS"),
        17 => Some("BADKEY"),
        18 => Some("BADTIME"),
        19 => Some("BADMODE"),
        20 => Some("BADNAME"),
        21 => Some("BADALG"),
        22 => Some("BADTRUNC"),
        23 => Some("BADCOOKIE"),
        _ => None,
    }
}

/// Returns the name of a 12-bit extended RCODE (see [`dns_rcode_name`]).
fn dns_extended_rcode_name(v: u16) -> Option<&'static str> {
    u8::try_from(v).ok().and_then(dns_rcode_name)
}

/// Returns the name of the Error field of a TSIG or TKEY RR.
///
/// RFC 8945, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc8945#section-4.2>
/// and the IANA "DNS RCODEs" registry: in these RRs, 16 is BADSIG.
fn tsig_rcode_name(v: u16) -> Option<&'static str> {
    match v {
        16 => Some("BADSIG"),
        _ => dns_extended_rcode_name(v),
    }
}

/// Maximum pointer follow depth to prevent infinite loops.
const MAX_POINTER_DEPTH: usize = 128;

/// Length of an uncompressed domain name at the start of `data`.
///
/// Returns the number of octets up to and including the root label, or
/// `None` if the name uses a compression pointer or a reserved label type,
/// exceeds 255 octets (RFC 1035, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.1>), or is truncated.
pub(crate) fn uncompressed_name_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        let len = *data.get(pos)? as usize;
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
        if pos > 255 || pos > data.len() {
            return None;
        }
        if len == 0 {
            return Some(pos);
        }
    }
}
// RFC 1035, Section 3.2.2 — TYPE values
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
// RFC 3596 — AAAA record
const TYPE_AAAA: u16 = 28;
// RFC 2782 — SRV record
const TYPE_SRV: u16 = 33;
// RFC 3403 — NAPTR record
const TYPE_NAPTR: u16 = 35;
// RFC 6672 — DNAME record
const TYPE_DNAME: u16 = 39;
// RFC 6891 — OPT pseudo-record (EDNS0)
const TYPE_OPT: u16 = 41;
// RFC 4035 — DNSSEC records
const TYPE_DS: u16 = 43;
const TYPE_RRSIG: u16 = 46;
const TYPE_NSEC: u16 = 47;
const TYPE_DNSKEY: u16 = 48;
// RFC 5155 — NSEC3 / NSEC3PARAM
const TYPE_NSEC3: u16 = 50;
const TYPE_NSEC3PARAM: u16 = 51;
// RFC 4255 — SSHFP record
const TYPE_SSHFP: u16 = 44;
// RFC 6698 — TLSA record
const TYPE_TLSA: u16 = 52;
// RFC 7344 — CDS/CDNSKEY records
const TYPE_CDS: u16 = 59;
const TYPE_CDNSKEY: u16 = 60;
// RFC 9460 — SVCB/HTTPS records
const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;
// RFC 8659 — CAA record
const TYPE_CAA: u16 = 257;
// RFC 1035, Section 3.3.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.2>
const TYPE_HINFO: u16 = 13;
// RFC 1876, Section 2 — <https://www.rfc-editor.org/rfc/rfc1876#section-2>
const TYPE_LOC: u16 = 29;
// RFC 4398, Section 2 — <https://www.rfc-editor.org/rfc/rfc4398#section-2>
const TYPE_CERT: u16 = 37;
// RFC 4025, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc4025#section-2.1>
const TYPE_IPSECKEY: u16 = 45;
// RFC 4701, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4701#section-3.1>
const TYPE_DHCID: u16 = 49;
// RFC 7929, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc7929#section-2.1>
const TYPE_OPENPGPKEY: u16 = 61;
// RFC 7477, Section 2.1.1 — <https://www.rfc-editor.org/rfc/rfc7477#section-2.1.1>
const TYPE_CSYNC: u16 = 62;
// RFC 8976, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8976#section-2.2>
const TYPE_ZONEMD: u16 = 63;
// RFC 7043, Sections 3.1 / 4.1 — <https://www.rfc-editor.org/rfc/rfc7043#section-3.1>
const TYPE_EUI48: u16 = 108;
const TYPE_EUI64: u16 = 109;
// RFC 2930, Section 2 — <https://www.rfc-editor.org/rfc/rfc2930#section-2>
const TYPE_TKEY: u16 = 249;
// RFC 8945, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc8945#section-4.2>
const TYPE_TSIG: u16 = 250;
// RFC 7553, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc7553#section-4.5>
const TYPE_URI: u16 = 256;

/// DNS Stateful Operations opcode.
///
/// RFC 8490, Section 5.4.1 — <https://www.rfc-editor.org/rfc/rfc8490#section-5.4.1>
const OPCODE_DSO: u8 = 6;

// -- Field descriptor index constants for dns_field_descriptors! (main array) --
const FD_ID: usize = 1;
const FD_QR: usize = 2;
const FD_OPCODE: usize = 3;
const FD_AA: usize = 4;
const FD_TC: usize = 5;
const FD_RD: usize = 6;
const FD_RA: usize = 7;
const FD_Z: usize = 8;
const FD_AD: usize = 9;
const FD_CD: usize = 10;
const FD_RCODE: usize = 11;
const FD_QDCOUNT: usize = 12;
const FD_ANCOUNT: usize = 13;
const FD_NSCOUNT: usize = 14;
const FD_ARCOUNT: usize = 15;
const FD_QUESTIONS: usize = 16;
const FD_ANSWERS: usize = 17;
const FD_AUTHORITIES: usize = 18;
const FD_ADDITIONALS: usize = 19;
const FD_DSO_TLVS: usize = 20;

// -- Field descriptor index constants for QUESTION_CHILD_FIELDS --
const QFD_NAME: usize = 0;
const QFD_TYPE: usize = 1;
const QFD_CLASS: usize = 2;
// RFC 6762, Section 18.12 — top bit of qclass in the Question Section is the
// "QU" (unicast-response) bit, not part of the class. Emitted only in mDNS
// mode; the DNS dissector leaves this descriptor unused.
const QFD_QU: usize = 3;
// NOTE: type/class have display_fn for dns_type_name/dns_class_name; no separate _name fields.

// -- Field descriptor index constants for RR_CHILD_FIELDS --
// NOTE: type/class have display_fn for dns_type_name/dns_class_name; no separate _name fields.
const RRFD_NAME: usize = 0;
const RRFD_TYPE: usize = 1;
const RRFD_CLASS: usize = 2;
const RRFD_TTL: usize = 3;
const RRFD_RDLENGTH: usize = 4;
const RRFD_RDATA: usize = 5;
const RRFD_UDP_PAYLOAD_SIZE: usize = 6;
const RRFD_EXTENDED_RCODE: usize = 7;
const RRFD_EDNS_VERSION: usize = 8;
const RRFD_DO_BIT: usize = 9;
const RRFD_EDNS_OPTIONS: usize = 10;
const RRFD_RDATA_PREFERENCE: usize = 11;
const RRFD_RDATA_EXCHANGE: usize = 12;
const RRFD_RDATA_MNAME: usize = 13;
const RRFD_RDATA_RNAME: usize = 14;
const RRFD_RDATA_SERIAL: usize = 15;
const RRFD_RDATA_REFRESH: usize = 16;
const RRFD_RDATA_RETRY: usize = 17;
const RRFD_RDATA_EXPIRE: usize = 18;
const RRFD_RDATA_MINIMUM: usize = 19;
const RRFD_RDATA_PRIORITY: usize = 20;
const RRFD_RDATA_WEIGHT: usize = 21;
const RRFD_RDATA_PORT: usize = 22;
const RRFD_RDATA_TARGET: usize = 23;
const RRFD_RDATA_ORDER: usize = 24;
const RRFD_RDATA_FLAGS: usize = 25;
const RRFD_RDATA_SERVICES: usize = 26;
const RRFD_RDATA_REGEXP: usize = 27;
const RRFD_RDATA_REPLACEMENT: usize = 28;
const RRFD_RDATA_ALGORITHM: usize = 29;
const RRFD_RDATA_FINGERPRINT_TYPE: usize = 30;
const RRFD_RDATA_FINGERPRINT: usize = 31;
const RRFD_RDATA_KEY_TAG: usize = 32;
const RRFD_RDATA_DIGEST_TYPE: usize = 33;
const RRFD_RDATA_DIGEST: usize = 34;
const RRFD_RDATA_TYPE_COVERED: usize = 35;
const RRFD_RDATA_LABELS: usize = 36;
const RRFD_RDATA_ORIGINAL_TTL: usize = 37;
const RRFD_RDATA_SIGNATURE_EXPIRATION: usize = 38;
const RRFD_RDATA_SIGNATURE_INCEPTION: usize = 39;
const RRFD_RDATA_SIGNER_NAME: usize = 40;
const RRFD_RDATA_SIGNATURE: usize = 41;
const RRFD_RDATA_NEXT_DOMAIN_NAME: usize = 42;
const RRFD_RDATA_TYPE_BITMAPS: usize = 43;
const RRFD_RDATA_PROTOCOL: usize = 44;
const RRFD_RDATA_PUBLIC_KEY: usize = 45;
const RRFD_RDATA_HASH_ALGORITHM: usize = 46;
const RRFD_RDATA_ITERATIONS: usize = 47;
const RRFD_RDATA_SALT_LENGTH: usize = 48;
const RRFD_RDATA_SALT: usize = 49;
const RRFD_RDATA_HASH_LENGTH: usize = 50;
const RRFD_RDATA_NEXT_HASHED_OWNER: usize = 51;
const RRFD_RDATA_CERT_USAGE: usize = 52;
const RRFD_RDATA_SELECTOR: usize = 53;
const RRFD_RDATA_MATCHING_TYPE: usize = 54;
const RRFD_RDATA_CERT_ASSOC_DATA: usize = 55;
const RRFD_RDATA_TAG: usize = 56;
const RRFD_RDATA_VALUE: usize = 57;
const RRFD_RDATA_PARAMS: usize = 58;
// RFC 6762, Section 18.13 / 10.2 — cache-flush bit (top bit of rrclass).
// Emitted only in mDNS mode for non-OPT records; the DNS dissector leaves
// this descriptor unused.
const RRFD_CACHE_FLUSH: usize = 59;
// RFC 6891, Section 6.1.3 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3>:
// 12-bit RCODE combined from the OPT TTL and the header.
const RRFD_RCODE: usize = 60;
const RRFD_RDATA_TYPES: usize = 61;
const RRFD_RDATA_SVC_PARAMS: usize = 62;
const RRFD_RDATA_CPU: usize = 63;
const RRFD_RDATA_OS: usize = 64;
const RRFD_RDATA_VERSION: usize = 65;
const RRFD_RDATA_SIZE: usize = 66;
const RRFD_RDATA_HORIZ_PRE: usize = 67;
const RRFD_RDATA_VERT_PRE: usize = 68;
const RRFD_RDATA_LATITUDE: usize = 69;
const RRFD_RDATA_LONGITUDE: usize = 70;
const RRFD_RDATA_ALTITUDE: usize = 71;
const RRFD_RDATA_CERT_TYPE: usize = 72;
const RRFD_RDATA_CERTIFICATE: usize = 73;
const RRFD_RDATA_PRECEDENCE: usize = 74;
const RRFD_RDATA_GATEWAY_TYPE: usize = 75;
const RRFD_RDATA_GATEWAY_IPV4: usize = 76;
const RRFD_RDATA_GATEWAY_IPV6: usize = 77;
const RRFD_RDATA_GATEWAY_NAME: usize = 78;
const RRFD_RDATA_IDENTIFIER_TYPE: usize = 79;
const RRFD_RDATA_SCHEME: usize = 80;
const RRFD_RDATA_ALGORITHM_NAME: usize = 81;
const RRFD_RDATA_INCEPTION: usize = 82;
const RRFD_RDATA_EXPIRATION: usize = 83;
const RRFD_RDATA_MODE: usize = 84;
const RRFD_RDATA_ERROR: usize = 85;
const RRFD_RDATA_KEY_SIZE: usize = 86;
const RRFD_RDATA_KEY_DATA: usize = 87;
const RRFD_RDATA_OTHER_LENGTH: usize = 88;
const RRFD_RDATA_OTHER_DATA: usize = 89;
const RRFD_RDATA_TIME_SIGNED: usize = 90;
const RRFD_RDATA_FUDGE: usize = 91;
const RRFD_RDATA_MAC_SIZE: usize = 92;
const RRFD_RDATA_MAC: usize = 93;
const RRFD_RDATA_ORIGINAL_ID: usize = 94;
const RRFD_RDATA_URI: usize = 95;

/// DNS dissector.
pub struct DnsDissector;

/// Write a DNS domain name as a JSON-quoted string directly to the writer.
///
/// Walks the label-compressed wire format starting at `field_range.start`
/// within the DNS layer (`layer_range`) of `packet_data`, following
/// compression pointers as needed. Produces output like `"example.com"`.
///
/// Used as [`FormatFn`](packet_dissector_core::field::FormatFn) on DNS name
/// fields so that dissection stores only raw byte offsets (zero allocation)
/// and the human-readable dotted name is reconstructed at serialization time.
pub fn write_dns_name(
    _value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let layer_start = ctx.layer_range.start as usize;
    let layer_end = ctx.layer_range.end.min(ctx.packet_data.len() as u32) as usize;
    let msg = &ctx.packet_data[layer_start..layer_end];
    let name_pos = (ctx.field_range.start as usize).saturating_sub(layer_start);

    w.write_all(b"\"")?;

    let mut cursor = name_pos;
    let mut first = true;
    let mut depth = 0u8;

    loop {
        if depth >= MAX_POINTER_DEPTH as u8 || cursor >= msg.len() {
            break;
        }
        depth += 1;

        let byte = msg[cursor];
        match byte & 0xC0 {
            0x00 => {
                let len = byte as usize;
                if len == 0 {
                    break; // root terminator
                }
                if cursor + 1 + len > msg.len() {
                    break;
                }
                if !first {
                    w.write_all(b".")?;
                }
                first = false;
                w.write_all(&msg[cursor + 1..cursor + 1 + len])?;
                cursor += 1 + len;
            }
            0xC0 => {
                if cursor + 1 >= msg.len() {
                    break;
                }
                let offset = (((byte as usize) & 0x3F) << 8) | (msg[cursor + 1] as usize);
                cursor = offset;
            }
            _ => break, // reserved
        }
    }

    if first {
        // empty name = root "."
        w.write_all(b".")?;
    }

    w.write_all(b"\"")
}

/// Parse a DNS domain name from the message, handling label compression.
///
/// Returns `(domain_name, bytes_consumed_from_pos)`.
/// `msg` is the entire DNS message (for pointer resolution).
/// `pos` is the current read position within `msg`.
fn parse_name(msg: &[u8], pos: usize) -> Result<usize, PacketError> {
    let mut cursor = pos;
    let mut consumed = 0;
    let mut followed_pointer = false;
    let mut depth = 0;
    // RFC 1035, Section 3.1 — total name wire representation must be ≤ 255 octets
    let mut wire_len: usize = 0;

    loop {
        if depth >= MAX_POINTER_DEPTH {
            return Err(PacketError::InvalidHeader("DNS name pointer loop detected"));
        }
        depth += 1;

        if cursor >= msg.len() {
            return Err(PacketError::Truncated {
                expected: cursor + 1,
                actual: msg.len(),
            });
        }

        let byte = msg[cursor];

        match byte & 0xC0 {
            // Label
            0x00 => {
                let len = byte as usize;
                if len == 0 {
                    // Root terminator: count the 1-byte zero label
                    wire_len += 1;
                    if wire_len > 255 {
                        return Err(PacketError::InvalidHeader(
                            "DNS name too long (exceeds 255 octets)",
                        ));
                    }
                    if !followed_pointer {
                        consumed += 1;
                    }
                    break;
                }
                // RFC 1035, Section 3.1 — count 1 length byte + label content
                wire_len += 1 + len;
                if wire_len > 255 {
                    return Err(PacketError::InvalidHeader(
                        "DNS name too long (exceeds 255 octets)",
                    ));
                }
                if cursor + 1 + len > msg.len() {
                    return Err(PacketError::Truncated {
                        expected: cursor + 1 + len,
                        actual: msg.len(),
                    });
                }
                cursor += 1 + len;
                if !followed_pointer {
                    consumed += 1 + len;
                }
            }
            // Pointer
            0xC0 => {
                if cursor + 1 >= msg.len() {
                    return Err(PacketError::Truncated {
                        expected: cursor + 2,
                        actual: msg.len(),
                    });
                }
                let offset = (read_be_u16(msg, cursor)? & 0x3FFF) as usize;
                if !followed_pointer {
                    consumed += 2;
                    followed_pointer = true;
                }
                cursor = offset;
            }
            // Reserved (01, 10)
            _ => {
                return Err(PacketError::InvalidHeader("DNS name: reserved label type"));
            }
        }
    }

    Ok(consumed)
}

/// Parse a domain name embedded in RDATA and require that its in-place
/// encoding fits inside RDATA.
///
/// `rel_pos` is the name's offset relative to the start of RDATA. Returns the
/// number of octets the name occupies at `rel_pos`, or `None` if the name is
/// malformed or runs past RDLENGTH.
///
/// RFC 1035, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>:
/// "RDATA           a variable length string of octets that describes the
///                 resource."  Its length is given by RDLENGTH, so a name that
/// continues past it is malformed. A compression pointer (RFC 1035,
/// Section 4.1.4 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4>)
/// may still refer to a name elsewhere in the message; only the octets
/// encoded in place are bounded by RDATA. Pointers are accepted even in RR
/// types whose names must not be compressed (RFC 3597, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc3597#section-4>), since the dissector
/// is liberal in what it accepts.
fn parse_rdata_name(
    msg: &[u8],
    rdata_offset: usize,
    rdata_len: usize,
    rel_pos: usize,
) -> Option<usize> {
    let consumed = parse_name(msg, rdata_offset + rel_pos).ok()?;
    (rel_pos + consumed <= rdata_len).then_some(consumed)
}

/// Like [`parse_rdata_name`], for a name that is the last RDATA field: the
/// name must end exactly at RDLENGTH, since octets after the final field are
/// not part of any field.
fn parse_final_rdata_name(
    msg: &[u8],
    rdata_offset: usize,
    rdata_len: usize,
    rel_pos: usize,
) -> Option<usize> {
    parse_rdata_name(msg, rdata_offset, rdata_len, rel_pos)
        .filter(|&consumed| rel_pos + consumed == rdata_len)
}

/// Push an RR child field whose range is `start..end` relative to RDATA.
fn push_rr<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    idx: usize,
    value: FieldValue<'pkt>,
    abs_offset: usize,
    start: usize,
    end: usize,
) {
    buf.push_field(
        &RR_CHILD_FIELDS[idx],
        value,
        abs_offset + start..abs_offset + end,
    );
}

/// Locate the <character-string> at `pos` in `rdata`.
///
/// RFC 1035, Section 3.3 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.3>:
/// "<character-string> is a single length octet followed by that number of
/// characters."  Returns the range of the characters (without the length
/// octet), or `None` if the string runs past `rdata`.
fn character_string(rdata: &[u8], pos: usize) -> Option<(usize, usize)> {
    let len = *rdata.get(pos)? as usize;
    let end = pos + 1 + len;
    (end <= rdata.len()).then_some((pos + 1, end))
}

/// Parse RDATA into typed fields based on the record type.
///
/// `msg` is the full DNS message (needed for name compression in RDATA).
/// `rdata_offset` is the absolute offset of RDATA within `msg`.
/// `rdata` is the RDATA slice.
/// `rtype` is the DNS record type.
/// `abs_offset` is the absolute byte offset in the original packet for field ranges.
///
/// Returns a list of sub-fields. If the type is unknown or parsing fails,
/// falls back to a single `FieldValue::Bytes` field.
fn parse_rdata<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    msg: &'pkt [u8],
    rdata_offset: usize,
    rdata: &'pkt [u8],
    rtype: u16,
    abs_offset: usize,
) {
    let rdata_range = abs_offset..abs_offset + rdata.len();

    match rtype {
        // RFC 1035, Section 3.4.1 — A record: 4-byte IPv4 address
        TYPE_A if rdata.len() == 4 => {
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA],
                FieldValue::Ipv4Addr([rdata[0], rdata[1], rdata[2], rdata[3]]),
                rdata_range,
            );
            return;
        }
        // RFC 3596 — AAAA record: 16-byte IPv6 address
        TYPE_AAAA if rdata.len() == 16 => {
            let addr: [u8; 16] = [
                rdata[0], rdata[1], rdata[2], rdata[3], rdata[4], rdata[5], rdata[6], rdata[7],
                rdata[8], rdata[9], rdata[10], rdata[11], rdata[12], rdata[13], rdata[14],
                rdata[15],
            ];
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA],
                FieldValue::Ipv6Addr(addr),
                rdata_range,
            );
            return;
        }
        // RFC 1035, Section 3.3.1/3.3.11/3.3.12 — CNAME/NS/PTR
        // RFC 6672 — DNAME: a single domain name
        TYPE_CNAME | TYPE_NS | TYPE_PTR | TYPE_DNAME => {
            if parse_rdata_name(msg, rdata_offset, rdata.len(), 0).is_some() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA],
                    FieldValue::Bytes(rdata),
                    rdata_range,
                );
                return;
            }
        }
        // RFC 1035, Section 3.3.9 — MX: preference (U16) + exchange (domain name)
        TYPE_MX if rdata.len() >= 3 => {
            let preference = read_be_u16(rdata, 0).unwrap_or_default();
            if parse_final_rdata_name(msg, rdata_offset, rdata.len(), 2).is_some() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PREFERENCE],
                    FieldValue::U16(preference),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_EXCHANGE],
                    FieldValue::Bytes(&rdata[2..]),
                    abs_offset + 2..abs_offset + rdata.len(),
                );
                return;
            }
        }
        // RFC 1035, Section 3.3.14 — TXT: one or more character-strings
        TYPE_TXT => {
            // Store raw TXT RDATA bytes — character-string decoding deferred to FormatFn.
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA],
                FieldValue::Bytes(rdata),
                rdata_range,
            );
            return;
        }
        // RFC 1035, Section 3.3.13 — SOA
        TYPE_SOA => {
            if let Some(mname_len) = parse_rdata_name(msg, rdata_offset, rdata.len(), 0) {
                if let Some(rname_len) = parse_rdata_name(msg, rdata_offset, rdata.len(), mname_len)
                {
                    let timers_off = mname_len + rname_len;
                    // MINIMUM is the last SOA field — RFC 1035, Section 3.3.13
                    // <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13>
                    if timers_off + 20 == rdata.len() {
                        let t = timers_off;
                        let serial = read_be_u32(rdata, t).unwrap_or_default();
                        let refresh = read_be_u32(rdata, t + 4).unwrap_or_default();
                        let retry = read_be_u32(rdata, t + 8).unwrap_or_default();
                        let expire = read_be_u32(rdata, t + 12).unwrap_or_default();
                        let minimum = read_be_u32(rdata, t + 16).unwrap_or_default();
                        let mname_end = abs_offset + mname_len;
                        let rname_end = mname_end + rname_len;
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_MNAME],
                            FieldValue::Bytes(&rdata[..mname_len]),
                            abs_offset..mname_end,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_RNAME],
                            FieldValue::Bytes(&rdata[mname_len..timers_off]),
                            mname_end..rname_end,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_SERIAL],
                            FieldValue::U32(serial),
                            rname_end..rname_end + 4,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_REFRESH],
                            FieldValue::U32(refresh),
                            rname_end + 4..rname_end + 8,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_RETRY],
                            FieldValue::U32(retry),
                            rname_end + 8..rname_end + 12,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_EXPIRE],
                            FieldValue::U32(expire),
                            rname_end + 12..rname_end + 16,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_MINIMUM],
                            FieldValue::U32(minimum),
                            rname_end + 16..rname_end + 20,
                        );
                        return;
                    }
                }
            }
        }
        // RFC 2782 — SRV: priority(2) + weight(2) + port(2) + target(name)
        TYPE_SRV if rdata.len() >= 7 => {
            let priority = read_be_u16(rdata, 0).unwrap_or_default();
            let weight = read_be_u16(rdata, 2).unwrap_or_default();
            let port = read_be_u16(rdata, 4).unwrap_or_default();
            if parse_final_rdata_name(msg, rdata_offset, rdata.len(), 6).is_some() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PRIORITY],
                    FieldValue::U16(priority),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_WEIGHT],
                    FieldValue::U16(weight),
                    abs_offset + 2..abs_offset + 4,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PORT],
                    FieldValue::U16(port),
                    abs_offset + 4..abs_offset + 6,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TARGET],
                    FieldValue::Bytes(&rdata[6..]),
                    abs_offset + 6..abs_offset + rdata.len(),
                );
                return;
            }
        }
        // RFC 3403 — NAPTR: order(2) + preference(2) + flags(charstr) + services(charstr) + regexp(charstr) + replacement(name)
        TYPE_NAPTR if rdata.len() >= 7 => {
            let order = read_be_u16(rdata, 0).unwrap_or_default();
            let preference = read_be_u16(rdata, 2).unwrap_or_default();
            let mut pos = 4;
            // Parse three character-strings: flags, services, regexp.
            // Fixed-size array to keep dissection zero-allocation.
            let mut byte_ranges: [(usize, usize); 3] = [(0, 0); 3];
            let mut n = 0usize;
            for _ in 0..3 {
                if pos >= rdata.len() {
                    break;
                }
                let str_len = rdata[pos] as usize;
                let str_start = pos;
                pos += 1;
                if pos + str_len > rdata.len() {
                    break;
                }
                byte_ranges[n] = (str_start, pos + str_len);
                n += 1;
                pos += str_len;
            }
            if n == 3 && parse_final_rdata_name(msg, rdata_offset, rdata.len(), pos).is_some() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_ORDER],
                    FieldValue::U16(order),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PREFERENCE],
                    FieldValue::U16(preference),
                    abs_offset + 2..abs_offset + 4,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_FLAGS],
                    FieldValue::Bytes(&rdata[byte_ranges[0].0..byte_ranges[0].1]),
                    abs_offset + byte_ranges[0].0..abs_offset + byte_ranges[0].1,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SERVICES],
                    FieldValue::Bytes(&rdata[byte_ranges[1].0..byte_ranges[1].1]),
                    abs_offset + byte_ranges[1].0..abs_offset + byte_ranges[1].1,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_REGEXP],
                    FieldValue::Bytes(&rdata[byte_ranges[2].0..byte_ranges[2].1]),
                    abs_offset + byte_ranges[2].0..abs_offset + byte_ranges[2].1,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_REPLACEMENT],
                    FieldValue::Bytes(&rdata[pos..]),
                    abs_offset + pos..abs_offset + rdata.len(),
                );
                return;
            }
        }
        // RFC 4255 — SSHFP: algorithm(1) + fingerprint_type(1) + fingerprint(rest)
        TYPE_SSHFP if rdata.len() >= 2 => {
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_ALGORITHM],
                FieldValue::U8(rdata[0]),
                abs_offset..abs_offset + 1,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_FINGERPRINT_TYPE],
                FieldValue::U8(rdata[1]),
                abs_offset + 1..abs_offset + 2,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_FINGERPRINT],
                FieldValue::Bytes(&rdata[2..]),
                abs_offset + 2..abs_offset + rdata.len(),
            );
            return;
        }
        // RFC 6698 — TLSA: cert_usage(1) + selector(1) + matching_type(1) + cert_assoc_data(rest)
        TYPE_TLSA if rdata.len() >= 3 => {
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_CERT_USAGE],
                FieldValue::U8(rdata[0]),
                abs_offset..abs_offset + 1,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_SELECTOR],
                FieldValue::U8(rdata[1]),
                abs_offset + 1..abs_offset + 2,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_MATCHING_TYPE],
                FieldValue::U8(rdata[2]),
                abs_offset + 2..abs_offset + 3,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_CERT_ASSOC_DATA],
                FieldValue::Bytes(&rdata[3..]),
                abs_offset + 3..abs_offset + rdata.len(),
            );
            return;
        }
        // RFC 4035 — DS / RFC 7344 — CDS: key_tag(2) + algorithm(1) + digest_type(1) + digest(rest)
        TYPE_DS | TYPE_CDS if rdata.len() >= 4 => {
            let key_tag = read_be_u16(rdata, 0).unwrap_or_default();
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_KEY_TAG],
                FieldValue::U16(key_tag),
                abs_offset..abs_offset + 2,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_ALGORITHM],
                FieldValue::U8(rdata[2]),
                abs_offset + 2..abs_offset + 3,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_DIGEST_TYPE],
                FieldValue::U8(rdata[3]),
                abs_offset + 3..abs_offset + 4,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_DIGEST],
                FieldValue::Bytes(&rdata[4..]),
                abs_offset + 4..abs_offset + rdata.len(),
            );
            return;
        }
        // RFC 4035 — RRSIG: type_covered(2) + algorithm(1) + labels(1) + original_ttl(4)
        //   + sig_expiration(4) + sig_inception(4) + key_tag(2) + signer_name + signature
        TYPE_RRSIG if rdata.len() >= 18 => {
            let type_covered = read_be_u16(rdata, 0).unwrap_or_default();
            let algorithm = rdata[2];
            let labels = rdata[3];
            let original_ttl = read_be_u32(rdata, 4).unwrap_or_default();
            let sig_expiration = read_be_u32(rdata, 8).unwrap_or_default();
            let sig_inception = read_be_u32(rdata, 12).unwrap_or_default();
            let key_tag = read_be_u16(rdata, 16).unwrap_or_default();
            if let Some(signer_name_len) = parse_rdata_name(msg, rdata_offset, rdata.len(), 18) {
                let sig_start = 18 + signer_name_len;
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TYPE_COVERED],
                    FieldValue::U16(type_covered),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_ALGORITHM],
                    FieldValue::U8(algorithm),
                    abs_offset + 2..abs_offset + 3,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_LABELS],
                    FieldValue::U8(labels),
                    abs_offset + 3..abs_offset + 4,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_ORIGINAL_TTL],
                    FieldValue::U32(original_ttl),
                    abs_offset + 4..abs_offset + 8,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SIGNATURE_EXPIRATION],
                    FieldValue::U32(sig_expiration),
                    abs_offset + 8..abs_offset + 12,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SIGNATURE_INCEPTION],
                    FieldValue::U32(sig_inception),
                    abs_offset + 12..abs_offset + 16,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_KEY_TAG],
                    FieldValue::U16(key_tag),
                    abs_offset + 16..abs_offset + 18,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SIGNER_NAME],
                    FieldValue::Bytes(&rdata[18..sig_start]),
                    abs_offset + 18..abs_offset + sig_start,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SIGNATURE],
                    FieldValue::Bytes(&rdata[sig_start..]),
                    abs_offset + sig_start..abs_offset + rdata.len(),
                );
                return;
            }
        }
        // RFC 4035 — NSEC: next_domain_name + type_bitmaps
        TYPE_NSEC => {
            if let Some(name_len) = parse_rdata_name(msg, rdata_offset, rdata.len(), 0) {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_NEXT_DOMAIN_NAME],
                    FieldValue::Bytes(&rdata[..name_len]),
                    abs_offset..abs_offset + name_len,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TYPE_BITMAPS],
                    FieldValue::Bytes(&rdata[name_len..]),
                    abs_offset + name_len..abs_offset + rdata.len(),
                );
                push_type_bitmap(
                    buf,
                    &RR_CHILD_FIELDS[RRFD_RDATA_TYPES],
                    &rdata[name_len..],
                    abs_offset + name_len,
                );
                return;
            }
        }
        // RFC 4035 — DNSKEY / RFC 7344 — CDNSKEY: flags(2) + protocol(1) + algorithm(1) + public_key(rest)
        TYPE_DNSKEY | TYPE_CDNSKEY if rdata.len() >= 4 => {
            let flags = read_be_u16(rdata, 0).unwrap_or_default();
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_FLAGS],
                FieldValue::U16(flags),
                abs_offset..abs_offset + 2,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_PROTOCOL],
                FieldValue::U8(rdata[2]),
                abs_offset + 2..abs_offset + 3,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_ALGORITHM],
                FieldValue::U8(rdata[3]),
                abs_offset + 3..abs_offset + 4,
            );
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA_PUBLIC_KEY],
                FieldValue::Bytes(&rdata[4..]),
                abs_offset + 4..abs_offset + rdata.len(),
            );
            return;
        }
        // RFC 5155 — NSEC3: hash_alg(1) + flags(1) + iterations(2) + salt_len(1) + salt
        //   + hash_len(1) + next_hashed_owner + type_bitmaps
        TYPE_NSEC3 if rdata.len() >= 5 => {
            let hash_algorithm = rdata[0];
            let flags = rdata[1];
            let iterations = read_be_u16(rdata, 2).unwrap_or_default();
            let salt_length = rdata[4] as usize;
            let salt_end = 5 + salt_length;
            if salt_end < rdata.len() {
                let hash_length = rdata[salt_end] as usize;
                let hash_start = salt_end + 1;
                let hash_end = hash_start + hash_length;
                if hash_end <= rdata.len() {
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_HASH_ALGORITHM],
                        FieldValue::U8(hash_algorithm),
                        abs_offset..abs_offset + 1,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_FLAGS],
                        FieldValue::U8(flags),
                        abs_offset + 1..abs_offset + 2,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_ITERATIONS],
                        FieldValue::U16(iterations),
                        abs_offset + 2..abs_offset + 4,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_SALT_LENGTH],
                        FieldValue::U8(salt_length as u8),
                        abs_offset + 4..abs_offset + 5,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_SALT],
                        FieldValue::Bytes(&rdata[5..salt_end]),
                        abs_offset + 5..abs_offset + salt_end,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_HASH_LENGTH],
                        FieldValue::U8(hash_length as u8),
                        abs_offset + salt_end..abs_offset + hash_start,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_NEXT_HASHED_OWNER],
                        FieldValue::Bytes(&rdata[hash_start..hash_end]),
                        abs_offset + hash_start..abs_offset + hash_end,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_TYPE_BITMAPS],
                        FieldValue::Bytes(&rdata[hash_end..]),
                        abs_offset + hash_end..abs_offset + rdata.len(),
                    );
                    // RFC 5155, Section 3.2.1 — <https://www.rfc-editor.org/rfc/rfc5155#section-3.2.1>
                    push_type_bitmap(
                        buf,
                        &RR_CHILD_FIELDS[RRFD_RDATA_TYPES],
                        &rdata[hash_end..],
                        abs_offset + hash_end,
                    );
                    return;
                }
            }
        }
        // RFC 5155 §4.2 — NSEC3PARAM: hash_alg(1) + flags(1) + iterations(2) + salt_len(1) + salt
        TYPE_NSEC3PARAM if rdata.len() >= 5 => {
            let hash_algorithm = rdata[0];
            let flags = rdata[1];
            let iterations = read_be_u16(rdata, 2).unwrap_or_default();
            let salt_length = rdata[4] as usize;
            if 5 + salt_length <= rdata.len() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_HASH_ALGORITHM],
                    FieldValue::U8(hash_algorithm),
                    abs_offset..abs_offset + 1,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_FLAGS],
                    FieldValue::U8(flags),
                    abs_offset + 1..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_ITERATIONS],
                    FieldValue::U16(iterations),
                    abs_offset + 2..abs_offset + 4,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SALT_LENGTH],
                    FieldValue::U8(salt_length as u8),
                    abs_offset + 4..abs_offset + 5,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_SALT],
                    FieldValue::Bytes(&rdata[5..5 + salt_length]),
                    abs_offset + 5..abs_offset + 5 + salt_length,
                );
                return;
            }
        }
        // RFC 9460 — SVCB/HTTPS: SvcPriority(2) + TargetName(name) + SvcParams(rest)
        TYPE_SVCB | TYPE_HTTPS if rdata.len() >= 3 => {
            let priority = read_be_u16(rdata, 0).unwrap_or_default();
            if let Some(target_len) = parse_rdata_name(msg, rdata_offset, rdata.len(), 2) {
                let params_start = 2 + target_len;
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PRIORITY],
                    FieldValue::U16(priority),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TARGET],
                    FieldValue::Bytes(&rdata[2..params_start]),
                    abs_offset + 2..abs_offset + params_start,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PARAMS],
                    FieldValue::Bytes(&rdata[params_start..]),
                    abs_offset + params_start..abs_offset + rdata.len(),
                );
                push_svc_params(
                    buf,
                    &RR_CHILD_FIELDS[RRFD_RDATA_SVC_PARAMS],
                    &rdata[params_start..],
                    abs_offset + params_start,
                );
                return;
            }
        }
        // RFC 8659 — CAA: flags(1) + tag_length(1) + tag + value
        TYPE_CAA if rdata.len() >= 2 => {
            let flags = rdata[0];
            let tag_len = rdata[1] as usize;
            if 2 + tag_len <= rdata.len() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_FLAGS],
                    FieldValue::U8(flags),
                    abs_offset..abs_offset + 1,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TAG],
                    FieldValue::Bytes(&rdata[2..2 + tag_len]),
                    abs_offset + 2..abs_offset + 2 + tag_len,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_VALUE],
                    FieldValue::Bytes(&rdata[2 + tag_len..]),
                    abs_offset + 2 + tag_len..abs_offset + rdata.len(),
                );
                return;
            }
        }
        // RFC 1035, Section 3.3.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.2>
        // HINFO: CPU and OS character-strings (also used by RFC 8482,
        // Section 4.2 — <https://www.rfc-editor.org/rfc/rfc8482#section-4.2> — to answer ANY).
        TYPE_HINFO => {
            if let Some((cpu_start, cpu_end)) = character_string(rdata, 0) {
                if let Some((os_start, os_end)) = character_string(rdata, cpu_end) {
                    if os_end == rdata.len() {
                        push_rr(
                            buf,
                            RRFD_RDATA_CPU,
                            FieldValue::Bytes(&rdata[cpu_start..cpu_end]),
                            abs_offset,
                            cpu_start,
                            cpu_end,
                        );
                        push_rr(
                            buf,
                            RRFD_RDATA_OS,
                            FieldValue::Bytes(&rdata[os_start..os_end]),
                            abs_offset,
                            os_start,
                            os_end,
                        );
                        return;
                    }
                }
            }
        }
        // RFC 1876, Section 2 — <https://www.rfc-editor.org/rfc/rfc1876#section-2>
        // LOC version 0: VERSION, SIZE, HORIZ PRE, VERT PRE (1 octet each),
        // LATITUDE, LONGITUDE, ALTITUDE (4 octets each).
        TYPE_LOC if rdata.len() == 16 && rdata[0] == 0 => {
            push_rr(
                buf,
                RRFD_RDATA_VERSION,
                FieldValue::U8(rdata[0]),
                abs_offset,
                0,
                1,
            );
            push_rr(
                buf,
                RRFD_RDATA_SIZE,
                FieldValue::U8(rdata[1]),
                abs_offset,
                1,
                2,
            );
            push_rr(
                buf,
                RRFD_RDATA_HORIZ_PRE,
                FieldValue::U8(rdata[2]),
                abs_offset,
                2,
                3,
            );
            push_rr(
                buf,
                RRFD_RDATA_VERT_PRE,
                FieldValue::U8(rdata[3]),
                abs_offset,
                3,
                4,
            );
            push_rr(
                buf,
                RRFD_RDATA_LATITUDE,
                FieldValue::U32(read_be_u32(rdata, 4).unwrap_or_default()),
                abs_offset,
                4,
                8,
            );
            push_rr(
                buf,
                RRFD_RDATA_LONGITUDE,
                FieldValue::U32(read_be_u32(rdata, 8).unwrap_or_default()),
                abs_offset,
                8,
                12,
            );
            push_rr(
                buf,
                RRFD_RDATA_ALTITUDE,
                FieldValue::U32(read_be_u32(rdata, 12).unwrap_or_default()),
                abs_offset,
                12,
                16,
            );
            return;
        }
        // RFC 4398, Section 2 — <https://www.rfc-editor.org/rfc/rfc4398#section-2>
        // CERT: type(2) + key tag(2) + algorithm(1) + certificate
        TYPE_CERT if rdata.len() >= 5 => {
            push_rr(
                buf,
                RRFD_RDATA_CERT_TYPE,
                FieldValue::U16(read_be_u16(rdata, 0).unwrap_or_default()),
                abs_offset,
                0,
                2,
            );
            push_rr(
                buf,
                RRFD_RDATA_KEY_TAG,
                FieldValue::U16(read_be_u16(rdata, 2).unwrap_or_default()),
                abs_offset,
                2,
                4,
            );
            push_rr(
                buf,
                RRFD_RDATA_ALGORITHM,
                FieldValue::U8(rdata[4]),
                abs_offset,
                4,
                5,
            );
            push_rr(
                buf,
                RRFD_RDATA_CERTIFICATE,
                FieldValue::Bytes(&rdata[5..]),
                abs_offset,
                5,
                rdata.len(),
            );
            return;
        }
        // RFC 4025, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc4025#section-2.1>
        // IPSECKEY: precedence(1) + gateway type(1) + algorithm(1) + gateway + public key
        TYPE_IPSECKEY if rdata.len() >= 3 => {
            // RFC 4025, Section 2.3 / 2.5 — gateway type 0: no gateway,
            // 1: 32-bit IPv4 address, 2: 128-bit IPv6 address, 3: an
            // uncompressed wire-encoded domain name.
            // <https://www.rfc-editor.org/rfc/rfc4025#section-2.5>
            let rest = &rdata[3..];
            let gateway = match rdata[1] {
                0 => Some((0, None)),
                1 if rest.len() >= 4 => Some((
                    4,
                    Some((
                        RRFD_RDATA_GATEWAY_IPV4,
                        FieldValue::Ipv4Addr([rest[0], rest[1], rest[2], rest[3]]),
                    )),
                )),
                2 if rest.len() >= 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&rest[..16]);
                    Some((16, Some((RRFD_RDATA_GATEWAY_IPV6, FieldValue::Ipv6Addr(a)))))
                }
                3 => uncompressed_name_len(rest).map(|n| {
                    (
                        n,
                        Some((RRFD_RDATA_GATEWAY_NAME, FieldValue::Bytes(&rest[..n]))),
                    )
                }),
                _ => None,
            };
            if let Some((gw_len, gw_field)) = gateway {
                push_rr(
                    buf,
                    RRFD_RDATA_PRECEDENCE,
                    FieldValue::U8(rdata[0]),
                    abs_offset,
                    0,
                    1,
                );
                push_rr(
                    buf,
                    RRFD_RDATA_GATEWAY_TYPE,
                    FieldValue::U8(rdata[1]),
                    abs_offset,
                    1,
                    2,
                );
                push_rr(
                    buf,
                    RRFD_RDATA_ALGORITHM,
                    FieldValue::U8(rdata[2]),
                    abs_offset,
                    2,
                    3,
                );
                if let Some((idx, value)) = gw_field {
                    push_rr(buf, idx, value, abs_offset, 3, 3 + gw_len);
                }
                push_rr(
                    buf,
                    RRFD_RDATA_PUBLIC_KEY,
                    FieldValue::Bytes(&rdata[3 + gw_len..]),
                    abs_offset,
                    3 + gw_len,
                    rdata.len(),
                );
                return;
            }
        }
        // RFC 4701, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4701#section-3.1>
        // DHCID: identifier type(2) + digest type(1) + digest
        TYPE_DHCID if rdata.len() >= 3 => {
            push_rr(
                buf,
                RRFD_RDATA_IDENTIFIER_TYPE,
                FieldValue::U16(read_be_u16(rdata, 0).unwrap_or_default()),
                abs_offset,
                0,
                2,
            );
            push_rr(
                buf,
                RRFD_RDATA_DIGEST_TYPE,
                FieldValue::U8(rdata[2]),
                abs_offset,
                2,
                3,
            );
            push_rr(
                buf,
                RRFD_RDATA_DIGEST,
                FieldValue::Bytes(&rdata[3..]),
                abs_offset,
                3,
                rdata.len(),
            );
            return;
        }
        // RFC 7929, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc7929#section-2.1>
        // OPENPGPKEY: a single OpenPGP Transferable Public Key.
        TYPE_OPENPGPKEY if !rdata.is_empty() => {
            push_rr(
                buf,
                RRFD_RDATA_PUBLIC_KEY,
                FieldValue::Bytes(rdata),
                abs_offset,
                0,
                rdata.len(),
            );
            return;
        }
        // RFC 7477, Section 2.1.1 — <https://www.rfc-editor.org/rfc/rfc7477#section-2.1.1>
        // CSYNC: SOA serial(4) + flags(2) + type bit map
        TYPE_CSYNC if rdata.len() >= 6 => {
            push_rr(
                buf,
                RRFD_RDATA_SERIAL,
                FieldValue::U32(read_be_u32(rdata, 0).unwrap_or_default()),
                abs_offset,
                0,
                4,
            );
            push_rr(
                buf,
                RRFD_RDATA_FLAGS,
                FieldValue::U16(read_be_u16(rdata, 4).unwrap_or_default()),
                abs_offset,
                4,
                6,
            );
            push_rr(
                buf,
                RRFD_RDATA_TYPE_BITMAPS,
                FieldValue::Bytes(&rdata[6..]),
                abs_offset,
                6,
                rdata.len(),
            );
            push_type_bitmap(
                buf,
                &RR_CHILD_FIELDS[RRFD_RDATA_TYPES],
                &rdata[6..],
                abs_offset + 6,
            );
            return;
        }
        // RFC 8976, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8976#section-2.2>
        // ZONEMD: serial(4) + scheme(1) + hash algorithm(1) + digest
        TYPE_ZONEMD if rdata.len() >= 6 => {
            push_rr(
                buf,
                RRFD_RDATA_SERIAL,
                FieldValue::U32(read_be_u32(rdata, 0).unwrap_or_default()),
                abs_offset,
                0,
                4,
            );
            push_rr(
                buf,
                RRFD_RDATA_SCHEME,
                FieldValue::U8(rdata[4]),
                abs_offset,
                4,
                5,
            );
            push_rr(
                buf,
                RRFD_RDATA_HASH_ALGORITHM,
                FieldValue::U8(rdata[5]),
                abs_offset,
                5,
                6,
            );
            push_rr(
                buf,
                RRFD_RDATA_DIGEST,
                FieldValue::Bytes(&rdata[6..]),
                abs_offset,
                6,
                rdata.len(),
            );
            return;
        }
        // RFC 7043, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc7043#section-3.1>
        // EUI48: a 6-octet address.
        TYPE_EUI48 if rdata.len() == 6 => {
            let mut a = [0u8; 6];
            a.copy_from_slice(rdata);
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA],
                FieldValue::MacAddr(MacAddr(a)),
                rdata_range,
            );
            return;
        }
        // RFC 7043, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc7043#section-4.1>
        // EUI64: an 8-octet address, shown as raw bytes (there is no 8-octet
        // address value type).
        TYPE_EUI64 if rdata.len() == 8 => {
            buf.push_field(
                &RR_CHILD_FIELDS[RRFD_RDATA],
                FieldValue::Bytes(rdata),
                rdata_range,
            );
            return;
        }
        // RFC 2930, Section 2 — <https://www.rfc-editor.org/rfc/rfc2930#section-2>
        // TKEY: algorithm(name) + inception(4) + expiration(4) + mode(2)
        //   + error(2) + key size(2) + key data + other size(2) + other data
        // RFC 3597, Section 4 — <https://www.rfc-editor.org/rfc/rfc3597#section-4>:
        // only the RR types defined in RFC 1035 are "well-known", and servers
        // "MUST NOT compress domain names embedded in the RDATA of types that
        // are class-specific or not well-known", so the TKEY Algorithm name
        // is uncompressed.
        TYPE_TKEY => {
            if let Some(n) = uncompressed_name_len(rdata) {
                let key_size = read_be_u16(rdata, n + 12).map(usize::from);
                if let Ok(key_size) = key_size {
                    let key_end = n + 14 + key_size;
                    if let Ok(other) = read_be_u16(rdata, key_end) {
                        let other_end = key_end + 2 + other as usize;
                        if other_end == rdata.len() {
                            push_rr(
                                buf,
                                RRFD_RDATA_ALGORITHM_NAME,
                                FieldValue::Bytes(&rdata[..n]),
                                abs_offset,
                                0,
                                n,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_INCEPTION,
                                FieldValue::U32(read_be_u32(rdata, n).unwrap_or_default()),
                                abs_offset,
                                n,
                                n + 4,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_EXPIRATION,
                                FieldValue::U32(read_be_u32(rdata, n + 4).unwrap_or_default()),
                                abs_offset,
                                n + 4,
                                n + 8,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_MODE,
                                FieldValue::U16(read_be_u16(rdata, n + 8).unwrap_or_default()),
                                abs_offset,
                                n + 8,
                                n + 10,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_ERROR,
                                FieldValue::U16(read_be_u16(rdata, n + 10).unwrap_or_default()),
                                abs_offset,
                                n + 10,
                                n + 12,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_KEY_SIZE,
                                FieldValue::U16(key_size as u16),
                                abs_offset,
                                n + 12,
                                n + 14,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_KEY_DATA,
                                FieldValue::Bytes(&rdata[n + 14..key_end]),
                                abs_offset,
                                n + 14,
                                key_end,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_OTHER_LENGTH,
                                FieldValue::U16(other),
                                abs_offset,
                                key_end,
                                key_end + 2,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_OTHER_DATA,
                                FieldValue::Bytes(&rdata[key_end + 2..]),
                                abs_offset,
                                key_end + 2,
                                other_end,
                            );
                            return;
                        }
                    }
                }
            }
        }
        // RFC 8945, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc8945#section-4.2>
        // TSIG: algorithm(name) + time signed(6) + fudge(2) + MAC size(2) + MAC
        //   + original ID(2) + error(2) + other len(2) + other data
        // Algorithm Name: "As per [RFC3597], this name MUST NOT be compressed."
        TYPE_TSIG => {
            if let Some(n) = uncompressed_name_len(rdata) {
                if let Ok(mac_size) = read_be_u16(rdata, n + 8) {
                    let mac_end = n + 10 + mac_size as usize;
                    if let Ok(other) = read_be_u16(rdata, mac_end + 4) {
                        let other_end = mac_end + 6 + other as usize;
                        if other_end == rdata.len() {
                            let time_hi = read_be_u16(rdata, n).unwrap_or_default() as u64;
                            let time_lo = read_be_u32(rdata, n + 2).unwrap_or_default() as u64;
                            push_rr(
                                buf,
                                RRFD_RDATA_ALGORITHM_NAME,
                                FieldValue::Bytes(&rdata[..n]),
                                abs_offset,
                                0,
                                n,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_TIME_SIGNED,
                                FieldValue::U64((time_hi << 32) | time_lo),
                                abs_offset,
                                n,
                                n + 6,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_FUDGE,
                                FieldValue::U16(read_be_u16(rdata, n + 6).unwrap_or_default()),
                                abs_offset,
                                n + 6,
                                n + 8,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_MAC_SIZE,
                                FieldValue::U16(mac_size),
                                abs_offset,
                                n + 8,
                                n + 10,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_MAC,
                                FieldValue::Bytes(&rdata[n + 10..mac_end]),
                                abs_offset,
                                n + 10,
                                mac_end,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_ORIGINAL_ID,
                                FieldValue::U16(read_be_u16(rdata, mac_end).unwrap_or_default()),
                                abs_offset,
                                mac_end,
                                mac_end + 2,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_ERROR,
                                FieldValue::U16(
                                    read_be_u16(rdata, mac_end + 2).unwrap_or_default(),
                                ),
                                abs_offset,
                                mac_end + 2,
                                mac_end + 4,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_OTHER_LENGTH,
                                FieldValue::U16(other),
                                abs_offset,
                                mac_end + 4,
                                mac_end + 6,
                            );
                            push_rr(
                                buf,
                                RRFD_RDATA_OTHER_DATA,
                                FieldValue::Bytes(&rdata[mac_end + 6..]),
                                abs_offset,
                                mac_end + 6,
                                other_end,
                            );
                            return;
                        }
                    }
                }
            }
        }
        // RFC 7553, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc7553#section-4.5>
        // URI: priority(2) + weight(2) + target (the rest, at least one octet)
        TYPE_URI if rdata.len() > 4 => {
            push_rr(
                buf,
                RRFD_RDATA_PRIORITY,
                FieldValue::U16(read_be_u16(rdata, 0).unwrap_or_default()),
                abs_offset,
                0,
                2,
            );
            push_rr(
                buf,
                RRFD_RDATA_WEIGHT,
                FieldValue::U16(read_be_u16(rdata, 2).unwrap_or_default()),
                abs_offset,
                2,
                4,
            );
            push_rr(
                buf,
                RRFD_RDATA_URI,
                FieldValue::Bytes(&rdata[4..]),
                abs_offset,
                4,
                rdata.len(),
            );
            return;
        }
        _ => {}
    }

    // Fallback: raw bytes for unknown or malformed rdata
    buf.push_field(
        &RR_CHILD_FIELDS[RRFD_RDATA],
        FieldValue::Bytes(rdata),
        rdata_range,
    );
}

/// Child field descriptors for question section entries.
///
/// The `qu` descriptor is emitted only by the mDNS parsing path per
/// RFC 6762, Section 18.12 — <https://www.rfc-editor.org/rfc/rfc6762#section-18.12>.
static QUESTION_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("name", "Name", FieldType::Bytes).with_format_fn(write_dns_name),
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => dns_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "class",
        display_name: "Class",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(c) => dns_class_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    // RFC 6762, Section 18.12 / 5.4 — unicast-response bit (top bit of qclass).
    // <https://www.rfc-editor.org/rfc/rfc6762#section-18.12>
    FieldDescriptor::new("qu", "Unicast Response", FieldType::U8).optional(),
];

/// Child field descriptors for resource record entries (answers, authorities, additionals).
///
/// This is a union of all fields emitted by [`parse_rdata`] across every supported
/// record type.  Fields that only appear for certain record types are marked `optional`.
static RR_CHILD_FIELDS: &[FieldDescriptor] = &[
    // -- Common RR fields (all record types) --
    FieldDescriptor::new("name", "Name", FieldType::Bytes).with_format_fn(write_dns_name),
    FieldDescriptor {
        name: "type",
        display_name: "Type",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => dns_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor {
        name: "class",
        display_name: "Class",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(c) => dns_class_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("ttl", "TTL", FieldType::U32).optional(),
    FieldDescriptor::new("rdlength", "Data Length", FieldType::U16).optional(),
    // A / AAAA / CNAME / NS / PTR / DNAME / TXT / fallback
    FieldDescriptor::new("rdata", "Data", FieldType::Str).optional(),
    // -- OPT (EDNS0) --
    FieldDescriptor::new("udp_payload_size", "UDP Payload Size", FieldType::U16).optional(),
    FieldDescriptor::new("extended_rcode", "Extended RCODE", FieldType::U8).optional(),
    FieldDescriptor::new("edns_version", "EDNS Version", FieldType::U8).optional(),
    FieldDescriptor::new("do_bit", "DO Bit", FieldType::U8).optional(),
    FieldDescriptor::new("edns_options", "EDNS Options", FieldType::Array)
        .optional()
        .with_children(EDNS_OPTION_CHILD_FIELDS),
    // -- MX --
    FieldDescriptor::new("rdata_preference", "Preference", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_exchange", "Mail Exchange", FieldType::Str).optional(),
    // -- SOA --
    FieldDescriptor::new("rdata_mname", "Primary Name Server", FieldType::Str).optional(),
    FieldDescriptor::new(
        "rdata_rname",
        "Responsible Authority Mailbox",
        FieldType::Str,
    )
    .optional(),
    FieldDescriptor::new("rdata_serial", "Serial Number", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_refresh", "Refresh Interval", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_retry", "Retry Interval", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_expire", "Expire Limit", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_minimum", "Minimum TTL", FieldType::U32).optional(),
    // -- SRV / SVCB / HTTPS --
    FieldDescriptor::new("rdata_priority", "Priority", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_weight", "Weight", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_port", "Port", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_target", "Target", FieldType::Str).optional(),
    // -- NAPTR --
    FieldDescriptor::new("rdata_order", "Order", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_flags", "Flags", FieldType::Str).optional(),
    FieldDescriptor::new("rdata_services", "Service", FieldType::Str).optional(),
    FieldDescriptor::new("rdata_regexp", "Regular Expression", FieldType::Str).optional(),
    FieldDescriptor::new("rdata_replacement", "Replacement", FieldType::Str).optional(),
    // -- SSHFP --
    FieldDescriptor::new("rdata_algorithm", "Algorithm", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_fingerprint_type", "Fingerprint Type", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_fingerprint", "Fingerprint", FieldType::Bytes).optional(),
    // -- DS / CDS --
    FieldDescriptor::new("rdata_key_tag", "Key Tag", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_digest_type", "Digest Type", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_digest", "Digest", FieldType::Bytes).optional(),
    // -- RRSIG --
    FieldDescriptor::new("rdata_type_covered", "Type Covered", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_labels", "Labels", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_original_ttl", "Original TTL", FieldType::U32).optional(),
    FieldDescriptor::new(
        "rdata_signature_expiration",
        "Signature Expiration",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new(
        "rdata_signature_inception",
        "Signature Inception",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("rdata_signer_name", "Signer's Name", FieldType::Str).optional(),
    FieldDescriptor::new("rdata_signature", "Signature", FieldType::Bytes).optional(),
    // -- NSEC --
    FieldDescriptor::new("rdata_next_domain_name", "Next Domain Name", FieldType::Str).optional(),
    FieldDescriptor::new("rdata_type_bitmaps", "Type Bit Maps", FieldType::Bytes).optional(),
    // -- DNSKEY / CDNSKEY --
    FieldDescriptor::new("rdata_protocol", "Protocol", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_public_key", "Public Key", FieldType::Bytes).optional(),
    // -- NSEC3 / NSEC3PARAM --
    FieldDescriptor::new("rdata_hash_algorithm", "Hash Algorithm", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_iterations", "Iterations", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_salt_length", "Salt Length", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_salt", "Salt", FieldType::Bytes).optional(),
    FieldDescriptor::new("rdata_hash_length", "Hash Length", FieldType::U8).optional(),
    FieldDescriptor::new(
        "rdata_next_hashed_owner",
        "Next Hashed Owner Name",
        FieldType::Bytes,
    )
    .optional(),
    // -- TLSA --
    FieldDescriptor::new("rdata_cert_usage", "Certificate Usage", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_selector", "Selector", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_matching_type", "Matching Type", FieldType::U8).optional(),
    FieldDescriptor::new(
        "rdata_cert_assoc_data",
        "Certificate Association Data",
        FieldType::Bytes,
    )
    .optional(),
    // -- CAA --
    FieldDescriptor::new("rdata_tag", "Tag", FieldType::Str).optional(),
    FieldDescriptor::new("rdata_value", "Value", FieldType::Str).optional(),
    // -- SVCB / HTTPS --
    FieldDescriptor::new("rdata_params", "SvcParams", FieldType::Bytes).optional(),
    // -- mDNS: cache-flush bit (top bit of rrclass) --
    // RFC 6762, Section 18.13 / 10.2 — <https://www.rfc-editor.org/rfc/rfc6762#section-10.2>
    // Emitted by the mDNS parsing path for non-OPT records only.
    FieldDescriptor::new("cache_flush", "Cache Flush", FieldType::U8).optional(),
    // -- OPT: combined 12-bit RCODE --
    // RFC 6891, Section 6.1.3 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3>
    FieldDescriptor {
        name: "rcode",
        display_name: "Response Code",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(r) => dns_extended_rcode_name(*r),
            _ => None,
        }),
        format_fn: None,
    },
    // -- NSEC / NSEC3 / CSYNC: decoded type bit maps --
    // RFC 4034, Section 4.1.2 — <https://www.rfc-editor.org/rfc/rfc4034#section-4.1.2>
    FieldDescriptor::new("rdata_types", "Types", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&FD_BITMAP_TYPE)),
    // -- SVCB / HTTPS: decoded SvcParams --
    // RFC 9460, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc9460#section-2.2>
    FieldDescriptor::new("rdata_svc_params", "SvcParams", FieldType::Array)
        .optional()
        .with_children(SVC_PARAM_CHILD_FIELDS),
    // -- HINFO: RFC 1035, Section 3.3.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.2> --
    FieldDescriptor::new("rdata_cpu", "CPU", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("rdata_os", "OS", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    // -- LOC: RFC 1876, Section 2 — <https://www.rfc-editor.org/rfc/rfc1876#section-2> --
    FieldDescriptor::new("rdata_version", "Version", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_size", "Size", FieldType::U8).optional(),
    FieldDescriptor::new(
        "rdata_horizontal_precision",
        "Horizontal Precision",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "rdata_vertical_precision",
        "Vertical Precision",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("rdata_latitude", "Latitude", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_longitude", "Longitude", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_altitude", "Altitude", FieldType::U32).optional(),
    // -- CERT: RFC 4398, Section 2 — <https://www.rfc-editor.org/rfc/rfc4398#section-2> --
    FieldDescriptor::new("rdata_cert_type", "Certificate Type", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_certificate", "Certificate", FieldType::Bytes).optional(),
    // -- IPSECKEY: RFC 4025, Section 2.1 — <https://www.rfc-editor.org/rfc/rfc4025#section-2.1> --
    FieldDescriptor::new("rdata_precedence", "Precedence", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_gateway_type", "Gateway Type", FieldType::U8).optional(),
    FieldDescriptor::new("rdata_gateway_ipv4", "Gateway", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("rdata_gateway_ipv6", "Gateway", FieldType::Ipv6Addr).optional(),
    FieldDescriptor::new("rdata_gateway_name", "Gateway", FieldType::Bytes)
        .optional()
        .with_format_fn(write_dns_name),
    // -- DHCID: RFC 4701, Section 3.1 — <https://www.rfc-editor.org/rfc/rfc4701#section-3.1> --
    FieldDescriptor::new("rdata_identifier_type", "Identifier Type", FieldType::U16).optional(),
    // -- ZONEMD: RFC 8976, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc8976#section-2.2> --
    FieldDescriptor::new("rdata_scheme", "Scheme", FieldType::U8).optional(),
    // -- TKEY: <https://www.rfc-editor.org/rfc/rfc2930#section-2> / TSIG: <https://www.rfc-editor.org/rfc/rfc8945#section-4.2> --
    FieldDescriptor::new("rdata_algorithm_name", "Algorithm Name", FieldType::Bytes)
        .optional()
        .with_format_fn(write_dns_name),
    FieldDescriptor::new("rdata_inception", "Inception", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_expiration", "Expiration", FieldType::U32).optional(),
    FieldDescriptor::new("rdata_mode", "Mode", FieldType::U16).optional(),
    FieldDescriptor {
        name: "rdata_error",
        display_name: "Error",
        field_type: FieldType::U16,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(e) => tsig_rcode_name(*e),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("rdata_key_size", "Key Size", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_key_data", "Key Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("rdata_other_length", "Other Length", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_other_data", "Other Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("rdata_time_signed", "Time Signed", FieldType::U64).optional(),
    FieldDescriptor::new("rdata_fudge", "Fudge", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_mac_size", "MAC Size", FieldType::U16).optional(),
    FieldDescriptor::new("rdata_mac", "MAC", FieldType::Bytes).optional(),
    FieldDescriptor::new("rdata_original_id", "Original ID", FieldType::U16).optional(),
    // -- URI: RFC 7553, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc7553#section-4.5> --
    FieldDescriptor::new("rdata_uri", "Target", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
];

/// Returns the name of a DSO-TYPE.
///
/// IANA "DSO Type Codes" registry (RFC 8490, Section 10.3 —
/// <https://www.rfc-editor.org/rfc/rfc8490#section-10.3>; RFC 8765,
/// Section 8 — <https://www.rfc-editor.org/rfc/rfc8765#section-8>).
fn dso_type_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("KeepAlive"),
        2 => Some("RetryDelay"),
        3 => Some("EncryptionPadding"),
        0x40 => Some("SUBSCRIBE"),
        0x41 => Some("PUSH"),
        0x42 => Some("UNSUBSCRIBE"),
        0x43 => Some("RECONFIRM"),
        _ => None,
    }
}

/// Child field descriptors for DSO TLVs.
///
/// RFC 8490, Section 5.4.4 — <https://www.rfc-editor.org/rfc/rfc8490#section-5.4.4>
static DSO_TLV_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "type",
        display_name: "DSO-TYPE",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(t) => dso_type_name(*t),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "DSO-LENGTH", FieldType::U16),
    FieldDescriptor::new("data", "DSO-DATA", FieldType::Bytes),
];

/// Descriptor for one DSO TLV Object; its label resolves to the DSO-TYPE name.
static FD_DSO_TLV: FieldDescriptor = FieldDescriptor {
    name: "dso_tlv",
    display_name: "DSO TLV",
    field_type: FieldType::Object,
    optional: false,
    children: None,
    display_fn: Some(|v, children| match v {
        FieldValue::Object(_) => children.iter().find_map(|f| match (f.name(), &f.value) {
            ("type", FieldValue::U16(t)) => dso_type_name(*t),
            _ => None,
        }),
        _ => None,
    }),
    format_fn: None,
};

/// Parse the DSO Data (a sequence of TLVs) that follows the sections of a
/// DSO message, returning the new read position.
///
/// RFC 8490, Section 5.4.4 — <https://www.rfc-editor.org/rfc/rfc8490#section-5.4.4>.
/// The DSO-DATA is kept opaque: "The generic DSO machinery treats the
/// DSO-DATA as an opaque "blob" without attempting to interpret it."
fn parse_dso_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    mut pos: usize,
    offset: usize,
) -> Result<usize, PacketError> {
    let arr = buf.begin_container(
        &DNS_FIELD_DESCRIPTORS[FD_DSO_TLVS],
        FieldValue::Array(0..0),
        offset + pos..offset + data.len(),
    );
    while pos < data.len() {
        if pos + 4 > data.len() {
            return Err(PacketError::Truncated {
                expected: pos + 4,
                actual: data.len(),
            });
        }
        let tlv_type = read_be_u16(data, pos)?;
        let len = read_be_u16(data, pos + 2)? as usize;
        let end = pos + 4 + len;
        if end > data.len() {
            return Err(PacketError::Truncated {
                expected: end,
                actual: data.len(),
            });
        }
        let obj = buf.begin_container(
            &FD_DSO_TLV,
            FieldValue::Object(0..0),
            offset + pos..offset + end,
        );
        buf.push_field(
            &DSO_TLV_CHILD_FIELDS[0],
            FieldValue::U16(tlv_type),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &DSO_TLV_CHILD_FIELDS[1],
            FieldValue::U16(len as u16),
            offset + pos + 2..offset + pos + 4,
        );
        buf.push_field(
            &DSO_TLV_CHILD_FIELDS[2],
            FieldValue::Bytes(&data[pos + 4..end]),
            offset + pos + 4..offset + end,
        );
        buf.end_container(obj);
        pos = end;
    }
    buf.end_container(arr);
    Ok(pos)
}

/// Generates the common DNS header + section field descriptors shared by both
/// the UDP and TCP variants.  The `$tcp_length_optional` parameter controls
/// whether the leading `tcp_length` field is marked optional (UDP schema, where
/// it is included only for `bask fields` completeness) or required (TCP schema).
macro_rules! dns_field_descriptors {
    (tcp_length_optional: $opt:expr) => {
        &[
            FieldDescriptor {
                name: "tcp_length",
                display_name: "TCP Length",
                field_type: FieldType::U16,
                optional: $opt,
                children: None,
                display_fn: None,
                format_fn: None,
            },
            FieldDescriptor::new("id", "Transaction ID", FieldType::U16),
            FieldDescriptor {
                name: "qr",
                display_name: "QR",
                field_type: FieldType::U8,
                optional: false,
                children: None,
                display_fn: Some(|v, _siblings| match v {
                    FieldValue::U8(0) => Some("Query"),
                    FieldValue::U8(1) => Some("Response"),
                    _ => None,
                }),
                format_fn: None,
            },
            FieldDescriptor {
                name: "opcode",
                display_name: "Opcode",
                field_type: FieldType::U8,
                optional: false,
                children: None,
                display_fn: Some(|v, _siblings| match v {
                    FieldValue::U8(o) => dns_opcode_name(*o),
                    _ => None,
                }),
                format_fn: None,
            },
            FieldDescriptor::new("aa", "Authoritative Answer", FieldType::U8),
            FieldDescriptor::new("tc", "Truncation", FieldType::U8),
            FieldDescriptor::new("rd", "Recursion Desired", FieldType::U8),
            FieldDescriptor::new("ra", "Recursion Available", FieldType::U8),
            FieldDescriptor::new("z", "Reserved", FieldType::U8),
            FieldDescriptor::new("ad", "Authentic Data", FieldType::U8),
            FieldDescriptor::new("cd", "Checking Disabled", FieldType::U8),
            FieldDescriptor {
                name: "rcode",
                display_name: "Response Code",
                field_type: FieldType::U8,
                optional: false,
                children: None,
                display_fn: Some(|v, _siblings| match v {
                    FieldValue::U8(r) => dns_rcode_name(*r),
                    _ => None,
                }),
                format_fn: None,
            },
            FieldDescriptor::new("qdcount", "Question Count", FieldType::U16),
            FieldDescriptor::new("ancount", "Answer Count", FieldType::U16),
            FieldDescriptor::new("nscount", "Authority Count", FieldType::U16),
            FieldDescriptor::new("arcount", "Additional Count", FieldType::U16),
            FieldDescriptor::new("questions", "Questions", FieldType::Array)
                .optional()
                .with_children(QUESTION_CHILD_FIELDS),
            FieldDescriptor::new("answers", "Answer Records", FieldType::Array)
                .optional()
                .with_children(RR_CHILD_FIELDS),
            FieldDescriptor::new("authorities", "Authority Records", FieldType::Array)
                .optional()
                .with_children(RR_CHILD_FIELDS),
            FieldDescriptor::new("additionals", "Additional Records", FieldType::Array)
                .optional()
                .with_children(RR_CHILD_FIELDS),
            // RFC 8490, Section 5.4.2 — <https://www.rfc-editor.org/rfc/rfc8490#section-5.4.2>
            FieldDescriptor::new("dso_tlvs", "DSO TLVs", FieldType::Array)
                .optional()
                .with_children(DSO_TLV_CHILD_FIELDS),
        ]
    };
}

/// Field descriptors for [`DnsDissector`] (DNS over UDP).
///
/// Includes the `tcp_length` field (as optional) so that `bask fields dns`
/// shows the full superset of fields for both UDP and TCP variants.
static DNS_FIELD_DESCRIPTORS: &[FieldDescriptor] =
    dns_field_descriptors!(tcp_length_optional: true);

/// Field descriptors for [`DnsTcpDissector`] (DNS over TCP).
///
/// Includes the 2-byte TCP length prefix field followed by the standard DNS fields.
/// TCP stream reassembly is handled centrally by the registry; the TCP layer's
/// `reassembly_in_progress` and `segment_count` fields indicate reassembly status,
/// and the `stream_id` field correlates segments belonging to the same stream.
static DNS_TCP_FIELD_DESCRIPTORS: &[FieldDescriptor] =
    dns_field_descriptors!(tcp_length_optional: false);

/// Specification references for the DNS dissectors.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 1035",
        "Domain names - implementation and specification",
        "https://www.rfc-editor.org/rfc/rfc1035",
    ),
    SpecReference::new(
        "RFC 3596",
        "DNS Extensions to Support IP Version 6",
        "https://www.rfc-editor.org/rfc/rfc3596",
    ),
    SpecReference::new(
        "RFC 4035",
        "Protocol Modifications for the DNS Security Extensions",
        "https://www.rfc-editor.org/rfc/rfc4035",
    ),
    SpecReference::new(
        "RFC 6891",
        "Extension Mechanisms for DNS (EDNS(0))",
        "https://www.rfc-editor.org/rfc/rfc6891",
    ),
    SpecReference::new(
        "RFC 7766",
        "DNS Transport over TCP - Implementation Requirements",
        "https://www.rfc-editor.org/rfc/rfc7766",
    ),
    SpecReference::new(
        "RFC 7828",
        "The edns-tcp-keepalive EDNS0 Option",
        "https://www.rfc-editor.org/rfc/rfc7828",
    ),
    SpecReference::new(
        "RFC 2782",
        "A DNS RR for specifying the location of services (DNS SRV)",
        "https://www.rfc-editor.org/rfc/rfc2782",
    ),
    SpecReference::new(
        "RFC 3403",
        "Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database",
        "https://www.rfc-editor.org/rfc/rfc3403",
    ),
    SpecReference::new(
        "RFC 4255",
        "Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints",
        "https://www.rfc-editor.org/rfc/rfc4255",
    ),
    SpecReference::new(
        "RFC 6672",
        "DNAME Redirection in the DNS",
        "https://www.rfc-editor.org/rfc/rfc6672",
    ),
    SpecReference::new(
        "RFC 6698",
        "The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA",
        "https://www.rfc-editor.org/rfc/rfc6698",
    ),
    SpecReference::new(
        "RFC 8659",
        "DNS Certification Authority Authorization (CAA) Resource Record",
        "https://www.rfc-editor.org/rfc/rfc8659",
    ),
    SpecReference::new(
        "RFC 5155",
        "DNS Security (DNSSEC) Hashed Authenticated Denial of Existence",
        "https://www.rfc-editor.org/rfc/rfc5155",
    ),
    SpecReference::new(
        "RFC 7344",
        "Automating DNSSEC Delegation Trust Maintenance",
        "https://www.rfc-editor.org/rfc/rfc7344",
    ),
    SpecReference::new(
        "RFC 9460",
        "Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)",
        "https://www.rfc-editor.org/rfc/rfc9460",
    ),
    SpecReference::new(
        "RFC 9461",
        "Service Binding Mapping for DNS Servers",
        "https://www.rfc-editor.org/rfc/rfc9461",
    ),
    SpecReference::new(
        "RFC 9848",
        "Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings",
        "https://www.rfc-editor.org/rfc/rfc9848",
    ),
    SpecReference::new(
        "RFC 5001",
        "DNS Name Server Identifier (NSID) Option",
        "https://www.rfc-editor.org/rfc/rfc5001",
    ),
    SpecReference::new(
        "RFC 6975",
        "Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)",
        "https://www.rfc-editor.org/rfc/rfc6975",
    ),
    SpecReference::new(
        "RFC 7314",
        "Extension Mechanisms for DNS (EDNS) EXPIRE Option",
        "https://www.rfc-editor.org/rfc/rfc7314",
    ),
    SpecReference::new(
        "RFC 7830",
        "The EDNS(0) Padding Option",
        "https://www.rfc-editor.org/rfc/rfc7830",
    ),
    SpecReference::new(
        "RFC 7871",
        "Client Subnet in DNS Queries",
        "https://www.rfc-editor.org/rfc/rfc7871",
    ),
    SpecReference::new(
        "RFC 7873",
        "Domain Name System (DNS) Cookies",
        "https://www.rfc-editor.org/rfc/rfc7873",
    ),
    SpecReference::new(
        "RFC 8145",
        "Signaling Trust Anchor Knowledge in DNS Security Extensions (DNSSEC)",
        "https://www.rfc-editor.org/rfc/rfc8145",
    ),
    SpecReference::new(
        "RFC 8914",
        "Extended DNS Errors",
        "https://www.rfc-editor.org/rfc/rfc8914",
    ),
    SpecReference::new(
        "RFC 9567",
        "DNS Error Reporting",
        "https://www.rfc-editor.org/rfc/rfc9567",
    ),
    SpecReference::new(
        "RFC 9660",
        "The DNS Zone Version (ZONEVERSION) Option",
        "https://www.rfc-editor.org/rfc/rfc9660",
    ),
    SpecReference::new(
        "RFC 4034",
        "Resource Records for the DNS Security Extensions",
        "https://www.rfc-editor.org/rfc/rfc4034",
    ),
    SpecReference::new(
        "RFC 1876",
        "A Means for Expressing Location Information in the Domain Name System",
        "https://www.rfc-editor.org/rfc/rfc1876",
    ),
    SpecReference::new(
        "RFC 2930",
        "Secret Key Establishment for DNS (TKEY RR)",
        "https://www.rfc-editor.org/rfc/rfc2930",
    ),
    SpecReference::new(
        "RFC 4025",
        "A Method for Storing IPsec Keying Material in DNS",
        "https://www.rfc-editor.org/rfc/rfc4025",
    ),
    SpecReference::new(
        "RFC 4398",
        "Storing Certificates in the Domain Name System (DNS)",
        "https://www.rfc-editor.org/rfc/rfc4398",
    ),
    SpecReference::new(
        "RFC 4701",
        "A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)",
        "https://www.rfc-editor.org/rfc/rfc4701",
    ),
    SpecReference::new(
        "RFC 7043",
        "Resource Records for EUI-48 and EUI-64 Addresses in the DNS",
        "https://www.rfc-editor.org/rfc/rfc7043",
    ),
    SpecReference::new(
        "RFC 7477",
        "Child-to-Parent Synchronization in DNS",
        "https://www.rfc-editor.org/rfc/rfc7477",
    ),
    SpecReference::new(
        "RFC 7553",
        "The Uniform Resource Identifier (URI) DNS Resource Record",
        "https://www.rfc-editor.org/rfc/rfc7553",
    ),
    SpecReference::new(
        "RFC 7929",
        "DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP",
        "https://www.rfc-editor.org/rfc/rfc7929",
    ),
    SpecReference::new(
        "RFC 8482",
        "Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY",
        "https://www.rfc-editor.org/rfc/rfc8482",
    ),
    SpecReference::new(
        "RFC 8945",
        "Secret Key Transaction Authentication for DNS (TSIG)",
        "https://www.rfc-editor.org/rfc/rfc8945",
    ),
    SpecReference::new(
        "RFC 8976",
        "Message Digest for DNS Zones",
        "https://www.rfc-editor.org/rfc/rfc8976",
    ),
    SpecReference::new(
        "RFC 8490",
        "DNS Stateful Operations",
        "https://www.rfc-editor.org/rfc/rfc8490",
    ),
    SpecReference::new(
        "RFC 2136",
        "Dynamic Updates in the Domain Name System (DNS UPDATE)",
        "https://www.rfc-editor.org/rfc/rfc2136",
    ),
];

impl Dissector for DnsDissector {
    fn name(&self) -> &'static str {
        "Domain Name System"
    }

    fn short_name(&self) -> &'static str {
        "DNS"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        DNS_FIELD_DESCRIPTORS
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
        // DNS (RFC 1035) — standard parsing without mDNS bit reinterpretation.
        dissect_dns_core(data, buf, offset, self.short_name(), false, false)
    }
}

/// Parse a Multicast DNS (RFC 6762) message.
///
/// This is the same DNS message parser used by [`DnsDissector`] but with
/// RFC 6762 reinterpretation applied to the class fields:
///
/// - Each question gets a `qu` child field carrying the top bit of qclass
///   (the unicast-response bit, RFC 6762, Section 18.12 — <https://www.rfc-editor.org/rfc/rfc6762#section-18.12>);
///   the `class` field carries only the lower 15 bits.
/// - Each non-OPT resource record gets a `cache_flush` child field carrying
///   the top bit of rrclass (RFC 6762, Section 18.13 / 10.2 —
///   <https://www.rfc-editor.org/rfc/rfc6762#section-10.2>); the `class`
///   field carries only the lower 15 bits.
/// - OPT pseudo-RRs (RFC 6891) are left untouched: their rrclass field is
///   the full 16-bit EDNS0 UDP payload size, as required by RFC 6762,
///   Section 10.2.
///
/// The produced layer is labelled `"mDNS"`. All other fields are identical
/// to the DNS parsing output.
pub fn dissect_as_mdns<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<DissectResult, PacketError> {
    dissect_dns_core(data, buf, offset, "mDNS", true, false)
}

/// Shared DNS / mDNS message parser.
///
/// `layer_name` is the short name pushed onto the layer (e.g., `"DNS"` or
/// `"mDNS"`). When `mdns_mode` is true, the top bit of each question's
/// qclass is emitted as a separate `qu` field, and the top bit of each
/// non-OPT record's rrclass is emitted as a separate `cache_flush` field,
/// per RFC 6762, Sections 18.12, 18.13 and 10.2.
///
/// `stream_transport` is true for DNS over TCP. Only then is the DSO Data of
/// an opcode 6 message parsed: RFC 8490, Section 4.2 —
/// <https://www.rfc-editor.org/rfc/rfc8490#section-4.2> — "Only DNS-over-TCP
/// and DNS-over-TLS are currently defined for use with DNS Stateful
/// Operations."
fn dissect_dns_core<'pkt>(
    data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
    layer_name: &'static str,
    mdns_mode: bool,
    stream_transport: bool,
) -> Result<DissectResult, PacketError> {
    if data.len() < HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }

    // RFC 1035, Section 4.1.1 — Header
    let id = read_be_u16(data, 0)?;
    let flags = read_be_u16(data, 2)?;

    let qr = ((flags >> 15) & 1) as u8;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let aa = ((flags >> 10) & 1) as u8;
    let tc = ((flags >> 9) & 1) as u8;
    let rd = ((flags >> 8) & 1) as u8;
    let ra = ((flags >> 7) & 1) as u8;
    // RFC 1035, Section 4.1.1 — Z reserved bit (must be zero)
    let z = ((flags >> 6) & 1) as u8;
    // RFC 4035 — AD and CD flags (formerly Z bits)
    let ad = ((flags >> 5) & 1) as u8;
    let cd = ((flags >> 4) & 1) as u8;
    let rcode = (flags & 0x0F) as u8;

    let qdcount = read_be_u16(data, 4)?;
    let ancount = read_be_u16(data, 6)?;
    let nscount = read_be_u16(data, 8)?;
    let arcount = read_be_u16(data, 10)?;

    buf.begin_layer(
        layer_name,
        None,
        DNS_FIELD_DESCRIPTORS,
        offset..offset + data.len(),
    );

    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_ID],
        FieldValue::U16(id),
        offset..offset + 2,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_QR],
        FieldValue::U8(qr),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_OPCODE],
        FieldValue::U8(opcode),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_AA],
        FieldValue::U8(aa),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_TC],
        FieldValue::U8(tc),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_RD],
        FieldValue::U8(rd),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_RA],
        FieldValue::U8(ra),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_Z],
        FieldValue::U8(z),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_AD],
        FieldValue::U8(ad),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_CD],
        FieldValue::U8(cd),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_RCODE],
        FieldValue::U8(rcode),
        offset + 2..offset + 4,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_QDCOUNT],
        FieldValue::U16(qdcount),
        offset + 4..offset + 6,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_ANCOUNT],
        FieldValue::U16(ancount),
        offset + 6..offset + 8,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_NSCOUNT],
        FieldValue::U16(nscount),
        offset + 8..offset + 10,
    );
    buf.push_field(
        &DNS_FIELD_DESCRIPTORS[FD_ARCOUNT],
        FieldValue::U16(arcount),
        offset + 10..offset + 12,
    );

    let mut pos = HEADER_SIZE;

    // RFC 1035, Section 4.1.2 — Question Section
    let questions_start = pos;
    let questions_count = qdcount as usize;
    let questions_array_idx = if questions_count > 0 {
        Some(buf.begin_container(
            &DNS_FIELD_DESCRIPTORS[FD_QUESTIONS],
            FieldValue::Array(0..0),
            offset + questions_start..offset + questions_start,
        ))
    } else {
        None
    };
    for _i in 0..questions_count {
        let name_len = parse_name(data, pos)?;
        let name_start = pos;
        pos += name_len;

        if pos + 4 > data.len() {
            return Err(PacketError::Truncated {
                expected: pos + 4,
                actual: data.len(),
            });
        }

        let qtype = read_be_u16(data, pos)?;
        let qclass_raw = read_be_u16(data, pos + 2)?;
        // RFC 6762, Section 18.12 / 5.4 — in mDNS the top bit of qclass is the
        // unicast-response ("QU") bit, not part of the class value.
        // <https://www.rfc-editor.org/rfc/rfc6762#section-18.12>
        let (qclass, qu_bit) = if mdns_mode {
            (qclass_raw & 0x7FFF, ((qclass_raw >> 15) & 1) as u8)
        } else {
            (qclass_raw, 0)
        };

        let obj_idx = buf.begin_container(
            &QUESTION_CHILD_FIELDS[QFD_NAME],
            FieldValue::Object(0..0),
            offset + name_start..offset + pos + 4,
        );
        buf.push_field(
            &QUESTION_CHILD_FIELDS[QFD_NAME],
            FieldValue::Bytes(&data[name_start..pos]),
            offset + name_start..offset + pos,
        );
        buf.push_field(
            &QUESTION_CHILD_FIELDS[QFD_TYPE],
            FieldValue::U16(qtype),
            offset + pos..offset + pos + 2,
        );
        buf.push_field(
            &QUESTION_CHILD_FIELDS[QFD_CLASS],
            FieldValue::U16(qclass),
            offset + pos + 2..offset + pos + 4,
        );
        if mdns_mode {
            buf.push_field(
                &QUESTION_CHILD_FIELDS[QFD_QU],
                FieldValue::U8(qu_bit),
                offset + pos + 2..offset + pos + 4,
            );
        }
        buf.end_container(obj_idx);
        pos += 4;
    }
    if let Some(idx) = questions_array_idx {
        // Update the range on the array container
        if let Some(field) = buf.field_mut(idx as usize) {
            field.range = offset + questions_start..offset + pos;
        }
        buf.end_container(idx);
    }

    // RFC 1035, Section 4.1.3 — Resource Records (Answer, Authority, Additional)
    let sections: &[(usize, u16)] = &[
        (FD_ANSWERS, ancount),
        (FD_AUTHORITIES, nscount),
        (FD_ADDITIONALS, arcount),
    ];

    for &(section_fd, count) in sections {
        let section_start = pos;
        let count = count as usize;
        let array_idx = if count > 0 {
            Some(buf.begin_container(
                &DNS_FIELD_DESCRIPTORS[section_fd],
                FieldValue::Array(0..0),
                offset + section_start..offset + section_start,
            ))
        } else {
            None
        };
        for _i in 0..count {
            let name_len = parse_name(data, pos)?;
            let name_start = pos;
            pos += name_len;

            // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
            if pos + 10 > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + 10,
                    actual: data.len(),
                });
            }

            let rtype = read_be_u16(data, pos)?;
            let rclass_raw = read_be_u16(data, pos + 2)?;
            let ttl = read_be_u32(data, pos + 4)?;
            let rdlength = read_be_u16(data, pos + 8)? as usize;

            if pos + 10 + rdlength > data.len() {
                return Err(PacketError::Truncated {
                    expected: pos + 10 + rdlength,
                    actual: data.len(),
                });
            }

            let rdata = &data[pos + 10..pos + 10 + rdlength];
            let record_end = pos + 10 + rdlength;

            let obj_idx = buf.begin_container(
                &RR_CHILD_FIELDS[RRFD_NAME],
                FieldValue::Object(0..0),
                offset + name_start..offset + record_end,
            );

            // RFC 6891 — OPT pseudo-record has different field semantics.
            // RFC 6762, Section 10.2 also specifies that the cache-flush bit
            // reuse does NOT apply to pseudo-RRs like OPT — the rrclass field
            // remains the full 16-bit UDP payload size.
            // <https://www.rfc-editor.org/rfc/rfc6762#section-10.2>
            if rtype == TYPE_OPT {
                let extended_rcode = ((ttl >> 24) & 0xFF) as u8;
                let edns_version = ((ttl >> 16) & 0xFF) as u8;
                let do_bit = ((ttl >> 15) & 1) as u8;
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_NAME],
                    FieldValue::Bytes(&data[name_start..pos]),
                    offset + name_start..offset + pos,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_TYPE],
                    FieldValue::U16(rtype),
                    offset + pos..offset + pos + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_UDP_PAYLOAD_SIZE],
                    FieldValue::U16(rclass_raw),
                    offset + pos + 2..offset + pos + 4,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_EXTENDED_RCODE],
                    FieldValue::U8(extended_rcode),
                    offset + pos + 4..offset + pos + 8,
                );
                // RFC 6891, Section 6.1.3 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3>:
                // "EXTENDED-RCODE
                //     Forms the upper 8 bits of extended 12-bit RCODE (together
                //     with the 4 bits defined in [RFC1035]."
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RCODE],
                    FieldValue::U16(((extended_rcode as u16) << 4) | rcode as u16),
                    offset + pos + 4..offset + pos + 8,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_EDNS_VERSION],
                    FieldValue::U8(edns_version),
                    offset + pos + 4..offset + pos + 8,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_DO_BIT],
                    FieldValue::U8(do_bit),
                    offset + pos + 4..offset + pos + 8,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDLENGTH],
                    FieldValue::U16(rdlength as u16),
                    offset + pos + 8..offset + pos + 10,
                );
                let edns_arr_idx = buf.begin_container(
                    &RR_CHILD_FIELDS[RRFD_EDNS_OPTIONS],
                    FieldValue::Array(0..0),
                    offset + pos + 10..offset + pos + 10 + rdlength,
                );
                parse_edns_options(buf, rdata, offset + pos + 10);
                buf.end_container(edns_arr_idx);
            } else {
                // RFC 6762, Section 18.13 / 10.2 — in mDNS the top bit of
                // rrclass is the cache-flush bit on non-OPT records.
                // <https://www.rfc-editor.org/rfc/rfc6762#section-18.13>
                let (rclass, cache_flush_bit) = if mdns_mode {
                    (rclass_raw & 0x7FFF, ((rclass_raw >> 15) & 1) as u8)
                } else {
                    (rclass_raw, 0)
                };
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_NAME],
                    FieldValue::Bytes(&data[name_start..pos]),
                    offset + name_start..offset + pos,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_TYPE],
                    FieldValue::U16(rtype),
                    offset + pos..offset + pos + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_CLASS],
                    FieldValue::U16(rclass),
                    offset + pos + 2..offset + pos + 4,
                );
                if mdns_mode {
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_CACHE_FLUSH],
                        FieldValue::U8(cache_flush_bit),
                        offset + pos + 2..offset + pos + 4,
                    );
                }
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_TTL],
                    FieldValue::U32(ttl),
                    offset + pos + 4..offset + pos + 8,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDLENGTH],
                    FieldValue::U16(rdlength as u16),
                    offset + pos + 8..offset + pos + 10,
                );
                // RFC 1035, Section 3.2 — Parse RDATA based on record type
                parse_rdata(buf, data, pos + 10, rdata, rtype, offset + pos + 10);
            }

            buf.end_container(obj_idx);
            pos += 10 + rdlength;
        }
        if let Some(idx) = array_idx {
            if let Some(field) = buf.field_mut(idx as usize) {
                field.range = offset + section_start..offset + pos;
            }
            buf.end_container(idx);
        }
    }

    // RFC 8490, Section 5.4.2 — <https://www.rfc-editor.org/rfc/rfc8490#section-5.4.2>:
    // in a DSO message, the DSO Data (TLVs) follows the (empty) sections.
    if stream_transport && opcode == OPCODE_DSO && pos < data.len() {
        pos = parse_dso_tlvs(buf, data, pos, offset)?;
    }

    // Update layer range to actual consumed bytes
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..offset + pos;
    }
    buf.end_layer();

    Ok(DissectResult::new(pos, DispatchHint::End))
}

/// Dissect a complete DNS-over-TCP message (length prefix + DNS payload).
///
/// `msg_data` must start with the 2-byte length prefix followed by the DNS message.
/// `offset` sets the base for all produced field and layer ranges. Pass the real
/// packet byte offset for single-segment (stateless) parsing, or `0` for
/// reassembled messages so that ranges are expressed in the reassembly buffer's
/// coordinate space rather than in original-packet byte positions.
fn dissect_dns_tcp_message<'pkt>(
    msg_data: &'pkt [u8],
    buf: &mut DissectBuffer<'pkt>,
    offset: usize,
) -> Result<DissectResult, PacketError> {
    let msg_len = read_be_u16(msg_data, 0)? as usize;

    // Push tcp_length field BEFORE calling the inner DNS dissector,
    // so it appears as the first field in the DNS layer.
    // We record the field index so we can include it in the layer's field_range.
    let tcp_len_field_idx = buf.field_count();
    buf.push_field(
        &DNS_TCP_FIELD_DESCRIPTORS[0], // tcp_length is the first descriptor
        FieldValue::U16(msg_len as u16),
        offset..offset + 2,
    );

    // RFC 1035, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2>:
    // the length prefix delimits the message, so a message that needs more
    // octets than it declares is malformed, not a truncated capture.
    let result = dissect_dns_core(
        &msg_data[2..2 + msg_len],
        buf,
        offset + 2,
        "DNS",
        false,
        true,
    )
    .map_err(|e| match e {
        PacketError::Truncated { .. } => {
            PacketError::InvalidHeader("DNS message overruns TCP length prefix")
        }
        other => other,
    })?;

    // Extend the DNS layer range to include the 2-byte TCP length prefix
    // and the tcp_length field we pushed before the DNS dissect call.
    if let Some(layer) = buf.last_layer_mut() {
        layer.range = offset..layer.range.end;
        layer.field_range.start = tcp_len_field_idx;
        layer.field_descriptors = DNS_TCP_FIELD_DESCRIPTORS;
    }

    Ok(DissectResult::new(
        2 + result.bytes_consumed,
        DispatchHint::End,
    ))
}

/// Stateless DNS over TCP dissector.
///
/// Handles the 2-byte length prefix used for DNS messages over TCP
/// (RFC 1035, Section 4.2.2 — <https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2>,
/// updated by RFC 7766 — <https://www.rfc-editor.org/rfc/rfc7766>).
/// TCP stream reassembly is handled centrally by the registry;
/// this dissector only parses complete DNS messages.
pub struct DnsTcpDissector;

impl Dissector for DnsTcpDissector {
    fn name(&self) -> &'static str {
        "DNS over TCP"
    }

    fn short_name(&self) -> &'static str {
        "DNS"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        DNS_TCP_FIELD_DESCRIPTORS
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
        // RFC 1035, Section 4.2.2 (updated by RFC 7766) — TCP messages are
        // prefixed with a 2-byte length.
        // <https://www.rfc-editor.org/rfc/rfc7766#section-8>
        if data.len() < 2 {
            return Err(PacketError::Truncated {
                expected: 2,
                actual: data.len(),
            });
        }

        let msg_len = read_be_u16(data, 0)? as usize;
        let total_len = 2 + msg_len;

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        dissect_dns_tcp_message(&data[..total_len], buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    // # RFC Coverage (DNS dissector)
    //
    // | RFC / Section          | Description                         | Test                              |
    // |------------------------|-------------------------------------|-----------------------------------|
    // | RFC 1035 §4.1.1        | Header layout & flag extraction     | parse_header_flags                |
    // | RFC 1035 §4.1.1        | Truncated DNS header (<12 bytes)    | parse_header_truncated            |
    // | RFC 1035 §4.1.2        | Question section (A/IN)             | parse_question_a_in               |
    // | RFC 1035 §4.1.3/§3.4.1 | A record RDATA                      | parse_a_record                    |
    // | RFC 1035 §3.3.1/§3.3.11/§3.3.12 | CNAME / NS / PTR           | parse_cname_ns_ptr_record         |
    // | RFC 1035 §3.3.9        | MX record                           | parse_mx_record                   |
    // | RFC 1035 §3.3.13       | SOA record                          | parse_soa_record                  |
    // | RFC 1035 §3.3.14       | TXT record                          | parse_txt_record                  |
    // | RFC 1035 §2.3.4/§3.1   | Name length > 255 octets rejected   | reject_name_over_255_octets       |
    // | RFC 1035 §4.1.4        | Name compression pointer loop       | reject_name_pointer_loop          |
    // | RFC 1035 §3.1          | Reserved label type (10)            | reject_reserved_label_type        |
    // | RFC 1035 §4.2.2 / 7766 | TCP 2-byte length prefix            | parse_tcp_length_prefix           |
    // | RFC 1035 §4.2.2 / 7766 | Message overruns TCP length prefix  | tcp_message_overrunning_length_prefix_is_invalid |
    // | RFC 3596               | AAAA record                         | parse_aaaa_record                 |
    // | RFC 2782               | SRV record                          | parse_srv_record                  |
    // | RFC 3403               | NAPTR record                        | parse_naptr_record                |
    // | RFC 3403               | NAPTR parsing is zero-allocation    | naptr_dissect_zero_alloc          |
    // | RFC 4035 §3.1.6        | AD / CD flag bit positions          | parse_header_flags                |
    // | RFC 4034 §2.1          | DNSKEY record                       | parse_dnskey_record               |
    // | RFC 4034 §3.1          | RRSIG record                        | parse_rrsig_record                |
    // | RFC 4034 §4.1          | NSEC record                         | parse_nsec_record                 |
    // | RFC 4034 §4.1.1 / RFC 3597 §4 | Compressed NSEC name (sender MUST NOT; accepted liberally) | nsec_next_name_compression_pointer_is_accepted |
    // | RFC 1035 §3.2.1        | NSEC next name past RDLENGTH        | nsec_next_name_overrunning_rdata_falls_back |
    // | RFC 1035 §3.2.1        | RRSIG signer name past RDLENGTH     | rrsig_signer_name_overrunning_rdata_falls_back |
    // | RFC 1035 §3.2.1        | SOA RNAME past RDLENGTH             | soa_rname_overrunning_rdata_falls_back |
    // | RFC 1035 §3.2.1        | Any RDATA name past RDLENGTH        | names_overrunning_rdata_fall_back_for_every_name_type |
    // | RFC 1035 §3.3.9/§3.3.13, RFC 2782, RFC 3403 §4.1 | Octets after final RDATA field | trailing_octets_after_final_rdata_field_fall_back |
    // | RFC 4034 §5.1          | DS record                           | parse_ds_record                   |
    // | RFC 4255               | SSHFP record                        | parse_sshfp_record                |
    // | RFC 5155 §3.2          | NSEC3 record                        | parse_nsec3_record                |
    // | RFC 5155 §4.2          | NSEC3PARAM record                   | parse_nsec3param_record           |
    // | RFC 6672               | DNAME record                        | parse_cname_ns_ptr_record         |
    // | RFC 6698               | TLSA record                         | parse_tlsa_record                 |
    // | RFC 6891 §6.1.2/§6.1.3 | OPT pseudo-RR (UDP size, DO bit)    | parse_opt_record_edns0            |
    // | RFC 7344               | CDS / CDNSKEY records               | parse_cds_record                  |
    // | RFC 7828 §3            | EDNS0 TCP Keepalive option          | parse_edns_tcp_keepalive          |
    // | RFC 8659 §4.1          | CAA record RDATA layout             | parse_caa_record                  |
    // | RFC 9460 §2.2          | SVCB / HTTPS record                 | parse_svcb_record                 |
    // | RFC 9460 §2.2/§7/§8, App. D.2 | SvcParams: mandatory, alpn, ipv4hint | svcb_params_rfc9460_figure9_mandatory_alpn_ipv4hint |
    // | RFC 9460 §7.2/§7.3, App. D.2 | SvcParams: port, ipv6hint   | svcb_params_rfc9460_figure4_port_and_figure7_ipv6hint |
    // | RFC 9460 §7.1          | HTTPS alpn=h2 (issue reproduction)  | svcb_params_issue_repro_https_alpn_h2 |
    // | RFC 9848 §3 / RFC 9461 §5 / RFC 9460 §7.1 | ech, dohpath, no-default-alpn, unknown key | svcb_params_ech_dohpath_no_default_alpn_and_unknown_key |
    // | RFC 9460 §7            | Malformed SvcParamValues kept raw   | svcb_params_malformed_values_fall_back_to_raw_value |
    // | RFC 9460 §2.2          | RDATA ends inside a SvcParam        | svcb_params_truncated_list_keeps_only_raw_params |
    // | RFC 6891 §6.1.3        | Combined 12-bit RCODE (BADVERS)     | opt_combined_rcode_badvers        |
    // | IANA DNS Parameters    | RCODE / opcode / TYPE / option names | rcode_opcode_and_type_names_follow_iana |
    // | RFC 5001 §2.3          | EDNS NSID                           | edns_nsid_exposes_text_when_printable |
    // | RFC 6975 §3            | EDNS DAU / DHU / N3U                | edns_dau_dhu_n3u_algorithm_lists  |
    // | RFC 7871 §6            | EDNS Client Subnet                  | edns_client_subnet_ipv4_and_ipv6  |
    // | RFC 7873 §4            | EDNS COOKIE                         | edns_cookie_client_and_server     |
    // | RFC 7830 §3 / RFC 7314 §3 / RFC 8145 §4.1 | Padding, EXPIRE, edns-key-tag | edns_padding_expire_key_tag |
    // | RFC 8914 §2            | Extended DNS Error                  | edns_extended_dns_error           |
    // | RFC 9567 §5            | Report-Channel agent domain         | edns_report_channel_agent_domain  |
    // | RFC 9660 §2.1          | ZONEVERSION                         | edns_zoneversion                  |
    // | RFC 4034 §4.1.2/§4.3   | NSEC type bit map                   | nsec_type_bitmap_rfc4034_example  |
    // | RFC 5155 §3.2.1        | NSEC3 type bit map                  | nsec3_type_bitmap_a_ns_soa_rrsig_nsec_dnskey |
    // | RFC 4034 §4.1.2        | Malformed type bit maps             | malformed_type_bitmaps_have_no_type_list |
    // | RFC 8945 §4.2          | TSIG record (uncompressed name)     | parse_tsig_record                 |
    // | RFC 2930 §2            | TKEY record                         | parse_tkey_record                 |
    // | RFC 8976 §2.2 / RFC 7477 §2.1.1 / RFC 7553 §4.5 | ZONEMD, CSYNC, URI | parse_zonemd_csync_uri_records |
    // | RFC 1035 §3.3.2 / RFC 1876 §2 | HINFO, LOC                   | parse_hinfo_loc_records           |
    // | RFC 4025 §2.1-§2.5     | IPSECKEY gateway types              | parse_ipseckey_record_gateway_types |
    // | RFC 4398 §2 / RFC 4701 §3.1 / RFC 7929 §2.1 / RFC 7043 §3.1, §4.1 | CERT, DHCID, OPENPGPKEY, EUI48/64 | parse_cert_dhcid_openpgpkey_eui_records |
    // | RFC 8490 §4.2/§5.4.2/§5.4.4 | DSO message TLVs (TCP only)    | dso_message_tlvs                  |
    // | —                      | Opcode / RCODE / TYPE / CLASS names | type_class_opcode_rcode_names     |
    // | —                      | Dispatch hint is End                | dispatch_hint_is_end              |
    // | —                      | `write_dns_name` formats output     | write_dns_name_formats_output     |

    /// Shared `DissectBuffer` for tests that only need a fresh buffer.
    fn buf() -> DissectBuffer<'static> {
        DissectBuffer::new()
    }

    /// Look up a child field by name within the nested range of `parent`.
    fn find_child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        parent: &Field<'pkt>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        let range = match &parent.value {
            FieldValue::Object(r) | FieldValue::Array(r) => r.clone(),
            _ => return None,
        };
        buf.nested_fields(&range).iter().find(|f| f.name() == name)
    }

    /// Return the first Object placeholder within an Array field.
    ///
    /// Flat-storage note: `nested_fields(array_range)` returns all fields
    /// between the Array's `begin_container` and `end_container`, i.e. both
    /// the per-entry Object placeholders AND their flattened children.
    /// Tests that only look at a single RR use this helper to locate that
    /// first Object directly.
    fn first_array_entry<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        array: &Field<'pkt>,
    ) -> &'a Field<'pkt> {
        let range = match &array.value {
            FieldValue::Array(r) => r.clone(),
            _ => panic!("expected Array field"),
        };
        buf.nested_fields(&range)
            .iter()
            .find(|f| matches!(f.value, FieldValue::Object(_)))
            .expect("array must have at least one Object entry")
    }

    /// Encode a domain name in wire format (no compression).
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if !name.is_empty() {
            for label in name.split('.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
        }
        out.push(0); // root terminator
        out
    }

    /// Assemble a DNS header (ID=0, flags=0x0000, counts = provided).
    fn header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&0u16.to_be_bytes()); // ID
        h.extend_from_slice(&0u16.to_be_bytes()); // Flags
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&an.to_be_bytes());
        h.extend_from_slice(&ns.to_be_bytes());
        h.extend_from_slice(&ar.to_be_bytes());
        h
    }

    // ---- RFC 1035 §4.1.1 — header & flag extraction ----------------------

    #[test]
    fn parse_header_flags() {
        // All flags set (including AD/CD from RFC 4035) with opcode=UPDATE(5),
        // rcode=REFUSED(5).
        // bits: QR=1 Opcode=5 AA=1 TC=1 RD=1 RA=1 Z=1 AD=1 CD=1 RCODE=5
        // 1 0101 1 1 1 1 1 1 1 0101 = 0xAFF5
        let flags: u16 = (1 << 15) // QR
            | (5 << 11) // Opcode=UPDATE
            | (1 << 10) // AA
            | (1 << 9)  // TC
            | (1 << 8)  // RD
            | (1 << 7)  // RA
            | (1 << 6)  // Z
            | (1 << 5)  // AD
            | (1 << 4)  // CD
            | 5; // RCODE=REFUSED

        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_be_bytes());
        data.extend_from_slice(&flags.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // zeros for counts

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();

        let layer = &b.layers()[0];
        let get = |name: &str| b.field_by_name(layer, name).unwrap().value.clone();

        assert_eq!(get("id"), FieldValue::U16(0xABCD));
        assert_eq!(get("qr"), FieldValue::U8(1));
        assert_eq!(get("opcode"), FieldValue::U8(5));
        assert_eq!(get("aa"), FieldValue::U8(1));
        assert_eq!(get("tc"), FieldValue::U8(1));
        assert_eq!(get("rd"), FieldValue::U8(1));
        assert_eq!(get("ra"), FieldValue::U8(1));
        assert_eq!(get("z"), FieldValue::U8(1));
        assert_eq!(get("ad"), FieldValue::U8(1));
        assert_eq!(get("cd"), FieldValue::U8(1));
        assert_eq!(get("rcode"), FieldValue::U8(5));
    }

    #[test]
    fn parse_header_truncated() {
        // RFC 1035 §4.1.1 — minimum header is 12 bytes.
        let mut b = buf();
        let err = DnsDissector.dissect(&[0u8; 11], &mut b, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 11,
            }
        ));
    }

    // ---- RFC 1035 §4.1.2 — question & §3.4.1 A RDATA ---------------------

    #[test]
    fn parse_question_a_in() {
        let mut data = header(1, 0, 0, 0);
        data.extend_from_slice(&wire_name("example.com"));
        data.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        data.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

        let mut b = buf();
        let res = DnsDissector.dissect(&data, &mut b, 0).unwrap();
        assert_eq!(res.bytes_consumed, data.len());

        let layer = &b.layers()[0];
        let questions = b.field_by_name(layer, "questions").unwrap();
        let FieldValue::Array(ref q_range) = questions.value else {
            panic!("questions should be an Array");
        };
        let q_list = b.nested_fields(q_range);

        let q = &q_list[0];
        assert_eq!(find_child(&b, q, "type").unwrap().value, FieldValue::U16(1));
        assert_eq!(
            find_child(&b, q, "class").unwrap().value,
            FieldValue::U16(1)
        );
    }

    #[test]
    fn parse_a_record() {
        // 1 answer RR: example.com. IN A 192.0.2.1
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("example.com"));
        data.extend_from_slice(&1u16.to_be_bytes()); // TYPE=A
        data.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
        data.extend_from_slice(&3600u32.to_be_bytes()); // TTL
        data.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        data.extend_from_slice(&[192, 0, 2, 1]);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        let rdata = find_child(&b, rr, "rdata").unwrap();
        assert_eq!(rdata.value, FieldValue::Ipv4Addr([192, 0, 2, 1]));
    }

    // ---- RFC 3596 — AAAA -------------------------------------------------

    #[test]
    fn parse_aaaa_record() {
        let addr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("example.com"));
        data.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes()); // IN
        data.extend_from_slice(&3600u32.to_be_bytes());
        data.extend_from_slice(&16u16.to_be_bytes());
        data.extend_from_slice(&addr);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        let rdata = find_child(&b, rr, "rdata").unwrap();
        assert_eq!(rdata.value, FieldValue::Ipv6Addr(addr));
    }

    // ---- RFC 1035 §3.3.{1,9,11,12,13,14} / RFC 6672 ----------------------

    #[test]
    fn parse_cname_ns_ptr_record() {
        // A single CNAME record: owner "a.test" → target "b.test"
        for rtype in [TYPE_CNAME, TYPE_NS, TYPE_PTR, TYPE_DNAME] {
            let mut data = header(0, 1, 0, 0);
            data.extend_from_slice(&wire_name("a.test"));
            data.extend_from_slice(&rtype.to_be_bytes());
            data.extend_from_slice(&1u16.to_be_bytes()); // IN
            data.extend_from_slice(&0u32.to_be_bytes());
            let target = wire_name("b.test");
            data.extend_from_slice(&(target.len() as u16).to_be_bytes());
            data.extend_from_slice(&target);

            let mut b = buf();
            DnsDissector.dissect(&data, &mut b, 0).unwrap();
            let layer = &b.layers()[0];
            let answers = b.field_by_name(layer, "answers").unwrap();
            let rr = first_array_entry(&b, answers);
            let rdata = find_child(&b, rr, "rdata").unwrap();
            // RDATA is stored as raw bytes pointing into the wire format name.
            assert_eq!(rdata.value, FieldValue::Bytes(&target));
        }
    }

    #[test]
    fn parse_mx_record() {
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_MX.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let exch = wire_name("mail.ex.test");
        let rdlen = (2 + exch.len()) as u16;
        data.extend_from_slice(&rdlen.to_be_bytes());
        data.extend_from_slice(&10u16.to_be_bytes()); // preference
        data.extend_from_slice(&exch);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_preference").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_exchange").unwrap().value,
            FieldValue::Bytes(&exch)
        );
    }

    #[test]
    fn parse_soa_record() {
        let mname = wire_name("ns1.ex.test");
        let rname = wire_name("hostmaster.ex.test");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&mname);
        rdata.extend_from_slice(&rname);
        rdata.extend_from_slice(&20_240_101u32.to_be_bytes()); // SERIAL
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // REFRESH
        rdata.extend_from_slice(&1800u32.to_be_bytes()); // RETRY
        rdata.extend_from_slice(&604_800u32.to_be_bytes()); // EXPIRE
        rdata.extend_from_slice(&300u32.to_be_bytes()); // MINIMUM

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_SOA.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);

        assert_eq!(
            find_child(&b, rr, "rdata_serial").unwrap().value,
            FieldValue::U32(20_240_101)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_refresh").unwrap().value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_retry").unwrap().value,
            FieldValue::U32(1800)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_expire").unwrap().value,
            FieldValue::U32(604_800)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_minimum").unwrap().value,
            FieldValue::U32(300)
        );
    }

    #[test]
    fn parse_txt_record() {
        let rdata: &[u8] = &[3, b'a', b'b', b'c', 2, b'd', b'e'];
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_TXT.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata").unwrap().value,
            FieldValue::Bytes(rdata)
        );
    }

    // ---- RFC 2782 — SRV --------------------------------------------------

    #[test]
    fn parse_srv_record() {
        let target = wire_name("sip.ex.test");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&20u16.to_be_bytes()); // weight
        rdata.extend_from_slice(&5060u16.to_be_bytes()); // port
        rdata.extend_from_slice(&target);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("_sip._udp.ex.test"));
        data.extend_from_slice(&TYPE_SRV.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_priority").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_weight").unwrap().value,
            FieldValue::U16(20)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_port").unwrap().value,
            FieldValue::U16(5060)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_target").unwrap().value,
            FieldValue::Bytes(&target)
        );
    }

    // ---- RFC 3403 — NAPTR ------------------------------------------------

    fn build_naptr_packet() -> Vec<u8> {
        let replacement = wire_name("ex.test");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&100u16.to_be_bytes()); // order
        rdata.extend_from_slice(&10u16.to_be_bytes()); // preference
        // flags char-string "s"
        rdata.extend_from_slice(&[1, b's']);
        // services "SIP+D2U"
        let svc = b"SIP+D2U";
        rdata.push(svc.len() as u8);
        rdata.extend_from_slice(svc);
        // regexp (empty)
        rdata.push(0);
        // replacement name
        rdata.extend_from_slice(&replacement);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_NAPTR.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);
        data
    }

    #[test]
    fn parse_naptr_record() {
        let data = build_naptr_packet();
        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_order").unwrap().value,
            FieldValue::U16(100)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_preference").unwrap().value,
            FieldValue::U16(10)
        );
        // flags and services character-strings include the leading length byte
        // in the stored bytes (they are emitted as raw RDATA slices).
        let flags = find_child(&b, rr, "rdata_flags").unwrap();
        assert_eq!(flags.value, FieldValue::Bytes(&[1, b's']));
        let services = find_child(&b, rr, "rdata_services").unwrap();
        let mut expected_svc = vec![7u8];
        expected_svc.extend_from_slice(b"SIP+D2U");
        assert_eq!(services.value, FieldValue::Bytes(&expected_svc));
    }

    // ---- RFC 6891 — EDNS0 OPT --------------------------------------------

    #[test]
    fn parse_opt_record_edns0() {
        // OPT pseudo-RR with UDP payload size 4096, DO=1, extended_rcode=0,
        // version=0, and a COOKIE option.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes()); // OPTION-CODE = COOKIE
        rdata.extend_from_slice(&8u16.to_be_bytes()); // OPTION-LENGTH = 8
        rdata.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);

        let mut data = header(0, 0, 0, 1);
        // OPT NAME MUST be root.
        data.push(0);
        data.extend_from_slice(&TYPE_OPT.to_be_bytes());
        data.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
        // TTL: extended-rcode(0) | version(0) | DO=1 | Z=0
        // DO bit = high bit of byte 2 → 0x8000_0000 in 16-bit lower half.
        data.extend_from_slice(&0x0000_8000u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let additionals = b.field_by_name(layer, "additionals").unwrap();
        let rr = first_array_entry(&b, additionals);
        assert_eq!(
            find_child(&b, rr, "udp_payload_size").unwrap().value,
            FieldValue::U16(4096)
        );
        assert_eq!(
            find_child(&b, rr, "extended_rcode").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            find_child(&b, rr, "edns_version").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            find_child(&b, rr, "do_bit").unwrap().value,
            FieldValue::U8(1)
        );

        let opts = find_child(&b, rr, "edns_options").unwrap();
        let FieldValue::Array(ref opt_range) = opts.value else {
            unreachable!()
        };
        let opt_list = b.nested_fields(opt_range);
        assert_eq!(
            find_child(&b, &opt_list[0], "code").unwrap().value,
            FieldValue::U16(10) // COOKIE
        );
        assert_eq!(
            find_child(&b, &opt_list[0], "length").unwrap().value,
            FieldValue::U16(8)
        );
    }

    #[test]
    fn edns_option_container_resolves_to_option_name() {
        // OPT RR carrying a single COOKIE option so the container label
        // should resolve to "COOKIE" rather than duplicating "Code".
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes()); // code = COOKIE
        rdata.extend_from_slice(&8u16.to_be_bytes()); // length = 8
        rdata.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);

        let mut data = header(0, 0, 0, 1);
        data.push(0);
        data.extend_from_slice(&TYPE_OPT.to_be_bytes());
        data.extend_from_slice(&4096u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();

        let (opt_idx, opt_field) = b
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == "edns_option")
            .expect("edns_option container not found");
        assert!(matches!(opt_field.value, FieldValue::Object(_)));
        assert_eq!(opt_field.display_name(), "EDNS Option");
        assert_eq!(
            b.resolve_container_display_name(opt_idx as u32),
            Some("COOKIE")
        );
    }

    // ---- RFC 7828 — EDNS TCP Keepalive -----------------------------------

    #[test]
    fn parse_edns_tcp_keepalive() {
        // OPT RR carrying a TCP-KEEPALIVE option with timeout = 300 (30 s).
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&EDNS_OPT_TCP_KEEPALIVE.to_be_bytes()); // code = 11
        rdata.extend_from_slice(&2u16.to_be_bytes()); // length = 2
        rdata.extend_from_slice(&300u16.to_be_bytes()); // 30.0 seconds

        let mut data = header(0, 0, 0, 1);
        data.push(0);
        data.extend_from_slice(&TYPE_OPT.to_be_bytes());
        data.extend_from_slice(&1232u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let additionals = b.field_by_name(layer, "additionals").unwrap();
        let rr = first_array_entry(&b, additionals);
        let opts = find_child(&b, rr, "edns_options").unwrap();
        let opt = first_array_entry(&b, opts);
        assert_eq!(
            find_child(&b, opt, "timeout").unwrap().value,
            FieldValue::U16(300)
        );
    }

    // ---- RFC 4255 — SSHFP ------------------------------------------------

    #[test]
    fn parse_sshfp_record() {
        // algorithm=2 (DSS), fingerprint_type=1 (SHA-1), fingerprint = 20 bytes.
        let rdata: Vec<u8> = {
            let mut v = vec![2u8, 1u8];
            v.extend_from_slice(&[0u8; 20]);
            v
        };
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_SSHFP.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_algorithm").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_fingerprint_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_fingerprint").unwrap().value,
            FieldValue::Bytes(&[0u8; 20])
        );
    }

    // ---- RFC 6698 — TLSA -------------------------------------------------

    #[test]
    fn parse_tlsa_record() {
        // usage=3 (DANE-EE), selector=1 (SPKI), matching_type=1 (SHA-256),
        // 32-byte SHA-256 hash.
        let rdata: Vec<u8> = {
            let mut v = vec![3u8, 1u8, 1u8];
            v.extend_from_slice(&[0xAAu8; 32]);
            v
        };
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("_443._tcp.ex.test"));
        data.extend_from_slice(&TYPE_TLSA.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_cert_usage").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_selector").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_matching_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_cert_assoc_data").unwrap().value,
            FieldValue::Bytes(&[0xAAu8; 32])
        );
    }

    // ---- RFC 4034 §5.1 — DS ---------------------------------------------

    #[test]
    fn parse_ds_record() {
        let digest = [0x11u8; 20]; // SHA-1 digest
        let rdata: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&12345u16.to_be_bytes()); // key tag
            v.push(8); // RSASHA256
            v.push(1); // SHA-1
            v.extend_from_slice(&digest);
            v
        };
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_DS.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_key_tag").unwrap().value,
            FieldValue::U16(12345)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_algorithm").unwrap().value,
            FieldValue::U8(8)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_digest_type").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_digest").unwrap().value,
            FieldValue::Bytes(&digest)
        );
    }

    // ---- RFC 7344 — CDS / CDNSKEY share parsing with DS / DNSKEY ---------

    #[test]
    fn parse_cds_record() {
        let digest = [0x22u8; 20];
        let rdata: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&65535u16.to_be_bytes());
            v.push(13); // ECDSAP256SHA256
            v.push(2); // SHA-256
            v.extend_from_slice(&digest);
            v
        };
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_CDS.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_key_tag").unwrap().value,
            FieldValue::U16(65535)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_digest").unwrap().value,
            FieldValue::Bytes(&digest)
        );
    }

    // ---- RFC 4034 §2.1 — DNSKEY ------------------------------------------

    #[test]
    fn parse_dnskey_record() {
        let pubkey = [0x33u8; 64];
        let rdata: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&256u16.to_be_bytes()); // flags: ZONE=1 (bit 7)
            v.push(3); // protocol MUST be 3
            v.push(13); // algorithm ECDSAP256SHA256
            v.extend_from_slice(&pubkey);
            v
        };
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_DNSKEY.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_flags").unwrap().value,
            FieldValue::U16(256)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_protocol").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_algorithm").unwrap().value,
            FieldValue::U8(13)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_public_key").unwrap().value,
            FieldValue::Bytes(&pubkey)
        );
    }

    // ---- RFC 4034 §3.1 — RRSIG ------------------------------------------

    #[test]
    fn parse_rrsig_record() {
        let signer = wire_name("ex.test");
        let signature = [0x55u8; 64];
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&TYPE_A.to_be_bytes()); // type covered
        rdata.push(13); // algorithm
        rdata.push(2); // labels
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // original TTL
        rdata.extend_from_slice(&2_000_000_000u32.to_be_bytes()); // expiration
        rdata.extend_from_slice(&1_000_000_000u32.to_be_bytes()); // inception
        rdata.extend_from_slice(&4321u16.to_be_bytes()); // key tag
        rdata.extend_from_slice(&signer);
        rdata.extend_from_slice(&signature);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_RRSIG.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_type_covered").unwrap().value,
            FieldValue::U16(TYPE_A)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_labels").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_original_ttl").unwrap().value,
            FieldValue::U32(3600)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_signature_expiration")
                .unwrap()
                .value,
            FieldValue::U32(2_000_000_000)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_signature_inception")
                .unwrap()
                .value,
            FieldValue::U32(1_000_000_000)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_key_tag").unwrap().value,
            FieldValue::U16(4321)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_signature").unwrap().value,
            FieldValue::Bytes(&signature)
        );
    }

    // ---- RFC 4034 §4.1 — NSEC -------------------------------------------

    #[test]
    fn parse_nsec_record() {
        // NSEC with next-domain-name = "next.ex.test" and a type bitmap
        // window 0 indicating A and AAAA are present.
        let next_name = wire_name("next.ex.test");
        // Bitmap window 0, length 4, bitmap covers bits for types 1 (A) and
        // 28 (AAAA). bit 1 in byte 0 → 0x40, bit 28 in byte 3 → 0x08.
        let bitmap = [0u8, 0, 0, 0x08, 0x40];
        // Actually build the bitmap dynamically for clarity.
        let mut bitmaps = Vec::new();
        bitmaps.push(0u8); // window block 0
        bitmaps.push(4u8); // bitmap length (covers bytes 0..4 → types 0..31)
        bitmaps.extend_from_slice(&[0x40, 0, 0, 0x08]); // A (1), AAAA (28)
        let _ = bitmap;

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&next_name);
        rdata.extend_from_slice(&bitmaps);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_NSEC.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_next_domain_name").unwrap().value,
            FieldValue::Bytes(&next_name)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_type_bitmaps").unwrap().value,
            FieldValue::Bytes(&bitmaps)
        );
    }

    // ---- RFC 1035 §3.2.1 — names embedded in RDATA stay within RDLENGTH --

    /// Build a response with one answer RR (root owner, class IN, TTL 0)
    /// whose RDLENGTH covers only `rdata`; `trailing` follows RDATA in the
    /// message, so a name that starts inside `rdata` can run into it.
    fn answer_with_trailing(rtype: u16, rdata: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut data = header(0, 1, 0, 0);
        data.push(0); // owner name: root
        data.extend_from_slice(&rtype.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        data.extend_from_slice(&0u32.to_be_bytes()); // TTL
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);
        data.extend_from_slice(trailing);
        data
    }

    /// Dissect `data` and assert that the single answer RR fell back to a
    /// raw `rdata` field covering exactly `rdata`, with no typed sub-field.
    fn assert_raw_rdata_fallback(data: &[u8], rdata: &[u8]) {
        let mut b = buf();
        DnsDissector.dissect(data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        let rdata_field = find_child(&b, rr, "rdata").expect("raw rdata fallback");
        assert_eq!(rdata_field.value, FieldValue::Bytes(rdata));
        // header (12) + root owner (1) + TYPE/CLASS/TTL/RDLENGTH (10)
        let rdata_start = 12 + 1 + 10;
        assert_eq!(rdata_field.range, rdata_start..rdata_start + rdata.len());
        let range = match &rr.value {
            FieldValue::Object(r) => r.clone(),
            _ => panic!("expected Object"),
        };
        for f in b.nested_fields(&range) {
            assert!(
                !f.name().starts_with("rdata_"),
                "unexpected typed field {}",
                f.name()
            );
            assert!(f.range.end <= rdata_start + rdata.len());
        }
    }

    /// "com." encoded in place: 5 octets, placed right after RDATA.
    const OVERRUN_NAME: [u8; 5] = [3, b'c', b'o', b'm', 0];

    #[test]
    fn nsec_next_name_overrunning_rdata_falls_back() {
        // RDLENGTH=1: only the "com" length octet is inside RDATA.
        let data = answer_with_trailing(TYPE_NSEC, &OVERRUN_NAME[..1], &OVERRUN_NAME[1..]);
        assert_raw_rdata_fallback(&data, &OVERRUN_NAME[..1]);
    }

    #[test]
    fn rrsig_signer_name_overrunning_rdata_falls_back() {
        // RDLENGTH=18: the fixed part only; the signer name lies outside RDATA.
        let rdata = [0u8; 18];
        let data = answer_with_trailing(TYPE_RRSIG, &rdata, &OVERRUN_NAME);
        assert_raw_rdata_fallback(&data, &rdata);
    }

    #[test]
    fn names_overrunning_rdata_fall_back_for_every_name_type() {
        // (type, fixed-size prefix before the embedded name)
        let cases: &[(u16, &[u8])] = &[
            (TYPE_CNAME, &[]),
            (TYPE_NS, &[]),
            (TYPE_PTR, &[]),
            (TYPE_DNAME, &[]),
            (TYPE_SOA, &[]),
            (TYPE_MX, &[0, 10]),
            (TYPE_SRV, &[0, 1, 0, 2, 0, 80]),
            // order, preference, three empty character-strings
            (TYPE_NAPTR, &[0, 1, 0, 2, 0, 0, 0]),
            (TYPE_SVCB, &[0, 1]),
            (TYPE_HTTPS, &[0, 1]),
        ];
        for &(rtype, prefix) in cases {
            // RDATA holds the prefix plus the first octet of the name.
            let mut rdata = prefix.to_vec();
            rdata.push(OVERRUN_NAME[0]);
            let data = answer_with_trailing(rtype, &rdata, &OVERRUN_NAME[1..]);
            assert_raw_rdata_fallback(&data, &rdata);
        }
    }

    #[test]
    fn trailing_octets_after_final_rdata_field_fall_back() {
        // RFC 1035 §3.3.9 / §3.3.13, RFC 2782, RFC 3403 §4.1 — the name (or,
        // for SOA, MINIMUM) is the last RDATA field, so RDATA that continues
        // past it is malformed.
        let garbage = [0xDEu8, 0xAD];
        let mut soa = wire_name("ns.test");
        soa.extend_from_slice(&wire_name("admin.test"));
        soa.extend_from_slice(&[0u8; 20]); // SERIAL .. MINIMUM
        let cases: Vec<(u16, Vec<u8>)> = vec![
            (TYPE_MX, [&[0u8, 10][..], &wire_name("mx.test")].concat()),
            (
                TYPE_SRV,
                [&[0u8, 1, 0, 2, 0, 80][..], &wire_name("sip.test")].concat(),
            ),
            (
                TYPE_NAPTR,
                [&[0u8, 1, 0, 2, 0, 0, 0][..], &wire_name("r.test")].concat(),
            ),
            (TYPE_SOA, soa),
        ];
        for (rtype, mut rdata) in cases {
            rdata.extend_from_slice(&garbage);
            let data = answer_with_trailing(rtype, &rdata, &[]);
            assert_raw_rdata_fallback(&data, &rdata);
        }
    }

    #[test]
    fn soa_rname_overrunning_rdata_falls_back() {
        // MNAME fits; RNAME starts on the last RDATA octet and runs past it.
        let mut rdata = wire_name("ns.test");
        rdata.push(OVERRUN_NAME[0]);
        let data = answer_with_trailing(TYPE_SOA, &rdata, &OVERRUN_NAME[1..]);
        assert_raw_rdata_fallback(&data, &rdata);
    }

    #[test]
    fn nsec_next_name_compression_pointer_is_accepted() {
        // RFC 4034 §4.1.1 says a sender MUST NOT compress the Next Domain
        // Name, and RFC 3597 §4 forbids compression in RR types newer than
        // RFC 1035. This is not spec behaviour: the dissector accepts such a
        // pointer liberally (Postel's Law). The pointer's 2 octets
        // (RFC 1035 §4.1.4) are what must fit inside RDATA.
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test")); // owner at offset 12
        data.extend_from_slice(&TYPE_NSEC.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let rdata = [0xC0u8, 0x0C, 0, 1, 0x40];
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_next_domain_name").unwrap().value,
            FieldValue::Bytes(&rdata[..2])
        );
        assert_eq!(
            find_child(&b, rr, "rdata_type_bitmaps").unwrap().value,
            FieldValue::Bytes(&rdata[2..])
        );
    }

    // ---- RFC 5155 §3.2 — NSEC3 ------------------------------------------

    #[test]
    fn parse_nsec3_record() {
        let salt = [0xCAu8, 0xFE];
        let next_hash = [0x11u8; 20];
        let bitmaps = [0u8, 1u8, 0x40u8]; // window 0, length 1, bit 1 (A)
        let mut rdata = Vec::new();
        rdata.push(1); // hash algorithm = SHA-1
        rdata.push(0); // flags
        rdata.extend_from_slice(&10u16.to_be_bytes()); // iterations
        rdata.push(salt.len() as u8);
        rdata.extend_from_slice(&salt);
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(&next_hash);
        rdata.extend_from_slice(&bitmaps);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_NSEC3.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_hash_algorithm").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_iterations").unwrap().value,
            FieldValue::U16(10)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_salt_length").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_salt").unwrap().value,
            FieldValue::Bytes(&salt)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_hash_length").unwrap().value,
            FieldValue::U8(20)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_next_hashed_owner").unwrap().value,
            FieldValue::Bytes(&next_hash)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_type_bitmaps").unwrap().value,
            FieldValue::Bytes(&bitmaps)
        );
    }

    // ---- RFC 5155 §4.2 — NSEC3PARAM -------------------------------------

    #[test]
    fn parse_nsec3param_record() {
        let salt = [0x01u8, 0x02, 0x03];
        let mut rdata = Vec::new();
        rdata.push(1); // hash algorithm
        rdata.push(0); // flags
        rdata.extend_from_slice(&5u16.to_be_bytes()); // iterations
        rdata.push(salt.len() as u8);
        rdata.extend_from_slice(&salt);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_NSEC3PARAM.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_hash_algorithm").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_iterations").unwrap().value,
            FieldValue::U16(5)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_salt").unwrap().value,
            FieldValue::Bytes(&salt)
        );
    }

    // ---- RFC 8659 §4.1 — CAA --------------------------------------------

    #[test]
    fn parse_caa_record() {
        // Flags = 0x80 (Issuer Critical), tag = "issue", value = "ca.example.net".
        let tag = b"issue";
        let value = b"ca.example.net";
        let mut rdata = Vec::new();
        rdata.push(0x80); // critical flag
        rdata.push(tag.len() as u8);
        rdata.extend_from_slice(tag);
        rdata.extend_from_slice(value);

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_CAA.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        // Remember absolute offset of the RDATA for range verification.
        let rdata_abs = data.len();
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);

        assert_eq!(
            find_child(&b, rr, "rdata_flags").unwrap().value,
            FieldValue::U8(0x80)
        );

        // Tag value and range. Range MUST cover exactly the tag bytes
        // (rdata[2..2+tag_len]) per RFC 8659 §4.1, not include the length
        // byte at offset 1.
        let tag_field = find_child(&b, rr, "rdata_tag").unwrap();
        assert_eq!(tag_field.value, FieldValue::Bytes(tag));
        assert_eq!(
            tag_field.range,
            (rdata_abs + 2)..(rdata_abs + 2 + tag.len())
        );
        assert_eq!(tag_field.range.len(), tag.len());

        let value_field = find_child(&b, rr, "rdata_value").unwrap();
        assert_eq!(value_field.value, FieldValue::Bytes(value));
        assert_eq!(
            value_field.range,
            (rdata_abs + 2 + tag.len())..(rdata_abs + 2 + tag.len() + value.len())
        );
    }

    // ---- RFC 9460 — SVCB / HTTPS -----------------------------------------

    #[test]
    fn parse_svcb_record() {
        // ServiceMode priority=1, target=svc.ex.test, empty SvcParams.
        let target = wire_name("svc.ex.test");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&target);
        // No SvcParams.

        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(&rdata);

        let mut b = buf();
        DnsDissector.dissect(&data, &mut b, 0).unwrap();
        let layer = &b.layers()[0];
        let answers = b.field_by_name(layer, "answers").unwrap();
        let rr = first_array_entry(&b, answers);
        assert_eq!(
            find_child(&b, rr, "rdata_priority").unwrap().value,
            FieldValue::U16(1)
        );
        assert_eq!(
            find_child(&b, rr, "rdata_target").unwrap().value,
            FieldValue::Bytes(&target)
        );
    }

    // ---- RFC 1035 §2.3.4 / §3.1 / §4.1.4 — name limits ------------------

    #[test]
    fn reject_name_over_255_octets() {
        // Build a 256-octet name (just exceeds the 255 limit) by stringing
        // together labels of 63 bytes + 63 + 63 + 62 + terminator.
        let label_63: Vec<u8> = core::iter::once(63u8)
            .chain(std::iter::repeat_n(b'a', 63))
            .collect();
        let label_62: Vec<u8> = core::iter::once(62u8)
            .chain(std::iter::repeat_n(b'a', 62))
            .collect();
        let mut name = Vec::new();
        name.extend_from_slice(&label_63);
        name.extend_from_slice(&label_63);
        name.extend_from_slice(&label_63);
        name.extend_from_slice(&label_62);
        name.push(0);
        assert_eq!(name.len(), 64 * 3 + 63 + 1); // 256

        let mut data = header(1, 0, 0, 0);
        data.extend_from_slice(&name);
        data.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
        data.extend_from_slice(&1u16.to_be_bytes()); // QCLASS

        let mut b = buf();
        let err = DnsDissector.dissect(&data, &mut b, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn reject_name_pointer_loop() {
        // Construct a QNAME that is a single 2-byte pointer referencing itself.
        // Pointer at offset 12 (== HEADER_SIZE) points back to offset 12.
        let mut data = header(1, 0, 0, 0);
        data.push(0xC0);
        data.push(HEADER_SIZE as u8); // pointer to self
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());

        let mut b = buf();
        let err = DnsDissector.dissect(&data, &mut b, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn reject_reserved_label_type() {
        // 01 / 10 label-type prefixes are reserved (RFC 1035 §4.1.4).
        let mut data = header(1, 0, 0, 0);
        data.push(0x80); // starts with bits 10 — reserved
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());

        let mut b = buf();
        let err = DnsDissector.dissect(&data, &mut b, 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    // ---- RFC 1035 §4.2.2 / RFC 7766 §8 — TCP length prefix ---------------

    #[test]
    fn parse_tcp_length_prefix() {
        let mut dns = header(1, 0, 0, 0);
        dns.extend_from_slice(&wire_name("ex.test"));
        dns.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        dns.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        let mut framed = Vec::new();
        framed.extend_from_slice(&(dns.len() as u16).to_be_bytes());
        framed.extend_from_slice(&dns);

        let mut b = buf();
        let res = DnsTcpDissector.dissect(&framed, &mut b, 0).unwrap();
        assert_eq!(res.bytes_consumed, framed.len());

        let layer = &b.layers()[0];
        assert_eq!(layer.name, "DNS");
        let tcp_len = b.field_by_name(layer, "tcp_length").unwrap();
        assert_eq!(tcp_len.value, FieldValue::U16(dns.len() as u16));
        assert_eq!(tcp_len.range, 0..2);
    }

    #[test]
    fn tcp_truncated_length_prefix() {
        let mut b = buf();
        let err = DnsTcpDissector.dissect(&[0u8], &mut b, 0).unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn tcp_message_overrunning_length_prefix_is_invalid() {
        // RFC 1035 §4.2.2 — the length prefix delimits the message. A message
        // whose sections need more octets than the prefix gives is malformed;
        // the capture itself is not truncated, so `Truncated` would be wrong
        // (and would report the inner slice length, not `data.len()`).
        let dns = header(1, 0, 0, 0); // QDCOUNT=1 but no question follows
        let mut framed = Vec::new();
        framed.extend_from_slice(&(dns.len() as u16).to_be_bytes());
        framed.extend_from_slice(&dns);
        framed.extend_from_slice(&wire_name("ex.test")); // beyond the prefix

        let mut b = buf();
        let err = DnsTcpDissector.dissect(&framed, &mut b, 0).unwrap_err();
        assert_eq!(
            err,
            PacketError::InvalidHeader("DNS message overruns TCP length prefix")
        );
    }

    // ---- Name lookup helpers --------------------------------------------

    #[test]
    fn type_class_opcode_rcode_names() {
        assert_eq!(dns_type_name(TYPE_A), Some("A"));
        assert_eq!(dns_type_name(TYPE_AAAA), Some("AAAA"));
        assert_eq!(dns_type_name(TYPE_OPT), Some("OPT"));
        assert_eq!(dns_type_name(TYPE_HTTPS), Some("HTTPS"));
        assert_eq!(dns_type_name(9999), None);

        assert_eq!(dns_class_name(1), Some("IN"));
        assert_eq!(dns_class_name(255), Some("ANY"));
        assert_eq!(dns_class_name(7), None);

        assert_eq!(dns_opcode_name(0), Some("QUERY"));
        assert_eq!(dns_opcode_name(5), Some("UPDATE"));
        assert_eq!(dns_opcode_name(15), None);

        assert_eq!(dns_rcode_name(0), Some("NOERROR"));
        assert_eq!(dns_rcode_name(3), Some("NXDOMAIN"));
        assert_eq!(dns_rcode_name(15), None);

        assert_eq!(edns_option_code_name(10), Some("COOKIE"));
        assert_eq!(
            edns_option_code_name(EDNS_OPT_TCP_KEEPALIVE),
            Some("TCP-KEEPALIVE")
        );
        assert_eq!(edns_option_code_name(9999), None);
    }

    #[test]
    fn dispatch_hint_is_end() {
        // DNS is terminal: dispatch key must be End.
        let mut data = header(0, 0, 0, 0);
        data.extend_from_slice(&[]);
        let mut b = buf();
        let res = DnsDissector.dissect(&data, &mut b, 0).unwrap();
        assert!(matches!(res.next, DispatchHint::End));
    }

    #[test]
    fn write_dns_name_formats_output() {
        // Build a minimal DNS message where the QNAME is a single compressed
        // pointer to "example.com." stored earlier in the buffer.
        let target = wire_name("example.com");
        let mut data = Vec::new();
        data.extend_from_slice(&[0xBE, 0xEF, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        // Place target name right after the header to make pointer offsets easy.
        let name_off = data.len();
        data.extend_from_slice(&target);
        data.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
        data.extend_from_slice(&1u16.to_be_bytes()); // QCLASS

        let ctx = FormatContext {
            packet_data: &data,
            scratch: &[],
            layer_range: 0..data.len() as u32,
            field_range: name_off as u32..(name_off + target.len()) as u32,
        };
        let mut out = Vec::new();
        write_dns_name(&FieldValue::Bytes(&target), &ctx, &mut out).unwrap();
        assert_eq!(&out, b"\"example.com\"");
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

        assert_layer_and_references(&DnsDissector);
        assert_layer_and_references(&DnsTcpDissector);
    }

    // ---- Helpers for the structured-decoding tests below -----------------

    /// Return the direct children of an Object / Array field (skipping the
    /// flattened grandchildren that `nested_fields` also yields).
    fn direct_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        parent: &Field<'pkt>,
    ) -> Vec<&'a Field<'pkt>> {
        let range = match &parent.value {
            FieldValue::Object(r) | FieldValue::Array(r) => r.clone(),
            _ => panic!("expected container"),
        };
        let fields = buf.fields();
        let mut out = Vec::new();
        let mut i = range.start;
        while i < range.end {
            let f = &fields[i as usize];
            out.push(f);
            i = match &f.value {
                FieldValue::Object(r) | FieldValue::Array(r) => r.end,
                _ => i + 1,
            };
        }
        out
    }

    /// Build a response with a single answer RR of `rtype` carrying `rdata`.
    fn single_answer(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut data = header(0, 1, 0, 0);
        data.extend_from_slice(&wire_name("ex.test"));
        data.extend_from_slice(&rtype.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&300u32.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);
        data
    }

    /// Build a message with a single OPT RR (additional section) carrying
    /// `rdata`, with the given header RCODE and OPT TTL.
    fn single_opt(header_rcode: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut data = header(0, 0, 0, 1);
        data[2..4].copy_from_slice(&(0x8000 | header_rcode).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&TYPE_OPT.to_be_bytes());
        data.extend_from_slice(&1232u16.to_be_bytes());
        data.extend_from_slice(&ttl.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);
        data
    }

    /// Dissect `data` and return the buffer.
    fn dissect(data: &[u8]) -> DissectBuffer<'_> {
        let mut b = DissectBuffer::new();
        DnsDissector.dissect(data, &mut b, 0).unwrap();
        b
    }

    /// First RR object of the named section.
    fn first_rr<'a, 'pkt>(b: &'a DissectBuffer<'pkt>, section: &str) -> &'a Field<'pkt> {
        let layer = &b.layers()[0];
        let arr = b.field_by_name(layer, section).unwrap();
        first_array_entry(b, arr)
    }

    /// Direct child of `parent` with `name`.
    fn child<'a, 'pkt>(
        b: &'a DissectBuffer<'pkt>,
        parent: &Field<'pkt>,
        name: &str,
    ) -> &'a Field<'pkt> {
        direct_children(b, parent)
            .into_iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("no child {name}"))
    }

    /// Whether `parent` has a direct child with `name`.
    fn has_child(b: &DissectBuffer<'_>, parent: &Field<'_>, name: &str) -> bool {
        direct_children(b, parent).iter().any(|f| f.name() == name)
    }

    /// The first EDNS option object of the single OPT RR in `b`.
    fn first_edns_option<'a, 'pkt>(b: &'a DissectBuffer<'pkt>) -> &'a Field<'pkt> {
        let rr = first_rr(b, "additionals");
        let opts = child(b, rr, "edns_options");
        direct_children(b, opts)[0]
    }

    /// Wrap an EDNS option in OPT RDATA.
    fn edns_opt(code: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    // ---- RFC 9460 §2.2 / §7, Appendix D.2 — SvcParams --------------------

    #[test]
    fn svcb_params_rfc9460_figure9_mandatory_alpn_ipv4hint() {
        // RFC 9460, Appendix D.2, Figure 9.
        let rdata: &[u8] = &[
            0x00, 0x10, 0x03, b'f', b'o', b'o', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'o', b'r', b'g', 0x00, // priority, target
            0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, // mandatory=alpn,ipv4hint
            0x00, 0x01, 0x00, 0x09, 0x02, b'h', b'2', 0x05, b'h', b'3', b'-', b'1',
            b'9', // alpn
            0x00, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, // ipv4hint
        ];
        let data = single_answer(TYPE_SVCB, rdata);
        let rdata_abs = data.len() - rdata.len();
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        // Raw SvcParams are kept for compatibility.
        assert_eq!(
            child(&b, rr, "rdata_params").value,
            FieldValue::Bytes(&rdata[19..])
        );
        let params = child(&b, rr, "rdata_svc_params");
        let entries = direct_children(&b, params);
        assert_eq!(entries.len(), 3);

        // mandatory
        let p0 = entries[0];
        assert_eq!(p0.range, rdata_abs + 19..rdata_abs + 27);
        assert_eq!(child(&b, p0, "key").value, FieldValue::U16(0));
        assert_eq!(child(&b, p0, "length").value, FieldValue::U16(4));
        let keys: Vec<_> = direct_children(&b, child(&b, p0, "mandatory"))
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(keys, vec![FieldValue::U16(1), FieldValue::U16(4)]);

        // alpn
        let p1 = entries[1];
        assert_eq!(child(&b, p1, "key").value, FieldValue::U16(1));
        let ids = direct_children(&b, child(&b, p1, "alpn"));
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].value, FieldValue::Bytes(b"h2"));
        assert_eq!(ids[0].range, rdata_abs + 32..rdata_abs + 34);
        assert_eq!(ids[1].value, FieldValue::Bytes(b"h3-19"));

        // ipv4hint
        let p2 = entries[2];
        let addrs = direct_children(&b, child(&b, p2, "ipv4hint"));
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].value, FieldValue::Ipv4Addr([192, 0, 2, 1]));

        // Container label and key names resolve to the registered key name.
        let idx = b
            .fields()
            .iter()
            .position(|f| core::ptr::eq(f, p1))
            .unwrap();
        assert_eq!(b.resolve_container_display_name(idx as u32), Some("alpn"));
        assert_eq!(svc_param_key_name(4), Some("ipv4hint"));
    }

    #[test]
    fn svcb_params_rfc9460_figure4_port_and_figure7_ipv6hint() {
        // Figure 4: port=53.
        let mut rdata = vec![0x00, 0x10];
        rdata.extend_from_slice(&wire_name("foo.example.com"));
        rdata.extend_from_slice(&[0x00, 0x03, 0x00, 0x02, 0x00, 0x35]);
        let data = single_answer(TYPE_SVCB, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let p = direct_children(&b, child(&b, rr, "rdata_svc_params"))[0];
        assert_eq!(child(&b, p, "port").value, FieldValue::U16(53));

        // Figure 7: two IPv6 hints.
        let mut rdata = vec![0x00, 0x01];
        rdata.extend_from_slice(&wire_name("foo.example.com"));
        rdata.extend_from_slice(&[0x00, 0x06, 0x00, 0x20]);
        let a1: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let a2: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53, 0, 1,
        ];
        rdata.extend_from_slice(&a1);
        rdata.extend_from_slice(&a2);
        let data = single_answer(TYPE_HTTPS, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let p = direct_children(&b, child(&b, rr, "rdata_svc_params"))[0];
        let addrs: Vec<_> = direct_children(&b, child(&b, p, "ipv6hint"))
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(
            addrs,
            vec![FieldValue::Ipv6Addr(a1), FieldValue::Ipv6Addr(a2)]
        );
    }

    #[test]
    fn svcb_params_issue_repro_https_alpn_h2() {
        // HTTPS RR, priority 1, target ".", alpn=h2 (issue reproduction).
        let rdata: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2'];
        let data = single_answer(TYPE_HTTPS, rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let p = direct_children(&b, child(&b, rr, "rdata_svc_params"))[0];
        assert_eq!(child(&b, p, "key").value, FieldValue::U16(1));
        let ids = direct_children(&b, child(&b, p, "alpn"));
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].value, FieldValue::Bytes(b"h2"));
    }

    #[test]
    fn svcb_params_ech_dohpath_no_default_alpn_and_unknown_key() {
        let mut rdata = vec![0x00, 0x01, 0x00];
        rdata.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]); // no-default-alpn
        rdata.extend_from_slice(&[0x00, 0x05, 0x00, 0x04, 0x00, 0x02, 0xfe, 0x0d]); // ech
        rdata.extend_from_slice(&[0x00, 0x07, 0x00, 0x0b]); // dohpath
        rdata.extend_from_slice(b"/q{?dns}xyz");
        rdata.extend_from_slice(&[0x02, 0x9b, 0x00, 0x05]); // key667 (Figure 5)
        rdata.extend_from_slice(b"hello");
        let data = single_answer(TYPE_SVCB, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let entries = direct_children(&b, child(&b, rr, "rdata_svc_params"));
        assert_eq!(entries.len(), 4);
        // no-default-alpn: key + length only.
        assert_eq!(direct_children(&b, entries[0]).len(), 2);
        assert_eq!(
            child(&b, entries[1], "ech").value,
            FieldValue::Bytes(&[0x00, 0x02, 0xfe, 0x0d])
        );
        assert_eq!(
            child(&b, entries[2], "dohpath").value,
            FieldValue::Bytes(b"/q{?dns}xyz")
        );
        assert_eq!(child(&b, entries[3], "key").value, FieldValue::U16(667));
        assert_eq!(
            child(&b, entries[3], "value").value,
            FieldValue::Bytes(b"hello")
        );
    }

    #[test]
    fn svcb_params_malformed_values_fall_back_to_raw_value() {
        // port with 1 octet, empty ipv4hint, alpn not exactly filled,
        // ipv6hint of 15 octets, mandatory of odd length.
        let mut rdata = vec![0x00, 0x01, 0x00];
        rdata.extend_from_slice(&[0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00]); // mandatory
        rdata.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x05, b'h']); // alpn
        rdata.extend_from_slice(&[0x00, 0x02, 0x00, 0x01, 0x00]); // no-default-alpn, len 1
        rdata.extend_from_slice(&[0x00, 0x03, 0x00, 0x01, 0x35]); // port
        rdata.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]); // ipv4hint
        rdata.extend_from_slice(&[0x00, 0x06, 0x00, 0x0f]); // ipv6hint
        rdata.extend_from_slice(&[0u8; 15]);
        let data = single_answer(TYPE_SVCB, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let entries = direct_children(&b, child(&b, rr, "rdata_svc_params"));
        assert_eq!(entries.len(), 6);
        for e in entries {
            let names: Vec<_> = direct_children(&b, e).iter().map(|f| f.name()).collect();
            assert_eq!(names, vec!["key", "length", "value"], "{names:?}");
        }
    }

    #[test]
    fn svcb_params_truncated_list_keeps_only_raw_params() {
        // RFC 9460 §2.2: the end of RDATA inside a SvcParam is malformed.
        let rdata: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00];
        let data = single_answer(TYPE_SVCB, rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert!(has_child(&b, rr, "rdata_params"));
        assert!(!has_child(&b, rr, "rdata_svc_params"));
    }

    // ---- RFC 6891 §6.1.3 — extended RCODE ---------------------------------

    #[test]
    fn opt_combined_rcode_badvers() {
        // Header RCODE 0, OPT TTL 01 00 00 00 → RCODE 16 (BADVERS).
        let data = single_opt(0, 0x0100_0000, &[]);
        let b = dissect(&data);
        let rr = first_rr(&b, "additionals");
        assert_eq!(child(&b, rr, "extended_rcode").value, FieldValue::U8(1));
        let rcode = child(&b, rr, "rcode");
        assert_eq!(rcode.value, FieldValue::U16(16));
        assert_eq!(
            (rcode.descriptor.display_fn.unwrap())(&rcode.value, &[]),
            Some("BADVERS")
        );
        // Low nibble comes from the header.
        let data = single_opt(3, 0x0100_0000, &[]);
        let b = dissect(&data);
        let rr = first_rr(&b, "additionals");
        assert_eq!(child(&b, rr, "rcode").value, FieldValue::U16(19));
    }

    #[test]
    fn rcode_opcode_and_type_names_follow_iana() {
        for (v, n) in [
            (6, "YXDOMAIN"),
            (7, "YXRRSET"),
            (8, "NXRRSET"),
            (9, "NOTAUTH"),
            (10, "NOTZONE"),
            (11, "DSOTYPENI"),
            (16, "BADVERS"),
            (17, "BADKEY"),
            (18, "BADTIME"),
            (19, "BADMODE"),
            (20, "BADNAME"),
            (21, "BADALG"),
            (22, "BADTRUNC"),
            (23, "BADCOOKIE"),
        ] {
            assert_eq!(dns_rcode_name(v), Some(n), "rcode {v}");
        }
        assert_eq!(dns_rcode_name(12), None);
        assert_eq!(dns_rcode_name(24), None);
        assert_eq!(tsig_rcode_name(16), Some("BADSIG"));
        assert_eq!(tsig_rcode_name(3), Some("NXDOMAIN"));
        assert_eq!(dns_opcode_name(6), Some("DSO"));
        for (v, n) in [
            (13, "HINFO"),
            (37, "CERT"),
            (39, "DNAME"),
            (44, "SSHFP"),
            (45, "IPSECKEY"),
            (49, "DHCID"),
            (51, "NSEC3PARAM"),
            (59, "CDS"),
            (60, "CDNSKEY"),
            (61, "OPENPGPKEY"),
            (62, "CSYNC"),
            (63, "ZONEMD"),
            (64, "SVCB"),
            (108, "EUI48"),
            (109, "EUI64"),
            (249, "TKEY"),
            (250, "TSIG"),
            (251, "IXFR"),
            (252, "AXFR"),
            (256, "URI"),
            (257, "CAA"),
        ] {
            assert_eq!(dns_type_name(v), Some(n), "type {v}");
        }
        for (v, n) in [
            (3, "NSID"),
            (5, "DAU"),
            (6, "DHU"),
            (7, "N3U"),
            (9, "EXPIRE"),
            (12, "PADDING"),
            (14, "KEY-TAG"),
            (18, "REPORT-CHANNEL"),
            (19, "ZONEVERSION"),
        ] {
            assert_eq!(edns_option_code_name(v), Some(n), "option {v}");
        }
        assert_eq!(ede_info_code_name(18), Some("Prohibited"));
        assert_eq!(ede_info_code_name(49151), None);
        // Every assigned code in the IANA registries has a name.
        assert!((1..=26).all(|c| c == 4 || edns_option_code_name(c).is_some()));
        assert_eq!(edns_option_code_name(4), None);
        assert!((0..=35).all(|c| ede_info_code_name(c).is_some()));
        assert!((0..=12).all(|k| svc_param_key_name(k).is_some()));
        assert_eq!(svc_param_key_name(13), None);
        assert_eq!(dso_type_name(0x41), Some("PUSH"));
        assert_eq!(dso_type_name(0), None);
        assert_eq!(tsig_rcode_name(300), None);
    }

    // ---- RFC 6891 §6.1.2 — EDNS options -----------------------------------

    #[test]
    fn edns_nsid_exposes_text_when_printable() {
        let data = single_opt(0, 0, &edns_opt(3, b"ns1.example"));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(
            child(&b, opt, "data").value,
            FieldValue::Bytes(b"ns1.example")
        );
        assert_eq!(child(&b, opt, "nsid").value, FieldValue::Str("ns1.example"));

        let data = single_opt(0, 0, &edns_opt(3, &[0x00, 0xff]));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert!(has_child(&b, opt, "data"));
        assert!(!has_child(&b, opt, "nsid"));
    }

    #[test]
    fn edns_dau_dhu_n3u_algorithm_lists() {
        for code in [5u16, 6, 7] {
            let data = single_opt(0, 0, &edns_opt(code, &[8, 13, 15]));
            let b = dissect(&data);
            let opt = first_edns_option(&b);
            let algs: Vec<_> = direct_children(&b, child(&b, opt, "algorithms"))
                .iter()
                .map(|f| f.value.clone())
                .collect();
            assert_eq!(
                algs,
                vec![FieldValue::U8(8), FieldValue::U8(13), FieldValue::U8(15)]
            );
        }
    }

    #[test]
    fn edns_client_subnet_ipv4_and_ipv6() {
        // FAMILY 1, /24 source, /0 scope, 3 address octets.
        let data = single_opt(0, 0, &edns_opt(8, &[0, 1, 24, 0, 192, 0, 2]));
        let opt_abs = data.len() - 7;
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(child(&b, opt, "family").value, FieldValue::U16(1));
        assert_eq!(
            child(&b, opt, "source_prefix_length").value,
            FieldValue::U8(24)
        );
        assert_eq!(
            child(&b, opt, "scope_prefix_length").value,
            FieldValue::U8(0)
        );
        let addr = child(&b, opt, "address");
        assert_eq!(addr.value, FieldValue::Ipv4Addr([192, 0, 2, 0]));
        assert_eq!(addr.range, opt_abs + 4..opt_abs + 7);

        // FAMILY 2, /56 source → 7 octets.
        let data = single_opt(
            0,
            0,
            &edns_opt(8, &[0, 2, 56, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 2]),
        );
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        let mut expected = [0u8; 16];
        expected[..7].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 2]);
        assert_eq!(
            child(&b, opt, "address").value,
            FieldValue::Ipv6Addr(expected)
        );
        assert_eq!(
            child(&b, opt, "scope_prefix_length").value,
            FieldValue::U8(48)
        );

        // Unknown family: raw address bytes.
        let data = single_opt(0, 0, &edns_opt(8, &[0, 9, 8, 0, 0xaa]));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(child(&b, opt, "address").value, FieldValue::Bytes(&[0xaa]));

        // Too short for FAMILY + prefix lengths: raw data.
        let data = single_opt(0, 0, &edns_opt(8, &[0, 1, 24]));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert!(has_child(&b, opt, "data"));
        assert!(!has_child(&b, opt, "family"));
    }

    #[test]
    fn edns_cookie_client_and_server() {
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let data = single_opt(0, 0, &edns_opt(10, &client));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(
            child(&b, opt, "client_cookie").value,
            FieldValue::Bytes(&client)
        );
        assert!(!has_child(&b, opt, "server_cookie"));

        let mut both = client.to_vec();
        both.extend_from_slice(&[9u8; 16]);
        let data = single_opt(0, 0, &edns_opt(10, &both));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(
            child(&b, opt, "server_cookie").value,
            FieldValue::Bytes(&[9u8; 16])
        );

        // RFC 7873 §4: 9..15 and > 40 octets are malformed → raw data.
        for len in [9usize, 15, 41] {
            let data = single_opt(0, 0, &edns_opt(10, &vec![0u8; len]));
            let b = dissect(&data);
            let opt = first_edns_option(&b);
            assert!(has_child(&b, opt, "data"), "len {len}");
            assert!(!has_child(&b, opt, "client_cookie"), "len {len}");
        }
    }

    #[test]
    fn edns_padding_expire_key_tag() {
        // Padding: length only.
        let data = single_opt(0, 0, &edns_opt(12, &[0u8; 6]));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        let names: Vec<_> = direct_children(&b, opt).iter().map(|f| f.name()).collect();
        assert_eq!(names, vec!["code", "length"]);

        // EXPIRE (RFC 7314 §3): 4-octet value in responses.
        let data = single_opt(0, 0, &edns_opt(9, &3600u32.to_be_bytes()));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(child(&b, opt, "expire").value, FieldValue::U32(3600));

        // edns-key-tag (RFC 8145 §4.1): list of 16-bit key tags.
        let data = single_opt(0, 0, &edns_opt(14, &[0x4f, 0x66, 0x9e, 0xb7]));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        let tags: Vec<_> = direct_children(&b, child(&b, opt, "key_tags"))
            .iter()
            .map(|f| f.value.clone())
            .collect();
        assert_eq!(tags, vec![FieldValue::U16(0x4f66), FieldValue::U16(0x9eb7)]);

        // Odd key-tag length: raw.
        let data = single_opt(0, 0, &edns_opt(14, &[1, 2, 3]));
        let b = dissect(&data);
        assert!(has_child(&b, first_edns_option(&b), "data"));
    }

    #[test]
    fn edns_extended_dns_error() {
        let mut v = 18u16.to_be_bytes().to_vec();
        v.extend_from_slice(b"blocked by policy");
        let data = single_opt(0, 0, &edns_opt(15, &v));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        let info = child(&b, opt, "info_code");
        assert_eq!(info.value, FieldValue::U16(18));
        assert_eq!(
            (info.descriptor.display_fn.unwrap())(&info.value, &[]),
            Some("Prohibited")
        );
        assert_eq!(
            child(&b, opt, "extra_text").value,
            FieldValue::Bytes(b"blocked by policy")
        );

        // No EXTRA-TEXT.
        let data = single_opt(0, 0, &edns_opt(15, &0u16.to_be_bytes()));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert!(has_child(&b, opt, "info_code"));
        assert!(!has_child(&b, opt, "extra_text"));

        // Too short: raw.
        let data = single_opt(0, 0, &edns_opt(15, &[1]));
        let b = dissect(&data);
        assert!(has_child(&b, first_edns_option(&b), "data"));
    }

    #[test]
    fn edns_report_channel_agent_domain() {
        let name = wire_name("a01.agent-domain.example");
        let data = single_opt(0, 0, &edns_opt(18, &name));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(
            child(&b, opt, "agent_domain").value,
            FieldValue::Bytes(&name)
        );

        // Compression pointer or a name not filling the option: raw.
        for bad in [vec![0xc0, 0x0c], {
            let mut v = wire_name("x");
            v.push(0);
            v
        }] {
            let data = single_opt(0, 0, &edns_opt(18, &bad));
            let b = dissect(&data);
            let opt = first_edns_option(&b);
            assert!(has_child(&b, opt, "data"));
            assert!(!has_child(&b, opt, "agent_domain"));
        }
    }

    #[test]
    fn edns_zoneversion() {
        // Query form: empty.
        let data = single_opt(0, 0, &edns_opt(19, &[]));
        let b = dissect(&data);
        let names: Vec<_> = direct_children(&b, first_edns_option(&b))
            .iter()
            .map(|f| f.name())
            .collect();
        assert_eq!(names, vec!["code", "length"]);

        // Response: LABELCOUNT 2, TYPE 0 (SOA-SERIAL), VERSION 4 octets.
        let data = single_opt(0, 0, &edns_opt(19, &[2, 0, 0, 0, 0x30, 0x39]));
        let b = dissect(&data);
        let opt = first_edns_option(&b);
        assert_eq!(child(&b, opt, "label_count").value, FieldValue::U8(2));
        let t = child(&b, opt, "version_type");
        assert_eq!(t.value, FieldValue::U8(0));
        assert_eq!(
            (t.descriptor.display_fn.unwrap())(&t.value, &[]),
            Some("SOA-SERIAL")
        );
        assert_eq!(
            child(&b, opt, "version").value,
            FieldValue::Bytes(&[0, 0, 0x30, 0x39])
        );

        // One octet: raw.
        let data = single_opt(0, 0, &edns_opt(19, &[2]));
        let b = dissect(&data);
        assert!(has_child(&b, first_edns_option(&b), "data"));
    }

    // ---- RFC 4034 §4.1.2 — type bit maps ----------------------------------

    /// RFC 4034 §4.3 example bitmap: A, MX, RRSIG, NSEC, TYPE1234.
    fn rfc4034_bitmap() -> Vec<u8> {
        let mut v = vec![0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03, 0x04, 0x1b];
        v.extend_from_slice(&[0u8; 26]);
        v.push(0x20);
        v
    }

    fn types_of(b: &DissectBuffer<'_>, rr: &Field<'_>) -> Vec<FieldValue<'static>> {
        direct_children(b, child(b, rr, "rdata_types"))
            .iter()
            .map(|f| match f.value {
                FieldValue::U16(v) => FieldValue::U16(v),
                _ => panic!("type must be U16"),
            })
            .collect()
    }

    #[test]
    fn nsec_type_bitmap_rfc4034_example() {
        let mut rdata = wire_name("host.example.com");
        let bitmap = rfc4034_bitmap();
        rdata.extend_from_slice(&bitmap);
        let data = single_answer(TYPE_NSEC, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            types_of(&b, rr),
            vec![
                FieldValue::U16(1),
                FieldValue::U16(15),
                FieldValue::U16(46),
                FieldValue::U16(47),
                FieldValue::U16(1234)
            ]
        );
        // Raw bitmap bytes are kept.
        assert_eq!(
            child(&b, rr, "rdata_type_bitmaps").value,
            FieldValue::Bytes(&bitmap)
        );
    }

    #[test]
    fn nsec3_type_bitmap_a_ns_soa_rrsig_nsec_dnskey() {
        // A(1) NS(2) SOA(6) RRSIG(46) NSEC(47) DNSKEY(48) in window 0.
        let bitmap = [0x00, 0x07, 0x62, 0, 0, 0, 0, 0x03, 0x80];
        let mut rdata = vec![1u8, 0, 0, 0, 0, 20];
        rdata.extend_from_slice(&[0xab; 20]);
        rdata.extend_from_slice(&bitmap);
        let data = single_answer(TYPE_NSEC3, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            types_of(&b, rr),
            vec![
                FieldValue::U16(1),
                FieldValue::U16(2),
                FieldValue::U16(6),
                FieldValue::U16(46),
                FieldValue::U16(47),
                FieldValue::U16(48)
            ]
        );
    }

    #[test]
    fn malformed_type_bitmaps_have_no_type_list() {
        // Bitmap length 0, length > 32, truncated, and decreasing windows.
        let cases: [&[u8]; 4] = [
            &[0x00, 0x00],
            &[0x00, 0x21],
            &[0x00, 0x02, 0x40],
            &[0x01, 0x01, 0x40, 0x00, 0x01, 0x40],
        ];
        for bm in cases {
            let mut rdata = wire_name("n.example");
            rdata.extend_from_slice(bm);
            let data = single_answer(TYPE_NSEC, &rdata);
            let b = dissect(&data);
            let rr = first_rr(&b, "answers");
            assert!(has_child(&b, rr, "rdata_type_bitmaps"), "{bm:?}");
            assert!(!has_child(&b, rr, "rdata_types"), "{bm:?}");
        }
    }

    // ---- Additional RR types ----------------------------------------------

    #[test]
    fn parse_tsig_record() {
        // RFC 8945 §4.2
        let mut rdata = wire_name("hmac-sha256");
        let name_len = rdata.len();
        rdata.extend_from_slice(&[0x00, 0x00, 0x5f, 0x5e, 0x10, 0x00]); // time signed
        rdata.extend_from_slice(&300u16.to_be_bytes()); // fudge
        rdata.extend_from_slice(&4u16.to_be_bytes()); // mac size
        rdata.extend_from_slice(&[0xaa; 4]); // mac
        rdata.extend_from_slice(&0x1234u16.to_be_bytes()); // original id
        rdata.extend_from_slice(&16u16.to_be_bytes()); // error BADSIG
        rdata.extend_from_slice(&6u16.to_be_bytes()); // other len
        rdata.extend_from_slice(&[0, 0, 0x5f, 0x5e, 0x10, 0x01]); // other data
        let data = single_answer(TYPE_TSIG, &rdata);
        let rdata_abs = data.len() - rdata.len();
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let alg = child(&b, rr, "rdata_algorithm_name");
        assert_eq!(alg.value, FieldValue::Bytes(&rdata[..name_len]));
        assert_eq!(alg.range, rdata_abs..rdata_abs + name_len);
        assert_eq!(
            child(&b, rr, "rdata_time_signed").value,
            FieldValue::U64(0x5f5e_1000)
        );
        assert_eq!(child(&b, rr, "rdata_fudge").value, FieldValue::U16(300));
        assert_eq!(child(&b, rr, "rdata_mac_size").value, FieldValue::U16(4));
        assert_eq!(
            child(&b, rr, "rdata_mac").value,
            FieldValue::Bytes(&[0xaa; 4])
        );
        assert_eq!(
            child(&b, rr, "rdata_original_id").value,
            FieldValue::U16(0x1234)
        );
        let err = child(&b, rr, "rdata_error");
        assert_eq!(err.value, FieldValue::U16(16));
        assert_eq!(
            (err.descriptor.display_fn.unwrap())(&err.value, &[]),
            Some("BADSIG")
        );
        assert_eq!(
            child(&b, rr, "rdata_other_length").value,
            FieldValue::U16(6)
        );
        assert_eq!(
            child(&b, rr, "rdata_other_data").value,
            FieldValue::Bytes(&[0, 0, 0x5f, 0x5e, 0x10, 0x01])
        );

        // Truncated MAC → raw rdata.
        let mut short = rdata.clone();
        short.truncate(name_len + 12);
        let data = single_answer(TYPE_TSIG, &short);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert!(has_child(&b, rr, "rdata"));
        assert!(!has_child(&b, rr, "rdata_mac"));

        // RFC 8945 §4.2: a compressed Algorithm Name is malformed → raw.
        let mut compressed = vec![0xc0, 0x0c];
        compressed.extend_from_slice(&rdata[name_len..]);
        let data = single_answer(TYPE_TSIG, &compressed);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert!(has_child(&b, rr, "rdata"));
        assert!(!has_child(&b, rr, "rdata_algorithm_name"));
    }

    #[test]
    fn parse_tkey_record() {
        // RFC 2930 §2
        let mut rdata = wire_name("gss-tsig");
        rdata.extend_from_slice(&1u32.to_be_bytes()); // inception
        rdata.extend_from_slice(&2u32.to_be_bytes()); // expiration
        rdata.extend_from_slice(&3u16.to_be_bytes()); // mode
        rdata.extend_from_slice(&0u16.to_be_bytes()); // error
        rdata.extend_from_slice(&2u16.to_be_bytes()); // key size
        rdata.extend_from_slice(&[0xde, 0xad]);
        rdata.extend_from_slice(&0u16.to_be_bytes()); // other size
        let data = single_answer(TYPE_TKEY, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata_inception").value, FieldValue::U32(1));
        assert_eq!(child(&b, rr, "rdata_expiration").value, FieldValue::U32(2));
        assert_eq!(child(&b, rr, "rdata_mode").value, FieldValue::U16(3));
        assert_eq!(child(&b, rr, "rdata_error").value, FieldValue::U16(0));
        assert_eq!(child(&b, rr, "rdata_key_size").value, FieldValue::U16(2));
        assert_eq!(
            child(&b, rr, "rdata_key_data").value,
            FieldValue::Bytes(&[0xde, 0xad])
        );
        assert_eq!(
            child(&b, rr, "rdata_other_length").value,
            FieldValue::U16(0)
        );
        assert_eq!(
            child(&b, rr, "rdata_other_data").value,
            FieldValue::Bytes(&[])
        );

        // Trailing octet after Other Data → raw rdata.
        let mut bad = rdata.clone();
        bad.push(0);
        let data = single_answer(TYPE_TKEY, &bad);
        let b = dissect(&data);
        assert!(has_child(&b, first_rr(&b, "answers"), "rdata"));
    }

    #[test]
    fn parse_zonemd_csync_uri_records() {
        // ZONEMD (RFC 8976 §2.2)
        let mut rdata = 2018031500u32.to_be_bytes().to_vec();
        rdata.extend_from_slice(&[1, 1]);
        rdata.extend_from_slice(&[0x55; 48]);
        let data = single_answer(TYPE_ZONEMD, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            child(&b, rr, "rdata_serial").value,
            FieldValue::U32(2018031500)
        );
        assert_eq!(child(&b, rr, "rdata_scheme").value, FieldValue::U8(1));
        assert_eq!(
            child(&b, rr, "rdata_hash_algorithm").value,
            FieldValue::U8(1)
        );
        assert_eq!(
            child(&b, rr, "rdata_digest").value,
            FieldValue::Bytes(&[0x55; 48])
        );

        // CSYNC (RFC 7477 §2.1.1): serial, flags, type bitmap (A NS AAAA).
        let mut rdata = 66u32.to_be_bytes().to_vec();
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[0x00, 0x04, 0x60, 0x00, 0x00, 0x08]);
        let data = single_answer(TYPE_CSYNC, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata_serial").value, FieldValue::U32(66));
        assert_eq!(child(&b, rr, "rdata_flags").value, FieldValue::U16(3));
        assert_eq!(
            types_of(&b, rr),
            vec![FieldValue::U16(1), FieldValue::U16(2), FieldValue::U16(28)]
        );

        // URI (RFC 7553 §4.5)
        let mut rdata = vec![0, 10, 0, 1];
        rdata.extend_from_slice(b"ftp://ftp1.example.com/public");
        let data = single_answer(TYPE_URI, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata_priority").value, FieldValue::U16(10));
        assert_eq!(child(&b, rr, "rdata_weight").value, FieldValue::U16(1));
        assert_eq!(
            child(&b, rr, "rdata_uri").value,
            FieldValue::Bytes(b"ftp://ftp1.example.com/public")
        );
        // Empty target is malformed.
        let data = single_answer(TYPE_URI, &[0, 10, 0, 1]);
        let b = dissect(&data);
        assert!(has_child(&b, first_rr(&b, "answers"), "rdata"));
    }

    #[test]
    fn parse_hinfo_loc_records() {
        // HINFO (RFC 1035 §3.3.2; RFC 8482 §4.2 "RFC8482")
        let rdata = [7, b'R', b'F', b'C', b'8', b'4', b'8', b'2', 0];
        let data = single_answer(TYPE_HINFO, &rdata);
        let rdata_abs = data.len() - rdata.len();
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        let cpu = child(&b, rr, "rdata_cpu");
        assert_eq!(cpu.value, FieldValue::Bytes(b"RFC8482"));
        assert_eq!(cpu.range, rdata_abs + 1..rdata_abs + 8);
        assert_eq!(child(&b, rr, "rdata_os").value, FieldValue::Bytes(b""));
        // Trailing octet → raw.
        let data = single_answer(TYPE_HINFO, &[1, b'a', 1, b'b', 0]);
        let b = dissect(&data);
        assert!(has_child(&b, first_rr(&b, "answers"), "rdata"));

        // LOC (RFC 1876 §2), version 0.
        let mut rdata = vec![0, 0x12, 0x16, 0x13];
        rdata.extend_from_slice(&0x8b0d_2c2cu32.to_be_bytes());
        rdata.extend_from_slice(&0x7f8c_9a8cu32.to_be_bytes());
        rdata.extend_from_slice(&0x0098_9680u32.to_be_bytes());
        let data = single_answer(TYPE_LOC, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata_version").value, FieldValue::U8(0));
        assert_eq!(child(&b, rr, "rdata_size").value, FieldValue::U8(0x12));
        assert_eq!(
            child(&b, rr, "rdata_horizontal_precision").value,
            FieldValue::U8(0x16)
        );
        assert_eq!(
            child(&b, rr, "rdata_vertical_precision").value,
            FieldValue::U8(0x13)
        );
        assert_eq!(
            child(&b, rr, "rdata_latitude").value,
            FieldValue::U32(0x8b0d_2c2c)
        );
        assert_eq!(
            child(&b, rr, "rdata_longitude").value,
            FieldValue::U32(0x7f8c_9a8c)
        );
        assert_eq!(
            child(&b, rr, "rdata_altitude").value,
            FieldValue::U32(0x0098_9680)
        );
        // Unknown version → raw.
        rdata[0] = 1;
        let data = single_answer(TYPE_LOC, &rdata);
        let b = dissect(&data);
        assert!(has_child(&b, first_rr(&b, "answers"), "rdata"));
    }

    #[test]
    fn parse_ipseckey_record_gateway_types() {
        // RFC 4025 §2.1: precedence, gateway type, algorithm, gateway, key.
        let key = [0x01, 0x03, 0x51, 0x53];
        let mut rdata = vec![10, 1, 2, 192, 0, 2, 38];
        rdata.extend_from_slice(&key);
        let data = single_answer(TYPE_IPSECKEY, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata_precedence").value, FieldValue::U8(10));
        assert_eq!(child(&b, rr, "rdata_gateway_type").value, FieldValue::U8(1));
        assert_eq!(child(&b, rr, "rdata_algorithm").value, FieldValue::U8(2));
        assert_eq!(
            child(&b, rr, "rdata_gateway_ipv4").value,
            FieldValue::Ipv4Addr([192, 0, 2, 38])
        );
        assert_eq!(
            child(&b, rr, "rdata_public_key").value,
            FieldValue::Bytes(&key)
        );

        // No gateway.
        let data = single_answer(TYPE_IPSECKEY, &[10, 0, 2, 0xaa]);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert!(!has_child(&b, rr, "rdata_gateway_ipv4"));
        assert_eq!(
            child(&b, rr, "rdata_public_key").value,
            FieldValue::Bytes(&[0xaa])
        );

        // IPv6 gateway.
        let mut rdata = vec![10, 2, 2];
        rdata.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = single_answer(TYPE_IPSECKEY, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert!(matches!(
            child(&b, rr, "rdata_gateway_ipv6").value,
            FieldValue::Ipv6Addr(_)
        ));

        // Domain-name gateway.
        let gw = wire_name("gw.example");
        let mut rdata = vec![10, 3, 2];
        rdata.extend_from_slice(&gw);
        rdata.push(0xbb);
        let data = single_answer(TYPE_IPSECKEY, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            child(&b, rr, "rdata_gateway_name").value,
            FieldValue::Bytes(&gw)
        );
        assert_eq!(
            child(&b, rr, "rdata_public_key").value,
            FieldValue::Bytes(&[0xbb])
        );

        // Unknown gateway type / short IPv4 gateway → raw.
        for bad in [&[10u8, 4, 2, 0][..], &[10, 1, 2, 192, 0][..]] {
            let data = single_answer(TYPE_IPSECKEY, bad);
            let b = dissect(&data);
            assert!(has_child(&b, first_rr(&b, "answers"), "rdata"), "{bad:?}");
        }
    }

    #[test]
    fn parse_cert_dhcid_openpgpkey_eui_records() {
        // CERT (RFC 4398 §2)
        let mut rdata = 1u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&12345u16.to_be_bytes());
        rdata.push(8);
        rdata.extend_from_slice(&[0x30, 0x82]);
        let data = single_answer(TYPE_CERT, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata_cert_type").value, FieldValue::U16(1));
        assert_eq!(child(&b, rr, "rdata_key_tag").value, FieldValue::U16(12345));
        assert_eq!(child(&b, rr, "rdata_algorithm").value, FieldValue::U8(8));
        assert_eq!(
            child(&b, rr, "rdata_certificate").value,
            FieldValue::Bytes(&[0x30, 0x82])
        );

        // DHCID (RFC 4701 §3.1)
        let mut rdata = 2u16.to_be_bytes().to_vec();
        rdata.push(1);
        rdata.extend_from_slice(&[0x77; 32]);
        let data = single_answer(TYPE_DHCID, &rdata);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            child(&b, rr, "rdata_identifier_type").value,
            FieldValue::U16(2)
        );
        assert_eq!(child(&b, rr, "rdata_digest_type").value, FieldValue::U8(1));
        assert_eq!(
            child(&b, rr, "rdata_digest").value,
            FieldValue::Bytes(&[0x77; 32])
        );

        // OPENPGPKEY (RFC 7929 §2.1)
        let data = single_answer(TYPE_OPENPGPKEY, &[0x99, 0x01]);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            child(&b, rr, "rdata_public_key").value,
            FieldValue::Bytes(&[0x99, 0x01])
        );

        // EUI48 / EUI64 (RFC 7043 §3.1, §4.1)
        let data = single_answer(TYPE_EUI48, &[0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a]);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(
            child(&b, rr, "rdata").value,
            FieldValue::MacAddr(packet_dissector_core::field::MacAddr([
                0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a
            ]))
        );
        let eui64 = [0x00, 0x00, 0x5e, 0xef, 0x10, 0x00, 0x00, 0x2a];
        let data = single_answer(TYPE_EUI64, &eui64);
        let b = dissect(&data);
        let rr = first_rr(&b, "answers");
        assert_eq!(child(&b, rr, "rdata").value, FieldValue::Bytes(&eui64));
        // Wrong length → raw.
        let data = single_answer(TYPE_EUI48, &[0; 5]);
        let b = dissect(&data);
        assert!(has_child(&b, first_rr(&b, "answers"), "rdata"));
    }

    // ---- RFC 8490 §5.4 — DSO messages --------------------------------------

    #[test]
    fn dso_message_tlvs() {
        // Opcode 6, all counts zero, Keepalive TLV (type 1, length 8), over TCP.
        let mut msg = header(0, 0, 0, 0);
        msg[2..4].copy_from_slice(&(6u16 << 11).to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x08]);
        msg.extend_from_slice(&15000u32.to_be_bytes());
        msg.extend_from_slice(&3600000u32.to_be_bytes());
        let mut data = (msg.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&msg);
        let mut b = DissectBuffer::new();
        let res = DnsTcpDissector.dissect(&data, &mut b, 0).unwrap();
        assert_eq!(res.bytes_consumed, data.len());
        let layer = &b.layers()[0];
        assert_eq!(layer.range, 0..data.len());
        let tlvs = b.field_by_name(layer, "dso_tlvs").unwrap();
        let tlv = direct_children(&b, tlvs)[0];
        let t = child(&b, tlv, "type");
        assert_eq!(t.value, FieldValue::U16(1));
        assert_eq!(
            (t.descriptor.display_fn.unwrap())(&t.value, &[]),
            Some("KeepAlive")
        );
        assert_eq!(child(&b, tlv, "length").value, FieldValue::U16(8));
        assert_eq!(
            child(&b, tlv, "data").value,
            FieldValue::Bytes(&data[18..26])
        );
        assert_eq!(child(&b, tlv, "data").range, 18..26);

        // A TLV overrunning the length-delimited message is malformed.
        let mut bad = msg.clone();
        bad.truncate(20);
        let mut data = (bad.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&bad);
        let mut b = DissectBuffer::new();
        assert!(DnsTcpDissector.dissect(&data, &mut b, 0).is_err());

        // RFC 8490 §4.2: DSO is not defined over UDP, so the DNS (UDP)
        // dissector does not parse DSO Data (and does not fail on it).
        let mut b = DissectBuffer::new();
        let res = DnsDissector.dissect(&bad, &mut b, 0).unwrap();
        assert_eq!(res.bytes_consumed, 12);
        assert!(b.field_by_name(&b.layers()[0], "dso_tlvs").is_none());
    }
}
