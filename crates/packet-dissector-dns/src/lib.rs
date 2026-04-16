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

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32};

/// DNS header size (fixed 12 bytes).
const HEADER_SIZE: usize = 12;

/// Returns a human-readable name for DNS QTYPE / TYPE values.
///
/// RFC 1035, Section 3.2.2; RFC 3596 (AAAA); RFC 2782 (SRV); RFC 6891 (OPT); RFC 9460 (HTTPS).
pub fn dns_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("A"),
        2 => Some("NS"),
        5 => Some("CNAME"),
        6 => Some("SOA"),
        12 => Some("PTR"),
        15 => Some("MX"),
        16 => Some("TXT"),
        28 => Some("AAAA"),
        29 => Some("LOC"),
        33 => Some("SRV"),
        35 => Some("NAPTR"),
        41 => Some("OPT"),
        43 => Some("DS"),
        46 => Some("RRSIG"),
        47 => Some("NSEC"),
        48 => Some("DNSKEY"),
        50 => Some("NSEC3"),
        52 => Some("TLSA"),
        65 => Some("HTTPS"),
        255 => Some("ANY"),
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
/// RFC 1035, Section 4.1.1; RFC 1996 (NOTIFY); RFC 2136 (UPDATE).
fn dns_opcode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("QUERY"),
        1 => Some("IQUERY"),
        2 => Some("STATUS"),
        4 => Some("NOTIFY"),
        5 => Some("UPDATE"),
        _ => None,
    }
}

/// Returns a human-readable name for DNS RCODE values.
///
/// RFC 1035, Section 4.1.1.
pub fn dns_rcode_name(v: u8) -> Option<&'static str> {
    match v {
        0 => Some("NOERROR"),
        1 => Some("FORMERR"),
        2 => Some("SERVFAIL"),
        3 => Some("NXDOMAIN"),
        4 => Some("NOTIMP"),
        5 => Some("REFUSED"),
        _ => None,
    }
}

/// Maximum pointer follow depth to prevent infinite loops.
const MAX_POINTER_DEPTH: usize = 128;
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

// -- Field descriptor index constants for QUESTION_CHILD_FIELDS --
const QFD_NAME: usize = 0;
const QFD_TYPE: usize = 1;
const QFD_CLASS: usize = 2;
// NOTE: type/class have display_fn for dns_type_name/dns_class_name; no separate _name fields.

// -- Field descriptor index constants for EDNS_OPTION_CHILD_FIELDS --
const EOFD_CODE: usize = 0;
const EOFD_LENGTH: usize = 1;
const EOFD_DATA: usize = 2;
const EOFD_TIMEOUT: usize = 3;
// NOTE: code has display_fn for edns_option_code_name; no separate code_name field.

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
            if let Ok(consumed) = parse_name(msg, rdata_offset) {
                let _ = consumed;
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA],
                    FieldValue::Bytes(&msg[rdata_offset..rdata_offset + rdata.len()]),
                    rdata_range,
                );
                return;
            }
        }
        // RFC 1035, Section 3.3.9 — MX: preference (U16) + exchange (domain name)
        TYPE_MX if rdata.len() >= 3 => {
            let preference = read_be_u16(rdata, 0).unwrap_or_default();
            if parse_name(msg, rdata_offset + 2).is_ok() {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PREFERENCE],
                    FieldValue::U16(preference),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_EXCHANGE],
                    FieldValue::Bytes(&msg[rdata_offset + 2..rdata_offset + rdata.len()]),
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
            if let Ok(mname_len) = parse_name(msg, rdata_offset) {
                let rname_off = rdata_offset + mname_len;
                if let Ok(rname_len) = parse_name(msg, rname_off) {
                    let timers_off = mname_len + rname_len;
                    if timers_off + 20 <= rdata.len() {
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
                            FieldValue::Bytes(&msg[rdata_offset..rdata_offset + mname_len]),
                            abs_offset..mname_end,
                        );
                        buf.push_field(
                            &RR_CHILD_FIELDS[RRFD_RDATA_RNAME],
                            FieldValue::Bytes(&msg[rname_off..rname_off + rname_len]),
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
            if parse_name(msg, rdata_offset + 6).is_ok() {
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
                    FieldValue::Bytes(&msg[rdata_offset + 6..rdata_offset + rdata.len()]),
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
            if n == 3 && parse_name(msg, rdata_offset + pos).is_ok() {
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
                    FieldValue::Bytes(&msg[rdata_offset + pos..rdata_offset + rdata.len()]),
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
            if let Ok(signer_name_len) = parse_name(msg, rdata_offset + 18) {
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
                    FieldValue::Bytes(&msg[rdata_offset + 18..rdata_offset + sig_start]),
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
            if let Ok(name_len) = parse_name(msg, rdata_offset) {
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_NEXT_DOMAIN_NAME],
                    FieldValue::Bytes(&msg[rdata_offset..rdata_offset + name_len]),
                    abs_offset..abs_offset + name_len,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TYPE_BITMAPS],
                    FieldValue::Bytes(&rdata[name_len..]),
                    abs_offset + name_len..abs_offset + rdata.len(),
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
            if let Ok(target_len) = parse_name(msg, rdata_offset + 2) {
                let params_start = 2 + target_len;
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_PRIORITY],
                    FieldValue::U16(priority),
                    abs_offset..abs_offset + 2,
                );
                buf.push_field(
                    &RR_CHILD_FIELDS[RRFD_RDATA_TARGET],
                    FieldValue::Bytes(&msg[rdata_offset + 2..rdata_offset + params_start]),
                    abs_offset + 2..abs_offset + params_start,
                );
                if params_start <= rdata.len() {
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_RDATA_PARAMS],
                        FieldValue::Bytes(&rdata[params_start..]),
                        abs_offset + params_start..abs_offset + rdata.len(),
                    );
                }
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
        _ => {}
    }

    // Fallback: raw bytes for unknown or malformed rdata
    buf.push_field(
        &RR_CHILD_FIELDS[RRFD_RDATA],
        FieldValue::Bytes(rdata),
        rdata_range,
    );
}

/// EDNS0 option code for TCP Keepalive.
///
/// RFC 7828, Section 3 — <https://www.rfc-editor.org/rfc/rfc7828#section-3>
const EDNS_OPT_TCP_KEEPALIVE: u16 = 11;

/// Returns a human-readable name for EDNS0 option codes.
///
/// RFC 6891, Section 6.1.2 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2>
fn edns_option_code_name(code: u16) -> Option<&'static str> {
    match code {
        3 => Some("NSID"),
        8 => Some("CLIENT-SUBNET"),
        10 => Some("COOKIE"),
        EDNS_OPT_TCP_KEEPALIVE => Some("TCP-KEEPALIVE"),
        15 => Some("EXTENDED-DNS-ERROR"),
        _ => None,
    }
}

/// Parse EDNS0 options from OPT RDATA.
///
/// Each option is: code(2) + length(2) + data(length).
///
/// Known options are decoded with structured sub-fields:
/// - TCP Keepalive (code 11): RFC 7828 — <https://www.rfc-editor.org/rfc/rfc7828>
fn parse_edns_options<'pkt>(buf: &mut DissectBuffer<'pkt>, rdata: &'pkt [u8], abs_offset: usize) {
    let mut pos = 0;
    while pos + 4 <= rdata.len() {
        let code = read_be_u16(rdata, pos).unwrap_or_default();
        let length = read_be_u16(rdata, pos + 2).unwrap_or_default() as usize;
        if pos + 4 + length > rdata.len() {
            break;
        }
        let option_data = &rdata[pos + 4..pos + 4 + length];
        let option_start = abs_offset + pos;
        let option_end = option_start + 4 + length;

        let obj_idx = buf.begin_container(
            &EDNS_OPTION_CHILD_FIELDS[EOFD_CODE],
            FieldValue::Object(0..0),
            option_start..option_end,
        );

        buf.push_field(
            &EDNS_OPTION_CHILD_FIELDS[EOFD_CODE],
            FieldValue::U16(code),
            option_start..option_start + 2,
        );
        buf.push_field(
            &EDNS_OPTION_CHILD_FIELDS[EOFD_LENGTH],
            FieldValue::U16(length as u16),
            option_start + 2..option_start + 4,
        );

        // RFC 7828, Section 3 — edns-tcp-keepalive option
        // <https://www.rfc-editor.org/rfc/rfc7828#section-3>
        // Format: optional 2-byte timeout in units of 100 milliseconds.
        // Length is 0 (query, no timeout) or 2 (response, with timeout).
        if code == EDNS_OPT_TCP_KEEPALIVE && length == 2 {
            let timeout = read_be_u16(option_data, 0).unwrap_or_default();
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_TIMEOUT],
                FieldValue::U16(timeout),
                option_start + 4..option_end,
            );
        } else if code == EDNS_OPT_TCP_KEEPALIVE && length == 0 {
            // Query form: no timeout field, no data to emit.
        } else {
            buf.push_field(
                &EDNS_OPTION_CHILD_FIELDS[EOFD_DATA],
                FieldValue::Bytes(option_data),
                option_start + 4..option_end,
            );
        }

        buf.end_container(obj_idx);
        pos += 4 + length;
    }
}

/// Child field descriptors for EDNS0 option entries.
///
/// RFC 6891, Section 6.1.2 — <https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2>
/// RFC 7828 (TCP Keepalive option) — <https://www.rfc-editor.org/rfc/rfc7828>
static EDNS_OPTION_CHILD_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor {
        name: "code",
        display_name: "Code",
        field_type: FieldType::U16,
        optional: false,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U16(c) => edns_option_code_name(*c),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    // RFC 7828, Section 3 — TCP Keepalive timeout (in 100ms units).
    FieldDescriptor::new("timeout", "Timeout", FieldType::U16).optional(),
];

/// Child field descriptors for question section entries.
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
];

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
            self.short_name(),
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
            let qclass = read_be_u16(data, pos + 2)?;

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
                let rclass = read_be_u16(data, pos + 2)?;
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

                // RFC 6891 — OPT pseudo-record has different field semantics
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
                        FieldValue::U16(rclass),
                        offset + pos + 2..offset + pos + 4,
                    );
                    buf.push_field(
                        &RR_CHILD_FIELDS[RRFD_EXTENDED_RCODE],
                        FieldValue::U8(extended_rcode),
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

        // Update layer range to actual consumed bytes
        if let Some(layer) = buf.last_layer_mut() {
            layer.range = offset..offset + pos;
        }
        buf.end_layer();

        Ok(DissectResult::new(pos, DispatchHint::End))
    }
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

    let result = DnsDissector.dissect(&msg_data[2..2 + msg_len], buf, offset + 2)?;

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
    // | RFC 3596               | AAAA record                         | parse_aaaa_record                 |
    // | RFC 2782               | SRV record                          | parse_srv_record                  |
    // | RFC 3403               | NAPTR record                        | parse_naptr_record                |
    // | RFC 3403               | NAPTR parsing is zero-allocation    | naptr_dissect_zero_alloc          |
    // | RFC 4035 §3.1.6        | AD / CD flag bit positions          | parse_header_flags                |
    // | RFC 4034 §2.1          | DNSKEY record                       | parse_dnskey_record               |
    // | RFC 4034 §3.1          | RRSIG record                        | parse_rrsig_record                |
    // | RFC 4034 §4.1          | NSEC record                         | parse_nsec_record                 |
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
}
