//! DNS message strategies.
//!
//! ## References
//! - RFC 1035, Section 4.1 — Message format: <https://www.rfc-editor.org/rfc/rfc1035#section-4.1>
//! - RFC 1035, Section 3.2.1 — RR format: <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>
//! - RFC 1035, Section 3.3 — Standard RRs (NS, CNAME, SOA, PTR, MX, TXT): <https://www.rfc-editor.org/rfc/rfc1035#section-3.3>
//! - RFC 1035, Section 4.1.4 — Message compression: <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4>
//! - RFC 2782 — SRV: <https://www.rfc-editor.org/rfc/rfc2782>
//! - RFC 3403, Section 4.1 — NAPTR: <https://www.rfc-editor.org/rfc/rfc3403#section-4.1>
//! - RFC 3596 — AAAA: <https://www.rfc-editor.org/rfc/rfc3596>
//! - RFC 4034 — DNSKEY, RRSIG, NSEC, DS: <https://www.rfc-editor.org/rfc/rfc4034>
//! - RFC 4255 — SSHFP: <https://www.rfc-editor.org/rfc/rfc4255>
//! - RFC 5155 — NSEC3, NSEC3PARAM: <https://www.rfc-editor.org/rfc/rfc5155>
//! - RFC 6672 — DNAME: <https://www.rfc-editor.org/rfc/rfc6672>
//! - RFC 6698 — TLSA: <https://www.rfc-editor.org/rfc/rfc6698>
//! - RFC 6891 — OPT: <https://www.rfc-editor.org/rfc/rfc6891>
//! - RFC 7344 — CDS, CDNSKEY: <https://www.rfc-editor.org/rfc/rfc7344>
//! - RFC 8659 — CAA: <https://www.rfc-editor.org/rfc/rfc8659>
//! - RFC 9460 — SVCB, HTTPS: <https://www.rfc-editor.org/rfc/rfc9460>

use proptest::prelude::*;

/// Where the dissector expects the first embedded domain name in RDATA.
#[derive(Clone, Copy, Debug)]
enum Layout {
    /// A name (if any) follows this many fixed octets.
    NameAfter(usize),
    /// NAPTR: ORDER, PREFERENCE, three `<character-string>`s, REPLACEMENT.
    Naptr,
    /// SOA: MNAME, RNAME, then five 32-bit fields.
    Soa,
}

/// RR TYPE values whose RDATA the DNS dissector decodes into typed fields,
/// each with the RDATA layout that places the generated name where the
/// dissector reads one (see the module references for each TYPE's
/// specification). An unassigned TYPE exercises the raw-bytes fallback.
const RR_TYPES: &[(u16, Layout)] = &[
    (1, Layout::NameAfter(0)),   // A
    (2, Layout::NameAfter(0)),   // NS
    (5, Layout::NameAfter(0)),   // CNAME
    (6, Layout::Soa),            // SOA
    (12, Layout::NameAfter(0)),  // PTR
    (15, Layout::NameAfter(2)),  // MX: PREFERENCE, EXCHANGE
    (16, Layout::NameAfter(0)),  // TXT
    (28, Layout::NameAfter(0)),  // AAAA
    (33, Layout::NameAfter(6)),  // SRV: priority, weight, port, target
    (35, Layout::Naptr),         // NAPTR
    (39, Layout::NameAfter(0)),  // DNAME
    (41, Layout::NameAfter(0)),  // OPT
    (43, Layout::NameAfter(0)),  // DS
    (44, Layout::NameAfter(0)),  // SSHFP
    (46, Layout::NameAfter(18)), // RRSIG: 18 fixed octets, Signer's Name
    (47, Layout::NameAfter(0)),  // NSEC: Next Domain Name, type bitmaps
    (48, Layout::NameAfter(0)),  // DNSKEY
    (50, Layout::NameAfter(0)),  // NSEC3
    (51, Layout::NameAfter(0)),  // NSEC3PARAM
    (52, Layout::NameAfter(0)),  // TLSA
    (59, Layout::NameAfter(0)),  // CDS
    (60, Layout::NameAfter(0)),  // CDNSKEY
    (64, Layout::NameAfter(2)),  // SVCB: SvcPriority, TargetName
    (65, Layout::NameAfter(2)),  // HTTPS: SvcPriority, TargetName
    (257, Layout::NameAfter(0)), // CAA
    (0xFF00, Layout::NameAfter(0)),
];

/// Encode `s` as a `<character-string>` (length octet + octets).
fn char_string(s: &[u8]) -> Vec<u8> {
    let mut out = vec![s.len() as u8];
    out.extend_from_slice(s);
    out
}

/// A domain name in wire format: up to three labels followed either by the
/// root label or by a compression pointer (RFC 1035, Section 3.1 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.1>, and Section 4.1.4 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4>).
fn arb_wire_name() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=10), 0..=3),
        prop::option::of(0u8..=64),
    )
        .prop_map(|(labels, pointer)| {
            let mut out = Vec::new();
            for label in labels {
                out.push(label.len() as u8);
                out.extend_from_slice(&label);
            }
            match pointer {
                Some(offset) => out.extend_from_slice(&[0xC0, offset]),
                None => out.push(0),
            }
            out
        })
}

/// One building block of RDATA: raw octets, a domain name, or a
/// `<character-string>` (RFC 1035, Section 3.3 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.3>).
fn arb_rdata_atom() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..=8),
        arb_wire_name(),
        prop::collection::vec(any::<u8>(), 0..=8).prop_map(|s| char_string(&s)),
    ]
}

/// Generate one resource record (RFC 1035, Section 3.2.1 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>) of a TYPE the
/// dissector decodes.
///
/// RDATA usually follows the TYPE's [`Layout`], so the generated name lands
/// where the dissector looks for one: fixed octets, then the name (NAPTR
/// gets its three `<character-string>`s first; SOA gets a second name and
/// the five 32-bit fields after it). Otherwise the prefix is `0..=20`
/// arbitrary octets. Up to three atoms from [`arb_rdata_atom`] follow.
/// RDLENGTH is either the exact RDATA length or cut short, so names and
/// character-strings can straddle the RDATA boundary and run into whatever
/// follows.
fn arb_rr() -> impl Strategy<Value = Vec<u8>> {
    prop::sample::select(RR_TYPES).prop_flat_map(|(rtype, layout)| {
        let fixed_len = match layout {
            Layout::NameAfter(n) => n,
            Layout::Naptr => 4,
            Layout::Soa => 0,
        };
        (
            arb_wire_name(),
            any::<u16>(),
            any::<u32>(),
            prop_oneof![
                3 => prop::collection::vec(any::<u8>(), fixed_len).prop_map(|p| (p, true)),
                1 => prop::collection::vec(any::<u8>(), 0..=20).prop_map(|p| (p, false)),
            ],
            prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=4), 3),
            arb_wire_name(),
            arb_wire_name(),
            any::<[u8; 20]>(),
            prop::collection::vec(arb_rdata_atom(), 0..=3),
            prop::option::of(any::<prop::sample::Index>()),
        )
            .prop_map(
                move |(
                    owner,
                    class,
                    ttl,
                    (prefix, follows_layout),
                    strings,
                    name,
                    second_name,
                    soa_fields,
                    atoms,
                    cut,
                )| {
                    let mut rdata = prefix;
                    if follows_layout && matches!(layout, Layout::Naptr) {
                        for s in &strings {
                            rdata.extend_from_slice(&char_string(s));
                        }
                    }
                    rdata.extend_from_slice(&name);
                    if follows_layout && matches!(layout, Layout::Soa) {
                        rdata.extend_from_slice(&second_name);
                        rdata.extend_from_slice(&soa_fields);
                    }
                    for atom in atoms {
                        rdata.extend_from_slice(&atom);
                    }
                    let rdlength = match cut {
                        Some(index) => index.index(rdata.len() + 1),
                        None => rdata.len(),
                    };
                    let mut out = owner;
                    out.extend_from_slice(&rtype.to_be_bytes());
                    out.extend_from_slice(&class.to_be_bytes());
                    out.extend_from_slice(&ttl.to_be_bytes());
                    out.extend_from_slice(&(rdlength as u16).to_be_bytes());
                    out.extend_from_slice(&rdata);
                    out
                },
            )
    })
}

prop_compose! {
    /// Generate a DNS message, possibly malformed, built from structured
    /// resource records
    /// (RFC 1035, Section 4.1 —
    /// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1>).
    ///
    /// The header carries arbitrary ID and flags, QDCOUNT = 0, and splits the
    /// generated RRs between the answer and additional sections. The message
    /// may be malformed (see [`arb_rr`]); it is meant for no-panic checks,
    /// not for asserting successful parses.
    pub fn arb_malformed_dns_message()(
        id in any::<u16>(),
        flags in any::<u16>(),
        rrs in prop::collection::vec(arb_rr(), 0..=4),
        split in any::<prop::sample::Index>(),
    ) -> Vec<u8> {
        let ancount = split.index(rrs.len() + 1);
        let arcount = rrs.len() - ancount;
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&(ancount as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&(arcount as u16).to_be_bytes());
        for rr in rrs {
            out.extend_from_slice(&rr);
        }
        out
    }
}
