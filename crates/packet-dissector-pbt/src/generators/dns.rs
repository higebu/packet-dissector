//! DNS message strategies.
//!
//! ## References
//! - RFC 1035, Section 4.1 — Message format: <https://www.rfc-editor.org/rfc/rfc1035#section-4.1>
//! - RFC 1035, Section 3.2.1 — RR format: <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>
//! - RFC 1035, Section 4.1.4 — Message compression: <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4>

use proptest::prelude::*;

/// RR TYPE values whose RDATA the DNS dissector decodes into typed fields,
/// each paired with the length of the fixed part that precedes the first
/// embedded domain name (or `0` when RDATA carries no name). An unassigned
/// TYPE exercises the raw-bytes fallback.
const RR_TYPES: &[(u16, usize)] = &[
    (1, 0),   // A (RFC 1035)
    (2, 0),   // NS (RFC 1035)
    (5, 0),   // CNAME (RFC 1035)
    (6, 0),   // SOA (RFC 1035): MNAME, RNAME, then five 32-bit timers
    (12, 0),  // PTR (RFC 1035)
    (15, 2),  // MX (RFC 1035): PREFERENCE, EXCHANGE
    (16, 0),  // TXT (RFC 1035)
    (28, 0),  // AAAA (RFC 3596)
    (33, 6),  // SRV (RFC 2782): priority, weight, port, target
    (35, 4),  // NAPTR (RFC 3403): order, preference, then character-strings
    (39, 0),  // DNAME (RFC 6672)
    (41, 0),  // OPT (RFC 6891)
    (43, 0),  // DS (RFC 4034)
    (44, 0),  // SSHFP (RFC 4255)
    (46, 18), // RRSIG (RFC 4034): 18 fixed octets, then Signer's Name
    (47, 0),  // NSEC (RFC 4034): Next Domain Name, then type bitmaps
    (48, 0),  // DNSKEY (RFC 4034)
    (50, 0),  // NSEC3 (RFC 5155)
    (51, 0),  // NSEC3PARAM (RFC 5155)
    (52, 0),  // TLSA (RFC 6698)
    (59, 0),  // CDS (RFC 7344)
    (60, 0),  // CDNSKEY (RFC 7344)
    (64, 2),  // SVCB (RFC 9460): SvcPriority, TargetName
    (65, 2),  // HTTPS (RFC 9460): SvcPriority, TargetName
    (257, 0), // CAA (RFC 8659)
    (0xFF00, 0),
];

/// A domain name in wire format: up to three labels followed either by the
/// root label or by a compression pointer (RFC 1035, Sections 3.1 and 4.1.4).
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
/// `<character-string>` (RFC 1035, Section 3.3).
fn arb_rdata_atom() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..=8),
        arb_wire_name(),
        prop::collection::vec(any::<u8>(), 0..=8).prop_map(|s| {
            let mut out = vec![s.len() as u8];
            out.extend_from_slice(&s);
            out
        }),
    ]
}

/// Generate one resource record (RFC 1035, Section 3.2.1 —
/// <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>) of a TYPE the
/// dissector decodes.
///
/// RDATA starts with a prefix that is usually exactly the TYPE's fixed part
/// (so an embedded name lands where the dissector looks for it) and
/// otherwise `0..=20` arbitrary octets, followed by a domain name and up to
/// three atoms from [`arb_rdata_atom`]. RDLENGTH is either the exact RDATA
/// length or cut short, so names and character-strings can straddle the
/// RDATA boundary and run into whatever follows.
fn arb_rr() -> impl Strategy<Value = Vec<u8>> {
    prop::sample::select(RR_TYPES).prop_flat_map(|(rtype, fixed_len)| {
        (
            arb_wire_name(),
            any::<u16>(),
            any::<u32>(),
            prop_oneof![
                3 => prop::collection::vec(any::<u8>(), fixed_len),
                1 => prop::collection::vec(any::<u8>(), 0..=20),
            ],
            arb_wire_name(),
            prop::collection::vec(arb_rdata_atom(), 0..=3),
            prop::option::of(any::<prop::sample::Index>()),
        )
            .prop_map(move |(owner, class, ttl, prefix, name, atoms, cut)| {
                let mut rdata = prefix;
                rdata.extend_from_slice(&name);
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
            })
    })
}

prop_compose! {
    /// Generate a DNS message built from structured resource records
    /// (RFC 1035, Section 4.1 —
    /// <https://www.rfc-editor.org/rfc/rfc1035#section-4.1>).
    ///
    /// The header carries arbitrary ID and flags, QDCOUNT = 0, and splits the
    /// generated RRs between the answer and additional sections. The message
    /// may be malformed (see [`arb_rr`]); it is meant for no-panic checks,
    /// not for asserting successful parses.
    pub fn arb_dns_message()(
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
