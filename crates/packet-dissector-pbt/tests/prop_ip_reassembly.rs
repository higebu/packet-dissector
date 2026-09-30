//! IP fragment reassembly property-based tests (registry middleware).
//!
//! # RFC 791 / RFC 8200 (fragment reassembly) Coverage
//!
//! | RFC Section  | Description                                              | Test                                |
//! |--------------|----------------------------------------------------------|-------------------------------------|
//! | RFC 791 3.2  | Shuffled IPv4 fragments dissect like the whole datagram  | ipv4_shuffled_fragments_reassemble  |
//! | RFC 8200 4.5 | Shuffled IPv6 fragments dissect like the whole packet    | ipv6_shuffled_fragments_reassemble  |
//!
//! References:
//! - RFC 791, Section 3.2 — <https://www.rfc-editor.org/rfc/rfc791#section-3.2>
//! - RFC 8200, Section 4.5 — <https://www.rfc-editor.org/rfc/rfc8200#section-4.5>

use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;
use packet_dissector::registry::DissectorRegistry;
use proptest::prelude::*;

/// Ethernet header followed by `ethertype`.
fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut p = vec![
        0, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    p.extend_from_slice(&ethertype.to_be_bytes());
    p
}

/// Ethernet + IPv4 (RFC 791, Section 3.1) with UDP as the protocol.
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
fn ipv4(mf: bool, offset: usize, data: &[u8]) -> Vec<u8> {
    let mut p = ethernet(0x0800);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&((20 + data.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x12, 0x34]);
    p.extend_from_slice(&((u16::from(mf) << 13) | (offset / 8) as u16).to_be_bytes());
    p.extend_from_slice(&[64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    p.extend_from_slice(data);
    p
}

/// Ethernet + IPv6 (RFC 8200, Section 3), with a Fragment header
/// (Section 4.5) when `fragment` is `Some((m, offset))`.
/// <https://www.rfc-editor.org/rfc/rfc8200#section-3>
fn ipv6(fragment: Option<(bool, usize)>, data: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    let next = match fragment {
        Some((m, offset)) => {
            ext.extend_from_slice(&[17, 0]);
            ext.extend_from_slice(&(((offset / 8) as u16) << 3 | u16::from(m)).to_be_bytes());
            ext.extend_from_slice(&0xcafe_f00du32.to_be_bytes());
            44
        }
        None => 17,
    };
    let mut p = ethernet(0x86dd);
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&((ext.len() + data.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[next, 64]);
    p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    p.extend_from_slice(&ext);
    p.extend_from_slice(data);
    p
}

/// One fragment of a datagram: (offset in bytes, more fragments, data range).
type Fragment = (usize, bool, std::ops::Range<usize>);

/// A UDP datagram to port 53 carrying arbitrary bytes, split at 8-octet
/// boundaries into shuffled fragments.
fn arb_fragmented_datagram() -> impl Strategy<Value = (Vec<u8>, Vec<Fragment>)> {
    (
        prop::collection::vec(any::<u8>(), 0..600),
        prop::collection::vec(1usize..32, 1..8),
    )
        .prop_flat_map(|(payload, blocks)| {
            let mut datagram = Vec::new();
            datagram.extend_from_slice(&40000u16.to_be_bytes());
            datagram.extend_from_slice(&53u16.to_be_bytes());
            datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            datagram.extend_from_slice(&[0, 0]);
            datagram.extend_from_slice(&payload);
            let mut frags = Vec::new();
            let mut pos = 0;
            for b in blocks {
                let end = pos + b * 8;
                if end >= datagram.len() {
                    break;
                }
                frags.push((pos, true, pos..end));
                pos = end;
            }
            frags.push((pos, false, pos..datagram.len()));
            (Just(datagram), Just(frags).prop_shuffle())
        })
}

/// Upper-layer names and values after the IP layers, container indices
/// reduced to their kind.
fn upper(buf: &DissectBuffer<'_>, ip_layers: usize) -> Vec<String> {
    let mut out = Vec::new();
    for layer in buf.layers().iter().skip(ip_layers + 1) {
        out.push(layer.name.to_string());
        for field in buf.layer_fields(layer) {
            let value = match field.value {
                FieldValue::Array(_) => "Array".to_string(),
                FieldValue::Object(_) => "Object".to_string(),
                ref v => format!("{v:?}"),
            };
            out.push(format!("{}={value}", field.name()));
        }
    }
    out
}

/// Feed `fragments` in order to a fresh registry: every packet but the last
/// ends after its `ip_layers` IP layers, and the last one dissects like
/// `whole`.
fn check(fragments: &[Vec<u8>], whole: &[u8], ip_layers: usize) -> Result<(), TestCaseError> {
    let reg = DissectorRegistry::default();
    let (last, rest) = fragments.split_last().expect("at least one fragment");
    for packet in rest {
        let mut buf = DissectBuffer::new();
        prop_assert!(reg.dissect(packet, &mut buf).is_ok());
        prop_assert_eq!(buf.layers().len(), 1 + ip_layers);
    }
    let mut buf = DissectBuffer::new();
    let result = reg.dissect(last, &mut buf).map(|_| ());
    let mut ref_buf = DissectBuffer::new();
    let ref_result = DissectorRegistry::default()
        .dissect(whole, &mut ref_buf)
        .map(|_| ());
    prop_assert_eq!(result, ref_result);
    prop_assert_eq!(upper(&buf, ip_layers), upper(&ref_buf, 1));
    Ok(())
}

proptest! {
    /// Fragments of an IPv4 datagram arriving in any order dissect, once
    /// complete, exactly like the unfragmented datagram (RFC 791,
    /// Section 3.2).
    #[test]
    fn ipv4_shuffled_fragments_reassemble((datagram, frags) in arb_fragmented_datagram()) {
        prop_assume!(frags.len() > 1);
        let packets: Vec<_> = frags
            .iter()
            .map(|(offset, more, range)| ipv4(*more, *offset, &datagram[range.clone()]))
            .collect();
        check(&packets, &ipv4(false, 0, &datagram), 1)?;
    }

    /// Fragments of an IPv6 packet arriving in any order dissect, once
    /// complete, exactly like the unfragmented packet (RFC 8200,
    /// Section 4.5).
    #[test]
    fn ipv6_shuffled_fragments_reassemble((datagram, frags) in arb_fragmented_datagram()) {
        prop_assume!(frags.len() > 1);
        let packets: Vec<_> = frags
            .iter()
            .map(|(offset, more, range)| ipv6(Some((*more, *offset)), &datagram[range.clone()]))
            .collect();
        check(&packets, &ipv6(None, &datagram), 2)?;
    }
}
