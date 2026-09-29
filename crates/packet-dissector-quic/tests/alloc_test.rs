//! Zero-allocation dissection tests for the QUIC dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_quic::QuicDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Encode a variable-length integer per RFC 9000, Section 16.
fn encode_varint(value: u64) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else if value <= 16383 {
        let v = (value as u16) | 0x4000;
        v.to_be_bytes().to_vec()
    } else {
        unreachable!("test helper: only small varints needed")
    }
}

/// Build a QUIC Initial packet with an empty token.
fn build_initial(dcid: &[u8], scid: &[u8], payload: &[u8]) -> Vec<u8> {
    let first_byte = 0xc0; // header_form=1, packet_type=0 (Initial)
    let mut pkt = vec![first_byte];
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version 1
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(scid);
    pkt.extend_from_slice(&encode_varint(0)); // token length = 0
    pkt.extend_from_slice(&encode_varint(payload.len() as u64)); // length
    pkt.extend_from_slice(payload);
    pkt
}

/// Build a QUIC Short Header packet.
fn build_short_header(payload: &[u8]) -> Vec<u8> {
    let first_byte = 0x40; // header_form=0, fixed_bit=1
    let mut pkt = vec![first_byte];
    pkt.extend_from_slice(payload);
    pkt
}

/// Build a QUIC Version Negotiation packet.
fn build_version_negotiation(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
    let first_byte = 0x80;
    let mut pkt = vec![first_byte];
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(scid);
    for &v in versions {
        pkt.extend_from_slice(&v.to_be_bytes());
    }
    pkt
}

#[test]
fn zero_alloc_dissect_quic_initial() {
    let raw = build_initial(&[0x01, 0x02], &[0x03], &[0xAA; 10]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        QuicDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "QUIC initial dissect allocated {allocs} times");
}

#[test]
fn zero_alloc_dissect_quic_short_header() {
    let raw = build_short_header(&[0xBB; 20]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        QuicDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "QUIC short header dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_quic_version_negotiation() {
    let raw = build_version_negotiation(&[0x01], &[0x02], &[0x0000_0001, 0x6b33_43cf]);
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        QuicDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "QUIC version negotiation dissect allocated {allocs} times"
    );
}

#[test]
fn zero_alloc_dissect_quic_coalesced() {
    // RFC 9000, Section 12.2 — Initial + Initial + Short Header in one datagram.
    // https://www.rfc-editor.org/rfc/rfc9000#section-12.2
    let mut raw = build_initial(&[0x01, 0x02], &[0x03], &[0xAA; 10]);
    raw.extend_from_slice(&build_initial(&[0x01, 0x02], &[0x03], &[0xCC; 12]));
    raw.extend_from_slice(&build_short_header(&[0xBB; 20]));
    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        QuicDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "QUIC coalesced dissect allocated {allocs} times");
}

/// RFC 9001, Appendix A.2 client Initial (1200 bytes).
/// <https://www.rfc-editor.org/rfc/rfc9001#appendix-A.2>
#[cfg(feature = "decrypt")]
fn rfc9001_a2_client_initial() -> Vec<u8> {
    let text = include_str!("data/rfc9001_a2_client_initial.hex");
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(feature = "decrypt")]
#[test]
fn zero_alloc_dissect_quic_decrypted_initial() {
    // RFC 9001, Section 5 — key derivation, header protection removal and
    // AEAD decryption of an Initial that fits the stack work buffer do not
    // allocate. The first run grows the scratch buffer to hold the CRYPTO
    // data, so it is not counted.
    // https://www.rfc-editor.org/rfc/rfc9001#section-5
    let raw = rfc9001_a2_client_initial();
    let mut buf = DissectBuffer::new();
    QuicDissector.dissect(&raw, &mut buf, 0).unwrap();
    let layer = &buf.layers()[0];
    assert!(buf.field_by_name(layer, "frames").is_some());

    let allocs = count_allocs(|| {
        buf.clear();
        QuicDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "QUIC decrypted Initial dissect allocated {allocs} times"
    );
}
