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

/// Build a client Initial of `payload_len` plaintext bytes (a PING frame
/// followed by PADDING), protected with the RFC 9001, Appendix A.1 client
/// keys for DCID 0x8394c8f03e515708.
/// <https://www.rfc-editor.org/rfc/rfc9001#appendix-A.1>
#[cfg(feature = "decrypt")]
fn protected_client_initial(payload_len: usize) -> Vec<u8> {
    use aes::Aes128;
    use aes::cipher::BlockCipherEncrypt;
    use aes_gcm::aead::{AeadInOut, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce};

    const KEY: [u8; 16] = [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2,
        0x2d,
    ];
    const IV: [u8; 12] = [
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    ];
    const HP: [u8; 16] = [
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed,
        0xd2,
    ];
    const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    let mut packet = vec![0xc0]; // Initial, 1-byte packet number
    packet.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    packet.push(DCID.len() as u8);
    packet.extend_from_slice(&DCID);
    packet.push(0); // SCID length
    packet.push(0); // Token Length
    packet.extend_from_slice(&encode_varint((1 + payload_len + 16) as u64));
    let pn_offset = packet.len();
    packet.push(0x00); // packet number 0

    let mut body = vec![0u8; payload_len];
    body[0] = 0x01; // PING
    // RFC 9001, Section 5.3 — https://www.rfc-editor.org/rfc/rfc9001#section-5.3
    // The nonce is the IV XORed with the packet number, which is 0 here.
    let tag = Aes128Gcm::new_from_slice(&KEY)
        .unwrap()
        .encrypt_inout_detached(&Nonce::from(IV), &packet, (&mut body[..]).into())
        .unwrap();
    packet.extend_from_slice(&body);
    packet.extend_from_slice(&tag);

    // RFC 9001, Section 5.4.1 — https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1
    let mut mask = [0u8; 16];
    mask.copy_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
    let mut mask = mask.into();
    Aes128::new_from_slice(&HP)
        .unwrap()
        .encrypt_block(&mut mask);
    packet[0] ^= mask[0] & 0x0f;
    packet[pn_offset] ^= mask[1];
    packet
}

#[cfg(feature = "decrypt")]
#[test]
fn zero_alloc_dissect_quic_decrypted_large_initial() {
    // A client Initial larger than a 1500-byte MTU (jumbo frames, loopback)
    // is decrypted without heap allocation as well. RFC 9000, Section 18.2 —
    // https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    let raw = protected_client_initial(9000);
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
        "QUIC large decrypted Initial dissect allocated {allocs} times"
    );
}
