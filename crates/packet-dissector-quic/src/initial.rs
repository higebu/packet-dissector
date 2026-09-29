//! QUIC Initial packet protection removal.
//!
//! Initial packets are protected with keys that any observer can derive
//! from the client's Destination Connection ID and a public,
//! version-specific salt. This module derives the client Initial keys,
//! removes header protection and decrypts the payload, so the frames of a
//! client Initial can be shown without any secret. Server Initials use keys
//! derived from the client's original Destination Connection ID, which is
//! not in the server's packet, so they are not decrypted here.
//!
//! ## References
//! - RFC 9001, Section 5 (Packet Protection): <https://www.rfc-editor.org/rfc/rfc9001#section-5>
//! - RFC 9369, Section 3.3 (QUIC v2 Cryptography Changes): <https://www.rfc-editor.org/rfc/rfc9369#section-3.3>
//! - RFC 8446, Section 7.1 (HKDF-Expand-Label): <https://www.rfc-editor.org/rfc/rfc8446#section-7.1>
//! - RFC 5869 (HKDF): <https://www.rfc-editor.org/rfc/rfc5869>

use aes::Aes128;
use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{VERSION_1, VERSION_2};

/// Initial salt for QUIC v1.
///
/// RFC 9001, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.2>:
/// "initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Initial salt for QUIC v2.
///
/// RFC 9369, Section 3.3.1 — <https://www.rfc-editor.org/rfc/rfc9369#section-3.3.1>:
/// "initial_salt = 0x0dede3def700a6db819381be6e269dcbf9bd2ed9"
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// HKDF-Expand-Label label of the client Initial secret.
///
/// RFC 9001, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.2>:
/// "The secret used by clients to construct Initial packets uses the PRK
/// and the label "client in" as input to the HKDF-Expand-Label function"
pub(crate) const CLIENT_IN: &[u8] = b"client in";

/// Authentication tag length of AEAD_AES_128_GCM.
///
/// RFC 9001, Section 5.4.2 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2>:
/// the TLS 1.3 cipher suites "have 16-byte expansions and 16-byte header
/// protection samples."
pub(crate) const AEAD_TAG_LEN: usize = 16;

/// Header protection sample length (see [`AEAD_TAG_LEN`]).
const SAMPLE_LEN: usize = 16;

/// Size of the on-stack work buffer. Packets up to this size (an Initial
/// in a 1500-byte Ethernet MTU always fits) are decrypted without heap
/// allocation. Larger Initials (jumbo frames, loopback captures) are rare;
/// they are decrypted in a heap buffer, the only allocating path of the
/// dissector, rather than left undecrypted.
pub(crate) const STACK_BUF_LEN: usize = 1500;

/// Packet protection keys for one direction.
///
/// RFC 9001, Section 5.1 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.1>
pub(crate) struct PacketKeys {
    /// AEAD key (AEAD_AES_128_GCM).
    pub(crate) key: [u8; 16],
    /// AEAD IV.
    pub(crate) iv: [u8; 12],
    /// Header protection key (AES-128).
    pub(crate) hp: [u8; 16],
}

/// HKDF-Expand-Label with an empty context.
///
/// RFC 8446, Section 7.1 — <https://www.rfc-editor.org/rfc/rfc8446#section-7.1>:
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn hkdf_expand_label(prk: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    const PREFIX: &[u8] = b"tls13 ";
    let length = u16::try_from(out.len()).ok()?.to_be_bytes();
    let label_len = [u8::try_from(PREFIX.len() + label.len()).ok()?];
    prk.expand_multi_info(&[&length, &label_len, PREFIX, label, &[0]], out)
        .ok()
}

/// Derive the Initial packet protection keys for `version` from the
/// client's Destination Connection ID. `label` is `"client in"` or
/// `"server in"`. Returns `None` for versions without known Initial salt.
///
/// RFC 9001, Section 5.2 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.2>
/// RFC 9369, Section 3.3.2 — <https://www.rfc-editor.org/rfc/rfc9369#section-3.3.2>:
/// the labels change "from "quic key" to "quicv2 key", from "quic iv" to
/// "quicv2 iv", from "quic hp" to "quicv2 hp""
pub(crate) fn derive_keys(version: u32, dcid: &[u8], label: &[u8]) -> Option<PacketKeys> {
    let (salt, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
        VERSION_1 => (&INITIAL_SALT_V1, b"quic key", b"quic iv", b"quic hp"),
        VERSION_2 => (&INITIAL_SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
        _ => return None,
    };

    // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
    let (_, initial_secret) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    // "The hash function for HKDF when deriving initial secrets and keys
    // is SHA-256", so Hash.length is 32.
    let mut secret = [0u8; 32];
    hkdf_expand_label(&initial_secret, label, &mut secret)?;
    let secret = Hkdf::<Sha256>::from_prk(&secret).ok()?;

    let mut keys = PacketKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    hkdf_expand_label(&secret, key_label, &mut keys.key)?;
    hkdf_expand_label(&secret, iv_label, &mut keys.iv)?;
    hkdf_expand_label(&secret, hp_label, &mut keys.hp)?;
    Some(keys)
}

/// AEAD nonce for a packet number.
///
/// RFC 9001, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.3>:
/// "The 62 bits of the reconstructed QUIC packet number in network byte
/// order are left-padded with zeros to the size of the IV.  The exclusive
/// OR of the padded packet number and the IV forms the AEAD nonce."
pub(crate) fn nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (n, p) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *n ^= p;
    }
    nonce
}

/// Header fields recovered by removing header protection.
pub(crate) struct UnprotectedHeader {
    /// First byte with the protected low 4 bits restored.
    pub(crate) first_byte: u8,
    /// Encoded length of the Packet Number field (1 to 4 bytes).
    pub(crate) packet_number_length: usize,
    /// Packet number.
    ///
    /// Without connection state no packet has been received yet, so the
    /// decoded value equals the truncated value on the wire (RFC 9000,
    /// Appendix A.3 with an expected packet number of 0 —
    /// <https://www.rfc-editor.org/rfc/rfc9000#appendix-A.3>).
    pub(crate) packet_number: u64,
}

/// Remove header and packet protection from a client Initial packet and
/// call `f` with the recovered header fields and the plaintext payload.
///
/// `packet` is exactly one Initial packet (ending where its Length field
/// says), `dcid` its Destination Connection ID and `pn_offset` the offset
/// of the Packet Number field. Returns `None` when the version has no known
/// Initial keys, the packet is too short for a header protection sample, or
/// the AEAD tag does not verify (for example a server Initial, whose keys
/// derive from a connection ID that is not in the packet).
pub(crate) fn unprotect_client_initial<R>(
    version: u32,
    packet: &[u8],
    dcid: &[u8],
    pn_offset: usize,
    f: impl FnOnce(&UnprotectedHeader, &[u8]) -> R,
) -> Option<R> {
    // RFC 9001, Section 5.4.2 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2>:
    // "sample_offset = pn_offset + 4". "An endpoint MUST discard packets
    // that are not long enough to contain a complete sample."
    let sample_offset = pn_offset.checked_add(4)?;
    let sample: [u8; SAMPLE_LEN] = packet
        .get(sample_offset..sample_offset.checked_add(SAMPLE_LEN)?)?
        .try_into()
        .ok()?;

    let keys = derive_keys(version, dcid, CLIENT_IN)?;

    // RFC 9001, Section 5.4.3 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.4.3>:
    // "mask = AES-ECB(hp_key, sample)"
    let mut mask = sample.into();
    Aes128::new_from_slice(&keys.hp)
        .ok()?
        .encrypt_block(&mut mask);

    // RFC 9001, Section 5.4.1 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1>:
    // "Long header: 4 bits masked", then "pn_length = (packet[0] & 0x03) + 1".
    let first_byte = packet[0] ^ (mask[0] & 0x0f);
    let packet_number_length = usize::from(first_byte & 0x03) + 1;
    let header_len = pn_offset + packet_number_length;
    let tag_start = packet.len() - AEAD_TAG_LEN;

    let mut stack = [0u8; STACK_BUF_LEN];
    let mut heap = Vec::new();
    let work: &mut [u8] = if packet.len() <= STACK_BUF_LEN {
        &mut stack[..packet.len()]
    } else {
        heap.resize(packet.len(), 0);
        &mut heap
    };
    work.copy_from_slice(packet);
    work[0] = first_byte;
    let mut packet_number = 0u64;
    for (i, b) in work[pn_offset..header_len].iter_mut().enumerate() {
        *b ^= mask[1 + i];
        packet_number = (packet_number << 8) | u64::from(*b);
    }

    // RFC 9001, Section 5.3 — <https://www.rfc-editor.org/rfc/rfc9001#section-5.3>:
    // "The associated data, A, for the AEAD is the contents of the QUIC
    // header, starting from the first byte of either the short or long
    // header, up to and including the unprotected packet number."
    let (header, rest) = work.split_at_mut(header_len);
    let (payload, tag) = rest.split_at_mut(tag_start - header_len);
    let tag = Tag::try_from(&*tag).ok()?;
    Aes128Gcm::new_from_slice(&keys.key)
        .ok()?
        .decrypt_inout_detached(
            &Nonce::from(nonce(&keys.iv, packet_number)),
            header,
            payload.into(),
            &tag,
        )
        .ok()?;

    let hdr = UnprotectedHeader {
        first_byte,
        packet_number_length,
        packet_number,
    };
    Some(f(&hdr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{
        DCID, hex, rfc9001_a2_client_initial, rfc9001_a2_crypto_frame, rfc9001_a3_server_initial,
        rfc9369_a2_client_initial,
    };
    use crate::{VERSION_1, VERSION_2};

    // # RFC 9001 / RFC 9369 Initial protection coverage
    //
    // | RFC Section          | Description                           | Test                               |
    // |----------------------|---------------------------------------|------------------------------------|
    // | 9001 §5.2, A.1       | v1 client Initial secrets and keys    | test_v1_client_keys                |
    // | 9001 §5.2, A.1       | v1 server Initial secrets and keys    | test_v1_server_keys                |
    // | 9369 §3.3.1-2, A.1   | v2 salt and "quicv2" labels           | test_v2_client_keys                |
    // | 9369 §3.3.1-2, A.1   | v2 server keys                        | test_v2_server_keys                |
    // | 9001 §5.2            | Unknown version: no keys              | test_unknown_version_no_keys       |
    // | 9001 §5.3-5.4, A.2   | v1 client Initial HP removal + AEAD   | test_decrypt_v1_client_initial     |
    // | 9369 §3.3, A.2       | v2 client Initial HP removal + AEAD   | test_decrypt_v2_client_initial     |
    // | 9001 §5.2, A.3       | Server Initial (keys need ODCID)      | test_server_initial_not_decrypted  |
    // | 9001 §5.3            | AEAD tag mismatch                     | test_tampered_packet_not_decrypted |
    // | 9001 §5.4.2          | Too short for the HP sample           | test_too_short_for_sample          |
    // | 9001 §5.4.1          | Unknown version: not decrypted        | test_unknown_version_not_decrypted |
    // | ---                  | Packet larger than the stack buffer   | test_decrypt_large_packet          |

    fn keys(version: u32, label: &[u8]) -> PacketKeys {
        derive_keys(version, &DCID, label).unwrap()
    }

    #[test]
    fn test_v1_client_keys() {
        // RFC 9001, Appendix A.1 — https://www.rfc-editor.org/rfc/rfc9001#appendix-A.1
        let k = keys(VERSION_1, CLIENT_IN);
        assert_eq!(k.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn test_v1_server_keys() {
        // RFC 9001, Appendix A.1 — https://www.rfc-editor.org/rfc/rfc9001#appendix-A.1
        let k = keys(VERSION_1, b"server in");
        assert_eq!(k.key.to_vec(), hex("cf3a5331653c364c88f0f379b6067e37"));
        assert_eq!(k.iv.to_vec(), hex("0ac1493ca1905853b0bba03e"));
        assert_eq!(k.hp.to_vec(), hex("c206b8d9b9f0f37644430b490eeaa314"));
    }

    #[test]
    fn test_v2_client_keys() {
        // RFC 9369, Appendix A.1 — https://www.rfc-editor.org/rfc/rfc9369#appendix-A.1
        let k = keys(VERSION_2, CLIENT_IN);
        assert_eq!(k.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(k.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    #[test]
    fn test_v2_server_keys() {
        // RFC 9369, Appendix A.1 — https://www.rfc-editor.org/rfc/rfc9369#appendix-A.1
        let k = keys(VERSION_2, b"server in");
        assert_eq!(k.key.to_vec(), hex("82db637861d55e1d011f19ea71d5d2a7"));
        assert_eq!(k.iv.to_vec(), hex("dd13c276499c0249d3310652"));
        assert_eq!(k.hp.to_vec(), hex("edf6d05c83121201b436e16877593c3a"));
    }

    #[test]
    fn test_unknown_version_no_keys() {
        assert!(derive_keys(0xff00_001d, &DCID, CLIENT_IN).is_none());
    }

    /// Packet Number offset of the Appendix A.2 client Initials:
    /// 1 + 4 (version) + 1 + 8 (DCID) + 1 + 0 (SCID) + 1 (Token Length)
    /// + 2 (Length).
    const A2_PN_OFFSET: usize = 18;

    fn check_a2(packet: &[u8], version: u32, first_byte: u8) {
        let crypto = rfc9001_a2_crypto_frame();
        let out = unprotect_client_initial(version, packet, &DCID, A2_PN_OFFSET, |hdr, plain| {
            assert_eq!(hdr.first_byte, first_byte);
            assert_eq!(hdr.packet_number_length, 4);
            assert_eq!(hdr.packet_number, 2);
            // RFC 9001, Appendix A.2 — "1162 bytes of frames"
            assert_eq!(plain.len(), 1162);
            assert_eq!(&plain[..crypto.len()], &crypto[..]);
            assert!(plain[crypto.len()..].iter().all(|&b| b == 0));
            42
        });
        assert_eq!(out, Some(42));
    }

    #[test]
    fn test_decrypt_v1_client_initial() {
        // RFC 9001, Appendix A.2 — https://www.rfc-editor.org/rfc/rfc9001#appendix-A.2
        check_a2(&rfc9001_a2_client_initial(), VERSION_1, 0xc3);
    }

    #[test]
    fn test_decrypt_v2_client_initial() {
        // RFC 9369, Appendix A.2 — https://www.rfc-editor.org/rfc/rfc9369#appendix-A.2
        check_a2(&rfc9369_a2_client_initial(), VERSION_2, 0xd3);
    }

    #[test]
    fn test_server_initial_not_decrypted() {
        // RFC 9001, Appendix A.3 — the server Initial carries a zero-length
        // DCID; its keys come from the client's original DCID, which is not
        // in the packet, so stateless decryption fails.
        // https://www.rfc-editor.org/rfc/rfc9001#appendix-A.3
        let packet = rfc9001_a3_server_initial();
        // 1 + 4 + 1 + 0 (DCID) + 1 + 8 (SCID) + 1 (Token Length) + 2 (Length)
        let out = unprotect_client_initial(VERSION_1, &packet, &[], 18, |_, _| ());
        assert!(out.is_none());
    }

    #[test]
    fn test_tampered_packet_not_decrypted() {
        // RFC 9001, Section 5.3 — the AEAD tag must verify.
        // https://www.rfc-editor.org/rfc/rfc9001#section-5.3
        let mut packet = rfc9001_a2_client_initial();
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        let out = unprotect_client_initial(VERSION_1, &packet, &DCID, A2_PN_OFFSET, |_, _| ());
        assert!(out.is_none());
    }

    #[test]
    fn test_too_short_for_sample() {
        // RFC 9001, Section 5.4.2 — "An endpoint MUST discard packets that
        // are not long enough to contain a complete sample."
        // https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2
        let packet = rfc9001_a2_client_initial();
        let short = &packet[..A2_PN_OFFSET + 4 + 15];
        let out = unprotect_client_initial(VERSION_1, short, &DCID, A2_PN_OFFSET, |_, _| ());
        assert!(out.is_none());
    }

    #[test]
    fn test_unknown_version_not_decrypted() {
        let packet = rfc9001_a2_client_initial();
        let out = unprotect_client_initial(0xff00_001d, &packet, &DCID, A2_PN_OFFSET, |_, _| ());
        assert!(out.is_none());
    }

    #[test]
    fn test_decrypt_large_packet() {
        // A packet larger than the stack work buffer takes the heap path.
        // Protect a synthetic Initial with the RFC 9001 Appendix A.1 client
        // keys, then remove the protection again.
        let k = keys(VERSION_1, CLIENT_IN);
        let payload_len = STACK_BUF_LEN + 100;
        let mut packet = Vec::new();
        packet.push(0xc1); // Initial, 2-byte packet number
        packet.extend_from_slice(&VERSION_1.to_be_bytes());
        packet.push(DCID.len() as u8);
        packet.extend_from_slice(&DCID);
        packet.push(0); // SCID length
        packet.push(0); // Token Length
        let length = (2 + payload_len + AEAD_TAG_LEN) as u16 | 0x4000;
        packet.extend_from_slice(&length.to_be_bytes());
        let pn_offset = packet.len();
        packet.extend_from_slice(&[0x00, 0x07]); // packet number 7
        let mut plain = vec![0u8; payload_len];
        plain[0] = 0x01; // PING, then PADDING
        protect(&k, &mut packet, pn_offset, 2, 7, &plain);

        let out = unprotect_client_initial(VERSION_1, &packet, &DCID, pn_offset, |hdr, p| {
            assert_eq!(hdr.first_byte, 0xc1);
            assert_eq!(hdr.packet_number_length, 2);
            assert_eq!(hdr.packet_number, 7);
            assert_eq!(p, &plain[..]);
        });
        assert!(out.is_some());
    }

    /// Apply packet protection (RFC 9001, Section 5.3 —
    /// <https://www.rfc-editor.org/rfc/rfc9001#section-5.3>) and header
    /// protection (RFC 9001, Section 5.4.1 —
    /// <https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1>) to `packet`,
    /// whose header ends with an unprotected packet number of `pn_len`
    /// bytes at `pn_offset`.
    fn protect(
        k: &PacketKeys,
        packet: &mut Vec<u8>,
        pn_offset: usize,
        pn_len: usize,
        pn: u64,
        plain: &[u8],
    ) {
        use aes::Aes128;
        use aes::cipher::BlockCipherEncrypt;
        use aes_gcm::aead::{AeadInOut, KeyInit};
        use aes_gcm::{Aes128Gcm, Nonce};

        let header_len = pn_offset + pn_len;
        let mut body = plain.to_vec();
        let tag = Aes128Gcm::new_from_slice(&k.key)
            .unwrap()
            .encrypt_inout_detached(
                &Nonce::from(nonce(&k.iv, pn)),
                &packet[..header_len],
                (&mut body[..]).into(),
            )
            .unwrap();
        packet.extend_from_slice(&body);
        packet.extend_from_slice(&tag);

        let mut sample = [0u8; 16];
        sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
        let mut block = sample.into();
        Aes128::new_from_slice(&k.hp)
            .unwrap()
            .encrypt_block(&mut block);
        packet[0] ^= block[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= block[1 + i];
        }
    }
}
