//! ESP decryption support.
//!
//! Provides decryption for ESP payloads using pre-shared Security Association
//! (SA) parameters. Supports CBC and GCM modes.
//!
//! ## References
//! - RFC 3602: The AES-CBC Cipher Algorithm and Its Use with IPsec:
//!   <https://www.rfc-editor.org/rfc/rfc3602>
//! - RFC 4106: The Use of Galois/Counter Mode (GCM) in IPsec ESP:
//!   <https://www.rfc-editor.org/rfc/rfc4106>
//! - RFC 2410: The NULL Encryption Algorithm and Its Use With IPsec:
//!   <https://www.rfc-editor.org/rfc/rfc2410>

use packet_dissector_core::error::PacketError;
use packet_dissector_core::lookup::ip_protocol_name;

/// IP protocol number for HOPOPT (IPv6 Hop-by-Hop Options).
const IP_PROTO_HOPOPT: u8 = 0;

/// IP protocol number for IPv6 No Next Header (RFC 8200, Section 4.7).
const IP_PROTO_IPV6_NONXT: u8 = 59;

/// Encryption algorithm for an ESP Security Association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// No encryption (RFC 2410). Payload is plaintext.
    Null,
    /// AES-128-CBC (RFC 3602). IV = 16 bytes, key = 16 bytes.
    Aes128Cbc,
    /// AES-192-CBC (RFC 3602). IV = 16 bytes, key = 24 bytes.
    Aes192Cbc,
    /// AES-256-CBC (RFC 3602). IV = 16 bytes, key = 32 bytes.
    Aes256Cbc,
    /// AES-128-GCM (RFC 4106). IV = 8 bytes in packet, salt = 4 bytes, key = 16 bytes.
    Aes128Gcm {
        /// 4-byte salt prepended to the 8-byte IV from the packet to form a 12-byte nonce.
        salt: [u8; 4],
    },
    /// AES-256-GCM (RFC 4106). IV = 8 bytes in packet, salt = 4 bytes, key = 32 bytes.
    Aes256Gcm {
        /// 4-byte salt prepended to the 8-byte IV from the packet to form a 12-byte nonce.
        salt: [u8; 4],
    },
}

/// Authentication algorithm for non-AEAD ESP modes.
///
/// **Note:** ICV (Integrity Check Value) verification is NOT performed.
/// The ICV length is used only to locate the encrypted payload boundary
/// within the ESP packet (i.e., to strip the trailing ICV bytes before
/// decryption). This matches the behaviour of passive capture analysis
/// tools such as Wireshark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationAlgorithm {
    /// No authentication.
    None,
    /// HMAC-SHA-1 with 96-bit ICV (RFC 2404).
    HmacSha1_96,
    /// HMAC-SHA-256 with 128-bit ICV (RFC 4868).
    HmacSha256_128,
}

/// Security Association parameters for ESP decryption.
#[derive(Debug, Clone)]
pub struct EspSa {
    /// Encryption algorithm.
    pub encryption: EncryptionAlgorithm,
    /// Encryption key bytes.
    pub enc_key: Vec<u8>,
    /// Authentication algorithm (ignored for AEAD ciphers).
    pub authentication: AuthenticationAlgorithm,
    /// Authentication key bytes (ignored for AEAD ciphers).
    pub auth_key: Vec<u8>,
}

impl EncryptionAlgorithm {
    /// Returns the IV length in bytes for this algorithm as present in the packet.
    pub fn iv_len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => 16,
            // RFC 4106, Section 3: "The IV is 8 octets."
            Self::Aes128Gcm { .. } | Self::Aes256Gcm { .. } => 8,
        }
    }

    /// Returns true if this is an AEAD cipher (combined encryption + authentication).
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::Aes128Gcm { .. } | Self::Aes256Gcm { .. })
    }
}

impl AuthenticationAlgorithm {
    /// Returns the ICV (Integrity Check Value) length in bytes.
    pub fn icv_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::HmacSha1_96 => 12,
            Self::HmacSha256_128 => 16,
        }
    }
}

/// Result of a successful ESP decryption.
#[derive(Debug)]
pub struct DecryptedEsp {
    /// Decrypted payload (inner protocol data, without padding).
    pub payload: Vec<u8>,
    /// Next Header value from the ESP trailer.
    pub next_header: u8,
    /// Pad Length value from the ESP trailer.
    pub pad_length: u8,
}

/// Decrypt an ESP payload.
///
/// # Arguments
/// * `sa` — Security Association parameters
/// * `spi` — Security Parameters Index (for GCM AAD)
/// * `seq` — Sequence number (for GCM AAD)
/// * `encrypted_data` — Data after the 8-byte ESP header: `[IV | ciphertext | ICV]`
///
/// # Returns
/// The decrypted payload, next header, and pad length.
pub fn decrypt_esp(
    sa: &EspSa,
    spi: u32,
    seq: u32,
    encrypted_data: &[u8],
) -> Result<DecryptedEsp, PacketError> {
    match &sa.encryption {
        EncryptionAlgorithm::Null => decrypt_null(sa, encrypted_data),
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::Aes128Cbc
        | EncryptionAlgorithm::Aes192Cbc
        | EncryptionAlgorithm::Aes256Cbc => decrypt_cbc(sa, encrypted_data),
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::Aes128Gcm { salt } | EncryptionAlgorithm::Aes256Gcm { salt } => {
            decrypt_gcm(sa, spi, seq, salt, encrypted_data)
        }
        #[cfg(not(any(feature = "decrypt", test)))]
        _ => Err(PacketError::InvalidHeader(
            "ESP decryption requires the 'decrypt' feature",
        )),
    }
}

/// NULL encryption — payload is plaintext, just strip ICV and extract trailer.
fn decrypt_null(sa: &EspSa, data: &[u8]) -> Result<DecryptedEsp, PacketError> {
    let icv_len = sa.authentication.icv_len();
    if data.len() < icv_len + 2 {
        return Err(PacketError::InvalidHeader(
            "ESP NULL: data too short for trailer + ICV",
        ));
    }
    let plaintext = data[..data.len() - icv_len].to_vec();
    extract_trailer(plaintext)
}

/// Heuristically attempt to decode ESP payload as NULL-encrypted plaintext.
///
/// When no Security Association is configured for the packet's SPI, this
/// function treats the raw payload (everything after the 8-byte ESP header)
/// as plaintext and tries to extract the ESP trailer. Inspired by passive
/// capture analysers such as Wireshark, it enables inner packet dissection
/// of unauthenticated NULL-encrypted ESP flows without pre-configuring an SA.
///
/// # Validation
///
/// Returns `None` (never allocating) unless ALL of the following hold:
///
/// 1. `data.len() >= 2` — room for `pad_length` and `next_header`.
/// 2. `next_header` (last byte) is a well-known IP protocol number
///    recognised by [`ip_protocol_name`]. This rejects the vast majority
///    of random bytes that would otherwise appear as valid trailers.
/// 3. `next_header` is not in the small set of values that are either
///    unlikely to appear as an ESP inner protocol or are strongly biased
///    towards false positives on zero-filled ciphertext: HOPOPT (0),
///    IPv6_NONXT (59). HOPOPT in particular matches any payload whose
///    final byte is `0x00`, which is extremely common in random data.
/// 4. `pad_length + 2 <= data.len()` — the padding field does not
///    overrun the payload.
/// 5. Padding bytes match the monotonically increasing sequence
///    `1, 2, 3, ..., pad_length` mandated by RFC 4303 Section 2.4.
///    This rule provides strong protection against false positives
///    when `pad_length > 0`.
///
/// Because authentication is never assumed for the heuristic path, this
/// function does not account for an ICV — NULL encryption with an ICV
/// requires an explicitly configured SA.
///
/// # References
/// - RFC 2410 (NULL Encryption):
///   <https://www.rfc-editor.org/rfc/rfc2410>
/// - RFC 4303, Section 2.4 (Padding):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.4>
/// - RFC 4303, Section 2.5 (Pad Length):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.5>
/// - RFC 4303, Section 2.6 (Next Header):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.6>
pub fn try_null_decrypt(data: &[u8]) -> Option<DecryptedEsp> {
    if data.len() < 2 {
        return None;
    }

    let next_header = data[data.len() - 1];
    let pad_length = data[data.len() - 2] as usize;

    ip_protocol_name(next_header)?;

    // HOPOPT matches any zero-filled trailer (extremely common in random
    // ciphertext), and IPv6_NONXT has no dispatch target.
    if next_header == IP_PROTO_HOPOPT || next_header == IP_PROTO_IPV6_NONXT {
        return None;
    }

    if pad_length + 2 > data.len() {
        return None;
    }

    let pad_start = data.len() - 2 - pad_length;
    for (i, &b) in data[pad_start..data.len() - 2].iter().enumerate() {
        if b as usize != i + 1 {
            return None;
        }
    }

    Some(DecryptedEsp {
        payload: data[..pad_start].to_vec(),
        next_header,
        pad_length: pad_length as u8,
    })
}

/// AES-CBC decryption.
///
/// RFC 3602, Section 3: <https://www.rfc-editor.org/rfc/rfc3602#section-3>
/// Layout: [IV(16)] [ciphertext(N*16)] [ICV(auth_icv_len)]
#[cfg(any(feature = "decrypt", test))]
fn decrypt_cbc(sa: &EspSa, data: &[u8]) -> Result<DecryptedEsp, PacketError> {
    use aes::Aes128;
    use aes::Aes192;
    use aes::Aes256;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

    let iv_len = sa.encryption.iv_len();
    let icv_len = sa.authentication.icv_len();

    if data.len() < iv_len + icv_len + 16 {
        return Err(PacketError::InvalidHeader(
            "ESP CBC: data too short for IV + ciphertext + ICV",
        ));
    }

    let iv = &data[..iv_len];
    let ciphertext = &data[iv_len..data.len() - icv_len];

    if ciphertext.len() % 16 != 0 {
        return Err(PacketError::InvalidHeader(
            "ESP CBC: ciphertext length not a multiple of block size",
        ));
    }

    let mut buf = ciphertext.to_vec();

    match sa.enc_key.len() {
        16 => {
            cbc::Decryptor::<Aes128>::new_from_slices(&sa.enc_key, iv)
                .map_err(|_| PacketError::InvalidHeader("ESP CBC key/IV error"))?
                .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| PacketError::InvalidHeader("ESP AES-128-CBC decrypt error"))?;
        }
        24 => {
            cbc::Decryptor::<Aes192>::new_from_slices(&sa.enc_key, iv)
                .map_err(|_| PacketError::InvalidHeader("ESP CBC key/IV error"))?
                .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| PacketError::InvalidHeader("ESP AES-192-CBC decrypt error"))?;
        }
        32 => {
            cbc::Decryptor::<Aes256>::new_from_slices(&sa.enc_key, iv)
                .map_err(|_| PacketError::InvalidHeader("ESP CBC key/IV error"))?
                .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|_| PacketError::InvalidHeader("ESP AES-256-CBC decrypt error"))?;
        }
        _ => {
            return Err(PacketError::InvalidHeader(
                "ESP CBC: unsupported key length",
            ));
        }
    }

    extract_trailer(buf)
}

/// AES-GCM decryption.
///
/// RFC 4106, Section 3: <https://www.rfc-editor.org/rfc/rfc4106#section-3>
/// Layout: [IV(8)] [ciphertext(N)] [ICV(16)]
/// Nonce = salt(4) || IV(8) = 12 bytes
/// AAD = SPI(4) || Seq(4) = 8 bytes
#[cfg(any(feature = "decrypt", test))]
fn decrypt_gcm(
    sa: &EspSa,
    spi: u32,
    seq: u32,
    salt: &[u8; 4],
    data: &[u8],
) -> Result<DecryptedEsp, PacketError> {
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::KeyInit;
    use aes_gcm::aead::Payload;
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

    const GCM_IV_LEN: usize = 8;
    const GCM_TAG_LEN: usize = 16;

    if data.len() < GCM_IV_LEN + GCM_TAG_LEN + 2 {
        return Err(PacketError::InvalidHeader(
            "ESP GCM: data too short for IV + ciphertext + tag",
        ));
    }

    let iv = &data[..GCM_IV_LEN];

    // RFC 4106, Section 3 — nonce = salt(4) || IV(8)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(salt);
    nonce_bytes[4..12].copy_from_slice(iv);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // RFC 4106, Section 5 — AAD = SPI(4) || Seq(4)
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&spi.to_be_bytes());
    aad[4..].copy_from_slice(&seq.to_be_bytes());

    // ciphertext + tag (GCM decryption expects them concatenated)
    let ciphertext_and_tag = &data[GCM_IV_LEN..];

    let payload = Payload {
        msg: ciphertext_and_tag,
        aad: &aad,
    };

    let plaintext = match sa.enc_key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(&sa.enc_key)
                .map_err(|_| PacketError::InvalidHeader("ESP GCM key error"))?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| PacketError::InvalidHeader("ESP AES-128-GCM decrypt error"))?
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(&sa.enc_key)
                .map_err(|_| PacketError::InvalidHeader("ESP GCM key error"))?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| PacketError::InvalidHeader("ESP AES-256-GCM decrypt error"))?
        }
        _ => {
            return Err(PacketError::InvalidHeader(
                "ESP GCM: unsupported key length",
            ));
        }
    };

    extract_trailer(plaintext)
}

/// Extract padding, pad_length, and next_header from decrypted plaintext.
///
/// Takes ownership of the plaintext `Vec` to avoid an extra allocation —
/// the vector is truncated in place to produce the payload.
///
/// RFC 4303, Section 2.4-2.6: <https://www.rfc-editor.org/rfc/rfc4303#section-2.4>
/// Plaintext layout: [payload] [padding(0-255)] [pad_length(1)] [next_header(1)]
fn extract_trailer(mut plaintext: Vec<u8>) -> Result<DecryptedEsp, PacketError> {
    if plaintext.len() < 2 {
        return Err(PacketError::InvalidHeader(
            "ESP: decrypted data too short for trailer",
        ));
    }

    let next_header = plaintext[plaintext.len() - 1];
    let pad_length = plaintext[plaintext.len() - 2] as usize;

    // Validate: pad_length + 2 (trailer) must not exceed plaintext length
    if pad_length + 2 > plaintext.len() {
        return Err(PacketError::InvalidHeader(
            "ESP: pad_length exceeds decrypted data length",
        ));
    }

    let payload_end = plaintext.len() - 2 - pad_length;
    plaintext.truncate(payload_end);

    Ok(DecryptedEsp {
        payload: plaintext,
        next_header,
        pad_length: pad_length as u8,
    })
}

/// Parse an encryption algorithm name string.
///
/// Returns an [`EncryptionAlgorithm`] if the name is recognized and the key length
/// in `key` matches the requirements for that algorithm, otherwise returns an
/// error message.
pub fn parse_encryption_algorithm(name: &str, key: &[u8]) -> Result<EncryptionAlgorithm, String> {
    match name {
        "null" => Ok(EncryptionAlgorithm::Null),
        "aes-128-cbc" => {
            if key.len() != 16 {
                return Err(format!(
                    "aes-128-cbc requires 16-byte key, got {}",
                    key.len()
                ));
            }
            Ok(EncryptionAlgorithm::Aes128Cbc)
        }
        "aes-192-cbc" => {
            if key.len() != 24 {
                return Err(format!(
                    "aes-192-cbc requires 24-byte key, got {}",
                    key.len()
                ));
            }
            Ok(EncryptionAlgorithm::Aes192Cbc)
        }
        "aes-256-cbc" => {
            if key.len() != 32 {
                return Err(format!(
                    "aes-256-cbc requires 32-byte key, got {}",
                    key.len()
                ));
            }
            Ok(EncryptionAlgorithm::Aes256Cbc)
        }
        "aes-128-gcm" => {
            // RFC 4106: key = 16 bytes enc_key + 4 bytes salt = 20 bytes total
            if key.len() != 20 {
                return Err(format!(
                    "aes-128-gcm requires 20-byte key (16 enc + 4 salt), got {}",
                    key.len()
                ));
            }
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&key[16..20]);
            Ok(EncryptionAlgorithm::Aes128Gcm { salt })
        }
        "aes-256-gcm" => {
            // RFC 4106: key = 32 bytes enc_key + 4 bytes salt = 36 bytes total
            if key.len() != 36 {
                return Err(format!(
                    "aes-256-gcm requires 36-byte key (32 enc + 4 salt), got {}",
                    key.len()
                ));
            }
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&key[32..36]);
            Ok(EncryptionAlgorithm::Aes256Gcm { salt })
        }
        _ => Err(format!("unknown encryption algorithm: {name}")),
    }
}

/// Parse an authentication algorithm name string.
pub fn parse_authentication_algorithm(
    name: &str,
    key: &[u8],
) -> Result<AuthenticationAlgorithm, String> {
    match name {
        "none" => Ok(AuthenticationAlgorithm::None),
        "hmac-sha1-96" => {
            if key.len() != 20 {
                return Err(format!(
                    "hmac-sha1-96 requires 20-byte key, got {}",
                    key.len()
                ));
            }
            Ok(AuthenticationAlgorithm::HmacSha1_96)
        }
        "hmac-sha256-128" => {
            if key.len() != 32 {
                return Err(format!(
                    "hmac-sha256-128 requires 32-byte key, got {}",
                    key.len()
                ));
            }
            Ok(AuthenticationAlgorithm::HmacSha256_128)
        }
        _ => Err(format!("unknown authentication algorithm: {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_trailer_basic() {
        // payload=[0x45, 0x00], padding=[], pad_length=0, next_header=4 (IPv4)
        let plaintext = [0x45, 0x00, 0x00, 0x04];
        let result = extract_trailer(plaintext.to_vec()).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_extract_trailer_with_padding() {
        // payload=[0x45], padding=[0x01, 0x02], pad_length=2, next_header=4
        let plaintext = [0x45, 0x01, 0x02, 0x02, 0x04];
        let result = extract_trailer(plaintext.to_vec()).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45]);
    }

    #[test]
    fn test_extract_trailer_too_short() {
        let plaintext = [0x04];
        let err = extract_trailer(plaintext.to_vec()).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_extract_trailer_bad_pad_length() {
        // pad_length=100 but only 4 bytes total
        let plaintext = [0x45, 0x00, 100, 0x04];
        let err = extract_trailer(plaintext.to_vec()).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_null_decryption() {
        // Plaintext: [payload(2)] [pad(0)] [pad_len=0] [next_header=4]
        let sa = EspSa {
            encryption: EncryptionAlgorithm::Null,
            enc_key: vec![],
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };
        let data = [0x45, 0x00, 0x00, 0x04]; // payload + trailer, no ICV
        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_null_with_icv() {
        let sa = EspSa {
            encryption: EncryptionAlgorithm::Null,
            enc_key: vec![],
            authentication: AuthenticationAlgorithm::HmacSha1_96,
            auth_key: vec![0; 20],
        };
        // payload + trailer + 12-byte ICV
        let mut data = vec![0x45, 0x00, 0x00, 0x04];
        data.extend_from_slice(&[0xAA; 12]); // ICV
        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_cbc_decryption() {
        use aes::Aes128;
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];

        // Build plaintext: inner_data(12) + padding(0x01, 0x02) + pad_len(2) + next_header(4)
        // Total = 16 bytes (one AES block)
        let mut plaintext = vec![0x45; 12];
        plaintext.extend_from_slice(&[0x01, 0x02]); // padding
        plaintext.push(2); // pad_length
        plaintext.push(4); // next_header (IPv4)

        // Encrypt
        let mut ciphertext = plaintext.clone();
        cbc::Encryptor::<Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, 16)
            .unwrap();

        // Build data: IV + ciphertext (no ICV since auth=none)
        let mut data = iv.to_vec();
        data.extend_from_slice(&ciphertext);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes128Cbc,
            enc_key: key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45; 12]);
    }

    #[test]
    fn test_gcm_decryption() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Nonce};

        let enc_key = [0x03u8; 16];
        let salt = [0x04u8; 4];
        let packet_iv = [0x05u8; 8];
        let spi: u32 = 0x1234;
        let seq: u32 = 1;

        // Build nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&salt);
        nonce_bytes[4..].copy_from_slice(&packet_iv);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Build AAD
        let mut aad = [0u8; 8];
        aad[..4].copy_from_slice(&spi.to_be_bytes());
        aad[4..].copy_from_slice(&seq.to_be_bytes());

        // Plaintext: payload(4) + pad_len(0) + next_header(4)
        let plaintext_inner = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x04];

        let cipher = Aes128Gcm::new_from_slice(&enc_key).unwrap();
        let ciphertext_and_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext_inner,
                    aad: &aad,
                },
            )
            .unwrap();

        // Build data: IV(8) + ciphertext_and_tag
        let mut data = packet_iv.to_vec();
        data.extend_from_slice(&ciphertext_and_tag);

        // Key for parse: enc_key(16) + salt(4) = 20 bytes
        let mut full_key = enc_key.to_vec();
        full_key.extend_from_slice(&salt);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes128Gcm { salt },
            enc_key: enc_key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let result = decrypt_esp(&sa, spi, seq, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.payload, vec![0x45, 0x00, 0x00, 0x28]);
    }

    #[test]
    fn test_parse_encryption_algorithm() {
        assert!(matches!(
            parse_encryption_algorithm("null", &[]),
            Ok(EncryptionAlgorithm::Null)
        ));
        assert!(matches!(
            parse_encryption_algorithm("aes-128-cbc", &[0; 16]),
            Ok(EncryptionAlgorithm::Aes128Cbc)
        ));
        assert!(parse_encryption_algorithm("aes-128-cbc", &[0; 15]).is_err());
        assert!(parse_encryption_algorithm("unknown", &[]).is_err());
    }

    #[test]
    fn test_parse_encryption_algorithm_aes192_cbc() {
        assert!(matches!(
            parse_encryption_algorithm("aes-192-cbc", &[0; 24]),
            Ok(EncryptionAlgorithm::Aes192Cbc)
        ));
        assert!(parse_encryption_algorithm("aes-192-cbc", &[0; 16]).is_err());
    }

    #[test]
    fn test_parse_encryption_algorithm_aes256_cbc() {
        assert!(matches!(
            parse_encryption_algorithm("aes-256-cbc", &[0; 32]),
            Ok(EncryptionAlgorithm::Aes256Cbc)
        ));
        assert!(parse_encryption_algorithm("aes-256-cbc", &[0; 16]).is_err());
    }

    #[test]
    fn test_parse_encryption_algorithm_aes128_gcm() {
        let key = [0u8; 20]; // 16 enc + 4 salt
        let result = parse_encryption_algorithm("aes-128-gcm", &key).unwrap();
        assert!(matches!(result, EncryptionAlgorithm::Aes128Gcm { .. }));
        assert!(parse_encryption_algorithm("aes-128-gcm", &[0; 16]).is_err());
    }

    #[test]
    fn test_parse_encryption_algorithm_aes256_gcm() {
        let key = [0u8; 36]; // 32 enc + 4 salt
        let result = parse_encryption_algorithm("aes-256-gcm", &key).unwrap();
        assert!(matches!(result, EncryptionAlgorithm::Aes256Gcm { .. }));
        assert!(parse_encryption_algorithm("aes-256-gcm", &[0; 32]).is_err());
    }

    #[test]
    fn test_parse_authentication_algorithm() {
        assert!(matches!(
            parse_authentication_algorithm("none", &[]),
            Ok(AuthenticationAlgorithm::None)
        ));
        assert!(matches!(
            parse_authentication_algorithm("hmac-sha1-96", &[0; 20]),
            Ok(AuthenticationAlgorithm::HmacSha1_96)
        ));
        assert!(parse_authentication_algorithm("hmac-sha1-96", &[0; 10]).is_err());
    }

    #[test]
    fn test_parse_authentication_algorithm_hmac_sha256() {
        assert!(matches!(
            parse_authentication_algorithm("hmac-sha256-128", &[0; 32]),
            Ok(AuthenticationAlgorithm::HmacSha256_128)
        ));
        assert!(parse_authentication_algorithm("hmac-sha256-128", &[0; 16]).is_err());
    }

    #[test]
    fn test_parse_authentication_algorithm_unknown() {
        assert!(parse_authentication_algorithm("unknown", &[]).is_err());
    }

    #[test]
    fn test_cbc_decryption_aes192() {
        use aes::Aes192;
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

        let key = [0x01u8; 24];
        let iv = [0x02u8; 16];

        let mut plaintext = vec![0x45; 12];
        plaintext.extend_from_slice(&[0x01, 0x02]);
        plaintext.push(2);
        plaintext.push(4);

        let mut ciphertext = plaintext.clone();
        cbc::Encryptor::<Aes192>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, 16)
            .unwrap();

        let mut data = iv.to_vec();
        data.extend_from_slice(&ciphertext);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes192Cbc,
            enc_key: key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45; 12]);
    }

    #[test]
    fn test_cbc_decryption_aes256() {
        use aes::Aes256;
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

        let key = [0x01u8; 32];
        let iv = [0x02u8; 16];

        let mut plaintext = vec![0x45; 12];
        plaintext.extend_from_slice(&[0x01, 0x02]);
        plaintext.push(2);
        plaintext.push(4);

        let mut ciphertext = plaintext.clone();
        cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, 16)
            .unwrap();

        let mut data = iv.to_vec();
        data.extend_from_slice(&ciphertext);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes256Cbc,
            enc_key: key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45; 12]);
    }

    #[test]
    fn test_gcm_decryption_aes256() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        let enc_key = [0x03u8; 32];
        let salt = [0x04u8; 4];
        let packet_iv = [0x05u8; 8];
        let spi: u32 = 0x1234;
        let seq: u32 = 1;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&salt);
        nonce_bytes[4..].copy_from_slice(&packet_iv);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = [0u8; 8];
        aad[..4].copy_from_slice(&spi.to_be_bytes());
        aad[4..].copy_from_slice(&seq.to_be_bytes());

        let plaintext_inner = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x04];

        let cipher = Aes256Gcm::new_from_slice(&enc_key).unwrap();
        let ciphertext_and_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext_inner,
                    aad: &aad,
                },
            )
            .unwrap();

        let mut data = packet_iv.to_vec();
        data.extend_from_slice(&ciphertext_and_tag);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes256Gcm { salt },
            enc_key: enc_key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let result = decrypt_esp(&sa, spi, seq, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.payload, vec![0x45, 0x00, 0x00, 0x28]);
    }

    #[test]
    fn test_cbc_ciphertext_not_block_aligned() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        // IV(16) + non-aligned ciphertext (15 bytes)
        let mut data = iv.to_vec();
        data.extend_from_slice(&[0xAA; 15]);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes128Cbc,
            enc_key: key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let err = decrypt_esp(&sa, 1, 1, &data).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_cbc_unsupported_key_length() {
        let iv = [0x02u8; 16];
        let mut data = iv.to_vec();
        data.extend_from_slice(&[0xAA; 16]);

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes128Cbc,
            enc_key: vec![0; 10], // wrong key length
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let err = decrypt_esp(&sa, 1, 1, &data).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_gcm_unsupported_key_length() {
        let salt = [0x04u8; 4];
        let packet_iv = [0x05u8; 8];
        let mut data = packet_iv.to_vec();
        data.extend_from_slice(&[0xAA; 18]); // need at least 16 tag + 2 trailer

        let sa = EspSa {
            encryption: EncryptionAlgorithm::Aes128Gcm { salt },
            enc_key: vec![0; 24], // wrong key length (not 16 or 32)
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
        };

        let err = decrypt_esp(&sa, 1, 1, &data).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_null_decryption_with_hmac_sha256() {
        let sa = EspSa {
            encryption: EncryptionAlgorithm::Null,
            enc_key: vec![],
            authentication: AuthenticationAlgorithm::HmacSha256_128,
            auth_key: vec![0; 32],
        };
        // payload + trailer + 16-byte ICV
        let mut data = vec![0x45, 0x00, 0x00, 0x04];
        data.extend_from_slice(&[0xBB; 16]); // ICV
        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_iv_len() {
        assert_eq!(EncryptionAlgorithm::Null.iv_len(), 0);
        assert_eq!(EncryptionAlgorithm::Aes128Cbc.iv_len(), 16);
        assert_eq!(EncryptionAlgorithm::Aes192Cbc.iv_len(), 16);
        assert_eq!(EncryptionAlgorithm::Aes256Cbc.iv_len(), 16);
        assert_eq!(EncryptionAlgorithm::Aes128Gcm { salt: [0; 4] }.iv_len(), 8);
        assert_eq!(EncryptionAlgorithm::Aes256Gcm { salt: [0; 4] }.iv_len(), 8);
    }

    #[test]
    fn test_is_aead() {
        assert!(!EncryptionAlgorithm::Null.is_aead());
        assert!(!EncryptionAlgorithm::Aes128Cbc.is_aead());
        assert!(EncryptionAlgorithm::Aes128Gcm { salt: [0; 4] }.is_aead());
        assert!(EncryptionAlgorithm::Aes256Gcm { salt: [0; 4] }.is_aead());
    }

    #[test]
    fn test_icv_len() {
        assert_eq!(AuthenticationAlgorithm::None.icv_len(), 0);
        assert_eq!(AuthenticationAlgorithm::HmacSha1_96.icv_len(), 12);
        assert_eq!(AuthenticationAlgorithm::HmacSha256_128.icv_len(), 16);
    }

    #[test]
    fn test_try_null_decrypt_basic() {
        // payload=[0x45, 0x00], pad_length=0, next_header=6 (TCP)
        let data = [0x45, 0x00, 0x00, 0x06];
        let result = try_null_decrypt(&data).unwrap();
        assert_eq!(result.next_header, 6);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_try_null_decrypt_with_padding() {
        // payload=[0x45], padding=[0x01, 0x02], pad_length=2, next_header=6 (TCP)
        let data = [0x45, 0x01, 0x02, 0x02, 0x06];
        let result = try_null_decrypt(&data).unwrap();
        assert_eq!(result.next_header, 6);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45]);
    }

    #[test]
    fn test_try_null_decrypt_unknown_next_header() {
        // next_header=0xFF (not in ip_protocol_name lookup)
        let data = [0x45, 0x00, 0x00, 0xFF];
        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_bad_padding_pattern() {
        // Padding bytes don't follow RFC 4303 pattern: [0x03, 0x02] != [0x01, 0x02]
        let data = [0x45, 0x03, 0x02, 0x02, 0x06];
        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_too_short() {
        assert!(try_null_decrypt(&[0x06]).is_none());
    }

    #[test]
    fn test_try_null_decrypt_empty() {
        assert!(try_null_decrypt(&[]).is_none());
    }

    #[test]
    fn test_try_null_decrypt_pad_length_exceeds_data() {
        // pad_length=100 but only 4 bytes total
        let data = [0x45, 0x00, 100, 0x06];
        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_valid_large_padding() {
        // payload=[0xAA], padding=[0x01, 0x02, 0x03, 0x04], pad_length=4, next_header=17 (UDP)
        let data = [0xAA, 0x01, 0x02, 0x03, 0x04, 0x04, 0x11];
        let result = try_null_decrypt(&data).unwrap();
        assert_eq!(result.next_header, 17);
        assert_eq!(result.pad_length, 4);
        assert_eq!(result.payload, vec![0xAA]);
    }

    #[test]
    fn test_try_null_decrypt_ipv4_encap() {
        // next_header=4 (IPv4-in-IPv4, RFC 2003)
        let data = [0x45, 0x00, 0x00, 0x04];
        let result = try_null_decrypt(&data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_try_null_decrypt_hopopt_excluded() {
        // next_header=0 (HOPOPT) is intentionally rejected by the heuristic
        // to prevent false positives on zero-filled ciphertext.
        let data = [0x00; 16];
        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_nonxt_excluded() {
        // next_header=59 (IPv6_NONXT) is excluded: no dispatch target.
        let data = [0x45, 0x00, 0x00, 59];
        assert!(try_null_decrypt(&data).is_none());
    }
}
