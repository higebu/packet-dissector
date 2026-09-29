//! ESP decryption support.
//!
//! Provides decryption for ESP payloads using pre-shared Security Association
//! (SA) parameters. Supports AES-CBC, 3DES-CBC, AES-CTR, AES-GCM (8/12/16
//! octet ICV), AES-CCM, ChaCha20-Poly1305 and ENCR_NULL_AUTH_AES_GMAC, with
//! optional Extended Sequence Numbers for the AEAD AAD. Integrity check values
//! of the HMAC transforms are located but not verified.
//!
//! ## References
//! - RFC 4303, Section 2.2.1 (Extended Sequence Numbers):
//!   <https://www.rfc-editor.org/rfc/rfc4303#section-2.2.1>
//! - RFC 8221: Cryptographic Algorithm Implementation Requirements for ESP and AH:
//!   <https://www.rfc-editor.org/rfc/rfc8221>
//! - RFC 2451: The ESP CBC-Mode Cipher Algorithms (3DES-CBC):
//!   <https://www.rfc-editor.org/rfc/rfc2451>
//! - RFC 3686: Using AES Counter Mode With IPsec ESP:
//!   <https://www.rfc-editor.org/rfc/rfc3686>
//! - RFC 4309: Using AES CCM Mode with IPsec ESP:
//!   <https://www.rfc-editor.org/rfc/rfc4309>
//! - RFC 4543: The Use of GMAC in IPsec ESP and AH:
//!   <https://www.rfc-editor.org/rfc/rfc4543>
//! - RFC 7634: ChaCha20, Poly1305, and Their Use in IKE and IPsec:
//!   <https://www.rfc-editor.org/rfc/rfc7634>
//! - RFC 2403 (HMAC-MD5-96): <https://www.rfc-editor.org/rfc/rfc2403>
//! - RFC 2404 (HMAC-SHA-1-96): <https://www.rfc-editor.org/rfc/rfc2404>
//! - RFC 4868 (HMAC-SHA-256/384/512): <https://www.rfc-editor.org/rfc/rfc4868>
//! - RFC 3602: The AES-CBC Cipher Algorithm and Its Use with IPsec:
//!   <https://www.rfc-editor.org/rfc/rfc3602>
//! - RFC 4106: The Use of Galois/Counter Mode (GCM) in IPsec ESP:
//!   <https://www.rfc-editor.org/rfc/rfc4106>
//! - RFC 2410: The NULL Encryption Algorithm and Its Use With IPsec:
//!   <https://www.rfc-editor.org/rfc/rfc2410>

use packet_dissector_core::error::PacketError;
use packet_dissector_core::lookup::ip_protocol_name;

/// IP protocol number for HOPOPT (IPv6 Hop-by-Hop Options, RFC 8200).
/// <https://www.rfc-editor.org/rfc/rfc8200>
const IP_PROTO_HOPOPT: u8 = 0;

/// IP protocol number for IPv4 (RFC 2003, IP-in-IP encapsulation).
/// <https://www.rfc-editor.org/rfc/rfc2003>
const IP_PROTO_IPV4: u8 = 4;

/// IP protocol number for TCP (RFC 9293).
/// <https://www.rfc-editor.org/rfc/rfc9293>
const IP_PROTO_TCP: u8 = 6;

/// IP protocol number for UDP (RFC 768).
const IP_PROTO_UDP: u8 = 17;

/// IP protocol number for IPv6 encapsulation (RFC 2473).
/// <https://www.rfc-editor.org/rfc/rfc2473>
const IP_PROTO_IPV6: u8 = 41;

/// IP protocol number for "no next header" (RFC 8200, Section 4.7).
///
/// Per RFC 4303, Section 2.6, this value is also mandated for ESP "dummy"
/// packets used to support traffic flow confidentiality: "the protocol
/// value 59 (which means 'no next header') MUST be used to designate a
/// 'dummy' packet."
/// <https://www.rfc-editor.org/rfc/rfc4303#section-2.6>
/// <https://www.rfc-editor.org/rfc/rfc8200#section-4.7>
const IP_PROTO_IPV6_NONXT: u8 = 59;

/// ICV length of an AEAD transform.
///
/// RFC 4106, Section 6 — "Implementations MUST support a full-length
/// 16-octet ICV, and MAY support 8 or 12 octet ICVs, and MUST NOT support
/// other ICV lengths." RFC 4309, Section 3 allows the same three lengths
/// for AES-CCM.
/// <https://www.rfc-editor.org/rfc/rfc4106#section-6>
/// <https://www.rfc-editor.org/rfc/rfc4309#section-3>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadIcvLen {
    /// 8-octet ICV (64 bits).
    Octets8,
    /// 12-octet ICV (96 bits).
    Octets12,
    /// 16-octet ICV (128 bits).
    Octets16,
}

impl AeadIcvLen {
    /// Returns the ICV length in bytes.
    pub fn octets(self) -> usize {
        match self {
            Self::Octets8 => 8,
            Self::Octets12 => 12,
            Self::Octets16 => 16,
        }
    }
}

/// Encryption algorithm for an ESP Security Association.
///
/// RFC 8221, Section 5 lists the ESP encryption algorithm requirements:
/// <https://www.rfc-editor.org/rfc/rfc8221#section-5>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// No encryption (RFC 2410). Payload is plaintext.
    /// <https://www.rfc-editor.org/rfc/rfc2410>
    Null,
    /// AES-128-CBC (RFC 3602). IV = 16 bytes, key = 16 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc3602>
    Aes128Cbc,
    /// AES-192-CBC (RFC 3602). IV = 16 bytes, key = 24 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc3602>
    Aes192Cbc,
    /// AES-256-CBC (RFC 3602). IV = 16 bytes, key = 32 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc3602>
    Aes256Cbc,
    /// AES-128-GCM (RFC 4106). IV = 8 bytes in packet, salt = 4 bytes, key = 16 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4106>
    Aes128Gcm {
        /// 4-byte salt prepended to the 8-byte IV from the packet to form a 12-byte nonce.
        salt: [u8; 4],
        /// ICV (authentication tag) length.
        icv_len: AeadIcvLen,
    },
    /// AES-192-GCM (RFC 4106, Section 8.1). IV = 8 bytes in packet,
    /// salt = 4 bytes, key = 24 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4106#section-8.1>
    Aes192Gcm {
        /// 4-byte salt prepended to the 8-byte IV from the packet to form a 12-byte nonce.
        salt: [u8; 4],
        /// ICV (authentication tag) length.
        icv_len: AeadIcvLen,
    },
    /// AES-256-GCM (RFC 4106). IV = 8 bytes in packet, salt = 4 bytes, key = 32 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4106>
    Aes256Gcm {
        /// 4-byte salt prepended to the 8-byte IV from the packet to form a 12-byte nonce.
        salt: [u8; 4],
        /// ICV (authentication tag) length.
        icv_len: AeadIcvLen,
    },
    /// 3DES-CBC (RFC 2451). IV = 8 bytes, key = 24 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc2451>
    TripleDesCbc,
    /// AES-128-CTR (RFC 3686). IV = 8 bytes in packet, nonce = 4 bytes, key = 16 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc3686>
    Aes128Ctr {
        /// 4-byte nonce from the keying material (RFC 3686, Section 4).
        /// <https://www.rfc-editor.org/rfc/rfc3686>
        nonce: [u8; 4],
    },
    /// AES-192-CTR (RFC 3686). IV = 8 bytes in packet, nonce = 4 bytes, key = 24 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc3686>
    Aes192Ctr {
        /// 4-byte nonce from the keying material (RFC 3686, Section 4).
        /// <https://www.rfc-editor.org/rfc/rfc3686>
        nonce: [u8; 4],
    },
    /// AES-256-CTR (RFC 3686). IV = 8 bytes in packet, nonce = 4 bytes, key = 32 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc3686>
    Aes256Ctr {
        /// 4-byte nonce from the keying material (RFC 3686, Section 4).
        /// <https://www.rfc-editor.org/rfc/rfc3686>
        nonce: [u8; 4],
    },
    /// AES-128-CCM (RFC 4309). IV = 8 bytes in packet, salt = 3 bytes, key = 16 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4309>
    Aes128Ccm {
        /// 3-byte salt prepended to the 8-byte IV to form the 11-byte nonce.
        salt: [u8; 3],
        /// ICV length.
        icv_len: AeadIcvLen,
    },
    /// AES-192-CCM (RFC 4309). IV = 8 bytes in packet, salt = 3 bytes, key = 24 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4309>
    Aes192Ccm {
        /// 3-byte salt prepended to the 8-byte IV to form the 11-byte nonce.
        salt: [u8; 3],
        /// ICV length.
        icv_len: AeadIcvLen,
    },
    /// AES-256-CCM (RFC 4309). IV = 8 bytes in packet, salt = 3 bytes, key = 32 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4309>
    Aes256Ccm {
        /// 3-byte salt prepended to the 8-byte IV to form the 11-byte nonce.
        salt: [u8; 3],
        /// ICV length.
        icv_len: AeadIcvLen,
    },
    /// ChaCha20-Poly1305 (RFC 7634). IV = 8 bytes in packet, salt = 4 bytes,
    /// key = 32 bytes, ICV = 16 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc7634>
    ChaCha20Poly1305 {
        /// 4-byte salt prepended to the 8-byte IV to form the 12-byte nonce.
        salt: [u8; 4],
    },
    /// ENCR_NULL_AUTH_AES_GMAC with a 128-bit key (RFC 4543). The payload is
    /// not encrypted; IV = 8 bytes, ICV = 16 bytes.
    /// <https://www.rfc-editor.org/rfc/rfc4543>
    Aes128Gmac {
        /// 4-byte salt (RFC 4543, Section 3.2).
        /// <https://www.rfc-editor.org/rfc/rfc4543#section-3.2>
        salt: [u8; 4],
    },
    /// ENCR_NULL_AUTH_AES_GMAC with a 192-bit key (RFC 4543).
    /// <https://www.rfc-editor.org/rfc/rfc4543>
    Aes192Gmac {
        /// 4-byte salt (RFC 4543, Section 3.2).
        /// <https://www.rfc-editor.org/rfc/rfc4543#section-3.2>
        salt: [u8; 4],
    },
    /// ENCR_NULL_AUTH_AES_GMAC with a 256-bit key (RFC 4543).
    /// <https://www.rfc-editor.org/rfc/rfc4543>
    Aes256Gmac {
        /// 4-byte salt (RFC 4543, Section 3.2).
        /// <https://www.rfc-editor.org/rfc/rfc4543#section-3.2>
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
    /// HMAC-MD5 with 96-bit ICV (RFC 2403).
    /// <https://www.rfc-editor.org/rfc/rfc2403>
    HmacMd5_96,
    /// HMAC-SHA-1 with 96-bit ICV (RFC 2404).
    /// <https://www.rfc-editor.org/rfc/rfc2404>
    HmacSha1_96,
    /// HMAC-SHA-256 with 128-bit ICV (RFC 4868).
    /// <https://www.rfc-editor.org/rfc/rfc4868>
    HmacSha256_128,
    /// HMAC-SHA-384 with 192-bit ICV (RFC 4868).
    /// <https://www.rfc-editor.org/rfc/rfc4868>
    HmacSha384_192,
    /// HMAC-SHA-512 with 256-bit ICV (RFC 4868).
    /// <https://www.rfc-editor.org/rfc/rfc4868>
    HmacSha512_256,
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
    /// Extended Sequence Numbers: `Some(high)` when ESN is negotiated, where
    /// `high` is the high-order 32 bits of the 64-bit sequence number
    /// (usually 0 early in the SA's life); `None` for 32-bit sequence
    /// numbers.
    ///
    /// RFC 4303, Section 2.2.1 — "Only the low-order 32 bits of the sequence
    /// number are transmitted in the plaintext ESP header of each packet". A stateless dissector
    /// cannot track the high-order bits, so they are configured here. Only
    /// the AEAD transforms use them (in the AAD, RFC 4106, Section 5).
    /// <https://www.rfc-editor.org/rfc/rfc4303#section-2.2.1>
    /// <https://www.rfc-editor.org/rfc/rfc4106>
    pub esn: Option<u32>,
}

impl EncryptionAlgorithm {
    /// Returns the IV length in bytes for this algorithm as present in the packet.
    pub fn iv_len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => 16,
            // RFC 2451, Section 2 — 64-bit IV for 3DES-CBC.
            // <https://www.rfc-editor.org/rfc/rfc2451#section-2>
            // RFC 3686, Section 3.1 — 8-octet IV for AES-CTR.
            // <https://www.rfc-editor.org/rfc/rfc3686#section-3.1>
            // RFC 4106, Section 3.1 — 8-octet IV for AES-GCM.
            // <https://www.rfc-editor.org/rfc/rfc4106#section-3.1>
            // RFC 4309, Section 3.1 — 8-octet IV for AES-CCM.
            // <https://www.rfc-editor.org/rfc/rfc4309#section-3.1>
            // RFC 7634, Section 2 — 8-octet IV for ChaCha20-Poly1305.
            // <https://www.rfc-editor.org/rfc/rfc7634#section-2>
            // RFC 4543, Section 3.1 — "The IV MUST be eight octets long."
            // <https://www.rfc-editor.org/rfc/rfc4543#section-3.1>
            Self::TripleDesCbc
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. }
            | Self::Aes128Gcm { .. }
            | Self::Aes192Gcm { .. }
            | Self::Aes256Gcm { .. }
            | Self::Aes128Ccm { .. }
            | Self::Aes192Ccm { .. }
            | Self::Aes256Ccm { .. }
            | Self::ChaCha20Poly1305 { .. }
            | Self::Aes128Gmac { .. }
            | Self::Aes192Gmac { .. }
            | Self::Aes256Gmac { .. } => 8,
        }
    }

    /// Returns true if this is an AEAD cipher (combined encryption + authentication).
    ///
    /// ENCR_NULL_AUTH_AES_GMAC is a combined-mode transform (RFC 4543) even
    /// though it does not encrypt.
    /// <https://www.rfc-editor.org/rfc/rfc4543>
    pub fn is_aead(&self) -> bool {
        self.aead_icv_len().is_some()
    }

    /// Returns the ICV length of an AEAD transform, or `None` for
    /// non-AEAD transforms (whose ICV comes from the authentication
    /// algorithm).
    pub fn aead_icv_len(&self) -> Option<usize> {
        match self {
            Self::Aes128Gcm { icv_len, .. }
            | Self::Aes192Gcm { icv_len, .. }
            | Self::Aes256Gcm { icv_len, .. }
            | Self::Aes128Ccm { icv_len, .. }
            | Self::Aes192Ccm { icv_len, .. }
            | Self::Aes256Ccm { icv_len, .. } => Some(icv_len.octets()),
            // RFC 7634, Section 2 — 16-octet tag.
            // <https://www.rfc-editor.org/rfc/rfc7634#section-2>
            // RFC 4543, Section 3.4 — "the length of the ICV is 16 octets".
            // <https://www.rfc-editor.org/rfc/rfc4543#section-3.4>
            Self::ChaCha20Poly1305 { .. }
            | Self::Aes128Gmac { .. }
            | Self::Aes192Gmac { .. }
            | Self::Aes256Gmac { .. } => Some(16),
            Self::Null
            | Self::Aes128Cbc
            | Self::Aes192Cbc
            | Self::Aes256Cbc
            | Self::TripleDesCbc
            | Self::Aes128Ctr { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes256Ctr { .. } => None,
        }
    }

    /// Returns the encryption key length in bytes required by this
    /// algorithm (excluding any salt / nonce), or `None` for NULL.
    pub fn key_len(&self) -> Option<usize> {
        match self {
            Self::Null => None,
            Self::Aes128Cbc
            | Self::Aes128Gcm { .. }
            | Self::Aes128Ctr { .. }
            | Self::Aes128Ccm { .. }
            | Self::Aes128Gmac { .. } => Some(16),
            Self::Aes192Cbc
            | Self::Aes192Gcm { .. }
            | Self::Aes192Ctr { .. }
            | Self::Aes192Ccm { .. }
            | Self::Aes192Gmac { .. }
            | Self::TripleDesCbc => Some(24),
            Self::Aes256Cbc
            | Self::Aes256Gcm { .. }
            | Self::Aes256Ctr { .. }
            | Self::Aes256Ccm { .. }
            | Self::Aes256Gmac { .. }
            | Self::ChaCha20Poly1305 { .. } => Some(32),
        }
    }
}

impl AuthenticationAlgorithm {
    /// Returns the ICV (Integrity Check Value) length in bytes.
    pub fn icv_len(&self) -> usize {
        match self {
            Self::None => 0,
            // RFC 2403, Section 2 / RFC 2404, Section 2 — 96-bit truncation.
            // <https://www.rfc-editor.org/rfc/rfc2403#section-2>
            // <https://www.rfc-editor.org/rfc/rfc2404>
            Self::HmacMd5_96 | Self::HmacSha1_96 => 12,
            // RFC 4868, Section 2.3 — truncation to half the output length.
            // <https://www.rfc-editor.org/rfc/rfc4868#section-2.3>
            Self::HmacSha256_128 => 16,
            Self::HmacSha384_192 => 24,
            Self::HmacSha512_256 => 32,
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
    /// Length in bytes of the ICV that follows the trailer on the wire.
    ///
    /// Callers use this to locate the trailer's original position inside the
    /// ESP packet: the Next Header byte sits `icv_len + 1` bytes from the end.
    /// It is the SA's configured ICV length on the keyed paths, and the length
    /// detected by [`try_null_decrypt`] on the heuristic path.
    pub icv_len: usize,
}

/// Decrypt an ESP payload.
///
/// # Arguments
/// * `sa` — Security Association parameters
/// * `spi` — Security Parameters Index (for the AEAD AAD)
/// * `seq` — Sequence number as carried in the packet (the low-order 32
///   bits when ESN is in use; the high-order bits come from [`EspSa::esn`])
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
    // The key size is part of the algorithm; a mismatching key is a
    // misconfigured SA rather than a different AES variant. GMAC does not
    // decrypt and so does not use the key.
    if let Some(key_len) = sa.encryption.key_len() {
        if sa.enc_key.len() != key_len && !is_gmac(&sa.encryption) {
            return Err(PacketError::InvalidHeader(
                "ESP: encryption key length does not match the algorithm",
            ));
        }
    }
    match &sa.encryption {
        EncryptionAlgorithm::Null => decrypt_null(sa, encrypted_data),
        EncryptionAlgorithm::Aes128Gmac { .. }
        | EncryptionAlgorithm::Aes192Gmac { .. }
        | EncryptionAlgorithm::Aes256Gmac { .. } => decrypt_gmac(encrypted_data),
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::Aes128Cbc
        | EncryptionAlgorithm::Aes192Cbc
        | EncryptionAlgorithm::Aes256Cbc
        | EncryptionAlgorithm::TripleDesCbc => decrypt_cbc(sa, encrypted_data),
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::Aes128Ctr { nonce }
        | EncryptionAlgorithm::Aes192Ctr { nonce }
        | EncryptionAlgorithm::Aes256Ctr { nonce } => decrypt_ctr(sa, nonce, encrypted_data),
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::Aes128Gcm { salt, icv_len }
        | EncryptionAlgorithm::Aes192Gcm { salt, icv_len }
        | EncryptionAlgorithm::Aes256Gcm { salt, icv_len } => {
            let aad = build_aad(spi, seq, sa.esn);
            decrypt_gcm(sa, aad.as_slice(), salt, *icv_len, encrypted_data)
        }
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::Aes128Ccm { salt, icv_len }
        | EncryptionAlgorithm::Aes192Ccm { salt, icv_len }
        | EncryptionAlgorithm::Aes256Ccm { salt, icv_len } => {
            let aad = build_aad(spi, seq, sa.esn);
            decrypt_ccm(sa, aad.as_slice(), salt, *icv_len, encrypted_data)
        }
        #[cfg(any(feature = "decrypt", test))]
        EncryptionAlgorithm::ChaCha20Poly1305 { salt } => {
            let aad = build_aad(spi, seq, sa.esn);
            decrypt_chacha20_poly1305(sa, aad.as_slice(), salt, encrypted_data)
        }
        #[cfg(not(any(feature = "decrypt", test)))]
        _ => {
            // SPI and sequence number only feed the AEAD AAD.
            let _ = (spi, seq);
            Err(PacketError::InvalidHeader(
                "ESP decryption requires the 'decrypt' feature",
            ))
        }
    }
}

fn is_gmac(alg: &EncryptionAlgorithm) -> bool {
    matches!(
        alg,
        EncryptionAlgorithm::Aes128Gmac { .. }
            | EncryptionAlgorithm::Aes192Gmac { .. }
            | EncryptionAlgorithm::Aes256Gmac { .. }
    )
}

/// Additional Authenticated Data of the AEAD transforms.
///
/// RFC 4106, Section 5 — "Two formats of the AAD are defined: one for
/// 32-bit sequence numbers, and one for 64-bit extended sequence numbers."
/// SPI(4) || Seq(4), or SPI(4) || ESN high(4) || ESN low(4). RFC 4309,
/// Section 5 and RFC 7634, Section 2.1 use the same AAD.
/// <https://www.rfc-editor.org/rfc/rfc4106#section-5>
/// <https://www.rfc-editor.org/rfc/rfc7634#section-2.1>
/// <https://www.rfc-editor.org/rfc/rfc4309>
#[cfg(any(feature = "decrypt", test))]
struct Aad {
    bytes: [u8; 12],
    len: usize,
}

#[cfg(any(feature = "decrypt", test))]
impl Aad {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(any(feature = "decrypt", test))]
fn build_aad(spi: u32, seq: u32, esn_high: Option<u32>) -> Aad {
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(&spi.to_be_bytes());
    match esn_high {
        Some(high) => {
            bytes[4..8].copy_from_slice(&high.to_be_bytes());
            bytes[8..12].copy_from_slice(&seq.to_be_bytes());
            Aad { bytes, len: 12 }
        }
        None => {
            bytes[4..8].copy_from_slice(&seq.to_be_bytes());
            Aad { bytes, len: 8 }
        }
    }
}

/// ENCR_NULL_AUTH_AES_GMAC — the payload is not encrypted.
///
/// RFC 4543, Section 3.5 — "the AES-GCM plaintext is zero-length": the ESP
/// payload between the 8-octet IV and the 16-octet ICV is plaintext. Like
/// the HMAC transforms, the ICV is located but not verified.
/// <https://www.rfc-editor.org/rfc/rfc4543#section-3.5>
fn decrypt_gmac(data: &[u8]) -> Result<DecryptedEsp, PacketError> {
    const GMAC_IV_LEN: usize = 8;
    const GMAC_ICV_LEN: usize = 16;
    if data.len() < GMAC_IV_LEN + 2 + GMAC_ICV_LEN {
        return Err(PacketError::InvalidHeader(
            "ESP GMAC: data too short for IV + trailer + ICV",
        ));
    }
    let plaintext = data[GMAC_IV_LEN..data.len() - GMAC_ICV_LEN].to_vec();
    extract_trailer(plaintext, GMAC_ICV_LEN)
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
    extract_trailer(plaintext, icv_len)
}

/// ICV lengths the NULL heuristic considers, in ascending order.
///
/// `0` covers ESP without integrity protection. The non-zero entries are the
/// ICV lengths of the integrity algorithms IPsec deploys in practice:
///
/// - 12 bytes — 96-bit ICVs: HMAC-MD5-96 (RFC 2403), HMAC-SHA-1-96
///   (RFC 2404), AES-XCBC-MAC-96 (RFC 3566).
/// - 16, 24, 32 bytes — HMAC-SHA-256-128, HMAC-SHA-384-192 and
///   HMAC-SHA-512-256 (RFC 4868, Section 2.3).
///
/// <https://www.rfc-editor.org/rfc/rfc2403>
/// <https://www.rfc-editor.org/rfc/rfc2404>
/// <https://www.rfc-editor.org/rfc/rfc3566>
/// <https://www.rfc-editor.org/rfc/rfc4868#section-2.3>
const NULL_HEURISTIC_ICV_LENS: [usize; 5] = [0, 12, 16, 24, 32];

/// Validate the two bytes preceding a candidate ICV as an ESP trailer.
///
/// Returns `(payload_end, next_header, pad_length)` where `payload_end` is the
/// offset at which the padding starts, i.e. the exclusive end of the inner
/// payload. Never allocates.
///
/// # References
/// - RFC 4303, Section 2.4 (Padding):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.4>
/// - RFC 4303, Section 2.5 (Pad Length):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.5>
/// - RFC 4303, Section 2.6 (Next Header):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.6>
fn null_trailer_at(data: &[u8], icv_len: usize) -> Option<(usize, u8, usize)> {
    let trailer_end = data.len().checked_sub(icv_len)?;
    if trailer_end < 2 {
        return None;
    }

    let next_header = data[trailer_end - 1];
    let pad_length = data[trailer_end - 2] as usize;

    ip_protocol_name(next_header)?;

    // HOPOPT matches any zero-filled trailer (extremely common in random
    // ciphertext), and IPv6_NONXT has no dispatch target.
    if next_header == IP_PROTO_HOPOPT || next_header == IP_PROTO_IPV6_NONXT {
        return None;
    }

    if pad_length + 2 > trailer_end {
        return None;
    }

    let payload_end = trailer_end - 2 - pad_length;
    for (i, &b) in data[payload_end..trailer_end - 2].iter().enumerate() {
        if b as usize != i + 1 {
            return None;
        }
    }

    Some((payload_end, next_header, pad_length))
}

/// Corroborate a candidate ESP trailer against the payload it would expose.
///
/// Returns `true` only when the inner header carries a self-describing length
/// (or an equivalent structural invariant) that matches `payload` exactly.
/// Protocols without one return `false`, which keeps the heuristic from
/// guessing an ICV length it cannot verify.
fn inner_header_matches(next_header: u8, payload: &[u8]) -> bool {
    match next_header {
        // RFC 791, Section 3.1 — Version, IHL and Total Length.
        // <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
        IP_PROTO_IPV4 => {
            const MIN_IHL: usize = 5;
            if payload.len() < MIN_IHL * 4 {
                return false;
            }
            let ihl = (payload[0] & 0x0F) as usize;
            payload[0] >> 4 == 4
                && ihl >= MIN_IHL
                && ihl * 4 <= payload.len()
                && u16::from_be_bytes([payload[2], payload[3]]) as usize == payload.len()
        }
        // RFC 8200, Section 3 — Version and Payload Length (excludes the
        // 40-byte fixed header).
        // <https://www.rfc-editor.org/rfc/rfc8200#section-3>
        IP_PROTO_IPV6 => {
            const HEADER_LEN: usize = 40;
            payload.len() >= HEADER_LEN
                && payload[0] >> 4 == 6
                && HEADER_LEN + u16::from_be_bytes([payload[4], payload[5]]) as usize
                    == payload.len()
        }
        // RFC 768 — Length covers the UDP header and data.
        // <https://www.rfc-editor.org/rfc/rfc768>
        IP_PROTO_UDP => {
            const HEADER_LEN: usize = 8;
            payload.len() >= HEADER_LEN
                && u16::from_be_bytes([payload[4], payload[5]]) as usize == payload.len()
        }
        // RFC 9293, Section 3.1 — Data Offset (>= 5 and within the segment)
        // and the reserved bits sharing its byte, which are sent as zero.
        // <https://www.rfc-editor.org/rfc/rfc9293#section-3.1>
        IP_PROTO_TCP => {
            const MIN_DATA_OFFSET: usize = 5;
            if payload.len() < MIN_DATA_OFFSET * 4 {
                return false;
            }
            let data_offset = (payload[12] >> 4) as usize;
            data_offset >= MIN_DATA_OFFSET
                && data_offset * 4 <= payload.len()
                && payload[12] & 0x0F == 0
        }
        _ => false,
    }
}

/// Heuristically attempt to decode ESP payload as NULL-encrypted plaintext.
///
/// When no Security Association is configured for the packet's SPI, this
/// function treats the raw payload (everything after the 8-byte ESP header)
/// as plaintext and tries to extract the ESP trailer. Inspired by passive
/// capture analysers such as Wireshark, it enables inner packet dissection
/// of NULL-encrypted ESP flows without pre-configuring an SA.
///
/// # ICV detection
///
/// With `ealg=null` the payload is plaintext whether or not the SA also
/// applies an integrity algorithm, but an ICV shifts the trailer away from
/// the end of the packet and its length is not carried on the wire. Each
/// candidate length (0, 12, 16, 24, 32) is therefore tried in turn:
///
/// - A candidate whose payload is corroborated by its own inner header
///   (a self-describing length that matches exactly) wins immediately,
///   at any ICV length.
/// - An uncorroborated candidate is accepted only at `icv_len == 0`, where
///   the trailer sits at the true end of the ESP payload and the checks
///   below stand on their own. Guessing a non-zero ICV length without
///   corroboration would invent a trailer position, so it is never done.
///
/// # Validation
///
/// A candidate trailer requires ALL of:
///
/// 1. Room for `pad_length` and `next_header` ahead of the candidate ICV.
/// 2. `next_header` is a well-known IP protocol number recognised by
///    [`ip_protocol_name`]. This rejects the vast majority of random bytes
///    that would otherwise appear as valid trailers.
/// 3. `next_header` is not in the small set of values that are either
///    unlikely to appear as an ESP inner protocol or are strongly biased
///    towards false positives on zero-filled ciphertext: HOPOPT (0),
///    IPv6_NONXT (59). HOPOPT in particular matches any payload whose
///    final byte is `0x00`, which is extremely common in random data.
/// 4. The padding field does not overrun the payload.
/// 5. Padding bytes match the monotonically increasing sequence
///    `1, 2, 3, ..., pad_length` mandated by RFC 4303 Section 2.4.
///
/// Nothing is allocated until a candidate is accepted.
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
/// - RFC 4303, Section 2.8 (Integrity Check Value):
///   <https://www.rfc-editor.org/rfc/rfc4303#section-2.8>
///
/// <https://www.rfc-editor.org/rfc/rfc4303#section-2.4>
pub fn try_null_decrypt(data: &[u8]) -> Option<DecryptedEsp> {
    let mut uncorroborated = None;

    for icv_len in NULL_HEURISTIC_ICV_LENS {
        let Some((payload_end, next_header, pad_length)) = null_trailer_at(data, icv_len) else {
            continue;
        };

        if inner_header_matches(next_header, &data[..payload_end]) {
            return Some(DecryptedEsp {
                payload: data[..payload_end].to_vec(),
                next_header,
                pad_length: pad_length as u8,
                icv_len,
            });
        }

        if icv_len == 0 {
            uncorroborated = Some((payload_end, next_header, pad_length));
        }
    }

    let (payload_end, next_header, pad_length) = uncorroborated?;
    Some(DecryptedEsp {
        payload: data[..payload_end].to_vec(),
        next_header,
        pad_length: pad_length as u8,
        icv_len: 0,
    })
}

/// CBC decryption: AES-CBC (RFC 3602) and 3DES-CBC (RFC 2451).
///
/// RFC 3602, Section 3: <https://www.rfc-editor.org/rfc/rfc3602#section-3>
/// RFC 2451, Section 2: <https://www.rfc-editor.org/rfc/rfc2451#section-2>
/// Layout: [IV(block)] [ciphertext(N*block)] [ICV(auth_icv_len)]
#[cfg(any(feature = "decrypt", test))]
fn decrypt_cbc(sa: &EspSa, data: &[u8]) -> Result<DecryptedEsp, PacketError> {
    use aes::Aes128;
    use aes::Aes192;
    use aes::Aes256;
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
    use des::TdesEde3;

    // The block size equals the IV length for both ciphers.
    let block = sa.encryption.iv_len();
    let icv_len = sa.authentication.icv_len();

    if data.len() < block + icv_len + block {
        return Err(PacketError::InvalidHeader(
            "ESP CBC: data too short for IV + ciphertext + ICV",
        ));
    }

    let iv = &data[..block];
    let ciphertext = &data[block..data.len() - icv_len];

    if ciphertext.len() % block != 0 {
        return Err(PacketError::InvalidHeader(
            "ESP CBC: ciphertext length not a multiple of block size",
        ));
    }

    let mut buf = ciphertext.to_vec();
    let key_err = |_| PacketError::InvalidHeader("ESP CBC key/IV error");
    let dec_err = |_| PacketError::InvalidHeader("ESP CBC decrypt error");

    match (&sa.encryption, sa.enc_key.len()) {
        (EncryptionAlgorithm::TripleDesCbc, 24) => {
            cbc::Decryptor::<TdesEde3>::new_from_slices(&sa.enc_key, iv)
                .map_err(key_err)?
                .decrypt_padded::<NoPadding>(&mut buf)
                .map_err(dec_err)?;
        }
        (EncryptionAlgorithm::TripleDesCbc, _) => {
            return Err(PacketError::InvalidHeader(
                "ESP 3DES-CBC: key must be 24 bytes",
            ));
        }
        (_, 16) => {
            cbc::Decryptor::<Aes128>::new_from_slices(&sa.enc_key, iv)
                .map_err(key_err)?
                .decrypt_padded::<NoPadding>(&mut buf)
                .map_err(dec_err)?;
        }
        (_, 24) => {
            cbc::Decryptor::<Aes192>::new_from_slices(&sa.enc_key, iv)
                .map_err(key_err)?
                .decrypt_padded::<NoPadding>(&mut buf)
                .map_err(dec_err)?;
        }
        (_, 32) => {
            cbc::Decryptor::<Aes256>::new_from_slices(&sa.enc_key, iv)
                .map_err(key_err)?
                .decrypt_padded::<NoPadding>(&mut buf)
                .map_err(dec_err)?;
        }
        _ => {
            return Err(PacketError::InvalidHeader(
                "ESP CBC: unsupported key length",
            ));
        }
    }

    extract_trailer(buf, icv_len)
}

/// Apply the AES counter-mode keystream to `buf`, starting from the
/// 16-octet counter block `block`.
#[cfg(any(feature = "decrypt", test))]
fn aes_ctr_keystream(key: &[u8], block: &[u8; 16], buf: &mut [u8]) -> Result<(), PacketError> {
    use aes::{Aes128, Aes192, Aes256};
    use ctr::cipher::{KeyIvInit, StreamCipher};

    let key_err = |_| PacketError::InvalidHeader("ESP CTR key error");
    match key.len() {
        16 => ctr::Ctr32BE::<Aes128>::new_from_slices(key, block)
            .map_err(key_err)?
            .apply_keystream(buf),
        24 => ctr::Ctr32BE::<Aes192>::new_from_slices(key, block)
            .map_err(key_err)?
            .apply_keystream(buf),
        32 => ctr::Ctr32BE::<Aes256>::new_from_slices(key, block)
            .map_err(key_err)?
            .apply_keystream(buf),
        _ => {
            return Err(PacketError::InvalidHeader(
                "ESP CTR: unsupported key length",
            ));
        }
    }
    Ok(())
}

/// Apply AES-CTR as used by ESP to `buf` (encryption and decryption are the
/// same operation).
///
/// RFC 3686, Section 4 — the counter block is Nonce(4) || IV(8) || Block
/// Counter(4), and "The block counter begins with the value of one".
/// <https://www.rfc-editor.org/rfc/rfc3686#section-4>
#[cfg(any(feature = "decrypt", test))]
fn aes_ctr_apply(
    key: &[u8],
    nonce: &[u8; 4],
    iv: &[u8; 8],
    buf: &mut [u8],
) -> Result<(), PacketError> {
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(nonce);
    block[4..12].copy_from_slice(iv);
    block[15] = 1;
    aes_ctr_keystream(key, &block, buf)
}

/// AES-CTR decryption.
///
/// RFC 3686, Section 3: <https://www.rfc-editor.org/rfc/rfc3686#section-3>
/// Layout: [IV(8)] [ciphertext(N)] [ICV(auth_icv_len)]
#[cfg(any(feature = "decrypt", test))]
fn decrypt_ctr(sa: &EspSa, nonce: &[u8; 4], data: &[u8]) -> Result<DecryptedEsp, PacketError> {
    const CTR_IV_LEN: usize = 8;
    let icv_len = sa.authentication.icv_len();
    if data.len() < CTR_IV_LEN + 2 + icv_len {
        return Err(PacketError::InvalidHeader(
            "ESP CTR: data too short for IV + trailer + ICV",
        ));
    }
    let mut iv = [0u8; CTR_IV_LEN];
    iv.copy_from_slice(&data[..CTR_IV_LEN]);
    let mut buf = data[CTR_IV_LEN..data.len() - icv_len].to_vec();
    aes_ctr_apply(&sa.enc_key, nonce, &iv, &mut buf)?;
    extract_trailer(buf, icv_len)
}

/// Decrypt with an AEAD cipher `C`, returning the plaintext.
#[cfg(any(feature = "decrypt", test))]
fn aead_open<C>(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, PacketError>
where
    C: aes_gcm::aead::KeyInit + aes_gcm::aead::Aead,
{
    use aes_gcm::aead::Payload;

    let cipher =
        C::new_from_slice(key).map_err(|_| PacketError::InvalidHeader("ESP AEAD key error"))?;
    let nonce = aes_gcm::aead::Nonce::<C>::try_from(nonce)
        .map_err(|_| PacketError::InvalidHeader("ESP AEAD nonce error"))?;
    cipher
        .decrypt(&nonce, Payload { msg, aad })
        .map_err(|_| PacketError::InvalidHeader("ESP AEAD decrypt error"))
}

/// Split `[IV(8) | ciphertext | ICV]` and build the nonce `salt || IV`.
///
/// Returns the nonce buffer, its length and the `ciphertext || ICV` slice.
#[cfg(any(feature = "decrypt", test))]
fn aead_split<'a>(
    salt: &[u8],
    icv_len: usize,
    data: &'a [u8],
) -> Result<([u8; 12], usize, &'a [u8]), PacketError> {
    const AEAD_IV_LEN: usize = 8;
    if data.len() < AEAD_IV_LEN + 2 + icv_len {
        return Err(PacketError::InvalidHeader(
            "ESP AEAD: data too short for IV + trailer + ICV",
        ));
    }
    let mut nonce = [0u8; 12];
    nonce[..salt.len()].copy_from_slice(salt);
    nonce[salt.len()..salt.len() + AEAD_IV_LEN].copy_from_slice(&data[..AEAD_IV_LEN]);
    Ok((nonce, salt.len() + AEAD_IV_LEN, &data[AEAD_IV_LEN..]))
}

/// AES-GCM decryption.
///
/// RFC 4106, Section 3: <https://www.rfc-editor.org/rfc/rfc4106#section-3>
/// Layout: [IV(8)] [ciphertext(N)] [ICV(8/12/16)]
/// Nonce = salt(4) || IV(8) = 12 bytes; AAD per [`build_aad`].
#[cfg(any(feature = "decrypt", test))]
fn decrypt_gcm(
    sa: &EspSa,
    aad: &[u8],
    salt: &[u8; 4],
    icv_len: AeadIcvLen,
    data: &[u8],
) -> Result<DecryptedEsp, PacketError> {
    use aes_gcm::AesGcm;
    use aes_gcm::aes::cipher::consts::{U12, U16};
    use aes_gcm::aes::{Aes128, Aes192, Aes256};

    // RFC 4106, Section 8.1 explicitly defines AES-192-GCM (24-byte key +
    // 4-byte salt), but `aes-gcm` only ships type aliases for AES-128 and
    // AES-256, so every variant is built from the generic `AesGcm` type.
    // <https://www.rfc-editor.org/rfc/rfc4106#section-8.1>
    let (nonce, nonce_len, body) = aead_split(salt, icv_len.octets(), data)?;
    let nonce = &nonce[..nonce_len];
    let key = &sa.enc_key;

    let plaintext = match (key.len(), icv_len) {
        (16, AeadIcvLen::Octets16) => aead_open::<AesGcm<Aes128, U12, U16>>(key, nonce, body, aad)?,
        (24, AeadIcvLen::Octets16) => aead_open::<AesGcm<Aes192, U12, U16>>(key, nonce, body, aad)?,
        (32, AeadIcvLen::Octets16) => aead_open::<AesGcm<Aes256, U12, U16>>(key, nonce, body, aad)?,
        (16, AeadIcvLen::Octets12) => aead_open::<AesGcm<Aes128, U12, U12>>(key, nonce, body, aad)?,
        (24, AeadIcvLen::Octets12) => aead_open::<AesGcm<Aes192, U12, U12>>(key, nonce, body, aad)?,
        (32, AeadIcvLen::Octets12) => aead_open::<AesGcm<Aes256, U12, U12>>(key, nonce, body, aad)?,
        (16 | 24 | 32, AeadIcvLen::Octets8) => gcm_open_icv8(key, nonce, body, aad)?,
        _ => {
            return Err(PacketError::InvalidHeader(
                "ESP GCM: unsupported key length",
            ));
        }
    };

    extract_trailer(plaintext, icv_len.octets())
}

/// AES-GCM with an 8-octet ICV, which `aes-gcm` does not support.
///
/// A truncated GCM tag is the leftmost bits of the full tag (NIST SP
/// 800-38D, Section 5.2.1.2), and GCM encrypts with the counter mode
/// keystream that starts at inc32(J0) = IV || 0x00000002 for a 96-bit IV
/// (Section 7.1). The ciphertext is therefore decrypted with AES-CTR, the
/// full tag is recomputed by re-encrypting the plaintext with the 16-octet
/// tag variant, and its leftmost 8 octets are compared with the ICV.
/// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
#[cfg(any(feature = "decrypt", test))]
fn gcm_open_icv8(
    key: &[u8],
    nonce: &[u8],
    body: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PacketError> {
    use aes_gcm::AesGcm;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::aes::cipher::consts::{U12, U16};
    use aes_gcm::aes::{Aes128, Aes192, Aes256};

    const TAG_LEN: usize = 8;
    let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);
    let mut block = [0u8; 16];
    block[..12].copy_from_slice(nonce);
    block[15] = 2;
    let mut plaintext = ciphertext.to_vec();
    aes_ctr_keystream(key, &block, &mut plaintext)?;

    fn seal<C: KeyInit + Aead>(
        key: &[u8],
        nonce: &[u8],
        msg: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let cipher =
            C::new_from_slice(key).map_err(|_| PacketError::InvalidHeader("ESP GCM key error"))?;
        let nonce = aes_gcm::aead::Nonce::<C>::try_from(nonce)
            .map_err(|_| PacketError::InvalidHeader("ESP GCM nonce error"))?;
        cipher
            .encrypt(&nonce, Payload { msg, aad })
            .map_err(|_| PacketError::InvalidHeader("ESP GCM tag error"))
    }
    let sealed = match key.len() {
        16 => seal::<AesGcm<Aes128, U12, U16>>(key, nonce, &plaintext, aad)?,
        24 => seal::<AesGcm<Aes192, U12, U16>>(key, nonce, &plaintext, aad)?,
        _ => seal::<AesGcm<Aes256, U12, U16>>(key, nonce, &plaintext, aad)?,
    };
    let full_tag = &sealed[plaintext.len()..];
    if full_tag[..TAG_LEN] != *tag {
        return Err(PacketError::InvalidHeader("ESP AEAD decrypt error"));
    }
    Ok(plaintext)
}

/// AES-CCM decryption.
///
/// RFC 4309, Sections 3-5: <https://www.rfc-editor.org/rfc/rfc4309#section-4>
/// Layout: [IV(8)] [ciphertext(N)] [ICV(8/12/16)]
/// Nonce = salt(3) || IV(8) = 11 bytes; AAD per [`build_aad`].
#[cfg(any(feature = "decrypt", test))]
fn decrypt_ccm(
    sa: &EspSa,
    aad: &[u8],
    salt: &[u8; 3],
    icv_len: AeadIcvLen,
    data: &[u8],
) -> Result<DecryptedEsp, PacketError> {
    use aes::{Aes128, Aes192, Aes256};
    use ccm::Ccm;
    use ccm::consts::{U8, U11, U12, U16};

    let (nonce, nonce_len, body) = aead_split(salt, icv_len.octets(), data)?;
    let nonce = &nonce[..nonce_len];
    let key = &sa.enc_key;

    let plaintext = match (key.len(), icv_len) {
        (16, AeadIcvLen::Octets8) => aead_open::<Ccm<Aes128, U8, U11>>(key, nonce, body, aad)?,
        (16, AeadIcvLen::Octets12) => aead_open::<Ccm<Aes128, U12, U11>>(key, nonce, body, aad)?,
        (16, AeadIcvLen::Octets16) => aead_open::<Ccm<Aes128, U16, U11>>(key, nonce, body, aad)?,
        (24, AeadIcvLen::Octets8) => aead_open::<Ccm<Aes192, U8, U11>>(key, nonce, body, aad)?,
        (24, AeadIcvLen::Octets12) => aead_open::<Ccm<Aes192, U12, U11>>(key, nonce, body, aad)?,
        (24, AeadIcvLen::Octets16) => aead_open::<Ccm<Aes192, U16, U11>>(key, nonce, body, aad)?,
        (32, AeadIcvLen::Octets8) => aead_open::<Ccm<Aes256, U8, U11>>(key, nonce, body, aad)?,
        (32, AeadIcvLen::Octets12) => aead_open::<Ccm<Aes256, U12, U11>>(key, nonce, body, aad)?,
        (32, AeadIcvLen::Octets16) => aead_open::<Ccm<Aes256, U16, U11>>(key, nonce, body, aad)?,
        _ => {
            return Err(PacketError::InvalidHeader(
                "ESP CCM: unsupported key length",
            ));
        }
    };

    extract_trailer(plaintext, icv_len.octets())
}

/// ChaCha20-Poly1305 decryption.
///
/// RFC 7634, Section 2: <https://www.rfc-editor.org/rfc/rfc7634#section-2>
/// Layout: [IV(8)] [ciphertext(N)] [ICV(16)]
/// Nonce = salt(4) || IV(8) = 12 bytes; AAD per [`build_aad`].
#[cfg(any(feature = "decrypt", test))]
fn decrypt_chacha20_poly1305(
    sa: &EspSa,
    aad: &[u8],
    salt: &[u8; 4],
    data: &[u8],
) -> Result<DecryptedEsp, PacketError> {
    const TAG_LEN: usize = 16;
    let (nonce, nonce_len, body) = aead_split(salt, TAG_LEN, data)?;
    let plaintext = aead_open::<chacha20poly1305::ChaCha20Poly1305>(
        &sa.enc_key,
        &nonce[..nonce_len],
        body,
        aad,
    )?;
    extract_trailer(plaintext, TAG_LEN)
}

/// Extract padding, pad_length, and next_header from decrypted plaintext.
///
/// Takes ownership of the plaintext `Vec` to avoid an extra allocation —
/// the vector is truncated in place to produce the payload.
///
/// RFC 4303, Section 2.4-2.6: <https://www.rfc-editor.org/rfc/rfc4303#section-2.4>
/// Plaintext layout: [payload] [padding(0-255)] [pad_length(1)] [next_header(1)]
fn extract_trailer(mut plaintext: Vec<u8>, icv_len: usize) -> Result<DecryptedEsp, PacketError> {
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
        icv_len,
    })
}

/// Split `key` into an encryption key of `key_len` bytes and an `N`-byte
/// salt / nonce that follows it, checking the total length.
fn split_keymat<const N: usize>(
    name: &str,
    key: &[u8],
    key_len: usize,
    what: &str,
) -> Result<[u8; N], String> {
    if key.len() != key_len + N {
        return Err(format!(
            "{name} requires {}-byte key ({key_len} enc + {N} {what}), got {}",
            key_len + N,
            key.len()
        ));
    }
    let mut salt = [0u8; N];
    salt.copy_from_slice(&key[key_len..]);
    Ok(salt)
}

/// Parse an encryption algorithm name string.
///
/// Returns an [`EncryptionAlgorithm`] if the name is recognized and the key length
/// in `key` matches the requirements for that algorithm, otherwise returns an
/// error message.
///
/// Recognized names:
/// - `null`, `3des-cbc`, `aes-{128,192,256}-cbc`
/// - `aes-{128,192,256}-gcm[-8|-12|-16]` (key + 4-byte salt, RFC 4106,
///   Section 8.1; the default ICV is 16 octets)
/// - `aes-{128,192,256}-ccm-{8,12,16}` (key + 3-byte salt, RFC 4309,
///   Section 7.1)
/// - `aes-{128,192,256}-ctr` (key + 4-byte nonce, RFC 3686, Section 5.1)
/// - `chacha20-poly1305` (32-byte key + 4-byte salt, RFC 7634, Section 3)
/// - `aes-{128,192,256}-gmac` (key + 4-byte salt, RFC 4543, Section 5.4)
///
/// <https://www.rfc-editor.org/rfc/rfc4106>
/// <https://www.rfc-editor.org/rfc/rfc4309>
/// <https://www.rfc-editor.org/rfc/rfc3686#section-5.1>
/// <https://www.rfc-editor.org/rfc/rfc7634>
/// <https://www.rfc-editor.org/rfc/rfc4543#section-5.4>
pub fn parse_encryption_algorithm(name: &str, key: &[u8]) -> Result<EncryptionAlgorithm, String> {
    let exact = |len: usize| {
        if key.len() == len {
            Ok(())
        } else {
            Err(format!("{name} requires {len}-byte key, got {}", key.len()))
        }
    };
    let aes_key_len = |bits: &str| match bits {
        "128" => Some(16),
        "192" => Some(24),
        "256" => Some(32),
        _ => None,
    };
    match name {
        "null" => return Ok(EncryptionAlgorithm::Null),
        "3des-cbc" => {
            exact(24)?;
            return Ok(EncryptionAlgorithm::TripleDesCbc);
        }
        "chacha20-poly1305" => {
            let salt = split_keymat::<4>(name, key, 32, "salt")?;
            return Ok(EncryptionAlgorithm::ChaCha20Poly1305 { salt });
        }
        _ => {}
    }

    // aes-<bits>-<mode>[-<icv octets>]
    let mut parts = name.split('-');
    let (Some("aes"), Some(bits), Some(mode)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("unknown encryption algorithm: {name}"));
    };
    let icv = parts.next();
    let Some(key_len) = aes_key_len(bits) else {
        return Err(format!("unknown encryption algorithm: {name}"));
    };
    if parts.next().is_some() {
        return Err(format!("unknown encryption algorithm: {name}"));
    }
    let icv_len = match (mode, icv) {
        ("gcm", None) => Some(AeadIcvLen::Octets16),
        ("gcm" | "ccm", Some("8")) => Some(AeadIcvLen::Octets8),
        ("gcm" | "ccm", Some("12")) => Some(AeadIcvLen::Octets12),
        ("gcm" | "ccm", Some("16")) => Some(AeadIcvLen::Octets16),
        ("cbc" | "ctr" | "gmac", None) => None,
        _ => return Err(format!("unknown encryption algorithm: {name}")),
    };
    let alg = match (mode, key_len, icv_len) {
        ("cbc", 16, _) => {
            exact(16)?;
            EncryptionAlgorithm::Aes128Cbc
        }
        ("cbc", 24, _) => {
            exact(24)?;
            EncryptionAlgorithm::Aes192Cbc
        }
        ("cbc", _, _) => {
            exact(32)?;
            EncryptionAlgorithm::Aes256Cbc
        }
        ("gcm", _, Some(icv_len)) => {
            let salt = split_keymat::<4>(name, key, key_len, "salt")?;
            match key_len {
                16 => EncryptionAlgorithm::Aes128Gcm { salt, icv_len },
                24 => EncryptionAlgorithm::Aes192Gcm { salt, icv_len },
                _ => EncryptionAlgorithm::Aes256Gcm { salt, icv_len },
            }
        }
        ("ccm", _, Some(icv_len)) => {
            let salt = split_keymat::<3>(name, key, key_len, "salt")?;
            match key_len {
                16 => EncryptionAlgorithm::Aes128Ccm { salt, icv_len },
                24 => EncryptionAlgorithm::Aes192Ccm { salt, icv_len },
                _ => EncryptionAlgorithm::Aes256Ccm { salt, icv_len },
            }
        }
        ("ctr", _, _) => {
            let nonce = split_keymat::<4>(name, key, key_len, "nonce")?;
            match key_len {
                16 => EncryptionAlgorithm::Aes128Ctr { nonce },
                24 => EncryptionAlgorithm::Aes192Ctr { nonce },
                _ => EncryptionAlgorithm::Aes256Ctr { nonce },
            }
        }
        _ => {
            // "gmac"
            let salt = split_keymat::<4>(name, key, key_len, "salt")?;
            match key_len {
                16 => EncryptionAlgorithm::Aes128Gmac { salt },
                24 => EncryptionAlgorithm::Aes192Gmac { salt },
                _ => EncryptionAlgorithm::Aes256Gmac { salt },
            }
        }
    };
    Ok(alg)
}

/// Parse an authentication algorithm name string.
///
/// Recognized names: `none`, `hmac-md5-96` (16-byte key, RFC 2403),
/// `hmac-sha1-96` (20, RFC 2404), `hmac-sha256-128` (32),
/// `hmac-sha384-192` (48) and `hmac-sha512-256` (64) (RFC 4868,
/// Section 2.1.1).
/// <https://www.rfc-editor.org/rfc/rfc2403>
/// <https://www.rfc-editor.org/rfc/rfc2404>
/// <https://www.rfc-editor.org/rfc/rfc4868>
pub fn parse_authentication_algorithm(
    name: &str,
    key: &[u8],
) -> Result<AuthenticationAlgorithm, String> {
    let (alg, key_len) = match name {
        "none" => return Ok(AuthenticationAlgorithm::None),
        "hmac-md5-96" => (AuthenticationAlgorithm::HmacMd5_96, 16),
        "hmac-sha1-96" => (AuthenticationAlgorithm::HmacSha1_96, 20),
        "hmac-sha256-128" => (AuthenticationAlgorithm::HmacSha256_128, 32),
        "hmac-sha384-192" => (AuthenticationAlgorithm::HmacSha384_192, 48),
        "hmac-sha512-256" => (AuthenticationAlgorithm::HmacSha512_256, 64),
        _ => return Err(format!("unknown authentication algorithm: {name}")),
    };
    if key.len() != key_len {
        return Err(format!(
            "{name} requires {key_len}-byte key, got {}",
            key.len()
        ));
    }
    Ok(alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_trailer_basic() {
        // payload=[0x45, 0x00], padding=[], pad_length=0, next_header=4 (IPv4)
        let plaintext = [0x45, 0x00, 0x00, 0x04];
        let result = extract_trailer(plaintext.to_vec(), 0).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.payload, vec![0x45, 0x00]);
    }

    #[test]
    fn test_extract_trailer_with_padding() {
        // payload=[0x45], padding=[0x01, 0x02], pad_length=2, next_header=4
        let plaintext = [0x45, 0x01, 0x02, 0x02, 0x04];
        let result = extract_trailer(plaintext.to_vec(), 0).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45]);
    }

    #[test]
    fn test_extract_trailer_too_short() {
        let plaintext = [0x04];
        let err = extract_trailer(plaintext.to_vec(), 0).unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn test_extract_trailer_bad_pad_length() {
        // pad_length=100 but only 4 bytes total
        let plaintext = [0x45, 0x00, 100, 0x04];
        let err = extract_trailer(plaintext.to_vec(), 0).unwrap_err();
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
            esn: None,
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
            esn: None,
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
            esn: None,
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
        let nonce = &Nonce::from(nonce_bytes);

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
            encryption: EncryptionAlgorithm::Aes128Gcm {
                salt,
                icv_len: AeadIcvLen::Octets16,
            },
            enc_key: enc_key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
            esn: None,
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
    fn test_parse_encryption_algorithm_aes192_gcm() {
        // RFC 4106, Section 8.1 — AES-192-GCM KEYMAT = 24 enc + 4 salt = 28 bytes.
        // <https://www.rfc-editor.org/rfc/rfc4106#section-8.1>
        let key = [0u8; 28];
        let result = parse_encryption_algorithm("aes-192-gcm", &key).unwrap();
        assert!(matches!(result, EncryptionAlgorithm::Aes192Gcm { .. }));
        assert!(parse_encryption_algorithm("aes-192-gcm", &[0; 24]).is_err());
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
            esn: None,
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
            esn: None,
        };

        let result = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 2);
        assert_eq!(result.payload, vec![0x45; 12]);
    }

    #[test]
    fn test_gcm_decryption_aes192() {
        // RFC 4106, Section 8.1 — AES-192-GCM KEYMAT = 24-byte key + 4-byte salt.
        // <https://www.rfc-editor.org/rfc/rfc4106#section-8.1>
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::aes::Aes192;
        use aes_gcm::aes::cipher::consts::U12;
        use aes_gcm::{AesGcm, Nonce};

        type Aes192Gcm = AesGcm<Aes192, U12>;

        let enc_key = [0x07u8; 24];
        let salt = [0x08u8; 4];
        let packet_iv = [0x09u8; 8];
        let spi: u32 = 0xABCD;
        let seq: u32 = 42;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&salt);
        nonce_bytes[4..].copy_from_slice(&packet_iv);
        let nonce = &Nonce::from(nonce_bytes);

        let mut aad = [0u8; 8];
        aad[..4].copy_from_slice(&spi.to_be_bytes());
        aad[4..].copy_from_slice(&seq.to_be_bytes());

        // Plaintext: inner(4) + pad_len(0) + next_header(4 = IPv4)
        let plaintext_inner = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x04];

        let cipher = Aes192Gcm::new_from_slice(&enc_key).unwrap();
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
            encryption: EncryptionAlgorithm::Aes192Gcm {
                salt,
                icv_len: AeadIcvLen::Octets16,
            },
            enc_key: enc_key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
            esn: None,
        };

        let result = decrypt_esp(&sa, spi, seq, &data).unwrap();
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.payload, vec![0x45, 0x00, 0x00, 0x28]);
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
        let nonce = &Nonce::from(nonce_bytes);

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
            encryption: EncryptionAlgorithm::Aes256Gcm {
                salt,
                icv_len: AeadIcvLen::Octets16,
            },
            enc_key: enc_key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
            esn: None,
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
            esn: None,
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
            esn: None,
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
            encryption: EncryptionAlgorithm::Aes128Gcm {
                salt,
                icv_len: AeadIcvLen::Octets16,
            },
            enc_key: vec![0; 24], // wrong key length (not 16 or 32)
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
            esn: None,
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
            esn: None,
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
        assert_eq!(
            EncryptionAlgorithm::Aes128Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
            .iv_len(),
            8
        );
        assert_eq!(
            EncryptionAlgorithm::Aes192Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
            .iv_len(),
            8
        );
        assert_eq!(
            EncryptionAlgorithm::Aes256Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
            .iv_len(),
            8
        );
    }

    #[test]
    fn test_is_aead() {
        assert!(!EncryptionAlgorithm::Null.is_aead());
        assert!(!EncryptionAlgorithm::Aes128Cbc.is_aead());
        assert!(
            EncryptionAlgorithm::Aes128Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
            .is_aead()
        );
        assert!(
            EncryptionAlgorithm::Aes192Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
            .is_aead()
        );
        assert!(
            EncryptionAlgorithm::Aes256Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
            .is_aead()
        );
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

    /// Build a minimal, well-formed inner IPv4 packet whose Total Length
    /// field matches its own byte length, so the NULL heuristic's inner
    /// header corroboration accepts it.
    fn inner_ipv4(payload_len: usize) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[9] = 17; // UDP
        pkt
    }

    #[test]
    fn test_try_null_decrypt_detects_12_byte_icv() {
        // ealg=null + aalg=hmac-sha1-96: plaintext payload with a 12-byte ICV
        // appended. The payload is plaintext, so the inner packet must be
        // recoverable without any key.
        let inner = inner_ipv4(8);
        let mut data = inner.clone();
        data.extend_from_slice(&[0, 4]); // pad_length=0, next_header=4 (IPv4)
        data.extend_from_slice(&[0xAA; 12]); // ICV

        let result = try_null_decrypt(&data).expect("12-byte ICV must be detected");
        assert_eq!(result.next_header, 4);
        assert_eq!(result.pad_length, 0);
        assert_eq!(result.icv_len, 12);
        assert_eq!(result.payload, inner);
    }

    #[test]
    fn test_try_null_decrypt_detects_16_byte_icv() {
        // ealg=null + aalg=hmac-sha256-128 (16-byte ICV).
        let inner = inner_ipv4(4);
        let mut data = inner.clone();
        data.extend_from_slice(&[0, 4]);
        data.extend_from_slice(&[0xBB; 16]);

        let result = try_null_decrypt(&data).expect("16-byte ICV must be detected");
        assert_eq!(result.icv_len, 16);
        assert_eq!(result.payload, inner);
    }

    #[test]
    fn test_try_null_decrypt_detects_icv_with_ipv6_inner() {
        // next_header=41 (IPv6-in-IPv6) corroborated by the inner IPv6 header.
        let mut inner = vec![0u8; 48];
        inner[0] = 0x60; // version 6
        inner[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload length
        inner[6] = 17; // next header = UDP
        let mut data = inner.clone();
        data.extend_from_slice(&[0, 41]);
        data.extend_from_slice(&[0xCC; 12]);

        let result = try_null_decrypt(&data).expect("IPv6 inner must be detected");
        assert_eq!(result.next_header, 41);
        assert_eq!(result.icv_len, 12);
        assert_eq!(result.payload, inner);
    }

    #[test]
    fn test_try_null_decrypt_detects_icv_with_udp_inner() {
        // Transport mode: next_header=17, corroborated by the UDP Length field.
        let mut inner = vec![0u8; 16];
        inner[0..2].copy_from_slice(&1234u16.to_be_bytes());
        inner[2..4].copy_from_slice(&5678u16.to_be_bytes());
        inner[4..6].copy_from_slice(&16u16.to_be_bytes()); // UDP length
        let mut data = inner.clone();
        data.extend_from_slice(&[0, 17]);
        data.extend_from_slice(&[0xDD; 16]);

        let result = try_null_decrypt(&data).expect("UDP inner must be detected");
        assert_eq!(result.next_header, 17);
        assert_eq!(result.icv_len, 16);
        assert_eq!(result.payload, inner);
    }

    #[test]
    fn test_try_null_decrypt_detects_icv_with_tcp_inner() {
        // Transport mode with next_header=6: TCP has no length field, so the
        // corroboration relies on Data Offset and the reserved bits.
        let mut inner = vec![0u8; 24];
        inner[12] = 0x60; // Data Offset = 6 (24 bytes), reserved bits zero
        let mut data = inner.clone();
        data.extend_from_slice(&[0, 6]);
        data.extend_from_slice(&[0xEE; 12]);

        let result = try_null_decrypt(&data).expect("TCP inner must be detected");
        assert_eq!(result.next_header, 6);
        assert_eq!(result.icv_len, 12);
        assert_eq!(result.payload, inner);
    }

    #[test]
    fn test_try_null_decrypt_rejects_tcp_inner_with_reserved_bits_set() {
        // Same packet with a non-zero reserved nibble is not corroborated,
        // so no ICV length is guessed.
        let mut inner = vec![0u8; 24];
        inner[12] = 0x6F; // Data Offset = 6, reserved bits set
        let mut data = inner;
        data.extend_from_slice(&[0, 6]);
        data.extend_from_slice(&[0xEE; 12]);

        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_prefers_corroborated_icv_over_loose_match() {
        // Craft an ICV whose last two bytes would pass the loose icv_len=0
        // checks (pad_length=0, next_header=6/TCP). The icv_len=12 candidate
        // is corroborated by a real inner IPv4 header and must win.
        let inner = inner_ipv4(12);
        let mut data = inner.clone();
        data.extend_from_slice(&[0, 4]);
        let mut icv = [0xAAu8; 12];
        icv[10] = 0; // would read as pad_length=0
        icv[11] = 6; // would read as next_header=TCP
        data.extend_from_slice(&icv);

        let result = try_null_decrypt(&data).expect("corroborated candidate must win");
        assert_eq!(result.next_header, 4);
        assert_eq!(result.icv_len, 12);
        assert_eq!(result.payload, inner);
    }

    #[test]
    fn test_try_null_decrypt_icv_requires_inner_corroboration() {
        // next_header=47 (GRE) cannot be corroborated from the inner header,
        // so a non-zero ICV length is never guessed for it.
        let mut data = vec![0x11; 24];
        data.extend_from_slice(&[0, 47]);
        data.extend_from_slice(&[0xEE; 12]);
        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_rejects_inconsistent_inner_length() {
        // next_header=4 but the inner Total Length does not match the payload
        // length, and the trailing bytes are not a valid no-ICV trailer.
        let mut inner = inner_ipv4(8);
        inner[2..4].copy_from_slice(&999u16.to_be_bytes()); // bogus Total Length
        let mut data = inner;
        data.extend_from_slice(&[0, 4]);
        data.extend_from_slice(&[0xAA; 12]);
        assert!(try_null_decrypt(&data).is_none());
    }

    #[test]
    fn test_try_null_decrypt_reports_zero_icv_len() {
        // The existing no-ICV path must keep reporting icv_len = 0.
        let data = [0x45, 0x00, 0x00, 0x04];
        let result = try_null_decrypt(&data).unwrap();
        assert_eq!(result.icv_len, 0);
    }

    // ── ESN, AEAD ICV lengths and additional algorithms ────────────────────

    /// Parse space-separated hex.
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    fn sa(encryption: EncryptionAlgorithm, enc_key: &[u8], esn: Option<u32>) -> EspSa {
        EspSa {
            encryption,
            enc_key: enc_key.to_vec(),
            authentication: AuthenticationAlgorithm::None,
            auth_key: vec![],
            esn,
        }
    }

    /// payload(4) + pad 1,2 + pad_length 2 + next_header 4 (IPv4).
    const INNER: [u8; 8] = [0x45, 0x00, 0x00, 0x28, 0x01, 0x02, 0x02, 0x04];

    /// AAD per RFC 4106, Section 5 (8 octets, or 12 with ESN).
    fn aad(spi: u32, seq: u32, esn_high: Option<u32>) -> Vec<u8> {
        let mut a = spi.to_be_bytes().to_vec();
        if let Some(high) = esn_high {
            a.extend_from_slice(&high.to_be_bytes());
        }
        a.extend_from_slice(&seq.to_be_bytes());
        a
    }

    fn gcm_encrypt(key: &[u8], salt: [u8; 4], iv: [u8; 8], aad: &[u8], icv: usize) -> Vec<u8> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::aes::Aes128;
        use aes_gcm::aes::cipher::consts::{U12, U16};
        use aes_gcm::{AesGcm, Nonce};
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&salt);
        n[4..].copy_from_slice(&iv);
        let nonce = &Nonce::from(n);
        let p = Payload { msg: &INNER, aad };
        let ct = match icv {
            // aes-gcm has no 8-octet tag; a truncated GCM tag is the prefix
            // of the full tag (NIST SP 800-38D, Section 5.2.1.2).
            8 => {
                let mut full = AesGcm::<Aes128, U12, U16>::new_from_slice(key)
                    .unwrap()
                    .encrypt(nonce, p)
                    .unwrap();
                full.truncate(full.len() - 8);
                full
            }
            12 => AesGcm::<Aes128, U12, U12>::new_from_slice(key)
                .unwrap()
                .encrypt(nonce, p)
                .unwrap(),
            _ => AesGcm::<Aes128, U12, U16>::new_from_slice(key)
                .unwrap()
                .encrypt(nonce, p)
                .unwrap(),
        };
        [iv.to_vec(), ct].concat()
    }

    #[test]
    fn test_gcm_esn_aad() {
        // RFC 4106, Section 5 — with ESN the AAD is SPI || ESN (high || low).
        // <https://www.rfc-editor.org/rfc/rfc4106#section-5>
        let key = [0x21u8; 16];
        let salt = [1, 2, 3, 4];
        for high in [0u32, 1] {
            let data = gcm_encrypt(&key, salt, [9; 8], &aad(0x100, 7, Some(high)), 16);
            let alg = EncryptionAlgorithm::Aes128Gcm {
                salt,
                icv_len: AeadIcvLen::Octets16,
            };
            let ok = decrypt_esp(&sa(alg.clone(), &key, Some(high)), 0x100, 7, &data).unwrap();
            assert_eq!(ok.payload, INNER[..4].to_vec());
            assert_eq!(ok.pad_length, 2);
            // Without ESN (8-octet AAD) the tag check fails.
            assert!(decrypt_esp(&sa(alg, &key, None), 0x100, 7, &data).is_err());
        }
    }

    #[test]
    fn test_gcm_short_icv() {
        // RFC 4106, Section 6 — 8- and 12-octet ICVs.
        // <https://www.rfc-editor.org/rfc/rfc4106#section-6>
        let key = [0x22u8; 16];
        let salt = [5, 6, 7, 8];
        for (icv, len) in [(8, AeadIcvLen::Octets8), (12, AeadIcvLen::Octets12)] {
            let data = gcm_encrypt(&key, salt, [3; 8], &aad(0x200, 1, None), icv);
            let alg = EncryptionAlgorithm::Aes128Gcm { salt, icv_len: len };
            let out = decrypt_esp(&sa(alg, &key, None), 0x200, 1, &data).unwrap();
            assert_eq!(out.payload, INNER[..4].to_vec());
            assert_eq!(out.icv_len, icv);
            // A corrupted ICV is rejected.
            let mut bad = data.clone();
            *bad.last_mut().unwrap() ^= 1;
            let alg = EncryptionAlgorithm::Aes128Gcm { salt, icv_len: len };
            assert!(decrypt_esp(&sa(alg, &key, None), 0x200, 1, &bad).is_err());
        }
        // GCM-8 with AES-192/256 keys and a bad key length.
        for key in [vec![0x23u8; 24], vec![0x24u8; 32]] {
            use aes_gcm::AesGcm;
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::aes::cipher::consts::{U12, U16};
            use aes_gcm::aes::{Aes192, Aes256};
            let mut n = [0u8; 12];
            n[..4].copy_from_slice(&salt);
            n[4..].copy_from_slice(&[3; 8]);
            let a = aad(0x200, 1, None);
            let p = Payload {
                msg: &INNER,
                aad: &a,
            };
            let mut ct = if key.len() == 24 {
                AesGcm::<Aes192, U12, U16>::new_from_slice(&key)
                    .unwrap()
                    .encrypt(&n.into(), p)
            } else {
                AesGcm::<Aes256, U12, U16>::new_from_slice(&key)
                    .unwrap()
                    .encrypt(&n.into(), p)
            }
            .unwrap();
            ct.truncate(ct.len() - 8);
            let data = [vec![3; 8], ct].concat();
            let alg = if key.len() == 24 {
                EncryptionAlgorithm::Aes192Gcm {
                    salt,
                    icv_len: AeadIcvLen::Octets8,
                }
            } else {
                EncryptionAlgorithm::Aes256Gcm {
                    salt,
                    icv_len: AeadIcvLen::Octets8,
                }
            };
            let out = decrypt_esp(&sa(alg, &key, None), 0x200, 1, &data).unwrap();
            assert_eq!(out.payload, INNER[..4].to_vec());
        }
        let alg = EncryptionAlgorithm::Aes128Gcm {
            salt,
            icv_len: AeadIcvLen::Octets8,
        };
        assert!(decrypt_esp(&sa(alg, &[0; 20], None), 1, 1, &[0; 30]).is_err());
        let alg = EncryptionAlgorithm::Aes128Ccm {
            salt: [0; 3],
            icv_len: AeadIcvLen::Octets8,
        };
        assert!(decrypt_esp(&sa(alg, &[0; 20], None), 1, 1, &[0; 30]).is_err());
        let alg = EncryptionAlgorithm::Aes128Ctr { nonce: [0; 4] };
        assert!(decrypt_esp(&sa(alg.clone(), &[0; 16], None), 1, 1, &[0; 9]).is_err());
        assert!(decrypt_esp(&sa(alg, &[0; 20], None), 1, 1, &[0; 20]).is_err());
        // Key size must match the algorithm variant.
        let alg = EncryptionAlgorithm::Aes128Gcm {
            salt,
            icv_len: AeadIcvLen::Octets16,
        };
        assert!(decrypt_esp(&sa(alg, &[0; 32], None), 1, 1, &[0; 40]).is_err());
        assert_eq!(EncryptionAlgorithm::Null.key_len(), None);
        assert_eq!(EncryptionAlgorithm::TripleDesCbc.key_len(), Some(24));
        assert!(
            decrypt_esp(
                &sa(EncryptionAlgorithm::TripleDesCbc, &[0; 16], None),
                1,
                1,
                &[0; 24]
            )
            .is_err()
        );
    }

    #[test]
    fn test_chacha20_poly1305_rfc7634_appendix_a() {
        // RFC 7634, Appendix A — ESP example.
        // <https://www.rfc-editor.org/rfc/rfc7634#appendix-A>
        let keymat = hex("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f \
             90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3");
        let alg = parse_encryption_algorithm("chacha20-poly1305", &keymat).unwrap();
        assert_eq!(
            alg,
            EncryptionAlgorithm::ChaCha20Poly1305 {
                salt: [0xa0, 0xa1, 0xa2, 0xa3]
            }
        );
        let esp_payload = hex(
            "10 11 12 13 14 15 16 17 24 03 94 28 b9 7f 41 7e 3c 13 75 3a \
             4f 05 08 7b 67 c3 52 e6 a7 fa b1 b9 82 d4 66 ef 40 7a e5 c6 \
             14 ee 80 99 d5 28 44 eb 61 aa 95 df ab 4c 02 f7 2a a7 1e 7c \
             4c 4f 64 c9 be fe 2f ac c6 38 e8 f3 cb ec 16 3f ac 46 9b 50 \
             27 73 f6 fb 94 e6 64 da 91 65 b8 28 29 f6 41 e0 76 aa a8 26 \
             6b 7f b0 f7 b1 1b 36 99 07 e1 ad 43",
        );
        let out = decrypt_esp(&sa(alg, &keymat[..32], None), 0x0102_0304, 5, &esp_payload).unwrap();
        let source = hex(
            "45 00 00 54 a6 f2 00 00 40 01 e7 78 c6 33 64 05 c0 00 02 05 08 00 5b 7a \
             3a 08 00 00 55 3b ec 10 00 07 36 27 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 \
             14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b \
             2c 2d 2e 2f 30 31 32 33 34 35 36 37",
        );
        assert_eq!(out.payload, source);
        assert_eq!(out.pad_length, 2);
        assert_eq!(out.next_header, 4);
        assert_eq!(out.icv_len, 16);
    }

    #[test]
    fn test_chacha20_poly1305_esn_and_bad_key() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        // RFC 7634, Section 2.1 — 12-octet AAD with ESN.
        // <https://www.rfc-editor.org/rfc/rfc7634#section-2.1>
        let key = [0x31u8; 32];
        let salt = [1, 1, 1, 1];
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&salt);
        n[4..].copy_from_slice(&[2; 8]);
        let ct = ChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(
                &Nonce::from(n),
                Payload {
                    msg: &INNER,
                    aad: &aad(9, 9, Some(3)),
                },
            )
            .unwrap();
        let data = [vec![2; 8], ct].concat();
        let alg = EncryptionAlgorithm::ChaCha20Poly1305 { salt };
        let out = decrypt_esp(&sa(alg.clone(), &key, Some(3)), 9, 9, &data).unwrap();
        assert_eq!(out.payload, INNER[..4].to_vec());
        assert!(decrypt_esp(&sa(alg.clone(), &key[..16], Some(3)), 9, 9, &data).is_err());
        assert!(decrypt_esp(&sa(alg, &key, Some(3)), 9, 9, &data[..20]).is_err());
    }

    #[test]
    fn test_ccm_all_icv_lengths_and_key_sizes() {
        use aes::{Aes128, Aes192, Aes256};
        use ccm::Ccm;
        use ccm::aead::{Aead, KeyInit, Payload};
        use ccm::consts::{U8, U11, U12, U16};
        // RFC 4309, Sections 3-5 — nonce = salt(3) || IV(8), AAD as GCM.
        // <https://www.rfc-editor.org/rfc/rfc4309#section-4>
        let salt = [7, 8, 9];
        let iv = [4u8; 8];
        let mut n = [0u8; 11];
        n[..3].copy_from_slice(&salt);
        n[3..].copy_from_slice(&iv);
        let a = aad(0x300, 2, None);
        macro_rules! enc {
            ($aes:ty, $tag:ty, $key:expr) => {
                Ccm::<$aes, $tag, U11>::new_from_slice($key)
                    .unwrap()
                    .encrypt(
                        &n.into(),
                        Payload {
                            msg: &INNER,
                            aad: &a,
                        },
                    )
                    .unwrap()
            };
        }
        let cases: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
            (vec![1; 16], enc!(Aes128, U8, &[1; 16]), "aes-128-ccm-8"),
            (vec![1; 16], enc!(Aes128, U12, &[1; 16]), "aes-128-ccm-12"),
            (vec![1; 16], enc!(Aes128, U16, &[1; 16]), "aes-128-ccm-16"),
            (vec![2; 24], enc!(Aes192, U16, &[2; 24]), "aes-192-ccm-16"),
            (vec![3; 32], enc!(Aes256, U8, &[3; 32]), "aes-256-ccm-8"),
            (vec![3; 32], enc!(Aes256, U12, &[3; 32]), "aes-256-ccm-12"),
        ];
        for (key, ct, name) in cases {
            let keymat = [key.clone(), salt.to_vec()].concat();
            let alg = parse_encryption_algorithm(name, &keymat).unwrap();
            let data = [iv.to_vec(), ct].concat();
            let out = decrypt_esp(&sa(alg, &key, None), 0x300, 2, &data)
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(out.payload, INNER[..4].to_vec(), "{name}");
        }
    }

    #[test]
    fn test_aes_ctr_rfc3686_vectors() {
        // RFC 3686, Section 6 — Test Vectors #1 and #7.
        // <https://www.rfc-editor.org/rfc/rfc3686#section-6>
        let mut buf = hex("E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8");
        aes_ctr_apply(
            &hex("AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E"),
            &[0, 0, 0, 0x30],
            &[0; 8],
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf, b"Single block msg");
        let mut buf = hex("14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0");
        aes_ctr_apply(
            &hex("77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C \
                 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04"),
            &[0, 0, 0, 0x60],
            &hex("DB 56 72 C9 7A A8 F0 B2").try_into().unwrap(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf, b"Single block msg");
        assert!(aes_ctr_apply(&[0; 5], &[0; 4], &[0; 8], &mut []).is_err());
    }

    #[test]
    fn test_aes_ctr_esp_with_icv() {
        // RFC 3686, Section 3 — IV(8) || ciphertext; the ICV follows.
        // <https://www.rfc-editor.org/rfc/rfc3686#section-3>
        let key = [0x41u8; 24];
        let nonce = [0, 0, 0, 1];
        let iv = [6u8; 8];
        let mut ct = INNER.to_vec();
        aes_ctr_apply(&key, &nonce, &iv, &mut ct).unwrap();
        let mut data = [iv.to_vec(), ct].concat();
        data.extend_from_slice(&[0xee; 24]); // HMAC-SHA-384-192 ICV
        let keymat = [key.to_vec(), nonce.to_vec()].concat();
        let alg = parse_encryption_algorithm("aes-192-ctr", &keymat).unwrap();
        let mut sa = sa(alg, &key, None);
        sa.authentication = AuthenticationAlgorithm::HmacSha384_192;
        let out = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(out.payload, INNER[..4].to_vec());
        assert_eq!(out.icv_len, 24);
    }

    #[test]
    fn test_3des_cbc() {
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
        use des::TdesEde3;
        // RFC 2451, Section 2 — 8-octet IV and block.
        // <https://www.rfc-editor.org/rfc/rfc2451#section-2>
        let key = [0x13u8; 24];
        let iv = [0x57u8; 8];
        let mut buf = INNER.to_vec();
        cbc::Encryptor::<TdesEde3>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buf, INNER.len())
            .unwrap();
        let mut data = [iv.to_vec(), buf].concat();
        data.extend_from_slice(&[0xaa; 12]); // HMAC-MD5-96 ICV
        let alg = parse_encryption_algorithm("3des-cbc", &key).unwrap();
        let mut sa = sa(alg, &key, None);
        sa.authentication = AuthenticationAlgorithm::HmacMd5_96;
        let out = decrypt_esp(&sa, 1, 1, &data).unwrap();
        assert_eq!(out.payload, INNER[..4].to_vec());
        // Not a multiple of the 8-octet block.
        assert!(decrypt_esp(&sa, 1, 1, &data[..data.len() - 1]).is_err());
    }

    #[test]
    fn test_aes_gmac_plaintext_payload() {
        // RFC 4543, Section 3 — ENCR_NULL_AUTH_AES_GMAC: IV(8), plaintext
        // payload, 16-octet ICV.
        // <https://www.rfc-editor.org/rfc/rfc4543#section-3>
        let mut data = vec![0x11; 8];
        data.extend_from_slice(&INNER);
        data.extend_from_slice(&[0xcc; 16]);
        let keymat = [vec![0; 32], vec![1, 2, 3, 4]].concat();
        let alg = parse_encryption_algorithm("aes-256-gmac", &keymat).unwrap();
        let out = decrypt_esp(&sa(alg, &keymat[..32], None), 1, 1, &data).unwrap();
        assert_eq!(out.payload, INNER[..4].to_vec());
        assert_eq!(out.icv_len, 16);
        assert!(
            decrypt_esp(
                &sa(
                    EncryptionAlgorithm::Aes128Gmac { salt: [0; 4] },
                    &[0; 16],
                    None
                ),
                1,
                1,
                &[0; 20]
            )
            .is_err()
        );
    }

    #[test]
    fn test_new_parse_names_and_lengths() {
        let ok = |n: &str, len: usize| parse_encryption_algorithm(n, &vec![0; len]).unwrap();
        assert_eq!(
            ok("aes-128-gcm-8", 20),
            EncryptionAlgorithm::Aes128Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets8
            }
        );
        assert_eq!(
            ok("aes-192-gcm-12", 28),
            EncryptionAlgorithm::Aes192Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets12
            }
        );
        assert_eq!(
            ok("aes-256-gcm-16", 36),
            EncryptionAlgorithm::Aes256Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
        );
        assert_eq!(
            ok("aes-128-gcm", 20),
            EncryptionAlgorithm::Aes128Gcm {
                salt: [0; 4],
                icv_len: AeadIcvLen::Octets16
            }
        );
        assert_eq!(
            ok("aes-128-ctr", 20),
            EncryptionAlgorithm::Aes128Ctr { nonce: [0; 4] }
        );
        assert_eq!(
            ok("aes-256-ctr", 36),
            EncryptionAlgorithm::Aes256Ctr { nonce: [0; 4] }
        );
        assert_eq!(
            ok("aes-192-ccm-8", 27),
            EncryptionAlgorithm::Aes192Ccm {
                salt: [0; 3],
                icv_len: AeadIcvLen::Octets8
            }
        );
        assert_eq!(
            ok("aes-128-gmac", 20),
            EncryptionAlgorithm::Aes128Gmac { salt: [0; 4] }
        );
        assert_eq!(
            ok("aes-192-gmac", 28),
            EncryptionAlgorithm::Aes192Gmac { salt: [0; 4] }
        );
        assert_eq!(ok("3des-cbc", 24), EncryptionAlgorithm::TripleDesCbc);
        for (name, bad) in [
            ("aes-128-gcm-8", 16),
            ("aes-128-ctr", 16),
            ("aes-128-ccm-16", 16),
            ("aes-128-gmac", 16),
            ("3des-cbc", 16),
            ("chacha20-poly1305", 32),
            ("aes-128-ccm-4", 19),
        ] {
            assert!(
                parse_encryption_algorithm(name, &vec![0; bad]).is_err(),
                "{name}"
            );
        }
        let auth = |n: &str, len: usize| parse_authentication_algorithm(n, &vec![0; len]);
        assert_eq!(
            auth("hmac-md5-96", 16).unwrap(),
            AuthenticationAlgorithm::HmacMd5_96
        );
        assert_eq!(
            auth("hmac-sha384-192", 48).unwrap(),
            AuthenticationAlgorithm::HmacSha384_192
        );
        assert_eq!(
            auth("hmac-sha512-256", 64).unwrap(),
            AuthenticationAlgorithm::HmacSha512_256
        );
        assert!(auth("hmac-md5-96", 20).is_err());
        assert!(auth("hmac-sha384-192", 32).is_err());
        assert!(auth("hmac-sha512-256", 32).is_err());
    }

    #[test]
    fn test_new_iv_icv_and_aead_properties() {
        use EncryptionAlgorithm as E;
        let s4 = [0u8; 4];
        assert_eq!(E::TripleDesCbc.iv_len(), 8);
        assert_eq!(E::Aes128Ctr { nonce: s4 }.iv_len(), 8);
        assert_eq!(E::ChaCha20Poly1305 { salt: s4 }.iv_len(), 8);
        assert_eq!(
            E::Aes256Ccm {
                salt: [0; 3],
                icv_len: AeadIcvLen::Octets12
            }
            .iv_len(),
            8
        );
        assert_eq!(E::Aes192Gmac { salt: s4 }.iv_len(), 8);
        assert!(E::ChaCha20Poly1305 { salt: s4 }.is_aead());
        assert!(
            E::Aes128Ccm {
                salt: [0; 3],
                icv_len: AeadIcvLen::Octets8
            }
            .is_aead()
        );
        assert!(E::Aes128Gmac { salt: s4 }.is_aead());
        assert!(!E::Aes128Ctr { nonce: s4 }.is_aead());
        assert!(!E::TripleDesCbc.is_aead());
        assert_eq!(E::Aes128Gmac { salt: s4 }.aead_icv_len(), Some(16));
        assert_eq!(
            E::Aes128Gcm {
                salt: s4,
                icv_len: AeadIcvLen::Octets12
            }
            .aead_icv_len(),
            Some(12)
        );
        assert_eq!(E::Aes128Cbc.aead_icv_len(), None);
        assert_eq!(AuthenticationAlgorithm::HmacMd5_96.icv_len(), 12);
        assert_eq!(AuthenticationAlgorithm::HmacSha384_192.icv_len(), 24);
        assert_eq!(AuthenticationAlgorithm::HmacSha512_256.icv_len(), 32);
    }
}
