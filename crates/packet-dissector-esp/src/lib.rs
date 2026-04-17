//! IP Encapsulating Security Payload (ESP) dissector.
//!
//! ## References
//! - RFC 4303: IP Encapsulating Security Payload (ESP):
//!   <https://www.rfc-editor.org/rfc/rfc4303>
//! - RFC 3602: The AES-CBC Cipher Algorithm and Its Use with IPsec:
//!   <https://www.rfc-editor.org/rfc/rfc3602>
//! - RFC 4106: The Use of Galois/Counter Mode (GCM) in IPsec ESP:
//!   <https://www.rfc-editor.org/rfc/rfc4106>

#![deny(missing_docs)]

pub mod crypto;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use packet_dissector_core::dissector::{DecryptedPayload, DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::lookup::ip_protocol_name;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u32;

/// Field descriptor indices for [`FIELD_DESCRIPTORS`].
const FD_SPI: usize = 0;
const FD_SEQUENCE_NUMBER: usize = 1;
const FD_ENCRYPTED_DATA: usize = 2;
const FD_NEXT_HEADER: usize = 3;
const FD_PAD_LENGTH: usize = 4;

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    // RFC 4303, Section 2.1 — Security Parameters Index (SPI)
    // <https://www.rfc-editor.org/rfc/rfc4303#section-2.1>
    FieldDescriptor::new("spi", "Security Parameters Index", FieldType::U32),
    // RFC 4303, Section 2.2 — Sequence Number
    // <https://www.rfc-editor.org/rfc/rfc4303#section-2.2>
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U32),
    // RFC 4303, Sections 2.3–2.7 — opaque payload region.
    // Wire layout: (optional IV) | Payload Data | Padding | Pad Length |
    // Next Header | ICV.  Per RFC 4303 Section 2.3, "if the algorithm used
    // to encrypt the payload requires cryptographic synchronization data,
    // e.g., an Initialization Vector (IV), then this data is carried
    // explicitly in the Payload field, but it is not called out as a
    // separate field in ESP."
    // <https://www.rfc-editor.org/rfc/rfc4303#section-2.3>
    FieldDescriptor::new("encrypted_data", "Encrypted Data", FieldType::Bytes).optional(),
    // Decryption result fields (present only when SA is configured)
    FieldDescriptor {
        name: "next_header",
        display_name: "Next Header",
        field_type: FieldType::U8,
        optional: true,
        children: None,
        display_fn: Some(|v, _siblings| match v {
            FieldValue::U8(p) => ip_protocol_name(*p),
            _ => None,
        }),
        format_fn: None,
    },
    FieldDescriptor::new("pad_length", "Pad Length", FieldType::U8).optional(),
];

pub use crypto::{
    AuthenticationAlgorithm, DecryptedEsp, EncryptionAlgorithm, EspSa,
    parse_authentication_algorithm, parse_encryption_algorithm,
};

/// Minimum ESP header size: SPI (4) + Sequence Number (4) = 8 bytes.
///
/// RFC 4303, Section 2: <https://www.rfc-editor.org/rfc/rfc4303#section-2>
const HEADER_MIN_SIZE: usize = 8;

/// Shared SA database with a fast-path emptiness check.
///
/// The `AtomicBool` avoids Mutex lock overhead on the hot path when no SAs
/// are configured (the common case).
pub struct SharedEspSaDb {
    db: Mutex<HashMap<u32, Arc<EspSa>>>,
    has_sas: AtomicBool,
}

impl Default for SharedEspSaDb {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedEspSaDb {
    /// Create an empty SA database.
    pub fn new() -> Self {
        Self {
            db: Mutex::new(HashMap::new()),
            has_sas: AtomicBool::new(false),
        }
    }

    /// Add a Security Association.
    ///
    /// If the mutex is poisoned (a prior holder panicked), the lock is
    /// recovered so SA insertion still succeeds.
    pub fn insert(&self, spi: u32, sa: EspSa) {
        let mut db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.insert(spi, Arc::new(sa));
        self.has_sas.store(true, Ordering::Release);
    }

    /// Look up an SA by SPI. Returns `None` fast if no SAs are configured.
    fn get(&self, spi: u32) -> Option<Arc<EspSa>> {
        if !self.has_sas.load(Ordering::Acquire) {
            return None;
        }
        let db = self.db.lock().ok()?;
        db.get(&spi).map(Arc::clone)
    }
}

/// Shared SA database type.
pub type EspSaDb = Arc<SharedEspSaDb>;

/// ESP dissector.
///
/// Unlike most dissectors (which are zero-sized unit structs), `EspDissector`
/// is stateful: it holds a shared Security Association (SA) database used for
/// decryption. When no SAs are configured, it behaves identically to a
/// stateless dissector — the `AtomicBool` guard ensures zero synchronization
/// overhead on the hot path.
///
/// Parses the IP Encapsulating Security Payload (protocol 50) as defined
/// in RFC 4303. When SA parameters are provided, the dissector can decrypt
/// the payload and chain to the inner protocol.
pub struct EspDissector {
    sa_db: EspSaDb,
}

impl EspDissector {
    /// Create a new ESP dissector without any SAs (no decryption).
    pub fn new() -> Self {
        Self {
            sa_db: Arc::new(SharedEspSaDb::new()),
        }
    }

    /// Create a new ESP dissector with a shared SA database.
    ///
    /// This allows external code (e.g., the CLI) to add SAs after
    /// the dissector has been registered in the registry.
    pub fn with_sa_db(sa_db: EspSaDb) -> Self {
        Self { sa_db }
    }

    /// Add a Security Association for decryption.
    pub fn add_sa(&self, spi: u32, sa: EspSa) {
        self.sa_db.insert(spi, sa);
    }

    /// Get a reference to the shared SA database.
    pub fn sa_db(&self) -> &EspSaDb {
        &self.sa_db
    }
}

impl Default for EspDissector {
    fn default() -> Self {
        Self::new()
    }
}

impl Dissector for EspDissector {
    fn name(&self) -> &'static str {
        "Encapsulating Security Payload"
    }

    fn short_name(&self) -> &'static str {
        "ESP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < HEADER_MIN_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_MIN_SIZE,
                actual: data.len(),
            });
        }

        // RFC 4303, Section 2.1 — SPI
        // <https://www.rfc-editor.org/rfc/rfc4303#section-2.1>
        let spi = read_be_u32(data, 0)?;

        // RFC 4303, Section 2.2 — Sequence Number
        // <https://www.rfc-editor.org/rfc/rfc4303#section-2.2>
        let sequence_number = read_be_u32(data, 4)?;

        let total_len = data.len();

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SPI],
            FieldValue::U32(spi),
            offset..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEQUENCE_NUMBER],
            FieldValue::U32(sequence_number),
            offset + 4..offset + 8,
        );

        // Try decryption if we have an SA for this SPI
        let decrypted = if total_len > HEADER_MIN_SIZE {
            let encrypted_data = &data[HEADER_MIN_SIZE..total_len];
            self.try_decrypt(spi, sequence_number, encrypted_data, offset, total_len, buf)
        } else {
            None
        };

        // If no decryption occurred, show encrypted_data field
        if decrypted.is_none() && total_len > HEADER_MIN_SIZE {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_ENCRYPTED_DATA],
                FieldValue::Bytes(&data[HEADER_MIN_SIZE..total_len]),
                offset + HEADER_MIN_SIZE..offset + total_len,
            );
        }

        buf.end_layer();

        match decrypted {
            Some(dp) => Ok(DissectResult::with_decrypted_payload(total_len, dp)),
            None => Ok(DissectResult::new(total_len, DispatchHint::End)),
        }
    }
}

impl EspDissector {
    /// Try to decrypt the ESP payload.
    ///
    /// First looks up a configured SA in the database. When no SA is
    /// present, falls back to a heuristic NULL-encryption decode
    /// ([`crypto::try_null_decrypt`]) so that unauthenticated plaintext
    /// ESP flows can still be chained into the inner protocol dissector
    /// without manual configuration.
    ///
    /// Returns `Some(DecryptedPayload)` on success, `None` when no decoding
    /// was possible (graceful degradation to displaying the raw encrypted
    /// bytes).
    fn try_decrypt(
        &self,
        spi: u32,
        seq: u32,
        encrypted_data: &[u8],
        offset: usize,
        total_len: usize,
        buf: &mut DissectBuffer<'_>,
    ) -> Option<DecryptedPayload> {
        // Determine the decrypted trailer and ICV length based on whether
        // an SA is configured. Without an SA, the heuristic NULL path
        // assumes no authentication (ICV length = 0).
        let (result, icv_len) = match self.sa_db.get(spi) {
            Some(sa) => {
                let result = crypto::decrypt_esp(&sa, spi, seq, encrypted_data).ok()?;
                (result, sa.authentication.icv_len())
            }
            None => (crypto::try_null_decrypt(encrypted_data)?, 0),
        };

        // Byte ranges for trailer fields point at the ESP trailer's original
        // position in the packet (last 2 bytes before the ICV, if any).
        if icv_len > total_len {
            return None;
        }
        let trailer_end = offset + total_len - icv_len;
        let next_header_range = trailer_end.saturating_sub(1)..trailer_end;
        let pad_length_range = trailer_end.saturating_sub(2)..trailer_end.saturating_sub(1);

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_HEADER],
            FieldValue::U8(result.next_header),
            next_header_range,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAD_LENGTH],
            FieldValue::U8(result.pad_length),
            pad_length_range,
        );

        Some(DecryptedPayload {
            data: result.payload,
            next: DispatchHint::ByIpProtocol(result.next_header),
        })
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 4303 (ESP) Coverage
    //!
    //! | RFC Section | Description                       | Test                            |
    //! |-------------|-----------------------------------|---------------------------------|
    //! | 2           | Header Format                     | parse_esp_basic                 |
    //! | 2.1         | SPI                               | parse_esp_basic                 |
    //! | 2.2         | Sequence Number                   | parse_esp_basic                 |
    //! | 2.3-2.7     | Encrypted Data                    | parse_esp_with_payload          |
    //! | —           | Truncated header                  | truncated_header                |
    //! | —           | Header only (no payload)          | parse_esp_header_only           |
    //! | —           | NULL decryption (with SA)         | decrypt_null_sa                 |
    //! | —           | AES-CBC decryption                | decrypt_aes_128_cbc             |
    //! | —           | No SA (graceful)                  | no_sa_shows_encrypted           |
    //! | 2.4-2.6     | NULL heuristic (no SA)            | null_heuristic_decrypts_without_sa |
    //! | 2.4         | NULL heuristic padding            | null_heuristic_with_padding     |
    //! | 2.4         | NULL heuristic bad padding        | null_heuristic_fails_bad_padding |
    //! | —           | SA overrides heuristic            | sa_takes_priority_over_heuristic |

    use super::*;

    #[test]
    fn parse_esp_basic() {
        let data: &[u8] = &[
            0x00, 0x00, 0x10, 0x01, // SPI = 0x00001001
            0x00, 0x00, 0x00, 0x05, // Sequence Number = 5
            0xDE, 0xAD, 0xBE, 0xEF, // encrypted data
        ];
        let mut buf = DissectBuffer::new();
        let result = EspDissector::new().dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 12);
        assert_eq!(result.next, DispatchHint::End);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "ESP");
        assert_eq!(
            buf.field_by_name(layer, "spi").unwrap().value,
            FieldValue::U32(0x0000_1001)
        );
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().value,
            FieldValue::U32(5)
        );
        assert_eq!(
            buf.field_by_name(layer, "encrypted_data").unwrap().value,
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn parse_esp_header_only() {
        let data: &[u8] = &[
            0x00, 0x00, 0x10, 0x01, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
        ];
        let mut buf = DissectBuffer::new();
        let result = EspDissector::new().dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "encrypted_data").is_none());
    }

    #[test]
    fn parse_esp_with_payload() {
        let mut data = vec![
            0xAB, 0xCD, 0xEF, 0x01, // SPI = 0xABCDEF01
            0x00, 0x00, 0x00, 0x64, // Sequence Number = 100
        ];
        // 128 bytes of encrypted data. The final byte 0xFF is not a known
        // IP protocol number, ensuring the NULL-decryption heuristic does
        // not match and the payload is displayed as opaque encrypted_data.
        let mut payload = vec![0x01; 127];
        payload.push(0xFF);
        data.extend_from_slice(&payload);

        let mut buf = DissectBuffer::new();
        let result = EspDissector::new().dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 136);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "encrypted_data").unwrap().value,
            FieldValue::Bytes(&payload)
        );
    }

    #[test]
    fn truncated_header() {
        let data = [0u8; 7]; // Less than 8 bytes
        let mut buf = DissectBuffer::new();
        let err = EspDissector::new().dissect(&data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 7
            }
        ));
    }

    #[test]
    fn offset_applied_correctly() {
        let data: &[u8] = &[
            0x00, 0x00, 0x10, 0x01, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number
        ];
        let mut buf = DissectBuffer::new();
        EspDissector::new().dissect(data, &mut buf, 50).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 50..58);
        assert_eq!(buf.field_by_name(layer, "spi").unwrap().range, 50..54);
        assert_eq!(
            buf.field_by_name(layer, "sequence_number").unwrap().range,
            54..58
        );
    }

    #[test]
    fn field_descriptors_match() {
        let descriptors = EspDissector::new().field_descriptors();
        assert_eq!(descriptors.len(), 5);
        assert_eq!(descriptors[0].name, "spi");
        assert_eq!(descriptors[1].name, "sequence_number");
        assert_eq!(descriptors[2].name, "encrypted_data");
        assert_eq!(descriptors[3].name, "next_header");
        assert!(descriptors[3].display_fn.is_some());
        assert_eq!(descriptors[4].name, "pad_length");
    }

    #[test]
    fn decrypt_null_sa() {
        let dissector = EspDissector::new();
        dissector.add_sa(
            0x1001,
            EspSa {
                encryption: EncryptionAlgorithm::Null,
                enc_key: vec![],
                authentication: AuthenticationAlgorithm::None,
                auth_key: vec![],
            },
        );

        // SPI=0x1001, seq=1, payload=[0x45, 0x00] + pad_len=0 + next_header=4 (IPv4)
        let data: &[u8] = &[
            0x00, 0x00, 0x10, 0x01, // SPI
            0x00, 0x00, 0x00, 0x01, // seq
            0x45, 0x00, 0x00, 0x04, // "encrypted": payload + trailer
        ];
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        // Should have decrypted payload
        assert!(result.decrypted_payload.is_some());
        let dp = result.decrypted_payload.unwrap();
        assert_eq!(dp.next, DispatchHint::ByIpProtocol(4));
        assert_eq!(dp.data, vec![0x45, 0x00]);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "pad_length").unwrap().value,
            FieldValue::U8(0)
        );
        // encrypted_data should NOT be present when decrypted
        assert!(buf.field_by_name(layer, "encrypted_data").is_none());
    }

    #[test]
    fn decrypt_aes_128_cbc() {
        use aes::Aes128;
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];

        // Build plaintext: inner(12) + pad(0x01, 0x02) + pad_len(2) + next_header(4)
        let mut plaintext = vec![0x45; 12];
        plaintext.extend_from_slice(&[0x01, 0x02]);
        plaintext.push(2);
        plaintext.push(4);

        let mut ciphertext = plaintext.clone();
        cbc::Encryptor::<Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut ciphertext, 16)
            .unwrap();

        let spi: u32 = 0x2002;
        let mut data = Vec::new();
        data.extend_from_slice(&spi.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes()); // seq
        data.extend_from_slice(&iv);
        data.extend_from_slice(&ciphertext);

        let dissector = EspDissector::new();
        dissector.add_sa(
            spi,
            EspSa {
                encryption: EncryptionAlgorithm::Aes128Cbc,
                enc_key: key.to_vec(),
                authentication: AuthenticationAlgorithm::None,
                auth_key: vec![],
            },
        );

        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        assert!(result.decrypted_payload.is_some());
        let dp = result.decrypted_payload.unwrap();
        assert_eq!(dp.next, DispatchHint::ByIpProtocol(4));
        assert_eq!(dp.data, vec![0x45; 12]);
    }

    #[test]
    fn no_sa_shows_encrypted() {
        let dissector = EspDissector::new();
        // No SA added for this SPI

        // Final byte 0xEF (239) is not a known IP protocol, so the NULL
        // decryption heuristic returns None and the dissector falls back
        // to displaying the opaque encrypted_data field.
        let data: &[u8] = &[
            0x00, 0x00, 0x30, 0x03, // SPI = 0x3003
            0x00, 0x00, 0x00, 0x01, // seq
            0xDE, 0xAD, 0xBE, 0xEF, // encrypted data
        ];
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.next, DispatchHint::End);
        assert!(result.decrypted_payload.is_none());
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "encrypted_data").is_some());
        assert!(buf.field_by_name(layer, "next_header").is_none());
    }

    #[test]
    fn null_heuristic_decrypts_without_sa() {
        let dissector = EspDissector::new();
        // No SA configured.

        // Payload layout: inner=[0x45, 0x00] + pad_length=0 + next_header=6 (TCP)
        let data: &[u8] = &[
            0x00, 0x00, 0x40, 0x04, // SPI = 0x4004
            0x00, 0x00, 0x00, 0x02, // seq = 2
            0x45, 0x00, 0x00, 0x06, // inner + trailer
        ];
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        // Heuristic should succeed and expose a decrypted payload.
        assert!(result.decrypted_payload.is_some());
        let dp = result.decrypted_payload.unwrap();
        assert_eq!(dp.next, DispatchHint::ByIpProtocol(6));
        assert_eq!(dp.data, vec![0x45, 0x00]);

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "pad_length").unwrap().value,
            FieldValue::U8(0)
        );
        // encrypted_data must NOT be present when the heuristic succeeded.
        assert!(buf.field_by_name(layer, "encrypted_data").is_none());
    }

    #[test]
    fn null_heuristic_with_padding() {
        let dissector = EspDissector::new();

        // inner=[0xAA] + padding=[0x01,0x02] + pad_length=2 + next_header=17 (UDP)
        let data: &[u8] = &[
            0x00, 0x00, 0x40, 0x05, // SPI
            0x00, 0x00, 0x00, 0x01, // seq
            0xAA, 0x01, 0x02, 0x02, 0x11,
        ];
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        let dp = result.decrypted_payload.unwrap();
        assert_eq!(dp.next, DispatchHint::ByIpProtocol(17));
        assert_eq!(dp.data, vec![0xAA]);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "pad_length").unwrap().value,
            FieldValue::U8(2)
        );
    }

    #[test]
    fn null_heuristic_fails_bad_padding() {
        let dissector = EspDissector::new();

        // pad_length=2 but padding bytes [0x03, 0x02] don't match [0x01, 0x02].
        let data: &[u8] = &[
            0x00, 0x00, 0x40, 0x06, // SPI
            0x00, 0x00, 0x00, 0x01, // seq
            0x45, 0x03, 0x02, 0x02, 0x06,
        ];
        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(data, &mut buf, 0).unwrap();

        assert!(result.decrypted_payload.is_none());
        assert_eq!(result.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "encrypted_data").is_some());
        assert!(buf.field_by_name(layer, "next_header").is_none());
    }

    #[test]
    fn sa_takes_priority_over_heuristic() {
        // When an SA is configured, the SA path must be used even if the
        // heuristic would also succeed on the same bytes.
        let dissector = EspDissector::new();
        dissector.add_sa(
            0x5005,
            EspSa {
                encryption: EncryptionAlgorithm::Null,
                enc_key: vec![],
                authentication: AuthenticationAlgorithm::HmacSha1_96,
                auth_key: vec![0; 20],
            },
        );

        // The SA has a 12-byte ICV, so the dissector strips the last 12 bytes
        // before extracting the trailer. Plaintext+trailer = [0x45, 0x00, 0x00, 0x04],
        // followed by a 12-byte ICV.
        let mut data = vec![
            0x00, 0x00, 0x50, 0x05, // SPI
            0x00, 0x00, 0x00, 0x01, // seq
            0x45, 0x00, 0x00, 0x04, // payload + trailer
        ];
        data.extend_from_slice(&[0xAA; 12]); // ICV

        let mut buf = DissectBuffer::new();
        let result = dissector.dissect(&data, &mut buf, 0).unwrap();

        let dp = result.decrypted_payload.unwrap();
        assert_eq!(dp.next, DispatchHint::ByIpProtocol(4));
        assert_eq!(dp.data, vec![0x45, 0x00]);
    }
}
