//! Name tables for TLS registry values.
//!
//! Generated from the IANA registries as of 2026-09-29:
//! - TLS Cipher Suites: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>
//! - TLS Supported Groups: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8>
//! - TLS SignatureScheme: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme>
//! - TLS ExtensionType Values: <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1>
//! - QUIC Transport Parameters (permanent entries): <https://www.iana.org/assignments/quic/quic.xhtml#quic-transport>
//!
//! GREASE values are reported as `"GREASE"`
//! (RFC 8701, Section 2 — <https://www.rfc-editor.org/rfc/rfc8701#section-2>).

/// Whether a 16-bit value is a GREASE value for cipher suites, extensions,
/// named groups, signature algorithms, or versions (0x0A0A, 0x1A1A, ...,
/// 0xFAFA).
///
/// RFC 8701, Section 2 — <https://www.rfc-editor.org/rfc/rfc8701#section-2>
pub(crate) fn is_grease_u16(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// Whether an 8-bit value is a GREASE value for `PskKeyExchangeMode`
/// (0x0B, 0x2A, ..., 0xE4).
///
/// RFC 8701, Section 2 — <https://www.rfc-editor.org/rfc/rfc8701#section-2>
pub(crate) fn is_grease_psk_ke_mode(v: u8) -> bool {
    v >= 0x0b && (v - 0x0b) % 0x1f == 0
}

/// Returns the IANA name of a `CipherSuite` value.
///
/// RFC 9846, Appendix B.4 — <https://www.rfc-editor.org/rfc/rfc9846#appendix-B.4>
pub(crate) fn cipher_suite_name(v: u16) -> Option<&'static str> {
    if is_grease_u16(v) {
        return Some("GREASE");
    }
    Some(match v {
        0x0000 => "TLS_NULL_WITH_NULL_NULL",
        0x0001 => "TLS_RSA_WITH_NULL_MD5",
        0x0002 => "TLS_RSA_WITH_NULL_SHA",
        0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0006 => "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0007 => "TLS_RSA_WITH_IDEA_CBC_SHA",
        0x0008 => "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0009 => "TLS_RSA_WITH_DES_CBC_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x000b => "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x000c => "TLS_DH_DSS_WITH_DES_CBC_SHA",
        0x000d => "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        0x000e => "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x000f => "TLS_DH_RSA_WITH_DES_CBC_SHA",
        0x0010 => "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0011 => "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0012 => "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        0x0013 => "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        0x0014 => "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0015 => "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        0x0016 => "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0017 => "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        0x0018 => "TLS_DH_anon_WITH_RC4_128_MD5",
        0x0019 => "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        0x001a => "TLS_DH_anon_WITH_DES_CBC_SHA",
        0x001b => "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        0x001e => "TLS_KRB5_WITH_DES_CBC_SHA",
        0x001f => "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
        0x0020 => "TLS_KRB5_WITH_RC4_128_SHA",
        0x0021 => "TLS_KRB5_WITH_IDEA_CBC_SHA",
        0x0022 => "TLS_KRB5_WITH_DES_CBC_MD5",
        0x0023 => "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
        0x0024 => "TLS_KRB5_WITH_RC4_128_MD5",
        0x0025 => "TLS_KRB5_WITH_IDEA_CBC_MD5",
        0x0026 => "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
        0x0027 => "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
        0x0028 => "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
        0x0029 => "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
        0x002a => "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
        0x002b => "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
        0x002c => "TLS_PSK_WITH_NULL_SHA",
        0x002d => "TLS_DHE_PSK_WITH_NULL_SHA",
        0x002e => "TLS_RSA_PSK_WITH_NULL_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0030 => "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        0x0031 => "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        0x0032 => "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0034 => "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0036 => "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
        0x0037 => "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
        0x0038 => "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x003a => "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        0x003b => "TLS_RSA_WITH_NULL_SHA256",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x003e => "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
        0x003f => "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
        0x0040 => "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        0x0041 => "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0042 => "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
        0x0043 => "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0044 => "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        0x0045 => "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0046 => "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x0068 => "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
        0x0069 => "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
        0x006a => "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        0x006b => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x006c => "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
        0x006d => "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
        0x006e => "TLS_ASCONAEAD128_ASCONHASH256",
        0x006f => "TLS_ASCONAEAD128_SHA256",
        0x0070 => "TLS_AES_128_GCM_ASCONHASH256",
        0x0071 => "TLS_AES_128_CCM_ASCONHASH256",
        0x0084 => "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0085 => "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
        0x0086 => "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0087 => "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        0x0088 => "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0089 => "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        0x008a => "TLS_PSK_WITH_RC4_128_SHA",
        0x008b => "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
        0x008c => "TLS_PSK_WITH_AES_128_CBC_SHA",
        0x008d => "TLS_PSK_WITH_AES_256_CBC_SHA",
        0x008e => "TLS_DHE_PSK_WITH_RC4_128_SHA",
        0x008f => "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
        0x0090 => "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
        0x0091 => "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
        0x0092 => "TLS_RSA_PSK_WITH_RC4_128_SHA",
        0x0093 => "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
        0x0094 => "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
        0x0095 => "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
        0x0096 => "TLS_RSA_WITH_SEED_CBC_SHA",
        0x0097 => "TLS_DH_DSS_WITH_SEED_CBC_SHA",
        0x0098 => "TLS_DH_RSA_WITH_SEED_CBC_SHA",
        0x0099 => "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        0x009a => "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        0x009b => "TLS_DH_anon_WITH_SEED_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x00a0 => "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        0x00a1 => "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        0x00a2 => "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        0x00a3 => "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        0x00a4 => "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        0x00a5 => "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        0x00a6 => "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
        0x00a7 => "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
        0x00a8 => "TLS_PSK_WITH_AES_128_GCM_SHA256",
        0x00a9 => "TLS_PSK_WITH_AES_256_GCM_SHA384",
        0x00aa => "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        0x00ab => "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        0x00ac => "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
        0x00ad => "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
        0x00ae => "TLS_PSK_WITH_AES_128_CBC_SHA256",
        0x00af => "TLS_PSK_WITH_AES_256_CBC_SHA384",
        0x00b0 => "TLS_PSK_WITH_NULL_SHA256",
        0x00b1 => "TLS_PSK_WITH_NULL_SHA384",
        0x00b2 => "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
        0x00b3 => "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
        0x00b4 => "TLS_DHE_PSK_WITH_NULL_SHA256",
        0x00b5 => "TLS_DHE_PSK_WITH_NULL_SHA384",
        0x00b6 => "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
        0x00b7 => "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
        0x00b8 => "TLS_RSA_PSK_WITH_NULL_SHA256",
        0x00b9 => "TLS_RSA_PSK_WITH_NULL_SHA384",
        0x00ba => "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bb => "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bc => "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bd => "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        0x00be => "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bf => "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
        0x00c0 => "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c1 => "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c2 => "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c3 => "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c4 => "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c5 => "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c6 => "TLS_SM4_GCM_SM3",
        0x00c7 => "TLS_SM4_CCM_SM3",
        0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0x1306 => "TLS_AEGIS_256_SHA512",
        0x1307 => "TLS_AEGIS_128L_SHA256",
        0x5600 => "TLS_FALLBACK_SCSV",
        0xc001 => "TLS_ECDH_ECDSA_WITH_NULL_SHA",
        0xc002 => "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        0xc003 => "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xc004 => "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        0xc005 => "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        0xc006 => "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        0xc007 => "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        0xc008 => "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc00b => "TLS_ECDH_RSA_WITH_NULL_SHA",
        0xc00c => "TLS_ECDH_RSA_WITH_RC4_128_SHA",
        0xc00d => "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc00e => "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        0xc00f => "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        0xc010 => "TLS_ECDHE_RSA_WITH_NULL_SHA",
        0xc011 => "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        0xc012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc015 => "TLS_ECDH_anon_WITH_NULL_SHA",
        0xc016 => "TLS_ECDH_anon_WITH_RC4_128_SHA",
        0xc017 => "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
        0xc018 => "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        0xc019 => "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        0xc01a => "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        0xc01b => "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc01c => "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        0xc01d => "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        0xc01e => "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        0xc01f => "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        0xc020 => "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
        0xc021 => "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        0xc022 => "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc025 => "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc026 => "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc029 => "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        0xc02a => "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02d => "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02e => "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc031 => "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        0xc032 => "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        0xc033 => "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
        0xc034 => "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
        0xc035 => "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        0xc036 => "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
        0xc037 => "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        0xc038 => "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        0xc039 => "TLS_ECDHE_PSK_WITH_NULL_SHA",
        0xc03a => "TLS_ECDHE_PSK_WITH_NULL_SHA256",
        0xc03b => "TLS_ECDHE_PSK_WITH_NULL_SHA384",
        0xc03c => "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc03d => "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc03e => "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
        0xc03f => "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
        0xc040 => "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc041 => "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc042 => "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
        0xc043 => "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
        0xc044 => "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc045 => "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc046 => "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
        0xc047 => "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
        0xc048 => "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
        0xc049 => "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
        0xc04a => "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
        0xc04b => "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
        0xc04c => "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc04d => "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc04e => "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc04f => "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc050 => "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc051 => "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc052 => "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc053 => "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc054 => "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc055 => "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc056 => "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
        0xc057 => "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
        0xc058 => "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
        0xc059 => "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
        0xc05a => "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
        0xc05b => "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
        0xc05c => "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
        0xc05d => "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
        0xc05e => "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
        0xc05f => "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
        0xc060 => "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc061 => "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc062 => "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc063 => "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc064 => "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc065 => "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc066 => "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc067 => "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc068 => "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc069 => "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc06a => "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
        0xc06b => "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
        0xc06c => "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
        0xc06d => "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
        0xc06e => "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
        0xc06f => "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
        0xc070 => "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc071 => "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc072 => "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc073 => "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc074 => "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc075 => "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc076 => "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc077 => "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc078 => "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc079 => "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc07a => "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc07b => "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc07c => "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc07d => "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc07e => "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc07f => "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc080 => "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        0xc081 => "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        0xc082 => "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        0xc083 => "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        0xc084 => "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
        0xc085 => "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
        0xc086 => "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc087 => "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc088 => "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc089 => "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc08a => "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc08b => "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc08c => "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc08d => "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc08e => "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        0xc08f => "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        0xc090 => "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        0xc091 => "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        0xc092 => "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        0xc093 => "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        0xc094 => "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc095 => "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc096 => "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc097 => "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc098 => "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc099 => "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc09a => "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc09b => "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc09c => "TLS_RSA_WITH_AES_128_CCM",
        0xc09d => "TLS_RSA_WITH_AES_256_CCM",
        0xc09e => "TLS_DHE_RSA_WITH_AES_128_CCM",
        0xc09f => "TLS_DHE_RSA_WITH_AES_256_CCM",
        0xc0a0 => "TLS_RSA_WITH_AES_128_CCM_8",
        0xc0a1 => "TLS_RSA_WITH_AES_256_CCM_8",
        0xc0a2 => "TLS_DHE_RSA_WITH_AES_128_CCM_8",
        0xc0a3 => "TLS_DHE_RSA_WITH_AES_256_CCM_8",
        0xc0a4 => "TLS_PSK_WITH_AES_128_CCM",
        0xc0a5 => "TLS_PSK_WITH_AES_256_CCM",
        0xc0a6 => "TLS_DHE_PSK_WITH_AES_128_CCM",
        0xc0a7 => "TLS_DHE_PSK_WITH_AES_256_CCM",
        0xc0a8 => "TLS_PSK_WITH_AES_128_CCM_8",
        0xc0a9 => "TLS_PSK_WITH_AES_256_CCM_8",
        0xc0aa => "TLS_PSK_DHE_WITH_AES_128_CCM_8",
        0xc0ab => "TLS_PSK_DHE_WITH_AES_256_CCM_8",
        0xc0ac => "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        0xc0ad => "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        0xc0ae => "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        0xc0af => "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
        0xc0b0 => "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
        0xc0b1 => "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
        0xc0b2 => "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
        0xc0b3 => "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
        0xc0b4 => "TLS_SHA256_SHA256",
        0xc0b5 => "TLS_SHA384_SHA384",
        0xc100 => "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
        0xc101 => "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
        0xc102 => "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
        0xc103 => "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
        0xc104 => "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
        0xc105 => "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
        0xc106 => "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccab => "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xccac => "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xccad => "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xccae => "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
        0xd001 => "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        0xd002 => "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
        0xd003 => "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
        0xd005 => "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
        _ => return None,
    })
}

/// Returns the IANA name of a `NamedGroup` value.
///
/// RFC 9846, Section 4.3.7 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.7>
pub(crate) fn named_group_name(v: u16) -> &'static str {
    if is_grease_u16(v) {
        return "GREASE";
    }
    match v {
        0x0001 => "sect163k1",
        0x0002 => "sect163r1",
        0x0003 => "sect163r2",
        0x0004 => "sect193r1",
        0x0005 => "sect193r2",
        0x0006 => "sect233k1",
        0x0007 => "sect233r1",
        0x0008 => "sect239k1",
        0x0009 => "sect283k1",
        0x000a => "sect283r1",
        0x000b => "sect409k1",
        0x000c => "sect409r1",
        0x000d => "sect571k1",
        0x000e => "sect571r1",
        0x000f => "secp160k1",
        0x0010 => "secp160r1",
        0x0011 => "secp160r2",
        0x0012 => "secp192k1",
        0x0013 => "secp192r1",
        0x0014 => "secp224k1",
        0x0015 => "secp224r1",
        0x0016 => "secp256k1",
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001a => "brainpoolP256r1",
        0x001b => "brainpoolP384r1",
        0x001c => "brainpoolP512r1",
        0x001d => "x25519",
        0x001e => "x448",
        0x001f => "brainpoolP256r1tls13",
        0x0020 => "brainpoolP384r1tls13",
        0x0021 => "brainpoolP512r1tls13",
        0x0022 => "GC256A",
        0x0023 => "GC256B",
        0x0024 => "GC256C",
        0x0025 => "GC256D",
        0x0026 => "GC512A",
        0x0027 => "GC512B",
        0x0028 => "GC512C",
        0x0029 => "curveSM2",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x0103 => "ffdhe6144",
        0x0104 => "ffdhe8192",
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",
        0x11e9 => "SecP256r1MLKEM512",
        0x11ea => "MLKEM512X25519",
        0x11eb => "SecP256r1MLKEM768",
        0x11ec => "X25519MLKEM768",
        0x11ed => "SecP384r1MLKEM1024",
        0x11ee => "curveSM2MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        0x639a => "SecP256r1Kyber768Draft00",
        0xff01 => "arbitrary_explicit_prime_curves",
        0xff02 => "arbitrary_explicit_char2_curves",
        _ => "unknown",
    }
}

/// Returns the IANA name of a `SignatureScheme` value.
///
/// RFC 9846, Section 4.3.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.3>
pub(crate) fn signature_scheme_name(v: u16) -> &'static str {
    if is_grease_u16(v) {
        return "GREASE";
    }
    match v {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0420 => "rsa_pkcs1_sha256_legacy",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0520 => "rsa_pkcs1_sha384_legacy",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0620 => "rsa_pkcs1_sha512_legacy",
        0x0704 => "eccsi_sha256",
        0x0705 => "iso_ibs1",
        0x0706 => "iso_ibs2",
        0x0707 => "iso_chinese_ibs",
        0x0708 => "sm2sig_sm3",
        0x0709 => "gostr34102012_256a",
        0x070a => "gostr34102012_256b",
        0x070b => "gostr34102012_256c",
        0x070c => "gostr34102012_256d",
        0x070d => "gostr34102012_512a",
        0x070e => "gostr34102012_512b",
        0x070f => "gostr34102012_512c",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        0x081a => "ecdsa_brainpoolP256r1tls13_sha256",
        0x081b => "ecdsa_brainpoolP384r1tls13_sha384",
        0x081c => "ecdsa_brainpoolP512r1tls13_sha512",
        0x0904 => "mldsa44",
        0x0905 => "mldsa65",
        0x0906 => "mldsa87",
        0x0911 => "slhdsa_sha2_128s",
        0x0912 => "slhdsa_sha2_128f",
        0x0913 => "slhdsa_sha2_192s",
        0x0914 => "slhdsa_sha2_192f",
        0x0915 => "slhdsa_sha2_256s",
        0x0916 => "slhdsa_sha2_256f",
        0x0917 => "slhdsa_shake_128s",
        0x0918 => "slhdsa_shake_128f",
        0x0919 => "slhdsa_shake_192s",
        0x091a => "slhdsa_shake_192f",
        0x091b => "slhdsa_shake_256s",
        0x091c => "slhdsa_shake_256f",
        _ => "unknown",
    }
}

/// Returns the IANA name of an `ExtensionType` value.
///
/// RFC 9846, Section 4.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3>
pub(crate) fn extension_type_name(v: u16) -> &'static str {
    if is_grease_u16(v) {
        return "GREASE";
    }
    match v {
        0x0000 => "server_name",
        0x0001 => "max_fragment_length",
        0x0002 => "client_certificate_url",
        0x0003 => "trusted_ca_keys",
        0x0004 => "truncated_hmac",
        0x0005 => "status_request",
        0x0006 => "user_mapping",
        0x0007 => "client_authz",
        0x0008 => "server_authz",
        0x0009 => "cert_type",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000c => "srp",
        0x000d => "signature_algorithms",
        0x000e => "use_srtp",
        0x000f => "heartbeat",
        0x0010 => "application_layer_protocol_negotiation",
        0x0011 => "status_request_v2",
        0x0012 => "signed_certificate_timestamp",
        0x0013 => "client_certificate_type",
        0x0014 => "server_certificate_type",
        0x0015 => "padding",
        0x0016 => "encrypt_then_mac",
        0x0017 => "extended_main_secret",
        0x0018 => "token_binding",
        0x0019 => "cached_info",
        0x001a => "tls_lts",
        0x001b => "compress_certificate",
        0x001c => "record_size_limit",
        0x001d => "pwd_protect",
        0x001e => "pwd_clear",
        0x001f => "password_salt",
        0x0020 => "ticket_pinning",
        0x0021 => "tls_cert_with_extern_psk",
        0x0022 => "delegated_credential",
        0x0023 => "session_ticket",
        0x0024 => "TLMSP",
        0x0025 => "TLMSP_proxying",
        0x0026 => "TLMSP_delegate",
        0x0027 => "supported_ekt_ciphers",
        0x0029 => "pre_shared_key",
        0x002a => "early_data",
        0x002b => "supported_versions",
        0x002c => "cookie",
        0x002d => "psk_key_exchange_modes",
        0x002f => "certificate_authorities",
        0x0030 => "oid_filters",
        0x0031 => "post_handshake_auth",
        0x0032 => "signature_algorithms_cert",
        0x0033 => "key_share",
        0x0034 => "transparency_info",
        0x0035 => "connection_id_deprecated",
        0x0036 => "connection_id",
        0x0037 => "external_id_hash",
        0x0038 => "external_session_id",
        0x0039 => "quic_transport_parameters",
        0x003a => "ticket_request",
        0x003b => "dnssec_chain",
        0x003c => "sequence_number_encryption_algorithms",
        0x003d => "rrc",
        0x003e => "tls_flags",
        0xfd00 => "ech_outer_extensions",
        0xfe0d => "encrypted_client_hello",
        0xff01 => "renegotiation_info",
        _ => "unknown",
    }
}

/// Returns the IANA name of a QUIC transport parameter ID.
///
/// RFC 9000, Section 18.2 — <https://www.rfc-editor.org/rfc/rfc9000#section-18.2>
pub(crate) fn quic_transport_parameter_name(id: u64) -> &'static str {
    match id {
        0x00 => "original_destination_connection_id",
        0x01 => "max_idle_timeout",
        0x02 => "stateless_reset_token",
        0x03 => "max_udp_payload_size",
        0x04 => "initial_max_data",
        0x05 => "initial_max_stream_data_bidi_local",
        0x06 => "initial_max_stream_data_bidi_remote",
        0x07 => "initial_max_stream_data_uni",
        0x08 => "initial_max_streams_bidi",
        0x09 => "initial_max_streams_uni",
        0x0a => "ack_delay_exponent",
        0x0b => "max_ack_delay",
        0x0c => "disable_active_migration",
        0x0d => "preferred_address",
        0x0e => "active_connection_id_limit",
        0x0f => "initial_source_connection_id",
        0x10 => "retry_source_connection_id",
        0x11 => "version_information",
        0x20 => "max_datagram_frame_size",
        0x2ab2 => "grease_quic_bit",
        // RFC 9000, Section 18.1 — https://www.rfc-editor.org/rfc/rfc9000#section-18.1
        // "31 * N + 27 for integer values of N are reserved to exercise the
        // requirement that unknown transport parameters be ignored."
        id if id % 31 == 27 => "reserved",
        _ => "unknown",
    }
}

/// Returns the name of an `ECPointFormat` value.
///
/// RFC 8422, Section 5.1.2 — <https://www.rfc-editor.org/rfc/rfc8422#section-5.1.2>
pub(crate) fn ec_point_format_name(v: u8) -> &'static str {
    match v {
        0 => "uncompressed",
        1 => "ansiX962_compressed_prime",
        2 => "ansiX962_compressed_char2",
        _ => "unknown",
    }
}

/// Returns the name of an `ECCurveType` value.
///
/// RFC 8422, Section 5.4 — <https://www.rfc-editor.org/rfc/rfc8422#section-5.4>
pub(crate) fn ec_curve_type_name(v: u8) -> &'static str {
    match v {
        1 => "explicit_prime",
        2 => "explicit_char2",
        3 => "named_curve",
        _ => "unknown",
    }
}

/// Returns the name of a `PskKeyExchangeMode` value.
///
/// RFC 9846, Section 4.3.9 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.3.9>
pub(crate) fn psk_ke_mode_name(v: u8) -> &'static str {
    if is_grease_psk_ke_mode(v) {
        return "GREASE";
    }
    match v {
        0 => "psk_ke",
        1 => "psk_dhe_ke",
        _ => "unknown",
    }
}

/// Returns the name of a `CertificateStatusType` value.
///
/// RFC 6066, Section 8 — <https://www.rfc-editor.org/rfc/rfc6066#section-8>
/// (`ocsp_multi(2)` is from RFC 6961, Section 2.2 —
/// <https://www.rfc-editor.org/rfc/rfc6961#section-2.2>).
pub(crate) fn certificate_status_type_name(v: u8) -> &'static str {
    match v {
        1 => "ocsp",
        2 => "ocsp_multi",
        _ => "unknown",
    }
}

/// Returns the name of a `CertificateCompressionAlgorithm` value.
///
/// RFC 8879, Section 3 — <https://www.rfc-editor.org/rfc/rfc8879#section-3>
pub(crate) fn certificate_compression_algorithm_name(v: u16) -> &'static str {
    match v {
        1 => "zlib",
        2 => "brotli",
        3 => "zstd",
        _ => "unknown",
    }
}

/// Returns the name of a `ClientCertificateType` value.
///
/// IANA TLS ClientCertificateType Identifiers:
/// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2>
/// RFC 5246, Section 7.4.4 — <https://www.rfc-editor.org/rfc/rfc5246#section-7.4.4>
pub(crate) fn client_certificate_type_name(v: u8) -> &'static str {
    match v {
        1 => "rsa_sign",
        2 => "dss_sign",
        3 => "rsa_fixed_dh",
        4 => "dss_fixed_dh",
        5 => "rsa_ephemeral_dh",
        6 => "dss_ephemeral_dh",
        20 => "fortezza_dms",
        64 => "ecdsa_sign",
        65 => "rsa_fixed_ecdh",
        66 => "ecdsa_fixed_ecdh",
        67 => "gost_sign256",
        68 => "gost_sign512",
        _ => "unknown",
    }
}

/// Returns the name of a `KeyUpdateRequest` value.
///
/// RFC 9846, Section 4.7.3 — <https://www.rfc-editor.org/rfc/rfc9846#section-4.7.3>
pub(crate) fn key_update_request_name(v: u8) -> &'static str {
    match v {
        0 => "update_not_requested",
        1 => "update_requested",
        _ => "unknown",
    }
}

/// Returns the name of a `HeartbeatMessageType` value.
///
/// RFC 6520, Section 3 — <https://www.rfc-editor.org/rfc/rfc6520#section-3>
pub(crate) fn heartbeat_message_type_name(v: u8) -> &'static str {
    match v {
        1 => "heartbeat_request",
        2 => "heartbeat_response",
        _ => "unknown",
    }
}

/// Returns the name of an `ECHClientHelloType` value.
///
/// RFC 9849, Section 5 — <https://www.rfc-editor.org/rfc/rfc9849#section-5>
pub(crate) fn ech_client_hello_type_name(v: u8) -> &'static str {
    match v {
        0 => "outer",
        1 => "inner",
        _ => "unknown",
    }
}

/// Returns the name of an HPKE KDF identifier.
///
/// RFC 9180, Section 7.2 — <https://www.rfc-editor.org/rfc/rfc9180#section-7.2>
/// and the IANA HPKE KDF Identifiers registry:
/// <https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-kdf-ids>
pub(crate) fn hpke_kdf_name(v: u16) -> &'static str {
    match v {
        1 => "HKDF-SHA256",
        2 => "HKDF-SHA384",
        3 => "HKDF-SHA512",
        0x10 => "SHAKE128",
        0x11 => "SHAKE256",
        0x12 => "TurboSHAKE128",
        0x13 => "TurboSHAKE256",
        _ => "unknown",
    }
}

/// Returns the name of an HPKE AEAD identifier.
///
/// RFC 9180, Section 7.3 — <https://www.rfc-editor.org/rfc/rfc9180#section-7.3>
/// and the IANA HPKE AEAD Identifiers registry:
/// <https://www.iana.org/assignments/hpke/hpke.xhtml#hpke-aead-ids>
pub(crate) fn hpke_aead_name(v: u16) -> &'static str {
    match v {
        1 => "AES-128-GCM",
        2 => "AES-256-GCM",
        3 => "ChaCha20Poly1305",
        0xffff => "Export-only",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    //! Checks that the generated tables match the IANA registry snapshot.

    use super::*;

    /// GREASE values in a 16-bit registry (RFC 8701, Section 2 (<https://www.rfc-editor.org/rfc/rfc8701#section-2>)).
    const GREASE_COUNT: usize = 16;

    #[test]
    fn registry_entry_counts() {
        let all = || 0..=u16::MAX;
        assert_eq!(all().filter(|&v| is_grease_u16(v)).count(), GREASE_COUNT);
        assert_eq!(
            all().filter(|&v| cipher_suite_name(v).is_some()).count(),
            356 + GREASE_COUNT
        );
        assert_eq!(
            all().filter(|&v| named_group_name(v) != "unknown").count(),
            59 + GREASE_COUNT
        );
        assert_eq!(
            all()
                .filter(|&v| signature_scheme_name(v) != "unknown")
                .count(),
            49 + GREASE_COUNT
        );
        assert_eq!(
            all()
                .filter(|&v| extension_type_name(v) != "unknown")
                .count(),
            64 + GREASE_COUNT
        );
        assert_eq!((0..=255u8).filter(|&v| is_grease_psk_ke_mode(v)).count(), 8);
        assert_eq!(
            (0..64u64)
                .filter(|&v| !matches!(quic_transport_parameter_name(v), "unknown" | "reserved"))
                .count(),
            19
        );
        assert_eq!(quic_transport_parameter_name(0x2ab2), "grease_quic_bit");
        assert_eq!(quic_transport_parameter_name(27), "reserved");
        assert_eq!(quic_transport_parameter_name(0x40), "unknown");
    }

    #[test]
    fn small_registries() {
        assert_eq!(ec_point_format_name(2), "ansiX962_compressed_char2");
        assert_eq!(ec_point_format_name(9), "unknown");
        assert_eq!(ec_curve_type_name(1), "explicit_prime");
        assert_eq!(ec_curve_type_name(2), "explicit_char2");
        assert_eq!(ec_curve_type_name(0), "unknown");
        assert_eq!(psk_ke_mode_name(0), "psk_ke");
        assert_eq!(psk_ke_mode_name(0xe4), "GREASE");
        assert_eq!(psk_ke_mode_name(2), "unknown");
        assert_eq!(certificate_status_type_name(2), "ocsp_multi");
        assert_eq!(certificate_status_type_name(0), "unknown");
        assert_eq!(certificate_compression_algorithm_name(9), "unknown");
        for (v, name) in [
            (2u8, "dss_sign"),
            (3, "rsa_fixed_dh"),
            (4, "dss_fixed_dh"),
            (5, "rsa_ephemeral_dh"),
            (6, "dss_ephemeral_dh"),
            (20, "fortezza_dms"),
            (65, "rsa_fixed_ecdh"),
            (66, "ecdsa_fixed_ecdh"),
            (67, "gost_sign256"),
            (68, "gost_sign512"),
            (0, "unknown"),
        ] {
            assert_eq!(client_certificate_type_name(v), name);
        }
        assert_eq!(key_update_request_name(0), "update_not_requested");
        assert_eq!(key_update_request_name(2), "unknown");
        assert_eq!(heartbeat_message_type_name(2), "heartbeat_response");
        assert_eq!(heartbeat_message_type_name(0), "unknown");
        assert_eq!(ech_client_hello_type_name(2), "unknown");
        for (v, name) in [
            (2u16, "HKDF-SHA384"),
            (3, "HKDF-SHA512"),
            (0x10, "SHAKE128"),
            (0x11, "SHAKE256"),
            (0x12, "TurboSHAKE128"),
            (0x13, "TurboSHAKE256"),
            (0, "unknown"),
        ] {
            assert_eq!(hpke_kdf_name(v), name);
        }
        for (v, name) in [
            (2u16, "AES-256-GCM"),
            (3, "ChaCha20Poly1305"),
            (0xffff, "Export-only"),
            (0, "unknown"),
        ] {
            assert_eq!(hpke_aead_name(v), name);
        }
    }
}
