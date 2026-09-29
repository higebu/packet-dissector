//! Name tables generated from the IANA IKEv2, IKE and ISAKMP registries.
//!
//! ## References
//! - IANA IKEv2 Parameters: <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml>
//! - IANA Internet Key Exchange (IKE) Attributes: <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml>
//! - IANA "Magic Numbers" for ISAKMP Protocol: <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml>
//!
//! Reserved, unassigned and private-use values return `None`.

/// IANA "Transform Type Values".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-3>
pub(crate) fn transform_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("Encryption Algorithm (ENCR)"),
        2 => Some("Pseudo-random Function (PRF)"),
        3 => Some("Integrity Algorithm (INTEG)"),
        4 => Some("Key Exchange Method (KE)"),
        5 => Some("Sequence Numbers (SN)"),
        6 => Some("Additional Key Exchange 1 (ADDKE1)"),
        7 => Some("Additional Key Exchange 2 (ADDKE2)"),
        8 => Some("Additional Key Exchange 3 (ADDKE3)"),
        9 => Some("Additional Key Exchange 4 (ADDKE4)"),
        10 => Some("Additional Key Exchange 5 (ADDKE5)"),
        11 => Some("Additional Key Exchange 6 (ADDKE6)"),
        12 => Some("Additional Key Exchange 7 (ADDKE7)"),
        13 => Some("Key Wrap Algorithm (KWA)"),
        14 => Some("Group Controller Authentication Method (GCAUTH)"),
        _ => None,
    }
}

/// IANA "Transform Type 1 - Encryption Algorithm Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5>
pub(crate) fn encr_transform_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("ENCR_DES_IV64"),
        2 => Some("ENCR_DES"),
        3 => Some("ENCR_3DES"),
        4 => Some("ENCR_RC5"),
        5 => Some("ENCR_IDEA"),
        6 => Some("ENCR_CAST"),
        7 => Some("ENCR_BLOWFISH"),
        8 => Some("ENCR_3IDEA"),
        9 => Some("ENCR_DES_IV32"),
        11 => Some("ENCR_NULL"),
        12 => Some("ENCR_AES_CBC"),
        13 => Some("ENCR_AES_CTR"),
        14 => Some("ENCR_AES_CCM_8"),
        15 => Some("ENCR_AES_CCM_12"),
        16 => Some("ENCR_AES_CCM_16"),
        18 => Some("ENCR_AES_GCM_8"),
        19 => Some("ENCR_AES_GCM_12"),
        20 => Some("ENCR_AES_GCM_16"),
        21 => Some("ENCR_NULL_AUTH_AES_GMAC"),
        23 => Some("ENCR_CAMELLIA_CBC"),
        24 => Some("ENCR_CAMELLIA_CTR"),
        25 => Some("ENCR_CAMELLIA_CCM_8"),
        26 => Some("ENCR_CAMELLIA_CCM_12"),
        27 => Some("ENCR_CAMELLIA_CCM_16"),
        28 => Some("ENCR_CHACHA20_POLY1305"),
        29 => Some("ENCR_AES_CCM_8_IIV"),
        30 => Some("ENCR_AES_GCM_16_IIV"),
        31 => Some("ENCR_CHACHA20_POLY1305_IIV"),
        32 => Some("ENCR_KUZNYECHIK_MGM_KTREE"),
        33 => Some("ENCR_MAGMA_MGM_KTREE"),
        34 => Some("ENCR_KUZNYECHIK_MGM_MAC_KTREE"),
        35 => Some("ENCR_MAGMA_MGM_MAC_KTREE"),
        _ => None,
    }
}

/// IANA "Transform Type 2 - Pseudorandom Function Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-6>
pub(crate) fn prf_transform_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("PRF_HMAC_MD5"),
        2 => Some("PRF_HMAC_SHA1"),
        3 => Some("PRF_HMAC_TIGER"),
        4 => Some("PRF_AES128_XCBC"),
        5 => Some("PRF_HMAC_SHA2_256"),
        6 => Some("PRF_HMAC_SHA2_384"),
        7 => Some("PRF_HMAC_SHA2_512"),
        8 => Some("PRF_AES128_CMAC"),
        9 => Some("PRF_HMAC_STREEBOG_512"),
        _ => None,
    }
}

/// IANA "Transform Type 3 - Integrity Algorithm Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7>
pub(crate) fn integ_transform_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("NONE"),
        1 => Some("AUTH_HMAC_MD5_96"),
        2 => Some("AUTH_HMAC_SHA1_96"),
        3 => Some("AUTH_DES_MAC"),
        4 => Some("AUTH_KPDK_MD5"),
        5 => Some("AUTH_AES_XCBC_96"),
        6 => Some("AUTH_HMAC_MD5_128"),
        7 => Some("AUTH_HMAC_SHA1_160"),
        8 => Some("AUTH_AES_CMAC_96"),
        9 => Some("AUTH_AES_128_GMAC"),
        10 => Some("AUTH_AES_192_GMAC"),
        11 => Some("AUTH_AES_256_GMAC"),
        12 => Some("AUTH_HMAC_SHA2_256_128"),
        13 => Some("AUTH_HMAC_SHA2_384_192"),
        14 => Some("AUTH_HMAC_SHA2_512_256"),
        _ => None,
    }
}

/// IANA "Transform Type 4 - Key Exchange Method Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-8>
pub(crate) fn ke_method_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("NONE"),
        1 => Some("768-bit MODP Group"),
        2 => Some("1024-bit MODP Group"),
        5 => Some("1536-bit MODP Group"),
        14 => Some("2048-bit MODP Group"),
        15 => Some("3072-bit MODP Group"),
        16 => Some("4096-bit MODP Group"),
        17 => Some("6144-bit MODP Group"),
        18 => Some("8192-bit MODP Group"),
        19 => Some("256-bit random ECP group"),
        20 => Some("384-bit random ECP group"),
        21 => Some("521-bit random ECP group"),
        22 => Some("1024-bit MODP Group with 160-bit Prime Order Subgroup"),
        23 => Some("2048-bit MODP Group with 224-bit Prime Order Subgroup"),
        24 => Some("2048-bit MODP Group with 256-bit Prime Order Subgroup"),
        25 => Some("192-bit Random ECP Group"),
        26 => Some("224-bit Random ECP Group"),
        27 => Some("brainpoolP224r1"),
        28 => Some("brainpoolP256r1"),
        29 => Some("brainpoolP384r1"),
        30 => Some("brainpoolP512r1"),
        31 => Some("Curve25519"),
        32 => Some("Curve448"),
        33 => Some("GOST3410_2012_256"),
        34 => Some("GOST3410_2012_512"),
        35 => Some("ml-kem-512"),
        36 => Some("ml-kem-768"),
        37 => Some("ml-kem-1024"),
        _ => None,
    }
}

/// IANA "Transform Type 5 - Sequence Numbers Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-9>
pub(crate) fn sn_transform_name(v: u16) -> Option<&'static str> {
    match v {
        0 => Some("32-bit Sequential Numbers"),
        1 => Some("Partially Transmitted 64-bit Sequential Numbers"),
        2 => Some("32-bit Unspecified Numbers"),
        _ => None,
    }
}

/// IANA "Transform Type 13 - Key Wrap Algorithm Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#key-wrap-algorithm-transform-ids>
pub(crate) fn kwa_transform_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("KW_5649_128"),
        2 => Some("KW_5649_192"),
        3 => Some("KW_5649_256"),
        4 => Some("KW_ARX"),
        _ => None,
    }
}

/// IANA "Transform Type 14 - Group Controller Authentication Method Transform IDs".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#group-controller-authentication-method-transform-ids>
pub(crate) fn gcauth_transform_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Implicit"),
        2 => Some("Digital Signature"),
        _ => None,
    }
}

/// IANA "IKEv2 Transform Attribute Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-4>
pub(crate) fn transform_attribute_name(v: u16) -> Option<&'static str> {
    match v {
        14 => Some("Key Length (in bits)"),
        18 => Some("Signature Algorithm Identifier"),
        _ => None,
    }
}

/// IANA "IKEv2 Identification Payload ID Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-10>
pub(crate) fn id_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("ID_IPV4_ADDR"),
        2 => Some("ID_FQDN"),
        3 => Some("ID_RFC822_ADDR"),
        5 => Some("ID_IPV6_ADDR"),
        9 => Some("ID_DER_ASN1_DN"),
        10 => Some("ID_DER_ASN1_GN"),
        11 => Some("ID_KEY_ID"),
        12 => Some("ID_FC_NAME"),
        13 => Some("ID_NULL"),
        _ => None,
    }
}

/// IANA "IKEv2 Certificate Encodings".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-11>
pub(crate) fn cert_encoding_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("PKCS #7 wrapped X.509 certificate"),
        2 => Some("PGP Certificate"),
        3 => Some("DNS Signed Key"),
        4 => Some("X.509 Certificate - Signature"),
        6 => Some("Kerberos Token"),
        7 => Some("Certificate Revocation List (CRL)"),
        8 => Some("Authority Revocation List (ARL)"),
        9 => Some("SPKI Certificate"),
        10 => Some("X.509 Certificate - Attribute"),
        11 => Some("Raw RSA Key (DEPRECATED)"),
        12 => Some("Hash and URL of X.509 certificate"),
        13 => Some("Hash and URL of X.509 bundle"),
        14 => Some("OCSP Content"),
        15 => Some("Raw Public Key"),
        _ => None,
    }
}

/// IANA "IKEv2 Authentication Method".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-12>
pub(crate) fn auth_method_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("RSA Digital Signature"),
        2 => Some("Shared Key Message Integrity Code"),
        3 => Some("DSS Digital Signature"),
        9 => Some("ECDSA with SHA-256 on the P-256 curve"),
        10 => Some("ECDSA with SHA-384 on the P-384 curve"),
        11 => Some("ECDSA with SHA-512 on the P-521 curve"),
        12 => Some("Generic Secure Password Authentication Method"),
        13 => Some("NULL Authentication"),
        14 => Some("Digital Signature"),
        _ => None,
    }
}

/// IANA "IKEv2 Notify Message Error Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-14>
pub(crate) fn notify_error_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("UNSUPPORTED_CRITICAL_PAYLOAD"),
        4 => Some("INVALID_IKE_SPI"),
        5 => Some("INVALID_MAJOR_VERSION"),
        7 => Some("INVALID_SYNTAX"),
        9 => Some("INVALID_MESSAGE_ID"),
        11 => Some("INVALID_SPI"),
        14 => Some("NO_PROPOSAL_CHOSEN"),
        17 => Some("INVALID_KE_PAYLOAD"),
        24 => Some("AUTHENTICATION_FAILED"),
        34 => Some("SINGLE_PAIR_REQUIRED"),
        35 => Some("NO_ADDITIONAL_SAS"),
        36 => Some("INTERNAL_ADDRESS_FAILURE"),
        37 => Some("FAILED_CP_REQUIRED"),
        38 => Some("TS_UNACCEPTABLE"),
        39 => Some("INVALID_SELECTORS"),
        40 => Some("UNACCEPTABLE_ADDRESSES"),
        41 => Some("UNEXPECTED_NAT_DETECTED"),
        42 => Some("USE_ASSIGNED_HoA"),
        43 => Some("TEMPORARY_FAILURE"),
        44 => Some("CHILD_SA_NOT_FOUND"),
        45 => Some("INVALID_GROUP_ID"),
        46 => Some("AUTHORIZATION_FAILED"),
        47 => Some("STATE_NOT_FOUND"),
        48 => Some("TS_MAX_QUEUE"),
        49 => Some("REGISTRATION_FAILED"),
        _ => None,
    }
}

/// IANA "IKEv2 Notify Message Status Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-16>
pub(crate) fn notify_status_name(v: u16) -> Option<&'static str> {
    match v {
        16384 => Some("INITIAL_CONTACT"),
        16385 => Some("SET_WINDOW_SIZE"),
        16386 => Some("ADDITIONAL_TS_POSSIBLE"),
        16387 => Some("IPCOMP_SUPPORTED"),
        16388 => Some("NAT_DETECTION_SOURCE_IP"),
        16389 => Some("NAT_DETECTION_DESTINATION_IP"),
        16390 => Some("COOKIE"),
        16391 => Some("USE_TRANSPORT_MODE"),
        16392 => Some("HTTP_CERT_LOOKUP_SUPPORTED"),
        16393 => Some("REKEY_SA"),
        16394 => Some("ESP_TFC_PADDING_NOT_SUPPORTED"),
        16395 => Some("NON_FIRST_FRAGMENTS_ALSO"),
        16396 => Some("MOBIKE_SUPPORTED"),
        16397 => Some("ADDITIONAL_IP4_ADDRESS"),
        16398 => Some("ADDITIONAL_IP6_ADDRESS"),
        16399 => Some("NO_ADDITIONAL_ADDRESSES"),
        16400 => Some("UPDATE_SA_ADDRESSES"),
        16401 => Some("COOKIE2"),
        16402 => Some("NO_NATS_ALLOWED"),
        16403 => Some("AUTH_LIFETIME"),
        16404 => Some("MULTIPLE_AUTH_SUPPORTED"),
        16405 => Some("ANOTHER_AUTH_FOLLOWS"),
        16406 => Some("REDIRECT_SUPPORTED"),
        16407 => Some("REDIRECT"),
        16408 => Some("REDIRECTED_FROM"),
        16409 => Some("TICKET_LT_OPAQUE"),
        16410 => Some("TICKET_REQUEST"),
        16411 => Some("TICKET_ACK"),
        16412 => Some("TICKET_NACK"),
        16413 => Some("TICKET_OPAQUE"),
        16414 => Some("LINK_ID"),
        16415 => Some("USE_WESP_MODE"),
        16416 => Some("ROHC_SUPPORTED"),
        16417 => Some("EAP_ONLY_AUTHENTICATION"),
        16418 => Some("CHILDLESS_IKEV2_SUPPORTED"),
        16419 => Some("QUICK_CRASH_DETECTION"),
        16420 => Some("IKEV2_MESSAGE_ID_SYNC_SUPPORTED"),
        16421 => Some("IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED"),
        16422 => Some("IKEV2_MESSAGE_ID_SYNC"),
        16423 => Some("IPSEC_REPLAY_COUNTER_SYNC"),
        16424 => Some("SECURE_PASSWORD_METHODS"),
        16425 => Some("PSK_PERSIST"),
        16426 => Some("PSK_CONFIRM"),
        16427 => Some("ERX_SUPPORTED"),
        16428 => Some("IFOM_CAPABILITY"),
        16429 => Some("GROUP_SENDER"),
        16430 => Some("IKEV2_FRAGMENTATION_SUPPORTED"),
        16431 => Some("SIGNATURE_HASH_ALGORITHMS"),
        16432 => Some("CLONE_IKE_SA_SUPPORTED"),
        16433 => Some("CLONE_IKE_SA"),
        16434 => Some("PUZZLE"),
        16435 => Some("USE_PPK"),
        16436 => Some("PPK_IDENTITY"),
        16437 => Some("NO_PPK_AUTH"),
        16438 => Some("INTERMEDIATE_EXCHANGE_SUPPORTED"),
        16439 => Some("IP4_ALLOWED"),
        16440 => Some("IP6_ALLOWED"),
        16441 => Some("ADDITIONAL_KEY_EXCHANGE"),
        16442 => Some("USE_AGGFRAG"),
        16443 => Some("SUPPORTED_AUTH_METHODS"),
        16444 => Some("SA_RESOURCE_INFO"),
        16445 => Some("USE_PPK_INT"),
        16446 => Some("PPK_IDENTITY_KEY"),
        16447 => Some("IKE_SA_INIT_FULL_TRANSCRIPT_AUTH"),
        _ => None,
    }
}

/// IANA "IKEv2 Security Protocol Identifiers".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-18>
pub(crate) fn protocol_id_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IKE"),
        2 => Some("AH"),
        3 => Some("ESP"),
        4 => Some("FC_ESP_HEADER"),
        5 => Some("FC_CT_AUTHENTICATION"),
        6 => Some("GIKE_UPDATE"),
        _ => None,
    }
}

/// IANA "IKEv2 Traffic Selector Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-19>
pub(crate) fn ts_type_name(v: u8) -> Option<&'static str> {
    match v {
        7 => Some("TS_IPV4_ADDR_RANGE"),
        8 => Some("TS_IPV6_ADDR_RANGE"),
        9 => Some("TS_FC_ADDR_RANGE"),
        10 => Some("TS_SECLABEL"),
        _ => None,
    }
}

/// IANA "IKEv2 Configuration Payload CFG Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-20>
pub(crate) fn cfg_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("CFG_REQUEST"),
        2 => Some("CFG_REPLY"),
        3 => Some("CFG_SET"),
        4 => Some("CFG_ACK"),
        _ => None,
    }
}

/// IANA "IKEv2 Configuration Payload Attribute Types".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-21>
pub(crate) fn cfg_attribute_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("INTERNAL_IP4_ADDRESS"),
        2 => Some("INTERNAL_IP4_NETMASK"),
        3 => Some("INTERNAL_IP4_DNS"),
        4 => Some("INTERNAL_IP4_NBNS"),
        6 => Some("INTERNAL_IP4_DHCP"),
        7 => Some("APPLICATION_VERSION"),
        8 => Some("INTERNAL_IP6_ADDRESS"),
        10 => Some("INTERNAL_IP6_DNS"),
        12 => Some("INTERNAL_IP6_DHCP"),
        13 => Some("INTERNAL_IP4_SUBNET"),
        14 => Some("SUPPORTED_ATTRIBUTES"),
        15 => Some("INTERNAL_IP6_SUBNET"),
        16 => Some("MIP6_HOME_PREFIX"),
        17 => Some("INTERNAL_IP6_LINK"),
        18 => Some("INTERNAL_IP6_PREFIX"),
        19 => Some("HOME_AGENT_ADDRESS"),
        20 => Some("P_CSCF_IP4_ADDRESS"),
        21 => Some("P_CSCF_IP6_ADDRESS"),
        22 => Some("FTT_KAT"),
        23 => Some("EXTERNAL_SOURCE_IP4_NAT_INFO"),
        24 => Some("TIMEOUT_PERIOD_FOR_LIVENESS_CHECK"),
        25 => Some("INTERNAL_DNS_DOMAIN"),
        26 => Some("INTERNAL_DNSSEC_TA"),
        27 => Some("ENCDNS_IP4"),
        28 => Some("ENCDNS_IP6"),
        29 => Some("ENCDNS_DIGEST_INFO"),
        _ => None,
    }
}

/// IANA "IKEv2 Hash Algorithms".
/// <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#hash-algorithms>
pub(crate) fn hash_algorithm_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("SHA1"),
        2 => Some("SHA2-256"),
        3 => Some("SHA2-384"),
        4 => Some("SHA2-512"),
        5 => Some("Identity"),
        6 => Some("STREEBOG_256"),
        7 => Some("STREEBOG_512"),
        _ => None,
    }
}

/// IANA "ISAKMP Domain of Interpretation (DOI)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-19>
pub(crate) fn v1_doi_name(v: u32) -> Option<&'static str> {
    match v {
        0 => Some("ISAKMP"),
        1 => Some("IPSEC"),
        2 => Some("GDOI"),
        _ => None,
    }
}

/// IANA "Attribute Classes".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-2>
pub(crate) fn v1_ike_attribute_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Encryption Algorithm"),
        2 => Some("Hash Algorithm"),
        3 => Some("Authentication Method"),
        4 => Some("Group Description"),
        5 => Some("Group Type"),
        6 => Some("Group Prime/Irreducible Polynomial"),
        7 => Some("Group Generator One"),
        8 => Some("Group Generator Two"),
        9 => Some("Group Curve A"),
        10 => Some("Group Curve B"),
        11 => Some("Life Type"),
        12 => Some("Life Duration"),
        13 => Some("PRF"),
        14 => Some("Key Length"),
        15 => Some("Field Size"),
        16 => Some("Group Order"),
        _ => None,
    }
}

/// IANA "Encryption Algorithm Class Values (Value 1)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-4>
pub(crate) fn v1_ike_encryption_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("DES-CBC"),
        2 => Some("IDEA-CBC"),
        3 => Some("Blowfish-CBC"),
        4 => Some("RC5-R16-B64-CBC"),
        5 => Some("3DES-CBC"),
        6 => Some("CAST-CBC"),
        7 => Some("AES-CBC"),
        8 => Some("CAMELLIA-CBC"),
        _ => None,
    }
}

/// IANA "Hash Algorithm (Value 2)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6>
pub(crate) fn v1_ike_hash_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("MD5"),
        2 => Some("SHA"),
        3 => Some("Tiger"),
        4 => Some("SHA2-256"),
        5 => Some("SHA2-384"),
        6 => Some("SHA2-512"),
        _ => None,
    }
}

/// IANA "IPSEC Authentication Methods (Value 3)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-8>
pub(crate) fn v1_ike_auth_method_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("pre-shared key"),
        2 => Some("DSS signatures"),
        3 => Some("RSA signatures"),
        4 => Some("Encryption with RSA"),
        5 => Some("Revised encryption with RSA"),
        9 => Some("ECDSA with SHA-256 on the P-256 curve"),
        10 => Some("ECDSA with SHA-384 on the P-384 curve"),
        11 => Some("ECDSA with SHA-512 on the P-521 curve"),
        _ => None,
    }
}

/// IANA "Group Description (Value 4)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-10>
pub(crate) fn v1_group_description_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("default 768-bit MODP group"),
        2 => Some("alternate 1024-bit MODP group"),
        3 => Some("EC2N group on GP[2^155]"),
        4 => Some("EC2N group on GP[2^185]"),
        5 => Some("1536-bit MODP group"),
        6 => Some("EC2N group over GF[2^163](see Note)"),
        7 => Some("EC2N group over GF[2^163](see Note)"),
        8 => Some("EC2N group over GF[2^283](see Note)"),
        9 => Some("EC2N group over GF[2^283](see Note)"),
        10 => Some("EC2N group over GF[2^409](see Note)"),
        11 => Some("EC2N group over GF[2^409](see Note)"),
        12 => Some("EC2N group over GF[2^571](see Note)"),
        13 => Some("EC2N group over GF[2^571](see Note)"),
        14 => Some("2048-bit MODP group"),
        15 => Some("3072-bit MODP group"),
        16 => Some("4096-bit MODP group"),
        17 => Some("6144-bit MODP group"),
        18 => Some("8192-bit MODP group"),
        19 => Some("256-bit random ECP group"),
        20 => Some("384-bit random ECP group"),
        21 => Some("521-bit random ECP group"),
        22 => Some("1024-bit MODP Group with 160-bit Prime Order Subgroup"),
        23 => Some("2048-bit MODP Group with 224-bit Prime Order Subgroup"),
        24 => Some("2048-bit MODP Group with 256-bit Prime Order Subgroup"),
        25 => Some("192-bit Random ECP Group"),
        26 => Some("224-bit Random ECP Group"),
        27 => Some("224-bit Brainpool ECP group"),
        28 => Some("256-bit Brainpool ECP group"),
        29 => Some("384-bit Brainpool ECP group"),
        30 => Some("512-bit Brainpool ECP group"),
        _ => None,
    }
}

/// IANA "Group Type (Value 5)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-12>
pub(crate) fn v1_group_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("MODP (modular exponentiation group)"),
        2 => Some("ECP (elliptic curve group over GF[P])"),
        3 => Some("EC2N (elliptic curve group over GF[2^N])"),
        _ => None,
    }
}

/// IANA "Life Type (Value 11)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-14>
pub(crate) fn v1_ike_life_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("seconds"),
        2 => Some("kilobytes"),
        _ => None,
    }
}

/// IANA "ipsec-registry-24".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-24>
pub(crate) fn v1_notify_error_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("INVALID-PAYLOAD-TYPE"),
        2 => Some("DOI-NOT-SUPPORTED"),
        3 => Some("SITUATION-NOT-SUPPORTED"),
        4 => Some("INVALID-COOKIE"),
        5 => Some("INVALID-MAJOR-VERSION"),
        6 => Some("INVALID-MINOR-VERSION"),
        7 => Some("INVALID-EXCHANGE-TYPE"),
        8 => Some("INVALID-FLAGS"),
        9 => Some("INVALID-MESSAGE-ID"),
        10 => Some("INVALID-PROTOCOL-ID"),
        11 => Some("INVALID-SPI"),
        12 => Some("INVALID-TRANSFORM-ID"),
        13 => Some("ATTRIBUTES-NOT-SUPPORTED"),
        14 => Some("NO-PROPOSAL-CHOSEN"),
        15 => Some("BAD-PROPOSAL-SYNTAX"),
        16 => Some("PAYLOAD-MALFORMED"),
        17 => Some("INVALID-KEY-INFORMATION"),
        18 => Some("INVALID-ID-INFORMATION"),
        19 => Some("INVALID-CERT-ENCODING"),
        20 => Some("INVALID-CERTIFICATE"),
        21 => Some("CERT-TYPE-UNSUPPORTED"),
        22 => Some("INVALID-CERT-AUTHORITY"),
        23 => Some("INVALID-HASH-INFORMATION"),
        24 => Some("AUTHENTICATION-FAILED"),
        25 => Some("INVALID-SIGNATURE"),
        26 => Some("ADDRESS-NOTIFICATION"),
        27 => Some("NOTIFY-SA-LIFETIME"),
        28 => Some("CERTIFICATE-UNAVAILABLE"),
        29 => Some("UNSUPPORTED-EXCHANGE-TYPE"),
        30 => Some("UNEQUAL-PAYLOAD-LENGTHS"),
        _ => None,
    }
}

/// IANA "Notify Messages - Status Types (16384-24575)".
/// <https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-25>
pub(crate) fn v1_notify_status_name(v: u16) -> Option<&'static str> {
    match v {
        16384 => Some("CONNECTED"),
        _ => None,
    }
}

/// IANA "IPSEC Security Protocol Identifiers".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-3>
pub(crate) fn v1_protocol_id_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("PROTO_ISAKMP"),
        2 => Some("PROTO_IPSEC_AH"),
        3 => Some("PROTO_IPSEC_ESP"),
        4 => Some("PROTO_IPCOMP"),
        5 => Some("PROTO_GIGABEAM_RADIO"),
        _ => None,
    }
}

/// IANA "IPSEC ISAKMP Transform Identifiers".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-5>
pub(crate) fn v1_isakmp_transform_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("KEY_IKE"),
        _ => None,
    }
}

/// IANA "IPSEC AH Transform Identifiers".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-7>
pub(crate) fn v1_ah_transform_name(v: u8) -> Option<&'static str> {
    match v {
        2 => Some("AH_MD5"),
        3 => Some("AH_SHA"),
        4 => Some("AH_DES"),
        5 => Some("AH_SHA2-256"),
        6 => Some("AH_SHA2-384"),
        7 => Some("AH_SHA2-512"),
        8 => Some("AH_RIPEMD"),
        9 => Some("AH_AES-XCBC-MAC"),
        10 => Some("AH_RSA"),
        11 => Some("AH_AES-128-GMAC"),
        12 => Some("AH_AES-192-GMAC"),
        13 => Some("AH_AES-256-GMAC"),
        _ => None,
    }
}

/// IANA "IPSEC ESP Transform Identifiers".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-9>
pub(crate) fn v1_esp_transform_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("ESP_DES_IV64"),
        2 => Some("ESP_DES"),
        3 => Some("ESP_3DES"),
        4 => Some("ESP_RC5"),
        5 => Some("ESP_IDEA"),
        6 => Some("ESP_CAST"),
        7 => Some("ESP_BLOWFISH"),
        8 => Some("ESP_3IDEA"),
        9 => Some("ESP_DES_IV32"),
        10 => Some("ESP_RC4"),
        11 => Some("ESP_NULL"),
        12 => Some("ESP_AES-CBC"),
        13 => Some("ESP_AES-CTR"),
        14 => Some("ESP_AES-CCM_8"),
        15 => Some("ESP_AES-CCM_12"),
        16 => Some("ESP_AES-CCM_16"),
        18 => Some("ESP_AES-GCM_8"),
        19 => Some("ESP_AES-GCM_12"),
        20 => Some("ESP_AES-GCM_16"),
        21 => Some("ESP_SEED_CBC"),
        22 => Some("ESP_CAMELLIA"),
        23 => Some("ESP_NULL_AUTH_AES-GMAC"),
        _ => None,
    }
}

/// IANA "IPSEC IPCOMP Transform Identifiers".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-11>
pub(crate) fn v1_ipcomp_transform_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("IPCOMP_OUI"),
        2 => Some("IPCOMP_DEFLATE"),
        3 => Some("IPCOMP_LZS"),
        4 => Some("IPCOMP_LZJH"),
        _ => None,
    }
}

/// IANA "IPSEC Security Association Attributes".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-13>
pub(crate) fn v1_ipsec_attribute_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("SA Life Type"),
        2 => Some("SA Life Duration"),
        3 => Some("Group Description"),
        4 => Some("Encapsulation Mode"),
        5 => Some("Authentication Algorithm"),
        6 => Some("Key Length"),
        7 => Some("Key Rounds"),
        8 => Some("Compress Dictionary Size"),
        9 => Some("Compress Private Algorithm"),
        10 => Some("ECN Tunnel"),
        11 => Some("Extended (64-bit) Sequence Number"),
        12 => Some("Authentication Key Length"),
        13 => Some("Signature Encoding Algorithm"),
        14 => Some("Address Preservation"),
        15 => Some("SA Direction"),
        _ => None,
    }
}

/// IANA "SA Life Type Values (Value 1)".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-15>
pub(crate) fn v1_ipsec_life_type_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("seconds"),
        2 => Some("kilobytes"),
        _ => None,
    }
}

/// IANA "Encapsulation Mode (Value 4)".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-18>
pub(crate) fn v1_encapsulation_mode_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("Tunnel"),
        2 => Some("Transport"),
        3 => Some("UDP-Encapsulated-Tunnel"),
        4 => Some("UDP-Encapsulated-Transport"),
        _ => None,
    }
}

/// IANA "Authentication Algorithm (Value 5)".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-20>
pub(crate) fn v1_ipsec_auth_algorithm_name(v: u16) -> Option<&'static str> {
    match v {
        1 => Some("HMAC-MD5"),
        2 => Some("HMAC-SHA"),
        3 => Some("DES-MAC"),
        4 => Some("KPDK"),
        5 => Some("HMAC-SHA2-256"),
        6 => Some("HMAC-SHA2-384"),
        7 => Some("HMAC-SHA2-512"),
        8 => Some("HMAC-RIPEMD"),
        9 => Some("AES-XCBC-MAC"),
        10 => Some("SIG-RSA"),
        11 => Some("AES-128-GMAC"),
        12 => Some("AES-192-GMAC"),
        13 => Some("AES-256-GMAC"),
        _ => None,
    }
}

/// IANA "IPSEC Identification Type".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-31>
pub(crate) fn v1_ipsec_id_type_name(v: u8) -> Option<&'static str> {
    match v {
        1 => Some("ID_IPV4_ADDR"),
        2 => Some("ID_FQDN"),
        3 => Some("ID_USER_FQDN"),
        4 => Some("ID_IPV4_ADDR_SUBNET"),
        5 => Some("ID_IPV6_ADDR"),
        6 => Some("ID_IPV6_ADDR_SUBNET"),
        7 => Some("ID_IPV4_ADDR_RANGE"),
        8 => Some("ID_IPV6_ADDR_RANGE"),
        9 => Some("ID_DER_ASN1_DN"),
        10 => Some("ID_DER_ASN1_GN"),
        11 => Some("ID_KEY_ID"),
        12 => Some("ID_LIST"),
        _ => None,
    }
}

/// IANA "Notify Messages - Status Types (24576-32767)".
/// <https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-36>
pub(crate) fn v1_ipsec_notify_status_name(v: u16) -> Option<&'static str> {
    match v {
        24576 => Some("RESPONDER-LIFETIME"),
        24577 => Some("REPLAY-STATUS"),
        24578 => Some("INITIAL-CONTACT"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every table resolves at least one value and rejects an unassigned one.
    #[test]
    fn tables_resolve_registered_values() {
        type Table = fn(u32) -> Option<&'static str>;
        let tables: &[(&str, Table)] = &[
            ("transform_type_name", |v| {
                transform_type_name(u8::try_from(v).ok()?)
            }),
            ("encr_transform_name", |v| {
                encr_transform_name(u16::try_from(v).ok()?)
            }),
            ("prf_transform_name", |v| {
                prf_transform_name(u16::try_from(v).ok()?)
            }),
            ("integ_transform_name", |v| {
                integ_transform_name(u16::try_from(v).ok()?)
            }),
            ("ke_method_name", |v| ke_method_name(u16::try_from(v).ok()?)),
            ("sn_transform_name", |v| {
                sn_transform_name(u16::try_from(v).ok()?)
            }),
            ("kwa_transform_name", |v| {
                kwa_transform_name(u16::try_from(v).ok()?)
            }),
            ("gcauth_transform_name", |v| {
                gcauth_transform_name(u16::try_from(v).ok()?)
            }),
            ("transform_attribute_name", |v| {
                transform_attribute_name(u16::try_from(v).ok()?)
            }),
            ("id_type_name", |v| id_type_name(u8::try_from(v).ok()?)),
            ("cert_encoding_name", |v| {
                cert_encoding_name(u8::try_from(v).ok()?)
            }),
            ("auth_method_name", |v| {
                auth_method_name(u8::try_from(v).ok()?)
            }),
            ("notify_error_name", |v| {
                notify_error_name(u16::try_from(v).ok()?)
            }),
            ("notify_status_name", |v| {
                notify_status_name(u16::try_from(v).ok()?)
            }),
            ("protocol_id_name", |v| {
                protocol_id_name(u8::try_from(v).ok()?)
            }),
            ("ts_type_name", |v| ts_type_name(u8::try_from(v).ok()?)),
            ("cfg_type_name", |v| cfg_type_name(u8::try_from(v).ok()?)),
            ("cfg_attribute_name", |v| {
                cfg_attribute_name(u16::try_from(v).ok()?)
            }),
            ("hash_algorithm_name", |v| {
                hash_algorithm_name(u16::try_from(v).ok()?)
            }),
            ("v1_doi_name", |v| v1_doi_name(v)),
            ("v1_ike_attribute_name", |v| {
                v1_ike_attribute_name(u16::try_from(v).ok()?)
            }),
            ("v1_ike_encryption_name", |v| {
                v1_ike_encryption_name(u16::try_from(v).ok()?)
            }),
            ("v1_ike_hash_name", |v| {
                v1_ike_hash_name(u16::try_from(v).ok()?)
            }),
            ("v1_ike_auth_method_name", |v| {
                v1_ike_auth_method_name(u16::try_from(v).ok()?)
            }),
            ("v1_group_description_name", |v| {
                v1_group_description_name(u16::try_from(v).ok()?)
            }),
            ("v1_group_type_name", |v| {
                v1_group_type_name(u16::try_from(v).ok()?)
            }),
            ("v1_ike_life_type_name", |v| {
                v1_ike_life_type_name(u16::try_from(v).ok()?)
            }),
            ("v1_notify_error_name", |v| {
                v1_notify_error_name(u16::try_from(v).ok()?)
            }),
            ("v1_notify_status_name", |v| {
                v1_notify_status_name(u16::try_from(v).ok()?)
            }),
            ("v1_protocol_id_name", |v| {
                v1_protocol_id_name(u8::try_from(v).ok()?)
            }),
            ("v1_isakmp_transform_name", |v| {
                v1_isakmp_transform_name(u8::try_from(v).ok()?)
            }),
            ("v1_ah_transform_name", |v| {
                v1_ah_transform_name(u8::try_from(v).ok()?)
            }),
            ("v1_esp_transform_name", |v| {
                v1_esp_transform_name(u8::try_from(v).ok()?)
            }),
            ("v1_ipcomp_transform_name", |v| {
                v1_ipcomp_transform_name(u8::try_from(v).ok()?)
            }),
            ("v1_ipsec_attribute_name", |v| {
                v1_ipsec_attribute_name(u16::try_from(v).ok()?)
            }),
            ("v1_ipsec_life_type_name", |v| {
                v1_ipsec_life_type_name(u16::try_from(v).ok()?)
            }),
            ("v1_encapsulation_mode_name", |v| {
                v1_encapsulation_mode_name(u16::try_from(v).ok()?)
            }),
            ("v1_ipsec_auth_algorithm_name", |v| {
                v1_ipsec_auth_algorithm_name(u16::try_from(v).ok()?)
            }),
            ("v1_ipsec_id_type_name", |v| {
                v1_ipsec_id_type_name(u8::try_from(v).ok()?)
            }),
            ("v1_ipsec_notify_status_name", |v| {
                v1_ipsec_notify_status_name(u16::try_from(v).ok()?)
            }),
        ];
        for (name, f) in tables {
            let count = (0..=65_535u32).filter(|v| f(*v).is_some()).count();
            assert!(count > 0, "{name} has no entries");
            assert!(f(u32::MAX).is_none(), "{name}");
        }
    }
}
