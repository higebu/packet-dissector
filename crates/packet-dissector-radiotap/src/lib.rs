//! Radiotap header dissector (`LINKTYPE_IEEE802_11_RADIOTAP`, 127).
//!
//! A radiotap header carries per-frame radio information (TSF timer, data
//! rate, channel, signal strength, MCS, …) in front of an IEEE 802.11 frame.
//! It starts with an 8-octet fixed part — `it_version`, `it_pad`, `it_len`
//! and the first `it_present` bitmap word — followed by further bitmap words
//! (bit 31 of a word says another word follows) and the fields announced by
//! the set bits, each at its natural alignment relative to the start of the
//! header. All multi-octet values are little-endian. `it_len` covers the
//! whole header; the IEEE 802.11 frame follows it and is dispatched to the
//! `LINKTYPE_IEEE802_11` (105) entry with [`DispatchHint::ByLinkType`].
//!
//! Bit 29 of a bitmap word starts a new radiotap namespace (used by Linux
//! to report per-antenna fields) and bit 30 a vendor namespace, whose data
//! is skipped with its `skip_length`. Bit 28 announces a TLV list that runs
//! to the end of the header. Decoding stops at the first field that is not
//! defined or that does not fit in `it_len`; `it_len` still bounds the
//! header, so the 802.11 frame is dissected either way.
//!
//! ## References
//! - Radiotap header format: <https://www.radiotap.org/>
//! - Radiotap defined fields (bit numbers, structure, alignment):
//!   <https://www.radiotap.org/fields/defined>
//! - Reference parser with the field alignment/size table (radiotap-library):
//!   <https://github.com/radiotap/radiotap-library>
//! - Link-layer header types (`LINKTYPE_IEEE802_11_RADIOTAP` = 127,
//!   `LINKTYPE_IEEE802_11` = 105): <https://www.tcpdump.org/linktypes.html>

#![deny(missing_docs)]

use core::ops::Range;

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

/// Size of the fixed part of the header: `it_version` (1), `it_pad` (1),
/// `it_len` (2) and the first `it_present` word (4).
const HEADER_SIZE: usize = 8;

/// Offset of the first `it_present` bitmap word.
const PRESENT_OFFSET: usize = 4;

/// Size of one `it_present` bitmap word.
const PRESENT_WORD_SIZE: usize = 4;

/// The only defined radiotap version (`it_version` is always 0).
const RADIOTAP_VERSION: u8 = 0;

/// `LINKTYPE_IEEE802_11` — the IEEE 802.11 frame that follows the header.
/// <https://www.tcpdump.org/linktypes.html>
pub const LINKTYPE_IEEE802_11: u32 = 105;

/// Presence bit 28: a TLV list follows the bitmap-defined fields.
const BIT_TLV: u32 = 28;
/// Presence bit 29: the next bitmap word starts a new radiotap namespace.
const BIT_RADIOTAP_NAMESPACE: u32 = 29;
/// Presence bit 30: the next bitmap word starts a vendor namespace.
const BIT_VENDOR_NAMESPACE: u32 = 30;
/// Presence bit 31: another bitmap word follows.
const BIT_EXT: u32 = 31;

/// Flags field (bit 1) value: the frame includes the 4-octet FCS at its end.
pub const FLAG_FCS: u8 = 0x10;
/// Flags field (bit 1) value: the frame has padding between the 802.11
/// header and the payload, to a 32-bit boundary.
pub const FLAG_DATA_PAD: u8 = 0x20;

/// Alignment of the vendor namespace field (OUI, sub namespace, skip length).
const VENDOR_NAMESPACE_ALIGN: usize = 2;
/// Size of the vendor namespace field.
const VENDOR_NAMESPACE_SIZE: usize = 6;

/// Alignment of a TLV in the TLV list.
const TLV_ALIGN: usize = 4;
/// Size of a TLV's type and length.
const TLV_HEADER_SIZE: usize = 4;

/// How one sub-field of a radiotap field is read.
#[derive(Clone, Copy)]
enum Kind {
    U8,
    /// Signed octet (dBm values), widened to `I32`.
    I8,
    U16,
    U32,
    U64,
    Bytes,
}

/// One sub-field of a radiotap field: descriptor index into
/// [`NS_FIELDS`], how to read it, and its offset/length in the field.
#[derive(Clone, Copy)]
struct Sub {
    fd: usize,
    kind: Kind,
    at: usize,
    len: usize,
}

/// Structure of one radiotap field: its required alignment and size, and
/// the sub-fields it is decoded into.
struct Layout {
    align: usize,
    size: usize,
    subs: &'static [Sub],
}

const fn sub(fd: usize, kind: Kind, at: usize, len: usize) -> Sub {
    Sub { fd, kind, at, len }
}

// Descriptor indices into NS_FIELDS.
const NS_TSFT: usize = 0;
const NS_FLAGS: usize = 1;
const NS_RATE: usize = 2;
const NS_CHANNEL_FREQ: usize = 3;
const NS_CHANNEL_FLAGS: usize = 4;
const NS_FHSS_HOP_SET: usize = 5;
const NS_FHSS_HOP_PATTERN: usize = 6;
const NS_DBM_ANTSIGNAL: usize = 7;
const NS_DBM_ANTNOISE: usize = 8;
const NS_LOCK_QUALITY: usize = 9;
const NS_TX_ATTENUATION: usize = 10;
const NS_DB_TX_ATTENUATION: usize = 11;
const NS_DBM_TX_POWER: usize = 12;
const NS_ANTENNA: usize = 13;
const NS_DB_ANTSIGNAL: usize = 14;
const NS_DB_ANTNOISE: usize = 15;
const NS_RX_FLAGS: usize = 16;
const NS_TX_FLAGS: usize = 17;
const NS_RTS_RETRIES: usize = 18;
const NS_DATA_RETRIES: usize = 19;
const NS_MCS_KNOWN: usize = 20;
const NS_MCS_FLAGS: usize = 21;
const NS_MCS_INDEX: usize = 22;
const NS_AMPDU_REFERENCE: usize = 23;
const NS_AMPDU_FLAGS: usize = 24;
const NS_AMPDU_DELIMITER_CRC: usize = 25;
const NS_AMPDU_RESERVED: usize = 26;
const NS_VHT_KNOWN: usize = 27;
const NS_VHT_FLAGS: usize = 28;
const NS_VHT_BANDWIDTH: usize = 29;
const NS_VHT_MCS_NSS: usize = 30;
const NS_VHT_CODING: usize = 31;
const NS_VHT_GROUP_ID: usize = 32;
const NS_VHT_PARTIAL_AID: usize = 33;
const NS_TIMESTAMP: usize = 34;
const NS_TIMESTAMP_ACCURACY: usize = 35;
const NS_TIMESTAMP_UNIT_POSITION: usize = 36;
const NS_TIMESTAMP_FLAGS: usize = 37;
const NS_HE_DATA1: usize = 38;
const NS_HE_DATA2: usize = 39;
const NS_HE_DATA3: usize = 40;
const NS_HE_DATA4: usize = 41;
const NS_HE_DATA5: usize = 42;
const NS_HE_DATA6: usize = 43;
const NS_HE_MU_FLAGS1: usize = 44;
const NS_HE_MU_FLAGS2: usize = 45;
const NS_HE_MU_RU_CHANNEL1: usize = 46;
const NS_HE_MU_RU_CHANNEL2: usize = 47;
const NS_HE_MU_USER_PER_USER_1: usize = 48;
const NS_HE_MU_USER_PER_USER_2: usize = 49;
const NS_HE_MU_USER_POSITION: usize = 50;
const NS_HE_MU_USER_KNOWN: usize = 51;
const NS_ZERO_LENGTH_PSDU: usize = 52;
const NS_LSIG_DATA1: usize = 53;
const NS_LSIG_DATA2: usize = 54;
const NS_COUNT: usize = 55;

/// Descriptors of the fields a radiotap namespace can carry, in presence
/// bit order. Names and structures follow the radiotap defined-fields list
/// (<https://www.radiotap.org/fields/defined>).
const NS_FIELDS: [FieldDescriptor; NS_COUNT] = [
    FieldDescriptor::new("tsft", "TSFT", FieldType::U64).optional(),
    FieldDescriptor::new("flags", "Flags", FieldType::U8).optional(),
    FieldDescriptor::new("rate", "Rate (500 kb/s)", FieldType::U8).optional(),
    FieldDescriptor::new("channel_freq", "Channel Frequency (MHz)", FieldType::U16).optional(),
    FieldDescriptor::new("channel_flags", "Channel Flags", FieldType::U16).optional(),
    FieldDescriptor::new("fhss_hop_set", "FHSS Hop Set", FieldType::U8).optional(),
    FieldDescriptor::new("fhss_hop_pattern", "FHSS Hop Pattern", FieldType::U8).optional(),
    FieldDescriptor::new("dbm_antsignal", "Antenna Signal (dBm)", FieldType::I32).optional(),
    FieldDescriptor::new("dbm_antnoise", "Antenna Noise (dBm)", FieldType::I32).optional(),
    FieldDescriptor::new("lock_quality", "Lock Quality", FieldType::U16).optional(),
    FieldDescriptor::new("tx_attenuation", "TX Attenuation", FieldType::U16).optional(),
    FieldDescriptor::new("db_tx_attenuation", "dB TX Attenuation", FieldType::U16).optional(),
    FieldDescriptor::new("dbm_tx_power", "TX Power (dBm)", FieldType::I32).optional(),
    FieldDescriptor::new("antenna", "Antenna", FieldType::U8).optional(),
    FieldDescriptor::new("db_antsignal", "Antenna Signal (dB)", FieldType::U8).optional(),
    FieldDescriptor::new("db_antnoise", "Antenna Noise (dB)", FieldType::U8).optional(),
    FieldDescriptor::new("rx_flags", "RX Flags", FieldType::U16).optional(),
    FieldDescriptor::new("tx_flags", "TX Flags", FieldType::U16).optional(),
    FieldDescriptor::new("rts_retries", "RTS Retries", FieldType::U8).optional(),
    FieldDescriptor::new("data_retries", "Data Retries", FieldType::U8).optional(),
    FieldDescriptor::new("mcs_known", "MCS Known", FieldType::U8).optional(),
    FieldDescriptor::new("mcs_flags", "MCS Flags", FieldType::U8).optional(),
    FieldDescriptor::new("mcs_index", "MCS Index", FieldType::U8).optional(),
    FieldDescriptor::new("ampdu_reference", "A-MPDU Reference", FieldType::U32).optional(),
    FieldDescriptor::new("ampdu_flags", "A-MPDU Flags", FieldType::U16).optional(),
    FieldDescriptor::new("ampdu_delimiter_crc", "A-MPDU Delimiter CRC", FieldType::U8).optional(),
    FieldDescriptor::new("ampdu_reserved", "A-MPDU Reserved", FieldType::U8).optional(),
    FieldDescriptor::new("vht_known", "VHT Known", FieldType::U16).optional(),
    FieldDescriptor::new("vht_flags", "VHT Flags", FieldType::U8).optional(),
    FieldDescriptor::new("vht_bandwidth", "VHT Bandwidth", FieldType::U8).optional(),
    FieldDescriptor::new("vht_mcs_nss", "VHT MCS/NSS (users 0-3)", FieldType::Bytes).optional(),
    FieldDescriptor::new("vht_coding", "VHT Coding", FieldType::U8).optional(),
    FieldDescriptor::new("vht_group_id", "VHT Group ID", FieldType::U8).optional(),
    FieldDescriptor::new("vht_partial_aid", "VHT Partial AID", FieldType::U16).optional(),
    FieldDescriptor::new("timestamp", "Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("timestamp_accuracy", "Timestamp Accuracy", FieldType::U16).optional(),
    FieldDescriptor::new(
        "timestamp_unit_position",
        "Timestamp Unit/Position",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("timestamp_flags", "Timestamp Flags", FieldType::U8).optional(),
    FieldDescriptor::new("he_data1", "HE Data 1", FieldType::U16).optional(),
    FieldDescriptor::new("he_data2", "HE Data 2", FieldType::U16).optional(),
    FieldDescriptor::new("he_data3", "HE Data 3", FieldType::U16).optional(),
    FieldDescriptor::new("he_data4", "HE Data 4", FieldType::U16).optional(),
    FieldDescriptor::new("he_data5", "HE Data 5", FieldType::U16).optional(),
    FieldDescriptor::new("he_data6", "HE Data 6", FieldType::U16).optional(),
    FieldDescriptor::new("he_mu_flags1", "HE-MU Flags 1", FieldType::U16).optional(),
    FieldDescriptor::new("he_mu_flags2", "HE-MU Flags 2", FieldType::U16).optional(),
    FieldDescriptor::new("he_mu_ru_channel1", "HE-MU RU Channel 1", FieldType::Bytes).optional(),
    FieldDescriptor::new("he_mu_ru_channel2", "HE-MU RU Channel 2", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "he_mu_user_per_user_1",
        "HE-MU-other-user Per User 1",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "he_mu_user_per_user_2",
        "HE-MU-other-user Per User 2",
        FieldType::U16,
    )
    .optional(),
    FieldDescriptor::new(
        "he_mu_user_position",
        "HE-MU-other-user Per User Position",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new(
        "he_mu_user_known",
        "HE-MU-other-user Per User Known",
        FieldType::U8,
    )
    .optional(),
    FieldDescriptor::new("zero_length_psdu", "0-length-PSDU Type", FieldType::U8).optional(),
    FieldDescriptor::new("lsig_data1", "L-SIG Data 1", FieldType::U16).optional(),
    FieldDescriptor::new("lsig_data2", "L-SIG Data 2", FieldType::U16).optional(),
];

/// Structure of the fields for presence bits 0–27 of the radiotap
/// namespace (<https://www.radiotap.org/fields/defined>; alignment and size
/// as in radiotap-library's `rtap_namespace_sizes`). `None` marks bits with
/// no defined field (bit 18, XChannel, is only a suggested field), which stop
/// decoding because the size of their data is unknown.
static LAYOUTS: [Option<Layout>; 28] = [
    // 0: TSFT — u64 mactime (microseconds).
    Some(Layout {
        align: 8,
        size: 8,
        subs: &[sub(NS_TSFT, Kind::U64, 0, 8)],
    }),
    // 1: Flags — u8.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_FLAGS, Kind::U8, 0, 1)],
    }),
    // 2: Rate — u8, 500 kb/s units.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_RATE, Kind::U8, 0, 1)],
    }),
    // 3: Channel — u16 frequency (MHz), u16 flags.
    Some(Layout {
        align: 2,
        size: 4,
        subs: &[
            sub(NS_CHANNEL_FREQ, Kind::U16, 0, 2),
            sub(NS_CHANNEL_FLAGS, Kind::U16, 2, 2),
        ],
    }),
    // 4: FHSS — u8 hop set, u8 hop pattern.
    Some(Layout {
        align: 2,
        size: 2,
        subs: &[
            sub(NS_FHSS_HOP_SET, Kind::U8, 0, 1),
            sub(NS_FHSS_HOP_PATTERN, Kind::U8, 1, 1),
        ],
    }),
    // 5: Antenna signal — s8 dBm.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_DBM_ANTSIGNAL, Kind::I8, 0, 1)],
    }),
    // 6: Antenna noise — s8 dBm.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_DBM_ANTNOISE, Kind::I8, 0, 1)],
    }),
    // 7: Lock quality — u16.
    Some(Layout {
        align: 2,
        size: 2,
        subs: &[sub(NS_LOCK_QUALITY, Kind::U16, 0, 2)],
    }),
    // 8: TX attenuation — u16.
    Some(Layout {
        align: 2,
        size: 2,
        subs: &[sub(NS_TX_ATTENUATION, Kind::U16, 0, 2)],
    }),
    // 9: dB TX attenuation — u16.
    Some(Layout {
        align: 2,
        size: 2,
        subs: &[sub(NS_DB_TX_ATTENUATION, Kind::U16, 0, 2)],
    }),
    // 10: dBm TX power — s8.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_DBM_TX_POWER, Kind::I8, 0, 1)],
    }),
    // 11: Antenna — u8 index.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_ANTENNA, Kind::U8, 0, 1)],
    }),
    // 12: dB antenna signal — u8.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_DB_ANTSIGNAL, Kind::U8, 0, 1)],
    }),
    // 13: dB antenna noise — u8.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_DB_ANTNOISE, Kind::U8, 0, 1)],
    }),
    // 14: RX flags — u16.
    Some(Layout {
        align: 2,
        size: 2,
        subs: &[sub(NS_RX_FLAGS, Kind::U16, 0, 2)],
    }),
    // 15: TX flags — u16.
    Some(Layout {
        align: 2,
        size: 2,
        subs: &[sub(NS_TX_FLAGS, Kind::U16, 0, 2)],
    }),
    // 16: RTS retries — u8.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_RTS_RETRIES, Kind::U8, 0, 1)],
    }),
    // 17: Data retries — u8.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_DATA_RETRIES, Kind::U8, 0, 1)],
    }),
    // 18: XChannel — not a defined field.
    None,
    // 19: MCS — u8 known, u8 flags, u8 mcs.
    Some(Layout {
        align: 1,
        size: 3,
        subs: &[
            sub(NS_MCS_KNOWN, Kind::U8, 0, 1),
            sub(NS_MCS_FLAGS, Kind::U8, 1, 1),
            sub(NS_MCS_INDEX, Kind::U8, 2, 1),
        ],
    }),
    // 20: A-MPDU status — u32 reference, u16 flags, u8 delimiter CRC, u8 reserved.
    Some(Layout {
        align: 4,
        size: 8,
        subs: &[
            sub(NS_AMPDU_REFERENCE, Kind::U32, 0, 4),
            sub(NS_AMPDU_FLAGS, Kind::U16, 4, 2),
            sub(NS_AMPDU_DELIMITER_CRC, Kind::U8, 6, 1),
            sub(NS_AMPDU_RESERVED, Kind::U8, 7, 1),
        ],
    }),
    // 21: VHT — u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], u8 coding,
    // u8 group_id, u16 partial_aid.
    Some(Layout {
        align: 2,
        size: 12,
        subs: &[
            sub(NS_VHT_KNOWN, Kind::U16, 0, 2),
            sub(NS_VHT_FLAGS, Kind::U8, 2, 1),
            sub(NS_VHT_BANDWIDTH, Kind::U8, 3, 1),
            sub(NS_VHT_MCS_NSS, Kind::Bytes, 4, 4),
            sub(NS_VHT_CODING, Kind::U8, 8, 1),
            sub(NS_VHT_GROUP_ID, Kind::U8, 9, 1),
            sub(NS_VHT_PARTIAL_AID, Kind::U16, 10, 2),
        ],
    }),
    // 22: Timestamp — u64 timestamp, u16 accuracy, u8 unit/position, u8 flags.
    Some(Layout {
        align: 8,
        size: 12,
        subs: &[
            sub(NS_TIMESTAMP, Kind::U64, 0, 8),
            sub(NS_TIMESTAMP_ACCURACY, Kind::U16, 8, 2),
            sub(NS_TIMESTAMP_UNIT_POSITION, Kind::U8, 10, 1),
            sub(NS_TIMESTAMP_FLAGS, Kind::U8, 11, 1),
        ],
    }),
    // 23: HE — u16 data1 … data6.
    Some(Layout {
        align: 2,
        size: 12,
        subs: &[
            sub(NS_HE_DATA1, Kind::U16, 0, 2),
            sub(NS_HE_DATA2, Kind::U16, 2, 2),
            sub(NS_HE_DATA3, Kind::U16, 4, 2),
            sub(NS_HE_DATA4, Kind::U16, 6, 2),
            sub(NS_HE_DATA5, Kind::U16, 8, 2),
            sub(NS_HE_DATA6, Kind::U16, 10, 2),
        ],
    }),
    // 24: HE-MU — u16 flags1, u16 flags2, u8 RU_channel1[4], u8 RU_channel2[4].
    Some(Layout {
        align: 2,
        size: 12,
        subs: &[
            sub(NS_HE_MU_FLAGS1, Kind::U16, 0, 2),
            sub(NS_HE_MU_FLAGS2, Kind::U16, 2, 2),
            sub(NS_HE_MU_RU_CHANNEL1, Kind::Bytes, 4, 4),
            sub(NS_HE_MU_RU_CHANNEL2, Kind::Bytes, 8, 4),
        ],
    }),
    // 25: HE-MU-other-user — u16 per_user_1, u16 per_user_2,
    // u8 per_user_position, u8 per_user_known.
    Some(Layout {
        align: 2,
        size: 6,
        subs: &[
            sub(NS_HE_MU_USER_PER_USER_1, Kind::U16, 0, 2),
            sub(NS_HE_MU_USER_PER_USER_2, Kind::U16, 2, 2),
            sub(NS_HE_MU_USER_POSITION, Kind::U8, 4, 1),
            sub(NS_HE_MU_USER_KNOWN, Kind::U8, 5, 1),
        ],
    }),
    // 26: 0-length-PSDU — u8 type.
    Some(Layout {
        align: 1,
        size: 1,
        subs: &[sub(NS_ZERO_LENGTH_PSDU, Kind::U8, 0, 1)],
    }),
    // 27: L-SIG — u16 data1, u16 data2.
    Some(Layout {
        align: 2,
        size: 4,
        subs: &[
            sub(NS_LSIG_DATA1, Kind::U16, 0, 2),
            sub(NS_LSIG_DATA2, Kind::U16, 2, 2),
        ],
    }),
];

// Descriptor indices into the vendor namespace part of NAMESPACE_FIELDS.
const VN_OUI: usize = 0;
const VN_SUB_NAMESPACE: usize = 1;
const VN_SKIP_LENGTH: usize = 2;
const VN_DATA: usize = 3;
const VN_COUNT: usize = 4;

/// Descriptors of a vendor namespace (presence bit 30).
const VENDOR_FIELDS: [FieldDescriptor; VN_COUNT] = [
    FieldDescriptor::new("oui", "Vendor OUI", FieldType::U32).optional(),
    FieldDescriptor::new("sub_namespace", "Vendor Sub Namespace", FieldType::U8).optional(),
    FieldDescriptor::new("skip_length", "Vendor Skip Length", FieldType::U16).optional(),
    FieldDescriptor::new("data", "Vendor Data", FieldType::Bytes).optional(),
];

/// Children of one `namespaces` element: either the fields of a further
/// radiotap namespace or a vendor namespace.
static NAMESPACE_FIELDS: [FieldDescriptor; NS_COUNT + VN_COUNT] = {
    let mut out = [VENDOR_FIELDS[0]; NS_COUNT + VN_COUNT];
    let mut i = 0;
    while i < NS_COUNT {
        out[i] = NS_FIELDS[i];
        i += 1;
    }
    let mut j = 0;
    while j < VN_COUNT {
        out[NS_COUNT + j] = VENDOR_FIELDS[j];
        j += 1;
    }
    out
};

// Descriptor indices into TLV_FIELDS.
const TLV_TYPE: usize = 0;
const TLV_LENGTH: usize = 1;
const TLV_VALUE: usize = 2;

/// Children of one `tlvs` element.
static TLV_FIELDS: [FieldDescriptor; 3] = [
    FieldDescriptor::new("type", "Type", FieldType::U16),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("value", "Value", FieldType::Bytes),
];

/// Children of the `present` array.
static PRESENT_FIELDS: [FieldDescriptor; 1] =
    [FieldDescriptor::new("word", "Present Word", FieldType::U32)];

/// Namespace element descriptor (Object of [`NAMESPACE_FIELDS`]).
static NAMESPACE_ELEMENT: FieldDescriptor =
    FieldDescriptor::new("namespace", "Namespace", FieldType::Object)
        .with_children(&NAMESPACE_FIELDS);

/// TLV element descriptor (Object of [`TLV_FIELDS`]).
static TLV_ELEMENT: FieldDescriptor =
    FieldDescriptor::new("tlv", "TLV", FieldType::Object).with_children(&TLV_FIELDS);

// Descriptor indices into FIELD_DESCRIPTORS.
const FD_VERSION: usize = 0;
const FD_PAD: usize = 1;
const FD_LENGTH: usize = 2;
const FD_PRESENT: usize = 3;
/// Index of the first namespace field ([`NS_FIELDS`] are copied here).
const FD_NS_BASE: usize = 4;
const FD_TLVS: usize = FD_NS_BASE + NS_COUNT;
const FD_NAMESPACES: usize = FD_TLVS + 1;
const FD_COUNT: usize = FD_NAMESPACES + 1;

/// Layer field descriptors: the fixed header, the fields of the first
/// radiotap namespace, the TLV list and the further namespaces.
static FIELD_DESCRIPTORS: [FieldDescriptor; FD_COUNT] = {
    let mut out = [NS_FIELDS[0]; FD_COUNT];
    out[FD_VERSION] = FieldDescriptor::new("version", "Version", FieldType::U8);
    out[FD_PAD] = FieldDescriptor::new("pad", "Pad", FieldType::U8);
    out[FD_LENGTH] = FieldDescriptor::new("length", "Length", FieldType::U16);
    out[FD_PRESENT] = FieldDescriptor::new("present", "Present Flags", FieldType::Array)
        .with_children(&PRESENT_FIELDS);
    let mut i = 0;
    while i < NS_COUNT {
        out[FD_NS_BASE + i] = NS_FIELDS[i];
        i += 1;
    }
    out[FD_TLVS] = FieldDescriptor::new("tlvs", "TLVs", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&TLV_ELEMENT));
    out[FD_NAMESPACES] = FieldDescriptor::new("namespaces", "Further Namespaces", FieldType::Array)
        .optional()
        .with_children(core::slice::from_ref(&NAMESPACE_ELEMENT));
    out
};

static REFERENCES: &[SpecReference] = &[
    SpecReference::new("Radiotap", "Radiotap", "https://www.radiotap.org/"),
    SpecReference::new(
        "LINKTYPE_IEEE802_11_RADIOTAP",
        "Link-layer header types: LINKTYPE_IEEE802_11_RADIOTAP",
        "https://www.tcpdump.org/linktypes.html",
    ),
];

/// Round `pos` up to a multiple of `align` (a power of two), relative to the
/// start of the radiotap header.
fn align_up(pos: usize, align: usize) -> usize {
    (pos + align - 1) & !(align - 1)
}

/// Read a little-endian unsigned integer of `len` (≤ 8) octets.
fn read_le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// Where the fields of the namespace being decoded are pushed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    /// Flat in the layer (the first radiotap namespace).
    Layer,
    /// Into the current `namespaces` element.
    Element,
}

/// Namespace a bitmap word belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Radiotap,
    Vendor,
}

/// Decoding state for the fields that follow the presence bitmap.
struct Walker<'a, 'pkt> {
    /// The radiotap header (`data[..it_len]`).
    hdr: &'pkt [u8],
    buf: &'a mut DissectBuffer<'pkt>,
    offset: usize,
    /// Current position in `hdr`.
    pos: usize,
    /// Index of the open `namespaces` array field.
    array: Option<u32>,
    /// Index of the open `namespaces` element and its start position.
    element: Option<(u32, usize)>,
}

impl<'pkt> Walker<'_, 'pkt> {
    fn range(&self, start: usize, len: usize) -> Range<usize> {
        self.offset + start..self.offset + start + len
    }

    /// Descriptor for namespace field `fd` in the current target.
    fn ns_descriptor(target: Target, fd: usize) -> &'static FieldDescriptor {
        match target {
            Target::Layer => &FIELD_DESCRIPTORS[FD_NS_BASE + fd],
            Target::Element => &NAMESPACE_FIELDS[fd],
        }
    }

    /// Decode the field for presence bit `bit` of a radiotap namespace.
    /// Returns `false` when decoding has to stop.
    fn radiotap_field(&mut self, bit: u32, target: Target) -> bool {
        let Some(Some(layout)) = LAYOUTS.get(bit as usize) else {
            return false;
        };
        let start = align_up(self.pos, layout.align);
        let Some(bytes) = self.hdr.get(start..start + layout.size) else {
            return false;
        };
        for s in layout.subs {
            let raw = &bytes[s.at..s.at + s.len];
            let value = match s.kind {
                Kind::U8 => FieldValue::U8(raw[0]),
                Kind::I8 => FieldValue::I32(i32::from(raw[0] as i8)),
                Kind::U16 => FieldValue::U16(read_le(raw) as u16),
                Kind::U32 => FieldValue::U32(read_le(raw) as u32),
                Kind::U64 => FieldValue::U64(read_le(raw)),
                Kind::Bytes => FieldValue::Bytes(raw),
            };
            let range = self.range(start + s.at, s.len);
            self.buf
                .push_field(Self::ns_descriptor(target, s.fd), value, range);
        }
        self.pos = start + layout.size;
        true
    }

    /// Decode the TLV list that runs from the current position (after all
    /// bitmap-defined fields) to the end of the header (presence bit 28).
    fn tlvs(&mut self) {
        let start = align_up(self.pos, TLV_ALIGN).min(self.hdr.len());
        let array = self.buf.begin_container(
            &FIELD_DESCRIPTORS[FD_TLVS],
            FieldValue::Array(0..0),
            self.range(start, self.hdr.len() - start),
        );
        let mut pos = start;
        while let Some(head) = self.hdr.get(pos..pos + TLV_HEADER_SIZE) {
            let tlv_type = read_le(&head[0..2]) as u16;
            let len = read_le(&head[2..4]) as usize;
            let value_start = pos + TLV_HEADER_SIZE;
            let Some(value) = self.hdr.get(value_start..value_start + len) else {
                break;
            };
            let elem = self.buf.begin_container(
                &TLV_ELEMENT,
                FieldValue::Object(0..0),
                self.range(pos, TLV_HEADER_SIZE + len),
            );
            self.buf.push_field(
                &TLV_FIELDS[TLV_TYPE],
                FieldValue::U16(tlv_type),
                self.range(pos, 2),
            );
            self.buf.push_field(
                &TLV_FIELDS[TLV_LENGTH],
                FieldValue::U16(len as u16),
                self.range(pos + 2, 2),
            );
            self.buf.push_field(
                &TLV_FIELDS[TLV_VALUE],
                FieldValue::Bytes(value),
                self.range(value_start, len),
            );
            self.buf.end_container(elem);
            pos = align_up(value_start + len, TLV_ALIGN);
        }
        self.buf.end_container(array);
        self.pos = self.hdr.len();
    }

    /// Open a new `namespaces` element at the current position.
    fn open_element(&mut self) {
        self.close_element();
        if self.array.is_none() {
            let idx = self.buf.begin_container(
                &FIELD_DESCRIPTORS[FD_NAMESPACES],
                FieldValue::Array(0..0),
                self.range(self.pos, 0),
            );
            self.array = Some(idx);
        }
        let idx = self.buf.begin_container(
            &NAMESPACE_ELEMENT,
            FieldValue::Object(0..0),
            self.range(self.pos, 0),
        );
        self.element = Some((idx, self.pos));
    }

    /// Close the open `namespaces` element, setting its byte range to the
    /// octets its fields occupy.
    fn close_element(&mut self) {
        if let Some((idx, start)) = self.element.take() {
            self.buf.end_container(idx);
            let range = self.offset + start..self.offset + self.pos.max(start);
            if let Some(field) = self.buf.field_mut(idx as usize) {
                field.range = range;
            }
        }
    }

    /// Close the `namespaces` array (and its open element).
    fn finish(&mut self) {
        self.close_element();
        if let Some(idx) = self.array.take() {
            self.buf.end_container(idx);
            let end = self.offset + self.pos;
            if let Some(field) = self.buf.field_mut(idx as usize) {
                field.range = field.range.start..end.max(field.range.start);
            }
        }
    }

    /// Decode a vendor namespace field (presence bit 30) and skip its data.
    /// Returns `false` when decoding has to stop.
    fn vendor_namespace(&mut self) -> bool {
        let start = align_up(self.pos, VENDOR_NAMESPACE_ALIGN);
        let Some(head) = self.hdr.get(start..start + VENDOR_NAMESPACE_SIZE) else {
            return false;
        };
        self.pos = start;
        self.open_element();
        let oui = u32::from_be_bytes([0, head[0], head[1], head[2]]);
        let skip = read_le(&head[4..6]) as usize;
        self.buf.push_field(
            &NAMESPACE_FIELDS[NS_COUNT + VN_OUI],
            FieldValue::U32(oui),
            self.range(start, 3),
        );
        self.buf.push_field(
            &NAMESPACE_FIELDS[NS_COUNT + VN_SUB_NAMESPACE],
            FieldValue::U8(head[3]),
            self.range(start + 3, 1),
        );
        self.buf.push_field(
            &NAMESPACE_FIELDS[NS_COUNT + VN_SKIP_LENGTH],
            FieldValue::U16(skip as u16),
            self.range(start + 4, 2),
        );
        self.pos = start + VENDOR_NAMESPACE_SIZE;
        let data_start = self.pos;
        let Some(data) = self.hdr.get(data_start..data_start + skip) else {
            return false;
        };
        self.buf.push_field(
            &NAMESPACE_FIELDS[NS_COUNT + VN_DATA],
            FieldValue::Bytes(data),
            self.range(data_start, skip),
        );
        self.pos = data_start + skip;
        true
    }

    /// Walk the fields announced by the presence bitmap words `words`.
    ///
    /// Returns whether a TLV list follows: presence bit 28 was set in a
    /// radiotap namespace and every field before the list could be located.
    /// The TLVs start after all bitmap-defined fields of all namespaces.
    fn walk(&mut self, words: &[u8]) -> bool {
        let mut tlv = false;
        let mut namespace = Namespace::Radiotap;
        let mut target = Target::Layer;
        // Index of the current word within its namespace.
        let mut word_in_namespace = 0u32;
        for word in words.chunks_exact(PRESENT_WORD_SIZE) {
            let present = read_le(word) as u32;
            if namespace == Namespace::Radiotap {
                for bit in 0..BIT_RADIOTAP_NAMESPACE {
                    if present & (1 << bit) == 0 {
                        continue;
                    }
                    let field_bit = word_in_namespace * 32 + bit;
                    if field_bit == BIT_TLV {
                        tlv = true;
                        continue;
                    }
                    if field_bit > BIT_TLV || !self.radiotap_field(field_bit, target) {
                        return false;
                    }
                }
            }
            // Vendor namespace fields live inside the skipped vendor data.
            if present & (1 << BIT_RADIOTAP_NAMESPACE) != 0 {
                namespace = Namespace::Radiotap;
                target = Target::Element;
                word_in_namespace = 0;
                self.open_element();
            } else if present & (1 << BIT_VENDOR_NAMESPACE) != 0 {
                namespace = Namespace::Vendor;
                word_in_namespace = 0;
                if !self.vendor_namespace() {
                    return false;
                }
                self.close_element();
            } else {
                word_in_namespace += 1;
            }
        }
        tlv
    }
}

/// Radiotap header dissector.
pub struct RadiotapDissector;

impl Dissector for RadiotapDissector {
    fn name(&self) -> &'static str {
        "Radiotap"
    }

    fn short_name(&self) -> &'static str {
        "Radiotap"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        &FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }
        let version = data[0];
        if version != RADIOTAP_VERSION {
            return Err(PacketError::InvalidFieldValue {
                field: "version",
                value: u32::from(version),
            });
        }
        let it_len = usize::from(u16::from_le_bytes([data[2], data[3]]));
        if it_len < HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "radiotap it_len shorter than the fixed header",
            ));
        }
        let Some(hdr) = data.get(..it_len) else {
            return Err(PacketError::Truncated {
                expected: it_len,
                actual: data.len(),
            });
        };

        // Presence bitmap words: bit 31 of each says another word follows.
        let mut words_end = PRESENT_OFFSET;
        loop {
            let Some(word) = hdr.get(words_end..words_end + PRESENT_WORD_SIZE) else {
                return Err(PacketError::InvalidHeader(
                    "radiotap presence bitmap runs past it_len",
                ));
            };
            words_end += PRESENT_WORD_SIZE;
            if read_le(word) as u32 & (1 << BIT_EXT) == 0 {
                break;
            }
        }

        buf.begin_layer(
            self.short_name(),
            None,
            &FIELD_DESCRIPTORS,
            offset..offset + it_len,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PAD],
            FieldValue::U8(data[1]),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LENGTH],
            FieldValue::U16(it_len as u16),
            offset + 2..offset + 4,
        );
        let present = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_PRESENT],
            FieldValue::Array(0..0),
            offset + PRESENT_OFFSET..offset + words_end,
        );
        let words = &hdr[PRESENT_OFFSET..words_end];
        for (i, word) in words.chunks_exact(PRESENT_WORD_SIZE).enumerate() {
            let start = offset + PRESENT_OFFSET + i * PRESENT_WORD_SIZE;
            buf.push_field(
                &PRESENT_FIELDS[0],
                FieldValue::U32(read_le(word) as u32),
                start..start + PRESENT_WORD_SIZE,
            );
        }
        buf.end_container(present);

        let mut walker = Walker {
            hdr,
            buf,
            offset,
            pos: words_end,
            array: None,
            element: None,
        };
        let tlv = walker.walk(words);
        walker.finish();
        if tlv {
            walker.tlvs();
        }
        buf.end_layer();

        Ok(DissectResult::new(
            it_len,
            DispatchHint::ByLinkType(LINKTYPE_IEEE802_11),
        ))
    }
}

#[cfg(test)]
mod tests {
    //! # Radiotap Coverage
    //!
    //! | Spec (radiotap.org)             | Description                                   | Test                                 |
    //! |---------------------------------|-----------------------------------------------|--------------------------------------|
    //! | Header                          | it_version / it_pad / it_len / it_present     | parse_minimal_header                 |
    //! | Header                          | Two it_present words, 8-octet TSFT alignment  | tsft_aligned_after_two_present_words |
    //! | Fields 1,2,3,5,6,11             | Flags, Rate, Channel, dBm signal/noise, Ant.  | common_fields                        |
    //! | Fields 19,20,21                 | MCS, A-MPDU status, VHT                       | mcs_ampdu_vht_fields                 |
    //! | Fields 4,7-10,12-17             | FHSS, lock quality, TX power, RX/TX flags, …  | remaining_legacy_fields              |
    //! | Fields 22-27                    | Timestamp, HE, HE-MU, HE-MU-other-user, …     | timestamp_and_he_fields              |
    //! | Namespaces (bit 29)             | Further radiotap namespaces (per antenna)     | radiotap_namespaces                  |
    //! | Vendor namespace (bit 30)       | OUI / sub namespace / skip_length, data skip  | vendor_namespace_is_skipped          |
    //! | Vendor namespace (bit 30)       | Truncated header / data past it_len           | vendor_namespace_truncated           |
    //! | TLVs (bit 28)                   | TLV list with 4-octet padding                 | tlv_list                             |
    //! | TLVs (bit 28)                   | Value past it_len; bit 28 in a later word     | tlv_truncated_and_nested             |
    //! | Parsing rules                   | Undefined bit stops decoding, it_len consumed | undefined_bit_stops_decoding         |
    //! | Parsing rules                   | Bit ≥ 32 in the radiotap namespace stops      | extended_bit_stops_decoding          |
    //! | Parsing rules                   | Field past it_len stops decoding              | field_past_it_len_stops_decoding     |
    //! | Header                          | Truncated / version / it_len errors           | header_errors                        |
    //! | LINKTYPE 127                    | Dispatch to LINKTYPE_IEEE802_11 (105)         | parse_minimal_header                 |

    use super::*;

    const EXT: u32 = 1 << BIT_EXT;
    const RT_NS: u32 = 1 << BIT_RADIOTAP_NAMESPACE;
    const VENDOR_NS: u32 = 1 << BIT_VENDOR_NAMESPACE;

    /// Build a radiotap header from its presence words and field octets.
    fn build(present: &[u32], fields: &[u8]) -> Vec<u8> {
        let len = 4 + present.len() * 4 + fields.len();
        let mut data = vec![0, 0];
        data.extend_from_slice(&(len as u16).to_le_bytes());
        for word in present {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(fields);
        data
    }

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let result = RadiotapDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, result)
    }

    /// Top-level field `name` of the layer (container children skipped).
    fn value<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Option<&'a FieldValue<'a>> {
        top_level(buf.layer_fields(&buf.layers()[0]))
            .into_iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    /// Fields of `fields` that are not children of a container in it.
    fn top_level<'a>(fields: &'a [Field<'a>]) -> Vec<&'a Field<'a>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < fields.len() {
            out.push(&fields[i]);
            i += match fields[i].value.as_container_range() {
                Some(r) => (r.end - r.start) as usize + 1,
                None => 1,
            };
        }
        out
    }

    /// Children of the Array field `name`.
    fn children<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> Vec<&'a [Field<'a>]> {
        let Some(FieldValue::Array(range)) = value(buf, name) else {
            panic!("{name} is not an array");
        };
        top_level(buf.nested_fields(range))
            .into_iter()
            .map(|f| match &f.value {
                FieldValue::Object(r) => buf.nested_fields(r),
                _ => core::slice::from_ref(f),
            })
            .collect()
    }

    fn child<'a>(fields: &'a [Field<'a>], name: &str) -> Option<&'a FieldValue<'a>> {
        top_level(fields)
            .into_iter()
            .find(|f| f.name() == name)
            .map(|f| &f.value)
    }

    use packet_dissector_core::field::Field;

    #[test]
    fn parse_minimal_header() {
        let data = build(&[0], &[]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 8);
        assert_eq!(result.next, DispatchHint::ByLinkType(105));
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "Radiotap");
        assert_eq!(layer.range, 0..8);
        assert_eq!(value(&buf, "version"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "pad"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "length"), Some(&FieldValue::U16(8)));
        let words = children(&buf, "present");
        assert_eq!(words.len(), 1);
        assert_eq!(words[0][0].value, FieldValue::U32(0));
        assert!(value(&buf, "namespaces").is_none());
        assert!(value(&buf, "tlvs").is_none());
    }

    #[test]
    fn tsft_aligned_after_two_present_words() {
        // Word 0: TSFT + Flags, bit 31 → word 1 (empty). The fields start at
        // octet 12; TSFT needs 8-octet alignment, so 4 pad octets precede it.
        let mut fields = vec![0xEE; 4];
        fields.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        fields.push(FLAG_FCS);
        let data = build(&[EXT | 0b11, 0], &fields);
        let mut buf = DissectBuffer::new();
        let result = RadiotapDissector.dissect(&data, &mut buf, 100).unwrap();
        assert_eq!(result.bytes_consumed, 25);
        assert_eq!(buf.layers()[0].range, 100..125);
        let tsft = buf
            .layer_fields(&buf.layers()[0])
            .iter()
            .find(|f| f.name() == "tsft")
            .unwrap();
        assert_eq!(tsft.value, FieldValue::U64(0x0102_0304_0506_0708));
        assert_eq!(tsft.range, 116..124);
        assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(0x10)));
        let words = children(&buf, "present");
        assert_eq!(words.len(), 2);
        assert_eq!(words[1][0].range, 108..112);
    }

    #[test]
    fn common_fields() {
        // Flags, Rate, Channel (2-aligned), dBm signal, dBm noise, Antenna.
        let present = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 6 | 1 << 11;
        let fields = [
            0x00, // flags (offset 8)
            0x0C, // rate 6 Mb/s (offset 9)
            0x85, 0x09, 0xA0, 0x00, // channel 2437 MHz, 2 GHz + OFDM (offset 10)
            0xD6, // -42 dBm
            0xA1, // -95 dBm
            0x01, // antenna 1
        ];
        let data = build(&[present], &fields);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "rate"), Some(&FieldValue::U8(12)));
        assert_eq!(value(&buf, "channel_freq"), Some(&FieldValue::U16(2437)));
        assert_eq!(value(&buf, "channel_flags"), Some(&FieldValue::U16(0x00A0)));
        assert_eq!(value(&buf, "dbm_antsignal"), Some(&FieldValue::I32(-42)));
        assert_eq!(value(&buf, "dbm_antnoise"), Some(&FieldValue::I32(-95)));
        assert_eq!(value(&buf, "antenna"), Some(&FieldValue::U8(1)));
        assert!(value(&buf, "tsft").is_none());
    }

    #[test]
    fn mcs_ampdu_vht_fields() {
        let present = 1 << 19 | 1 << 20 | 1 << 21;
        let mut fields = vec![0x07, 0x04, 0x07, 0x00]; // MCS (8..11) + 1 pad
        fields.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // A-MPDU at 12
        fields.extend_from_slice(&[0x04, 0x00, 0xAB, 0x00]);
        fields.extend_from_slice(&[0x44, 0x00, 0x04, 0x04, 0x92, 0, 0, 0, 0x01, 0x00]);
        fields.extend_from_slice(&0x0123u16.to_le_bytes()); // VHT at 20..32
        let data = build(&[present], &fields);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "mcs_known"), Some(&FieldValue::U8(0x07)));
        assert_eq!(value(&buf, "mcs_flags"), Some(&FieldValue::U8(0x04)));
        assert_eq!(value(&buf, "mcs_index"), Some(&FieldValue::U8(7)));
        assert_eq!(
            value(&buf, "ampdu_reference"),
            Some(&FieldValue::U32(0x1234_5678))
        );
        assert_eq!(value(&buf, "ampdu_flags"), Some(&FieldValue::U16(0x0004)));
        assert_eq!(
            value(&buf, "ampdu_delimiter_crc"),
            Some(&FieldValue::U8(0xAB))
        );
        assert_eq!(value(&buf, "ampdu_reserved"), Some(&FieldValue::U8(0)));
        assert_eq!(value(&buf, "vht_known"), Some(&FieldValue::U16(0x0044)));
        assert_eq!(value(&buf, "vht_flags"), Some(&FieldValue::U8(0x04)));
        assert_eq!(value(&buf, "vht_bandwidth"), Some(&FieldValue::U8(4)));
        assert_eq!(
            value(&buf, "vht_mcs_nss"),
            Some(&FieldValue::Bytes(&[0x92, 0, 0, 0]))
        );
        assert_eq!(value(&buf, "vht_coding"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "vht_group_id"), Some(&FieldValue::U8(0)));
        assert_eq!(
            value(&buf, "vht_partial_aid"),
            Some(&FieldValue::U16(0x0123))
        );
    }

    #[test]
    fn remaining_legacy_fields() {
        let present = 1 << 4
            | 1 << 7
            | 1 << 8
            | 1 << 9
            | 1 << 10
            | 1 << 12
            | 1 << 13
            | 1 << 14
            | 1 << 15
            | 1 << 16
            | 1 << 17;
        let fields = [
            0x01, 0x02, // FHSS (8..10)
            0x32, 0x00, // lock quality 50
            0x03, 0x00, // TX attenuation 3
            0x04, 0x00, // dB TX attenuation 4
            0xFB, // dBm TX power -5 (16)
            0x1E, // dB signal 30
            0x05, // dB noise 5
            0x00, // pad (19)
            0x02, 0x00, // RX flags (20..22)
            0x08, 0x00, // TX flags (22..24)
            0x01, // RTS retries
            0x02, // data retries
        ];
        let data = build(&[present], &fields);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 26);
        assert_eq!(value(&buf, "fhss_hop_set"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "fhss_hop_pattern"), Some(&FieldValue::U8(2)));
        assert_eq!(value(&buf, "lock_quality"), Some(&FieldValue::U16(50)));
        assert_eq!(value(&buf, "tx_attenuation"), Some(&FieldValue::U16(3)));
        assert_eq!(value(&buf, "db_tx_attenuation"), Some(&FieldValue::U16(4)));
        assert_eq!(value(&buf, "dbm_tx_power"), Some(&FieldValue::I32(-5)));
        assert_eq!(value(&buf, "db_antsignal"), Some(&FieldValue::U8(30)));
        assert_eq!(value(&buf, "db_antnoise"), Some(&FieldValue::U8(5)));
        assert_eq!(value(&buf, "rx_flags"), Some(&FieldValue::U16(0x0002)));
        assert_eq!(value(&buf, "tx_flags"), Some(&FieldValue::U16(0x0008)));
        assert_eq!(value(&buf, "rts_retries"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "data_retries"), Some(&FieldValue::U8(2)));
    }

    #[test]
    fn timestamp_and_he_fields() {
        let present = 1 << 22 | 1 << 23 | 1 << 24 | 1 << 25 | 1 << 26 | 1 << 27;
        let mut fields = Vec::new();
        fields.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // 8..16
        fields.extend_from_slice(&[0x10, 0x00, 0x31, 0x02]); // accuracy, unit/pos, flags
        for i in 1..=6u16 {
            fields.extend_from_slice(&i.to_le_bytes()); // HE data1..6 (20..32)
        }
        fields.extend_from_slice(&[0x11, 0x00, 0x22, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]); // HE-MU
        fields.extend_from_slice(&[0x33, 0x00, 0x44, 0x00, 0x02, 0x3F]); // HE-MU-user (44..50)
        fields.push(0x01); // 0-length-PSDU (50)
        fields.push(0x00); // pad (51)
        fields.extend_from_slice(&[0x03, 0x00, 0x4B, 0x06]); // L-SIG (52..56)
        let data = build(&[present], &fields);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 56);
        assert_eq!(
            value(&buf, "timestamp"),
            Some(&FieldValue::U64(0x1122_3344_5566_7788))
        );
        assert_eq!(
            value(&buf, "timestamp_accuracy"),
            Some(&FieldValue::U16(0x10))
        );
        assert_eq!(
            value(&buf, "timestamp_unit_position"),
            Some(&FieldValue::U8(0x31))
        );
        assert_eq!(value(&buf, "timestamp_flags"), Some(&FieldValue::U8(0x02)));
        assert_eq!(value(&buf, "he_data1"), Some(&FieldValue::U16(1)));
        assert_eq!(value(&buf, "he_data6"), Some(&FieldValue::U16(6)));
        assert_eq!(value(&buf, "he_mu_flags1"), Some(&FieldValue::U16(0x11)));
        assert_eq!(value(&buf, "he_mu_flags2"), Some(&FieldValue::U16(0x22)));
        assert_eq!(
            value(&buf, "he_mu_ru_channel1"),
            Some(&FieldValue::Bytes(&[1, 2, 3, 4]))
        );
        assert_eq!(
            value(&buf, "he_mu_ru_channel2"),
            Some(&FieldValue::Bytes(&[5, 6, 7, 8]))
        );
        assert_eq!(
            value(&buf, "he_mu_user_per_user_1"),
            Some(&FieldValue::U16(0x33))
        );
        assert_eq!(
            value(&buf, "he_mu_user_per_user_2"),
            Some(&FieldValue::U16(0x44))
        );
        assert_eq!(value(&buf, "he_mu_user_position"), Some(&FieldValue::U8(2)));
        assert_eq!(value(&buf, "he_mu_user_known"), Some(&FieldValue::U8(0x3F)));
        assert_eq!(value(&buf, "zero_length_psdu"), Some(&FieldValue::U8(1)));
        assert_eq!(value(&buf, "lsig_data1"), Some(&FieldValue::U16(0x0003)));
        assert_eq!(value(&buf, "lsig_data2"), Some(&FieldValue::U16(0x064B)));
    }

    #[test]
    fn radiotap_namespaces() {
        // Linux mac80211 style: the first namespace carries Flags and the
        // combined signal, two further radiotap namespaces carry per-antenna
        // signal and antenna index.
        let words = [
            EXT | RT_NS | 1 << 1 | 1 << 5,
            EXT | RT_NS | 1 << 5 | 1 << 11,
            1 << 5 | 1 << 11,
        ];
        let fields = [
            FLAG_FCS, 0xD8, // flags, -40 dBm (16, 17)
            0xD7, 0x00, // -41 dBm, antenna 0 (18, 19)
            0xD9, 0x01, // -39 dBm, antenna 1 (20, 21)
        ];
        let data = build(&words, &fields);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 22);
        assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(FLAG_FCS)));
        assert_eq!(value(&buf, "dbm_antsignal"), Some(&FieldValue::I32(-40)));
        assert!(value(&buf, "antenna").is_none());
        let namespaces = children(&buf, "namespaces");
        assert_eq!(namespaces.len(), 2);
        assert_eq!(
            child(namespaces[0], "dbm_antsignal"),
            Some(&FieldValue::I32(-41))
        );
        assert_eq!(child(namespaces[0], "antenna"), Some(&FieldValue::U8(0)));
        assert_eq!(
            child(namespaces[1], "dbm_antsignal"),
            Some(&FieldValue::I32(-39))
        );
        assert_eq!(child(namespaces[1], "antenna"), Some(&FieldValue::U8(1)));
        let array = buf
            .layer_fields(&buf.layers()[0])
            .iter()
            .find(|f| f.name() == "namespaces")
            .unwrap();
        assert_eq!(array.range, 18..22);
    }

    #[test]
    fn vendor_namespace_is_skipped() {
        let words = [
            EXT | VENDOR_NS | 1 << 2,
            EXT | RT_NS | 0x5, // vendor-defined bits, then back to radiotap
            1 << 11,
        ];
        let fields = [
            0x0C, // rate (16)
            0x00, // pad to 2 (17)
            0x00, 0x11, 0x22, 0x01, 0x03, 0x00, // OUI, sub ns 1, skip 3 (18..24)
            0xAA, 0xBB, 0xCC, // vendor data (24..27)
            0x02, // antenna (27)
        ];
        let data = build(&words, &fields);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "rate"), Some(&FieldValue::U8(12)));
        let namespaces = children(&buf, "namespaces");
        assert_eq!(namespaces.len(), 2);
        assert_eq!(
            child(namespaces[0], "oui"),
            Some(&FieldValue::U32(0x0000_1122))
        );
        assert_eq!(
            child(namespaces[0], "sub_namespace"),
            Some(&FieldValue::U8(1))
        );
        assert_eq!(
            child(namespaces[0], "skip_length"),
            Some(&FieldValue::U16(3))
        );
        assert_eq!(
            child(namespaces[0], "data"),
            Some(&FieldValue::Bytes(&[0xAA, 0xBB, 0xCC]))
        );
        assert_eq!(child(namespaces[1], "antenna"), Some(&FieldValue::U8(2)));
    }

    #[test]
    fn vendor_namespace_truncated() {
        // Header needs 6 octets at offset 8 but only 3 are left.
        let data = build(&[VENDOR_NS], &[0x00, 0x11, 0x22]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 11);
        assert!(value(&buf, "namespaces").is_none());

        // Complete header, but skip_length runs past it_len.
        let data = build(&[VENDOR_NS], &[0x00, 0x11, 0x22, 0x00, 0x64, 0x00]);
        let (buf, _) = dissect(&data);
        let namespaces = children(&buf, "namespaces");
        assert_eq!(
            child(namespaces[0], "skip_length"),
            Some(&FieldValue::U16(100))
        );
        assert!(child(namespaces[0], "data").is_none());
    }

    #[test]
    fn tlv_list() {
        let present = 1 << 1 | 1 << BIT_TLV;
        let mut fields = vec![0x00, 0, 0, 0]; // flags (8) + pad to 12
        fields.extend_from_slice(&[0x05, 0x00, 0x03, 0x00, 1, 2, 3, 0]); // 12..20
        fields.extend_from_slice(&[0x21, 0x00, 0x04, 0x00, 9, 8, 7, 6]); // 20..28
        let data = build(&[present], &fields);
        let mut buf = DissectBuffer::new();
        RadiotapDissector.dissect(&data, &mut buf, 0).unwrap();
        let tlvs = children(&buf, "tlvs");
        assert_eq!(tlvs.len(), 2);
        assert_eq!(child(tlvs[0], "type"), Some(&FieldValue::U16(5)));
        assert_eq!(child(tlvs[0], "length"), Some(&FieldValue::U16(3)));
        assert_eq!(
            child(tlvs[0], "value"),
            Some(&FieldValue::Bytes(&[1, 2, 3]))
        );
        assert_eq!(child(tlvs[1], "type"), Some(&FieldValue::U16(0x21)));
        assert_eq!(
            child(tlvs[1], "value"),
            Some(&FieldValue::Bytes(&[9, 8, 7, 6]))
        );
        assert_eq!(tlvs[1][2].range, 24..28);
    }

    #[test]
    fn tlv_truncated_and_nested() {
        // TLV whose value runs past it_len is not decoded.
        let fields = [0x05, 0x00, 0x08, 0x00, 1, 2];
        let data = build(&[1 << BIT_TLV], &fields);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 14);
        assert!(children(&buf, "tlvs").is_empty());

        // Linux mac80211 sets bit 28 in the last word, here a further
        // namespace: the TLVs follow the fields of all namespaces.
        let mut fields = vec![0x10, 0xD8, 0x03, 0x00]; // flags, signal; antenna, pad
        fields.extend_from_slice(&[0x21, 0x00, 0x02, 0x00, 0xAB, 0xCD, 0x00, 0x00]);
        let data = build(
            &[EXT | RT_NS | 1 << 1 | 1 << 5, 1 << BIT_TLV | 1 << 11],
            &fields,
        );
        let (buf, _) = dissect(&data);
        let namespaces = children(&buf, "namespaces");
        assert_eq!(namespaces.len(), 1);
        assert_eq!(child(namespaces[0], "antenna"), Some(&FieldValue::U8(3)));
        let tlvs = children(&buf, "tlvs");
        assert_eq!(tlvs.len(), 1);
        assert_eq!(child(tlvs[0], "type"), Some(&FieldValue::U16(0x21)));
        assert_eq!(tlvs[0][2].range, 20..22);

        // Bit 28 in word 0 with further namespaces: their fields come first.
        let mut fields = vec![0x10, 0x03, 0x00, 0x00];
        fields.extend_from_slice(&[0x05, 0x00, 0x01, 0x00, 0x7F, 0x00, 0x00, 0x00]);
        let data = build(&[EXT | RT_NS | 1 << 1 | 1 << BIT_TLV, 1 << 11], &fields);
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(0x10)));
        let namespaces = children(&buf, "namespaces");
        assert_eq!(child(namespaces[0], "antenna"), Some(&FieldValue::U8(3)));
        let tlvs = children(&buf, "tlvs");
        assert_eq!(child(tlvs[0], "value"), Some(&FieldValue::Bytes(&[0x7F])));

        // An undefined field before the list: the TLVs cannot be located.
        let data = build(&[1 << 18 | 1 << BIT_TLV], &[0; 8]);
        let (buf, _) = dissect(&data);
        assert!(value(&buf, "tlvs").is_none());
    }

    #[test]
    fn undefined_bit_stops_decoding() {
        // Bit 18 (XChannel) has no defined size: MCS after it is not
        // decoded, but it_len still bounds the header.
        let data = build(&[1 << 1 | 1 << 18 | 1 << 19], &[0x00, 1, 2, 3, 4, 5, 6, 7]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 16);
        assert_eq!(result.next, DispatchHint::ByLinkType(LINKTYPE_IEEE802_11));
        assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(0)));
        assert!(value(&buf, "mcs_known").is_none());
    }

    #[test]
    fn extended_bit_stops_decoding() {
        // Word 1 of the radiotap namespace covers bits 32-63, none of which
        // has a field defined in the bitmap.
        let data = build(
            &[EXT | 1 << 1, EXT | RT_NS | 1 << 1, 1 << 11],
            &[0x02, 0x07],
        );
        let (buf, _) = dissect(&data);
        assert_eq!(value(&buf, "flags"), Some(&FieldValue::U8(2)));
        assert!(value(&buf, "namespaces").is_none());
    }

    #[test]
    fn field_past_it_len_stops_decoding() {
        // Rate fits, the 2-aligned 4-octet Channel does not.
        let data = build(&[1 << 2 | 1 << 3], &[0x0C, 0x00, 0x85]);
        let (buf, result) = dissect(&data);
        assert_eq!(result.bytes_consumed, 11);
        assert_eq!(value(&buf, "rate"), Some(&FieldValue::U8(12)));
        assert!(value(&buf, "channel_freq").is_none());
    }

    #[test]
    fn header_errors() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RadiotapDissector.dissect(&[0; 7], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 8,
                actual: 7
            })
        );

        let mut data = build(&[0], &[]);
        data[0] = 1;
        assert_eq!(
            RadiotapDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            })
        );

        let data = [0, 0, 6, 0, 0, 0, 0, 0];
        assert!(matches!(
            RadiotapDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));

        let data = [0, 0, 20, 0, 0, 0, 0, 0];
        assert_eq!(
            RadiotapDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 20,
                actual: 8
            })
        );

        // Bit 31 announces a word that it_len does not cover.
        let data = build(&[EXT], &[]);
        assert!(matches!(
            RadiotapDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn dissector_metadata() {
        let d = RadiotapDissector;
        assert_eq!(d.name(), "Radiotap");
        assert_eq!(d.short_name(), "Radiotap");
        assert_eq!(d.layer(), Some(ProtocolLayer::Link));
        assert!(!d.references().is_empty());
        let fds = d.field_descriptors();
        assert_eq!(fds.len(), FD_COUNT);
        assert_eq!(fds[FD_NS_BASE + NS_FLAGS].name, "flags");
        assert_eq!(fds[FD_NAMESPACES].name, "namespaces");
        let mut names: Vec<_> = fds.iter().map(|f| f.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FD_COUNT, "duplicate field names");
    }
}
