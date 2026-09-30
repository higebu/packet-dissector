//! RTCP (RTP Control Protocol) dissector.
//!
//! Decodes a compound RTCP datagram (RFC 3550, Section 6.1 —
//! <https://www.rfc-editor.org/rfc/rfc3550#section-6.1>) packet by packet,
//! including reduced-size (non-compound) RTCP (RFC 5506 —
//! <https://www.rfc-editor.org/rfc/rfc5506>).
//!
//! ## References
//! - RFC 3550, Sections 6.4-6.7 — SR, RR, SDES, BYE and APP packets:
//!   <https://www.rfc-editor.org/rfc/rfc3550#section-6.4>
//! - RFC 4585, Section 6 — RTCP feedback messages (RTPFB, PSFB):
//!   <https://www.rfc-editor.org/rfc/rfc4585#section-6>
//! - RFC 5104, Section 4 — Codec Control Messages (FIR, TMMBR, TMMBN):
//!   <https://www.rfc-editor.org/rfc/rfc5104#section-4>
//! - RFC 3611, Sections 2-4 — RTCP Extended Reports (XR):
//!   <https://www.rfc-editor.org/rfc/rfc3611#section-2>
//! - RFC 5506, Section 3 — Reduced-Size RTCP:
//!   <https://www.rfc-editor.org/rfc/rfc5506#section-3>
//! - RFC 5761, Section 4 — distinguishing RTP and RTCP on a single port:
//!   <https://www.rfc-editor.org/rfc/rfc5761#section-4>
//! - IANA RTP Parameters (packet types, SDES items, FMT values):
//!   <https://www.iana.org/assignments/rtp-parameters/>
//! - IANA RTCP XR Block Types:
//!   <https://www.iana.org/assignments/rtcp-xr-block-types/>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{
    Field, FieldDescriptor, FieldType, FieldValue, format_utf8_lossy,
};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_be_u64};

/// Size of the RTCP common header (V, P, count, PT, length).
///
/// RFC 3550, Section 6.4.1 — <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1>
const HEADER_SIZE: usize = 4;

/// RTP/RTCP version.
///
/// RFC 3550, Section 6.4.1 — "The version defined by this specification is
/// two (2)." <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1>
const RTCP_VERSION: u8 = 2;

/// Sender Report packet type. RFC 3550, Section 6.4.1 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1>
const PT_SR: u8 = 200;
/// Receiver Report packet type. RFC 3550, Section 6.4.2 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.2>
const PT_RR: u8 = 201;
/// Source Description packet type. RFC 3550, Section 6.5 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.5>
const PT_SDES: u8 = 202;
/// Goodbye packet type. RFC 3550, Section 6.6 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.6>
const PT_BYE: u8 = 203;
/// Application-defined packet type. RFC 3550, Section 6.7 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.7>
const PT_APP: u8 = 204;
/// Transport layer feedback packet type. RFC 4585, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc4585#section-6.1>
const PT_RTPFB: u8 = 205;
/// Payload-specific feedback packet type. RFC 4585, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc4585#section-6.1>
const PT_PSFB: u8 = 206;
/// Extended Report packet type. RFC 3611, Section 2 —
/// <https://www.rfc-editor.org/rfc/rfc3611#section-2>
const PT_XR: u8 = 207;

/// Size of the SR sender information section.
///
/// RFC 3550, Section 6.4.1 — "The second section, the sender information, is
/// 20 octets long". <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1>
const SENDER_INFO_SIZE: usize = 20;

/// Size of one SR/RR reception report block (six 32-bit words).
///
/// RFC 3550, Section 6.4.1 — <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1>
const REPORT_BLOCK_SIZE: usize = 24;

/// SDES PRIV item type. RFC 3550, Section 6.5.8 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.5.8>
const SDES_PRIV: u8 = 8;

/// RTPFB FMT values (RFC 4585, Section 6.2 —
/// <https://www.rfc-editor.org/rfc/rfc4585#section-6.2>; RFC 5104,
/// Section 4.2 — <https://www.rfc-editor.org/rfc/rfc5104#section-4.2>).
const FMT_GENERIC_NACK: u8 = 1;
const FMT_TMMBR: u8 = 3;
const FMT_TMMBN: u8 = 4;

/// PSFB FMT values (RFC 4585, Section 6.3 —
/// <https://www.rfc-editor.org/rfc/rfc4585#section-6.3>; RFC 5104,
/// Section 4.3 — <https://www.rfc-editor.org/rfc/rfc5104#section-4.3>).
const FMT_PLI: u8 = 1;
const FMT_SLI: u8 = 2;
const FMT_RPSI: u8 = 3;
const FMT_FIR: u8 = 4;

/// XR block types (RFC 3611, Section 4 —
/// <https://www.rfc-editor.org/rfc/rfc3611#section-4>).
const XR_BT_LOSS_RLE: u8 = 1;
const XR_BT_DUPLICATE_RLE: u8 = 2;
const XR_BT_RRT: u8 = 4;
const XR_BT_DLRR: u8 = 5;

/// Size of a DLRR sub-block (SSRC, LRR, DLRR).
///
/// RFC 3611, Section 4.5 — "The report consists of one or more 3 word sub-
/// blocks: one sub-block per Receiver Report."
/// <https://www.rfc-editor.org/rfc/rfc3611#section-4.5>
const DLRR_SUB_BLOCK_SIZE: usize = 12;

/// Returns the IANA abbreviation of an RTCP packet type.
///
/// IANA "RTCP Control Packet Types (PT)" —
/// <https://www.iana.org/assignments/rtp-parameters/>
pub fn packet_type_name(pt: u8) -> Option<&'static str> {
    match pt {
        194 => Some("SMPTETC"),
        195 => Some("IJ"),
        PT_SR => Some("SR"),
        PT_RR => Some("RR"),
        PT_SDES => Some("SDES"),
        PT_BYE => Some("BYE"),
        PT_APP => Some("APP"),
        PT_RTPFB => Some("RTPFB"),
        PT_PSFB => Some("PSFB"),
        PT_XR => Some("XR"),
        208 => Some("AVB"),
        209 => Some("RSI"),
        210 => Some("TOKEN"),
        211 => Some("IDMS"),
        212 => Some("RGRS"),
        213 => Some("SNM"),
        _ => None,
    }
}

/// Returns the IANA abbreviation of an SDES item type.
///
/// IANA "RTP SDES Item Types" — <https://www.iana.org/assignments/rtp-parameters/>
pub fn sdes_item_name(item_type: u8) -> Option<&'static str> {
    match item_type {
        0 => Some("END"),
        1 => Some("CNAME"),
        2 => Some("NAME"),
        3 => Some("EMAIL"),
        4 => Some("PHONE"),
        5 => Some("LOC"),
        6 => Some("TOOL"),
        7 => Some("NOTE"),
        SDES_PRIV => Some("PRIV"),
        9 => Some("H323-CADDR"),
        10 => Some("APSI"),
        11 => Some("RGRP"),
        12 => Some("RtpStreamId"),
        13 => Some("RepairedRtpStreamId"),
        14 => Some("CCID"),
        15 => Some("MID"),
        _ => None,
    }
}

/// Returns the name of an RTPFB (PT 205) feedback message type.
///
/// IANA "FMT Values for RTPFB Payload Types" —
/// <https://www.iana.org/assignments/rtp-parameters/>
pub fn rtpfb_fmt_name(fmt: u8) -> Option<&'static str> {
    match fmt {
        FMT_GENERIC_NACK => Some("Generic NACK"),
        FMT_TMMBR => Some("TMMBR"),
        FMT_TMMBN => Some("TMMBN"),
        5 => Some("RTCP-SR-REQ"),
        6 => Some("RAMS"),
        7 => Some("TLLEI"),
        8 => Some("RTCP-ECN-FB"),
        9 => Some("PAUSE-RESUME"),
        10 => Some("DBI"),
        11 => Some("CCFB"),
        31 => Some("Extension"),
        _ => None,
    }
}

/// Returns the name of a PSFB (PT 206) feedback message type.
///
/// IANA "FMT Values for PSFB Payload Types" —
/// <https://www.iana.org/assignments/rtp-parameters/>
pub fn psfb_fmt_name(fmt: u8) -> Option<&'static str> {
    match fmt {
        FMT_PLI => Some("PLI"),
        FMT_SLI => Some("SLI"),
        FMT_RPSI => Some("RPSI"),
        FMT_FIR => Some("FIR"),
        5 => Some("TSTR"),
        6 => Some("TSTN"),
        7 => Some("VBCM"),
        8 => Some("PSLEI"),
        9 => Some("ROI"),
        10 => Some("LRR"),
        11 => Some("VP"),
        15 => Some("AFB"),
        31 => Some("Extension"),
        _ => None,
    }
}

/// Returns the name of an RTCP XR block type.
///
/// IANA "RTCP XR Block Type" —
/// <https://www.iana.org/assignments/rtcp-xr-block-types/>
pub fn xr_block_type_name(bt: u8) -> Option<&'static str> {
    match bt {
        XR_BT_LOSS_RLE => Some("Loss RLE Report Block"),
        XR_BT_DUPLICATE_RLE => Some("Duplicate RLE Report Block"),
        3 => Some("Packet Receipt Times Report Block"),
        XR_BT_RRT => Some("Receiver Reference Time Report Block"),
        XR_BT_DLRR => Some("DLRR Report Block"),
        6 => Some("Statistics Summary Report Block"),
        7 => Some("VoIP Metrics Report Block"),
        8 => Some("RTCP XR"),
        9 => Some("Texas Instruments Extended VoIP Quality Block"),
        10 => Some("Post-repair Loss RLE Report Block"),
        11 => Some("Multicast Acquisition Report Block"),
        12 => Some("IDMS Report Block"),
        13 => Some("ECN Summary Report"),
        14 => Some("Measurement Information Block"),
        15 => Some("Packet Delay Variation Metrics Block"),
        16 => Some("Delay Metrics Block"),
        17 => Some("Burst/Gap Loss Summary Statistics Block"),
        18 => Some("Burst/Gap Discard Summary Statistics Block"),
        19 => Some("Frame Impairment Statistics Summary"),
        20 => Some("Burst/Gap Loss Metrics Block"),
        21 => Some("Burst/Gap Discard Metrics Block"),
        22 => Some("MPEG2 Transport Stream PSI-Independent Decodability Statistics Metrics Block"),
        23 => Some("De-Jitter Buffer Metrics Block"),
        24 => Some("Discard Count Metrics Block"),
        25 => Some("DRLE (Discard RLE Report)"),
        26 => Some("BDR (Bytes Discarded Report)"),
        27 => Some("RFISD (RTP Flows Initial Synchronization Delay)"),
        28 => Some("RFSO (RTP Flows Synchronization Offset Metrics Block)"),
        29 => Some("MOS Metrics Block"),
        30 => Some("LCB (Loss Concealment Metrics Block)"),
        31 => Some("CSB (Concealed Seconds Metrics Block)"),
        32 => Some("MPEG2 Transport Stream PSI Decodability Statistics Metrics Block"),
        33 => Some("Post-Repair Loss Count Metrics Report Block"),
        34 => Some("Video Loss Concealment Metric Report Block"),
        35 => Some("Independent Burst/Gap Discard Metrics Block"),
        36 => Some("Timing Information for QoE Metrics Calculation Block"),
        _ => None,
    }
}

/// Display function for `fmt`, which is interpreted relative to the sibling
/// `packet_type` (RFC 4585, Section 6.1 — "This field identifies the type of
/// the FB message and is interpreted relative to the type (transport layer,
/// payload-specific, or application layer feedback)."
/// <https://www.rfc-editor.org/rfc/rfc4585#section-6.1>).
fn fmt_display(v: &FieldValue<'_>, siblings: &[Field<'_>]) -> Option<&'static str> {
    let FieldValue::U8(fmt) = v else {
        return None;
    };
    let pt = siblings
        .iter()
        .find(|f| f.name() == "packet_type")
        .and_then(|f| f.value.as_u8())?;
    match pt {
        PT_RTPFB => rtpfb_fmt_name(*fmt),
        PT_PSFB => psfb_fmt_name(*fmt),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Field descriptors
// ---------------------------------------------------------------------------

/// Children of one SR/RR reception report block.
static REPORT_BLOCK_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32),
    FieldDescriptor::new("fraction_lost", "Fraction Lost", FieldType::U8),
    FieldDescriptor::new(
        "cumulative_lost",
        "Cumulative Number of Packets Lost",
        FieldType::I32,
    ),
    FieldDescriptor::new(
        "extended_highest_sequence",
        "Extended Highest Sequence Number Received",
        FieldType::U32,
    ),
    FieldDescriptor::new("jitter", "Interarrival Jitter", FieldType::U32),
    FieldDescriptor::new("lsr", "Last SR Timestamp", FieldType::U32),
    FieldDescriptor::new("dlsr", "Delay Since Last SR", FieldType::U32),
];
const RB_SSRC: usize = 0;
const RB_FRACTION_LOST: usize = 1;
const RB_CUMULATIVE_LOST: usize = 2;
const RB_EXT_HIGHEST_SEQ: usize = 3;
const RB_JITTER: usize = 4;
const RB_LSR: usize = 5;
const RB_DLSR: usize = 6;
static FD_REPORT_BLOCK: FieldDescriptor =
    FieldDescriptor::new("report_block", "Report Block", FieldType::Object);

/// Children of one SDES item.
static SDES_ITEM_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8).with_display_fn(|v, _| match v {
        FieldValue::U8(t) => sdes_item_name(*t),
        _ => None,
    }),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("prefix_length", "Prefix Length", FieldType::U8).optional(),
    FieldDescriptor::new("prefix", "Prefix", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("text", "Text", FieldType::Bytes).with_format_fn(format_utf8_lossy),
];
const IT_TYPE: usize = 0;
const IT_LENGTH: usize = 1;
const IT_PREFIX_LENGTH: usize = 2;
const IT_PREFIX: usize = 3;
const IT_TEXT: usize = 4;
static FD_SDES_ITEM: FieldDescriptor = FieldDescriptor::new("item", "SDES Item", FieldType::Object);

/// Children of one SDES chunk.
static SDES_CHUNK_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ssrc", "SSRC/CSRC", FieldType::U32),
    FieldDescriptor::new("items", "Items", FieldType::Array)
        .optional()
        .with_children(SDES_ITEM_FIELDS),
];
const CH_SSRC: usize = 0;
const CH_ITEMS: usize = 1;
static FD_SDES_CHUNK: FieldDescriptor =
    FieldDescriptor::new("chunk", "SDES Chunk", FieldType::Object);

/// Children of one Generic NACK FCI entry.
static NACK_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("pid", "Packet ID", FieldType::U16),
    FieldDescriptor::new("blp", "Bitmask of Following Lost Packets", FieldType::U16),
];
static FD_NACK_ENTRY: FieldDescriptor =
    FieldDescriptor::new("nack_entry", "Generic NACK", FieldType::Object);

/// Children of one TMMBR / TMMBN FCI entry.
static TMMB_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32),
    FieldDescriptor::new("mxtbr_exp", "MxTBR Exp", FieldType::U8),
    FieldDescriptor::new("mxtbr_mantissa", "MxTBR Mantissa", FieldType::U32),
    FieldDescriptor::new("measured_overhead", "Measured Overhead", FieldType::U16),
];
static FD_TMMB_ENTRY: FieldDescriptor =
    FieldDescriptor::new("tmmb_entry", "TMMBR/TMMBN Entry", FieldType::Object);

/// Children of one FIR FCI entry.
static FIR_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32),
    FieldDescriptor::new("seq_nr", "Sequence Number", FieldType::U8),
];
static FD_FIR_ENTRY: FieldDescriptor =
    FieldDescriptor::new("fir_entry", "FIR Entry", FieldType::Object);

/// Children of one SLI FCI entry.
static SLI_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("first", "First", FieldType::U16),
    FieldDescriptor::new("number", "Number", FieldType::U16),
    FieldDescriptor::new("picture_id", "PictureID", FieldType::U8),
];
static FD_SLI_ENTRY: FieldDescriptor =
    FieldDescriptor::new("sli_entry", "SLI Entry", FieldType::Object);

/// Children of the RPSI FCI.
static RPSI_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("pb", "Padding Bits", FieldType::U8),
    FieldDescriptor::new("payload_type", "Payload Type", FieldType::U8),
    FieldDescriptor::new("bit_string", "Native RPSI Bit String", FieldType::Bytes),
];

/// Children of one Loss / Duplicate RLE chunk.
static RLE_CHUNK_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("run_type", "Run Type", FieldType::U8).optional(),
    FieldDescriptor::new("run_length", "Run Length", FieldType::U16).optional(),
    FieldDescriptor::new("bit_vector", "Bit Vector", FieldType::U16).optional(),
];
static FD_RLE_CHUNK: FieldDescriptor =
    FieldDescriptor::new("rle_chunk", "RLE Chunk", FieldType::Object);

/// Children of one DLRR sub-block.
static DLRR_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32),
    FieldDescriptor::new("lrr", "Last RR Timestamp", FieldType::U32),
    FieldDescriptor::new("dlrr", "Delay Since Last RR", FieldType::U32),
];
static FD_DLRR_SUB_BLOCK: FieldDescriptor =
    FieldDescriptor::new("dlrr_sub_block", "DLRR Sub-block", FieldType::Object);

/// Children of one XR report block (union of all decoded block layouts).
static XR_BLOCK_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("block_type", "Block Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(bt) => xr_block_type_name(*bt),
            _ => None,
        },
    ),
    FieldDescriptor::new("type_specific", "Type-specific", FieldType::U8),
    FieldDescriptor::new("thinning", "Thinning", FieldType::U8).optional(),
    FieldDescriptor::new("block_length", "Block Length", FieldType::U16),
    FieldDescriptor::new("ssrc", "SSRC of Source", FieldType::U32).optional(),
    FieldDescriptor::new("begin_seq", "Begin Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("end_seq", "End Sequence Number", FieldType::U16).optional(),
    FieldDescriptor::new("rle_chunks", "Chunks", FieldType::Array)
        .optional()
        .with_children(RLE_CHUNK_FIELDS),
    FieldDescriptor::new("ntp_timestamp", "NTP Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("dlrr", "DLRR Sub-blocks", FieldType::Array)
        .optional()
        .with_children(DLRR_FIELDS),
    FieldDescriptor::new("contents", "Block Contents", FieldType::Bytes).optional(),
];
const XB_BLOCK_TYPE: usize = 0;
const XB_TYPE_SPECIFIC: usize = 1;
const XB_THINNING: usize = 2;
const XB_BLOCK_LENGTH: usize = 3;
const XB_SSRC: usize = 4;
const XB_BEGIN_SEQ: usize = 5;
const XB_END_SEQ: usize = 6;
const XB_RLE_CHUNKS: usize = 7;
const XB_NTP_TIMESTAMP: usize = 8;
const XB_DLRR: usize = 9;
const XB_CONTENTS: usize = 10;
static FD_XR_BLOCK: FieldDescriptor =
    FieldDescriptor::new("xr_block", "XR Report Block", FieldType::Object);

/// Children of one RTCP packet (union of all packet-type layouts).
static PACKET_FIELDS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Version", FieldType::U8),
    FieldDescriptor::new("padding", "Padding", FieldType::U8),
    // RFC 3550, Section 6.4.1 — SR/RR "reception report count (RC)".
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
    FieldDescriptor::new(
        "reception_report_count",
        "Reception Report Count",
        FieldType::U8,
    )
    .optional(),
    // RFC 3550, Sections 6.5, 6.6 — SDES/BYE "source count (SC)".
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.5
    FieldDescriptor::new("source_count", "Source Count", FieldType::U8).optional(),
    // RFC 3550, Section 6.7 — APP "subtype".
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.7
    FieldDescriptor::new("subtype", "Subtype", FieldType::U8).optional(),
    // RFC 4585, Section 6.1 — "Feedback message type (FMT)".
    // https://www.rfc-editor.org/rfc/rfc4585#section-6.1
    FieldDescriptor::new("fmt", "Feedback Message Type", FieldType::U8)
        .optional()
        .with_display_fn(fmt_display),
    // RFC 3611, Section 2 — XR "reserved".
    // https://www.rfc-editor.org/rfc/rfc3611#section-2
    FieldDescriptor::new("reserved", "Reserved", FieldType::U8).optional(),
    // The 5-bit count field of a packet type this dissector does not decode.
    FieldDescriptor::new("count", "Count", FieldType::U8).optional(),
    FieldDescriptor::new("packet_type", "Packet Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(pt) => packet_type_name(*pt),
            _ => None,
        },
    ),
    FieldDescriptor::new("length", "Length", FieldType::U16),
    FieldDescriptor::new("ssrc", "SSRC", FieldType::U32).optional(),
    FieldDescriptor::new("media_ssrc", "SSRC of Media Source", FieldType::U32).optional(),
    FieldDescriptor::new("ntp_timestamp", "NTP Timestamp", FieldType::U64).optional(),
    FieldDescriptor::new("rtp_timestamp", "RTP Timestamp", FieldType::U32).optional(),
    FieldDescriptor::new(
        "sender_packet_count",
        "Sender's Packet Count",
        FieldType::U32,
    )
    .optional(),
    FieldDescriptor::new("sender_octet_count", "Sender's Octet Count", FieldType::U32).optional(),
    FieldDescriptor::new("report_blocks", "Report Blocks", FieldType::Array)
        .optional()
        .with_children(REPORT_BLOCK_FIELDS),
    FieldDescriptor::new(
        "profile_extensions",
        "Profile-specific Extensions",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("chunks", "SDES Chunks", FieldType::Array)
        .optional()
        .with_children(SDES_CHUNK_FIELDS),
    FieldDescriptor::new("sources", "SSRC/CSRC List", FieldType::Array).optional(),
    FieldDescriptor::new("reason_length", "Reason Length", FieldType::U8).optional(),
    FieldDescriptor::new("reason", "Reason for Leaving", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("name", "Name", FieldType::Bytes)
        .optional()
        .with_format_fn(format_utf8_lossy),
    FieldDescriptor::new("app_data", "Application-dependent Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("nack", "Generic NACKs", FieldType::Array)
        .optional()
        .with_children(NACK_FIELDS),
    FieldDescriptor::new("tmmb", "TMMBR/TMMBN Entries", FieldType::Array)
        .optional()
        .with_children(TMMB_FIELDS),
    FieldDescriptor::new("fir", "FIR Entries", FieldType::Array)
        .optional()
        .with_children(FIR_FIELDS),
    FieldDescriptor::new("sli", "SLI Entries", FieldType::Array)
        .optional()
        .with_children(SLI_FIELDS),
    FieldDescriptor::new("rpsi", "RPSI", FieldType::Object)
        .optional()
        .with_children(RPSI_FIELDS),
    FieldDescriptor::new("fci", "Feedback Control Information", FieldType::Bytes).optional(),
    FieldDescriptor::new("xr_blocks", "Report Blocks", FieldType::Array)
        .optional()
        .with_children(XR_BLOCK_FIELDS),
    // Octets of the packet body that could not be decoded (unknown packet
    // type, or a malformed variable-length part).
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("padding_length", "Padding Length", FieldType::U8).optional(),
];
const PF_VERSION: usize = 0;
const PF_PADDING: usize = 1;
const PF_RC: usize = 2;
const PF_SC: usize = 3;
const PF_SUBTYPE: usize = 4;
const PF_FMT: usize = 5;
const PF_RESERVED: usize = 6;
const PF_COUNT: usize = 7;
const PF_PACKET_TYPE: usize = 8;
const PF_LENGTH: usize = 9;
const PF_SSRC: usize = 10;
const PF_MEDIA_SSRC: usize = 11;
const PF_NTP_TIMESTAMP: usize = 12;
const PF_RTP_TIMESTAMP: usize = 13;
const PF_SENDER_PACKET_COUNT: usize = 14;
const PF_SENDER_OCTET_COUNT: usize = 15;
const PF_REPORT_BLOCKS: usize = 16;
const PF_PROFILE_EXTENSIONS: usize = 17;
const PF_CHUNKS: usize = 18;
const PF_SOURCES: usize = 19;
const PF_REASON_LENGTH: usize = 20;
const PF_REASON: usize = 21;
const PF_NAME: usize = 22;
const PF_APP_DATA: usize = 23;
const PF_NACK: usize = 24;
const PF_TMMB: usize = 25;
const PF_FIR: usize = 26;
const PF_SLI: usize = 27;
const PF_RPSI: usize = 28;
const PF_FCI: usize = 29;
const PF_XR_BLOCKS: usize = 30;
const PF_DATA: usize = 31;
const PF_PADDING_LENGTH: usize = 32;
static FD_PACKET: FieldDescriptor =
    FieldDescriptor::new("packet", "RTCP Packet", FieldType::Object);

static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("packets", "Packets", FieldType::Array).with_children(PACKET_FIELDS),
    // Octets after the last well-formed RTCP packet (e.g. an SRTCP trailer).
    FieldDescriptor::new("trailing_data", "Trailing Data", FieldType::Bytes).optional(),
];
const FD_PACKETS: usize = 0;
const FD_TRAILING_DATA: usize = 1;

/// Specification references for the RTCP dissector.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 3550",
        "RTP: A Transport Protocol for Real-Time Applications",
        "https://www.rfc-editor.org/rfc/rfc3550#section-6",
    ),
    SpecReference::new(
        "RFC 4585",
        "Extended RTP Profile for Real-time Transport Control Protocol (RTCP)-Based Feedback (RTP/AVPF)",
        "https://www.rfc-editor.org/rfc/rfc4585#section-6",
    ),
    SpecReference::new(
        "RFC 5104",
        "Codec Control Messages in the RTP Audio-Visual Profile with Feedback (AVPF)",
        "https://www.rfc-editor.org/rfc/rfc5104#section-4",
    ),
    SpecReference::new(
        "RFC 3611",
        "RTP Control Protocol Extended Reports (RTCP XR)",
        "https://www.rfc-editor.org/rfc/rfc3611",
    ),
    SpecReference::new(
        "RFC 5506",
        "Support for Reduced-Size Real-Time Transport Control Protocol (RTCP): Opportunities and Consequences",
        "https://www.rfc-editor.org/rfc/rfc5506",
    ),
    SpecReference::new(
        "RFC 5761",
        "Multiplexing RTP Data and Control Packets on a Single Port",
        "https://www.rfc-editor.org/rfc/rfc5761#section-4",
    ),
];

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// A validated RTCP common header.
struct Header {
    padding: u8,
    count: u8,
    pt: u8,
    length: u16,
    /// Total packet size in octets, including header and padding.
    total: usize,
    /// Number of padding octets at the end of the packet (0 when P=0).
    pad: usize,
}

/// Minimum body size (octets after the common header, excluding padding)
/// required by the fixed part of each packet type.
fn fixed_body_len(pt: u8, count: u8) -> usize {
    let count = usize::from(count);
    match pt {
        // RFC 3550, Section 6.4.1 — SSRC, 20-octet sender info, RC blocks.
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
        PT_SR => 4 + SENDER_INFO_SIZE + count * REPORT_BLOCK_SIZE,
        // RFC 3550, Section 6.4.2 — SSRC, RC report blocks.
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.2
        PT_RR => 4 + count * REPORT_BLOCK_SIZE,
        // RFC 3550, Section 6.6 — SC SSRC/CSRC identifiers.
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.6
        PT_BYE => 4 * count,
        // RFC 3550, Section 6.7 — SSRC/CSRC and a 4-octet name.
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.7
        PT_APP => 8,
        // RFC 4585, Section 6.1 — SSRC of packet sender and of media source.
        // https://www.rfc-editor.org/rfc/rfc4585#section-6.1
        PT_RTPFB | PT_PSFB => 8,
        // RFC 3611, Section 2 — "An XR packet consists of a header of two
        // 32-bit words". https://www.rfc-editor.org/rfc/rfc3611#section-2
        PT_XR => 4,
        _ => 0,
    }
}

/// Validate the RTCP packet starting at `pos`.
///
/// `Truncated.actual` is always `data.len()` so the error describes the whole
/// datagram handed to the dissector.
fn check_packet(data: &[u8], pos: usize) -> Result<Header, PacketError> {
    // RFC 3550, Section 6.4.1 — common header.
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
    if data.len() < pos + HEADER_SIZE {
        return Err(PacketError::Truncated {
            expected: pos + HEADER_SIZE,
            actual: data.len(),
        });
    }
    let b0 = data[pos];
    let version = b0 >> 6;
    if version != RTCP_VERSION {
        return Err(PacketError::InvalidFieldValue {
            field: "version",
            value: u32::from(version),
        });
    }
    let padding = (b0 >> 5) & 0x01;
    let count = b0 & 0x1F;
    let pt = data[pos + 1];
    let length = read_be_u16(data, pos + 2)?;

    // RFC 3550, Section 6.4.1 — "The length of this RTCP packet in 32-bit
    // words minus one, including the header and any padding."
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
    let total = (usize::from(length) + 1) * 4;
    if data.len() < pos + total {
        return Err(PacketError::Truncated {
            expected: pos + total,
            actual: data.len(),
        });
    }

    // RFC 3550, Section 6.4.1 — "The last octet of the padding is a count of
    // how many padding octets should be ignored, including itself".
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
    let pad = if padding == 1 {
        let pc = usize::from(data[pos + total - 1]);
        if pc == 0 || pc > total - HEADER_SIZE {
            return Err(PacketError::InvalidHeader(
                "RTCP padding count is zero or exceeds the packet",
            ));
        }
        pc
    } else {
        0
    };

    if total - HEADER_SIZE - pad < fixed_body_len(pt, count) {
        return Err(PacketError::InvalidHeader(
            "RTCP packet is shorter than the fixed part of its type",
        ));
    }

    Ok(Header {
        padding,
        count,
        pt,
        length,
        total,
        pad,
    })
}

/// Push a big-endian `u32` read from `body[at..at + 4]`.
fn push_u32<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    body: &'pkt [u8],
    at: usize,
    base: usize,
) -> Result<(), PacketError> {
    buf.push_field(
        fd,
        FieldValue::U32(read_be_u32(body, at)?),
        base + at..base + at + 4,
    );
    Ok(())
}

/// Push `bytes` (a sub-slice of `body` starting at `at`) as a `Bytes` field
/// when it is non-empty.
fn push_bytes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fd: &'static FieldDescriptor,
    bytes: &'pkt [u8],
    at: usize,
    base: usize,
) {
    if !bytes.is_empty() {
        buf.push_field(
            fd,
            FieldValue::Bytes(bytes),
            base + at..base + at + bytes.len(),
        );
    }
}

/// SR (RFC 3550, Section 6.4.1) and RR (Section 6.4.2) body.
///
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1>
fn emit_report<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
    sender_report: bool,
    rc: u8,
) -> Result<(), PacketError> {
    push_u32(buf, &PACKET_FIELDS[PF_SSRC], body, 0, base)?;
    let mut pos = 4;
    if sender_report {
        buf.push_field(
            &PACKET_FIELDS[PF_NTP_TIMESTAMP],
            FieldValue::U64(read_be_u64(body, 4)?),
            base + 4..base + 12,
        );
        push_u32(buf, &PACKET_FIELDS[PF_RTP_TIMESTAMP], body, 12, base)?;
        push_u32(buf, &PACKET_FIELDS[PF_SENDER_PACKET_COUNT], body, 16, base)?;
        push_u32(buf, &PACKET_FIELDS[PF_SENDER_OCTET_COUNT], body, 20, base)?;
        pos += SENDER_INFO_SIZE;
    }

    if rc > 0 {
        let blocks_end = pos + usize::from(rc) * REPORT_BLOCK_SIZE;
        let arr = buf.begin_container(
            &PACKET_FIELDS[PF_REPORT_BLOCKS],
            FieldValue::Array(0..0),
            base + pos..base + blocks_end,
        );
        while pos < blocks_end {
            let obj = buf.begin_container(
                &FD_REPORT_BLOCK,
                FieldValue::Object(0..0),
                base + pos..base + pos + REPORT_BLOCK_SIZE,
            );
            push_u32(buf, &REPORT_BLOCK_FIELDS[RB_SSRC], body, pos, base)?;
            buf.push_field(
                &REPORT_BLOCK_FIELDS[RB_FRACTION_LOST],
                FieldValue::U8(body[pos + 4]),
                base + pos + 4..base + pos + 5,
            );
            // RFC 3550, Section 6.4.1 — "cumulative number of packets lost:
            // 24 bits" ... "the loss may be negative if there are
            // duplicates." Sign-extend the 24-bit two's complement value.
            // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
            let raw = read_be_u32(body, pos + 4)? & 0x00FF_FFFF;
            let lost = ((raw << 8) as i32) >> 8;
            buf.push_field(
                &REPORT_BLOCK_FIELDS[RB_CUMULATIVE_LOST],
                FieldValue::I32(lost),
                base + pos + 5..base + pos + 8,
            );
            push_u32(
                buf,
                &REPORT_BLOCK_FIELDS[RB_EXT_HIGHEST_SEQ],
                body,
                pos + 8,
                base,
            )?;
            push_u32(buf, &REPORT_BLOCK_FIELDS[RB_JITTER], body, pos + 12, base)?;
            push_u32(buf, &REPORT_BLOCK_FIELDS[RB_LSR], body, pos + 16, base)?;
            push_u32(buf, &REPORT_BLOCK_FIELDS[RB_DLSR], body, pos + 20, base)?;
            buf.end_container(obj);
            pos += REPORT_BLOCK_SIZE;
        }
        buf.end_container(arr);
    }

    // RFC 3550, Section 6.4.1 — "possibly followed by a fourth
    // profile-specific extension section if defined."
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
    push_bytes(
        buf,
        &PACKET_FIELDS[PF_PROFILE_EXTENSIONS],
        &body[pos..],
        pos,
        base,
    );
    Ok(())
}

/// Scan the item list of one SDES chunk starting at `start` (just after the
/// SSRC/CSRC). Returns `(items_end, next_chunk)`: the offset of the null item
/// that ends the list and the offset of the next chunk, or `None` when the
/// item list is malformed.
///
/// RFC 3550, Section 6.5 — <https://www.rfc-editor.org/rfc/rfc3550#section-6.5>
fn scan_sdes_items(body: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut pos = start;
    loop {
        let item_type = *body.get(pos)?;
        if item_type == 0 {
            // RFC 3550, Section 6.5 — "The list of items in each chunk MUST
            // be terminated by one or more null octets, the first of which is
            // interpreted as an item type of zero to denote the end of the
            // list. No length octet follows the null item type octet, but
            // additional null octets MUST be included if needed to pad until
            // the next 32-bit boundary."
            // https://www.rfc-editor.org/rfc/rfc3550#section-6.5
            let next = (pos + 1).next_multiple_of(4);
            return (next <= body.len()).then_some((pos, next));
        }
        let len = usize::from(*body.get(pos + 1)?);
        if pos + 2 + len > body.len() {
            return None;
        }
        // RFC 3550, Section 6.5.8 — the PRIV text starts with an 8-bit prefix
        // length that must fit in the item.
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.5.8
        if item_type == SDES_PRIV && (len == 0 || 1 + usize::from(body[pos + 2]) > len) {
            return None;
        }
        pos += 2 + len;
    }
}

/// Emit the items `body[start..end]` of one SDES chunk, already validated by
/// [`scan_sdes_items`].
fn emit_sdes_items<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
    start: usize,
    end: usize,
) {
    if end == start {
        return;
    }
    let arr = buf.begin_container(
        &SDES_CHUNK_FIELDS[CH_ITEMS],
        FieldValue::Array(0..0),
        base + start..base + end,
    );
    let mut pos = start;
    while pos < end {
        let item_type = body[pos];
        let len = usize::from(body[pos + 1]);
        let obj = buf.begin_container(
            &FD_SDES_ITEM,
            FieldValue::Object(0..0),
            base + pos..base + pos + 2 + len,
        );
        buf.push_field(
            &SDES_ITEM_FIELDS[IT_TYPE],
            FieldValue::U8(item_type),
            base + pos..base + pos + 1,
        );
        buf.push_field(
            &SDES_ITEM_FIELDS[IT_LENGTH],
            FieldValue::U8(body[pos + 1]),
            base + pos + 1..base + pos + 2,
        );
        let mut text_start = pos + 2;
        if item_type == SDES_PRIV {
            // RFC 3550, Section 6.5.8 — "PRIV: Private Extensions SDES
            // Item" with an 8-bit prefix length, prefix string and value
            // string. https://www.rfc-editor.org/rfc/rfc3550#section-6.5.8
            let plen = usize::from(body[text_start]);
            buf.push_field(
                &SDES_ITEM_FIELDS[IT_PREFIX_LENGTH],
                FieldValue::U8(body[text_start]),
                base + text_start..base + text_start + 1,
            );
            buf.push_field(
                &SDES_ITEM_FIELDS[IT_PREFIX],
                FieldValue::Bytes(&body[text_start + 1..text_start + 1 + plen]),
                base + text_start + 1..base + text_start + 1 + plen,
            );
            text_start += 1 + plen;
        }
        let text_end = pos + 2 + len;
        buf.push_field(
            &SDES_ITEM_FIELDS[IT_TEXT],
            FieldValue::Bytes(&body[text_start..text_end]),
            base + text_start..base + text_end,
        );
        buf.end_container(obj);
        pos = text_end;
    }
    buf.end_container(arr);
}

/// SDES body (RFC 3550, Section 6.5 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.5>).
///
/// Chunks are decoded until the source count is reached; a malformed chunk
/// and everything after it is kept as raw `data`.
fn emit_sdes<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
    sc: u8,
) -> Result<(), PacketError> {
    // Find the well-formed chunks first so every range is known up front.
    let mut valid_end = 0;
    let mut chunks = 0;
    while chunks < sc && body.len() >= valid_end + 4 {
        let Some((_, next)) = scan_sdes_items(body, valid_end + 4) else {
            break;
        };
        valid_end = next;
        chunks += 1;
    }

    if chunks > 0 {
        let arr = buf.begin_container(
            &PACKET_FIELDS[PF_CHUNKS],
            FieldValue::Array(0..0),
            base..base + valid_end,
        );
        let mut pos = 0;
        while pos < valid_end {
            let Some((items_end, next)) = scan_sdes_items(body, pos + 4) else {
                break;
            };
            let obj = buf.begin_container(
                &FD_SDES_CHUNK,
                FieldValue::Object(0..0),
                base + pos..base + next,
            );
            push_u32(buf, &SDES_CHUNK_FIELDS[CH_SSRC], body, pos, base)?;
            emit_sdes_items(buf, body, base, pos + 4, items_end);
            buf.end_container(obj);
            pos = next;
        }
        buf.end_container(arr);
    }
    push_bytes(
        buf,
        &PACKET_FIELDS[PF_DATA],
        &body[valid_end..],
        valid_end,
        base,
    );
    Ok(())
}

/// BYE body (RFC 3550, Section 6.6 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.6>).
fn emit_bye<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
    sc: u8,
) -> Result<(), PacketError> {
    let list_end = 4 * usize::from(sc);
    if sc > 0 {
        let arr = buf.begin_container(
            &PACKET_FIELDS[PF_SOURCES],
            FieldValue::Array(0..0),
            base..base + list_end,
        );
        for at in (0..list_end).step_by(4) {
            push_u32(buf, &PACKET_FIELDS[PF_SOURCES], body, at, base)?;
        }
        buf.end_container(arr);
    }

    // RFC 3550, Section 6.6 — "Optionally, the BYE packet MAY include an
    // 8-bit octet count followed by that many octets of text indicating the
    // reason for leaving".
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.6
    let rest = &body[list_end..];
    if let Some(&rl) = rest.first() {
        let rl = usize::from(rl);
        if rl < rest.len() {
            buf.push_field(
                &PACKET_FIELDS[PF_REASON_LENGTH],
                FieldValue::U8(rest[0]),
                base + list_end..base + list_end + 1,
            );
            push_bytes(
                buf,
                &PACKET_FIELDS[PF_REASON],
                &rest[1..1 + rl],
                list_end + 1,
                base,
            );
        } else {
            push_bytes(buf, &PACKET_FIELDS[PF_DATA], rest, list_end, base);
        }
    }
    Ok(())
}

/// APP body (RFC 3550, Section 6.7 —
/// <https://www.rfc-editor.org/rfc/rfc3550#section-6.7>).
fn emit_app<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
) -> Result<(), PacketError> {
    push_u32(buf, &PACKET_FIELDS[PF_SSRC], body, 0, base)?;
    buf.push_field(
        &PACKET_FIELDS[PF_NAME],
        FieldValue::Bytes(&body[4..8]),
        base + 4..base + 8,
    );
    push_bytes(buf, &PACKET_FIELDS[PF_APP_DATA], &body[8..], 8, base);
    Ok(())
}

/// Emit `fci` as an array of fixed-size entries; a trailing partial entry is
/// kept as raw `data`.
fn emit_fci_entries<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    fci: &'pkt [u8],
    base: usize,
    array_fd: &'static FieldDescriptor,
    entry_fd: &'static FieldDescriptor,
    entry_size: usize,
    mut emit: impl FnMut(&mut DissectBuffer<'pkt>, &'pkt [u8], usize) -> Result<(), PacketError>,
) -> Result<(), PacketError> {
    let whole = fci.len() / entry_size * entry_size;
    if whole > 0 {
        let arr = buf.begin_container(array_fd, FieldValue::Array(0..0), base..base + whole);
        for at in (0..whole).step_by(entry_size) {
            let obj = buf.begin_container(
                entry_fd,
                FieldValue::Object(0..0),
                base + at..base + at + entry_size,
            );
            emit(buf, &fci[at..at + entry_size], base + at)?;
            buf.end_container(obj);
        }
        buf.end_container(arr);
    }
    push_bytes(buf, &PACKET_FIELDS[PF_DATA], &fci[whole..], whole, base);
    Ok(())
}

/// TMMBR / TMMBN FCI entry (RFC 5104, Sections 4.2.1.1 and 4.2.2.1 —
/// <https://www.rfc-editor.org/rfc/rfc5104#section-4.2.1.1>).
fn emit_tmmb_entry<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    e: &'pkt [u8],
    base: usize,
) -> Result<(), PacketError> {
    push_u32(buf, &TMMB_FIELDS[0], e, 0, base)?;
    // "MxTBR Exp (6 bits)", "MxTBR Mantissa (17 bits)", "Measured Overhead
    // (9 bits)".
    let w = read_be_u32(e, 4)?;
    buf.push_field(
        &TMMB_FIELDS[1],
        FieldValue::U8((w >> 26) as u8),
        base + 4..base + 5,
    );
    buf.push_field(
        &TMMB_FIELDS[2],
        FieldValue::U32((w >> 9) & 0x1_FFFF),
        base + 4..base + 7,
    );
    buf.push_field(
        &TMMB_FIELDS[3],
        FieldValue::U16((w & 0x1FF) as u16),
        base + 6..base + 8,
    );
    Ok(())
}

/// RTPFB / PSFB body (RFC 4585, Section 6.1 —
/// <https://www.rfc-editor.org/rfc/rfc4585#section-6.1>).
fn emit_feedback<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
    pt: u8,
    fmt: u8,
) -> Result<(), PacketError> {
    push_u32(buf, &PACKET_FIELDS[PF_SSRC], body, 0, base)?;
    push_u32(buf, &PACKET_FIELDS[PF_MEDIA_SSRC], body, 4, base)?;
    let fci = &body[8..];
    let fci_base = base + 8;
    match (pt, fmt) {
        // RFC 4585, Section 6.2.1 — Generic NACK: 16-bit PID, 16-bit BLP.
        // https://www.rfc-editor.org/rfc/rfc4585#section-6.2.1
        (PT_RTPFB, FMT_GENERIC_NACK) => emit_fci_entries(
            buf,
            fci,
            fci_base,
            &PACKET_FIELDS[PF_NACK],
            &FD_NACK_ENTRY,
            4,
            |buf, e, b| {
                buf.push_field(
                    &NACK_FIELDS[0],
                    FieldValue::U16(read_be_u16(e, 0)?),
                    b..b + 2,
                );
                buf.push_field(
                    &NACK_FIELDS[1],
                    FieldValue::U16(read_be_u16(e, 2)?),
                    b + 2..b + 4,
                );
                Ok(())
            },
        ),
        // RFC 5104, Sections 4.2.1.1 / 4.2.2.1 — TMMBR / TMMBN entries.
        // https://www.rfc-editor.org/rfc/rfc5104#section-4.2.1.1
        (PT_RTPFB, FMT_TMMBR | FMT_TMMBN) => emit_fci_entries(
            buf,
            fci,
            fci_base,
            &PACKET_FIELDS[PF_TMMB],
            &FD_TMMB_ENTRY,
            8,
            emit_tmmb_entry,
        ),
        // RFC 4585, Section 6.3.1.2 — "PLI does not require parameters.
        // Therefore, the length field MUST be 2, and there MUST NOT be any
        // Feedback Control Information."
        // https://www.rfc-editor.org/rfc/rfc4585#section-6.3.1.2
        (PT_PSFB, FMT_PLI) => {
            push_bytes(buf, &PACKET_FIELDS[PF_DATA], fci, 8, base);
            Ok(())
        }
        // RFC 4585, Section 6.3.2.2 — SLI: First (13 bits), Number (13 bits),
        // PictureID (6 bits).
        // https://www.rfc-editor.org/rfc/rfc4585#section-6.3.2.2
        (PT_PSFB, FMT_SLI) => emit_fci_entries(
            buf,
            fci,
            fci_base,
            &PACKET_FIELDS[PF_SLI],
            &FD_SLI_ENTRY,
            4,
            |buf, e, b| {
                let w = read_be_u32(e, 0)?;
                buf.push_field(&SLI_FIELDS[0], FieldValue::U16((w >> 19) as u16), b..b + 2);
                buf.push_field(
                    &SLI_FIELDS[1],
                    FieldValue::U16(((w >> 6) & 0x1FFF) as u16),
                    b + 1..b + 4,
                );
                buf.push_field(
                    &SLI_FIELDS[2],
                    FieldValue::U8((w & 0x3F) as u8),
                    b + 3..b + 4,
                );
                Ok(())
            },
        ),
        // RFC 4585, Section 6.3.3.2 — RPSI: PB (8 bits), 0 (1 bit), Payload
        // Type (7 bits), native RPSI bit string.
        // https://www.rfc-editor.org/rfc/rfc4585#section-6.3.3.2
        (PT_PSFB, FMT_RPSI) if fci.len() >= 2 => {
            let obj = buf.begin_container(
                &PACKET_FIELDS[PF_RPSI],
                FieldValue::Object(0..0),
                fci_base..fci_base + fci.len(),
            );
            buf.push_field(
                &RPSI_FIELDS[0],
                FieldValue::U8(fci[0]),
                fci_base..fci_base + 1,
            );
            buf.push_field(
                &RPSI_FIELDS[1],
                FieldValue::U8(fci[1] & 0x7F),
                fci_base + 1..fci_base + 2,
            );
            buf.push_field(
                &RPSI_FIELDS[2],
                FieldValue::Bytes(&fci[2..]),
                fci_base + 2..fci_base + fci.len(),
            );
            buf.end_container(obj);
            Ok(())
        }
        // RFC 5104, Section 4.3.1.1 — FIR: SSRC, Seq nr. (8 bits), Reserved.
        // https://www.rfc-editor.org/rfc/rfc5104#section-4.3.1.1
        (PT_PSFB, FMT_FIR) => emit_fci_entries(
            buf,
            fci,
            fci_base,
            &PACKET_FIELDS[PF_FIR],
            &FD_FIR_ENTRY,
            8,
            |buf, e, b| {
                push_u32(buf, &FIR_FIELDS[0], e, 0, b)?;
                buf.push_field(&FIR_FIELDS[1], FieldValue::U8(e[4]), b + 4..b + 5);
                Ok(())
            },
        ),
        // Other FMT values (e.g. AFB): FCI kept opaque.
        _ => {
            push_bytes(buf, &PACKET_FIELDS[PF_FCI], fci, 8, base);
            Ok(())
        }
    }
}

/// Type-specific contents of one XR block.
fn emit_xr_block_contents<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    bt: u8,
    type_specific: u8,
    contents: &'pkt [u8],
    base: usize,
) -> Result<(), PacketError> {
    match bt {
        // RFC 3611, Sections 4.1 and 4.2 — Loss / Duplicate RLE: SSRC of
        // source, begin_seq, end_seq, then 16-bit chunks.
        // https://www.rfc-editor.org/rfc/rfc3611#section-4.1
        XR_BT_LOSS_RLE | XR_BT_DUPLICATE_RLE if contents.len() >= 8 => {
            // "thinning (T): 4 bits"
            buf.push_field(
                &XR_BLOCK_FIELDS[XB_THINNING],
                FieldValue::U8(type_specific & 0x0F),
                base - 3..base - 2,
            );
            push_u32(buf, &XR_BLOCK_FIELDS[XB_SSRC], contents, 0, base)?;
            buf.push_field(
                &XR_BLOCK_FIELDS[XB_BEGIN_SEQ],
                FieldValue::U16(read_be_u16(contents, 4)?),
                base + 4..base + 6,
            );
            buf.push_field(
                &XR_BLOCK_FIELDS[XB_END_SEQ],
                FieldValue::U16(read_be_u16(contents, 6)?),
                base + 6..base + 8,
            );
            let chunks = &contents[8..];
            let mut arr = None;
            for at in (0..chunks.len() / 2 * 2).step_by(2) {
                let c = read_be_u16(chunks, at)?;
                // RFC 3611, Section 4.1 — "If the chunk is all zeroes, then
                // it is a terminating null chunk."
                // https://www.rfc-editor.org/rfc/rfc3611#section-4.1
                if c == 0 {
                    continue;
                }
                let cb = base + 8 + at;
                if arr.is_none() {
                    arr = Some(buf.begin_container(
                        &XR_BLOCK_FIELDS[XB_RLE_CHUNKS],
                        FieldValue::Array(0..0),
                        base + 8..base + contents.len(),
                    ));
                }
                let obj = buf.begin_container(&FD_RLE_CHUNK, FieldValue::Object(0..0), cb..cb + 2);
                if c & 0x8000 == 0 {
                    // RFC 3611, Section 4.1.1 — Run Length Chunk: C=0, run
                    // type (R) 1 bit, run length 14 bits.
                    // https://www.rfc-editor.org/rfc/rfc3611#section-4.1.1
                    buf.push_field(
                        &RLE_CHUNK_FIELDS[0],
                        FieldValue::U8(((c >> 14) & 0x01) as u8),
                        cb..cb + 1,
                    );
                    buf.push_field(
                        &RLE_CHUNK_FIELDS[1],
                        FieldValue::U16(c & 0x3FFF),
                        cb..cb + 2,
                    );
                } else {
                    // RFC 3611, Section 4.1.2 — Bit Vector Chunk: C=1,
                    // 15-bit vector.
                    // https://www.rfc-editor.org/rfc/rfc3611#section-4.1.2
                    buf.push_field(
                        &RLE_CHUNK_FIELDS[2],
                        FieldValue::U16(c & 0x7FFF),
                        cb..cb + 2,
                    );
                }
                buf.end_container(obj);
            }
            if let Some(arr_idx) = arr {
                buf.end_container(arr_idx);
            }
        }
        // RFC 3611, Section 4.4 — Receiver Reference Time: 64-bit NTP
        // timestamp ("block length = 2").
        // https://www.rfc-editor.org/rfc/rfc3611#section-4.4
        XR_BT_RRT if contents.len() == 8 => {
            buf.push_field(
                &XR_BLOCK_FIELDS[XB_NTP_TIMESTAMP],
                FieldValue::U64(read_be_u64(contents, 0)?),
                base..base + 8,
            );
        }
        // RFC 3611, Section 4.5 — DLRR: 3-word sub-blocks.
        // https://www.rfc-editor.org/rfc/rfc3611#section-4.5
        XR_BT_DLRR if !contents.is_empty() && contents.len() % DLRR_SUB_BLOCK_SIZE == 0 => {
            let arr = buf.begin_container(
                &XR_BLOCK_FIELDS[XB_DLRR],
                FieldValue::Array(0..0),
                base..base + contents.len(),
            );
            for at in (0..contents.len()).step_by(DLRR_SUB_BLOCK_SIZE) {
                let obj = buf.begin_container(
                    &FD_DLRR_SUB_BLOCK,
                    FieldValue::Object(0..0),
                    base + at..base + at + DLRR_SUB_BLOCK_SIZE,
                );
                push_u32(buf, &DLRR_FIELDS[0], contents, at, base)?;
                push_u32(buf, &DLRR_FIELDS[1], contents, at + 4, base)?;
                push_u32(buf, &DLRR_FIELDS[2], contents, at + 8, base)?;
                buf.end_container(obj);
            }
            buf.end_container(arr);
        }
        _ => push_bytes(buf, &XR_BLOCK_FIELDS[XB_CONTENTS], contents, 0, base),
    }
    Ok(())
}

/// XR body (RFC 3611, Sections 2 and 3 —
/// <https://www.rfc-editor.org/rfc/rfc3611#section-3>).
fn emit_xr<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    body: &'pkt [u8],
    base: usize,
) -> Result<(), PacketError> {
    push_u32(buf, &PACKET_FIELDS[PF_SSRC], body, 0, base)?;
    let mut pos = 4;
    let mut arr = None;
    // RFC 3611, Section 3 — "block length: 16 bits  The length of this report
    // block, including the header, in 32-bit words minus one."
    // https://www.rfc-editor.org/rfc/rfc3611#section-3
    while body.len() >= pos + 4 {
        let block_len = read_be_u16(body, pos + 2)?;
        let block_total = (usize::from(block_len) + 1) * 4;
        if body.len() < pos + block_total {
            break;
        }
        if arr.is_none() {
            arr = Some(buf.begin_container(
                &PACKET_FIELDS[PF_XR_BLOCKS],
                FieldValue::Array(0..0),
                base + 4..base + body.len(),
            ));
        }
        let bt = body[pos];
        let type_specific = body[pos + 1];
        let obj = buf.begin_container(
            &FD_XR_BLOCK,
            FieldValue::Object(0..0),
            base + pos..base + pos + block_total,
        );
        buf.push_field(
            &XR_BLOCK_FIELDS[XB_BLOCK_TYPE],
            FieldValue::U8(bt),
            base + pos..base + pos + 1,
        );
        buf.push_field(
            &XR_BLOCK_FIELDS[XB_TYPE_SPECIFIC],
            FieldValue::U8(type_specific),
            base + pos + 1..base + pos + 2,
        );
        buf.push_field(
            &XR_BLOCK_FIELDS[XB_BLOCK_LENGTH],
            FieldValue::U16(block_len),
            base + pos + 2..base + pos + 4,
        );
        emit_xr_block_contents(
            buf,
            bt,
            type_specific,
            &body[pos + 4..pos + block_total],
            base + pos + 4,
        )?;
        buf.end_container(obj);
        pos += block_total;
    }
    if let Some(arr_idx) = arr {
        buf.end_container(arr_idx);
        if let Some(f) = buf.field_mut(arr_idx as usize) {
            f.range = base + 4..base + pos;
        }
    }
    push_bytes(buf, &PACKET_FIELDS[PF_DATA], &body[pos..], pos, base);
    Ok(())
}

/// Emit one validated RTCP packet as an object element of `packets`.
fn emit_packet<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    pkt: &'pkt [u8],
    h: &Header,
    base: usize,
) -> Result<(), PacketError> {
    let obj = buf.begin_container(&FD_PACKET, FieldValue::Object(0..0), base..base + h.total);
    buf.push_field(
        &PACKET_FIELDS[PF_VERSION],
        FieldValue::U8(RTCP_VERSION),
        base..base + 1,
    );
    buf.push_field(
        &PACKET_FIELDS[PF_PADDING],
        FieldValue::U8(h.padding),
        base..base + 1,
    );
    let count_fd = match h.pt {
        PT_SR | PT_RR => PF_RC,
        PT_SDES | PT_BYE => PF_SC,
        PT_APP => PF_SUBTYPE,
        PT_RTPFB | PT_PSFB => PF_FMT,
        PT_XR => PF_RESERVED,
        _ => PF_COUNT,
    };
    buf.push_field(
        &PACKET_FIELDS[count_fd],
        FieldValue::U8(h.count),
        base..base + 1,
    );
    buf.push_field(
        &PACKET_FIELDS[PF_PACKET_TYPE],
        FieldValue::U8(h.pt),
        base + 1..base + 2,
    );
    buf.push_field(
        &PACKET_FIELDS[PF_LENGTH],
        FieldValue::U16(h.length),
        base + 2..base + 4,
    );

    let body = &pkt[HEADER_SIZE..h.total - h.pad];
    let body_base = base + HEADER_SIZE;
    match h.pt {
        PT_SR => emit_report(buf, body, body_base, true, h.count)?,
        PT_RR => emit_report(buf, body, body_base, false, h.count)?,
        PT_SDES => emit_sdes(buf, body, body_base, h.count)?,
        PT_BYE => emit_bye(buf, body, body_base, h.count)?,
        PT_APP => emit_app(buf, body, body_base)?,
        PT_RTPFB | PT_PSFB => emit_feedback(buf, body, body_base, h.pt, h.count)?,
        PT_XR => emit_xr(buf, body, body_base)?,
        _ => push_bytes(buf, &PACKET_FIELDS[PF_DATA], body, 0, body_base),
    }

    if h.pad > 0 {
        buf.push_field(
            &PACKET_FIELDS[PF_PADDING_LENGTH],
            FieldValue::U8(pkt[h.total - 1]),
            base + h.total - 1..base + h.total,
        );
    }
    buf.end_container(obj);
    Ok(())
}

/// RTCP dissector.
///
/// Decodes every RTCP packet of a compound datagram into the `packets`
/// array. The first packet must be well-formed; after it, the walk stops at
/// the first octets that do not form a well-formed RTCP packet, which are
/// kept as `trailing_data` (for example an SRTCP trailer, RFC 3711,
/// Section 3.4 — <https://www.rfc-editor.org/rfc/rfc3711#section-3.4>).
pub struct RtcpDissector;

impl Dissector for RtcpDissector {
    fn name(&self) -> &'static str {
        "RTP Control Protocol"
    }

    fn short_name(&self) -> &'static str {
        "RTCP"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // RFC 5506, Section 3.4.2 — "the header verification must take into
        // account that the payload type numbers for the (first) RTCP in the
        // lower-layer datagram may differ from 200 or 201 (SR or RR)." Only
        // the first packet's header is required to be valid.
        // https://www.rfc-editor.org/rfc/rfc5506#section-3.4.2
        let mut header = check_packet(data, 0)?;

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + data.len(),
        );
        let arr = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_PACKETS],
            FieldValue::Array(0..0),
            offset..offset,
        );
        let mut end = 0;
        loop {
            emit_packet(buf, &data[end..end + header.total], &header, offset + end)?;
            end += header.total;
            if end == data.len() {
                break;
            }
            // Stop at the first octets that are not a well-formed packet.
            match check_packet(data, end) {
                Ok(next) => header = next,
                Err(_) => break,
            }
        }
        buf.end_container(arr);
        if let Some(f) = buf.field_mut(arr as usize) {
            f.range = offset..offset + end;
        }

        if end < data.len() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_TRAILING_DATA],
                FieldValue::Bytes(&data[end..]),
                offset + end..offset + data.len(),
            );
        }
        buf.end_layer();

        // RTCP carries no further protocol; the whole datagram is consumed.
        Ok(DissectResult::new(data.len(), DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::Field;

    // # RFC 3550 (RTCP) Coverage
    //
    // | RFC Section | Description                                   | Test                                   |
    // |-------------|-----------------------------------------------|----------------------------------------|
    // | 6.1         | Compound packet walk (SR + SDES)              | sr_two_report_blocks_and_sdes_cname    |
    // | 6.4.1       | SR header, sender info, report blocks         | sr_two_report_blocks_and_sdes_cname    |
    // | 6.4.1       | Cumulative lost is a signed 24-bit value      | report_block_negative_cumulative_lost  |
    // | 6.4.1       | Profile-specific extensions                   | sr_profile_specific_extensions         |
    // | 6.4.1       | SR shorter than RC report blocks rejected     | sr_shorter_than_report_count_rejected  |
    // | 6.4.1       | Padding bit and padding count                 | padding_on_last_packet                 |
    // | 6.4.1       | Padding count zero rejected                   | padding_count_zero_rejected            |
    // | 6.4.1       | Length overrunning the datagram               | length_overrunning_datagram            |
    // | 6.4.1       | Truncated common header                       | truncated_common_header                |
    // | 6.4.1       | Version must be 2                             | invalid_version_rejected               |
    // | 6.4.2       | RR with a report block                        | rr_only_reduced_size                   |
    // | 6.5         | SDES chunks, CNAME / NAME items, null padding | sdes_two_chunks                        |
    // | 6.5.8       | SDES PRIV prefix                              | sdes_priv_item                         |
    // | 6.5         | SDES item overrunning the packet → raw data   | sdes_item_overrun_kept_raw             |
    // | 6.5, 6.5.8  | Malformed later chunk / PRIV / short SC       | sdes_malformed_chunks_kept_raw         |
    // | 6.6         | BYE with reason                               | bye_with_reason                        |
    // | 6.6         | BYE reason overrunning the packet → raw data  | bye_reason_overrun_kept_raw            |
    // | 6.7         | APP subtype, name, data                       | app_packet                             |
    // | A.2         | Trailing bytes after the compound packet      | trailing_bytes_after_compound          |
    // | 12.1        | Unknown packet type kept raw                  | unknown_packet_type                    |
    // | 12.1, 12.2  | Packet type / SDES item names (IANA)          | name_tables, name_tables_cover_iana_assignments |
    // | —           | Display functions ignore other values         | display_functions_ignore_other_values  |
    // | —           | Field ranges honour the layer offset          | offset_is_applied_to_ranges            |
    // | —           | Dissector metadata                            | dissector_metadata                     |
    //
    // # RFC 4585 (RTP/AVPF) Coverage
    //
    // | RFC Section | Description                                   | Test                                   |
    // |-------------|-----------------------------------------------|----------------------------------------|
    // | 6.1         | Common FB header, FMT name                    | psfb_pli                               |
    // | 6.2.1       | Generic NACK entries                          | rtpfb_generic_nack                     |
    // | 6.3.1       | PLI (no FCI)                                  | psfb_pli                               |
    // | 6.3.2       | SLI entries                                   | psfb_sli                               |
    // | 6.3.3       | RPSI                                          | psfb_rpsi                              |
    // | 6.1         | Unknown FMT keeps raw FCI                     | psfb_afb_kept_raw                      |
    // | 6.1         | FB shorter than its fixed part rejected       | feedback_too_short_rejected            |
    // | 6.3.1.2     | PLI carrying FCI → raw data                   | feedback_and_xr_edge_cases             |
    //
    // # RFC 5104 (CCM) Coverage
    //
    // | RFC Section | Description                                   | Test                                   |
    // |-------------|-----------------------------------------------|----------------------------------------|
    // | 4.2.1       | TMMBR entries                                 | rtpfb_tmmbr                            |
    // | 4.2.2       | TMMBN entries                                 | rtpfb_tmmbn                            |
    // | 4.3.1       | FIR entries                                   | psfb_fir                               |
    //
    // # RFC 3611 (RTCP XR) Coverage
    //
    // | RFC Section | Description                                   | Test                                   |
    // |-------------|-----------------------------------------------|----------------------------------------|
    // | 2, 3        | XR header and block framework                 | xr_dlrr                                |
    // | 4.1         | Loss RLE: thinning, run length / bit vector   | xr_loss_rle                            |
    // | 4.4         | Receiver Reference Time                       | xr_receiver_reference_time             |
    // | 4.5         | DLRR sub-blocks                               | xr_dlrr                                |
    // | 3           | Unknown block type kept raw                   | xr_unknown_block_and_overrun           |
    // | 3           | Block overrunning the packet → raw data       | xr_unknown_block_and_overrun           |
    // | 4.1.3, 4.2  | Duplicate RLE with terminating null chunk     | feedback_and_xr_edge_cases             |
    // | 4.4, 4.5    | RRT / DLRR with unexpected length kept raw    | feedback_and_xr_edge_cases             |
    //
    // # RFC 5506 (Reduced-Size RTCP) Coverage
    //
    // | RFC Section | Description                                   | Test                                   |
    // |-------------|-----------------------------------------------|----------------------------------------|
    // | 3.4.2       | First packet need not be SR/RR               | psfb_pli, rtpfb_generic_nack           |
    // | 3.4.2       | Malformed later packet stops the walk         | malformed_second_packet_is_trailing    |

    /// Build one RTCP packet: header (V=2, P=0, count, PT, length) + body.
    fn pkt(count: u8, pt: u8, body: &[u8]) -> Vec<u8> {
        assert_eq!(body.len() % 4, 0, "test body must be 32-bit aligned");
        let words = ((4 + body.len()) / 4 - 1) as u16;
        let mut v = vec![0x80 | (count & 0x1F), pt];
        v.extend_from_slice(&words.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn report_block(ssrc: u32, fraction: u8, lost: [u8; 3], ext_seq: u32) -> Vec<u8> {
        let mut v = ssrc.to_be_bytes().to_vec();
        v.push(fraction);
        v.extend_from_slice(&lost);
        v.extend_from_slice(&ext_seq.to_be_bytes());
        v.extend_from_slice(&0x0000_0010u32.to_be_bytes()); // jitter
        v.extend_from_slice(&0xB705_2000u32.to_be_bytes()); // LSR
        v.extend_from_slice(&0x0005_4000u32.to_be_bytes()); // DLSR
        v
    }

    fn dissect(data: &[u8]) -> (DissectBuffer<'_>, DissectResult) {
        let mut buf = DissectBuffer::new();
        let res = RtcpDissector.dissect(data, &mut buf, 0).unwrap();
        (buf, res)
    }

    /// Direct children of a container field.
    fn children<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, f: &Field<'pkt>) -> Vec<&'a Field<'pkt>> {
        let r = f.value.as_container_range().unwrap().clone();
        let mut out = Vec::new();
        let mut i = r.start;
        while i < r.end {
            let c = &buf.fields()[i as usize];
            out.push(c);
            i = match c.value.as_container_range() {
                Some(cr) => cr.end,
                None => i + 1,
            };
        }
        out
    }

    fn child<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        f: &Field<'pkt>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        children(buf, f).into_iter().find(|c| c.name() == name)
    }

    fn val<'pkt>(buf: &DissectBuffer<'pkt>, f: &Field<'pkt>, name: &str) -> FieldValue<'pkt> {
        child(buf, f, name)
            .unwrap_or_else(|| panic!("missing field {name}"))
            .value
            .clone()
    }

    /// The per-packet objects of the RTCP layer.
    fn packets<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>) -> Vec<&'a Field<'pkt>> {
        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, "packets").unwrap();
        children(buf, arr)
    }

    #[test]
    fn sr_two_report_blocks_and_sdes_cname() {
        let mut sr_body = 0x1111_1111u32.to_be_bytes().to_vec(); // SSRC of sender
        sr_body.extend_from_slice(&0xB44D_B705_2000_0000u64.to_be_bytes()); // NTP
        sr_body.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // RTP ts
        sr_body.extend_from_slice(&100u32.to_be_bytes()); // packet count
        sr_body.extend_from_slice(&16_000u32.to_be_bytes()); // octet count
        sr_body.extend(report_block(0x2222_2222, 0x40, [0, 0, 5], 0x0001_0010));
        sr_body.extend(report_block(0x3333_3333, 0, [0, 0, 0], 0x0000_0100));
        let mut data = pkt(2, 200, &sr_body);
        // SDES: one chunk, CNAME "ab", end + pad to 32-bit boundary.
        let mut sdes = 0x1111_1111u32.to_be_bytes().to_vec();
        sdes.extend_from_slice(&[1, 2, b'a', b'b', 0, 0, 0, 0]);
        let sdes_start = data.len();
        data.extend(pkt(1, 202, &sdes));

        let (buf, res) = dissect(&data);
        assert_eq!(res.bytes_consumed, data.len());
        assert_eq!(res.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "RTCP");
        assert_eq!(layer.range, 0..data.len());

        let pkts = packets(&buf);
        assert_eq!(pkts.len(), 2);
        let sr = pkts[0];
        assert_eq!(sr.range, 0..sdes_start);
        assert_eq!(val(&buf, sr, "version"), FieldValue::U8(2));
        assert_eq!(val(&buf, sr, "padding"), FieldValue::U8(0));
        assert_eq!(val(&buf, sr, "reception_report_count"), FieldValue::U8(2));
        assert_eq!(val(&buf, sr, "packet_type"), FieldValue::U8(200));
        assert_eq!(
            buf.resolve_nested_display_name(
                sr.value.as_container_range().unwrap(),
                "packet_type_name"
            ),
            Some("SR")
        );
        assert_eq!(val(&buf, sr, "length"), FieldValue::U16(18));
        assert_eq!(val(&buf, sr, "ssrc"), FieldValue::U32(0x1111_1111));
        assert_eq!(
            val(&buf, sr, "ntp_timestamp"),
            FieldValue::U64(0xB44D_B705_2000_0000)
        );
        assert_eq!(val(&buf, sr, "rtp_timestamp"), FieldValue::U32(0x0001_0000));
        assert_eq!(val(&buf, sr, "sender_packet_count"), FieldValue::U32(100));
        assert_eq!(val(&buf, sr, "sender_octet_count"), FieldValue::U32(16_000));
        assert!(child(&buf, sr, "profile_extensions").is_none());

        let rbs = children(&buf, child(&buf, sr, "report_blocks").unwrap());
        assert_eq!(rbs.len(), 2);
        assert_eq!(rbs[0].range, 28..52);
        assert_eq!(val(&buf, rbs[0], "ssrc"), FieldValue::U32(0x2222_2222));
        assert_eq!(val(&buf, rbs[0], "fraction_lost"), FieldValue::U8(0x40));
        assert_eq!(val(&buf, rbs[0], "cumulative_lost"), FieldValue::I32(5));
        assert_eq!(
            val(&buf, rbs[0], "extended_highest_sequence"),
            FieldValue::U32(0x0001_0010)
        );
        assert_eq!(val(&buf, rbs[0], "jitter"), FieldValue::U32(0x10));
        assert_eq!(val(&buf, rbs[0], "lsr"), FieldValue::U32(0xB705_2000));
        assert_eq!(val(&buf, rbs[0], "dlsr"), FieldValue::U32(0x0005_4000));
        assert_eq!(val(&buf, rbs[1], "ssrc"), FieldValue::U32(0x3333_3333));

        let sdes = pkts[1];
        assert_eq!(val(&buf, sdes, "source_count"), FieldValue::U8(1));
        let chunks = children(&buf, child(&buf, sdes, "chunks").unwrap());
        assert_eq!(chunks.len(), 1);
        assert_eq!(val(&buf, chunks[0], "ssrc"), FieldValue::U32(0x1111_1111));
        let items = children(&buf, child(&buf, chunks[0], "items").unwrap());
        assert_eq!(items.len(), 1);
        assert_eq!(val(&buf, items[0], "type"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_nested_display_name(
                items[0].value.as_container_range().unwrap(),
                "type_name"
            ),
            Some("CNAME")
        );
        assert_eq!(val(&buf, items[0], "length"), FieldValue::U8(2));
        assert_eq!(val(&buf, items[0], "text"), FieldValue::Bytes(b"ab"));
        assert_eq!(
            child(&buf, items[0], "text").unwrap().range,
            sdes_start + 10..sdes_start + 12
        );
    }

    #[test]
    fn report_block_negative_cumulative_lost() {
        // RFC 3550, Section 6.4.1 — "the loss may be negative if there are
        // duplicates": 0xFFFFFE is -2 as a signed 24-bit value.
        // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
        let mut body = 0x1u32.to_be_bytes().to_vec();
        body.extend(report_block(0x2, 0, [0xFF, 0xFF, 0xFE], 1));
        let data = pkt(1, 201, &body);
        let (buf, _) = dissect(&data);
        let rr = packets(&buf)[0];
        let rb = children(&buf, child(&buf, rr, "report_blocks").unwrap())[0];
        assert_eq!(val(&buf, rb, "cumulative_lost"), FieldValue::I32(-2));
    }

    #[test]
    fn sr_profile_specific_extensions() {
        let mut body = vec![0u8; 24]; // SSRC + sender info, RC=0
        body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let data = pkt(0, 200, &body);
        let (buf, _) = dissect(&data);
        let sr = packets(&buf)[0];
        assert!(child(&buf, sr, "report_blocks").is_none());
        assert_eq!(
            val(&buf, sr, "profile_extensions"),
            FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(child(&buf, sr, "profile_extensions").unwrap().range, 28..32);
    }

    #[test]
    fn sr_shorter_than_report_count_rejected() {
        // RC=1 but only the SSRC and sender info are present.
        let data = pkt(1, 200, &[0u8; 24]);
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            RtcpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
        assert!(buf.layers().is_empty());
    }

    #[test]
    fn rr_only_reduced_size() {
        let mut body = 0x1234_5678u32.to_be_bytes().to_vec();
        body.extend(report_block(0x9ABC_DEF0, 1, [0, 1, 0], 2));
        let data = pkt(1, 201, &body);
        let (buf, res) = dissect(&data);
        assert_eq!(res.bytes_consumed, 32);
        let pkts = packets(&buf);
        assert_eq!(pkts.len(), 1);
        assert_eq!(val(&buf, pkts[0], "packet_type"), FieldValue::U8(201));
        assert_eq!(val(&buf, pkts[0], "ssrc"), FieldValue::U32(0x1234_5678));
        assert!(child(&buf, pkts[0], "ntp_timestamp").is_none());
        let rb = children(&buf, child(&buf, pkts[0], "report_blocks").unwrap())[0];
        assert_eq!(val(&buf, rb, "cumulative_lost"), FieldValue::I32(256));
    }

    #[test]
    fn padding_on_last_packet() {
        // RR with RC=0 plus 4 octets of padding (count 4 in the last octet).
        let mut data = vec![0xA0, 201, 0x00, 0x02];
        data.extend_from_slice(&0x1u32.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 4]);
        let (buf, res) = dissect(&data);
        assert_eq!(res.bytes_consumed, 12);
        let rr = packets(&buf)[0];
        assert_eq!(val(&buf, rr, "padding"), FieldValue::U8(1));
        assert_eq!(val(&buf, rr, "padding_length"), FieldValue::U8(4));
        assert_eq!(child(&buf, rr, "padding_length").unwrap().range, 11..12);
        assert!(child(&buf, rr, "profile_extensions").is_none());
    }

    #[test]
    fn padding_count_zero_rejected() {
        let mut data = vec![0xA0, 201, 0x00, 0x01];
        data.extend_from_slice(&[0, 0, 0, 0]);
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            RtcpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    #[test]
    fn length_overrunning_datagram() {
        // length = 7 words (32 octets) but only 8 octets are present.
        let data = [0x80, 201, 0x00, 0x07, 0, 0, 0, 1];
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RtcpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 32,
                actual: 8
            })
        );
    }

    #[test]
    fn truncated_common_header() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RtcpDissector.dissect(&[0x80, 201, 0x00], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn invalid_version_rejected() {
        let data = [0x40, 201, 0x00, 0x01, 0, 0, 0, 1];
        let mut buf = DissectBuffer::new();
        assert_eq!(
            RtcpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidFieldValue {
                field: "version",
                value: 1
            })
        );
    }

    #[test]
    fn sdes_two_chunks() {
        let mut body = 0xAu32.to_be_bytes().to_vec();
        // CNAME "x", NAME "yz", end, pad → 1+1+1 + 1+1+2 + 1 = 8 octets.
        body.extend_from_slice(&[1, 1, b'x', 2, 2, b'y', b'z', 0]);
        body.extend_from_slice(&0xBu32.to_be_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]); // chunk with zero items
        let data = pkt(2, 202, &body);
        let (buf, _) = dissect(&data);
        let sdes = packets(&buf)[0];
        let chunks = children(&buf, child(&buf, sdes, "chunks").unwrap());
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].range, 4..16);
        let items = children(&buf, child(&buf, chunks[0], "items").unwrap());
        assert_eq!(items.len(), 2);
        assert_eq!(val(&buf, items[1], "type"), FieldValue::U8(2));
        assert_eq!(val(&buf, items[1], "text"), FieldValue::Bytes(b"yz"));
        assert_eq!(val(&buf, chunks[1], "ssrc"), FieldValue::U32(0xB));
        assert!(child(&buf, chunks[1], "items").is_none());
        assert!(child(&buf, sdes, "data").is_none());
    }

    #[test]
    fn sdes_priv_item() {
        let mut body = 0xAu32.to_be_bytes().to_vec();
        // PRIV, length 5: prefix length 2, prefix "ab", value "cd"; end + pad.
        body.extend_from_slice(&[8, 5, 2, b'a', b'b', b'c', b'd', 0]);
        let data = pkt(1, 202, &body);
        let (buf, _) = dissect(&data);
        let chunk = children(&buf, child(&buf, packets(&buf)[0], "chunks").unwrap())[0];
        let item = children(&buf, child(&buf, chunk, "items").unwrap())[0];
        assert_eq!(val(&buf, item, "type"), FieldValue::U8(8));
        assert_eq!(val(&buf, item, "prefix_length"), FieldValue::U8(2));
        assert_eq!(val(&buf, item, "prefix"), FieldValue::Bytes(b"ab"));
        assert_eq!(val(&buf, item, "text"), FieldValue::Bytes(b"cd"));
        assert_eq!(child(&buf, item, "text").unwrap().range, 13..15);
    }

    #[test]
    fn sdes_item_overrun_kept_raw() {
        let mut body = 0xAu32.to_be_bytes().to_vec();
        body.extend_from_slice(&[1, 9, b'a', b'b']); // length 9 overruns
        let data = pkt(1, 202, &body);
        let (buf, _) = dissect(&data);
        let sdes = packets(&buf)[0];
        assert!(child(&buf, sdes, "chunks").is_none());
        assert_eq!(val(&buf, sdes, "data"), FieldValue::Bytes(&body));
        assert_eq!(child(&buf, sdes, "data").unwrap().range, 4..12);
    }

    #[test]
    fn bye_with_reason() {
        let mut body = 0x1u32.to_be_bytes().to_vec();
        body.extend_from_slice(&0x2u32.to_be_bytes());
        body.extend_from_slice(&[5, b'c', b'a', b'm', b'e', b'r', 0, 0]);
        let data = pkt(2, 203, &body);
        let (buf, _) = dissect(&data);
        let bye = packets(&buf)[0];
        assert_eq!(val(&buf, bye, "source_count"), FieldValue::U8(2));
        let srcs = children(&buf, child(&buf, bye, "sources").unwrap());
        assert_eq!(srcs.len(), 2);
        assert_eq!(srcs[1].value, FieldValue::U32(2));
        assert_eq!(srcs[1].range, 8..12);
        assert_eq!(val(&buf, bye, "reason_length"), FieldValue::U8(5));
        assert_eq!(val(&buf, bye, "reason"), FieldValue::Bytes(b"camer"));
        assert_eq!(child(&buf, bye, "reason").unwrap().range, 13..18);
    }

    #[test]
    fn bye_reason_overrun_kept_raw() {
        let mut body = 0x1u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[9, b'a', b'b', b'c']);
        let data = pkt(1, 203, &body);
        let (buf, _) = dissect(&data);
        let bye = packets(&buf)[0];
        assert!(child(&buf, bye, "reason").is_none());
        assert_eq!(
            val(&buf, bye, "data"),
            FieldValue::Bytes(&[9, b'a', b'b', b'c'])
        );
    }

    #[test]
    fn app_packet() {
        let mut body = 0x1u32.to_be_bytes().to_vec();
        body.extend_from_slice(b"TEST");
        body.extend_from_slice(&[1, 2, 3, 4]);
        let data = pkt(3, 204, &body);
        let (buf, _) = dissect(&data);
        let app = packets(&buf)[0];
        assert_eq!(val(&buf, app, "subtype"), FieldValue::U8(3));
        assert_eq!(val(&buf, app, "ssrc"), FieldValue::U32(1));
        assert_eq!(val(&buf, app, "name"), FieldValue::Bytes(b"TEST"));
        assert_eq!(val(&buf, app, "app_data"), FieldValue::Bytes(&[1, 2, 3, 4]));
    }

    #[test]
    fn trailing_bytes_after_compound() {
        // RR followed by an SRTCP-like trailer (E flag + index) that is not
        // a valid RTCP header.
        let mut data = pkt(0, 201, &0x1u32.to_be_bytes());
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x01, 0xAA, 0xBB]);
        let (buf, res) = dissect(&data);
        assert_eq!(res.bytes_consumed, data.len());
        assert_eq!(packets(&buf).len(), 1);
        let layer = &buf.layers()[0];
        let trailing = buf.field_by_name(layer, "trailing_data").unwrap();
        assert_eq!(trailing.range, 8..14);
        assert_eq!(
            trailing.value,
            FieldValue::Bytes(&[0x80, 0x00, 0x00, 0x01, 0xAA, 0xBB])
        );
    }

    #[test]
    fn malformed_second_packet_is_trailing() {
        // Second packet claims RC=1 but has no report block.
        let mut data = pkt(0, 201, &0x1u32.to_be_bytes());
        data.extend(pkt(1, 201, &0x2u32.to_be_bytes()));
        let (buf, _) = dissect(&data);
        assert_eq!(packets(&buf).len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "trailing_data").unwrap().range,
            8..16
        );
    }

    #[test]
    fn unknown_packet_type() {
        let data = pkt(7, 210, &[1, 2, 3, 4]);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(val(&buf, p, "count"), FieldValue::U8(7));
        assert_eq!(val(&buf, p, "data"), FieldValue::Bytes(&[1, 2, 3, 4]));
        assert_eq!(
            buf.resolve_nested_display_name(
                p.value.as_container_range().unwrap(),
                "packet_type_name"
            ),
            Some("TOKEN")
        );
    }

    fn fb(fmt: u8, pt: u8, fci: &[u8]) -> Vec<u8> {
        let mut body = 0x1111_1111u32.to_be_bytes().to_vec();
        body.extend_from_slice(&0x2222_2222u32.to_be_bytes());
        body.extend_from_slice(fci);
        pkt(fmt, pt, &body)
    }

    #[test]
    fn psfb_pli() {
        let data = fb(1, 206, &[]);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(val(&buf, p, "fmt"), FieldValue::U8(1));
        assert_eq!(
            buf.resolve_nested_display_name(p.value.as_container_range().unwrap(), "fmt_name"),
            Some("PLI")
        );
        assert_eq!(val(&buf, p, "ssrc"), FieldValue::U32(0x1111_1111));
        assert_eq!(val(&buf, p, "media_ssrc"), FieldValue::U32(0x2222_2222));
        assert!(child(&buf, p, "fci").is_none());
        assert!(child(&buf, p, "data").is_none());
    }

    #[test]
    fn rtpfb_generic_nack() {
        let data = fb(1, 205, &[0x00, 0x10, 0x00, 0x05, 0x01, 0x00, 0x80, 0x00]);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(
            buf.resolve_nested_display_name(p.value.as_container_range().unwrap(), "fmt_name"),
            Some("Generic NACK")
        );
        let nacks = children(&buf, child(&buf, p, "nack").unwrap());
        assert_eq!(nacks.len(), 2);
        assert_eq!(nacks[0].range, 12..16);
        assert_eq!(val(&buf, nacks[0], "pid"), FieldValue::U16(0x10));
        assert_eq!(val(&buf, nacks[0], "blp"), FieldValue::U16(0x05));
        assert_eq!(val(&buf, nacks[1], "pid"), FieldValue::U16(0x100));
        assert_eq!(val(&buf, nacks[1], "blp"), FieldValue::U16(0x8000));
    }

    #[test]
    fn rtpfb_tmmbr() {
        // exp=3, mantissa=0x1_0000, overhead=40 → 0x0E000028 | (0x10000 << 9)
        let word: u32 = (3 << 26) | (0x1_0000 << 9) | 40;
        let mut fci = 0x3333_3333u32.to_be_bytes().to_vec();
        fci.extend_from_slice(&word.to_be_bytes());
        let data = fb(3, 205, &fci);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        let e = children(&buf, child(&buf, p, "tmmb").unwrap())[0];
        assert_eq!(val(&buf, e, "ssrc"), FieldValue::U32(0x3333_3333));
        assert_eq!(val(&buf, e, "mxtbr_exp"), FieldValue::U8(3));
        assert_eq!(val(&buf, e, "mxtbr_mantissa"), FieldValue::U32(0x1_0000));
        assert_eq!(val(&buf, e, "measured_overhead"), FieldValue::U16(40));
    }

    #[test]
    fn rtpfb_tmmbn() {
        // TMMBN may carry zero entries (RFC 5104, Section 4.2.2.1 —
        // https://www.rfc-editor.org/rfc/rfc5104#section-4.2.2.1), and a
        // partial trailing entry is kept raw.
        let data = fb(4, 205, &[]);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(
            buf.resolve_nested_display_name(p.value.as_container_range().unwrap(), "fmt_name"),
            Some("TMMBN")
        );
        assert!(child(&buf, p, "tmmb").is_none());

        let data = fb(4, 205, &[0, 0, 0, 1]);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert!(child(&buf, p, "tmmb").is_none());
        assert_eq!(val(&buf, p, "data"), FieldValue::Bytes(&[0, 0, 0, 1]));
    }

    #[test]
    fn psfb_sli() {
        // first=5, number=3, picture_id=7
        let word: u32 = (5 << 19) | (3 << 6) | 7;
        let data = fb(2, 206, &word.to_be_bytes());
        let (buf, _) = dissect(&data);
        let e = children(&buf, child(&buf, packets(&buf)[0], "sli").unwrap())[0];
        assert_eq!(val(&buf, e, "first"), FieldValue::U16(5));
        assert_eq!(val(&buf, e, "number"), FieldValue::U16(3));
        assert_eq!(val(&buf, e, "picture_id"), FieldValue::U8(7));
    }

    #[test]
    fn psfb_rpsi() {
        let data = fb(3, 206, &[8, 0x60, 0xAB, 0x00]);
        let (buf, _) = dissect(&data);
        let r = child(&buf, packets(&buf)[0], "rpsi").unwrap();
        assert_eq!(val(&buf, r, "pb"), FieldValue::U8(8));
        assert_eq!(val(&buf, r, "payload_type"), FieldValue::U8(0x60));
        assert_eq!(val(&buf, r, "bit_string"), FieldValue::Bytes(&[0xAB, 0x00]));
    }

    #[test]
    fn psfb_fir() {
        let mut fci = 0x4444_4444u32.to_be_bytes().to_vec();
        fci.extend_from_slice(&[9, 0, 0, 0]);
        let data = fb(4, 206, &fci);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(
            buf.resolve_nested_display_name(p.value.as_container_range().unwrap(), "fmt_name"),
            Some("FIR")
        );
        let e = children(&buf, child(&buf, p, "fir").unwrap())[0];
        assert_eq!(e.range, 12..20);
        assert_eq!(val(&buf, e, "ssrc"), FieldValue::U32(0x4444_4444));
        assert_eq!(val(&buf, e, "seq_nr"), FieldValue::U8(9));
    }

    #[test]
    fn psfb_afb_kept_raw() {
        let data = fb(15, 206, b"REMB");
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(
            buf.resolve_nested_display_name(p.value.as_container_range().unwrap(), "fmt_name"),
            Some("AFB")
        );
        assert_eq!(val(&buf, p, "fci"), FieldValue::Bytes(b"REMB"));
    }

    #[test]
    fn feedback_too_short_rejected() {
        let data = pkt(1, 206, &0x1u32.to_be_bytes());
        let mut buf = DissectBuffer::new();
        assert!(matches!(
            RtcpDissector.dissect(&data, &mut buf, 0),
            Err(PacketError::InvalidHeader(_))
        ));
    }

    fn xr(blocks: &[u8]) -> Vec<u8> {
        let mut body = 0x5555_5555u32.to_be_bytes().to_vec();
        body.extend_from_slice(blocks);
        pkt(0, 207, &body)
    }

    #[test]
    fn xr_dlrr() {
        let mut blocks = vec![5, 0, 0, 3];
        blocks.extend_from_slice(&0x6666_6666u32.to_be_bytes());
        blocks.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        blocks.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        let data = xr(&blocks);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        assert_eq!(val(&buf, p, "packet_type"), FieldValue::U8(207));
        assert_eq!(val(&buf, p, "ssrc"), FieldValue::U32(0x5555_5555));
        let bs = children(&buf, child(&buf, p, "xr_blocks").unwrap());
        assert_eq!(bs.len(), 1);
        assert_eq!(bs[0].range, 8..24);
        assert_eq!(val(&buf, bs[0], "block_type"), FieldValue::U8(5));
        assert_eq!(
            buf.resolve_nested_display_name(
                bs[0].value.as_container_range().unwrap(),
                "block_type_name"
            ),
            Some("DLRR Report Block")
        );
        assert_eq!(val(&buf, bs[0], "block_length"), FieldValue::U16(3));
        let subs = children(&buf, child(&buf, bs[0], "dlrr").unwrap());
        assert_eq!(subs.len(), 1);
        assert_eq!(val(&buf, subs[0], "ssrc"), FieldValue::U32(0x6666_6666));
        assert_eq!(val(&buf, subs[0], "lrr"), FieldValue::U32(0x1234_5678));
        assert_eq!(val(&buf, subs[0], "dlrr"), FieldValue::U32(0x0001_0000));
    }

    #[test]
    fn xr_receiver_reference_time() {
        let mut blocks = vec![4, 0, 0, 2];
        blocks.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        let data = xr(&blocks);
        let (buf, _) = dissect(&data);
        let b = children(&buf, child(&buf, packets(&buf)[0], "xr_blocks").unwrap())[0];
        assert_eq!(
            val(&buf, b, "ntp_timestamp"),
            FieldValue::U64(0x0102_0304_0506_0708)
        );
        assert!(child(&buf, b, "contents").is_none());
    }

    #[test]
    fn xr_loss_rle() {
        // T=2, SSRC, begin 13821, end 13866, one bit vector + null chunk.
        let mut blocks = vec![1, 0x02, 0, 3];
        blocks.extend_from_slice(&0x7777_7777u32.to_be_bytes());
        blocks.extend_from_slice(&13_821u16.to_be_bytes());
        blocks.extend_from_slice(&13_866u16.to_be_bytes());
        // run of 21 receipts (C=0, R=1, 21), bit vector 0b1_111110111100000
        blocks.extend_from_slice(&[0x40, 21, 0xFB, 0xE0]);
        let data = xr(&blocks);
        let (buf, _) = dissect(&data);
        let b = children(&buf, child(&buf, packets(&buf)[0], "xr_blocks").unwrap())[0];
        assert_eq!(val(&buf, b, "thinning"), FieldValue::U8(2));
        assert_eq!(val(&buf, b, "ssrc"), FieldValue::U32(0x7777_7777));
        assert_eq!(val(&buf, b, "begin_seq"), FieldValue::U16(13_821));
        assert_eq!(val(&buf, b, "end_seq"), FieldValue::U16(13_866));
        let chunks = children(&buf, child(&buf, b, "rle_chunks").unwrap());
        assert_eq!(chunks.len(), 2);
        assert_eq!(val(&buf, chunks[0], "run_type"), FieldValue::U8(1));
        assert_eq!(val(&buf, chunks[0], "run_length"), FieldValue::U16(21));
        assert_eq!(val(&buf, chunks[1], "bit_vector"), FieldValue::U16(0x7BE0));
        assert_eq!(chunks[1].range, 22..24);
    }

    #[test]
    fn xr_unknown_block_and_overrun() {
        let mut blocks = vec![200, 0x11, 0, 0]; // unknown BT, zero-length contents
        blocks.extend_from_slice(&[42, 0, 0, 1]); // BT 42, 1 word
        blocks.extend_from_slice(&[1, 2, 3, 4]);
        blocks.extend_from_slice(&[7, 0, 0, 9]); // overruns the packet
        let data = xr(&blocks);
        let (buf, _) = dissect(&data);
        let p = packets(&buf)[0];
        let bs = children(&buf, child(&buf, p, "xr_blocks").unwrap());
        assert_eq!(bs.len(), 2);
        assert_eq!(val(&buf, bs[0], "type_specific"), FieldValue::U8(0x11));
        assert!(child(&buf, bs[0], "contents").is_none());
        assert_eq!(
            val(&buf, bs[1], "contents"),
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        assert_eq!(val(&buf, p, "data"), FieldValue::Bytes(&[7, 0, 0, 9]));
        assert_eq!(child(&buf, p, "data").unwrap().range, 20..24);
    }

    #[test]
    fn offset_is_applied_to_ranges() {
        let data = fb(1, 206, &[]);
        let mut buf = DissectBuffer::new();
        RtcpDissector.dissect(&data, &mut buf, 100).unwrap();
        assert_eq!(buf.layers()[0].range, 100..112);
        let p = packets(&buf)[0];
        assert_eq!(p.range, 100..112);
        assert_eq!(child(&buf, p, "media_ssrc").unwrap().range, 108..112);
    }

    #[test]
    fn dissector_metadata() {
        let d = RtcpDissector;
        assert_eq!(d.name(), "RTP Control Protocol");
        assert_eq!(d.short_name(), "RTCP");
        assert_eq!(d.layer(), Some(ProtocolLayer::Application));
        assert!(d.references().iter().any(|r| r.id == "RFC 3550"));
        let names: Vec<_> = d.field_descriptors().iter().map(|f| f.name).collect();
        assert_eq!(names, ["packets", "trailing_data"]);
    }

    #[test]
    fn name_tables() {
        assert_eq!(packet_type_name(194), Some("SMPTETC"));
        assert_eq!(packet_type_name(213), Some("SNM"));
        assert_eq!(packet_type_name(1), None);
        assert_eq!(sdes_item_name(15), Some("MID"));
        assert_eq!(sdes_item_name(16), None);
        assert_eq!(rtpfb_fmt_name(11), Some("CCFB"));
        assert_eq!(rtpfb_fmt_name(2), None);
        assert_eq!(psfb_fmt_name(10), Some("LRR"));
        assert_eq!(psfb_fmt_name(12), None);
        assert_eq!(
            xr_block_type_name(36),
            Some("Timing Information for QoE Metrics Calculation Block")
        );
        assert_eq!(xr_block_type_name(37), None);
    }

    #[test]
    fn name_tables_cover_iana_assignments() {
        // IANA "RTCP Control Packet Types (PT)": 194-195 and 200-213.
        for pt in (194..=195).chain(200..=213) {
            assert!(packet_type_name(pt).is_some(), "PT {pt}");
        }
        for pt in [0u8, 192, 193, 196, 199, 214, 255] {
            assert!(packet_type_name(pt).is_none(), "PT {pt}");
        }
        for t in 0..=15 {
            assert!(sdes_item_name(t).is_some(), "SDES {t}");
        }
        for fmt in [1u8, 3, 4, 5, 6, 7, 8, 9, 10, 11, 31] {
            assert!(rtpfb_fmt_name(fmt).is_some(), "RTPFB {fmt}");
        }
        for fmt in (1u8..=11).chain([15, 31]) {
            assert!(psfb_fmt_name(fmt).is_some(), "PSFB {fmt}");
        }
        for bt in 1..=36 {
            assert!(xr_block_type_name(bt).is_some(), "XR BT {bt}");
        }
        assert!(xr_block_type_name(0).is_none());
    }

    #[test]
    fn display_functions_ignore_other_values() {
        // `fmt` has no name outside RTPFB / PSFB, or for a non-U8 value.
        let pt_sr = [Field {
            descriptor: &PACKET_FIELDS[PF_PACKET_TYPE],
            value: FieldValue::U8(PT_SR),
            range: 0..1,
        }];
        assert_eq!(fmt_display(&FieldValue::U8(1), &pt_sr), None);
        assert_eq!(fmt_display(&FieldValue::U16(1), &pt_sr), None);
        assert_eq!(fmt_display(&FieldValue::U8(1), &[]), None);
        for fd in [
            &PACKET_FIELDS[PF_PACKET_TYPE],
            &SDES_ITEM_FIELDS[IT_TYPE],
            &XR_BLOCK_FIELDS[XB_BLOCK_TYPE],
        ] {
            let display = fd.display_fn.unwrap();
            assert_eq!(display(&FieldValue::U16(1), &[]), None, "{}", fd.name);
        }
    }

    #[test]
    fn sdes_malformed_chunks_kept_raw() {
        // First chunk is fine; the second has no room for its null padding.
        let mut body = 0xAu32.to_be_bytes().to_vec();
        body.extend_from_slice(&[1, 1, b'x', 0]);
        body.extend_from_slice(&0xBu32.to_be_bytes());
        body.extend_from_slice(&[1, 2, b'y', b'z']); // no terminator
        let data = pkt(2, 202, &body);
        let (buf, _) = dissect(&data);
        let sdes = packets(&buf)[0];
        let chunks = child(&buf, sdes, "chunks").unwrap();
        assert_eq!(chunks.range, 4..12);
        assert_eq!(children(&buf, chunks).len(), 1);
        assert_eq!(child(&buf, sdes, "data").unwrap().range, 12..20);

        // PRIV whose prefix length overruns the item.
        let mut body = 0xAu32.to_be_bytes().to_vec();
        body.extend_from_slice(&[8, 2, 5, b'a', 0, 0, 0, 0]);
        let data = pkt(1, 202, &body);
        let (buf, _) = dissect(&data);
        let sdes = packets(&buf)[0];
        assert!(child(&buf, sdes, "chunks").is_none());
        assert_eq!(val(&buf, sdes, "data"), FieldValue::Bytes(&body));

        // SC larger than the chunks present: decoding stops, nothing left.
        let mut body = 0xAu32.to_be_bytes().to_vec();
        body.extend_from_slice(&[0, 0, 0, 0]);
        let data = pkt(3, 202, &body);
        let (buf, _) = dissect(&data);
        let sdes = packets(&buf)[0];
        assert_eq!(
            children(&buf, child(&buf, sdes, "chunks").unwrap()).len(),
            1
        );
        assert!(child(&buf, sdes, "data").is_none());
    }

    #[test]
    fn feedback_and_xr_edge_cases() {
        // PLI must not carry FCI; anything present is kept raw.
        let data = fb(1, 206, &[1, 2, 3, 4]);
        let (buf, _) = dissect(&data);
        assert_eq!(
            val(&buf, packets(&buf)[0], "data"),
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        // An RPSI without its 2-octet header cannot happen with 32-bit
        // aligned packets, but an empty FCI is kept as no field at all.
        let data = fb(3, 206, &[]);
        let (buf, _) = dissect(&data);
        assert!(child(&buf, packets(&buf)[0], "rpsi").is_none());

        // XR: RRT with the wrong length, DLRR with a partial sub-block, and
        // a Loss RLE block with a terminating null chunk.
        let mut blocks = vec![4, 0, 0, 1, 1, 2, 3, 4];
        blocks.extend_from_slice(&[5, 0, 0, 1, 9, 9, 9, 9]);
        blocks.extend_from_slice(&[2, 0x0F, 0, 3, 0, 0, 0, 1, 0, 1, 0, 2]);
        blocks.extend_from_slice(&[0x80, 0x01, 0x00, 0x00]);
        let data = xr(&blocks);
        let (buf, _) = dissect(&data);
        let bs = children(&buf, child(&buf, packets(&buf)[0], "xr_blocks").unwrap());
        assert_eq!(bs.len(), 3);
        assert_eq!(
            val(&buf, bs[0], "contents"),
            FieldValue::Bytes(&[1, 2, 3, 4])
        );
        assert_eq!(
            val(&buf, bs[1], "contents"),
            FieldValue::Bytes(&[9, 9, 9, 9])
        );
        assert_eq!(val(&buf, bs[2], "thinning"), FieldValue::U8(15));
        let chunks = children(&buf, child(&buf, bs[2], "rle_chunks").unwrap());
        assert_eq!(chunks.len(), 1);
        assert_eq!(val(&buf, chunks[0], "bit_vector"), FieldValue::U16(1));
    }
}
