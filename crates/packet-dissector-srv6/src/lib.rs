//! SRv6 Segment Routing Header (SRH) dissector.
//!
//! ## References
//! - RFC 8754: <https://www.rfc-editor.org/rfc/rfc8754>
//! - RFC 8986 (SRv6 Network Programming): <https://www.rfc-editor.org/rfc/rfc8986>
//! - RFC 9259 (SRv6 OAM, O-flag): <https://www.rfc-editor.org/rfc/rfc9259>
//! - RFC 9800 (updates RFC 8754, CSID/REPLACE-CSID): <https://www.rfc-editor.org/rfc/rfc9800>
//! - RFC 9433 (SRv6 Mobile User Plane): <https://www.rfc-editor.org/rfc/rfc9433>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DispatchHint, DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, FormatContext};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::{read_be_u16, read_be_u32, read_ipv6_addr};

/// SRH fixed header size: Next Header (1) + Hdr Ext Len (1) + Routing Type (1)
/// + Segments Left (1) + Last Entry (1) + Flags (1) + Tag (2) = 8 bytes.
const SRH_FIXED_SIZE: usize = 8;

/// Size of a single Segment List entry (IPv6 address).
const SEGMENT_SIZE: usize = 16;

/// Minimum HMAC TLV value length: D-flag+Reserved (2) + HMAC Key ID (4) = 6 bytes.
/// A conforming HMAC TLV also includes HMAC data (multiples of 8, up to 32 bytes),
/// but we accept shorter values gracefully per Postel's law.
const HMAC_TLV_MIN_VALUE_LEN: usize = 6;

/// CSID flavor selection (RFC 9800).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsidFlavor {
    /// No CSID — classic SRv6 mode.
    Classic,
    /// REPLACE-CSID flavor (RFC 9800, Section 4).
    ///
    /// Each 128-bit segment list entry is split into `K = 128 / LNFL` slots of
    /// `LNFL` bits, where `LNFL = locator_node_bits + function_bits`.
    ReplaceCsid {
        /// CSID length in bits (equal to LNFL in REPLACE-CSID).
        csid_bits: u8,
    },
    /// NEXT-CSID flavor (RFC 9800, Section 3) — also known as "uSID".
    ///
    /// Each 128-bit entry carries a Locator-Block prefix followed by
    /// `K = (128 - LBL) / LNFL` micro-SIDs packed from the MSB of the
    /// remaining bits.
    NextCsid {
        /// Micro-SID length in bits (equal to LNFL).
        usid_bits: u8,
    },
}

/// Mobile SID encoding configuration (RFC 9433).
///
/// Defines how mobile-specific information (IPv4 addresses, Args.Mob.Session,
/// rate-limiting parameters) is packed into the 128-bit SID beyond the standard
/// Locator-Block / Locator-Node / Function / Argument decomposition.
///
/// These encodings are operator-configurable and the bit widths vary by
/// deployment.
// RFC 9433, Sections 6.2–6.8 — https://www.rfc-editor.org/rfc/rfc9433#section-6
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileSidEncoding {
    /// End.M.GTP4.E (RFC 9433, Section 6.6, Figure 9):
    /// `SRGW-IPv6-LOC-FUNC | IPv4DA(a) | Args.Mob.Session(b) | 0-padded(c)`
    ///
    /// where `a + b + c = 128 − len(LOC-FUNC)`.
    EndMGtp4E {
        /// Width of the embedded IPv4 Destination Address in bits.
        ipv4da_bits: u8,
        /// Width of the Args.Mob.Session field in bits.
        args_mob_session_bits: u8,
    },
    /// End.M.GTP6.E (RFC 9433, Section 6.5):
    /// Args.Mob.Session is carried in the Argument portion of the SID.
    EndMGtp6E,
    /// H.M.GTP4.D (RFC 9433, Section 6.7, Figure 11):
    /// `Destination UPF Prefix | IPv4DA(a) | Args.Mob.Session(b) | 0-padded(c)`
    HmGtp4D {
        /// Width of the Destination UPF Prefix in bits.
        prefix_bits: u8,
        /// Width of the embedded IPv4 Destination Address in bits.
        ipv4da_bits: u8,
        /// Width of the Args.Mob.Session field in bits.
        args_mob_session_bits: u8,
    },
    /// End.Limit (RFC 9433, Section 6.8, Figure 12):
    /// `LOC+FUNC(rate-limit) | group-id(i) | limit-rate(j)`
    EndLimit {
        /// Width of the group identifier in bits.
        group_id_bits: u8,
        /// Width of the limit rate in bits.
        limit_rate_bits: u8,
    },
}

// IANA SRv6 Endpoint Behaviors (RFC 9433, Section 11)
// https://www.rfc-editor.org/rfc/rfc9433#section-11

/// End.MAP endpoint behavior value (0x0028).
pub const BEHAVIOR_END_MAP: u16 = 40;
/// End.Limit endpoint behavior value (0x0029).
pub const BEHAVIOR_END_LIMIT: u16 = 41;
/// End.M.GTP6.D endpoint behavior value (0x0045).
pub const BEHAVIOR_END_M_GTP6_D: u16 = 69;
/// End.M.GTP6.Di endpoint behavior value (0x0046).
pub const BEHAVIOR_END_M_GTP6_DI: u16 = 70;
/// End.M.GTP6.E endpoint behavior value (0x0047).
pub const BEHAVIOR_END_M_GTP6_E: u16 = 71;
/// End.M.GTP4.E endpoint behavior value (0x0048).
pub const BEHAVIOR_END_M_GTP4_E: u16 = 72;

/// Return a human-readable name for an IANA SRv6 endpoint behavior value
/// defined in RFC 9433, or `None` if the value is not recognized.
pub fn endpoint_behavior_name(value: u16) -> Option<&'static str> {
    match value {
        BEHAVIOR_END_MAP => Some("End.MAP"),
        BEHAVIOR_END_LIMIT => Some("End.Limit"),
        BEHAVIOR_END_M_GTP6_D => Some("End.M.GTP6.D"),
        BEHAVIOR_END_M_GTP6_DI => Some("End.M.GTP6.Di"),
        BEHAVIOR_END_M_GTP6_E => Some("End.M.GTP6.E"),
        BEHAVIOR_END_M_GTP4_E => Some("End.M.GTP4.E"),
        _ => None,
    }
}

/// SRv6 SID structure configuration (RFC 8986, Section 3.1).
///
/// Defines the bit-level decomposition of a 128-bit SRv6 SID into its
/// constituent parts: Locator-Block, Locator-Node, Function, and Argument.
/// These boundaries are not visible on the wire and require out-of-band
/// configuration (e.g., from the control plane).
#[derive(Debug, Clone)]
pub struct SidStructure {
    /// Locator-Block length in bits.
    pub locator_block_bits: u8,
    /// Locator-Node length in bits.
    pub locator_node_bits: u8,
    /// Function length in bits.
    pub function_bits: u8,
    /// Argument length in bits (remaining bits up to 128).
    pub argument_bits: u8,
    /// CSID flavor (RFC 9800). Use [`CsidFlavor::Classic`] for classic mode.
    pub csid_flavor: CsidFlavor,
    /// Optional mobile SID encoding (RFC 9433). When set, each segment in the
    /// Segment List is additionally decomposed into mobile-specific fields
    /// (embedded IPv4 address, Args.Mob.Session, or rate-limiting parameters)
    /// within the `segments_structure` output.
    pub mobile_encoding: Option<MobileSidEncoding>,
}

impl SidStructure {
    /// Creates a new [`SidStructure`] without mobile SID encoding.
    ///
    /// This constructor initializes the SRv6 SID decomposition as defined in
    /// RFC 8986, Section 3.1, and defaults [`SidStructure::mobile_encoding`]
    /// to [`None`]. Use this method instead of struct literals to avoid
    /// source breakage when new optional fields are added in the future.
    pub fn new(
        locator_block_bits: u8,
        locator_node_bits: u8,
        function_bits: u8,
        argument_bits: u8,
        csid_flavor: CsidFlavor,
    ) -> Self {
        SidStructure {
            locator_block_bits,
            locator_node_bits,
            function_bits,
            argument_bits,
            csid_flavor,
            mobile_encoding: None,
        }
    }
}

/// SRv6 Segment Routing Header dissector.
///
/// Registered at Routing Type 4 via `ByIpv6RoutingType` dispatch. Receives the
/// full Routing Header bytes (including the common fields) from the
/// `RoutingDissector` dispatcher.
///
/// When created with [`Srv6Dissector::with_sid_structure`], each segment in the
/// Segment List is additionally decomposed into Locator-Block, Locator-Node,
/// Function, and Argument fields per RFC 8986.
pub struct Srv6Dissector {
    sid_structure: Option<SidStructure>,
}

impl Srv6Dissector {
    /// Create a new dissector without SID structure analysis.
    pub fn new() -> Self {
        Self {
            sid_structure: None,
        }
    }

    /// Create a new dissector with SID structure analysis enabled.
    pub fn with_sid_structure(s: SidStructure) -> Self {
        Self {
            sid_structure: Some(s),
        }
    }
}

impl Default for Srv6Dissector {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse SRH TLVs (RFC 8754, Section 2.1).
///
/// Iterates over the TLV area and pushes each TLV as an Object container
/// into `buf`. Known TLV types (Pad1, PadN, HMAC) are parsed semantically;
/// unknown types are stored as raw bytes.
fn parse_tlvs<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    tlv_start: usize,
    tlv_end: usize,
) -> Result<(), PacketError> {
    let mut cursor = tlv_start;

    while cursor < tlv_end {
        let type_byte = data[cursor];

        // RFC 8754, Section 2.1.1 — Pad1 TLV (Type 0)
        if type_byte == 0 {
            let obj_idx = buf.begin_container(
                &TLV_DESCRIPTORS[FD_TLV_TYPE],
                FieldValue::Object(0..0),
                offset + cursor..offset + cursor + 1,
            );
            buf.push_field(
                &TLV_DESCRIPTORS[FD_TLV_TYPE],
                FieldValue::U8(0),
                offset + cursor..offset + cursor + 1,
            );
            buf.end_container(obj_idx);
            cursor += 1;
            continue;
        }

        // All other TLVs: need at least Type + Length (2 bytes)
        if cursor + 1 >= tlv_end {
            return Err(PacketError::Truncated {
                expected: cursor + 2,
                actual: tlv_end,
            });
        }

        let length = data[cursor + 1] as usize;
        let value_start = cursor + 2;
        let value_end = value_start + length;

        if value_end > tlv_end {
            return Err(PacketError::Truncated {
                expected: value_end,
                actual: tlv_end,
            });
        }

        let obj_idx = buf.begin_container(
            &TLV_DESCRIPTORS[FD_TLV_TYPE],
            FieldValue::Object(0..0),
            offset + cursor..offset + value_end,
        );
        buf.push_field(
            &TLV_DESCRIPTORS[FD_TLV_TYPE],
            FieldValue::U8(type_byte),
            offset + cursor..offset + cursor + 1,
        );
        buf.push_field(
            &TLV_DESCRIPTORS[FD_TLV_LENGTH],
            FieldValue::U8(data[cursor + 1]),
            offset + cursor + 1..offset + cursor + 2,
        );

        match type_byte {
            // RFC 8754, Section 2.1.1 — PadN TLV (Type 4)
            4 => {
                buf.push_field(
                    &TLV_DESCRIPTORS[FD_TLV_PADDING],
                    FieldValue::Bytes(&data[value_start..value_end]),
                    offset + value_start..offset + value_end,
                );
            }
            // RFC 8754, Section 2.1.2 — HMAC TLV (Type 5)
            5 if length >= HMAC_TLV_MIN_VALUE_LEN => {
                // D-flag (1 bit) + Reserved (15 bits) = 2 bytes
                let d_flag = (data[value_start] >> 7) & 1;
                // HMAC Key ID (4 bytes) at value_start+2
                let key_id = read_be_u32(data, value_start + 2)?;
                let hmac_start = value_start + 6;

                buf.push_field(
                    &TLV_DESCRIPTORS[FD_TLV_HMAC_D_FLAG],
                    FieldValue::U8(d_flag),
                    offset + value_start..offset + value_start + 2,
                );
                buf.push_field(
                    &TLV_DESCRIPTORS[FD_TLV_HMAC_KEY_ID],
                    FieldValue::U32(key_id),
                    offset + value_start + 2..offset + value_start + 6,
                );
                if hmac_start < value_end {
                    buf.push_field(
                        &TLV_DESCRIPTORS[FD_TLV_HMAC],
                        FieldValue::Bytes(&data[hmac_start..value_end]),
                        offset + hmac_start..offset + value_end,
                    );
                }
            }
            // Unknown TLV or undersized HMAC — store value as raw bytes
            _ => {
                buf.push_field(
                    &TLV_DESCRIPTORS[FD_TLV_VALUE],
                    FieldValue::Bytes(&data[value_start..value_end]),
                    offset + value_start..offset + value_end,
                );
            }
        }

        buf.end_container(obj_idx);
        cursor = value_end;
    }

    Ok(())
}

/// Maximum byte length for extracted bit fields (128-bit SID = 16 bytes max).
const EXTRACT_BITS_MAX: usize = 16;

/// Extract a range of bits from a byte slice into a stack buffer.
///
/// Returns `(buffer, length)` where `buffer[..length]` contains the
/// right-aligned extracted bytes.
fn extract_bits(data: &[u8], bit_offset: u16, bit_len: u8) -> ([u8; EXTRACT_BITS_MAX], usize) {
    let mut result = [0u8; EXTRACT_BITS_MAX];
    if bit_len == 0 {
        return (result, 0);
    }
    let num_bytes = (bit_len as usize).div_ceil(8);
    for i in 0..bit_len as u16 {
        let src_bit = bit_offset + i;
        let src_byte = (src_bit / 8) as usize;
        let src_bit_pos = 7 - (src_bit % 8);
        if src_byte < data.len() {
            let bit_val = (data[src_byte] >> src_bit_pos) & 1;
            let dst_bit = (bit_len as u16 - 1) - i;
            let dst_byte = (dst_bit / 8) as usize;
            let dst_bit_pos = dst_bit % 8;
            result[num_bytes - 1 - dst_byte] |= bit_val << dst_bit_pos;
        }
    }
    (result, num_bytes)
}

/// Extracted SID parts as stack-allocated buffers.
struct SidParts {
    lb: ([u8; EXTRACT_BITS_MAX], usize),
    ln: ([u8; EXTRACT_BITS_MAX], usize),
    func: ([u8; EXTRACT_BITS_MAX], usize),
    arg: ([u8; EXTRACT_BITS_MAX], usize),
}

/// Extract SID parts from a 128-bit SID.
///
/// Returns `(locator_block, locator_node, function, argument)` as stack buffers,
/// each right-aligned to the nearest byte boundary.
fn extract_sid_parts(sid: &[u8], ss: &SidStructure) -> SidParts {
    let mut bit_offset: u16 = 0;
    let lb = extract_bits(sid, bit_offset, ss.locator_block_bits);
    bit_offset += ss.locator_block_bits as u16;
    let ln = extract_bits(sid, bit_offset, ss.locator_node_bits);
    bit_offset += ss.locator_node_bits as u16;
    let func = extract_bits(sid, bit_offset, ss.function_bits);
    bit_offset += ss.function_bits as u16;
    let arg = extract_bits(sid, bit_offset, ss.argument_bits);
    SidParts { lb, ln, func, arg }
}

/// Decompose segment list entries into CSID containers.
///
/// Each 128-bit entry is split into `k` slots of `slot_bits` starting at
/// `start_bit`. Each slot is extracted as `csid_bits` (which equals the
/// effective CSID width).
///
#[allow(clippy::too_many_arguments)]
fn decompose_csid_containers<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    data: &'pkt [u8],
    offset: usize,
    num_segments: usize,
    total_len: usize,
    k: usize,
    start_bit: usize,
    slot_bits: usize,
    csid_bits: u8,
) {
    for i in 0..num_segments {
        let seg_start = SRH_FIXED_SIZE + i * SEGMENT_SIZE;
        let seg_end = seg_start + SEGMENT_SIZE;
        if seg_end > total_len {
            break;
        }
        let sid = &data[seg_start..seg_end];
        let seg_range = offset + seg_start..offset + seg_end;

        // Object: { container_index, csids[] }
        let obj_idx = buf.begin_container(
            &CSID_CONTAINER_DESCRIPTORS[FD_CONTAINER_INDEX],
            FieldValue::Object(0..0),
            seg_range.clone(),
        );
        buf.push_field(
            &CSID_CONTAINER_DESCRIPTORS[FD_CONTAINER_INDEX],
            FieldValue::U8(i as u8),
            seg_range.clone(),
        );
        // Array of CSIDs
        let arr_idx = buf.begin_container(
            &CSID_CONTAINER_DESCRIPTORS[FD_CSIDS],
            FieldValue::Array(0..0),
            seg_range.clone(),
        );
        for slot in 0..k {
            let bit_offset = (start_bit + slot * slot_bits) as u16;
            let (csid_buf, csid_len) = extract_bits(sid, bit_offset, csid_bits);
            let scratch_range = buf.push_scratch(&csid_buf[..csid_len]);
            buf.push_field(
                &CSID_CONTAINER_DESCRIPTORS[FD_CSIDS],
                FieldValue::Scratch(scratch_range),
                seg_range.clone(),
            );
        }
        buf.end_container(arr_idx);
        buf.end_container(obj_idx);
    }
}

/// Minimum bit width required for Args.Mob.Session (RFC 9433, Figure 8).
///
/// Layout: QFI (6) + R (1) + U (1) + PDU Session ID (32) = 40 bits.
const ARGS_MOB_SESSION_MIN_BITS: u8 = 40;

/// Parse Args.Mob.Session from a 128-bit SID at the given bit offset.
///
/// Pushes an Object container with QFI, R flag, U flag, and PDU Session ID
/// fields into `buf`, or does nothing if the available bits are insufficient.
///
/// Layout (40 bits):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   QFI     |R|U|                PDU Session ID                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |PDU Sess(cont')|
/// +-+-+-+-+-+-+-+-+
/// ```
// RFC 9433, Section 6.1 — https://www.rfc-editor.org/rfc/rfc9433#section-6.1
fn push_args_mob_session<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    sid: &[u8],
    bit_offset: u16,
    available_bits: u8,
    offset: usize,
    seg_range: std::ops::Range<usize>,
) {
    if available_bits < ARGS_MOB_SESSION_MIN_BITS {
        return;
    }

    // Extract all 40 bits at once to avoid 4 separate allocations.
    let (raw, _) = extract_bits(sid, bit_offset, ARGS_MOB_SESSION_MIN_BITS);
    // raw[0]: QFI(6) | R(1) | U(1),  raw[1..5]: PDU Session ID(32)
    let qfi = (raw[0] >> 2) & 0x3F;
    let r_flag = (raw[0] >> 1) & 1;
    let u_flag = raw[0] & 1;
    let pdu_session_id = read_be_u32(&raw, 1).unwrap_or_default();

    let abs_range = offset + seg_range.start..offset + seg_range.end;
    let obj_idx = buf.begin_container(
        &AMS_PARENT_DESCRIPTORS[FD_ARGS_MOB_SESSION],
        FieldValue::Object(0..0),
        abs_range.clone(),
    );
    buf.push_field(
        &AMS_DESCRIPTORS[FD_AMS_QFI],
        FieldValue::U8(qfi),
        abs_range.clone(),
    );
    buf.push_field(
        &AMS_DESCRIPTORS[FD_AMS_R_FLAG],
        FieldValue::U8(r_flag),
        abs_range.clone(),
    );
    buf.push_field(
        &AMS_DESCRIPTORS[FD_AMS_U_FLAG],
        FieldValue::U8(u_flag),
        abs_range.clone(),
    );
    buf.push_field(
        &AMS_DESCRIPTORS[FD_AMS_PDU_SESSION_ID],
        FieldValue::U32(pdu_session_id),
        abs_range,
    );
    buf.end_container(obj_idx);
}

/// Decompose mobile-specific fields from a 128-bit SID.
///
/// Pushes additional fields into the current Object container in `buf`
/// alongside the standard locator-block / locator-node / function /
/// argument fields.
// RFC 9433, Sections 6.5–6.8 — https://www.rfc-editor.org/rfc/rfc9433#section-6
fn push_mobile_sid<'pkt>(
    buf: &mut DissectBuffer<'pkt>,
    sid: &[u8],
    ss: &SidStructure,
    encoding: &MobileSidEncoding,
    offset: usize,
    seg_range: std::ops::Range<usize>,
) {
    let abs_range = offset + seg_range.start..offset + seg_range.end;
    let loc_func_bits =
        ss.locator_block_bits as u16 + ss.locator_node_bits as u16 + ss.function_bits as u16;

    /// Extract an embedded IPv4 field from a SID and push it into buf.
    ///
    /// Decodes as an IPv4 address only when the field is exactly 32 bits wide
    /// and byte-aligned; otherwise emits Scratch bytes to avoid misinterpretation.
    fn push_embedded_ipv4(
        buf: &mut DissectBuffer<'_>,
        sid: &[u8],
        bit_offset: u16,
        ipv4da_bits: u8,
        range: std::ops::Range<usize>,
    ) {
        let (raw, raw_len) = extract_bits(sid, bit_offset, ipv4da_bits);
        if ipv4da_bits == 32 && bit_offset % 8 == 0 {
            let mut addr = [0u8; 4];
            for (i, b) in raw[..raw_len].iter().take(4).enumerate() {
                addr[i] = *b;
            }
            buf.push_field(
                &MOBILE_DESCRIPTORS[FD_MOBILE_EMBEDDED_IPV4],
                FieldValue::Ipv4Addr(addr),
                range,
            );
        } else {
            let scratch_range = buf.push_scratch(&raw[..raw_len]);
            buf.push_field(
                &MOBILE_DESCRIPTORS[FD_MOBILE_EMBEDDED_IPV4],
                FieldValue::Scratch(scratch_range),
                range,
            );
        }
    }

    match encoding {
        MobileSidEncoding::EndMGtp4E {
            ipv4da_bits,
            args_mob_session_bits,
        } => {
            // RFC 9433, Figure 9 — End.M.GTP4.E SID:
            // LOC-FUNC | IPv4DA(a) | Args.Mob.Session(b) | 0-padded(c)
            if *ipv4da_bits > 0 {
                push_embedded_ipv4(buf, sid, loc_func_bits, *ipv4da_bits, abs_range.clone());
            }
            let ams_offset = loc_func_bits + *ipv4da_bits as u16;
            push_args_mob_session(
                buf,
                sid,
                ams_offset,
                *args_mob_session_bits,
                offset,
                seg_range,
            );
        }
        MobileSidEncoding::EndMGtp6E => {
            // RFC 9433, Section 6.5 — End.M.GTP6.E:
            // Args.Mob.Session is in the Argument portion
            let arg_offset = loc_func_bits;
            push_args_mob_session(buf, sid, arg_offset, ss.argument_bits, offset, seg_range);
        }
        MobileSidEncoding::HmGtp4D {
            prefix_bits,
            ipv4da_bits,
            args_mob_session_bits,
        } => {
            // RFC 9433, Figure 11 — H.M.GTP4.D SID:
            // Destination UPF Prefix | IPv4DA(a) | Args.Mob.Session(b) | 0-padded(c)
            let ipv4_start = *prefix_bits as u16;
            if *ipv4da_bits > 0 {
                push_embedded_ipv4(buf, sid, ipv4_start, *ipv4da_bits, abs_range.clone());
            }
            let ams_offset = ipv4_start + *ipv4da_bits as u16;
            push_args_mob_session(
                buf,
                sid,
                ams_offset,
                *args_mob_session_bits,
                offset,
                seg_range,
            );
        }
        MobileSidEncoding::EndLimit {
            group_id_bits,
            limit_rate_bits,
        } => {
            // RFC 9433, Figure 12 — End.Limit:
            // LOC+FUNC(rate-limit) | group-id(i) | limit-rate(j)
            if *group_id_bits > 0 {
                let (gid_buf, gid_len) = extract_bits(sid, loc_func_bits, *group_id_bits);
                let scratch_range = buf.push_scratch(&gid_buf[..gid_len]);
                buf.push_field(
                    &MOBILE_DESCRIPTORS[FD_MOBILE_GROUP_ID],
                    FieldValue::Scratch(scratch_range),
                    abs_range.clone(),
                );
            }
            if *limit_rate_bits > 0 {
                let lr_offset = loc_func_bits + *group_id_bits as u16;
                let (lr_buf, lr_len) = extract_bits(sid, lr_offset, *limit_rate_bits);
                let scratch_range = buf.push_scratch(&lr_buf[..lr_len]);
                buf.push_field(
                    &MOBILE_DESCRIPTORS[FD_MOBILE_LIMIT_RATE],
                    FieldValue::Scratch(scratch_range),
                    abs_range,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level field descriptor indices
// ---------------------------------------------------------------------------

const FD_NEXT_HEADER: usize = 0;
const FD_HDR_EXT_LEN: usize = 1;
const FD_ROUTING_TYPE: usize = 2;
const FD_SEGMENTS_LEFT: usize = 3;
const FD_LAST_ENTRY: usize = 4;
const FD_FLAGS: usize = 5;
const FD_TAG: usize = 6;
const FD_SEGMENTS: usize = 7;
const FD_SEGMENTS_STRUCTURE: usize = 8;
const FD_CSID_CONTAINERS: usize = 9;
const FD_TLVS: usize = 10;

/// Top-level field descriptors for the SRv6 dissector.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("next_header", "Next Header", FieldType::U8),
    FieldDescriptor::new("hdr_ext_len", "Header Extension Length", FieldType::U8),
    FieldDescriptor::new("routing_type", "Routing Type", FieldType::U8),
    FieldDescriptor::new("segments_left", "Segments Left", FieldType::U8),
    FieldDescriptor::new("last_entry", "Last Entry", FieldType::U8),
    FieldDescriptor::new("flags", "Flags", FieldType::Object),
    FieldDescriptor::new("tag", "Tag", FieldType::U16),
    FieldDescriptor::new("segments", "Segment List", FieldType::Array),
    FieldDescriptor::new("segments_structure", "Segment Structure", FieldType::Array).optional(),
    FieldDescriptor::new("csid_containers", "CSID Containers", FieldType::Array).optional(),
    FieldDescriptor::new("tlvs", "TLVs", FieldType::Array).optional(),
];

// ---------------------------------------------------------------------------
// Child field descriptor arrays for sub-fields
// ---------------------------------------------------------------------------

// TLV sub-field descriptors (used in parse_tlvs)
const FD_TLV_TYPE: usize = 0;
const FD_TLV_LENGTH: usize = 1;
const FD_TLV_PADDING: usize = 2;
const FD_TLV_HMAC_D_FLAG: usize = 3;
const FD_TLV_HMAC_KEY_ID: usize = 4;
const FD_TLV_HMAC: usize = 5;
const FD_TLV_VALUE: usize = 6;

static TLV_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("type", "Type", FieldType::U8),
    FieldDescriptor::new("length", "Length", FieldType::U8),
    FieldDescriptor::new("padding", "Padding", FieldType::Bytes).optional(),
    FieldDescriptor::new("hmac_d_flag", "D Flag", FieldType::U8).optional(),
    FieldDescriptor::new("hmac_key_id", "HMAC Key ID", FieldType::U32).optional(),
    FieldDescriptor::new("hmac", "HMAC", FieldType::Bytes).optional(),
    FieldDescriptor::new("value", "Value", FieldType::Bytes).optional(),
];

// CSID container sub-field descriptors
const FD_CONTAINER_INDEX: usize = 0;
const FD_CSIDS: usize = 1;

static CSID_CONTAINER_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("container_index", "Container Index", FieldType::U8),
    FieldDescriptor::new("csids", "CSIDs", FieldType::Array),
];

// Args.Mob.Session sub-field descriptors
const FD_AMS_QFI: usize = 0;
const FD_AMS_R_FLAG: usize = 1;
const FD_AMS_U_FLAG: usize = 2;
const FD_AMS_PDU_SESSION_ID: usize = 3;

static AMS_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("qfi", "QFI", FieldType::U8),
    FieldDescriptor::new("r_flag", "R Flag", FieldType::U8),
    FieldDescriptor::new("u_flag", "U Flag", FieldType::U8),
    FieldDescriptor::new("pdu_session_id", "PDU Session ID", FieldType::U32),
];

// Parent descriptor for the args_mob_session Object field
const FD_ARGS_MOB_SESSION: usize = 0;

static AMS_PARENT_DESCRIPTORS: &[FieldDescriptor] =
    &[
        FieldDescriptor::new("args_mob_session", "Args.Mob.Session", FieldType::Object)
            .optional()
            .with_children(AMS_DESCRIPTORS),
    ];

// Mobile SID sub-field descriptors (embedded_ipv4, group_id, limit_rate)
const FD_MOBILE_EMBEDDED_IPV4: usize = 0;
const FD_MOBILE_GROUP_ID: usize = 1;
const FD_MOBILE_LIMIT_RATE: usize = 2;

static MOBILE_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("embedded_ipv4", "Embedded IPv4", FieldType::Ipv4Addr).optional(),
    FieldDescriptor::new("group_id", "Group ID", FieldType::Bytes).optional(),
    FieldDescriptor::new("limit_rate", "Limit Rate", FieldType::Bytes).optional(),
];

/// Writes a SID structure sub-field as a JSON-quoted hex string (e.g., `"20010db8"`).
///
/// Handles both [`FieldValue::Scratch`] (bit-extracted sub-byte data stored in the
/// scratch buffer) and [`FieldValue::Bytes`] (byte-aligned data).
fn format_sid_hex(
    value: &FieldValue<'_>,
    ctx: &FormatContext<'_>,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let bytes: &[u8] = match value {
        FieldValue::Scratch(range) => &ctx.scratch[range.start as usize..range.end as usize],
        FieldValue::Bytes(b) => b,
        _ => return w.write_all(b"\"\""),
    };
    if bytes.is_empty() {
        return w.write_all(b"\"\"");
    }
    w.write_all(b"\"")?;
    for &b in bytes {
        write!(w, "{b:02x}")?;
    }
    w.write_all(b"\"")
}

// SID structure sub-field descriptors
const FD_SID_LOCATOR_BLOCK: usize = 0;
const FD_SID_LOCATOR_NODE: usize = 1;
const FD_SID_FUNCTION: usize = 2;
const FD_SID_ARGUMENT: usize = 3;

static SID_STRUCTURE_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("locator_block", "Locator Block", FieldType::Bytes)
        .with_format_fn(format_sid_hex),
    FieldDescriptor::new("locator_node", "Locator Node", FieldType::Bytes)
        .with_format_fn(format_sid_hex),
    FieldDescriptor::new("function", "Function", FieldType::Bytes).with_format_fn(format_sid_hex),
    FieldDescriptor::new("argument", "Argument", FieldType::Bytes).with_format_fn(format_sid_hex),
];

// Flags sub-field descriptors
const FD_FLAGS_RAW: usize = 0;
const FD_FLAGS_O_FLAG: usize = 1;

static FLAGS_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("raw", "Raw", FieldType::U8),
    FieldDescriptor::new("o_flag", "O Flag", FieldType::U8),
];

impl Dissector for Srv6Dissector {
    fn name(&self) -> &'static str {
        "IPv6 Segment Routing Header"
    }

    fn short_name(&self) -> &'static str {
        "SRv6"
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
        if data.len() < SRH_FIXED_SIZE {
            return Err(PacketError::Truncated {
                expected: SRH_FIXED_SIZE,
                actual: data.len(),
            });
        }

        // RFC 8754, Section 2 — SRH fixed fields
        let next_header = data[0];
        let hdr_ext_len = data[1];
        let routing_type = data[2];
        let segments_left = data[3];
        let last_entry = data[4];
        let flags = data[5];
        let tag = read_be_u16(data, 6)?;

        // RFC 8200, Section 4.4 — total length = (Hdr Ext Len + 1) * 8
        let total_len = (hdr_ext_len as usize + 1) * 8;

        if data.len() < total_len {
            return Err(PacketError::Truncated {
                expected: total_len,
                actual: data.len(),
            });
        }

        // RFC 8754, Section 4.3.1.1 — validation
        // max_last_entry = (Hdr Ext Len / 2) - 1
        // Equivalently: Last Entry must be strictly less than (Hdr Ext Len / 2).
        // When Hdr Ext Len < 2, (Hdr Ext Len / 2) = 0, so all Last Entry values
        // are invalid (the RFC formula would give −1 in signed arithmetic).
        let max_segs = hdr_ext_len as usize / 2;
        if last_entry as usize >= max_segs {
            return Err(PacketError::InvalidHeader(
                "SRH Last Entry exceeds maximum for Hdr Ext Len",
            ));
        }

        if segments_left as usize > last_entry as usize + 1 {
            return Err(PacketError::InvalidHeader(
                "SRH Segments Left exceeds Last Entry + 1",
            ));
        }

        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..offset + total_len,
        );

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_NEXT_HEADER],
            FieldValue::U8(next_header),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_HDR_EXT_LEN],
            FieldValue::U8(hdr_ext_len),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_ROUTING_TYPE],
            FieldValue::U8(routing_type),
            offset + 2..offset + 3,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_SEGMENTS_LEFT],
            FieldValue::U8(segments_left),
            offset + 3..offset + 4,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_LAST_ENTRY],
            FieldValue::U8(last_entry),
            offset + 4..offset + 5,
        );

        // RFC 8754, Section 2 — Flags (8 bits)
        // RFC 9259, Section 3 — O-flag (OAM) at bit 2
        let flags_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_FLAGS],
            FieldValue::Object(0..0),
            offset + 5..offset + 6,
        );
        buf.push_field(
            &FLAGS_DESCRIPTORS[FD_FLAGS_RAW],
            FieldValue::U8(flags),
            offset + 5..offset + 6,
        );
        buf.push_field(
            &FLAGS_DESCRIPTORS[FD_FLAGS_O_FLAG],
            FieldValue::U8((flags >> 5) & 1),
            offset + 5..offset + 6,
        );
        buf.end_container(flags_idx);

        buf.push_field(
            &FIELD_DESCRIPTORS[FD_TAG],
            FieldValue::U16(tag),
            offset + 6..offset + 8,
        );

        // RFC 8754, Section 2 — Segment List
        // Encoded starting from the last segment of the SR Policy.
        // Segment List[0] is the last segment; Segment List[n] is the first.
        let num_segments = last_entry as usize + 1;
        let mut actual_segments = 0usize;
        let seg_arr_idx = buf.begin_container(
            &FIELD_DESCRIPTORS[FD_SEGMENTS],
            FieldValue::Array(0..0),
            offset + SRH_FIXED_SIZE..offset + SRH_FIXED_SIZE + num_segments * SEGMENT_SIZE,
        );
        for i in 0..num_segments {
            let seg_start = SRH_FIXED_SIZE + i * SEGMENT_SIZE;
            let seg_end = seg_start + SEGMENT_SIZE;
            if seg_end > total_len {
                break;
            }
            let addr = read_ipv6_addr(data, seg_start)?;
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_SEGMENTS],
                FieldValue::Ipv6Addr(addr),
                offset + seg_start..offset + seg_end,
            );
            actual_segments += 1;
        }
        buf.end_container(seg_arr_idx);

        let seg_range_end = SRH_FIXED_SIZE + actual_segments * SEGMENT_SIZE;

        // RFC 8986, Section 3.1 — SID structure decomposition (optional)
        if let Some(ref ss) = self.sid_structure {
            let struct_arr_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_SEGMENTS_STRUCTURE],
                FieldValue::Array(0..0),
                offset + SRH_FIXED_SIZE..offset + seg_range_end,
            );
            for i in 0..num_segments {
                let seg_start = SRH_FIXED_SIZE + i * SEGMENT_SIZE;
                let seg_end = seg_start + SEGMENT_SIZE;
                if seg_end > total_len {
                    break;
                }
                let sid = &data[seg_start..seg_end];
                let parts = extract_sid_parts(sid, ss);
                let seg_range = offset + seg_start..offset + seg_end;

                let obj_idx = buf.begin_container(
                    &SID_STRUCTURE_DESCRIPTORS[FD_SID_LOCATOR_BLOCK],
                    FieldValue::Object(0..0),
                    seg_range.clone(),
                );

                let lb_scratch = buf.push_scratch(&parts.lb.0[..parts.lb.1]);
                buf.push_field(
                    &SID_STRUCTURE_DESCRIPTORS[FD_SID_LOCATOR_BLOCK],
                    FieldValue::Scratch(lb_scratch),
                    seg_range.clone(),
                );
                let ln_scratch = buf.push_scratch(&parts.ln.0[..parts.ln.1]);
                buf.push_field(
                    &SID_STRUCTURE_DESCRIPTORS[FD_SID_LOCATOR_NODE],
                    FieldValue::Scratch(ln_scratch),
                    seg_range.clone(),
                );
                let func_scratch = buf.push_scratch(&parts.func.0[..parts.func.1]);
                buf.push_field(
                    &SID_STRUCTURE_DESCRIPTORS[FD_SID_FUNCTION],
                    FieldValue::Scratch(func_scratch),
                    seg_range.clone(),
                );
                let arg_scratch = buf.push_scratch(&parts.arg.0[..parts.arg.1]);
                buf.push_field(
                    &SID_STRUCTURE_DESCRIPTORS[FD_SID_ARGUMENT],
                    FieldValue::Scratch(arg_scratch),
                    seg_range.clone(),
                );

                // RFC 9433 — Mobile SID encoding decomposition
                if let Some(ref enc) = ss.mobile_encoding {
                    push_mobile_sid(buf, sid, ss, enc, offset, seg_start..seg_end);
                }

                buf.end_container(obj_idx);
            }
            buf.end_container(struct_arr_idx);

            // RFC 9800 — CSID container decomposition
            let lnfl = ss.locator_node_bits as usize + ss.function_bits as usize;
            // `lnfl > 0` guards every division below; the lint's `checked_div`
            // suggestion would only obscure the shared precondition.
            #[allow(clippy::manual_checked_ops)]
            if lnfl > 0 {
                match &ss.csid_flavor {
                    CsidFlavor::ReplaceCsid { csid_bits } if *csid_bits > 0 => {
                        // REPLACE-CSID (Section 4): K = 128 / LNFL slots per entry
                        let k = 128 / lnfl;
                        let csid_arr_idx = buf.begin_container(
                            &FIELD_DESCRIPTORS[FD_CSID_CONTAINERS],
                            FieldValue::Array(0..0),
                            offset + SRH_FIXED_SIZE..offset + seg_range_end,
                        );
                        decompose_csid_containers(
                            buf,
                            data,
                            offset,
                            num_segments,
                            total_len,
                            k,
                            0, // slots start at bit 0
                            lnfl,
                            *csid_bits,
                        );
                        buf.end_container(csid_arr_idx);
                    }
                    CsidFlavor::NextCsid { usid_bits } if *usid_bits > 0 => {
                        // NEXT-CSID / uSID (Section 3):
                        // Locator-Block occupies first LBL bits; remaining
                        // (128 - LBL) bits hold K = (128 - LBL) / LNFL uSIDs.
                        let lbl = ss.locator_block_bits as usize;
                        if lbl < 128 {
                            let k = (128 - lbl) / lnfl;
                            let csid_arr_idx = buf.begin_container(
                                &FIELD_DESCRIPTORS[FD_CSID_CONTAINERS],
                                FieldValue::Array(0..0),
                                offset + SRH_FIXED_SIZE..offset + seg_range_end,
                            );
                            decompose_csid_containers(
                                buf,
                                data,
                                offset,
                                num_segments,
                                total_len,
                                k,
                                lbl, // slots start after Locator-Block
                                lnfl,
                                *usid_bits,
                            );
                            buf.end_container(csid_arr_idx);
                        }
                    }
                    _ => {}
                }
            }
        }

        // RFC 8754, Section 2.1 — Optional TLVs after the Segment List
        let tlv_start = SRH_FIXED_SIZE + num_segments * SEGMENT_SIZE;
        if tlv_start < total_len {
            let tlv_arr_idx = buf.begin_container(
                &FIELD_DESCRIPTORS[FD_TLVS],
                FieldValue::Array(0..0),
                offset + tlv_start..offset + total_len,
            );
            parse_tlvs(buf, data, offset, tlv_start, total_len)?;
            buf.end_container(tlv_arr_idx);
        }

        buf.end_layer();

        Ok(DissectResult::new(
            total_len,
            DispatchHint::ByIpProtocol(next_header),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::{Field, FormatContext};
    use packet_dissector_core::packet::Layer;

    /// Look up a nested field within an Object/Array container by name.
    fn nested_field_by_name<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        parent: &Field<'pkt>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        let range = parent.value.as_container_range()?;
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    /// Resolve a Scratch field value into its byte slice for comparison.
    fn resolve_scratch<'a>(buf: &'a DissectBuffer<'_>, field: &Field<'_>) -> &'a [u8] {
        let range = field
            .value
            .as_scratch_range()
            .expect("expected Scratch value");
        &buf.scratch()[range.start as usize..range.end as usize]
    }

    /// Collect top-level entries from an Array's nested fields (skipping sub-children of containers).
    fn array_entries<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        array_field: &Field<'pkt>,
    ) -> Vec<&'a Field<'pkt>> {
        let range = array_field.value.as_container_range().unwrap();
        let all = buf.nested_fields(range);
        let base = range.start;
        let mut result = Vec::new();
        let mut abs_idx = base;
        while abs_idx < range.end {
            let rel = (abs_idx - base) as usize;
            let field = &all[rel];
            result.push(field);
            // If this field is a container, skip its children
            if let Some(child_range) = field.value.as_container_range() {
                // Jump past this field + all its children
                abs_idx = child_range.end;
            } else {
                abs_idx += 1;
            }
        }
        result
    }

    // # RFC 8754 (SRv6 SRH) Coverage
    //
    // | RFC Section  | Description              | Test                                  |
    // |--------------|--------------------------|---------------------------------------|
    // | 2            | SRH format               | parse_srv6_single_segment             |
    // | 2            | SRH format               | parse_srv6_multiple_segments          |
    // | 2            | Metadata                 | srv6_dissector_metadata               |
    // | 2            | Segment List layout      | parse_srv6_multiple_segments          |
    // | 2            | Flags/Tag                | parse_srv6_flags_and_tag              |
    // | 2            | Optional TLVs            | parse_srv6_with_tlvs                  |
    // | 2            | Offset handling          | parse_srv6_with_offset                |
    // | 2.1          | Pad1 TLV                 | parse_srv6_tlv_pad1                   |
    // | 2.1          | PadN TLV                 | parse_srv6_tlv_padn                   |
    // | 2.1          | HMAC TLV                 | parse_srv6_tlv_hmac                   |
    // | 2.1          | HMAC D-flag              | parse_srv6_tlv_hmac_d_flag_clear      |
    // | 2.1          | Unknown TLV              | parse_srv6_tlv_unknown                |
    // | 2.1          | Multiple TLVs            | parse_srv6_tlv_multiple               |
    // | 2.1          | Truncated TLV header     | parse_srv6_tlv_truncated_length       |
    // | 2.1          | Truncated TLV value      | parse_srv6_tlv_truncated_value        |
    // | 2.1          | Undersized HMAC TLV      | parse_srv6_tlv_hmac_truncated         |
    // | 4.3.1.1      | Last Entry validation    | parse_srv6_invalid_last_entry         |
    // | 4.3.1.1      | Hdr Ext Len too small    | parse_srv6_invalid_hdr_ext_len_small  |
    // | 4.3.1.1      | Segments Left validation | parse_srv6_invalid_segments_left      |
    // | —            | Truncated fixed header   | parse_srv6_truncated_header           |
    // | —            | Truncated total length   | parse_srv6_truncated_total            |
    // | —            | Next header chaining     | parse_srv6_next_header_tcp            |
    //
    // # RFC 9259 (SRv6 OAM) Coverage
    //
    // | RFC Section  | Description              | Test                                  |
    // |--------------|--------------------------|---------------------------------------|
    // | 3            | O-flag definition        | parse_srv6_flags_o_flag_set           |
    // | 3            | O-flag clear             | parse_srv6_flags_all_zero             |
    // | 3            | O-flag with other bits   | parse_srv6_flags_and_tag              |

    const SID_A: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    const SID_B: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    const SID_C: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03,
    ];

    /// Build an SRH with given parameters.
    fn build_srh(
        next_header: u8,
        segments_left: u8,
        segments: &[[u8; 16]],
        flags: u8,
        tag: u16,
        tlvs: &[u8],
    ) -> Vec<u8> {
        let num_segments = segments.len();
        // Pad TLVs to 8-byte alignment
        let seg_bytes = num_segments * SEGMENT_SIZE;
        let tlv_padded_len = if tlvs.is_empty() {
            0
        } else {
            // Total length must be multiple of 8
            let raw_total = SRH_FIXED_SIZE + seg_bytes + tlvs.len();
            let padded_total = (raw_total + 7) & !7;
            padded_total - SRH_FIXED_SIZE - seg_bytes
        };
        let total_len = SRH_FIXED_SIZE + seg_bytes + tlv_padded_len;
        let hdr_ext_len = (total_len / 8) - 1;
        let last_entry = if num_segments == 0 {
            0
        } else {
            (num_segments - 1) as u8
        };

        let mut data = Vec::with_capacity(total_len);
        data.push(next_header);
        data.push(hdr_ext_len as u8);
        data.push(4); // Routing Type = 4
        data.push(segments_left);
        data.push(last_entry);
        data.push(flags);
        data.extend_from_slice(&tag.to_be_bytes());

        for seg in segments {
            data.extend_from_slice(seg);
        }

        if !tlvs.is_empty() {
            data.extend_from_slice(tlvs);
            // Pad to total_len
            data.resize(total_len, 0);
        }

        data
    }

    #[test]
    fn srv6_dissector_metadata() {
        let d = Srv6Dissector::new();
        assert_eq!(d.name(), "IPv6 Segment Routing Header");
        assert_eq!(d.short_name(), "SRv6");
    }

    #[test]
    fn parse_srv6_single_segment() {
        // 1 segment: hdr_ext_len = 2, total = 24 bytes
        let data = build_srh(6, 1, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        let result = Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 24);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "SRv6");
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().value,
            FieldValue::U8(6)
        );
        assert_eq!(
            buf.field_by_name(layer, "hdr_ext_len").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "routing_type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            buf.field_by_name(layer, "segments_left").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "last_entry").unwrap().value,
            FieldValue::U8(0)
        );
        let segments = {
            let r = buf
                .field_by_name(layer, "segments")
                .unwrap()
                .value
                .as_container_range()
                .unwrap();
            buf.nested_fields(r)
        };
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].value, FieldValue::Ipv6Addr(SID_A));
        assert!(buf.field_by_name(layer, "tlvs").is_none());
    }

    #[test]
    fn parse_srv6_multiple_segments() {
        // 3 segments: hdr_ext_len = 6, total = 56 bytes
        let data = build_srh(17, 2, &[SID_A, SID_B, SID_C], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        let result = Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 56);
        assert_eq!(result.next, DispatchHint::ByIpProtocol(17));

        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "last_entry").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            buf.field_by_name(layer, "segments_left").unwrap().value,
            FieldValue::U8(2)
        );
        let segments = {
            let r = buf
                .field_by_name(layer, "segments")
                .unwrap()
                .value
                .as_container_range()
                .unwrap();
            buf.nested_fields(r)
        };
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].value, FieldValue::Ipv6Addr(SID_A));
        assert_eq!(segments[1].value, FieldValue::Ipv6Addr(SID_B));
        assert_eq!(segments[2].value, FieldValue::Ipv6Addr(SID_C));
    }

    /// Look up a sub-field within a flags Object value.
    fn flags_sub_field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &Layer,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        let flags_field = buf.field_by_name(layer, "flags")?;
        let range = flags_field.value.as_container_range()?;
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    #[test]
    fn parse_srv6_flags_and_tag() {
        // 0xAB = 0b1010_1011: bit0=1, bit1=0, bit2(O-flag)=1, bit3=0, bit4=1, bit5=0, bit6=1, bit7=1
        let data = build_srh(59, 0, &[SID_A], 0xAB, 0x1234, &[]);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        // Raw value preserved
        assert_eq!(
            flags_sub_field(&buf, layer, "raw").unwrap().value,
            FieldValue::U8(0xAB)
        );
        // RFC 9259 — O-flag is bit 2 (0x20): (0xAB >> 5) & 1 = 1
        assert_eq!(
            flags_sub_field(&buf, layer, "o_flag").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "tag").unwrap().value,
            FieldValue::U16(0x1234)
        );
    }

    #[test]
    fn parse_srv6_flags_o_flag_set() {
        // Only O-flag set: 0x20 = 0b0010_0000
        let data = build_srh(6, 1, &[SID_A], 0x20, 0, &[]);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            flags_sub_field(&buf, layer, "raw").unwrap().value,
            FieldValue::U8(0x20)
        );
        assert_eq!(
            flags_sub_field(&buf, layer, "o_flag").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_srv6_flags_all_zero() {
        let data = build_srh(6, 1, &[SID_A], 0x00, 0, &[]);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert_eq!(
            flags_sub_field(&buf, layer, "raw").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            flags_sub_field(&buf, layer, "o_flag").unwrap().value,
            FieldValue::U8(0)
        );
    }

    #[test]
    fn parse_srv6_with_tlvs() {
        // PadN TLV (type=4, len=2, data=0x00 0x00) = 4 bytes
        // After 1 segment (24 bytes header+seg), need to pad to 32 bytes
        // So TLV area = 8 bytes, hdr_ext_len = 3
        let tlvs = [4, 2, 0x00, 0x00]; // PadN
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        let result = Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, 32);

        let layer = &buf.layers()[0];
        // TLV[0]: PadN (type=4, length=2)
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        let tlv0 = tlvs[0];
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "length").unwrap().value,
            FieldValue::U8(2)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0])
        );
    }

    #[test]
    fn parse_srv6_with_offset() {
        let data = build_srh(6, 1, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        let result = Srv6Dissector::new().dissect(&data, &mut buf, 200).unwrap();

        assert_eq!(result.bytes_consumed, 24);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 200..224);
        assert_eq!(
            buf.field_by_name(layer, "next_header").unwrap().range,
            200..201
        );
        let segments = {
            let r = buf
                .field_by_name(layer, "segments")
                .unwrap()
                .value
                .as_container_range()
                .unwrap();
            buf.nested_fields(r)
        };
        assert_eq!(segments[0].range, 208..224);
    }

    #[test]
    fn parse_srv6_truncated_header() {
        let data = [6, 2, 4, 1, 0, 0]; // only 6 bytes, need 8
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 8,
                actual: 6
            }
        ));
    }

    #[test]
    fn parse_srv6_truncated_total() {
        // hdr_ext_len=2 means total=24, but only provide 16 bytes
        let mut data = vec![6, 2, 4, 1, 0, 0, 0, 0]; // 8 bytes fixed header
        data.extend_from_slice(&[0u8; 8]); // only 8 more (total 16), need 24
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 24,
                actual: 16
            }
        ));
    }

    #[test]
    fn parse_srv6_invalid_last_entry() {
        // hdr_ext_len=2 → max_last_entry = (2/2)-1 = 0
        // Set last_entry=1 → invalid
        let mut data = vec![0u8; 24];
        data[0] = 6; // next_header
        data[1] = 2; // hdr_ext_len
        data[2] = 4; // routing_type
        data[3] = 0; // segments_left
        data[4] = 1; // last_entry = 1 (invalid, max is 0)
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_srv6_invalid_hdr_ext_len_small() {
        // RFC 8754, Section 4.3.1.1: max_last_entry = (Hdr Ext Len / 2) - 1.
        // For Hdr Ext Len = 0, max_last_entry = -1 in signed arithmetic,
        // meaning all Last Entry values are invalid (Last Entry 0 > -1).
        // Verify that any last_entry value is rejected when hdr_ext_len = 0.
        let mut data = vec![0u8; 8];
        data[0] = 6; // next_header
        data[1] = 0; // hdr_ext_len = 0 → max_segs = 0 → all last_entry invalid
        data[2] = 4; // routing_type
        data[3] = 0; // segments_left
        data[4] = 0; // last_entry = 0 (invalid: 0 >= max_segs 0)
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));

        // Same for hdr_ext_len = 1 (total = 16 bytes, still no room for a segment)
        let mut data2 = vec![0u8; 16];
        data2[0] = 6;
        data2[1] = 1; // hdr_ext_len = 1 → max_segs = 0 → all last_entry invalid
        data2[2] = 4;
        data2[3] = 0;
        data2[4] = 0; // last_entry = 0 (invalid)
        let mut buf2 = DissectBuffer::new();
        let err2 = Srv6Dissector::new()
            .dissect(&data2, &mut buf2, 0)
            .unwrap_err();
        assert!(matches!(err2, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_srv6_invalid_segments_left() {
        // 1 segment (last_entry=0), but segments_left=2 → invalid
        let mut data = vec![0u8; 24];
        data[0] = 6;
        data[1] = 2;
        data[2] = 4;
        data[3] = 2; // segments_left = 2 (invalid, max is last_entry+1 = 1)
        data[4] = 0; // last_entry = 0
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(err, PacketError::InvalidHeader(_)));
    }

    #[test]
    fn parse_srv6_next_header_tcp() {
        // Verify chaining: next_header=6 (TCP) propagates
        let data = build_srh(6, 0, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        let result = Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::ByIpProtocol(6));
    }

    #[test]
    fn parse_srv6_next_header_no_next() {
        // next_header=59 (No Next Header)
        let data = build_srh(59, 0, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        let result = Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.next, DispatchHint::ByIpProtocol(59));
    }

    // --- TLV parsing tests (RFC 8754, Section 2.1) ---

    /// Look up a sub-field within a TLV entry's Object value.
    fn tlv_sub_field<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        tlv: &Field<'pkt>,
        name: &str,
    ) -> Option<&'a Field<'pkt>> {
        let range = tlv.value.as_container_range()?;
        buf.nested_fields(range).iter().find(|f| f.name() == name)
    }

    #[test]
    fn parse_srv6_tlv_pad1() {
        // Pad1 (type=0) is a single byte with no Length/Value.
        // We need 8 bytes of TLV area for alignment: Pad1 + PadN(5) to fill.
        // Pad1=0x00, PadN: type=4, len=5, 5 zero bytes => total 8 bytes TLV
        let tlvs = [0x00, 4, 5, 0, 0, 0, 0, 0];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        assert!(tlvs.len() >= 2);
        // First TLV: Pad1
        assert_eq!(
            tlv_sub_field(&buf, tlvs[0], "type").unwrap().value,
            FieldValue::U8(0)
        );
        // Pad1 has no length field
        assert!(tlv_sub_field(&buf, tlvs[0], "length").is_none());
        // Second TLV: PadN
        assert_eq!(
            tlv_sub_field(&buf, tlvs[1], "type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlvs[1], "length").unwrap().value,
            FieldValue::U8(5)
        );
    }

    #[test]
    fn parse_srv6_tlv_padn() {
        // PadN TLV: type=4, length=4, 4 zero bytes => 6 bytes
        // build_srh pads to 8-byte alignment, so TLV area = 8 bytes
        let tlvs = [4, 4, 0, 0, 0, 0];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        let tlv0 = tlvs[0];
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "length").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "padding").unwrap().value,
            FieldValue::Bytes(&[0, 0, 0, 0])
        );
    }

    #[test]
    fn parse_srv6_tlv_hmac() {
        // HMAC TLV: type=5, length=38 (2 D+Reserved + 4 KeyID + 32 HMAC)
        // D-flag=1 (MSB of first value byte), Reserved=0, Key ID=0x00000001
        // Total TLV = 1+1+38 = 40 bytes; after 1 segment (24 bytes), total = 64
        let mut tlv_bytes = vec![5u8, 38]; // type, length
        // D-flag(1) + Reserved(15 bits) = 0x8000
        tlv_bytes.extend_from_slice(&[0x80, 0x00]);
        // HMAC Key ID = 1
        tlv_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // 32-byte HMAC
        let hmac_value: Vec<u8> = (1..=32).collect();
        tlv_bytes.extend_from_slice(&hmac_value);

        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlv_bytes);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        let tlv0 = tlvs[0];
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "type").unwrap().value,
            FieldValue::U8(5)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "length").unwrap().value,
            FieldValue::U8(38)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "hmac_d_flag").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "hmac_key_id").unwrap().value,
            FieldValue::U32(1)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "hmac").unwrap().value,
            FieldValue::Bytes(&hmac_value)
        );
    }

    #[test]
    fn parse_srv6_tlv_hmac_d_flag_clear() {
        // Same as above but D-flag=0
        let mut tlv_bytes = vec![5u8, 38];
        // D-flag(0) + Reserved(15 bits) = 0x0000
        tlv_bytes.extend_from_slice(&[0x00, 0x00]);
        // HMAC Key ID = 0x12345678
        tlv_bytes.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        // 32-byte HMAC (all 0xFF)
        tlv_bytes.extend_from_slice(&[0xFF; 32]);

        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlv_bytes);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        let tlv0 = tlvs[0];
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "hmac_d_flag").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "hmac_key_id").unwrap().value,
            FieldValue::U32(0x12345678)
        );
    }

    #[test]
    fn parse_srv6_tlv_unknown() {
        // Unknown TLV type=99, length=3, value=[0xAA, 0xBB, 0xCC]
        // Total TLV = 1+1+3 = 5 bytes; padded to 8
        let tlvs = [99, 3, 0xAA, 0xBB, 0xCC];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        let tlv0 = tlvs[0];
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "type").unwrap().value,
            FieldValue::U8(99)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "length").unwrap().value,
            FieldValue::U8(3)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "value").unwrap().value,
            FieldValue::Bytes(&[0xAA, 0xBB, 0xCC])
        );
    }

    #[test]
    fn parse_srv6_tlv_multiple() {
        // Pad1(1 byte) + PadN(type=4, len=1, 1 zero byte = 3 bytes)
        // + Pad1(1 byte) + trailing zeros parsed as Pad1s
        // Total TLV area: 8 bytes
        let tlvs = [0x00, 4, 1, 0x00, 0x00];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        assert!(tlvs.len() >= 2);
        // TLV[0]: Pad1
        assert_eq!(
            tlv_sub_field(&buf, tlvs[0], "type").unwrap().value,
            FieldValue::U8(0)
        );
        // TLV[1]: PadN
        assert_eq!(
            tlv_sub_field(&buf, tlvs[1], "type").unwrap().value,
            FieldValue::U8(4)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlvs[1], "length").unwrap().value,
            FieldValue::U8(1)
        );
    }

    #[test]
    fn parse_srv6_tlv_truncated_length() {
        // TLV area has only 1 byte (non-Pad1 type with no length byte).
        // We need to build this manually: 1 segment + 1 byte TLV area.
        // hdr_ext_len must produce total_len that leaves exactly 1 TLV byte.
        // 1 segment = 24 bytes header+seg. We need total=32 (hdr_ext_len=3)
        // with TLV area = 8 bytes, but place a non-Pad1 type at the very end.
        // Build: 7 Pad1 bytes (0x00) + 1 non-Pad1 type byte (e.g., 99)
        let tlvs = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 99];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_srv6_tlv_truncated_value() {
        // TLV with type=99, length=20 but only 6 bytes remaining
        let tlvs = [99, 20, 0xAA, 0xBB, 0xCC, 0xDD];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        let err = Srv6Dissector::new()
            .dissect(&data, &mut buf, 0)
            .unwrap_err();
        assert!(matches!(err, PacketError::Truncated { .. }));
    }

    #[test]
    fn parse_srv6_tlv_hmac_truncated() {
        // HMAC TLV with length < 6 (minimum: 2 D+Reserved + 4 Key ID)
        // Falls back to raw bytes via unknown path (Postel's law)
        // type=5, length=4, value=4 bytes
        let tlvs = [5, 4, 0x80, 0x00, 0x00, 0x01];
        let data = build_srh(6, 1, &[SID_A], 0, 0, &tlvs);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let tlvs_field = buf.field_by_name(layer, "tlvs").unwrap();
        let tlvs = array_entries(&buf, tlvs_field);
        let tlv0 = tlvs[0];
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "type").unwrap().value,
            FieldValue::U8(5)
        );
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "length").unwrap().value,
            FieldValue::U8(4)
        );
        // Falls back to raw value since length < 6
        assert_eq!(
            tlv_sub_field(&buf, tlv0, "value").unwrap().value,
            FieldValue::Bytes(&[0x80, 0x00, 0x00, 0x01])
        );
        // HMAC-specific fields should not be present
        assert!(tlv_sub_field(&buf, tlv0, "hmac_d_flag").is_none());
    }

    // --- SID structure analysis tests (RFC 8986, Section 3.1) ---

    // # RFC 8986 (SRv6 Network Programming) Coverage
    //
    // | RFC Section  | Description              | Test                                  |
    // |--------------|--------------------------|---------------------------------------|
    // | 3.1          | SID structure            | parse_srv6_sid_structure_48_16_16_48   |
    // | 3.1          | No SID structure config  | parse_srv6_sid_structure_none          |
    //
    // # RFC 9800 (CSID/REPLACE-CSID) Coverage
    //
    // | RFC Section  | Description              | Test                                  |
    // |--------------|--------------------------|---------------------------------------|
    // | 3            | NEXT-CSID (uSID) decomp  | parse_srv6_usid_next_csid             |
    // | 4            | REPLACE-CSID decomp      | parse_srv6_csid_replace_csid          |
    // | —            | CSID disabled            | parse_srv6_csid_disabled              |

    #[test]
    fn parse_srv6_sid_structure_none() {
        // Without SidStructure config, no segments_structure field should appear
        let data = build_srh(6, 1, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        Srv6Dissector::new().dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "segments_structure").is_none());
    }

    #[test]
    fn parse_srv6_sid_structure_48_16_16_48() {
        // SID_A = 2001:0db8:0001:0000:0000:0000:0000:0001
        // With B=48, N=16, F=16, A=48:
        //   Locator-Block (48 bits) = 2001:0db8:0001 → [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]
        //   Locator-Node  (16 bits) = 0000 → [0x00, 0x00]
        //   Function      (16 bits) = 0000 → [0x00, 0x00]
        //   Argument      (48 bits) = 0000:0000:0001 → [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: None,
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        assert_eq!(structure.len(), 1);

        let seg0 = structure[0];
        assert_eq!(
            resolve_scratch(
                &buf,
                nested_field_by_name(&buf, seg0, "locator_block").unwrap()
            ),
            &[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]
        );
        assert_eq!(
            resolve_scratch(
                &buf,
                nested_field_by_name(&buf, seg0, "locator_node").unwrap()
            ),
            &[0x00, 0x00]
        );
        assert_eq!(
            resolve_scratch(&buf, nested_field_by_name(&buf, seg0, "function").unwrap()),
            &[0x00, 0x00]
        );
        assert_eq!(
            resolve_scratch(&buf, nested_field_by_name(&buf, seg0, "argument").unwrap()),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    // --- CSID tests (RFC 9800) ---

    #[test]
    fn parse_srv6_csid_disabled() {
        // csid_bits=0 means no CSID decomposition
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: None,
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        // segments_structure should exist (SID structure enabled)
        assert!(buf.field_by_name(layer, "segments_structure").is_some());
        // csid_containers should NOT exist
        assert!(buf.field_by_name(layer, "csid_containers").is_none());
    }

    #[test]
    fn parse_srv6_csid_replace_csid() {
        // REPLACE-CSID with B=32, N=16, F=16, A=64, CSID=32 (N+F=32)
        // K = 128 / 32 = 4 slots per container
        //
        // Container: 0xAAAA BBBB CCCC DDDD 0000 0000 0000 0000
        // (16 bytes: AA AA BB BB CC CC DD DD 00 00 00 00 00 00 00 00)
        // Slot layout (32 bits each):
        //   Slot 0 (bits 0..31)  = 0xAAAABBBB
        //   Slot 1 (bits 32..63) = 0xCCCCDDDD
        //   Slot 2 (bits 64..95) = 0x00000000
        //   Slot 3 (bits 96..127)= 0x00000000
        let container: [u8; 16] = [
            0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC, 0xDD, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let ss = SidStructure {
            locator_block_bits: 32,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 64,
            csid_flavor: CsidFlavor::ReplaceCsid { csid_bits: 32 },
            mobile_encoding: None,
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[container], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let containers_field = buf.field_by_name(layer, "csid_containers").unwrap();
        let containers = array_entries(&buf, containers_field);
        assert_eq!(containers.len(), 1);

        let c0 = containers[0];
        assert_eq!(
            nested_field_by_name(&buf, c0, "container_index")
                .unwrap()
                .value,
            FieldValue::U8(0)
        );
        let csids_field = nested_field_by_name(&buf, c0, "csids").unwrap();
        let csids = buf.nested_fields(csids_field.value.as_container_range().unwrap());
        assert_eq!(csids.len(), 4);
        // Slot 0: bits 0..31 = 0xAAAABBBB
        assert_eq!(resolve_scratch(&buf, &csids[0]), &[0xAA, 0xAA, 0xBB, 0xBB]);
        // Slot 1: bits 32..63 = 0xCCCCDDDD
        assert_eq!(resolve_scratch(&buf, &csids[1]), &[0xCC, 0xCC, 0xDD, 0xDD]);
        // Slot 2: bits 64..95 = 0x00000000
        assert_eq!(resolve_scratch(&buf, &csids[2]), &[0x00, 0x00, 0x00, 0x00]);
        // Slot 3: bits 96..127 = 0x00000000
        assert_eq!(resolve_scratch(&buf, &csids[3]), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn parse_srv6_usid_next_csid() {
        // NEXT-CSID (uSID) with LBL=32, N=16, F=16, A=64
        // LNFL = 16 + 16 = 32, K = (128 - 32) / 32 = 3 uSID slots
        //
        // Container: 0xAAAAAAAA BBBB1111 CCCC2222 DDDD3333
        // (Locator-Block: 0xAAAAAAAA = first 32 bits, not a uSID slot)
        // uSID slots (each 32 bits, starting after LBL at bit 32):
        //   Slot 0 (bits 32..63)  = 0xBBBB1111
        //   Slot 1 (bits 64..95)  = 0xCCCC2222
        //   Slot 2 (bits 96..127) = 0xDDDD3333
        let container: [u8; 16] = [
            0xAA, 0xAA, 0xAA, 0xAA, // Locator-Block
            0xBB, 0xBB, 0x11, 0x11, // uSID slot 0
            0xCC, 0xCC, 0x22, 0x22, // uSID slot 1
            0xDD, 0xDD, 0x33, 0x33, // uSID slot 2
        ];
        let ss = SidStructure {
            locator_block_bits: 32,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 64,
            csid_flavor: CsidFlavor::NextCsid { usid_bits: 32 },
            mobile_encoding: None,
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[container], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let containers_field = buf.field_by_name(layer, "csid_containers").unwrap();
        let containers = array_entries(&buf, containers_field);
        assert_eq!(containers.len(), 1);

        let c0 = containers[0];
        let csids_field = nested_field_by_name(&buf, c0, "csids").unwrap();
        let csids = buf.nested_fields(csids_field.value.as_container_range().unwrap());
        // 3 uSID slots (after Locator-Block)
        assert_eq!(csids.len(), 3);
        // Slot 0: bits 32..63 = 0xBBBB1111
        assert_eq!(resolve_scratch(&buf, &csids[0]), &[0xBB, 0xBB, 0x11, 0x11]);
        // Slot 1: bits 64..95 = 0xCCCC2222
        assert_eq!(resolve_scratch(&buf, &csids[1]), &[0xCC, 0xCC, 0x22, 0x22]);
        // Slot 2: bits 96..127 = 0xDDDD3333
        assert_eq!(resolve_scratch(&buf, &csids[2]), &[0xDD, 0xDD, 0x33, 0x33]);
    }

    // # RFC 9433 (SRv6 Mobile User Plane) Coverage
    //
    // | RFC Section  | Description                    | Test                                         |
    // |--------------|--------------------------------|----------------------------------------------|
    // | 6.1 Fig.8    | Args.Mob.Session basic         | parse_srv6_args_mob_session_basic             |
    // | 6.1 Fig.8    | Args.Mob.Session max QFI       | parse_srv6_args_mob_session_max_qfi           |
    // | 6.1 Fig.8    | Args.Mob.Session R flag set    | parse_srv6_args_mob_session_r_flag            |
    // | 6.1 Fig.8    | Args.Mob.Session too short     | parse_srv6_args_mob_session_too_short         |
    // | Fig.9        | End.M.GTP4.E SID encoding      | parse_srv6_mobile_end_m_gtp4_e                |
    // | 6.5          | End.M.GTP6.E SID encoding      | parse_srv6_mobile_end_m_gtp6_e                |
    // | Fig.11       | H.M.GTP4.D SID encoding        | parse_srv6_mobile_h_m_gtp4_d                  |
    // | Fig.12       | End.Limit SID encoding         | parse_srv6_mobile_end_limit                   |
    // | 11           | Endpoint behavior names        | endpoint_behavior_names                       |
    // | —            | No mobile encoding (regression)| parse_srv6_mobile_encoding_none                |

    #[test]
    fn endpoint_behavior_names() {
        assert_eq!(endpoint_behavior_name(BEHAVIOR_END_MAP), Some("End.MAP"));
        assert_eq!(
            endpoint_behavior_name(BEHAVIOR_END_LIMIT),
            Some("End.Limit")
        );
        assert_eq!(
            endpoint_behavior_name(BEHAVIOR_END_M_GTP6_D),
            Some("End.M.GTP6.D")
        );
        assert_eq!(
            endpoint_behavior_name(BEHAVIOR_END_M_GTP6_DI),
            Some("End.M.GTP6.Di")
        );
        assert_eq!(
            endpoint_behavior_name(BEHAVIOR_END_M_GTP6_E),
            Some("End.M.GTP6.E")
        );
        assert_eq!(
            endpoint_behavior_name(BEHAVIOR_END_M_GTP4_E),
            Some("End.M.GTP4.E")
        );
        assert_eq!(endpoint_behavior_name(0), None);
        assert_eq!(endpoint_behavior_name(9999), None);
    }

    #[test]
    fn parse_srv6_args_mob_session_basic() {
        // End.M.GTP6.E: LOC(48) + Node(16) + Func(16) + Arg(48)
        // Argument carries Args.Mob.Session (40 bits) + 8 bits padding.
        //
        // Args.Mob.Session: QFI=9 (0b001001), R=0, U=0, PDU Session ID=0x12345678
        // Binary: 001001_0_0 = 0x24  then 0x12 0x34 0x56 0x78  then 0x00 padding
        //
        // SID layout (16 bytes):
        //   Bytes 0-5:  LOC  = 2001:0db8:0001
        //   Bytes 6-7:  Node = 0002
        //   Bytes 8-9:  Func = 0047 (End.M.GTP6.E IANA value, but opaque here)
        //   Bytes 10-14: Arg  = 0x24 0x12 0x34 0x56 0x78  (Args.Mob.Session)
        //   Byte 15:     Arg  = 0x00 (padding)
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, // LOC (48 bits)
            0x00, 0x02, // Node (16 bits)
            0x00, 0x47, // Func (16 bits)
            0x24, 0x12, 0x34, 0x56, 0x78, // Args.Mob.Session (40 bits)
            0x00, // padding (8 bits)
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndMGtp6E),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        assert_eq!(structure.len(), 1);

        let seg0 = structure[0];
        // Verify standard fields exist
        assert!(nested_field_by_name(&buf, seg0, "locator_block").is_some());
        assert!(nested_field_by_name(&buf, seg0, "function").is_some());

        // Verify Args.Mob.Session
        let ams = nested_field_by_name(&buf, seg0, "args_mob_session").unwrap();
        let ams_obj = buf.nested_fields(ams.value.as_container_range().unwrap());
        let qfi = ams_obj.iter().find(|f| f.name() == "qfi").unwrap();
        assert_eq!(qfi.value, FieldValue::U8(9));
        let r_flag = ams_obj.iter().find(|f| f.name() == "r_flag").unwrap();
        assert_eq!(r_flag.value, FieldValue::U8(0));
        let u_flag = ams_obj.iter().find(|f| f.name() == "u_flag").unwrap();
        assert_eq!(u_flag.value, FieldValue::U8(0));
        let pdu_id = ams_obj
            .iter()
            .find(|f| f.name() == "pdu_session_id")
            .unwrap();
        assert_eq!(pdu_id.value, FieldValue::U32(0x12345678));
    }

    #[test]
    fn parse_srv6_args_mob_session_max_qfi() {
        // QFI max value = 63 (0b111111), R=0, U=0, PDU Session ID=0x00000001
        // Binary: 111111_0_0 = 0xFC  then 0x00 0x00 0x00 0x01
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, // LOC
            0x00, 0x02, // Node
            0x00, 0x47, // Func
            0xFC, 0x00, 0x00, 0x00, 0x01, // Args.Mob.Session
            0x00, // padding
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndMGtp6E),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];
        let ams = nested_field_by_name(&buf, seg0, "args_mob_session").unwrap();
        let ams_obj = buf.nested_fields(ams.value.as_container_range().unwrap());
        let qfi = ams_obj.iter().find(|f| f.name() == "qfi").unwrap();
        assert_eq!(qfi.value, FieldValue::U8(63));
    }

    #[test]
    fn parse_srv6_args_mob_session_r_flag() {
        // QFI=0, R=1, U=0, PDU Session ID=0xAABBCCDD
        // Binary: 000000_1_0 = 0x02  then 0xAA 0xBB 0xCC 0xDD
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, // LOC
            0x00, 0x02, // Node
            0x00, 0x47, // Func
            0x02, 0xAA, 0xBB, 0xCC, 0xDD, // Args.Mob.Session
            0x00, // padding
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndMGtp6E),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];
        let ams = nested_field_by_name(&buf, seg0, "args_mob_session").unwrap();
        let ams_obj = buf.nested_fields(ams.value.as_container_range().unwrap());
        let qfi = ams_obj.iter().find(|f| f.name() == "qfi").unwrap();
        assert_eq!(qfi.value, FieldValue::U8(0));
        let r_flag = ams_obj.iter().find(|f| f.name() == "r_flag").unwrap();
        assert_eq!(r_flag.value, FieldValue::U8(1));
        let u_flag = ams_obj.iter().find(|f| f.name() == "u_flag").unwrap();
        assert_eq!(u_flag.value, FieldValue::U8(0));
        let pdu_id = ams_obj
            .iter()
            .find(|f| f.name() == "pdu_session_id")
            .unwrap();
        assert_eq!(pdu_id.value, FieldValue::U32(0xAABBCCDD));
    }

    #[test]
    fn parse_srv6_args_mob_session_too_short() {
        // Argument is only 32 bits — too short for Args.Mob.Session (40 bits).
        // Mobile fields should be absent (graceful degradation per Postel's law).
        // LOC(48) + Node(16) + Func(32) + Arg(32) = 128
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, // LOC (48)
            0x00, 0x02, // Node (16)
            0x00, 0x47, 0x00, 0x01, // Func (32)
            0x24, 0x12, 0x34, 0x56, // Arg (32) — too short for AMS
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 32,
            argument_bits: 32,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndMGtp6E),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];
        // args_mob_session should NOT be present (too short)
        assert!(nested_field_by_name(&buf, seg0, "args_mob_session").is_none());
    }

    #[test]
    fn parse_srv6_mobile_end_m_gtp4_e() {
        // End.M.GTP4.E (RFC 9433, Figure 9):
        // LOC-FUNC(48) | IPv4DA(32) | Args.Mob.Session(40) | 0-padded(8)
        //
        // IPv4DA = 10.0.0.1 (0x0A000001)
        // Args.Mob.Session: QFI=5 (0b000101), R=0, U=0, PDU Session ID=0x00000042
        // AMS binary: 000101_0_0 = 0x14  then 0x00 0x00 0x00 0x42
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, // LOC-FUNC bytes 0-3
            0x00, 0x01, // LOC-FUNC bytes 4-5  (48 bits total)
            0x0A, 0x00, 0x00, 0x01, // IPv4DA = 10.0.0.1 (32 bits)
            0x14, 0x00, 0x00, 0x00, 0x42, // Args.Mob.Session (40 bits)
            0x00, // padding (8 bits)
        ];
        let ss = SidStructure {
            locator_block_bits: 32,
            locator_node_bits: 0,
            function_bits: 16,
            argument_bits: 80,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndMGtp4E {
                ipv4da_bits: 32,
                args_mob_session_bits: 40,
            }),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];

        // Verify embedded IPv4
        let ipv4 = nested_field_by_name(&buf, seg0, "embedded_ipv4").unwrap();
        assert_eq!(ipv4.value, FieldValue::Ipv4Addr([10, 0, 0, 1]));

        // Verify Args.Mob.Session
        let ams = nested_field_by_name(&buf, seg0, "args_mob_session").unwrap();
        let ams_obj = buf.nested_fields(ams.value.as_container_range().unwrap());
        let qfi = ams_obj.iter().find(|f| f.name() == "qfi").unwrap();
        assert_eq!(qfi.value, FieldValue::U8(5));
        let pdu_id = ams_obj
            .iter()
            .find(|f| f.name() == "pdu_session_id")
            .unwrap();
        assert_eq!(pdu_id.value, FieldValue::U32(0x00000042));
    }

    #[test]
    fn parse_srv6_mobile_end_m_gtp6_e() {
        // End.M.GTP6.E: Same as parse_srv6_args_mob_session_basic (already tested)
        // Here we verify that the standard locator/function/argument fields coexist
        // with mobile fields in the same structure entry.
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, // LOC (48)
            0x00, 0x02, // Node (16)
            0x00, 0x47, // Func (16)
            0x24, 0x12, 0x34, 0x56, 0x78, // AMS: QFI=9, R=0, U=0, PDU=0x12345678
            0x00, // padding
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndMGtp6E),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];

        // All standard fields present
        assert!(nested_field_by_name(&buf, seg0, "locator_block").is_some());
        assert!(nested_field_by_name(&buf, seg0, "locator_node").is_some());
        assert!(nested_field_by_name(&buf, seg0, "function").is_some());
        assert!(nested_field_by_name(&buf, seg0, "argument").is_some());

        // Mobile field also present
        assert!(nested_field_by_name(&buf, seg0, "args_mob_session").is_some());

        // No embedded_ipv4 for GTP6.E
        assert!(nested_field_by_name(&buf, seg0, "embedded_ipv4").is_none());
    }

    #[test]
    fn parse_srv6_mobile_h_m_gtp4_d() {
        // H.M.GTP4.D (RFC 9433, Figure 11):
        // Destination UPF Prefix(48) | IPv4DA(32) | Args.Mob.Session(40) | 0-padded(8)
        //
        // IPv4DA = 192.168.1.1 (0xC0A80101)
        // AMS: QFI=15 (0b001111), R=1, U=0, PDU Session ID=0xDEADBEEF
        // AMS binary: 001111_1_0 = 0x3E  then 0xDE 0xAD 0xBE 0xEF
        let sid: [u8; 16] = [
            0xFD, 0x00, 0x00, 0x00, 0x00, 0x01, // UPF Prefix (48 bits)
            0xC0, 0xA8, 0x01, 0x01, // IPv4DA = 192.168.1.1 (32 bits)
            0x3E, 0xDE, 0xAD, 0xBE, 0xEF, // Args.Mob.Session (40 bits)
            0x00, // padding (8 bits)
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 0,
            function_bits: 0,
            argument_bits: 80,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::HmGtp4D {
                prefix_bits: 48,
                ipv4da_bits: 32,
                args_mob_session_bits: 40,
            }),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];

        // Verify embedded IPv4
        let ipv4 = nested_field_by_name(&buf, seg0, "embedded_ipv4").unwrap();
        assert_eq!(ipv4.value, FieldValue::Ipv4Addr([192, 168, 1, 1]));

        // Verify Args.Mob.Session
        let ams = nested_field_by_name(&buf, seg0, "args_mob_session").unwrap();
        let ams_obj = buf.nested_fields(ams.value.as_container_range().unwrap());
        let qfi = ams_obj.iter().find(|f| f.name() == "qfi").unwrap();
        assert_eq!(qfi.value, FieldValue::U8(15));
        let r_flag = ams_obj.iter().find(|f| f.name() == "r_flag").unwrap();
        assert_eq!(r_flag.value, FieldValue::U8(1));
        let pdu_id = ams_obj
            .iter()
            .find(|f| f.name() == "pdu_session_id")
            .unwrap();
        assert_eq!(pdu_id.value, FieldValue::U32(0xDEADBEEF));
    }

    #[test]
    fn parse_srv6_mobile_end_limit() {
        // End.Limit (RFC 9433, Figure 12):
        // LOC+FUNC(rate-limit)(64) | group-id(32) | limit-rate(32)
        let sid: [u8; 16] = [
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x29, // LOC+FUNC (64 bits)
            0x00, 0x00, 0x00, 0x05, // group-id = 5 (32 bits)
            0x00, 0x01, 0x00, 0x00, // limit-rate = 65536 (32 bits)
        ];
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 0,
            function_bits: 16,
            argument_bits: 64,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: Some(MobileSidEncoding::EndLimit {
                group_id_bits: 32,
                limit_rate_bits: 32,
            }),
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[sid], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];

        // Verify group_id
        let gid = nested_field_by_name(&buf, seg0, "group_id").unwrap();
        assert_eq!(resolve_scratch(&buf, gid), &[0x00, 0x00, 0x00, 0x05]);

        // Verify limit_rate
        let lr = nested_field_by_name(&buf, seg0, "limit_rate").unwrap();
        assert_eq!(resolve_scratch(&buf, lr), &[0x00, 0x01, 0x00, 0x00]);

        // No args_mob_session or embedded_ipv4
        assert!(nested_field_by_name(&buf, seg0, "args_mob_session").is_none());
        assert!(nested_field_by_name(&buf, seg0, "embedded_ipv4").is_none());
    }

    #[test]
    fn parse_srv6_mobile_encoding_none() {
        // Regression: SidStructure with mobile_encoding: None should produce
        // segments_structure with only the standard 4 fields (no mobile extras).
        let ss = SidStructure {
            locator_block_bits: 48,
            locator_node_bits: 16,
            function_bits: 16,
            argument_bits: 48,
            csid_flavor: CsidFlavor::Classic,
            mobile_encoding: None,
        };
        let dissector = Srv6Dissector::with_sid_structure(ss);
        let data = build_srh(6, 1, &[SID_A], 0, 0, &[]);
        let mut buf = DissectBuffer::new();
        dissector.dissect(&data, &mut buf, 0).unwrap();

        let layer = &buf.layers()[0];
        let structure_field = buf.field_by_name(layer, "segments_structure").unwrap();
        let structure = array_entries(&buf, structure_field);
        let seg0 = structure[0];
        let obj = buf.nested_fields(seg0.value.as_container_range().unwrap());
        // Exactly 4 fields: locator_block, locator_node, function, argument
        assert_eq!(obj.len(), 4);
        assert!(nested_field_by_name(&buf, seg0, "args_mob_session").is_none());
        assert!(nested_field_by_name(&buf, seg0, "embedded_ipv4").is_none());
        assert!(nested_field_by_name(&buf, seg0, "group_id").is_none());
        assert!(nested_field_by_name(&buf, seg0, "limit_rate").is_none());
    }

    fn call_format_fn(
        f: fn(&FieldValue<'_>, &FormatContext<'_>, &mut dyn std::io::Write) -> std::io::Result<()>,
        value: &FieldValue<'_>,
        scratch: &[u8],
    ) -> String {
        let ctx = FormatContext {
            packet_data: &[],
            scratch,
            layer_range: 0..0,
            field_range: 0..0,
        };
        let mut out = Vec::new();
        f(value, &ctx, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn format_sid_hex_scratch() {
        let scratch = [0x20, 0x01, 0x0d, 0xb8];
        let val = FieldValue::Scratch(0..4);
        assert_eq!(
            call_format_fn(format_sid_hex, &val, &scratch),
            "\"20010db8\""
        );
    }

    #[test]
    fn format_sid_hex_bytes() {
        let data = [0xab, 0xcd, 0xef];
        let val = FieldValue::Bytes(&data);
        assert_eq!(call_format_fn(format_sid_hex, &val, &[]), "\"abcdef\"");
    }

    #[test]
    fn format_sid_hex_empty_scratch() {
        let val = FieldValue::Scratch(0..0);
        assert_eq!(call_format_fn(format_sid_hex, &val, &[]), "\"\"");
    }

    #[test]
    fn format_sid_hex_empty_bytes() {
        let val = FieldValue::Bytes(&[]);
        assert_eq!(call_format_fn(format_sid_hex, &val, &[]), "\"\"");
    }

    #[test]
    fn format_sid_hex_other_variant() {
        let val = FieldValue::U8(42);
        assert_eq!(call_format_fn(format_sid_hex, &val, &[]), "\"\"");
    }
}
