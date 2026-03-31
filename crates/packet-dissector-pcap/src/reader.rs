//! Pcap/pcapng reader.
//!
//! Supports both classic pcap and pcapng formats with automatic detection.
//! Reads only record/block headers for indexing — packet data is not copied.
//!
//! ## References
//! - Pcap file format: <https://wiki.wireshark.org/Development/LibpcapFileFormat>
//! - Pcapng: <https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html>

use std::io::{self, BufReader, Read};
use std::ops::ControlFlow;

use crate::{LINKTYPE_ETHERNET, PacketRecord, PcapError};

// ---------------------------------------------------------------------------
// Pcap magic numbers and sizes
// ---------------------------------------------------------------------------

const PCAP_MAGIC_LE: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];
const PCAP_MAGIC_BE: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
const PCAP_MAGIC_NSEC_LE: [u8; 4] = [0x4D, 0x3C, 0xB2, 0xA1];
const PCAP_MAGIC_NSEC_BE: [u8; 4] = [0xA1, 0xB2, 0x3C, 0x4D];

/// Pcapng Section Header Block magic.
const PCAPNG_MAGIC: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

/// Pcap global header size.
const PCAP_GLOBAL_HEADER_SIZE: usize = 24;
/// Pcap per-packet record header size (ts_sec, ts_usec, incl_len, orig_len).
const PCAP_RECORD_HEADER_SIZE: usize = 16;

/// Pcapng block type constants.
const PCAPNG_BT_IDB: u32 = 0x0000_0001;
const PCAPNG_BT_EPB: u32 = 0x0000_0006;
const PCAPNG_BT_SPB: u32 = 0x0000_0003;
const PCAPNG_BT_SHB: u32 = 0x0A0D_0D0A;

// ---------------------------------------------------------------------------
// Chunked indexing types
// ---------------------------------------------------------------------------

/// Interface information for pcapng chunked indexing.
#[derive(Debug, Clone)]
pub struct PcapngIfaceInfo {
    /// Link-layer type for this interface.
    pub link_type: u16,
    /// Timestamp units per second (derived from `if_tsresol` option).
    pub ts_units_per_sec: u64,
}

/// Parsed format information for resumable indexing.
#[derive(Debug, Clone)]
pub enum IndexFormat {
    /// Classic pcap format.
    Pcap {
        /// Little-endian byte order.
        is_le: bool,
        /// Link-layer type from the global header.
        link_type: u16,
    },
    /// Pcapng format.
    Pcapng {
        /// Little-endian byte order (from the current section).
        is_le: bool,
        /// Interface descriptions accumulated so far.
        ifaces: Vec<PcapngIfaceInfo>,
    },
}

/// Resumable state for chunked index building.
///
/// Created by [`build_index_start`] and advanced by [`build_index_chunk`].
#[derive(Debug, Clone)]
pub struct IndexState {
    /// Current byte offset in the data.
    pub byte_offset: usize,
    /// Parsed format information.
    pub format: IndexFormat,
    /// Whether scanning is complete (no more records to read).
    pub done: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a packet index from raw file bytes.
///
/// Supports both pcap and pcapng formats.  Only reads record/block headers —
/// no packet data is accessed during indexing.
pub fn build_index(data: &[u8]) -> Result<Vec<PacketRecord>, PcapError> {
    let mut state = build_index_start(data)?;
    let mut records = Vec::new();
    while !state.done {
        records.extend(build_index_chunk(data, &mut state, usize::MAX)?);
    }
    Ok(records)
}

/// Parse the file header and return an initial [`IndexState`] for chunked
/// indexing.
///
/// After calling this, repeatedly call [`build_index_chunk`] until
/// `state.done` is `true`.
pub fn build_index_start(data: &[u8]) -> Result<IndexState, PcapError> {
    if data.len() < 4 {
        return Err(PcapError::TooSmall);
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap_or_default();

    if magic == PCAPNG_MAGIC {
        start_pcapng(data)
    } else {
        start_pcap(data)
    }
}

/// Parse up to `limit` records from `data` starting at `state.byte_offset`.
///
/// Advances `state` so that the next call continues where this one left off.
/// Sets `state.done = true` when there are no more records.
pub fn build_index_chunk(
    data: &[u8],
    state: &mut IndexState,
    limit: usize,
) -> Result<Vec<PacketRecord>, PcapError> {
    match &mut state.format {
        IndexFormat::Pcap { is_le, link_type } => chunk_pcap(
            data,
            &mut state.byte_offset,
            &mut state.done,
            *is_le,
            *link_type,
            limit,
        ),
        IndexFormat::Pcapng { is_le, ifaces } => chunk_pcapng(
            data,
            &mut state.byte_offset,
            &mut state.done,
            is_le,
            ifaces,
            limit,
        ),
    }
}

/// Stream packets from a reader, calling `f` for each one.
///
/// Only one packet's data is buffered at a time.  Supports both pcap and
/// pcapng formats with auto-detection based on the first 4 bytes.
///
/// Return [`ControlFlow::Break`] from the callback to stop early.
pub fn stream_packets<R, F>(reader: R, f: F) -> Result<(), PcapError>
where
    R: Read,
    F: FnMut(&PacketRecord, &[u8]) -> ControlFlow<()>,
{
    let mut reader = BufReader::new(reader);
    let mut magic = [0u8; 4];
    match reader.read_exact(&mut magic) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(PcapError::TooSmall),
        Err(e) => return Err(PcapError::Io(e)),
    }

    if magic == PCAPNG_MAGIC {
        stream_pcapng(reader, magic, f)
    } else {
        stream_pcap(reader, magic, f)
    }
}

fn stream_pcap<R, F>(mut reader: R, magic: [u8; 4], mut f: F) -> Result<(), PcapError>
where
    R: Read,
    F: FnMut(&PacketRecord, &[u8]) -> ControlFlow<()>,
{
    let is_le = matches!(magic, PCAP_MAGIC_LE | PCAP_MAGIC_NSEC_LE);
    let is_be = matches!(magic, PCAP_MAGIC_BE | PCAP_MAGIC_NSEC_BE);
    if !is_le && !is_be {
        return Err(PcapError::UnsupportedFormat);
    }

    let read_u16 = if is_le { u16_le } else { u16_be };
    let read_u32 = if is_le { u32_le } else { u32_be };

    // Read remaining 20 bytes of global header.
    let mut hdr = [0u8; 20];
    reader.read_exact(&mut hdr).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            PcapError::TooSmall
        } else {
            PcapError::Io(e)
        }
    })?;
    let link_type = read_u16(&hdr[16..18]);
    let mut pos: u64 = PCAP_GLOBAL_HEADER_SIZE as u64;

    let mut pkt_buf = Vec::new();

    loop {
        // Read 16-byte record header.
        let mut rec_hdr = [0u8; PCAP_RECORD_HEADER_SIZE];
        match reader.read_exact(&mut rec_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(PcapError::Io(e)),
        }

        let ts_sec = read_u32(&rec_hdr[0..4]);
        let ts_usec = read_u32(&rec_hdr[4..8]);
        let incl_len = read_u32(&rec_hdr[8..12]);
        let orig_len = read_u32(&rec_hdr[12..16]);

        let data_offset = pos + PCAP_RECORD_HEADER_SIZE as u64;

        // Read packet data.
        pkt_buf.resize(incl_len as usize, 0);
        reader.read_exact(&mut pkt_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                PcapError::Truncated {
                    offset: data_offset as usize,
                }
            } else {
                PcapError::Io(e)
            }
        })?;

        let record = PacketRecord {
            data_offset,
            captured_len: incl_len,
            original_len: orig_len,
            timestamp_secs: ts_sec as u64,
            timestamp_usecs: ts_usec,
            link_type,
        };

        if f(&record, &pkt_buf).is_break() {
            return Ok(());
        }

        pos += PCAP_RECORD_HEADER_SIZE as u64 + incl_len as u64;
    }
}

fn stream_pcapng<R, F>(mut reader: R, _magic: [u8; 4], mut f: F) -> Result<(), PcapError>
where
    R: Read,
    F: FnMut(&PacketRecord, &[u8]) -> ControlFlow<()>,
{
    struct IfaceInfo {
        link_type: u16,
        ts_units_per_sec: u64,
    }
    let mut ifaces: Vec<IfaceInfo> = Vec::new();
    const DEFAULT_TS_UNITS: u64 = 1_000_000;

    let mut pos: u64 = 0;
    let mut pkt_buf = Vec::new();
    let mut block_buf = Vec::new();

    // We already read 4 bytes (the magic). Process the SHB now.
    // Read next 4 bytes (block total length).
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            PcapError::TooSmall
        } else {
            PcapError::Io(e)
        }
    })?;

    // We need 4 more bytes (BOM) to determine endianness.
    let mut bom_buf = [0u8; 4];
    reader.read_exact(&mut bom_buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            PcapError::TooSmall
        } else {
            PcapError::Io(e)
        }
    })?;

    let mut is_le = u32_le(&bom_buf) == 0x1A2B_3C4D;
    let read_u32_fn = if is_le { u32_le } else { u32_be };

    let block_len = read_u32_fn(&len_buf) as usize;
    // Skip rest of SHB: block_len - 12 bytes already consumed (4 type + 4 len + 4 bom).
    let remaining = block_len.saturating_sub(12);
    skip_bytes(&mut reader, remaining as u64)?;
    pos += block_len as u64;

    // Now read subsequent blocks.
    loop {
        // Read 8-byte block header (type + length).
        let mut blk_hdr = [0u8; 8];
        match reader.read_exact(&mut blk_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(PcapError::Io(e)),
        }

        let block_type = u32_le(&blk_hdr[0..4]);
        let read_u32_fn = if is_le { u32_le } else { u32_be };
        let block_len = read_u32_fn(&blk_hdr[4..8]) as usize;

        if block_len < 12 {
            return Ok(());
        }

        // Bytes remaining in this block after the 8-byte header (includes trailing 4-byte length).
        let body_len = block_len - 8;

        match block_type {
            PCAPNG_BT_SHB => {
                // New section: re-read BOM from body.
                let mut shb_bom = [0u8; 4];
                match reader.read_exact(&mut shb_bom) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(e) => return Err(PcapError::Io(e)),
                }
                is_le = u32_le(&shb_bom) == 0x1A2B_3C4D;
                ifaces.clear();
                skip_bytes(&mut reader, (body_len - 4) as u64)?;
            }
            PCAPNG_BT_IDB => {
                // Read full body to parse options for tsresol.
                block_buf.resize(body_len, 0);
                reader.read_exact(&mut block_buf).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        PcapError::Truncated {
                            offset: pos as usize,
                        }
                    } else {
                        PcapError::Io(e)
                    }
                })?;

                let read_u16_fn = if is_le { u16_le } else { u16_be };
                let (link_type, ts_units) = if block_buf.len() >= 8 {
                    let lt = read_u16_fn(&block_buf[0..2]);
                    // Options start at offset 8 in body, end before trailing 4-byte length.
                    let opts_end = block_buf.len().saturating_sub(4);
                    let opts_start = 8.min(opts_end);
                    let tsresol = parse_tsresol_option(&block_buf[opts_start..opts_end], is_le);
                    (lt, ts_units_per_second(tsresol))
                } else {
                    (LINKTYPE_ETHERNET, DEFAULT_TS_UNITS)
                };
                ifaces.push(IfaceInfo {
                    link_type,
                    ts_units_per_sec: ts_units,
                });
            }
            PCAPNG_BT_EPB => {
                // EPB fixed fields: interface_id(4) + ts_high(4) + ts_low(4) +
                // captured_len(4) + original_len(4) = 20 bytes, then packet data,
                // then options, then trailing block length (4 bytes).
                if body_len < 24 {
                    // 20 fixed + 4 trailing
                    skip_bytes(&mut reader, body_len as u64)?;
                    pos += block_len as u64;
                    continue;
                }

                let mut epb_hdr = [0u8; 20];
                reader.read_exact(&mut epb_hdr).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        PcapError::Truncated {
                            offset: pos as usize,
                        }
                    } else {
                        PcapError::Io(e)
                    }
                })?;

                let iface_id = read_u32_fn(&epb_hdr[0..4]);
                let ts_high = read_u32_fn(&epb_hdr[4..8]);
                let ts_low = read_u32_fn(&epb_hdr[8..12]);
                let captured_len = read_u32_fn(&epb_hdr[12..16]);
                let original_len = read_u32_fn(&epb_hdr[16..20]);

                let iface = ifaces.get(iface_id as usize);
                let link_type = iface.map(|i| i.link_type).unwrap_or(LINKTYPE_ETHERNET);
                let units_per_sec = iface
                    .map(|i| i.ts_units_per_sec)
                    .unwrap_or(DEFAULT_TS_UNITS);

                let raw_ts = ((ts_high as u64) << 32) | (ts_low as u64);
                let (timestamp_secs, timestamp_usecs) =
                    convert_pcapng_ts(raw_ts as u128, units_per_sec);

                // data_offset = position of packet data in stream.
                let data_offset = pos + 28; // 8 (block hdr) + 20 (EPB fixed)

                pkt_buf.resize(captured_len as usize, 0);
                reader.read_exact(&mut pkt_buf).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        PcapError::Truncated {
                            offset: data_offset as usize,
                        }
                    } else {
                        PcapError::Io(e)
                    }
                })?;

                let record = PacketRecord {
                    data_offset,
                    captured_len,
                    original_len,
                    timestamp_secs,
                    timestamp_usecs,
                    link_type,
                };

                if f(&record, &pkt_buf).is_break() {
                    return Ok(());
                }

                // Skip remaining bytes (padding + options + trailing length).
                let consumed = 20 + captured_len as usize;
                let remaining = body_len.saturating_sub(consumed);
                skip_bytes(&mut reader, remaining as u64)?;
            }
            PCAPNG_BT_SPB => {
                // SPB: original_len(4) + packet data + trailing length(4).
                if body_len < 8 {
                    skip_bytes(&mut reader, body_len as u64)?;
                    pos += block_len as u64;
                    continue;
                }

                let mut spb_hdr = [0u8; 4];
                reader.read_exact(&mut spb_hdr).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        PcapError::Truncated {
                            offset: pos as usize,
                        }
                    } else {
                        PcapError::Io(e)
                    }
                })?;

                let original_len = read_u32_fn(&spb_hdr);
                let link_type = ifaces
                    .first()
                    .map(|i| i.link_type)
                    .unwrap_or(LINKTYPE_ETHERNET);
                // SPB captured_len = block_len - 16 (8 hdr + 4 orig_len + 4 trailer).
                let captured_len = if block_len > 16 {
                    (block_len - 16) as u32
                } else {
                    original_len
                };

                let data_offset = pos + 12; // 8 (block hdr) + 4 (orig_len)

                pkt_buf.resize(captured_len as usize, 0);
                reader.read_exact(&mut pkt_buf).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        PcapError::Truncated {
                            offset: data_offset as usize,
                        }
                    } else {
                        PcapError::Io(e)
                    }
                })?;

                let record = PacketRecord {
                    data_offset,
                    captured_len,
                    original_len,
                    timestamp_secs: 0,
                    timestamp_usecs: 0,
                    link_type,
                };

                if f(&record, &pkt_buf).is_break() {
                    return Ok(());
                }

                let consumed = 4 + captured_len as usize;
                let remaining = body_len.saturating_sub(consumed);
                skip_bytes(&mut reader, remaining as u64)?;
            }
            _ => {
                skip_bytes(&mut reader, body_len as u64)?;
            }
        }

        pos += block_len as u64;
    }
}

/// Skip `n` bytes from a reader by reading and discarding them.
fn skip_bytes<R: Read>(reader: &mut R, n: u64) -> Result<(), PcapError> {
    if n > 0 {
        io::copy(&mut reader.take(n), &mut io::sink())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Classic pcap
// ---------------------------------------------------------------------------

fn start_pcap(data: &[u8]) -> Result<IndexState, PcapError> {
    if data.len() < PCAP_GLOBAL_HEADER_SIZE {
        return Err(PcapError::TooSmall);
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap_or_default();
    let is_le = matches!(magic, PCAP_MAGIC_LE | PCAP_MAGIC_NSEC_LE);
    let is_be = matches!(magic, PCAP_MAGIC_BE | PCAP_MAGIC_NSEC_BE);
    if !is_le && !is_be {
        return Err(PcapError::UnsupportedFormat);
    }

    let read_u32 = if is_le { u32_le } else { u32_be };
    let link_type = read_u32(&data[20..24]) as u16;

    Ok(IndexState {
        byte_offset: PCAP_GLOBAL_HEADER_SIZE,
        format: IndexFormat::Pcap { is_le, link_type },
        done: PCAP_GLOBAL_HEADER_SIZE + PCAP_RECORD_HEADER_SIZE > data.len(),
    })
}

fn chunk_pcap(
    data: &[u8],
    pos: &mut usize,
    done: &mut bool,
    is_le: bool,
    link_type: u16,
    limit: usize,
) -> Result<Vec<PacketRecord>, PcapError> {
    let read_u32 = if is_le { u32_le } else { u32_be };
    // Estimate capacity: remaining bytes / minimum record size gives an upper bound.
    let remaining = data.len().saturating_sub(*pos);
    let est = remaining / (PCAP_RECORD_HEADER_SIZE + 1);
    let mut records = Vec::with_capacity(est.min(limit));
    let mut count = 0usize;

    while *pos + PCAP_RECORD_HEADER_SIZE <= data.len() && count < limit {
        let ts_sec = read_u32(&data[*pos..*pos + 4]);
        let ts_usec = read_u32(&data[*pos + 4..*pos + 8]);
        let incl_len = read_u32(&data[*pos + 8..*pos + 12]);
        let orig_len = read_u32(&data[*pos + 12..*pos + 16]);

        let data_offset = (*pos + PCAP_RECORD_HEADER_SIZE) as u64;

        records.push(PacketRecord {
            data_offset,
            captured_len: incl_len,
            original_len: orig_len,
            timestamp_secs: ts_sec as u64,
            timestamp_usecs: ts_usec,
            link_type,
        });

        *pos += PCAP_RECORD_HEADER_SIZE + incl_len as usize;
        count += 1;
    }

    if *pos + PCAP_RECORD_HEADER_SIZE > data.len() {
        *done = true;
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// Pcapng
// ---------------------------------------------------------------------------

fn start_pcapng(data: &[u8]) -> Result<IndexState, PcapError> {
    if data.len() < 12 {
        return Err(PcapError::TooSmall);
    }

    // Read the BOM from the SHB to determine endianness.
    let is_le = u32_le(&data[8..12]) == 0x1A2B_3C4D;

    Ok(IndexState {
        byte_offset: 0,
        format: IndexFormat::Pcapng {
            is_le,
            ifaces: Vec::new(),
        },
        done: false,
    })
}

const DEFAULT_TS_UNITS: u64 = 1_000_000;

fn chunk_pcapng(
    data: &[u8],
    pos: &mut usize,
    done: &mut bool,
    is_le: &mut bool,
    ifaces: &mut Vec<PcapngIfaceInfo>,
    limit: usize,
) -> Result<Vec<PacketRecord>, PcapError> {
    let mut records = Vec::with_capacity(limit.min(1024));
    let mut count = 0usize;

    while *pos + 12 <= data.len() && count < limit {
        let block_type = u32_le(&data[*pos..*pos + 4]);

        let read_u32 = if *is_le { u32_le } else { u32_be };

        match block_type {
            PCAPNG_BT_SHB => {
                if *pos + 12 <= data.len() {
                    let bom = u32_le(&data[*pos + 8..*pos + 12]);
                    *is_le = bom == 0x1A2B_3C4D;
                }
                ifaces.clear();
                let read_u32 = if *is_le { u32_le } else { u32_be };
                let block_len = read_u32(&data[*pos + 4..*pos + 8]) as usize;
                *pos += block_len.max(12);
            }
            PCAPNG_BT_IDB => {
                let block_len = read_u32(&data[*pos + 4..*pos + 8]) as usize;

                let body_start = *pos + 8;
                let body_end = (*pos + block_len).saturating_sub(4).min(data.len());
                let (link_type, ts_units) = if body_start + 8 <= body_end {
                    let read_u16 = if *is_le { u16_le } else { u16_be };
                    let lt = read_u16(&data[body_start..body_start + 2]);
                    let opts_start = body_start + 8;
                    let tsresol = parse_tsresol_option(&data[opts_start..body_end], *is_le);
                    (lt, ts_units_per_second(tsresol))
                } else {
                    (LINKTYPE_ETHERNET, DEFAULT_TS_UNITS)
                };
                ifaces.push(PcapngIfaceInfo {
                    link_type,
                    ts_units_per_sec: ts_units,
                });

                *pos += block_len.max(12);
            }
            PCAPNG_BT_EPB => {
                let block_len = read_u32(&data[*pos + 4..*pos + 8]) as usize;

                if *pos + 28 <= data.len() {
                    let iface_id = read_u32(&data[*pos + 8..*pos + 12]);
                    let ts_high = read_u32(&data[*pos + 12..*pos + 16]);
                    let ts_low = read_u32(&data[*pos + 16..*pos + 20]);
                    let captured_len = read_u32(&data[*pos + 20..*pos + 24]);
                    let original_len = read_u32(&data[*pos + 24..*pos + 28]);

                    let iface = ifaces.get(iface_id as usize);
                    let link_type = iface.map(|i| i.link_type).unwrap_or(LINKTYPE_ETHERNET);
                    let units_per_sec = iface
                        .map(|i| i.ts_units_per_sec)
                        .unwrap_or(DEFAULT_TS_UNITS);

                    let raw_ts = ((ts_high as u64) << 32) | (ts_low as u64);
                    let (timestamp_secs, timestamp_usecs) =
                        convert_pcapng_ts(raw_ts as u128, units_per_sec);

                    records.push(PacketRecord {
                        data_offset: (*pos + 28) as u64,
                        captured_len,
                        original_len,
                        timestamp_secs,
                        timestamp_usecs,
                        link_type,
                    });
                    count += 1;
                }
                *pos += block_len.max(12);
            }
            PCAPNG_BT_SPB => {
                let block_len = read_u32(&data[*pos + 4..*pos + 8]) as usize;

                if *pos + 12 <= data.len() {
                    let original_len = read_u32(&data[*pos + 8..*pos + 12]);
                    let link_type = ifaces
                        .first()
                        .map(|i| i.link_type)
                        .unwrap_or(LINKTYPE_ETHERNET);
                    let captured_len = if block_len > 16 {
                        (block_len - 16) as u32
                    } else {
                        original_len
                    };

                    records.push(PacketRecord {
                        data_offset: (*pos + 12) as u64,
                        captured_len,
                        original_len,
                        timestamp_secs: 0,
                        timestamp_usecs: 0,
                        link_type,
                    });
                    count += 1;
                }
                *pos += block_len.max(12);
            }
            _ => {
                let block_len = read_u32(&data[*pos + 4..*pos + 8]) as usize;
                if block_len < 12 {
                    *done = true;
                    return Ok(records);
                }
                *pos += block_len;
            }
        }
    }

    if *pos + 12 > data.len() {
        *done = true;
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Scan pcapng options for `if_tsresol` (option code 9, length 1).
///
/// Pcapng options are TLV-encoded: code(u16) + length(u16) + value + padding.
/// Reference: pcapng spec, Section 4.2.
fn parse_tsresol_option(opts: &[u8], is_le: bool) -> u8 {
    let read_u16 = if is_le { u16_le } else { u16_be };
    let mut p = 0;
    while p + 4 <= opts.len() {
        let code = read_u16(&opts[p..p + 2]);
        let length = read_u16(&opts[p + 2..p + 4]) as usize;
        if code == 0 {
            break;
        }
        if code == 9 && length == 1 && p + 4 < opts.len() {
            return opts[p + 4];
        }
        let padded = (length + 3) & !3;
        p += 4 + padded;
    }
    6 // Default: 10^-6 (microseconds)
}

/// Compute timestamp units per second from a pcapng `if_tsresol` value.
fn ts_units_per_second(tsresol: u8) -> u64 {
    if tsresol & 0x80 == 0 {
        10u64.pow(u32::from(tsresol & 0x7F))
    } else {
        1u64 << u32::from(tsresol & 0x7F)
    }
}

/// Convert a raw pcapng timestamp to (seconds, microseconds).
fn convert_pcapng_ts(raw_ts: u128, units_per_sec: u64) -> (u64, u32) {
    let units = units_per_sec as u128;
    let secs = (raw_ts / units) as u64;
    let frac = raw_ts % units;
    let usecs = (frac * 1_000_000 / units) as u32;
    (secs, usecs)
}

fn u16_le(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

fn u16_be(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

fn u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

fn u32_be(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal pcap file with `n` packets.
    fn build_pcap_bytes(n: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        // Global header
        buf.extend_from_slice(&PCAP_MAGIC_LE);
        buf.extend_from_slice(&2u16.to_le_bytes()); // major
        buf.extend_from_slice(&4u16.to_le_bytes()); // minor
        buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

        let pkt: &[u8] = &[0xff; 42]; // dummy packet
        for i in 0..n {
            buf.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
            buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // incl_len
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // orig_len
            buf.extend_from_slice(pkt);
        }
        buf
    }

    #[test]
    fn detect_pcap_le() {
        let data = build_pcap_bytes(0);
        let records = build_index(&data).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn detect_unsupported() {
        // 24 bytes (enough for a global header) but wrong magic.
        let data = [0x00; 24];
        let err = build_index(&data).unwrap_err();
        assert!(matches!(err, PcapError::UnsupportedFormat));
    }

    #[test]
    fn detect_too_small() {
        let err = build_index(&[0x00]).unwrap_err();
        assert!(matches!(err, PcapError::TooSmall));
    }

    #[test]
    fn build_index_pcap_single_packet() {
        let data = build_pcap_bytes(1);
        let records = build_index(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].captured_len, 42);
        assert_eq!(records[0].link_type, 1);
        assert_eq!(records[0].timestamp_secs, 0);
    }

    #[test]
    fn build_index_pcap_multiple_packets() {
        let data = build_pcap_bytes(100);
        let records = build_index(&data).unwrap();
        assert_eq!(records.len(), 100);
        assert_eq!(records[50].timestamp_secs, 50);
    }

    #[test]
    fn chunked_pcap_matches_build_index() {
        let data = build_pcap_bytes(100);
        let all = build_index(&data).unwrap();

        // Chunked: 30 records per chunk.
        let mut state = build_index_start(&data).unwrap();
        let mut chunked = Vec::new();
        while !state.done {
            chunked.extend(build_index_chunk(&data, &mut state, 30).unwrap());
        }

        assert_eq!(chunked.len(), all.len());
        for (a, b) in all.iter().zip(chunked.iter()) {
            assert_eq!(a.data_offset, b.data_offset);
            assert_eq!(a.captured_len, b.captured_len);
            assert_eq!(a.timestamp_secs, b.timestamp_secs);
            assert_eq!(a.link_type, b.link_type);
        }
    }

    #[test]
    fn chunked_pcapng_matches_build_index() {
        let pkt = [0xAA; 10];
        let packets: Vec<(u64, u32, &[u8])> = (0..50)
            .map(|i| (i as u64 * 1_000_000, 10u32, pkt.as_slice()))
            .collect();
        let data = build_pcapng_bytes(1, &packets);
        let all = build_index(&data).unwrap();

        let mut state = build_index_start(&data).unwrap();
        let mut chunked = Vec::new();
        while !state.done {
            chunked.extend(build_index_chunk(&data, &mut state, 10).unwrap());
        }

        assert_eq!(chunked.len(), all.len());
        for (a, b) in all.iter().zip(chunked.iter()) {
            assert_eq!(a.data_offset, b.data_offset);
            assert_eq!(a.captured_len, b.captured_len);
            assert_eq!(a.timestamp_secs, b.timestamp_secs);
            assert_eq!(a.link_type, b.link_type);
        }
    }

    #[test]
    fn chunked_empty_pcap() {
        let data = build_pcap_bytes(0);
        let mut state = build_index_start(&data).unwrap();
        assert!(state.done);
        let records = build_index_chunk(&data, &mut state, 100).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn chunked_single_record_per_chunk() {
        let data = build_pcap_bytes(5);
        let mut state = build_index_start(&data).unwrap();
        let mut total = Vec::new();
        while !state.done {
            let chunk = build_index_chunk(&data, &mut state, 1).unwrap();
            assert!(chunk.len() <= 1);
            total.extend(chunk);
        }
        assert_eq!(total.len(), 5);
    }

    #[test]
    fn ts_units_microseconds() {
        assert_eq!(ts_units_per_second(6), 1_000_000);
    }

    #[test]
    fn ts_units_nanoseconds() {
        assert_eq!(ts_units_per_second(9), 1_000_000_000);
    }

    #[test]
    fn ts_units_binary() {
        // Bit 7 set → 2^(value & 0x7F)
        assert_eq!(ts_units_per_second(0x80 | 10), 1024);
    }

    #[test]
    fn convert_ts_basic() {
        let (secs, usecs) = convert_pcapng_ts(1_500_000, 1_000_000);
        assert_eq!(secs, 1);
        assert_eq!(usecs, 500_000);
    }

    // -----------------------------------------------------------------------
    // stream_packets tests
    // -----------------------------------------------------------------------

    use std::io::Cursor;

    /// Build a minimal pcapng file with given packets.
    /// Each EPB uses interface 0 with the given link_type.
    fn build_pcapng_bytes(
        link_type: u16,
        packets: &[(u64, u32, &[u8])], // (timestamp_raw, orig_len, data)
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // --- SHB (Section Header Block) ---
        // Block type
        buf.extend_from_slice(&PCAPNG_MAGIC);
        // Block total length (placeholder, filled below)
        let shb_len_pos = buf.len();
        buf.extend_from_slice(&0u32.to_le_bytes());
        // BOM
        buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        // Major version
        buf.extend_from_slice(&1u16.to_le_bytes());
        // Minor version
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Section length (-1 = unspecified)
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        // No options
        // Trailing block length
        // Actually, let's compute properly:
        // SHB = type(4) + length(4) + bom(4) + major(2) + minor(2) + section_len(8) + trailer(4) = 28
        let shb_block_len = 28u32;
        buf.extend_from_slice(&shb_block_len.to_le_bytes()); // trailer
        // Fix the length field
        buf[shb_len_pos..shb_len_pos + 4].copy_from_slice(&shb_block_len.to_le_bytes());

        // --- IDB (Interface Description Block) ---
        let idb_block_len = 20u32; // type(4) + len(4) + linktype(2) + reserved(2) + snaplen(4) + trailer(4)
        buf.extend_from_slice(&PCAPNG_BT_IDB.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());
        buf.extend_from_slice(&link_type.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&262144u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&idb_block_len.to_le_bytes()); // trailer

        // --- EPB packets ---
        for &(ts_raw, orig_len, data) in packets {
            let captured_len = data.len() as u32;
            let padded_len = (data.len() + 3) & !3;
            // EPB = type(4) + len(4) + iface_id(4) + ts_high(4) + ts_low(4)
            //     + cap_len(4) + orig_len(4) + data(padded) + trailer(4)
            let epb_block_len = (32 + padded_len) as u32;
            buf.extend_from_slice(&PCAPNG_BT_EPB.to_le_bytes());
            buf.extend_from_slice(&epb_block_len.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // interface_id
            let ts_high = (ts_raw >> 32) as u32;
            let ts_low = ts_raw as u32;
            buf.extend_from_slice(&ts_high.to_le_bytes());
            buf.extend_from_slice(&ts_low.to_le_bytes());
            buf.extend_from_slice(&captured_len.to_le_bytes());
            buf.extend_from_slice(&orig_len.to_le_bytes());
            buf.extend_from_slice(data);
            // Padding
            buf.extend(std::iter::repeat_n(0, padded_len - data.len()));
            buf.extend_from_slice(&epb_block_len.to_le_bytes()); // trailer
        }

        buf
    }

    /// Build a pcapng with an SPB (Simple Packet Block).
    fn build_pcapng_spb(link_type: u16, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // SHB
        let shb_block_len = 28u32;
        buf.extend_from_slice(&PCAPNG_MAGIC);
        buf.extend_from_slice(&shb_block_len.to_le_bytes());
        buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        buf.extend_from_slice(&shb_block_len.to_le_bytes());

        // IDB
        let idb_block_len = 20u32;
        buf.extend_from_slice(&PCAPNG_BT_IDB.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());
        buf.extend_from_slice(&link_type.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&262144u32.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());

        // SPB
        let padded_len = (data.len() + 3) & !3;
        let spb_block_len = (16 + padded_len) as u32;
        buf.extend_from_slice(&PCAPNG_BT_SPB.to_le_bytes());
        buf.extend_from_slice(&spb_block_len.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // original_len
        buf.extend_from_slice(data);
        buf.extend(std::iter::repeat_n(0, padded_len - data.len()));
        buf.extend_from_slice(&spb_block_len.to_le_bytes());

        buf
    }

    /// Build a pcapng with two interfaces having different link_types.
    fn build_pcapng_multi_iface() -> Vec<u8> {
        let mut buf = Vec::new();

        // SHB
        let shb_block_len = 28u32;
        buf.extend_from_slice(&PCAPNG_MAGIC);
        buf.extend_from_slice(&shb_block_len.to_le_bytes());
        buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        buf.extend_from_slice(&shb_block_len.to_le_bytes());

        // IDB 0: link_type = 1 (Ethernet)
        let idb_block_len = 20u32;
        buf.extend_from_slice(&PCAPNG_BT_IDB.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&262144u32.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());

        // IDB 1: link_type = 113 (Linux SLL)
        buf.extend_from_slice(&PCAPNG_BT_IDB.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());
        buf.extend_from_slice(&113u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&262144u32.to_le_bytes());
        buf.extend_from_slice(&idb_block_len.to_le_bytes());

        // EPB for interface 0
        let data = [0xAA; 4];
        // EPB = type(4) + len(4) + iface_id(4) + ts_high(4) + ts_low(4)
        //     + cap_len(4) + orig_len(4) + data(4, already aligned) + trailer(4) = 36
        let epb_block_len = 36u32;
        buf.extend_from_slice(&PCAPNG_BT_EPB.to_le_bytes());
        buf.extend_from_slice(&epb_block_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // interface_id = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        buf.extend_from_slice(&100u32.to_le_bytes()); // ts_low
        buf.extend_from_slice(&4u32.to_le_bytes()); // captured_len
        buf.extend_from_slice(&4u32.to_le_bytes()); // original_len
        buf.extend_from_slice(&data);
        buf.extend_from_slice(&epb_block_len.to_le_bytes());

        // EPB for interface 1
        let data2 = [0xBB; 4];
        buf.extend_from_slice(&PCAPNG_BT_EPB.to_le_bytes());
        buf.extend_from_slice(&epb_block_len.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // interface_id = 1
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        buf.extend_from_slice(&200u32.to_le_bytes()); // ts_low
        buf.extend_from_slice(&4u32.to_le_bytes()); // captured_len
        buf.extend_from_slice(&4u32.to_le_bytes()); // original_len
        buf.extend_from_slice(&data2);
        buf.extend_from_slice(&epb_block_len.to_le_bytes());

        buf
    }

    #[test]
    fn stream_pcap_single_packet() {
        let data = build_pcap_bytes(1);
        let mut records = Vec::new();
        stream_packets(Cursor::new(data), |rec, pkt| {
            assert_eq!(pkt.len(), 42);
            records.push(rec.clone());
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].captured_len, 42);
        assert_eq!(records[0].original_len, 42);
        assert_eq!(records[0].link_type, 1);
        assert_eq!(records[0].timestamp_secs, 0);
    }

    #[test]
    fn stream_pcap_multiple_packets() {
        let data = build_pcap_bytes(100);
        let mut count = 0u64;
        stream_packets(Cursor::new(data), |rec, _| {
            assert_eq!(rec.timestamp_secs, count);
            count += 1;
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn stream_pcap_early_stop() {
        let data = build_pcap_bytes(10);
        let mut count = 0u64;
        stream_packets(Cursor::new(data), |_, _| {
            count += 1;
            if count >= 5 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn stream_pcap_empty() {
        let data = build_pcap_bytes(0);
        let mut count = 0u64;
        stream_packets(Cursor::new(data), |_, _| {
            count += 1;
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn stream_pcapng_epb() {
        let pkt_data = [0xDE, 0xAD, 0xBE, 0xEF];
        let ts_raw = 1_500_000u64; // 1.5 seconds at default microsecond resolution
        let data = build_pcapng_bytes(1, &[(ts_raw, 4, &pkt_data)]);
        let mut records = Vec::new();
        let mut pkt_bytes = Vec::new();
        stream_packets(Cursor::new(data), |rec, pkt| {
            records.push(rec.clone());
            pkt_bytes.extend_from_slice(pkt);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].link_type, 1);
        assert_eq!(records[0].timestamp_secs, 1);
        assert_eq!(records[0].timestamp_usecs, 500_000);
        assert_eq!(records[0].captured_len, 4);
        assert_eq!(records[0].original_len, 4);
        assert_eq!(pkt_bytes, pkt_data);
    }

    #[test]
    fn stream_pcapng_spb() {
        let pkt_data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let data = build_pcapng_spb(1, &pkt_data);
        let mut records = Vec::new();
        let mut pkt_bytes = Vec::new();
        stream_packets(Cursor::new(data), |rec, pkt| {
            records.push(rec.clone());
            pkt_bytes.extend_from_slice(pkt);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].link_type, 1);
        assert_eq!(records[0].timestamp_secs, 0);
        assert_eq!(records[0].timestamp_usecs, 0);
        // SPB captured_len = block_len - 16: data is 5 bytes padded to 8, so block = 16+8=24, cap=8
        // Actually: padded_len = (5+3)&!3 = 8, spb_block_len = 16+8 = 24, captured = 24-16 = 8
        // But original_len = 5, and the actual meaningful data is 5 bytes (rest is padding).
        assert_eq!(records[0].original_len, 5);
        assert_eq!(&pkt_bytes[..5], &pkt_data);
    }

    #[test]
    fn stream_pcapng_multiple_ifaces() {
        let data = build_pcapng_multi_iface();
        let mut records = Vec::new();
        let mut all_data = Vec::new();
        stream_packets(Cursor::new(data), |rec, pkt| {
            records.push(rec.clone());
            all_data.push(pkt.to_vec());
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].link_type, 1); // Ethernet
        assert_eq!(records[1].link_type, 113); // Linux SLL
        assert_eq!(all_data[0], [0xAA; 4]);
        assert_eq!(all_data[1], [0xBB; 4]);
    }

    #[test]
    fn stream_too_small() {
        let err =
            stream_packets(Cursor::new([0u8; 3]), |_, _| ControlFlow::Continue(())).unwrap_err();
        assert!(matches!(err, PcapError::TooSmall));
    }

    #[test]
    fn stream_unsupported_format() {
        // 24 bytes with invalid magic
        let data = [0x00u8; 24];
        let err = stream_packets(Cursor::new(data), |_, _| ControlFlow::Continue(())).unwrap_err();
        assert!(matches!(err, PcapError::UnsupportedFormat));
    }

    #[test]
    fn stream_truncated_packet_data() {
        let mut data = build_pcap_bytes(1);
        // Truncate: keep header + record header but remove packet data.
        data.truncate(PCAP_GLOBAL_HEADER_SIZE + PCAP_RECORD_HEADER_SIZE + 5);
        let err = stream_packets(Cursor::new(data), |_, _| ControlFlow::Continue(())).unwrap_err();
        assert!(matches!(err, PcapError::Truncated { .. }));
    }

    #[test]
    fn stream_matches_build_index() {
        let data = build_pcap_bytes(20);
        // Collect via build_index
        let index_records = build_index(&data).unwrap();
        let mut index_data: Vec<Vec<u8>> = Vec::new();
        for rec in &index_records {
            let start = rec.data_offset as usize;
            let end = start + rec.captured_len as usize;
            index_data.push(data[start..end].to_vec());
        }

        // Collect via stream_packets
        let mut stream_records = Vec::new();
        let mut stream_data = Vec::new();
        stream_packets(Cursor::new(data), |rec, pkt| {
            stream_records.push(rec.clone());
            stream_data.push(pkt.to_vec());
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(index_records.len(), stream_records.len());
        for (i, (ir, sr)) in index_records.iter().zip(stream_records.iter()).enumerate() {
            assert_eq!(ir.captured_len, sr.captured_len, "packet {i} captured_len");
            assert_eq!(ir.original_len, sr.original_len, "packet {i} original_len");
            assert_eq!(ir.timestamp_secs, sr.timestamp_secs, "packet {i} ts_secs");
            assert_eq!(
                ir.timestamp_usecs, sr.timestamp_usecs,
                "packet {i} ts_usecs"
            );
            assert_eq!(ir.link_type, sr.link_type, "packet {i} link_type");
            assert_eq!(index_data[i], stream_data[i], "packet {i} data");
        }
    }
}
