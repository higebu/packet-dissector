//! Pcap/pcapng reader and writer.
//!
//! Provides zero-copy reading of pcap and pcapng capture files, and writing
//! of classic pcap files.  No external dependencies beyond `thiserror`.
//!
//! ## References
//! - Pcap: <https://www.tcpdump.org/linktypes.html>
//! - Pcapng: <https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html>

#![deny(missing_docs)]

mod reader;
mod writer;

pub use reader::{
    IndexFormat, IndexState, PcapngIfaceInfo, build_index, build_index_chunk, build_index_start,
    stream_packets,
};
pub use writer::PcapWriter;

/// Per-packet metadata extracted from pcap/pcapng headers.
#[derive(Debug, Clone)]
pub struct PacketRecord {
    /// Byte offset of the packet *data* (not the record header) in the file.
    pub data_offset: u64,
    /// Captured length in bytes.
    pub captured_len: u32,
    /// Original (on-wire) length in bytes.
    pub original_len: u32,
    /// Timestamp seconds since the Unix epoch.
    pub timestamp_secs: u64,
    /// Sub-second part of the timestamp in microseconds.
    pub timestamp_usecs: u32,
    /// Link-layer type (e.g., 1 = Ethernet).
    pub link_type: u16,
}

/// Errors produced by pcap reading and writing operations.
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    /// The file is too small to contain a valid header.
    #[error("file too small to detect format")]
    TooSmall,
    /// The magic number does not match any known pcap/pcapng format.
    #[error("unsupported capture format")]
    UnsupportedFormat,
    /// The file is truncated.
    #[error("truncated file at offset {offset}")]
    Truncated {
        /// Byte offset where truncation was detected.
        offset: usize,
    },
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Default link type when no Interface Description Block is present.
pub(crate) const LINKTYPE_ETHERNET: u16 = 1;
