//! Classic pcap file writer.
//!
//! Writes the standard little-endian pcap format (magic `0xA1B2C3D4`).
//!
//! ## References
//! - Pcap file format: <https://wiki.wireshark.org/Development/LibpcapFileFormat>

use std::io::Write;

use crate::{PacketRecord, PcapError};

/// Writes packets in classic pcap (little-endian) format.
///
/// # Example
///
/// ```no_run
/// use packet_dissector_pcap::{PacketRecord, PcapWriter};
///
/// let mut writer = PcapWriter::new(std::fs::File::create("out.pcap").unwrap(), 1).unwrap();
/// writer.write_packet(&PacketRecord {
///     data_offset: 0,
///     captured_len: 4,
///     original_len: 4,
///     timestamp_secs: 1000,
///     timestamp_usecs: 0,
///     link_type: 1,
/// }, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
/// writer.finish().unwrap();
/// ```
pub struct PcapWriter<W: Write> {
    inner: W,
    count: usize,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new pcap writer with the given link type.
    ///
    /// Writes the 24-byte global header immediately.
    pub fn new(mut writer: W, link_type: u32) -> Result<Self, PcapError> {
        // Pcap global header (24 bytes, little-endian).
        writer.write_all(&0xA1B2C3D4u32.to_le_bytes())?; // magic
        writer.write_all(&2u16.to_le_bytes())?; // version major
        writer.write_all(&4u16.to_le_bytes())?; // version minor
        writer.write_all(&0i32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&262144u32.to_le_bytes())?; // snaplen
        writer.write_all(&link_type.to_le_bytes())?; // link type
        Ok(Self {
            inner: writer,
            count: 0,
        })
    }

    /// Write a single packet record and its data.
    ///
    /// Note: the classic pcap format stores timestamps as 32-bit unsigned
    /// integers. Values of [`PacketRecord::timestamp_secs`] beyond `u32::MAX`
    /// (year 2106) will wrap. Use pcapng for timestamps beyond that range.
    pub fn write_packet(&mut self, record: &PacketRecord, data: &[u8]) -> Result<(), PcapError> {
        // Pcap record header (16 bytes, little-endian).
        self.inner
            .write_all(&(record.timestamp_secs as u32).to_le_bytes())?;
        self.inner
            .write_all(&record.timestamp_usecs.to_le_bytes())?;
        self.inner.write_all(&record.captured_len.to_le_bytes())?;
        self.inner.write_all(&record.original_len.to_le_bytes())?;
        self.inner.write_all(data)?;
        self.count += 1;
        Ok(())
    }

    /// Return the number of packets written so far.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Flush and return the inner writer.
    pub fn finish(mut self) -> Result<W, PcapError> {
        self.inner.flush()?;
        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::build_index;

    #[test]
    fn write_empty() {
        let mut buf = Vec::new();
        let writer = PcapWriter::new(&mut buf, 1).unwrap();
        assert_eq!(writer.count(), 0);
        writer.finish().unwrap();

        // Should produce a valid pcap with 0 packets.
        let records = build_index(&buf).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn write_single_packet() {
        let mut buf = Vec::new();
        let mut writer = PcapWriter::new(&mut buf, 1).unwrap();
        let data = [0xde, 0xad, 0xbe, 0xef];
        writer
            .write_packet(
                &PacketRecord {
                    data_offset: 0,
                    captured_len: 4,
                    original_len: 4,
                    timestamp_secs: 1000,
                    timestamp_usecs: 500,
                    link_type: 1,
                },
                &data,
            )
            .unwrap();
        assert_eq!(writer.count(), 1);
        writer.finish().unwrap();

        let records = build_index(&buf).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].captured_len, 4);
        assert_eq!(records[0].timestamp_secs, 1000);
        assert_eq!(records[0].timestamp_usecs, 500);
    }

    #[test]
    fn write_roundtrip() {
        // Build a pcap, read it, write it, read it again, compare.
        let original_data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let record = PacketRecord {
            data_offset: 0,
            captured_len: 5,
            original_len: 5,
            timestamp_secs: 42,
            timestamp_usecs: 123456,
            link_type: 1,
        };

        let mut buf1 = Vec::new();
        let mut w1 = PcapWriter::new(&mut buf1, 1).unwrap();
        w1.write_packet(&record, &original_data).unwrap();
        w1.finish().unwrap();

        // Read back.
        let records1 = build_index(&buf1).unwrap();
        assert_eq!(records1.len(), 1);
        let r = &records1[0];
        let start = r.data_offset as usize;
        let end = start + r.captured_len as usize;
        let read_data = &buf1[start..end];
        assert_eq!(read_data, &original_data);

        // Write again from the read records.
        let mut buf2 = Vec::new();
        let mut w2 = PcapWriter::new(&mut buf2, 1).unwrap();
        w2.write_packet(r, read_data).unwrap();
        w2.finish().unwrap();

        // The two outputs should be identical.
        assert_eq!(buf1, buf2);
    }
}
