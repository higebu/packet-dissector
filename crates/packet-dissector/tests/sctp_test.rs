//! # RFC 9260 (SCTP) Coverage
//!
//! | RFC Section | Description                          | Test                                  |
//! |-------------|--------------------------------------|---------------------------------------|
//! | 3           | Source Port, Destination Port         | parse_sctp_basic                      |
//! | 3           | Verification Tag                     | parse_sctp_basic                      |
//! | 3           | Checksum                             | parse_sctp_basic                      |
//! | 3.1         | Source port 0 MUST NOT be used       | parse_sctp_port_zero_src              |
//! | 3.1         | Destination port 0 MUST NOT be used  | parse_sctp_port_zero_dst              |
//! | 3.2         | Chunk Type, Flags, Length, Value      | parse_sctp_single_chunk               |
//! | 3.2         | Multiple chunks                      | parse_sctp_multiple_chunks            |
//! | 3.2         | Chunk padding to 4-byte boundary     | parse_sctp_chunk_padding              |
//! | 3.2         | Chunk Length < 4 invalid              | parse_sctp_invalid_chunk_length       |
//! | 3.2         | Chunk truncated                      | parse_sctp_truncated_chunk            |
//! | 3.3.1       | DATA chunk embedded payload           | sctp_data_chunk_embedded_payload      |
//! | 3.3.1       | DATA chunk with preceding chunks      | sctp_data_chunk_with_preceding_chunks |
//! | —           | Header only (no chunks)              | parse_sctp_header_only                |
//! | —           | No DATA chunk → no embedded payload  | sctp_no_data_chunk_no_payload         |
//! | —           | Truncated common header              | parse_sctp_truncated                  |
//! | —           | Offset handling                      | parse_sctp_with_offset                |
//! | —           | Dissector metadata                   | sctp_dissector_metadata               |
//! | —           | Next dissector by port               | parse_sctp_next_dissector_by_port     |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::sctp::SctpDissector;

/// Build a minimal SCTP packet with common header only (12 bytes).
fn build_sctp_header(src_port: u16, dst_port: u16, vtag: u32, checksum: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 12];
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[4..8].copy_from_slice(&vtag.to_be_bytes());
    pkt[8..12].copy_from_slice(&checksum.to_be_bytes());
    pkt
}

/// Append a chunk to the packet. Adds padding to 4-byte boundary.
fn append_chunk(pkt: &mut Vec<u8>, chunk_type: u8, flags: u8, value: &[u8]) {
    let length = 4 + value.len();
    pkt.push(chunk_type);
    pkt.push(flags);
    pkt.extend_from_slice(&(length as u16).to_be_bytes());
    pkt.extend_from_slice(value);
    // Pad to 4-byte boundary
    let padding = (4 - (length % 4)) % 4;
    if padding > 0 {
        pkt.resize(pkt.len() + padding, 0);
    }
}

/// Get a field value from a chunk Object by chunk index and field name.
fn chunk_field_value<'a>(
    buf: &'a packet_dissector::packet::DissectBuffer<'_>,
    layer: &packet_dissector::packet::Layer,
    chunk_index: usize,
    field_name: &str,
) -> Option<FieldValue<'a>> {
    let chunks_field = buf.field_by_name(layer, "chunks")?;
    let FieldValue::Array(ref arr_range) = chunks_field.value else {
        return None;
    };
    let arr = buf.nested_fields(arr_range);
    let objects: Vec<_> = arr.iter().filter(|f| f.value.is_object()).collect();
    let obj = objects.get(chunk_index)?;
    let FieldValue::Object(ref obj_range) = obj.value else {
        return None;
    };
    let fields = buf.nested_fields(obj_range);
    fields
        .iter()
        .find(|f| f.name() == field_name)
        .map(|f| f.value.clone())
}

#[test]
fn parse_sctp_basic() {
    let data = build_sctp_header(12345, 80, 0xAABBCCDD, 0x11223344);
    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 12);

    let layer = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(layer.name, "SCTP");
    assert_eq!(layer.range, 0..12);

    assert_eq!(
        buf.field_by_name(layer, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(layer, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
    assert_eq!(
        buf.field_by_name(layer, "verification_tag").unwrap().value,
        FieldValue::U32(0xAABBCCDD)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U32(0x11223344)
    );
}

#[test]
fn parse_sctp_header_only() {
    let data = build_sctp_header(1, 2, 0, 0);
    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 12);
    let layer = buf.layer_by_name("SCTP").unwrap();
    // Only 4 fields (common header), no chunks field
    assert_eq!(buf.layer_fields(layer).len(), 4);
    assert!(buf.field_by_name(layer, "chunks").is_none());
}

#[test]
fn parse_sctp_single_chunk() {
    let mut data = build_sctp_header(1, 2, 0, 0);
    // DATA chunk (type=0, flags=0x03, value=4 bytes)
    append_chunk(&mut data, 0, 0x03, &[0xDE, 0xAD, 0xBE, 0xEF]);

    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    // 12 (header) + 8 (chunk: 4 header + 4 value, already 4-byte aligned)
    assert_eq!(result.bytes_consumed, 20);

    let layer = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "type").unwrap(),
        FieldValue::U8(0)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "flags").unwrap(),
        FieldValue::U8(0x03)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "length").unwrap(),
        FieldValue::U16(8)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "value").unwrap(),
        FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
    );
}

#[test]
fn parse_sctp_multiple_chunks() {
    let mut data = build_sctp_header(1, 2, 0, 0);
    // INIT chunk (type=1)
    append_chunk(&mut data, 1, 0, &[0x01, 0x02, 0x03, 0x04]);
    // SACK chunk (type=3)
    append_chunk(&mut data, 3, 0, &[0x05, 0x06]);

    let mut buf = DissectBuffer::new();
    SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "type").unwrap(),
        FieldValue::U8(1)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 1, "type").unwrap(),
        FieldValue::U8(3)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 1, "length").unwrap(),
        FieldValue::U16(6) // 4 header + 2 value
    );
}

#[test]
fn parse_sctp_chunk_padding() {
    // A chunk with 5-byte value (length=9) must be padded to 12 bytes
    let mut data = build_sctp_header(1, 2, 0, 0);
    append_chunk(&mut data, 0, 0, &[0x01, 0x02, 0x03, 0x04, 0x05]);
    // Add another chunk after the padded one to verify padding is skipped correctly
    append_chunk(&mut data, 1, 0, &[0xAA, 0xBB]);

    let mut buf = DissectBuffer::new();
    SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("SCTP").unwrap();
    // First chunk: length=9 (value=5 bytes), padded to 12
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "length").unwrap(),
        FieldValue::U16(9)
    );
    // Second chunk should be found after padding
    assert_eq!(
        chunk_field_value(&buf, layer, 1, "type").unwrap(),
        FieldValue::U8(1)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 1, "value").unwrap(),
        FieldValue::Bytes(&[0xAA, 0xBB])
    );
}

#[test]
fn parse_sctp_invalid_chunk_length() {
    let mut data = build_sctp_header(1, 2, 0, 0);
    // Chunk with length=2 (invalid, must be >= 4)
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);

    let mut buf = DissectBuffer::new();
    let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { .. }
    ));
}

#[test]
fn parse_sctp_truncated_chunk() {
    let mut data = build_sctp_header(1, 2, 0, 0);
    // Chunk says length=20 but only 8 bytes available
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00]);

    let mut buf = DissectBuffer::new();
    let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated { .. }
    ));
}

#[test]
fn parse_sctp_truncated() {
    let data = [0u8; 8]; // Only 8 bytes, need 12
    let mut buf = DissectBuffer::new();
    let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 12,
            actual: 8
        }
    ));
}

#[test]
fn parse_sctp_with_offset() {
    let data = build_sctp_header(80, 443, 0, 0);
    let mut buf = DissectBuffer::new();
    SctpDissector.dissect(&data, &mut buf, 34).unwrap();

    let layer = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(layer.range, 34..46);
    assert_eq!(buf.field_by_name(layer, "src_port").unwrap().range, 34..36);
    assert_eq!(buf.field_by_name(layer, "dst_port").unwrap().range, 36..38);
    assert_eq!(
        buf.field_by_name(layer, "verification_tag").unwrap().range,
        38..42
    );
    assert_eq!(buf.field_by_name(layer, "checksum").unwrap().range, 42..46);
}

#[test]
fn parse_sctp_next_dissector_by_port() {
    // Carries both src and dst ports; registry dispatches low→high
    let data = build_sctp_header(54321, 80, 0, 0);
    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.next, DispatchHint::BySctpPort(54321, 80));

    let data2 = build_sctp_header(80, 54321, 0, 0);
    let mut buf2 = DissectBuffer::new();
    let result2 = SctpDissector.dissect(&data2, &mut buf2, 0).unwrap();
    assert_eq!(result2.next, DispatchHint::BySctpPort(80, 54321));
}

#[test]
fn sctp_dissector_metadata() {
    let d = SctpDissector;
    assert_eq!(d.name(), "Stream Control Transmission Protocol");
    assert_eq!(d.short_name(), "SCTP");
}

/// RFC 9260, Section 3.1: Source port 0 MUST NOT be used.
#[test]
fn parse_sctp_port_zero_src() {
    let data = build_sctp_header(0, 80, 0, 0);
    let mut buf = DissectBuffer::new();
    let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { .. }
    ));
}

/// RFC 9260, Section 3.1: Destination port 0 MUST NOT be used.
#[test]
fn parse_sctp_port_zero_dst() {
    let data = build_sctp_header(80, 0, 0, 0);
    let mut buf = DissectBuffer::new();
    let err = SctpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue { .. }
    ));
}

/// Chunk with empty value (length=4, just the chunk header)
#[test]
fn parse_sctp_chunk_no_value() {
    let mut data = build_sctp_header(1, 2, 0, 0);
    // HEARTBEAT ACK (type=5), no value
    append_chunk(&mut data, 5, 0, &[]);

    let mut buf = DissectBuffer::new();
    SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("SCTP").unwrap();
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "type").unwrap(),
        FieldValue::U8(5)
    );
    assert_eq!(
        chunk_field_value(&buf, layer, 0, "length").unwrap(),
        FieldValue::U16(4)
    );
    // No value field for empty chunks
    assert!(chunk_field_value(&buf, layer, 0, "value").is_none());
}

// ── RFC 9260, Section 3.3.1 — DATA chunk embedded payload tests ─────────

/// Append a DATA chunk (type=0) with full RFC 9260 Section 3.3.1 header.
/// DATA chunk header: Type(1) + Flags(1) + Length(2) + TSN(4) + Stream ID(2) +
/// Stream Seq(2) + PPI(4) = 16 bytes, followed by user data.
fn append_data_chunk(
    pkt: &mut Vec<u8>,
    flags: u8,
    tsn: u32,
    stream_id: u16,
    stream_seq: u16,
    ppi: u32,
    user_data: &[u8],
) {
    let length = 16 + user_data.len();
    pkt.push(0); // type = DATA
    pkt.push(flags);
    pkt.extend_from_slice(&(length as u16).to_be_bytes());
    pkt.extend_from_slice(&tsn.to_be_bytes());
    pkt.extend_from_slice(&stream_id.to_be_bytes());
    pkt.extend_from_slice(&stream_seq.to_be_bytes());
    pkt.extend_from_slice(&ppi.to_be_bytes());
    pkt.extend_from_slice(user_data);
    // Pad to 4-byte boundary
    let padding = (4 - (length % 4)) % 4;
    let new_len = pkt.len() + padding;
    pkt.resize(new_len, 0u8);
}

#[test]
fn sctp_data_chunk_embedded_payload() {
    // RFC 9260, Section 3.3.1 — DATA chunk with embedded user data.
    // The dissector should return embedded_payload pointing to the user data.
    let user_data =
        b"\x01\x00\x00\x14\xC0\x00\x01\x3C\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02";
    let mut data = build_sctp_header(3868, 3868, 0xAABBCCDD, 0);
    append_data_chunk(&mut data, 0x03, 1, 0, 0, 46, user_data);

    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    // embedded_payload should point to the user data within the DATA chunk.
    // SCTP header = 12, DATA chunk header = 16, so user data starts at 28.
    assert!(result.embedded_payload.is_some());
    let range = result.embedded_payload.unwrap();
    assert_eq!(range.start, 28);
    assert_eq!(range.end, 28 + user_data.len());
    // Verify the bytes at that range match user data
    assert_eq!(&data[range.start..range.end], user_data);
}

#[test]
fn sctp_no_data_chunk_no_payload() {
    // INIT and SACK only — no DATA chunk means no embedded_payload.
    let mut data = build_sctp_header(3868, 3868, 0, 0);
    append_chunk(&mut data, 1, 0, &[0x01, 0x02, 0x03, 0x04]); // INIT
    append_chunk(&mut data, 3, 0, &[0x05, 0x06, 0x07, 0x08]); // SACK

    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert!(result.embedded_payload.is_none());
}

#[test]
fn sctp_data_chunk_with_preceding_chunks() {
    // SACK chunk before DATA chunk — embedded_payload should still point
    // to the DATA chunk's user data (not the SACK).
    let user_data = b"DIAMETER_PAYLOAD";
    let mut data = build_sctp_header(3868, 3868, 0xAABBCCDD, 0);
    // SACK chunk (type=3, 8 bytes value)
    append_chunk(&mut data, 3, 0, &[0x00; 8]);
    // DATA chunk with user_data
    let data_chunk_start = data.len();
    append_data_chunk(&mut data, 0x03, 42, 1, 0, 46, user_data);

    let mut buf = DissectBuffer::new();
    let result = SctpDissector.dissect(&data, &mut buf, 0).unwrap();

    assert!(result.embedded_payload.is_some());
    let range = result.embedded_payload.unwrap();
    // DATA chunk starts at data_chunk_start, user data at +16
    assert_eq!(range.start, data_chunk_start + 16);
    assert_eq!(range.end, data_chunk_start + 16 + user_data.len());
    assert_eq!(&data[range.start..range.end], user_data);
}
