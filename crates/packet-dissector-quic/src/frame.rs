//! QUIC frame parser.
//!
//! Parses the frames in a decrypted packet payload. Byte-valued frame
//! fields are copied to the scratch buffer because the plaintext does not
//! live in the packet data.
//!
//! ## References
//! - RFC 9000, Section 12.4 (Frames and Frame Types): <https://www.rfc-editor.org/rfc/rfc9000#section-12.4>
//! - RFC 9000, Section 19 (Frame Types and Formats): <https://www.rfc-editor.org/rfc/rfc9000#section-19>
//! - RFC 9221, Section 4 (DATAGRAM Frame Types): <https://www.rfc-editor.org/rfc/rfc9221#section-4>

// Only the Initial decryption path calls the parser today.
#![cfg_attr(not(any(feature = "decrypt", test)), allow(dead_code))]

use core::ops::Range;

use packet_dissector_core::field::{Field, FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

use crate::decode_varint;

/// Frame type values.
///
/// RFC 9000, Section 12.4, Table 3 — <https://www.rfc-editor.org/rfc/rfc9000#section-12.4>
const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_RESET_STREAM: u64 = 0x04;
const FRAME_STOP_SENDING: u64 = 0x05;
const FRAME_CRYPTO: u64 = 0x06;
const FRAME_NEW_TOKEN: u64 = 0x07;
const FRAME_STREAM_MIN: u64 = 0x08;
const FRAME_STREAM_MAX: u64 = 0x0f;
const FRAME_MAX_DATA: u64 = 0x10;
const FRAME_MAX_STREAM_DATA: u64 = 0x11;
const FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
const FRAME_MAX_STREAMS_UNI: u64 = 0x13;
const FRAME_DATA_BLOCKED: u64 = 0x14;
const FRAME_STREAM_DATA_BLOCKED: u64 = 0x15;
const FRAME_STREAMS_BLOCKED_BIDI: u64 = 0x16;
const FRAME_STREAMS_BLOCKED_UNI: u64 = 0x17;
const FRAME_NEW_CONNECTION_ID: u64 = 0x18;
const FRAME_RETIRE_CONNECTION_ID: u64 = 0x19;
const FRAME_PATH_CHALLENGE: u64 = 0x1a;
const FRAME_PATH_RESPONSE: u64 = 0x1b;
const FRAME_CONNECTION_CLOSE_TRANSPORT: u64 = 0x1c;
const FRAME_CONNECTION_CLOSE_APPLICATION: u64 = 0x1d;
const FRAME_HANDSHAKE_DONE: u64 = 0x1e;
/// RFC 9221, Section 4 — <https://www.rfc-editor.org/rfc/rfc9221#section-4>
const FRAME_DATAGRAM: u64 = 0x30;
const FRAME_DATAGRAM_LEN: u64 = 0x31;

/// STREAM frame type bits.
///
/// RFC 9000, Section 19.8 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.8>
const STREAM_OFF_BIT: u64 = 0x04;
const STREAM_LEN_BIT: u64 = 0x02;
const STREAM_FIN_BIT: u64 = 0x01;

/// PATH_CHALLENGE / PATH_RESPONSE Data length (64 bits).
///
/// RFC 9000, Section 19.17 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.17>
const PATH_DATA_LEN: usize = 8;

/// Stateless Reset Token length (128 bits).
///
/// RFC 9000, Section 19.15 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.15>
const STATELESS_RESET_TOKEN_LEN: usize = 16;

/// Name of a frame type.
///
/// RFC 9000, Section 12.4, Table 3 — <https://www.rfc-editor.org/rfc/rfc9000#section-12.4>
/// RFC 9221, Section 4 — <https://www.rfc-editor.org/rfc/rfc9221#section-4>
pub(crate) fn frame_type_name(frame_type: u64) -> Option<&'static str> {
    Some(match frame_type {
        FRAME_PADDING => "PADDING",
        FRAME_PING => "PING",
        FRAME_ACK | FRAME_ACK_ECN => "ACK",
        FRAME_RESET_STREAM => "RESET_STREAM",
        FRAME_STOP_SENDING => "STOP_SENDING",
        FRAME_CRYPTO => "CRYPTO",
        FRAME_NEW_TOKEN => "NEW_TOKEN",
        FRAME_STREAM_MIN..=FRAME_STREAM_MAX => "STREAM",
        FRAME_MAX_DATA => "MAX_DATA",
        FRAME_MAX_STREAM_DATA => "MAX_STREAM_DATA",
        FRAME_MAX_STREAMS_BIDI | FRAME_MAX_STREAMS_UNI => "MAX_STREAMS",
        FRAME_DATA_BLOCKED => "DATA_BLOCKED",
        FRAME_STREAM_DATA_BLOCKED => "STREAM_DATA_BLOCKED",
        FRAME_STREAMS_BLOCKED_BIDI | FRAME_STREAMS_BLOCKED_UNI => "STREAMS_BLOCKED",
        FRAME_NEW_CONNECTION_ID => "NEW_CONNECTION_ID",
        FRAME_RETIRE_CONNECTION_ID => "RETIRE_CONNECTION_ID",
        FRAME_PATH_CHALLENGE => "PATH_CHALLENGE",
        FRAME_PATH_RESPONSE => "PATH_RESPONSE",
        FRAME_CONNECTION_CLOSE_TRANSPORT | FRAME_CONNECTION_CLOSE_APPLICATION => "CONNECTION_CLOSE",
        FRAME_HANDSHAKE_DONE => "HANDSHAKE_DONE",
        FRAME_DATAGRAM | FRAME_DATAGRAM_LEN => "DATAGRAM",
        _ => return None,
    })
}

fn frame_type_display(value: &FieldValue<'_>, _siblings: &[Field<'_>]) -> Option<&'static str> {
    match value {
        FieldValue::U64(t) => frame_type_name(*t),
        _ => None,
    }
}

const FC_FRAME_TYPE: usize = 0;
const FC_PADDING_LENGTH: usize = 1;
const FC_LARGEST_ACKNOWLEDGED: usize = 2;
const FC_ACK_DELAY: usize = 3;
const FC_ACK_RANGE_COUNT: usize = 4;
const FC_FIRST_ACK_RANGE: usize = 5;
const FC_ACK_RANGES: usize = 6;
const FC_ECT0_COUNT: usize = 7;
const FC_ECT1_COUNT: usize = 8;
const FC_ECN_CE_COUNT: usize = 9;
const FC_STREAM_ID: usize = 10;
const FC_APPLICATION_ERROR_CODE: usize = 11;
const FC_FINAL_SIZE: usize = 12;
const FC_OFFSET: usize = 13;
const FC_LENGTH: usize = 14;
const FC_CRYPTO_DATA: usize = 15;
const FC_TOKEN_LENGTH: usize = 16;
const FC_TOKEN: usize = 17;
const FC_FIN: usize = 18;
const FC_STREAM_DATA: usize = 19;
const FC_MAXIMUM_DATA: usize = 20;
const FC_MAXIMUM_STREAM_DATA: usize = 21;
const FC_MAXIMUM_STREAMS: usize = 22;
const FC_SEQUENCE_NUMBER: usize = 23;
const FC_RETIRE_PRIOR_TO: usize = 24;
const FC_CONNECTION_ID_LENGTH: usize = 25;
const FC_CONNECTION_ID: usize = 26;
const FC_STATELESS_RESET_TOKEN: usize = 27;
const FC_DATA: usize = 28;
const FC_ERROR_CODE: usize = 29;
const FC_ERROR_FRAME_TYPE: usize = 30;
const FC_REASON_PHRASE_LENGTH: usize = 31;
const FC_REASON_PHRASE: usize = 32;

/// Fields of an ACK Range (RFC 9000, Section 19.3.1 —
/// <https://www.rfc-editor.org/rfc/rfc9000#section-19.3.1>).
static ACK_RANGE_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("gap", "Gap", FieldType::U64),
    FieldDescriptor::new("ack_range_length", "ACK Range Length", FieldType::U64),
];

static ACK_RANGE_OBJECT: FieldDescriptor =
    FieldDescriptor::new("ack_range", "ACK Range", FieldType::Object)
        .with_children(ACK_RANGE_CHILDREN);

/// Union of the fields of all frame types (RFC 9000, Section 19 —
/// <https://www.rfc-editor.org/rfc/rfc9000#section-19>). Every field is
/// optional because which ones appear depends on `frame_type`.
pub(crate) static FRAME_CHILDREN: &[FieldDescriptor] = &[
    FieldDescriptor::new("frame_type", "Frame Type", FieldType::U64)
        .optional()
        .with_display_fn(frame_type_display),
    FieldDescriptor::new("padding_length", "Padding Length", FieldType::U64).optional(),
    FieldDescriptor::new(
        "largest_acknowledged",
        "Largest Acknowledged",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new("ack_delay", "ACK Delay", FieldType::U64).optional(),
    FieldDescriptor::new("ack_range_count", "ACK Range Count", FieldType::U64).optional(),
    FieldDescriptor::new("first_ack_range", "First ACK Range", FieldType::U64).optional(),
    FieldDescriptor::new("ack_ranges", "ACK Ranges", FieldType::Array)
        .optional()
        .with_children(ACK_RANGE_CHILDREN),
    FieldDescriptor::new("ect0_count", "ECT0 Count", FieldType::U64).optional(),
    FieldDescriptor::new("ect1_count", "ECT1 Count", FieldType::U64).optional(),
    FieldDescriptor::new("ecn_ce_count", "ECN-CE Count", FieldType::U64).optional(),
    FieldDescriptor::new("stream_id", "Stream ID", FieldType::U64).optional(),
    FieldDescriptor::new(
        "application_error_code",
        "Application Protocol Error Code",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new("final_size", "Final Size", FieldType::U64).optional(),
    FieldDescriptor::new("offset", "Offset", FieldType::U64).optional(),
    FieldDescriptor::new("length", "Length", FieldType::U64).optional(),
    FieldDescriptor::new("crypto_data", "Crypto Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("token_length", "Token Length", FieldType::U64).optional(),
    FieldDescriptor::new("token", "Token", FieldType::Bytes).optional(),
    FieldDescriptor::new("fin", "FIN", FieldType::U8).optional(),
    FieldDescriptor::new("stream_data", "Stream Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("maximum_data", "Maximum Data", FieldType::U64).optional(),
    FieldDescriptor::new("maximum_stream_data", "Maximum Stream Data", FieldType::U64).optional(),
    FieldDescriptor::new("maximum_streams", "Maximum Streams", FieldType::U64).optional(),
    FieldDescriptor::new("sequence_number", "Sequence Number", FieldType::U64).optional(),
    FieldDescriptor::new("retire_prior_to", "Retire Prior To", FieldType::U64).optional(),
    FieldDescriptor::new("connection_id_length", "Length", FieldType::U8).optional(),
    FieldDescriptor::new("connection_id", "Connection ID", FieldType::Bytes).optional(),
    FieldDescriptor::new(
        "stateless_reset_token",
        "Stateless Reset Token",
        FieldType::Bytes,
    )
    .optional(),
    FieldDescriptor::new("data", "Data", FieldType::Bytes).optional(),
    FieldDescriptor::new("error_code", "Error Code", FieldType::U64).optional(),
    FieldDescriptor::new("error_frame_type", "Frame Type", FieldType::U64)
        .optional()
        .with_display_fn(frame_type_display),
    FieldDescriptor::new(
        "reason_phrase_length",
        "Reason Phrase Length",
        FieldType::U64,
    )
    .optional(),
    FieldDescriptor::new("reason_phrase", "Reason Phrase", FieldType::Bytes).optional(),
];

static FRAME_OBJECT: FieldDescriptor =
    FieldDescriptor::new("frame", "Frame", FieldType::Object).with_children(FRAME_CHILDREN);

/// Reads fields from the plaintext and pushes them with absolute ranges.
struct FrameReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Absolute offset of `data[0]` in the packet.
    base: usize,
}

impl<'a> FrameReader<'a> {
    fn abs(&self, range: Range<usize>) -> Range<usize> {
        self.base + range.start..self.base + range.end
    }

    /// Read a variable-length integer (RFC 9000, Section 16 —
    /// <https://www.rfc-editor.org/rfc/rfc9000#section-16>).
    fn varint(&mut self) -> Option<(u64, Range<usize>)> {
        let (value, len) = decode_varint(&self.data[self.pos..])?;
        let range = self.abs(self.pos..self.pos + len);
        self.pos += len;
        Some((value, range))
    }

    fn bytes(&mut self, len: usize) -> Option<(&'a [u8], Range<usize>)> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.data.get(self.pos..end)?;
        let range = self.abs(self.pos..end);
        self.pos = end;
        Some((bytes, range))
    }

    fn rest(&mut self) -> (&'a [u8], Range<usize>) {
        let bytes = &self.data[self.pos..];
        let range = self.abs(self.pos..self.data.len());
        self.pos = self.data.len();
        (bytes, range)
    }

    fn push_varint(&mut self, buf: &mut DissectBuffer<'_>, fc: usize) -> Option<u64> {
        let (value, range) = self.varint()?;
        buf.push_field(&FRAME_CHILDREN[fc], FieldValue::U64(value), range);
        Some(value)
    }

    fn push_bytes(&mut self, buf: &mut DissectBuffer<'_>, fc: usize, len: u64) -> Option<()> {
        let (bytes, range) = self.bytes(usize::try_from(len).ok()?)?;
        push_scratch_field(buf, fc, bytes, range);
        Some(())
    }

    fn push_rest(&mut self, buf: &mut DissectBuffer<'_>, fc: usize) {
        let (bytes, range) = self.rest();
        push_scratch_field(buf, fc, bytes, range);
    }
}

fn push_scratch_field(buf: &mut DissectBuffer<'_>, fc: usize, bytes: &[u8], range: Range<usize>) {
    let scratch = buf.push_scratch(bytes);
    buf.push_field(&FRAME_CHILDREN[fc], FieldValue::Scratch(scratch), range);
}

/// Parse the frames in a decrypted packet payload into an Array field
/// described by `frames_fd`. `offset` is the absolute offset of the
/// payload's first byte, so field ranges point at the matching ciphertext
/// bytes (AEAD_AES_128_GCM does not change the length).
///
/// Parsing never fails: when a frame is cut short or has an unknown type,
/// the fields read so far are kept, the remaining bytes are shown as `data`
/// and parsing stops.
pub(crate) fn push_frames(
    buf: &mut DissectBuffer<'_>,
    frames_fd: &'static FieldDescriptor,
    plain: &[u8],
    offset: usize,
) {
    let array_idx = buf.begin_container(
        frames_fd,
        FieldValue::Array(0..0),
        offset..offset + plain.len(),
    );
    let mut reader = FrameReader {
        data: plain,
        pos: 0,
        base: offset,
    };
    while reader.pos < plain.len() {
        let start = reader.pos;
        let obj_idx = buf.begin_container(
            &FRAME_OBJECT,
            FieldValue::Object(0..0),
            offset + start..offset + start,
        );
        let complete = push_frame(buf, &mut reader).is_some();
        if !complete && reader.pos < plain.len() {
            reader.push_rest(buf, FC_DATA);
        }
        buf.end_container(obj_idx);
        if let Some(obj) = buf.field_mut(obj_idx as usize) {
            obj.range.end = offset + reader.pos;
        }
        if !complete {
            break;
        }
    }
    buf.end_container(array_idx);
}

/// Parse one frame. Returns `None` when the frame is cut short or its type
/// is unknown, after pushing whatever fields could be read.
///
/// RFC 9000, Section 19 — <https://www.rfc-editor.org/rfc/rfc9000#section-19>
fn push_frame(buf: &mut DissectBuffer<'_>, r: &mut FrameReader<'_>) -> Option<()> {
    let start = r.pos;
    let (frame_type, type_range) = r.varint()?;
    buf.push_field(
        &FRAME_CHILDREN[FC_FRAME_TYPE],
        FieldValue::U64(frame_type),
        type_range.clone(),
    );

    match frame_type {
        FRAME_PADDING => {
            // RFC 9000, Section 19.1 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.1>
            // A run of PADDING frames is shown as one frame with its length.
            let zeros = r.data[r.pos..].iter().take_while(|&&b| b == 0).count();
            r.pos += zeros;
            buf.push_field(
                &FRAME_CHILDREN[FC_PADDING_LENGTH],
                FieldValue::U64((r.pos - start) as u64),
                r.abs(start..r.pos),
            );
        }
        FRAME_PING | FRAME_HANDSHAKE_DONE => {}
        FRAME_ACK | FRAME_ACK_ECN => {
            // RFC 9000, Section 19.3 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.3>
            r.push_varint(buf, FC_LARGEST_ACKNOWLEDGED)?;
            r.push_varint(buf, FC_ACK_DELAY)?;
            let count = r.push_varint(buf, FC_ACK_RANGE_COUNT)?;
            r.push_varint(buf, FC_FIRST_ACK_RANGE)?;
            if count > 0 {
                push_ack_ranges(buf, r, count)?;
            }
            if frame_type == FRAME_ACK_ECN {
                // RFC 9000, Section 19.3.2 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.3.2>
                r.push_varint(buf, FC_ECT0_COUNT)?;
                r.push_varint(buf, FC_ECT1_COUNT)?;
                r.push_varint(buf, FC_ECN_CE_COUNT)?;
            }
        }
        FRAME_RESET_STREAM => {
            // RFC 9000, Section 19.4 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.4>
            r.push_varint(buf, FC_STREAM_ID)?;
            r.push_varint(buf, FC_APPLICATION_ERROR_CODE)?;
            r.push_varint(buf, FC_FINAL_SIZE)?;
        }
        FRAME_STOP_SENDING => {
            // RFC 9000, Section 19.5 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.5>
            r.push_varint(buf, FC_STREAM_ID)?;
            r.push_varint(buf, FC_APPLICATION_ERROR_CODE)?;
        }
        FRAME_CRYPTO => {
            // RFC 9000, Section 19.6 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.6>
            r.push_varint(buf, FC_OFFSET)?;
            let len = r.push_varint(buf, FC_LENGTH)?;
            r.push_bytes(buf, FC_CRYPTO_DATA, len)?;
        }
        FRAME_NEW_TOKEN => {
            // RFC 9000, Section 19.7 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.7>
            let len = r.push_varint(buf, FC_TOKEN_LENGTH)?;
            r.push_bytes(buf, FC_TOKEN, len)?;
        }
        FRAME_STREAM_MIN..=FRAME_STREAM_MAX => {
            // RFC 9000, Section 19.8 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.8>
            buf.push_field(
                &FRAME_CHILDREN[FC_FIN],
                FieldValue::U8(u8::from(frame_type & STREAM_FIN_BIT != 0)),
                type_range,
            );
            r.push_varint(buf, FC_STREAM_ID)?;
            if frame_type & STREAM_OFF_BIT != 0 {
                r.push_varint(buf, FC_OFFSET)?;
            }
            if frame_type & STREAM_LEN_BIT != 0 {
                let len = r.push_varint(buf, FC_LENGTH)?;
                r.push_bytes(buf, FC_STREAM_DATA, len)?;
            } else {
                // "If this bit is set to 0, the Length field is absent and
                // the Stream Data field extends to the end of the packet."
                r.push_rest(buf, FC_STREAM_DATA);
            }
        }
        FRAME_MAX_DATA | FRAME_DATA_BLOCKED => {
            // RFC 9000, Sections 19.9 and 19.12 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.9>
            r.push_varint(buf, FC_MAXIMUM_DATA)?;
        }
        FRAME_MAX_STREAM_DATA | FRAME_STREAM_DATA_BLOCKED => {
            // RFC 9000, Sections 19.10 and 19.13 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.10>
            r.push_varint(buf, FC_STREAM_ID)?;
            r.push_varint(buf, FC_MAXIMUM_STREAM_DATA)?;
        }
        FRAME_MAX_STREAMS_BIDI
        | FRAME_MAX_STREAMS_UNI
        | FRAME_STREAMS_BLOCKED_BIDI
        | FRAME_STREAMS_BLOCKED_UNI => {
            // RFC 9000, Sections 19.11 and 19.14 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.11>
            r.push_varint(buf, FC_MAXIMUM_STREAMS)?;
        }
        FRAME_NEW_CONNECTION_ID => {
            // RFC 9000, Section 19.15 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.15>
            r.push_varint(buf, FC_SEQUENCE_NUMBER)?;
            r.push_varint(buf, FC_RETIRE_PRIOR_TO)?;
            let (len, len_range) = r.bytes(1)?;
            let len = len[0];
            buf.push_field(
                &FRAME_CHILDREN[FC_CONNECTION_ID_LENGTH],
                FieldValue::U8(len),
                len_range,
            );
            r.push_bytes(buf, FC_CONNECTION_ID, u64::from(len))?;
            r.push_bytes(
                buf,
                FC_STATELESS_RESET_TOKEN,
                STATELESS_RESET_TOKEN_LEN as u64,
            )?;
        }
        FRAME_RETIRE_CONNECTION_ID => {
            // RFC 9000, Section 19.16 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.16>
            r.push_varint(buf, FC_SEQUENCE_NUMBER)?;
        }
        FRAME_PATH_CHALLENGE | FRAME_PATH_RESPONSE => {
            // RFC 9000, Sections 19.17 and 19.18 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.17>
            r.push_bytes(buf, FC_DATA, PATH_DATA_LEN as u64)?;
        }
        FRAME_CONNECTION_CLOSE_TRANSPORT | FRAME_CONNECTION_CLOSE_APPLICATION => {
            // RFC 9000, Section 19.19 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.19>:
            // "The application-specific variant of CONNECTION_CLOSE (type
            // 0x1d) does not include this field."
            r.push_varint(buf, FC_ERROR_CODE)?;
            if frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT {
                r.push_varint(buf, FC_ERROR_FRAME_TYPE)?;
            }
            let len = r.push_varint(buf, FC_REASON_PHRASE_LENGTH)?;
            r.push_bytes(buf, FC_REASON_PHRASE, len)?;
        }
        FRAME_DATAGRAM => {
            // RFC 9221, Section 4 — <https://www.rfc-editor.org/rfc/rfc9221#section-4>:
            // "if this bit is set to 0, the Length field is absent and the
            // Datagram Data field extends to the end of the packet"
            r.push_rest(buf, FC_DATA);
        }
        FRAME_DATAGRAM_LEN => {
            let len = r.push_varint(buf, FC_LENGTH)?;
            r.push_bytes(buf, FC_DATA, len)?;
        }
        _ => {
            // RFC 9000, Section 12.4 — <https://www.rfc-editor.org/rfc/rfc9000#section-12.4>
            // The length of an unknown frame type cannot be determined, so
            // the rest of the payload is not parsed.
            return None;
        }
    }
    Some(())
}

/// Push the ACK Range array of an ACK frame.
///
/// RFC 9000, Section 19.3.1 — <https://www.rfc-editor.org/rfc/rfc9000#section-19.3.1>
fn push_ack_ranges(buf: &mut DissectBuffer<'_>, r: &mut FrameReader<'_>, count: u64) -> Option<()> {
    let start = r.pos;
    let array_idx = buf.begin_container(
        &FRAME_CHILDREN[FC_ACK_RANGES],
        FieldValue::Array(0..0),
        r.abs(start..start),
    );
    let mut complete = true;
    // Every ACK Range takes at least two bytes, so the loop ends with the
    // data even for a bogus count.
    for _ in 0..count {
        let range_start = r.pos;
        let Some((gap, gap_range)) = r.varint() else {
            complete = false;
            break;
        };
        let obj_idx = buf.begin_container(
            &ACK_RANGE_OBJECT,
            FieldValue::Object(0..0),
            r.abs(range_start..range_start),
        );
        buf.push_field(&ACK_RANGE_CHILDREN[0], FieldValue::U64(gap), gap_range);
        let len = r.varint();
        if let Some((len, len_range)) = len.clone() {
            buf.push_field(&ACK_RANGE_CHILDREN[1], FieldValue::U64(len), len_range);
        }
        buf.end_container(obj_idx);
        if let Some(obj) = buf.field_mut(obj_idx as usize) {
            obj.range.end = r.base + r.pos;
        }
        if len.is_none() {
            complete = false;
            break;
        }
    }
    buf.end_container(array_idx);
    if let Some(array) = buf.field_mut(array_idx as usize) {
        array.range.end = r.base + r.pos;
    }
    complete.then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FD_FRAMES, FIELD_DESCRIPTORS};
    use packet_dissector_core::field::Field;

    // # RFC 9000 §19 / RFC 9221 frame coverage
    //
    // | RFC Section   | Description                        | Test                              |
    // |---------------|------------------------------------|-----------------------------------|
    // | 9000 §12.4    | Frame type names                   | test_frame_type_names             |
    // | 9000 §12.4    | Frame type display function        | test_frame_type_display           |
    // | 9000 §19.3.1  | ACK Ranges cut short               | test_ack_ranges_truncated         |
    // | 9000 §19.15   | NEW_CONNECTION_ID token cut short  | test_new_connection_id_truncated_token |
    // | 9000 §19.1    | PADDING (run collapsed)            | test_padding_and_ping             |
    // | 9000 §19.2    | PING                               | test_padding_and_ping             |
    // | 9000 §19.3    | ACK with ACK Ranges                | test_ack                          |
    // | 9000 §19.3.2  | ACK with ECN Counts                | test_ack_ecn                      |
    // | 9000 §19.4    | RESET_STREAM                       | test_reset_stream_stop_sending    |
    // | 9000 §19.5    | STOP_SENDING                       | test_reset_stream_stop_sending    |
    // | 9000 §19.6    | CRYPTO                             | test_crypto                       |
    // | 9000 §19.7    | NEW_TOKEN                          | test_new_token                    |
    // | 9000 §19.8    | STREAM with OFF/LEN/FIN            | test_stream_off_len_fin           |
    // | 9000 §19.8    | STREAM without LEN (to end)        | test_stream_to_end                |
    // | 9000 §19.9-14 | Flow control frames                | test_flow_control_frames          |
    // | 9000 §19.15   | NEW_CONNECTION_ID                  | test_new_connection_id            |
    // | 9000 §19.16   | RETIRE_CONNECTION_ID               | test_new_connection_id            |
    // | 9000 §19.17-18| PATH_CHALLENGE / PATH_RESPONSE     | test_path_challenge_response      |
    // | 9000 §19.19   | CONNECTION_CLOSE (0x1c, 0x1d)      | test_connection_close             |
    // | 9000 §19.20   | HANDSHAKE_DONE                     | test_handshake_done               |
    // | 9221 §4       | DATAGRAM (0x30, 0x31)              | test_datagram                     |
    // | 9000 §12.4    | Unknown frame type: rest as data   | test_unknown_frame_type           |
    // | ---           | Truncated frame body               | test_truncated_crypto             |
    // | ---           | Truncated frame type varint        | test_truncated_frame_type         |

    const BASE: usize = 100;

    fn parse(plain: &[u8]) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("QUIC", None, FIELD_DESCRIPTORS, 0..BASE + plain.len());
        push_frames(&mut buf, &FIELD_DESCRIPTORS[FD_FRAMES], plain, BASE);
        buf.end_layer();
        buf
    }

    /// The fields of each frame object, in order.
    fn frames<'a>(
        buf: &'a DissectBuffer<'static>,
    ) -> Vec<(&'a Field<'static>, &'a [Field<'static>])> {
        let layer = &buf.layers()[0];
        let array = buf.field_by_name(layer, "frames").unwrap();
        assert_eq!(array.range, BASE..layer.range.end);
        let FieldValue::Array(ref range) = array.value else {
            panic!("expected Array");
        };
        let children = buf.nested_fields(range);
        let mut out = Vec::new();
        let mut i = 0;
        while i < children.len() {
            let FieldValue::Object(ref r) = children[i].value else {
                panic!("expected Object");
            };
            let fields = buf.nested_fields(r);
            out.push((&children[i], fields));
            i += 1 + fields.len();
        }
        out
    }

    fn value<'a>(fields: &'a [Field<'static>], name: &str) -> &'a FieldValue<'static> {
        &fields
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("missing field {name}"))
            .value
    }

    fn u64_of(fields: &[Field<'static>], name: &str) -> u64 {
        match value(fields, name) {
            FieldValue::U64(v) => *v,
            other => panic!("{name}: expected U64, got {other:?}"),
        }
    }

    fn bytes_of<'a>(
        buf: &'a DissectBuffer<'static>,
        fields: &[Field<'static>],
        name: &str,
    ) -> &'a [u8] {
        match value(fields, name) {
            FieldValue::Scratch(r) => &buf.scratch()[r.start as usize..r.end as usize],
            other => panic!("{name}: expected Scratch, got {other:?}"),
        }
    }

    fn has(fields: &[Field<'static>], name: &str) -> bool {
        fields.iter().any(|f| f.name() == name)
    }

    #[test]
    fn test_frame_type_names() {
        // RFC 9000, Section 12.4, Table 3 — https://www.rfc-editor.org/rfc/rfc9000#section-12.4
        let table: &[(u64, &str)] = &[
            (0x00, "PADDING"),
            (0x01, "PING"),
            (0x02, "ACK"),
            (0x03, "ACK"),
            (0x04, "RESET_STREAM"),
            (0x05, "STOP_SENDING"),
            (0x06, "CRYPTO"),
            (0x07, "NEW_TOKEN"),
            (0x08, "STREAM"),
            (0x0f, "STREAM"),
            (0x10, "MAX_DATA"),
            (0x11, "MAX_STREAM_DATA"),
            (0x12, "MAX_STREAMS"),
            (0x13, "MAX_STREAMS"),
            (0x14, "DATA_BLOCKED"),
            (0x15, "STREAM_DATA_BLOCKED"),
            (0x16, "STREAMS_BLOCKED"),
            (0x17, "STREAMS_BLOCKED"),
            (0x18, "NEW_CONNECTION_ID"),
            (0x19, "RETIRE_CONNECTION_ID"),
            (0x1a, "PATH_CHALLENGE"),
            (0x1b, "PATH_RESPONSE"),
            (0x1c, "CONNECTION_CLOSE"),
            (0x1d, "CONNECTION_CLOSE"),
            (0x1e, "HANDSHAKE_DONE"),
            // RFC 9221, Section 4 — https://www.rfc-editor.org/rfc/rfc9221#section-4
            (0x30, "DATAGRAM"),
            (0x31, "DATAGRAM"),
        ];
        for &(frame_type, name) in table {
            assert_eq!(frame_type_name(frame_type), Some(name), "{frame_type:#x}");
        }
        assert_eq!(frame_type_name(0x21), None);
    }

    #[test]
    fn test_frame_type_display() {
        // The `frame_type` and `error_frame_type` fields resolve names
        // through the same display function.
        assert_eq!(
            frame_type_display(&FieldValue::U64(0x06), &[]),
            Some("CRYPTO")
        );
        assert_eq!(frame_type_display(&FieldValue::U64(0x21), &[]), None);
        assert_eq!(frame_type_display(&FieldValue::U8(0x06), &[]), None);
    }

    #[test]
    fn test_new_connection_id_truncated_token() {
        // RFC 9000, Section 19.15 — the 128-bit Stateless Reset Token is cut
        // short: the fields read so far are kept and the rest is data.
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        let mut plain = vec![0x18, 0x01, 0x00, 0x02, 0xc1, 0xc2];
        plain.extend_from_slice(&[0x5a; 5]);
        let buf = parse(&plain);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        assert_eq!(bytes_of(&buf, f[0].1, "connection_id"), &[0xc1, 0xc2]);
        assert!(!has(f[0].1, "stateless_reset_token"));
        assert_eq!(bytes_of(&buf, f[0].1, "data"), &[0x5a; 5]);
    }

    #[test]
    fn test_ack_ranges_truncated() {
        // RFC 9000, Section 19.3.1 — ACK Range Count says 2 but the data
        // ends inside the ranges. Case 1: the second Gap is missing.
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.3.1
        let buf = parse(&[0x02, 0x10, 0x00, 0x02, 0x00, 0x01, 0x01]);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        assert_eq!(u64_of(f[0].1, "ack_range_count"), 2);
        assert_eq!(u64_of(f[0].1, "gap"), 1);
        assert_eq!(u64_of(f[0].1, "ack_range_length"), 1);
        let ranges = f[0].1.iter().find(|x| x.name() == "ack_ranges").unwrap();
        assert_eq!(ranges.range, BASE + 5..BASE + 7);

        // Case 2: the ACK Range Length of the only range is missing.
        let buf = parse(&[0x02, 0x10, 0x00, 0x01, 0x00, 0x01]);
        let f = frames(&buf);
        assert_eq!(u64_of(f[0].1, "gap"), 1);
        assert!(!has(f[0].1, "ack_range_length"));
        assert_eq!(f[0].0.range, BASE..BASE + 6);
    }

    #[test]
    fn test_padding_and_ping() {
        // RFC 9000, Sections 19.1 and 19.2 —
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.1
        let buf = parse(&[0x00, 0x00, 0x00, 0x01, 0x00]);
        let f = frames(&buf);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].0.range, BASE..BASE + 3);
        assert_eq!(u64_of(f[0].1, "frame_type"), 0x00);
        assert_eq!(u64_of(f[0].1, "padding_length"), 3);
        assert_eq!(f[1].0.range, BASE + 3..BASE + 4);
        assert_eq!(u64_of(f[1].1, "frame_type"), 0x01);
        assert_eq!(f[1].1.len(), 1);
        assert_eq!(u64_of(f[2].1, "padding_length"), 1);
    }

    #[test]
    fn test_ack() {
        // RFC 9000, Section 19.3 — https://www.rfc-editor.org/rfc/rfc9000#section-19.3
        let buf = parse(&[0x02, 0x10, 0x05, 0x01, 0x02, 0x01, 0x03]);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        let ack = f[0].1;
        assert_eq!(u64_of(ack, "largest_acknowledged"), 0x10);
        assert_eq!(u64_of(ack, "ack_delay"), 5);
        assert_eq!(u64_of(ack, "ack_range_count"), 1);
        assert_eq!(u64_of(ack, "first_ack_range"), 2);
        assert_eq!(u64_of(ack, "gap"), 1);
        assert_eq!(u64_of(ack, "ack_range_length"), 3);
        assert!(!has(ack, "ect0_count"));
        let ranges = ack.iter().find(|x| x.name() == "ack_ranges").unwrap();
        assert_eq!(ranges.range, BASE + 5..BASE + 7);
    }

    #[test]
    fn test_ack_ecn() {
        // RFC 9000, Section 19.3.2 — https://www.rfc-editor.org/rfc/rfc9000#section-19.3.2
        let buf = parse(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]);
        let f = frames(&buf);
        let ack = f[0].1;
        assert_eq!(u64_of(ack, "ack_range_count"), 0);
        assert!(!has(ack, "ack_ranges"));
        assert_eq!(u64_of(ack, "ect0_count"), 1);
        assert_eq!(u64_of(ack, "ect1_count"), 2);
        assert_eq!(u64_of(ack, "ecn_ce_count"), 3);
    }

    #[test]
    fn test_reset_stream_stop_sending() {
        // RFC 9000, Sections 19.4 and 19.5 —
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.4
        let buf = parse(&[0x04, 0x01, 0x02, 0x03, 0x05, 0x04, 0x05]);
        let f = frames(&buf);
        assert_eq!(u64_of(f[0].1, "stream_id"), 1);
        assert_eq!(u64_of(f[0].1, "application_error_code"), 2);
        assert_eq!(u64_of(f[0].1, "final_size"), 3);
        assert_eq!(u64_of(f[1].1, "stream_id"), 4);
        assert_eq!(u64_of(f[1].1, "application_error_code"), 5);
    }

    #[test]
    fn test_crypto() {
        // RFC 9000, Section 19.6 — https://www.rfc-editor.org/rfc/rfc9000#section-19.6
        let buf = parse(&[0x06, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        let crypto = f[0].1;
        assert_eq!(u64_of(crypto, "offset"), 0);
        assert_eq!(u64_of(crypto, "length"), 5);
        assert_eq!(bytes_of(&buf, crypto, "crypto_data"), b"hello");
        let data = crypto.iter().find(|x| x.name() == "crypto_data").unwrap();
        assert_eq!(data.range, BASE + 3..BASE + 8);
    }

    #[test]
    fn test_new_token() {
        // RFC 9000, Section 19.7 — https://www.rfc-editor.org/rfc/rfc9000#section-19.7
        let buf = parse(&[0x07, 0x02, 0xaa, 0xbb]);
        let f = frames(&buf);
        assert_eq!(u64_of(f[0].1, "token_length"), 2);
        assert_eq!(bytes_of(&buf, f[0].1, "token"), &[0xaa, 0xbb]);
    }

    #[test]
    fn test_stream_off_len_fin() {
        // RFC 9000, Section 19.8 — https://www.rfc-editor.org/rfc/rfc9000#section-19.8
        let buf = parse(&[0x0f, 0x04, 0x10, 0x03, b'a', b'b', b'c', 0x01]);
        let f = frames(&buf);
        assert_eq!(f.len(), 2);
        let s = f[0].1;
        assert_eq!(u64_of(s, "stream_id"), 4);
        assert_eq!(u64_of(s, "offset"), 0x10);
        assert_eq!(u64_of(s, "length"), 3);
        assert_eq!(value(s, "fin"), &FieldValue::U8(1));
        assert_eq!(bytes_of(&buf, s, "stream_data"), b"abc");
        assert_eq!(u64_of(f[1].1, "frame_type"), 0x01);
    }

    #[test]
    fn test_stream_to_end() {
        // RFC 9000, Section 19.8 — without the LEN bit the Stream Data
        // "extends to the end of the packet".
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.8
        let buf = parse(&[0x08, 0x00, b'x', b'y', 0x01]);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        let s = f[0].1;
        assert!(!has(s, "offset"));
        assert!(!has(s, "length"));
        assert_eq!(value(s, "fin"), &FieldValue::U8(0));
        assert_eq!(bytes_of(&buf, s, "stream_data"), &[b'x', b'y', 0x01]);
    }

    #[test]
    fn test_flow_control_frames() {
        // RFC 9000, Sections 19.9 to 19.14 —
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.9
        let buf = parse(&[
            0x10, 0x01, // MAX_DATA
            0x11, 0x02, 0x03, // MAX_STREAM_DATA
            0x12, 0x04, // MAX_STREAMS (bidi)
            0x13, 0x05, // MAX_STREAMS (uni)
            0x14, 0x06, // DATA_BLOCKED
            0x15, 0x07, 0x08, // STREAM_DATA_BLOCKED
            0x16, 0x09, // STREAMS_BLOCKED (bidi)
            0x17, 0x0a, // STREAMS_BLOCKED (uni)
        ]);
        let f = frames(&buf);
        assert_eq!(f.len(), 8);
        assert_eq!(u64_of(f[0].1, "maximum_data"), 1);
        assert_eq!(u64_of(f[1].1, "stream_id"), 2);
        assert_eq!(u64_of(f[1].1, "maximum_stream_data"), 3);
        assert_eq!(u64_of(f[2].1, "maximum_streams"), 4);
        assert_eq!(u64_of(f[3].1, "maximum_streams"), 5);
        assert_eq!(u64_of(f[4].1, "maximum_data"), 6);
        assert_eq!(u64_of(f[5].1, "stream_id"), 7);
        assert_eq!(u64_of(f[5].1, "maximum_stream_data"), 8);
        assert_eq!(u64_of(f[6].1, "maximum_streams"), 9);
        assert_eq!(u64_of(f[7].1, "maximum_streams"), 10);
    }

    #[test]
    fn test_new_connection_id() {
        // RFC 9000, Sections 19.15 and 19.16 —
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        let mut plain = vec![0x18, 0x01, 0x00, 0x04, 0xc1, 0xc2, 0xc3, 0xc4];
        plain.extend_from_slice(&[0x5a; 16]);
        plain.extend_from_slice(&[0x19, 0x02]);
        let buf = parse(&plain);
        let f = frames(&buf);
        assert_eq!(f.len(), 2);
        let n = f[0].1;
        assert_eq!(u64_of(n, "sequence_number"), 1);
        assert_eq!(u64_of(n, "retire_prior_to"), 0);
        assert_eq!(value(n, "connection_id_length"), &FieldValue::U8(4));
        assert_eq!(
            bytes_of(&buf, n, "connection_id"),
            &[0xc1, 0xc2, 0xc3, 0xc4]
        );
        assert_eq!(bytes_of(&buf, n, "stateless_reset_token"), &[0x5a; 16]);
        assert_eq!(u64_of(f[1].1, "sequence_number"), 2);
    }

    #[test]
    fn test_path_challenge_response() {
        // RFC 9000, Sections 19.17 and 19.18 —
        // https://www.rfc-editor.org/rfc/rfc9000#section-19.17
        let mut plain = vec![0x1a];
        plain.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        plain.push(0x1b);
        plain.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        let buf = parse(&plain);
        let f = frames(&buf);
        assert_eq!(bytes_of(&buf, f[0].1, "data"), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(bytes_of(&buf, f[1].1, "data"), &[8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn test_connection_close() {
        // RFC 9000, Section 19.19 — https://www.rfc-editor.org/rfc/rfc9000#section-19.19
        let buf = parse(&[
            0x1c, 0x0a, 0x06, 0x03, b'b', b'a', b'd', // transport close
            0x1d, 0x01, 0x00, // application close, empty reason
        ]);
        let f = frames(&buf);
        assert_eq!(u64_of(f[0].1, "error_code"), 0x0a);
        assert_eq!(u64_of(f[0].1, "error_frame_type"), 0x06);
        assert_eq!(u64_of(f[0].1, "reason_phrase_length"), 3);
        assert_eq!(bytes_of(&buf, f[0].1, "reason_phrase"), b"bad");
        assert_eq!(u64_of(f[1].1, "error_code"), 1);
        assert!(!has(f[1].1, "error_frame_type"));
        assert_eq!(u64_of(f[1].1, "reason_phrase_length"), 0);
    }

    #[test]
    fn test_handshake_done() {
        // RFC 9000, Section 19.20 — https://www.rfc-editor.org/rfc/rfc9000#section-19.20
        let buf = parse(&[0x1e]);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1.len(), 1);
    }

    #[test]
    fn test_datagram() {
        // RFC 9221, Section 4 — https://www.rfc-editor.org/rfc/rfc9221#section-4
        let buf = parse(&[0x31, 0x02, b'a', b'b', 0x30, b'x', b'y', b'z']);
        let f = frames(&buf);
        assert_eq!(f.len(), 2);
        assert_eq!(u64_of(f[0].1, "length"), 2);
        assert_eq!(bytes_of(&buf, f[0].1, "data"), b"ab");
        assert!(!has(f[1].1, "length"));
        assert_eq!(bytes_of(&buf, f[1].1, "data"), b"xyz");
    }

    #[test]
    fn test_unknown_frame_type() {
        // RFC 9000, Section 12.4 — the layout of an unknown frame type is
        // not known, so the rest of the payload is shown as data.
        // https://www.rfc-editor.org/rfc/rfc9000#section-12.4
        let buf = parse(&[0x01, 0x40, 0x21, 0xde, 0xad]);
        let f = frames(&buf);
        assert_eq!(f.len(), 2);
        assert_eq!(u64_of(f[1].1, "frame_type"), 0x21);
        assert_eq!(bytes_of(&buf, f[1].1, "data"), &[0xde, 0xad]);
        assert_eq!(f[1].0.range, BASE + 1..BASE + 5);
    }

    #[test]
    fn test_truncated_crypto() {
        // CRYPTO says 10 bytes but only 2 follow: the fields that were read
        // are kept and parsing stops.
        let buf = parse(&[0x06, 0x00, 0x0a, b'h', b'i']);
        let f = frames(&buf);
        assert_eq!(f.len(), 1);
        assert_eq!(u64_of(f[0].1, "length"), 10);
        assert!(!has(f[0].1, "crypto_data"));
        assert_eq!(bytes_of(&buf, f[0].1, "data"), b"hi");
        assert_eq!(f[0].0.range, BASE..BASE + 5);
    }

    #[test]
    fn test_truncated_frame_type() {
        // A 2-byte frame type varint with one byte left.
        let buf = parse(&[0x01, 0x40]);
        let f = frames(&buf);
        assert_eq!(f.len(), 2);
        assert!(!has(f[1].1, "frame_type"));
        assert_eq!(bytes_of(&buf, f[1].1, "data"), &[0x40]);
    }
}
