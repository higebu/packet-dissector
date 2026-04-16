//! PAP (Password Authentication Protocol) parser.
//!
//! ## References
//! - RFC 1334 (PPP Authentication Protocols): <https://www.rfc-editor.org/rfc/rfc1334>
//!
//! Note: RFC 1334 is obsoleted by RFC 1994 for CHAP only; its PAP definition
//! (Section 2) remains the authoritative specification.

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

// Authenticate-Request fields.
// RFC 1334, Section 2.2.1 — <https://www.rfc-editor.org/rfc/rfc1334#section-2.2.1>
static FD_INLINE_PASSWORD: FieldDescriptor =
    FieldDescriptor::new("password", "Password", FieldType::Bytes)
        .with_format_fn(format_utf8_lossy);
static FD_INLINE_PEER_ID: FieldDescriptor =
    FieldDescriptor::new("peer_id", "Peer-ID", FieldType::Bytes).with_format_fn(format_utf8_lossy);

// Authenticate-Ack / Authenticate-Nak fields.
// RFC 1334, Section 2.2.2 — <https://www.rfc-editor.org/rfc/rfc1334#section-2.2.2>
static FD_INLINE_MESSAGE: FieldDescriptor =
    FieldDescriptor::new("message", "Message", FieldType::Bytes).with_format_fn(format_utf8_lossy);

/// Parse a PAP packet into a DissectBuffer.
///
/// RFC 1334, Section 2.2 — <https://www.rfc-editor.org/rfc/rfc1334#section-2.2>
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((code, length)) =
        crate::parse_header(data, offset, crate::PAP_HEADER_DESCRIPTORS, buf)
    else {
        static FD_RAW: FieldDescriptor = FieldDescriptor::new("data", "Data", FieldType::Bytes);
        buf.push_field(
            &FD_RAW,
            FieldValue::Bytes(data),
            offset..offset + data.len(),
        );
        return;
    };
    if data.len() <= crate::PPP_HEADER_SIZE {
        return;
    }

    // Clip to the declared Length per RFC 1334, Section 2.2 so padding is
    // ignored; fall back to the available buffer when Length overruns it.
    let pap_data = if (length as usize) <= data.len() && length >= crate::PPP_HEADER_SIZE as u16 {
        &data[crate::PPP_HEADER_SIZE..length as usize]
    } else {
        &data[crate::PPP_HEADER_SIZE..]
    };
    let payload_offset = offset + crate::PPP_HEADER_SIZE;

    match code {
        // Authenticate-Request — RFC 1334, Section 2.2.1 —
        // <https://www.rfc-editor.org/rfc/rfc1334#section-2.2.1>
        // Peer-ID-Length (1) + Peer-ID (Peer-ID-Length) +
        // Passwd-Length (1) + Password (Passwd-Length).
        1 => parse_authenticate_request(pap_data, payload_offset, buf),
        // Authenticate-Ack / Authenticate-Nak — RFC 1334, Section 2.2.2 —
        // <https://www.rfc-editor.org/rfc/rfc1334#section-2.2.2>
        // Msg-Length (1) + Message (Msg-Length).
        2 | 3 => parse_authenticate_reply(pap_data, payload_offset, buf),
        _ => {}
    }
}

fn parse_authenticate_request<'pkt>(
    pap_data: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    if pap_data.is_empty() {
        return;
    }
    let peer_id_len = pap_data[0] as usize;
    // Require room for the Peer-ID bytes plus the following Passwd-Length
    // octet. A malformed packet that cannot satisfy this is silently skipped
    // (Postel's Law).
    if 1 + peer_id_len >= pap_data.len() {
        return;
    }
    buf.push_field(
        &FD_INLINE_PEER_ID,
        FieldValue::Bytes(&pap_data[1..1 + peer_id_len]),
        payload_offset + 1..payload_offset + 1 + peer_id_len,
    );
    let pw_offset = 1 + peer_id_len;
    let pw_len = pap_data[pw_offset] as usize;
    if pw_offset + 1 + pw_len <= pap_data.len() {
        buf.push_field(
            &FD_INLINE_PASSWORD,
            FieldValue::Bytes(&pap_data[pw_offset + 1..pw_offset + 1 + pw_len]),
            payload_offset + pw_offset + 1..payload_offset + pw_offset + 1 + pw_len,
        );
    }
}

fn parse_authenticate_reply<'pkt>(
    pap_data: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    if pap_data.is_empty() {
        return;
    }
    let msg_len = pap_data[0] as usize;
    // Bounds-check the declared Msg-Length against the buffer. Postel's Law:
    // malformed replies are silently dropped rather than panicking.
    if 1 + msg_len > pap_data.len() {
        return;
    }
    buf.push_field(
        &FD_INLINE_MESSAGE,
        FieldValue::Bytes(&pap_data[1..1 + msg_len]),
        payload_offset + 1..payload_offset + 1 + msg_len,
    );
}

#[cfg(test)]
mod tests {
    //! # RFC 1334 (PAP) Coverage
    //!
    //! | RFC Section | Description                          | Test                           |
    //! |-------------|--------------------------------------|--------------------------------|
    //! | 2.2         | Packet Format (Code/Id/Length)       | parse_truncated                |
    //! | 2.2.1       | Authenticate-Request                 | parse_authenticate_request     |
    //! | 2.2.1       | Authenticate-Request malformed       | parse_authenticate_request_malformed |
    //! | 2.2.2       | Authenticate-Ack with Message        | parse_authenticate_ack_with_message |
    //! | 2.2.2       | Authenticate-Ack empty Message       | parse_authenticate_ack         |
    //! | 2.2.2       | Authenticate-Nak with Message        | parse_authenticate_nak_with_message |
    //! | —           | Length field clipping                | parse_ack_length_clipping      |

    use super::*;

    fn obj_range(buf: &DissectBuffer<'_>) -> core::ops::Range<u32> {
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        match &fields[0].value {
            FieldValue::Object(r) => r.clone(),
            _ => panic!("expected Object"),
        }
    }

    fn fill_buf<'a>(buf: &mut DissectBuffer<'a>, data: &'a [u8]) {
        buf.begin_layer("test", None, &[], 0..data.len());
        let idx = buf.begin_container(
            &crate::FIELD_DESCRIPTORS[crate::FD_PAYLOAD],
            FieldValue::Object(0..0),
            0..data.len(),
        );
        parse(data, 0, buf);
        buf.end_container(idx);
        buf.end_layer();
    }

    #[test]
    fn parse_authenticate_request() {
        let data = [
            0x01, 0x01, 0x00, 0x0E, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's',
        ];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 5);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Authenticate-Request")
        );
        assert_eq!(f[3].name(), "peer_id");
        assert_eq!(f[3].value, FieldValue::Bytes(b"user" as &[u8]));
        assert_eq!(f[4].name(), "password");
        assert_eq!(f[4].value, FieldValue::Bytes(b"pass" as &[u8]));
    }

    #[test]
    fn parse_authenticate_request_malformed() {
        // Peer-ID-Length declares more bytes than remain — must not panic and
        // must not push any Peer-ID / Password fields.
        #[rustfmt::skip]
        let data = [0x01, 0x01, 0x00, 0x07, 0xFF, b'u', b's'];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 3);
    }

    #[test]
    fn parse_authenticate_ack() {
        // Msg-Length=0, empty Message — the Message field is still emitted as
        // an empty byte slice to represent the declared Msg-Length=0 field.
        let data = [0x02, 0x01, 0x00, 0x05, 0x00];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 4);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Authenticate-Ack")
        );
        assert_eq!(f[3].name(), "message");
        assert_eq!(f[3].value, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_authenticate_ack_with_message() {
        // Code=2, Msg-Length=2, Message="OK"
        #[rustfmt::skip]
        let data = [0x02, 0x01, 0x00, 0x07, 2, b'O', b'K'];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 4);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Authenticate-Ack")
        );
        assert_eq!(f[3].name(), "message");
        assert_eq!(f[3].value, FieldValue::Bytes(b"OK" as &[u8]));
    }

    #[test]
    fn parse_authenticate_nak_with_message() {
        // Code=3, Msg-Length=4, Message="FAIL"
        #[rustfmt::skip]
        let data = [0x03, 0x02, 0x00, 0x09, 4, b'F', b'A', b'I', b'L'];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 4);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Authenticate-Nak")
        );
        assert_eq!(f[3].value, FieldValue::Bytes(b"FAIL" as &[u8]));
    }

    #[test]
    fn parse_ack_length_clipping() {
        // Length=5 but data contains 3 trailing bytes that should be ignored
        // (treated as padding beyond Length).
        #[rustfmt::skip]
        let data = [0x02, 0x01, 0x00, 0x05, 0x00, 0xDE, 0xAD, 0xBE];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 4);
        assert_eq!(f[3].value, FieldValue::Bytes(&[]));
    }

    #[test]
    fn parse_truncated() {
        let data = [0x01];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..1);
        parse(&data, 0, &mut buf);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert!(matches!(fields[0].value, FieldValue::Bytes(_)));
    }
}
