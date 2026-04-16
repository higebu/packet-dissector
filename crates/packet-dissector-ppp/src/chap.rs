//! CHAP (Challenge Handshake Authentication Protocol) parser.
//!
//! ## References
//! - RFC 1994 (CHAP; obsoletes RFC 1334 CHAP portion): <https://www.rfc-editor.org/rfc/rfc1994>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

// Challenge / Response fields.
// RFC 1994, Section 4.1 — <https://www.rfc-editor.org/rfc/rfc1994#section-4.1>
static CHAP_VALUE_DESC: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);
static CHAP_NAME_DESC: FieldDescriptor =
    FieldDescriptor::new("name", "Name", FieldType::Bytes).with_format_fn(format_utf8_lossy);

// Success / Failure fields.
// RFC 1994, Section 4.2 — <https://www.rfc-editor.org/rfc/rfc1994#section-4.2>
static CHAP_MESSAGE_DESC: FieldDescriptor =
    FieldDescriptor::new("message", "Message", FieldType::Bytes).with_format_fn(format_utf8_lossy);

/// Parse a CHAP packet into a DissectBuffer.
///
/// RFC 1994, Section 4 — <https://www.rfc-editor.org/rfc/rfc1994#section-4>
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((code, length)) =
        crate::parse_header(data, offset, crate::CHAP_HEADER_DESCRIPTORS, buf)
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

    // Clip to the declared Length per RFC 1994, Section 4.
    let chap_data = if (length as usize) <= data.len() && length >= crate::PPP_HEADER_SIZE as u16 {
        &data[crate::PPP_HEADER_SIZE..length as usize]
    } else {
        &data[crate::PPP_HEADER_SIZE..]
    };
    let payload_offset = offset + crate::PPP_HEADER_SIZE;

    match code {
        // Challenge (1) / Response (2) — RFC 1994, Section 4.1 —
        // <https://www.rfc-editor.org/rfc/rfc1994#section-4.1>
        // Value-Size (1) + Value (Value-Size) + Name (remaining).
        1 | 2 => parse_challenge_response(chap_data, payload_offset, buf),
        // Success (3) / Failure (4) — RFC 1994, Section 4.2 —
        // <https://www.rfc-editor.org/rfc/rfc1994#section-4.2>
        // Message (zero or more octets).
        3 | 4 if !chap_data.is_empty() => {
            buf.push_field(
                &CHAP_MESSAGE_DESC,
                FieldValue::Bytes(chap_data),
                payload_offset..payload_offset + chap_data.len(),
            );
        }
        _ => {}
    }
}

fn parse_challenge_response<'pkt>(
    chap_data: &'pkt [u8],
    payload_offset: usize,
    buf: &mut DissectBuffer<'pkt>,
) {
    if chap_data.is_empty() {
        return;
    }
    let value_size = chap_data[0] as usize;
    if value_size >= chap_data.len() {
        return;
    }
    buf.push_field(
        &CHAP_VALUE_DESC,
        FieldValue::Bytes(&chap_data[1..1 + value_size]),
        payload_offset + 1..payload_offset + 1 + value_size,
    );
    let name_start = 1 + value_size;
    if name_start < chap_data.len() {
        buf.push_field(
            &CHAP_NAME_DESC,
            FieldValue::Bytes(&chap_data[name_start..]),
            payload_offset + name_start..payload_offset + chap_data.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    //! # RFC 1994 (CHAP) Coverage
    //!
    //! | RFC Section | Description                        | Test                        |
    //! |-------------|------------------------------------|-----------------------------|
    //! | 4           | Packet Format (Code/Id/Length)     | parse_truncated             |
    //! | 4.1         | Challenge (Value-Size/Value/Name)  | parse_challenge             |
    //! | 4.1         | Response (Value-Size/Value/Name)   | parse_response              |
    //! | 4.2         | Success Message                    | parse_success_with_message  |
    //! | 4.2         | Success empty Message              | parse_success               |
    //! | 4.2         | Failure Message                    | parse_failure_with_message  |

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
    fn parse_challenge() {
        let data = [
            0x01, 0x01, 0x00, 0x0F, 4, 0xDE, 0xAD, 0xBE, 0xEF, b's', b'e', b'r', b'v', b'e', b'r',
        ];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 5);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Challenge")
        );
        assert_eq!(f[3].value, FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(f[4].value, FieldValue::Bytes(b"server" as &[u8]));
    }

    #[test]
    fn parse_response() {
        let data = [0x02, 0x01, 0x00, 0x08, 2, 0xAB, 0xCD, b'c'];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 5);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Response")
        );
    }

    #[test]
    fn parse_success() {
        // Code=3, Length=4, empty Message (zero octets per RFC 1994 §4.2).
        let data = [0x03, 0x01, 0x00, 0x04];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 3);
    }

    #[test]
    fn parse_success_with_message() {
        // Code=3, Length=11, Message="Welcome" per RFC 1994 §4.2.
        #[rustfmt::skip]
        let data = [
            0x03, 0x01, 0x00, 0x0B,
            b'W', b'e', b'l', b'c', b'o', b'm', b'e',
        ];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 4);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Success")
        );
        assert_eq!(f[3].name(), "message");
        assert_eq!(f[3].value, FieldValue::Bytes(b"Welcome" as &[u8]));
    }

    #[test]
    fn parse_failure_with_message() {
        // Code=4 (Failure), Message="E=691".
        #[rustfmt::skip]
        let data = [
            0x04, 0x02, 0x00, 0x09,
            b'E', b'=', b'6', b'9', b'1',
        ];
        let mut buf = DissectBuffer::new();
        fill_buf(&mut buf, &data);
        let r = obj_range(&buf);
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 4);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Failure")
        );
        assert_eq!(f[3].value, FieldValue::Bytes(b"E=691" as &[u8]));
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
