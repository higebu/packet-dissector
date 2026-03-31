//! CHAP (Challenge Handshake Authentication Protocol) parser.
//!
//! ## References
//! - RFC 1994 (CHAP): <https://www.rfc-editor.org/rfc/rfc1994>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue, format_utf8_lossy};
use packet_dissector_core::packet::DissectBuffer;

static CHAP_VALUE_DESC: FieldDescriptor = FieldDescriptor::new("value", "Value", FieldType::Bytes);

static CHAP_NAME_DESC: FieldDescriptor =
    FieldDescriptor::new("name", "Name", FieldType::Bytes).with_format_fn(format_utf8_lossy);

/// Parse a CHAP packet into a DissectBuffer.
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((code, _length)) =
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
    if matches!(code, 1 | 2) && data.len() > crate::PPP_HEADER_SIZE {
        let chap_data = &data[crate::PPP_HEADER_SIZE..];
        if !chap_data.is_empty() {
            let value_size = chap_data[0] as usize;
            if value_size < chap_data.len() {
                buf.push_field(
                    &CHAP_VALUE_DESC,
                    FieldValue::Bytes(&chap_data[1..1 + value_size]),
                    offset + 5..offset + 5 + value_size,
                );
                let name_start = 1 + value_size;
                if name_start < chap_data.len() {
                    buf.push_field(
                        &CHAP_NAME_DESC,
                        FieldValue::Bytes(&chap_data[name_start..]),
                        offset + 4 + name_start..offset + data.len(),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_challenge() {
        let data = [
            0x01, 0x01, 0x00, 0x11, 4, 0xDE, 0xAD, 0xBE, 0xEF, b's', b'e', b'r', b'v', b'e', b'r',
        ];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..data.len());
        let idx = buf.begin_container(
            &crate::FIELD_DESCRIPTORS[crate::FD_PAYLOAD],
            FieldValue::Object(0..0),
            0..data.len(),
        );
        parse(&data, 0, &mut buf);
        buf.end_container(idx);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let r = match &fields[0].value {
            FieldValue::Object(r) => r.clone(),
            _ => panic!("expected Object"),
        };
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
        let data = [0x02, 0x01, 0x00, 0x09, 2, 0xAB, 0xCD, b'c'];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..data.len());
        let idx = buf.begin_container(
            &crate::FIELD_DESCRIPTORS[crate::FD_PAYLOAD],
            FieldValue::Object(0..0),
            0..data.len(),
        );
        parse(&data, 0, &mut buf);
        buf.end_container(idx);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let r = match &fields[0].value {
            FieldValue::Object(r) => r.clone(),
            _ => panic!("expected Object"),
        };
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 5);
        assert_eq!(
            f[0].descriptor.display_fn.unwrap()(&f[0].value, &[]),
            Some("Response")
        );
    }

    #[test]
    fn parse_success() {
        let data = [0x03, 0x01, 0x00, 0x04];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("test", None, &[], 0..data.len());
        let idx = buf.begin_container(
            &crate::FIELD_DESCRIPTORS[crate::FD_PAYLOAD],
            FieldValue::Object(0..0),
            0..data.len(),
        );
        parse(&data, 0, &mut buf);
        buf.end_container(idx);
        buf.end_layer();
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        let r = match &fields[0].value {
            FieldValue::Object(r) => r.clone(),
            _ => panic!("expected Object"),
        };
        let f = buf.nested_fields(&r);
        assert_eq!(f.len(), 3);
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
