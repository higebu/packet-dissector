//! PAP (Password Authentication Protocol) parser.
//!
//! ## References
//! - RFC 1334 (PAP / CHAP): <https://www.rfc-editor.org/rfc/rfc1334>

use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;

static FD_INLINE_PASSWORD: FieldDescriptor =
    FieldDescriptor::new("password", "Password", FieldType::Bytes);
static FD_INLINE_PEER_ID: FieldDescriptor =
    FieldDescriptor::new("peer_id", "Peer ID", FieldType::Bytes);

/// Parse a PAP packet into a DissectBuffer.
pub fn parse<'pkt>(data: &'pkt [u8], offset: usize, buf: &mut DissectBuffer<'pkt>) {
    let Some((code, _length)) =
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
    if code == 1 && data.len() > crate::PPP_HEADER_SIZE {
        let pap_data = &data[crate::PPP_HEADER_SIZE..];
        if !pap_data.is_empty() {
            let peer_id_len = pap_data[0] as usize;
            if 1 + peer_id_len < pap_data.len() {
                buf.push_field(
                    &FD_INLINE_PEER_ID,
                    FieldValue::Bytes(&pap_data[1..1 + peer_id_len]),
                    offset + 5..offset + 5 + peer_id_len,
                );
                let pw_offset = 1 + peer_id_len;
                if pw_offset < pap_data.len() {
                    let pw_len = pap_data[pw_offset] as usize;
                    if pw_offset + 1 + pw_len <= pap_data.len() {
                        buf.push_field(
                            &FD_INLINE_PASSWORD,
                            FieldValue::Bytes(&pap_data[pw_offset + 1..pw_offset + 1 + pw_len]),
                            offset + 4 + pw_offset + 1..offset + 4 + pw_offset + 1 + pw_len,
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authenticate_request() {
        let data = [
            0x01, 0x01, 0x00, 0x0E, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's',
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
            Some("Authenticate-Request")
        );
        assert_eq!(f[3].name(), "peer_id");
        assert_eq!(f[3].value, FieldValue::Bytes(b"user" as &[u8]));
        assert_eq!(f[4].name(), "password");
        assert_eq!(f[4].value, FieldValue::Bytes(b"pass" as &[u8]));
    }

    #[test]
    fn parse_authenticate_ack() {
        let data = [0x02, 0x01, 0x00, 0x05, 0x00];
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
