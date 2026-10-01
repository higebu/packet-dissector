//! EAPOL (EAP over LANs, IEEE 802.1X) dissector.
//!
//! ## References
//! - IEEE Std 802.1X-2020, clause 11.3 (EAPOL PDU format), 11.3.2 (Packet
//!   Type), 11.9 (EAPOL-Key): <https://standards.ieee.org/ieee/802.1X/7345/>

use packet_dissector_core::dissector::{
    DispatchHint, DissectResult, Dissector, ProtocolLayer, SpecReference,
};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::{FieldDescriptor, FieldType, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_core::util::read_be_u16;

use crate::EapDissector;

/// EAPOL header size: Protocol Version, Packet Type, Packet Body Length.
/// IEEE Std 802.1X-2020, 11.3.
pub const EAPOL_HEADER_SIZE: usize = 4;

/// EAPOL Packet Type of an EAPOL-EAP PDU (IEEE Std 802.1X-2020, 11.3.2).
const PACKET_TYPE_EAP: u8 = 0;
/// EAPOL Packet Type of an EAPOL-Key PDU (IEEE Std 802.1X-2020, 11.3.2).
const PACKET_TYPE_KEY: u8 = 3;

/// Returns the name of an EAPOL Protocol Version.
///
/// IEEE Std 802.1X-2020, 11.3.1 — each revision of IEEE 802.1X that changed
/// the EAPOL format incremented the version.
pub fn eapol_version_name(version: u8) -> Option<&'static str> {
    match version {
        1 => Some("802.1X-2001"),
        2 => Some("802.1X-2004"),
        3 => Some("802.1X-2010 or later"),
        _ => None,
    }
}

/// Returns the name of an EAPOL Packet Type.
///
/// IEEE Std 802.1X-2020, 11.3.2, Table 11-3.
pub fn eapol_packet_type_name(packet_type: u8) -> Option<&'static str> {
    match packet_type {
        0 => Some("EAPOL-EAP"),
        1 => Some("EAPOL-Start"),
        2 => Some("EAPOL-Logoff"),
        3 => Some("EAPOL-Key"),
        4 => Some("EAPOL-Encapsulated-ASF-Alert"),
        5 => Some("EAPOL-MKA"),
        6 => Some("EAPOL-Announcement (Generic)"),
        7 => Some("EAPOL-Announcement (Specific)"),
        8 => Some("EAPOL-Announcement-Req"),
        _ => None,
    }
}

/// Returns the name of an EAPOL-Key Descriptor Type.
///
/// IEEE Std 802.1X-2020, 11.9 (1 and 2). 254 is the pre-RSN WPA descriptor
/// of the Wi-Fi Alliance, named as Wireshark does (secondary source).
fn key_descriptor_type_name(descriptor_type: u8) -> Option<&'static str> {
    match descriptor_type {
        1 => Some("RC4"),
        2 => Some("IEEE 802.11"),
        254 => Some("WPA"),
        _ => None,
    }
}

const FD_VERSION: usize = 0;
const FD_PACKET_TYPE: usize = 1;
const FD_BODY_LENGTH: usize = 2;
const FD_KEY_DESCRIPTOR_TYPE: usize = 3;
const FD_BODY: usize = 4;

/// Field descriptors of the `EAPOL` layer.
static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[
    FieldDescriptor::new("version", "Protocol Version", FieldType::U8).with_display_fn(|v, _| {
        match v {
            FieldValue::U8(x) => eapol_version_name(*x),
            _ => None,
        }
    }),
    FieldDescriptor::new("packet_type", "Packet Type", FieldType::U8).with_display_fn(
        |v, _| match v {
            FieldValue::U8(t) => eapol_packet_type_name(*t),
            _ => None,
        },
    ),
    FieldDescriptor::new("body_length", "Packet Body Length", FieldType::U16),
    FieldDescriptor::new("key_descriptor_type", "Key Descriptor Type", FieldType::U8)
        .optional()
        .with_display_fn(|v, _| match v {
            FieldValue::U8(t) => key_descriptor_type_name(*t),
            _ => None,
        }),
    FieldDescriptor::new("body", "Packet Body", FieldType::Bytes).optional(),
];

/// Specification references for the EAPOL dissector.
static REFERENCES: &[SpecReference] = &[SpecReference::new(
    "IEEE 802.1X-2020",
    "IEEE Standard for Local and Metropolitan Area Networks—Port-Based Network Access Control",
    "https://standards.ieee.org/ieee/802.1X/7345/",
)];

/// EAPOL dissector (EtherType 0x888E).
///
/// Produces an `EAPOL` layer. The body of an EAPOL-EAP PDU is decoded by
/// [`EapDissector`] into an `EAP` layer that follows it; other bodies are
/// kept as raw bytes (EAPOL-Key after its Descriptor Type). Octets past the
/// Packet Body Length (Ethernet padding) are not decoded.
/// IEEE Std 802.1X-2020, 11.3.
pub struct EapolDissector;

impl Dissector for EapolDissector {
    fn name(&self) -> &'static str {
        "EAP over LAN"
    }

    fn short_name(&self) -> &'static str {
        "EAPOL"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        FIELD_DESCRIPTORS
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Link)
    }

    /// EAP: an EAP-Packet body is pushed as an `EAP` layer.
    fn visit_sub_dissectors(&self, visit: &mut dyn FnMut(&dyn Dissector)) {
        visit(&EapDissector);
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        if data.len() < EAPOL_HEADER_SIZE {
            return Err(PacketError::Truncated {
                expected: EAPOL_HEADER_SIZE,
                actual: data.len(),
            });
        }
        // IEEE Std 802.1X-2020, 11.3 — Protocol Version, Packet Type and
        // Packet Body Length, followed by the Packet Body.
        let version = data[0];
        let packet_type = data[1];
        let body_length = read_be_u16(data, 2)?;
        let end = EAPOL_HEADER_SIZE + usize::from(body_length);
        if data.len() < end {
            return Err(PacketError::Truncated {
                expected: end,
                actual: data.len(),
            });
        }
        let body = &data[EAPOL_HEADER_SIZE..end];
        let body_offset = offset + EAPOL_HEADER_SIZE;
        let carries_eap = packet_type == PACKET_TYPE_EAP && !body.is_empty();

        let layer_end = if carries_eap {
            body_offset
        } else {
            offset + end
        };
        buf.begin_layer(
            self.short_name(),
            None,
            FIELD_DESCRIPTORS,
            offset..layer_end,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_VERSION],
            FieldValue::U8(version),
            offset..offset + 1,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_PACKET_TYPE],
            FieldValue::U8(packet_type),
            offset + 1..offset + 2,
        );
        buf.push_field(
            &FIELD_DESCRIPTORS[FD_BODY_LENGTH],
            FieldValue::U16(body_length),
            offset + 2..offset + 4,
        );

        if carries_eap {
            buf.end_layer();
            // Octets of the body past the EAP Length are data link padding
            // (RFC 3748, Section 4 — <https://www.rfc-editor.org/rfc/rfc3748#section-4>).
            if EapDissector.dissect(body, buf, body_offset).is_ok() {
                return Ok(DissectResult::new(end, DispatchHint::End));
            }
            // A malformed EAP packet pushes nothing; keep the well-formed
            // EAPOL header and show the body raw instead.
            if let Some(layer) = buf.last_layer_mut() {
                layer.range.end = offset + end;
            }
        }

        let mut raw = body;
        let mut raw_offset = body_offset;
        if packet_type == PACKET_TYPE_KEY && !body.is_empty() {
            // IEEE Std 802.1X-2020, 11.9 — the EAPOL-Key body begins with
            // the Descriptor Type.
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_KEY_DESCRIPTOR_TYPE],
                FieldValue::U8(body[0]),
                body_offset..body_offset + 1,
            );
            raw = &body[1..];
            raw_offset += 1;
        }
        if !raw.is_empty() {
            buf.push_field(
                &FIELD_DESCRIPTORS[FD_BODY],
                FieldValue::Bytes(raw),
                raw_offset..raw_offset + raw.len(),
            );
        }
        buf.end_layer();
        Ok(DissectResult::new(end, DispatchHint::End))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // # IEEE Std 802.1X-2020 (EAPOL) Coverage
    //
    // | Clause  | Description                              | Test                              |
    // |---------|------------------------------------------|-----------------------------------|
    // | 11.3    | Header, EAPOL-Start with padding         | eapol_start_with_padding          |
    // | 11.3    | Header truncated                         | eapol_truncated_header            |
    // | 11.3    | Body Length beyond captured data         | eapol_body_length_exceeds_data    |
    // | 11.3.2  | EAPOL-EAP body → EAP layer               | eapol_eap_identity                |
    // | 11.3.2  | EAPOL-EAP with malformed EAP → raw body  | eapol_eap_malformed_keeps_raw_body|
    // | 11.3.2  | EAP shorter than EAPOL body              | eapol_eap_shorter_than_body       |
    // | 11.3.2  | EAPOL-Logoff                             | eapol_logoff                      |
    // | 11.9    | EAPOL-Key descriptor type and raw body   | eapol_key_raw_body                |
    // | 11.9    | EAPOL-Key with empty body                | eapol_key_empty_body              |
    // | 11.3.2  | Other packet types keep raw body         | eapol_mka_raw_body                |
    // | —       | Name tables                              | eapol_name_tables                 |

    #[test]
    fn eapol_start_with_padding() {
        let mut raw = vec![0x01, 0x01, 0x00, 0x00];
        raw.resize(46, 0);
        let mut buf = DissectBuffer::new();
        let r = EapolDissector.dissect(&raw, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, 4);
        assert_eq!(r.next, DispatchHint::End);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "EAPOL");
        assert_eq!(layer.range, 14..18);
        assert_eq!(
            buf.resolve_display_name(layer, "version_name"),
            Some("802.1X-2001")
        );
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("EAPOL-Start")
        );
        assert_eq!(buf.field_u16(layer, "body_length"), Some(0));
        assert!(buf.field_by_name(layer, "body").is_none());
    }

    #[test]
    fn eapol_logoff() {
        let raw: &[u8] = &[0x02, 0x02, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        EapolDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.resolve_display_name(layer, "packet_type_name"),
            Some("EAPOL-Logoff")
        );
    }

    #[test]
    fn eapol_eap_identity() {
        let mut raw = vec![0x02, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01];
        raw.resize(46, 0);
        let mut buf = DissectBuffer::new();
        let r = EapolDissector.dissect(&raw, &mut buf, 14).unwrap();
        assert_eq!(r.bytes_consumed, 9);
        assert_eq!(buf.layers().len(), 2);
        assert_eq!(buf.layers()[0].range, 14..18);
        let eap = &buf.layers()[1];
        assert_eq!(eap.name, "EAP");
        assert_eq!(eap.range, 18..23);
        assert_eq!(buf.resolve_display_name(eap, "type_name"), Some("Identity"));
        assert!(buf.field_by_name(&buf.layers()[0], "body").is_none());
    }

    #[test]
    fn eapol_eap_malformed_keeps_raw_body() {
        // EAP Length (9) larger than the EAPOL body (5): the EAPOL header is
        // kept and the body is shown raw.
        let raw: &[u8] = &[0x02, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x09, 0x01];
        let mut buf = DissectBuffer::new();
        let r = EapolDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 9);
        assert_eq!(buf.layers().len(), 1);
        let layer = &buf.layers()[0];
        assert_eq!(layer.range, 0..9);
        let body = buf.field_by_name(layer, "body").unwrap();
        assert_eq!(body.value, FieldValue::Bytes(&raw[4..]));
        assert_eq!(body.range, 4..9);
    }

    #[test]
    fn eapol_eap_shorter_than_body() {
        // EAP Length 4 (Success) inside an 8-octet body: the rest of the body
        // is data link padding (RFC 3748, Section 4 —
        // https://www.rfc-editor.org/rfc/rfc3748#section-4).
        let raw: &[u8] = &[0x02, 0x00, 0x00, 0x08, 0x03, 0x01, 0x00, 0x04, 0, 0, 0, 0];
        let mut buf = DissectBuffer::new();
        let r = EapolDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 12);
        assert_eq!(buf.layers()[1].range, 4..8);
    }

    #[test]
    fn eapol_key_raw_body() {
        let raw: &[u8] = &[0x02, 0x03, 0x00, 0x04, 0x02, 0x01, 0x0A, 0x00];
        let mut buf = DissectBuffer::new();
        let r = EapolDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 8);
        let layer = &buf.layers()[0];
        assert_eq!(buf.field_u8(layer, "key_descriptor_type"), Some(2));
        assert_eq!(
            buf.resolve_display_name(layer, "key_descriptor_type_name"),
            Some("IEEE 802.11")
        );
        let body = buf.field_by_name(layer, "body").unwrap();
        assert_eq!(body.value, FieldValue::Bytes(&[0x01, 0x0A, 0x00]));
        assert_eq!(body.range, 5..8);
    }

    #[test]
    fn eapol_key_empty_body() {
        let raw: &[u8] = &[0x02, 0x03, 0x00, 0x00];
        let mut buf = DissectBuffer::new();
        EapolDissector.dissect(raw, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        assert!(buf.field_by_name(layer, "key_descriptor_type").is_none());
    }

    #[test]
    fn eapol_mka_raw_body() {
        let raw: &[u8] = &[0x03, 0x05, 0x00, 0x02, 0xAB, 0xCD, 0xEE];
        let mut buf = DissectBuffer::new();
        let r = EapolDissector.dissect(raw, &mut buf, 0).unwrap();
        assert_eq!(r.bytes_consumed, 6);
        let layer = &buf.layers()[0];
        assert_eq!(
            buf.field_by_name(layer, "body").unwrap().value,
            FieldValue::Bytes(&[0xAB, 0xCD])
        );
    }

    #[test]
    fn eapol_truncated_header() {
        let mut buf = DissectBuffer::new();
        let err = EapolDissector
            .dissect(&[0x02, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 4,
                actual: 2
            }
        );
    }

    #[test]
    fn eapol_body_length_exceeds_data() {
        let mut buf = DissectBuffer::new();
        let err = EapolDissector
            .dissect(&[0x02, 0x05, 0x00, 0x08, 0x00], &mut buf, 0)
            .unwrap_err();
        assert_eq!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 5
            }
        );
    }

    #[test]
    fn eapol_name_tables() {
        assert_eq!(eapol_version_name(2), Some("802.1X-2004"));
        assert_eq!(eapol_version_name(3), Some("802.1X-2010 or later"));
        assert_eq!(eapol_version_name(4), None);
        for (t, n) in [
            (4u8, "EAPOL-Encapsulated-ASF-Alert"),
            (5, "EAPOL-MKA"),
            (6, "EAPOL-Announcement (Generic)"),
            (7, "EAPOL-Announcement (Specific)"),
            (8, "EAPOL-Announcement-Req"),
        ] {
            assert_eq!(eapol_packet_type_name(t), Some(n));
        }
        assert_eq!(eapol_packet_type_name(9), None);
        assert_eq!(key_descriptor_type_name(1), Some("RC4"));
        assert_eq!(key_descriptor_type_name(254), Some("WPA"));
        assert_eq!(key_descriptor_type_name(3), None);
    }

    #[test]
    fn eapol_metadata() {
        assert_eq!(EapolDissector.name(), "EAP over LAN");
        assert_eq!(EapolDissector.short_name(), "EAPOL");
        assert_eq!(EapolDissector.field_descriptors().len(), 5);
        assert_eq!(EapolDissector.references()[0].id, "IEEE 802.1X-2020");
        assert_eq!(EapolDissector.layer(), Some(ProtocolLayer::Link));
    }

    #[test]
    fn visit_sub_dissectors_lists_embedded_layers() {
        let mut names = Vec::new();
        EapolDissector.visit_sub_dissectors(&mut |d| names.push(d.short_name()));
        assert_eq!(names, ["EAP"]);
    }
}
