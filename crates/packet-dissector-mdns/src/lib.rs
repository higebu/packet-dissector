//! mDNS (Multicast DNS) dissector.
//!
//! mDNS uses the same message format as unicast DNS (RFC 1035) but operates
//! over UDP port 5353 with multicast addressing.
//!
//! ## References
//! - RFC 6762 (mDNS): <https://www.rfc-editor.org/rfc/rfc6762>
//! - RFC 1035 (DNS message format): <https://www.rfc-editor.org/rfc/rfc1035>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::FieldDescriptor;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dns::DnsDissector;

/// mDNS dissector.
///
/// Delegates parsing to [`DnsDissector`] and relabels the protocol layer
/// as "mDNS". The wire format is identical to DNS (RFC 1035); the only
/// difference at the dissector level is the protocol name displayed.
pub struct MdnsDissector;

impl Dissector for MdnsDissector {
    fn name(&self) -> &'static str {
        "Multicast Domain Name System"
    }

    fn short_name(&self) -> &'static str {
        "mDNS"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        DnsDissector.field_descriptors()
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        let result = DnsDissector.dissect(data, buf, offset)?;

        // Relabel the layer added by DnsDissector from "DNS" to "mDNS".
        if let Some(layer) = buf.last_layer_mut() {
            layer.name = self.short_name();
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;

    // # RFC 6762 (mDNS) Coverage
    //
    // | RFC Section | Description              | Test                          |
    // |-------------|--------------------------|-------------------------------|
    // | 6           | Message format (= DNS)   | parse_mdns_query              |
    // | 6           | Response parsing         | parse_mdns_response           |
    // | —           | Truncated packet         | parse_mdns_truncated          |

    /// Minimal mDNS query for _http._tcp.local PTR.
    fn mdns_query_bytes() -> Vec<u8> {
        vec![
            0x00, 0x00, // Transaction ID (typically 0 for mDNS queries)
            0x00, 0x00, // Flags: QR=0 (query), no RD
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // QNAME: _http._tcp.local
            0x05, b'_', b'h', b't', b't', b'p', // "_http"
            0x04, b'_', b't', b'c', b'p', // "_tcp"
            0x05, b'l', b'o', b'c', b'a', b'l', // "local"
            0x00, // root label
            0x00, 0x0c, // QTYPE = PTR (12)
            0x00, 0x01, // QCLASS = IN
        ]
    }

    #[test]
    fn parse_mdns_query() {
        let data = mdns_query_bytes();
        let mut buf = DissectBuffer::new();
        let result = MdnsDissector.dissect(&data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(buf.layers().len(), 1);

        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "mDNS");

        // Transaction ID = 0
        assert_eq!(
            buf.field_by_name(layer, "id").unwrap().value,
            FieldValue::U16(0)
        );
        // QR = 0 (query)
        assert_eq!(
            buf.field_by_name(layer, "qr").unwrap().value,
            FieldValue::U8(0)
        );
        // QDCOUNT = 1
        assert_eq!(
            buf.field_by_name(layer, "qdcount").unwrap().value,
            FieldValue::U16(1)
        );
    }

    #[test]
    fn parse_mdns_response() {
        // mDNS response with one A record answer.
        let data: &[u8] = &[
            0x00, 0x00, // Transaction ID
            0x84, 0x00, // Flags: QR=1 (response), AA=1
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Answer: myhost.local A 192.168.1.10
            0x06, b'm', b'y', b'h', b'o', b's', b't', // "myhost"
            0x05, b'l', b'o', b'c', b'a', b'l', // "local"
            0x00, // root label
            0x00, 0x01, // TYPE = A
            0x80, 0x01, // CLASS = IN with cache-flush bit set (RFC 6762, Section 10.2)
            0x00, 0x00, 0x00, 0x78, // TTL = 120
            0x00, 0x04, // RDLENGTH = 4
            0xc0, 0xa8, 0x01, 0x0a, // RDATA = 192.168.1.10
        ];

        let mut buf = DissectBuffer::new();
        let result = MdnsDissector.dissect(data, &mut buf, 0).unwrap();

        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(buf.layers().len(), 1);
        assert_eq!(buf.layers()[0].name, "mDNS");

        let layer = &buf.layers()[0];
        // QR = 1 (response)
        assert_eq!(
            buf.field_by_name(layer, "qr").unwrap().value,
            FieldValue::U8(1)
        );
        // AA = 1
        assert_eq!(
            buf.field_by_name(layer, "aa").unwrap().value,
            FieldValue::U8(1)
        );
        // ANCOUNT = 1
        assert_eq!(
            buf.field_by_name(layer, "ancount").unwrap().value,
            FieldValue::U16(1)
        );
    }

    #[test]
    fn parse_mdns_truncated() {
        let data: &[u8] = &[0x00, 0x00, 0x00]; // Only 3 bytes, need 12
        let mut buf = DissectBuffer::new();
        let err = MdnsDissector.dissect(data, &mut buf, 0).unwrap_err();
        assert!(matches!(
            err,
            PacketError::Truncated {
                expected: 12,
                actual: 3
            }
        ));
    }

    #[test]
    fn field_descriptors_match_dns() {
        assert_eq!(
            MdnsDissector.field_descriptors().len(),
            DnsDissector.field_descriptors().len()
        );
    }

    #[test]
    fn name_and_short_name() {
        assert_eq!(MdnsDissector.name(), "Multicast Domain Name System");
        assert_eq!(MdnsDissector.short_name(), "mDNS");
    }
}
