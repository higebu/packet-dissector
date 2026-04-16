//! mDNS (Multicast DNS) dissector.
//!
//! mDNS reuses the DNS message format (RFC 1035) but operates over UDP
//! port 5353 and redefines two bits that DNS would otherwise treat as part
//! of the 16-bit CLASS field:
//!
//! - **Top bit of `qclass` in the Question Section** — the unicast-response
//!   bit ("QU" bit); see RFC 6762, Section 18.12 and Section 5.4.
//! - **Top bit of `rrclass` in the Resource Record Sections** — the
//!   cache-flush bit; see RFC 6762, Section 18.13 and Section 10.2.
//!
//! Per RFC 6762, Section 10.2 the cache-flush reuse does not apply to
//! pseudo-RRs (e.g., OPT), whose `rrclass` field continues to encode the
//! EDNS0 UDP payload size as a full 16-bit value.
//!
//! ## References
//! - RFC 6762 (mDNS): <https://www.rfc-editor.org/rfc/rfc6762>
//! - RFC 1035 (DNS message format): <https://www.rfc-editor.org/rfc/rfc1035>
//! - RFC 6891 (EDNS0 / OPT pseudo-RR): <https://www.rfc-editor.org/rfc/rfc6891>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DissectResult, Dissector};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::FieldDescriptor;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dns::{DnsDissector, dissect_as_mdns};

/// mDNS dissector.
///
/// Parses a Multicast DNS message by reusing the DNS (RFC 1035) message
/// parser and applying the RFC 6762 reinterpretation of the top bit of the
/// `qclass` / `rrclass` fields (see module-level docs for details). The
/// layer is labelled "mDNS" and field names match the DNS dissector, plus
/// `qu` on each question and `cache_flush` on each non-OPT resource record.
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
        // RFC 6762, Section 18 — <https://www.rfc-editor.org/rfc/rfc6762#section-18>
        // Delegates to the shared DNS parser in mDNS mode, which splits the
        // QU bit (questions) and cache-flush bit (RRs) from the 15-bit class.
        dissect_as_mdns(data, buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::Layer;

    // # RFC 6762 (mDNS) Coverage
    //
    // | RFC Section | Description                                        | Test                                 |
    // |-------------|----------------------------------------------------|--------------------------------------|
    // | 18.1        | ID (Query Identifier)                              | parse_mdns_query                     |
    // | 18.2        | QR (Query/Response) bit                            | parse_mdns_query, parse_mdns_response|
    // | 18.4        | AA (Authoritative Answer) bit                      | parse_mdns_response                  |
    // | 18.12 / 5.4 | Top bit of qclass = unicast-response (QU) bit      | parse_mdns_qu_bit_set                |
    // | 18.12 / 5.4 | QM question (top bit of qclass clear)              | parse_mdns_qm_bit_clear              |
    // | 18.13/10.2  | Top bit of rrclass = cache-flush bit               | parse_mdns_cache_flush_bit_set       |
    // | 18.13/10.2  | Non-flushed record (top bit of rrclass clear)      | parse_mdns_cache_flush_bit_clear     |
    // | 10.2        | OPT pseudo-RR not subject to cache-flush reuse     | parse_mdns_opt_rrclass_unchanged     |
    // | —           | Truncated packet                                   | parse_mdns_truncated                 |

    /// Minimal mDNS query for _http._tcp.local PTR IN (no QU bit).
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
            0x00, 0x01, // QCLASS = IN (QU bit clear)
        ]
    }

    /// Return the children of the first Object in the `questions` Array of
    /// the first layer in `buf`.
    fn first_question_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &'a Layer,
    ) -> &'a [Field<'pkt>] {
        let questions = buf.field_by_name(layer, "questions").expect("questions");
        let arr = match &questions.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {:?}", other),
        };
        let first = &buf.nested_fields(&arr)[0];
        let obj = match &first.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {:?}", other),
        };
        buf.nested_fields(&obj)
    }

    /// Return the children of the first Object in the named RR Array
    /// (e.g., "answers").
    fn first_rr_children<'a, 'pkt>(
        buf: &'a DissectBuffer<'pkt>,
        layer: &'a Layer,
        section: &str,
    ) -> &'a [Field<'pkt>] {
        let arr_field = buf.field_by_name(layer, section).expect("section array");
        let arr = match &arr_field.value {
            FieldValue::Array(r) => r.clone(),
            other => panic!("expected Array, got {:?}", other),
        };
        let first = &buf.nested_fields(&arr)[0];
        let obj = match &first.value {
            FieldValue::Object(r) => r.clone(),
            other => panic!("expected Object, got {:?}", other),
        };
        buf.nested_fields(&obj)
    }

    fn child_by_name<'a, 'pkt>(children: &'a [Field<'pkt>], name: &str) -> Option<&'a Field<'pkt>> {
        children.iter().find(|f| f.name() == name)
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

        // RFC 6762, Section 18.1 — Transaction ID is 0 in multicast queries.
        assert_eq!(
            buf.field_by_name(layer, "id").unwrap().value,
            FieldValue::U16(0)
        );
        // RFC 6762, Section 18.2 — QR = 0 for queries.
        assert_eq!(
            buf.field_by_name(layer, "qr").unwrap().value,
            FieldValue::U8(0)
        );
        assert_eq!(
            buf.field_by_name(layer, "qdcount").unwrap().value,
            FieldValue::U16(1)
        );
    }

    #[test]
    fn parse_mdns_response() {
        // mDNS response with one A record answer and the cache-flush bit set
        // on the answer record (RFC 6762, Section 10.2 / Section 18.13).
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
            0x80, 0x01, // rrclass = 0x8001 = cache-flush bit set, class = IN (1)
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
        // RFC 6762, Section 18.2 — QR = 1 for responses.
        assert_eq!(
            buf.field_by_name(layer, "qr").unwrap().value,
            FieldValue::U8(1)
        );
        // RFC 6762, Section 18.4 — AA = 1 in responses.
        assert_eq!(
            buf.field_by_name(layer, "aa").unwrap().value,
            FieldValue::U8(1)
        );
        assert_eq!(
            buf.field_by_name(layer, "ancount").unwrap().value,
            FieldValue::U16(1)
        );
    }

    #[test]
    fn parse_mdns_qu_bit_set() {
        // Query with top bit of qclass set — "QU" question requesting unicast.
        // RFC 6762, Section 18.12 / Section 5.4.
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, // ID, flags
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QDCOUNT=1
            // QNAME: host.local
            0x04, b'h', b'o', b's', b't', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00,
            0x01, // QTYPE = A
            0x80, 0x01, // qclass: QU=1, class=IN(1)
        ];
        let mut buf = DissectBuffer::new();
        MdnsDissector.dissect(data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let fields = first_question_children(&buf, layer);

        // RFC 6762, Section 18.12 — the top bit is the QU (unicast-response) bit.
        assert_eq!(
            child_by_name(fields, "qu").map(|f| f.value.clone()),
            Some(FieldValue::U8(1)),
            "qu bit should be 1 when top bit of qclass is set"
        );
        // The class itself is the lower 15 bits.
        assert_eq!(
            child_by_name(fields, "class").map(|f| f.value.clone()),
            Some(FieldValue::U16(1)),
            "class should be 0x0001 (IN) after masking off QU bit"
        );
    }

    #[test]
    fn parse_mdns_qm_bit_clear() {
        // Query without QU bit — "QM" question requesting multicast response.
        let data = mdns_query_bytes();
        let mut buf = DissectBuffer::new();
        MdnsDissector.dissect(&data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let fields = first_question_children(&buf, layer);

        assert_eq!(
            child_by_name(fields, "qu").map(|f| f.value.clone()),
            Some(FieldValue::U8(0))
        );
        assert_eq!(
            child_by_name(fields, "class").map(|f| f.value.clone()),
            Some(FieldValue::U16(1))
        );
    }

    #[test]
    fn parse_mdns_cache_flush_bit_set() {
        // Response with cache-flush bit set on the answer.
        // RFC 6762, Section 18.13 / Section 10.2.
        let data: &[u8] = &[
            0x00, 0x00, 0x84, 0x00, // ID, flags (QR=1, AA=1)
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // ANCOUNT=1
            // Answer: myhost.local A 192.168.1.10
            0x06, b'm', b'y', b'h', b'o', b's', b't', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            0x00, 0x01, // TYPE = A
            0x80, 0x01, // rrclass: cache-flush=1, class=IN(1)
            0x00, 0x00, 0x00, 0x78, // TTL=120
            0x00, 0x04, 0xc0, 0xa8, 0x01, 0x0a, // RDLENGTH=4, 192.168.1.10
        ];
        let mut buf = DissectBuffer::new();
        MdnsDissector.dissect(data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let fields = first_rr_children(&buf, layer, "answers");

        // RFC 6762, Section 10.2 — the top bit is the cache-flush bit.
        assert_eq!(
            child_by_name(fields, "cache_flush").map(|f| f.value.clone()),
            Some(FieldValue::U8(1)),
            "cache_flush should be 1 when top bit of rrclass is set"
        );
        assert_eq!(
            child_by_name(fields, "class").map(|f| f.value.clone()),
            Some(FieldValue::U16(1)),
            "class should be 0x0001 (IN) after masking off cache-flush bit"
        );
    }

    #[test]
    fn parse_mdns_cache_flush_bit_clear() {
        // Response with cache-flush bit clear (shared record).
        let data: &[u8] = &[
            0x00, 0x00, 0x84, 0x00, //
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, //
            0x06, b'm', b'y', b'h', b'o', b's', b't', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // rrclass: cache-flush=0, class=IN(1)
            0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x0a,
        ];
        let mut buf = DissectBuffer::new();
        MdnsDissector.dissect(data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let fields = first_rr_children(&buf, layer, "answers");

        assert_eq!(
            child_by_name(fields, "cache_flush").map(|f| f.value.clone()),
            Some(FieldValue::U8(0))
        );
        assert_eq!(
            child_by_name(fields, "class").map(|f| f.value.clone()),
            Some(FieldValue::U16(1))
        );
    }

    #[test]
    fn parse_mdns_opt_rrclass_unchanged() {
        // RFC 6762, Section 10.2 — the cache-flush reinterpretation does NOT
        // apply to pseudo-RRs such as OPT (RFC 6891). The OPT rrclass field
        // continues to encode the EDNS0 UDP payload size as a full 16-bit
        // value, so the dissector must not emit a `cache_flush` field on
        // OPT and must preserve the full value in `udp_payload_size`.
        let data: &[u8] = &[
            0x00, 0x00, 0x84, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ARCOUNT=1
            // OPT pseudo-RR: name=root(0), type=OPT(41), rrclass=0x05A0 (payload 1440)
            0x00, // root name
            0x00, 0x29, // TYPE = 41 (OPT)
            0x05, 0xa0, // rrclass = 1440 (UDP payload size, NOT a cache-flush+class)
            0x00, 0x00, 0x00, 0x00, // extended-rcode/version/DO/Z
            0x00, 0x00, // RDLENGTH = 0
        ];
        let mut buf = DissectBuffer::new();
        MdnsDissector.dissect(data, &mut buf, 0).unwrap();
        let layer = &buf.layers()[0];
        let fields = first_rr_children(&buf, layer, "additionals");

        // No cache_flush field on OPT records.
        assert!(
            child_by_name(fields, "cache_flush").is_none(),
            "OPT pseudo-RR must not expose a cache_flush bit"
        );
        // udp_payload_size preserved as the full 16-bit value 0x05A0 = 1440.
        assert_eq!(
            child_by_name(fields, "udp_payload_size").map(|f| f.value.clone()),
            Some(FieldValue::U16(1440))
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
