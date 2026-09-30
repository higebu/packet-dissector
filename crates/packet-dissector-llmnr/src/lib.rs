//! LLMNR (Link-Local Multicast Name Resolution) dissector.
//!
//! LLMNR reuses the DNS message format (RFC 1035, Section 4) on UDP and TCP
//! port 5355, with a different meaning for three header bits: the bits DNS
//! uses for AA, RD and RA are C (Conflict), T (Tentative) and a 4-bit
//! reserved Z field; TC keeps its meaning (RFC 4795, Section 2.1.1). The
//! layer is labelled "LLMNR" and carries `c`, `tc`, `t` and `z` instead of
//! the DNS flag fields; questions and resource records match the DNS
//! dissector's fields.
//!
//! ## References
//! - RFC 4795 (LLMNR): <https://www.rfc-editor.org/rfc/rfc4795>
//! - RFC 4795, Section 2.1.1 (header format):
//!   <https://www.rfc-editor.org/rfc/rfc4795#section-2.1.1>
//! - RFC 1035, Section 4 (DNS message format, TCP length prefix):
//!   <https://www.rfc-editor.org/rfc/rfc1035#section-4>

#![deny(missing_docs)]

use packet_dissector_core::dissector::{DissectResult, Dissector, ProtocolLayer, SpecReference};
use packet_dissector_core::error::PacketError;
use packet_dissector_core::field::FieldDescriptor;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_dns::{
    dissect_as_llmnr, dissect_as_llmnr_tcp, llmnr_field_descriptors, llmnr_tcp_field_descriptors,
};

/// Specification references for the LLMNR dissectors.
static REFERENCES: &[SpecReference] = &[
    SpecReference::new(
        "RFC 4795",
        "Link-local Multicast Name Resolution (LLMNR)",
        "https://www.rfc-editor.org/rfc/rfc4795",
    ),
    SpecReference::new(
        "RFC 1035",
        "Domain names - implementation and specification",
        "https://www.rfc-editor.org/rfc/rfc1035",
    ),
];

/// LLMNR dissector for UDP (port 5355, multicast 224.0.0.252 / FF02::1:3).
///
/// RFC 4795, Section 2 — "LLMNR queries are sent to and received on port
/// 5355." <https://www.rfc-editor.org/rfc/rfc4795#section-2>
pub struct LlmnrDissector;

impl Dissector for LlmnrDissector {
    fn name(&self) -> &'static str {
        "Link-Local Multicast Name Resolution"
    }

    fn short_name(&self) -> &'static str {
        "LLMNR"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        llmnr_field_descriptors()
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // RFC 4795, Section 2.1 — "LLMNR is based on the DNS packet format
        // defined in [RFC1035] Section 4 for both queries and responses."
        // https://www.rfc-editor.org/rfc/rfc4795#section-2.1
        dissect_as_llmnr(data, buf, offset)
    }
}

/// LLMNR dissector for TCP (unicast, port 5355), where each message is
/// preceded by the 2-octet length field of RFC 1035, Section 4.2.2.
///
/// RFC 4795, Section 2.4 — "Unicast LLMNR queries MUST be done using TCP and
/// the responses MUST be sent using the same TCP connection as the query."
/// <https://www.rfc-editor.org/rfc/rfc4795#section-2.4>
pub struct LlmnrTcpDissector;

impl Dissector for LlmnrTcpDissector {
    fn name(&self) -> &'static str {
        "LLMNR over TCP"
    }

    fn short_name(&self) -> &'static str {
        "LLMNR"
    }

    fn field_descriptors(&self) -> &'static [FieldDescriptor] {
        llmnr_tcp_field_descriptors()
    }

    fn references(&self) -> &'static [SpecReference] {
        REFERENCES
    }

    fn layer(&self) -> Option<ProtocolLayer> {
        Some(ProtocolLayer::Application)
    }

    fn dissect<'pkt>(
        &self,
        data: &'pkt [u8],
        buf: &mut DissectBuffer<'pkt>,
        offset: usize,
    ) -> Result<DissectResult, PacketError> {
        // RFC 1035, Section 4.2.2 — "The message is prefixed with a two byte
        // length field which gives the message length, excluding the two
        // byte length field."
        // https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2
        dissect_as_llmnr_tcp(data, buf, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::dissector::{DispatchHint, Dissector, ProtocolLayer};
    use packet_dissector_core::error::PacketError;
    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::DissectBuffer;

    // # RFC 4795 (LLMNR) Coverage
    //
    // | RFC Section | Description                                      | Test                                 |
    // |-------------|--------------------------------------------------|--------------------------------------|
    // | 2.1.1       | Query with C=0 (header flags C / TC / T / Z)     | parse_llmnr_query                    |
    // | 2.1.1       | Response with T=1 (Tentative)                    | parse_llmnr_response_tentative       |
    // | 2.1.1       | Response with C=1 (Conflict) and two answers     | parse_llmnr_response_conflict        |
    // | 2.1, 2.4    | TCP query with the 2-octet length prefix         | parse_llmnr_tcp_query                |
    // | 2.1         | Truncated header                                 | parse_llmnr_truncated                |
    // | 2.1.1       | Field descriptors name C / T, not AA / RD / RA   | field_descriptors_use_llmnr_flags    |
    // | —           | Names, references, layer                         | metadata                             |

    /// LLMNR header: ID 0x1234, the given flags word, and section counts.
    fn header(flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut h = 0x1234u16.to_be_bytes().to_vec();
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&an.to_be_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
        h
    }

    /// Question "host1" A IN, starting at offset 12.
    fn question() -> Vec<u8> {
        let mut q = vec![5, b'h', b'o', b's', b't', b'1', 0];
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        q
    }

    /// Answer "host1" (compressed pointer to offset 12) A IN, TTL 30.
    fn answer(addr: [u8; 4]) -> Vec<u8> {
        let mut rr = vec![0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01];
        rr.extend_from_slice(&30u32.to_be_bytes());
        rr.extend_from_slice(&4u16.to_be_bytes());
        rr.extend_from_slice(&addr);
        rr
    }

    fn flag(buf: &DissectBuffer<'_>, name: &str) -> FieldValue<'static> {
        let layer = &buf.layers()[0];
        match buf.field_by_name(layer, name).unwrap().value {
            FieldValue::U8(v) => FieldValue::U8(v),
            ref other => panic!("{name}: unexpected {other:?}"),
        }
    }

    fn array_objects<'a, 'pkt>(buf: &'a DissectBuffer<'pkt>, name: &str) -> Vec<&'a Field<'pkt>> {
        let layer = &buf.layers()[0];
        let arr = buf.field_by_name(layer, name).unwrap();
        let range = arr.value.as_container_range().unwrap();
        buf.nested_fields(range)
            .iter()
            .filter(|f| f.value.is_object())
            .collect()
    }

    #[test]
    fn parse_llmnr_query() {
        let mut data = header(0x0000, 1, 0);
        data.extend(question());
        let mut buf = DissectBuffer::new();
        let result = LlmnrDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        assert_eq!(result.next, DispatchHint::End);
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "LLMNR");
        assert_eq!(layer.range, 0..data.len());
        assert_eq!(flag(&buf, "qr"), FieldValue::U8(0));
        assert_eq!(flag(&buf, "c"), FieldValue::U8(0));
        assert_eq!(flag(&buf, "tc"), FieldValue::U8(0));
        assert_eq!(flag(&buf, "t"), FieldValue::U8(0));
        assert_eq!(flag(&buf, "z"), FieldValue::U8(0));
        assert!(buf.field_by_name(layer, "aa").is_none());
        assert!(buf.field_by_name(layer, "rd").is_none());
        assert_eq!(array_objects(&buf, "questions").len(), 1);
    }

    #[test]
    fn parse_llmnr_response_tentative() {
        // QR=1, T=1 (bit 8, the DNS RD position).
        let mut data = header(0x8100, 1, 1);
        data.extend(question());
        data.extend(answer([192, 0, 2, 1]));
        let mut buf = DissectBuffer::new();
        LlmnrDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(flag(&buf, "qr"), FieldValue::U8(1));
        assert_eq!(flag(&buf, "t"), FieldValue::U8(1));
        assert_eq!(flag(&buf, "c"), FieldValue::U8(0));
        assert_eq!(array_objects(&buf, "answers").len(), 1);
    }

    #[test]
    fn parse_llmnr_response_conflict() {
        // QR=1, C=1 (bit 10, the DNS AA position), two answers.
        let mut data = header(0x8400, 1, 2);
        data.extend(question());
        data.extend(answer([192, 0, 2, 1]));
        data.extend(answer([192, 0, 2, 2]));
        let mut buf = DissectBuffer::new();
        LlmnrDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(flag(&buf, "c"), FieldValue::U8(1));
        assert_eq!(flag(&buf, "t"), FieldValue::U8(0));
        let answers = array_objects(&buf, "answers");
        assert_eq!(answers.len(), 2);
        let rdata = buf
            .nested_fields(answers[1].value.as_container_range().unwrap())
            .iter()
            .find(|f| f.name() == "rdata")
            .unwrap();
        assert_eq!(rdata.value, FieldValue::Ipv4Addr([192, 0, 2, 2]));
    }

    #[test]
    fn parse_llmnr_tcp_query() {
        let mut msg = header(0x0000, 1, 0);
        msg.extend(question());
        let mut data = (msg.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&msg);
        let mut buf = DissectBuffer::new();
        let result = LlmnrTcpDissector.dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, data.len());
        let layer = &buf.layers()[0];
        assert_eq!(layer.name, "LLMNR");
        assert_eq!(layer.range, 0..data.len());
        assert_eq!(
            buf.field_by_name(layer, "tcp_length").unwrap().value,
            FieldValue::U16(msg.len() as u16)
        );
        assert_eq!(flag(&buf, "c"), FieldValue::U8(0));
        assert_eq!(array_objects(&buf, "questions").len(), 1);
    }

    #[test]
    fn parse_llmnr_truncated() {
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LlmnrDissector.dissect(&[0u8; 11], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 12,
                actual: 11
            })
        );
        let mut buf = DissectBuffer::new();
        assert_eq!(
            LlmnrTcpDissector.dissect(&[0u8; 1], &mut buf, 0),
            Err(PacketError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn field_descriptors_use_llmnr_flags() {
        for d in [
            &LlmnrDissector as &dyn Dissector,
            &LlmnrTcpDissector as &dyn Dissector,
        ] {
            let names: Vec<_> = d.field_descriptors().iter().map(|f| f.name).collect();
            for expected in ["id", "qr", "opcode", "c", "tc", "t", "z", "rcode"] {
                assert!(names.contains(&expected), "{expected}");
            }
            for dns_only in ["aa", "rd", "ra", "ad", "cd"] {
                assert!(!names.contains(&dns_only), "{dns_only}");
            }
        }
        assert!(LlmnrDissector.field_descriptors()[0].optional);
        assert!(!LlmnrTcpDissector.field_descriptors()[0].optional);
    }

    #[test]
    fn metadata() {
        assert_eq!(
            LlmnrDissector.name(),
            "Link-Local Multicast Name Resolution"
        );
        assert_eq!(LlmnrDissector.short_name(), "LLMNR");
        assert_eq!(LlmnrTcpDissector.name(), "LLMNR over TCP");
        assert_eq!(LlmnrTcpDissector.short_name(), "LLMNR");
        for d in [
            &LlmnrDissector as &dyn Dissector,
            &LlmnrTcpDissector as &dyn Dissector,
        ] {
            assert_eq!(d.layer(), Some(ProtocolLayer::Application));
            assert!(d.references().iter().any(|r| r.id == "RFC 4795"));
        }
    }
}
