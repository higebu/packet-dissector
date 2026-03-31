//! # RFC 1035 (DNS) Coverage
//!
//! | RFC Section | Description                         | Test                                |
//! |-------------|-------------------------------------|-------------------------------------|
//! | 4.1.1       | Header: ID                          | parse_dns_query_basic               |
//! | 4.1.1       | Header: QR, OPCODE, AA, TC, RD      | parse_dns_query_basic               |
//! | 4.1.1       | Header: RA, Z, AD, CD, RCODE        | parse_dns_response_basic            |
//! | 4.1.1       | Header: QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT | parse_dns_response_basic     |
//! | 4.1.2       | Question: QNAME, QTYPE, QCLASS      | parse_dns_query_basic              |
//! | 4.1.3       | Resource Record: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA | parse_dns_response_basic |
//! | 4.1.4       | Name compression (pointer)           | parse_dns_response_compressed_name |
//! | 3.4.1       | RDATA: A record (IPv4 address)       | parse_dns_rdata_a                   |
//! | 3.3.1       | RDATA: CNAME (canonical name)        | parse_dns_rdata_cname               |
//! | 3.3.11      | RDATA: NS (name server)              | parse_dns_rdata_ns                  |
//! | 3.3.12      | RDATA: PTR (pointer)                 | parse_dns_rdata_ptr                 |
//! | 3.3.9       | RDATA: MX (mail exchange)            | parse_dns_rdata_mx                  |
//! | 3.3.14      | RDATA: TXT (text strings)            | parse_dns_rdata_txt                 |
//! | 3.3.13      | RDATA: SOA (start of authority)      | parse_dns_rdata_soa                 |
//! | ---         | RDATA: AAAA (IPv6 address, RFC 3596) | parse_dns_rdata_aaaa                |
//! | ---         | RDATA: Unknown type (raw bytes)      | parse_dns_rdata_unknown             |
//! | ---         | Truncated header                     | parse_dns_truncated                 |
//! | ---         | Truncated question section           | parse_dns_truncated_question        |
//! | ---         | Offset handling                      | parse_dns_with_offset               |
//! | ---         | Dissector metadata                   | dns_dissector_metadata              |
//! | ---         | Multiple questions                   | parse_dns_multiple_questions        |
//! | ---         | Pointer loop detection               | parse_dns_pointer_loop              |
//! | ---         | RDATA: SRV (RFC 2782)                | parse_dns_rdata_srv                 |
//! | ---         | RDATA: CAA (RFC 8659)                | parse_dns_rdata_caa                 |
//! | ---         | RDATA: NAPTR (RFC 3403)              | parse_dns_rdata_naptr               |
//! | ---         | RDATA: DNAME (RFC 6672)              | parse_dns_rdata_dname               |
//! | ---         | RDATA: SSHFP (RFC 4255)              | parse_dns_rdata_sshfp               |
//! | ---         | RDATA: TLSA (RFC 6698)               | parse_dns_rdata_tlsa                |
//! | ---         | EDNS0 OPT basic (RFC 6891)           | parse_dns_edns0_opt_basic           |
//! | ---         | EDNS0 OPT with options (RFC 6891)    | parse_dns_edns0_opt_with_options    |
//! | ---         | EDNS0 TCP Keepalive with timeout (RFC 7828) | parse_dns_edns0_tcp_keepalive_with_timeout |
//! | ---         | EDNS0 TCP Keepalive without timeout (RFC 7828) | parse_dns_edns0_tcp_keepalive_no_timeout |
//! | ---         | EDNS0 OPT DO bit set (RFC 6891)      | parse_dns_edns0_opt_do_bit_set      |
//! | ---         | RDATA: DNSKEY (RFC 4035)             | parse_dns_rdata_dnskey               |
//! | ---         | RDATA: DS (RFC 4035)                 | parse_dns_rdata_ds                   |
//! | ---         | RDATA: RRSIG (RFC 4035)              | parse_dns_rdata_rrsig                |
//! | ---         | RDATA: NSEC (RFC 4035)               | parse_dns_rdata_nsec                 |
//! | ---         | RDATA: NSEC3 (RFC 5155)              | parse_dns_rdata_nsec3                |
//! | ---         | DNS over TCP basic (RFC 1035 §4.2.2) | parse_dns_tcp_basic                  |
//! | ---         | DNS over TCP truncated length         | parse_dns_tcp_truncated_length       |
//! | ---         | DNS over TCP length mismatch          | parse_dns_tcp_length_mismatch        |
//! | ---         | DNS TCP dissector metadata            | dns_tcp_dissector_metadata           |
//! | ---         | RDATA: HTTPS (RFC 9460)              | parse_dns_rdata_https                |
//! | ---         | RDATA: SVCB (RFC 9460)               | parse_dns_rdata_svcb                 |
//! | ---         | RDATA: HTTPS alias mode (RFC 9460)   | parse_dns_rdata_https_alias_mode     |
//! | ---         | RDATA: NSEC3PARAM (RFC 5155)         | parse_dns_rdata_nsec3param           |
//! | ---         | RDATA: CDS (RFC 7344)                | parse_dns_rdata_cds                  |
//! | ---         | RDATA: CDNSKEY (RFC 7344)             | parse_dns_rdata_cdnskey              |
//! | ---         | RDATA: A truncated fallback          | parse_dns_rdata_a_truncated          |
//! | ---         | RDATA: SRV truncated fallback        | parse_dns_rdata_srv_truncated        |
//! | ---         | RDATA: DNSKEY truncated fallback     | parse_dns_rdata_dnskey_truncated     |
//! | 3.1         | Name: total wire length ≤ 255 octets | parse_dns_name_too_long              |
//! | 4.1.1       | Header: Z reserved bit               | parse_dns_header_z_bit               |
//! | ---         | RDATA: NAPTR sub-field byte ranges   | parse_dns_rdata_naptr_field_ranges   |
//! | 4.2.2       | DNS/TCP: reassembly across 2 segments | dns_tcp_reassembly_two_segments     |
//! | 4.2.2       | DNS/TCP: reassembly across 3 segments | dns_tcp_reassembly_three_segments   |
//! | 4.2.2       | DNS/TCP: single segment with stream  | dns_tcp_single_segment_with_stream_info |
//! | 4.2.2       | DNS/TCP: independent streams         | dns_tcp_independent_streams          |
//! | ---         | DNS/TCP: pipelined messages (RFC 7766 §6.2.1) | dns_tcp_pipelined_messages |
//! | ---         | DNS/TCP: buffered pipelined messages preserve names | dns_tcp_buffered_pipelined_messages_preserve_names |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::FieldValue;
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::dns::{DnsDissector, DnsTcpDissector};

/// Encode a domain name into DNS wire format for test assertions.
fn dns_wire_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();
    if !name.is_empty() {
        for label in name.split('.') {
            result.push(label.len() as u8);
            result.extend_from_slice(label.as_bytes());
        }
    }
    result.push(0); // root terminator
    result
}

/// Look up a sub-field by name within an Object field (via flat buffer).
fn obj_field<'a>(
    buf: &'a packet_dissector::packet::DissectBuffer<'_>,
    obj_field: &packet_dissector::field::Field<'_>,
    name: &str,
) -> Option<FieldValue<'a>> {
    let FieldValue::Object(ref range) = obj_field.value else {
        return None;
    };
    let fields = buf.nested_fields(range);
    fields
        .iter()
        .find(|f| f.name() == name)
        .map(|f| f.value.clone())
}

/// Build a DNS query for "example.com" with a custom transaction ID.
fn build_dns_query_with_id(id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header (12 bytes)
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: QR=0, RD=1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT = 0
    // Question: example.com, Type A, Class IN
    pkt.push(7); // "example" length
    pkt.extend_from_slice(b"example");
    pkt.push(3); // "com" length
    pkt.extend_from_slice(b"com");
    pkt.push(0); // root terminator
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    pkt
}

/// Build a DNS query for "example.com" with type A, class IN.
fn build_dns_query() -> Vec<u8> {
    build_dns_query_with_id(0x1234)
}

/// Build a DNS response for "example.com" with one A record answer.
fn build_dns_response() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header (12 bytes)
    pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT = 0
    // Question: example.com
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    // Answer RR: example.com -> 93.184.216.34
    // NAME: pointer to offset 12 (question name)
    pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to offset 12
    pkt.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL = 300
    pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    pkt.extend_from_slice(&[93, 184, 216, 34]); // RDATA = 93.184.216.34
    pkt
}

#[test]
fn parse_dns_query_basic() {
    let data = build_dns_query();
    let mut buf = DissectBuffer::new();
    let result = DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, data.len());
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("DNS").unwrap();
    assert_eq!(layer.name, "DNS");

    // Header fields
    assert_eq!(
        buf.field_by_name(layer, "id").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "qr").unwrap().value,
        FieldValue::U8(0)
    ); // Query
    assert_eq!(
        buf.field_by_name(layer, "opcode").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "aa").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "tc").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "rd").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ra").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "ad").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "cd").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "rcode").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "qdcount").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ancount").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "nscount").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "arcount").unwrap().value,
        FieldValue::U16(0)
    );

    // Question section (Array of Object entries)
    let FieldValue::Array(ref questions_range) =
        buf.field_by_name(layer, "questions").unwrap().value
    else {
        panic!("expected Array")
    };
    let questions_all = buf.nested_fields(questions_range);
    let questions: Vec<_> = questions_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    assert_eq!(questions.len(), 1);
    let q0 = &questions[0];
    assert_eq!(
        obj_field(&buf, q0, "name"),
        Some(FieldValue::Bytes(dns_wire_name("example.com").leak()))
    );
    assert_eq!(obj_field(&buf, q0, "type"), Some(FieldValue::U16(1))); // A
    assert_eq!(
        {
            let FieldValue::Object(ref _rng) = q0.value else {
                panic!("expected Object")
            };
            buf.resolve_nested_display_name(_rng, "type_name")
        },
        Some("A")
    );
    assert_eq!(obj_field(&buf, q0, "class"), Some(FieldValue::U16(1))); // IN
    assert_eq!(
        {
            let FieldValue::Object(ref _rng) = q0.value else {
                panic!("expected Object")
            };
            buf.resolve_nested_display_name(_rng, "class_name")
        },
        Some("IN")
    );

    // Header name fields (resolved via display_fn)
    assert_eq!(buf.resolve_display_name(layer, "qr_name"), Some("Query"));
    assert_eq!(
        buf.resolve_display_name(layer, "opcode_name"),
        Some("QUERY")
    );
    assert_eq!(
        buf.resolve_display_name(layer, "rcode_name"),
        Some("NOERROR")
    );
}

#[test]
fn parse_dns_response_basic() {
    let data = build_dns_response();
    let mut buf = DissectBuffer::new();
    let result = DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, data.len());

    let layer = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "qr").unwrap().value,
        FieldValue::U8(1)
    ); // Response
    assert_eq!(buf.resolve_display_name(layer, "qr_name"), Some("Response"));
    assert_eq!(
        buf.field_by_name(layer, "rd").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ra").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "qdcount").unwrap().value,
        FieldValue::U16(1)
    );
    assert_eq!(
        buf.field_by_name(layer, "ancount").unwrap().value,
        FieldValue::U16(1)
    );

    // Answer RR (Array of Object entries)
    let FieldValue::Array(ref answers_range) = buf.field_by_name(layer, "answers").unwrap().value
    else {
        panic!("expected Array")
    };
    let answers_all = buf.nested_fields(answers_range);
    let answers: Vec<_> = answers_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(answers.len(), 1);
    let a0 = &answers[0];
    // Answer name uses DNS compression pointer 0xC00C (pointing to question name at offset 12)
    assert_eq!(
        obj_field(&buf, a0, "name"),
        Some(FieldValue::Bytes(&[0xC0, 0x0C]))
    );
    assert_eq!(obj_field(&buf, a0, "type"), Some(FieldValue::U16(1))); // A
    assert_eq!(
        {
            let FieldValue::Object(ref _rng) = a0.value else {
                panic!("expected Object")
            };
            buf.resolve_nested_display_name(_rng, "type_name")
        },
        Some("A")
    );
    assert_eq!(obj_field(&buf, a0, "class"), Some(FieldValue::U16(1))); // IN
    assert_eq!(
        {
            let FieldValue::Object(ref _rng) = a0.value else {
                panic!("expected Object")
            };
            buf.resolve_nested_display_name(_rng, "class_name")
        },
        Some("IN")
    );
    assert_eq!(obj_field(&buf, a0, "ttl"), Some(FieldValue::U32(300)));
    assert_eq!(obj_field(&buf, a0, "rdlength"), Some(FieldValue::U16(4)));
    assert_eq!(
        obj_field(&buf, a0, "rdata"),
        Some(FieldValue::Ipv4Addr([93, 184, 216, 34]))
    );
}

#[test]
fn parse_dns_response_compressed_name() {
    // The response builder uses a pointer (0xC00C) for the answer name
    let data = build_dns_response();
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref answers_range) = buf.field_by_name(layer, "answers").unwrap().value
    else {
        panic!("expected Array")
    };
    let answers_all = buf.nested_fields(answers_range);
    let answers: Vec<_> = answers_all.iter().filter(|f| f.value.is_object()).collect();
    // Compressed name is stored as the raw pointer bytes (0xC00C)
    assert_eq!(
        obj_field(&buf, answers[0], "name"),
        Some(FieldValue::Bytes(&[0xC0, 0x0C]))
    );
}

#[test]
fn parse_dns_truncated() {
    let data = [0u8; 6]; // Only 6 bytes, need 12
    let mut buf = DissectBuffer::new();
    let err = DnsDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 12,
            actual: 6
        }
    ));
}

#[test]
fn parse_dns_truncated_question() {
    // Header says 1 question but no question data follows
    let mut data = vec![0u8; 12];
    data[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    let mut buf = DissectBuffer::new();
    let err = DnsDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated { .. }
    ));
}

#[test]
fn parse_dns_with_offset() {
    let data = build_dns_query();
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 42).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    assert_eq!(layer.range.start, 42);
    assert_eq!(buf.field_by_name(layer, "id").unwrap().range, 42..44);
}

#[test]
fn dns_dissector_metadata() {
    let d = DnsDissector;
    assert_eq!(d.name(), "Domain Name System");
    assert_eq!(d.short_name(), "DNS");
}

#[test]
fn parse_dns_multiple_questions() {
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&0xABCDu16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    pkt.extend_from_slice(&0x0002u16.to_be_bytes()); // QDCOUNT = 2
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT
    // Question 1: a.com
    pkt.push(1);
    pkt.extend_from_slice(b"a");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    // Question 2: b.org
    pkt.push(1);
    pkt.extend_from_slice(b"b");
    pkt.push(3);
    pkt.extend_from_slice(b"org");
    pkt.push(0);
    pkt.extend_from_slice(&28u16.to_be_bytes()); // QTYPE = AAAA
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&pkt, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref questions_range) =
        buf.field_by_name(layer, "questions").unwrap().value
    else {
        panic!("expected Array")
    };
    let questions_all = buf.nested_fields(questions_range);
    let questions: Vec<_> = questions_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    assert_eq!(questions.len(), 2);

    assert_eq!(
        obj_field(&buf, questions[0], "name"),
        Some(FieldValue::Bytes(dns_wire_name("a.com").leak()))
    );
    assert_eq!(
        obj_field(&buf, questions[0], "type"),
        Some(FieldValue::U16(1))
    );

    assert_eq!(
        obj_field(&buf, questions[1], "name"),
        Some(FieldValue::Bytes(dns_wire_name("b.org").leak()))
    );
    assert_eq!(
        obj_field(&buf, questions[1], "type"),
        Some(FieldValue::U16(28)) // AAAA
    );
}

#[test]
fn parse_dns_pointer_loop() {
    let mut data = vec![0u8; 12];
    // Header: 0 questions, 1 answer
    data[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    // Answer RR at offset 12: NAME is a pointer to itself
    data.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to offset 12 (self-loop)
    data.extend_from_slice(&1u16.to_be_bytes()); // TYPE
    data.extend_from_slice(&1u16.to_be_bytes()); // CLASS
    data.extend_from_slice(&0u32.to_be_bytes()); // TTL
    data.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH

    let mut buf = DissectBuffer::new();
    let err = DnsDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidHeader(_)
    ));
}

/// Helper: build a DNS response with one answer RR of the given type and rdata.
fn build_dns_response_with_rdata(rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // ARCOUNT = 0
    // Question: example.com, Type A, Class IN
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS
    // Answer RR
    pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to "example.com"
    pkt.extend_from_slice(&rtype.to_be_bytes()); // TYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
    pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    pkt.extend_from_slice(rdata); // RDATA
    pkt
}

/// Get the first answer record's sub-field value by name.
fn answer_0_sub<'a>(
    buf: &'a packet_dissector::packet::DissectBuffer<'_>,
    name: &str,
) -> FieldValue<'a> {
    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref arr_range) = buf.field_by_name(layer, "answers").unwrap().value
    else {
        panic!("expected Array")
    };
    let answers = buf.nested_fields(arr_range);
    let objects: Vec<_> = answers.iter().filter(|f| f.value.is_object()).collect();
    let FieldValue::Object(ref obj_range) = objects[0].value else {
        panic!("expected Object")
    };
    let fields = buf.nested_fields(obj_range);
    fields
        .iter()
        .find(|f| f.name() == name)
        .unwrap()
        .value
        .clone()
}

#[test]
fn parse_dns_rdata_a() {
    let data = build_dns_response_with_rdata(1, &[10, 0, 0, 1]);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Ipv4Addr([10, 0, 0, 1])
    );
}

#[test]
fn parse_dns_rdata_aaaa() {
    // 2001:0db8::1
    let mut addr = [0u8; 16];
    addr[0] = 0x20;
    addr[1] = 0x01;
    addr[2] = 0x0d;
    addr[3] = 0xb8;
    addr[15] = 0x01;
    let data = build_dns_response_with_rdata(28, &addr);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata"), FieldValue::Ipv6Addr(addr));
}

#[test]
fn parse_dns_rdata_cname() {
    let mut rdata = Vec::new();
    rdata.push(3);
    rdata.extend_from_slice(b"www");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(5, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(dns_wire_name("www.example.com").leak())
    );
}

#[test]
fn parse_dns_rdata_ns() {
    let mut rdata = Vec::new();
    rdata.push(3);
    rdata.extend_from_slice(b"ns1");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(2, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(dns_wire_name("ns1.example.com").leak())
    );
}

#[test]
fn parse_dns_rdata_ptr() {
    let mut rdata = Vec::new();
    rdata.push(4);
    rdata.extend_from_slice(b"host");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(12, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(dns_wire_name("host.example.com").leak())
    );
}

#[test]
fn parse_dns_rdata_mx() {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&10u16.to_be_bytes()); // preference = 10
    rdata.push(4);
    rdata.extend_from_slice(b"mail");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(15, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_preference"), FieldValue::U16(10));
    assert_eq!(
        answer_0_sub(&buf, "rdata_exchange"),
        FieldValue::Bytes(dns_wire_name("mail.example.com").leak())
    );
}

#[test]
fn parse_dns_rdata_txt() {
    let mut rdata = Vec::new();
    let txt = b"v=spf1 include:example.com ~all";
    rdata.push(txt.len() as u8);
    rdata.extend_from_slice(txt);

    let data = build_dns_response_with_rdata(16, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    // TXT RDATA includes the character-string length prefix
    let mut expected = vec![txt.len() as u8];
    expected.extend_from_slice(txt);
    assert_eq!(answer_0_sub(&buf, "rdata"), FieldValue::Bytes(&expected));
}

#[test]
fn parse_dns_rdata_soa() {
    let mut rdata = Vec::new();
    // MNAME: ns1.example.com
    rdata.push(3);
    rdata.extend_from_slice(b"ns1");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);
    // RNAME: admin.example.com
    rdata.push(5);
    rdata.extend_from_slice(b"admin");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);
    // SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
    rdata.extend_from_slice(&2024010101u32.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&900u32.to_be_bytes());
    rdata.extend_from_slice(&604800u32.to_be_bytes());
    rdata.extend_from_slice(&86400u32.to_be_bytes());

    let data = build_dns_response_with_rdata(6, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata_mname"),
        FieldValue::Bytes(dns_wire_name("ns1.example.com").leak())
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_rname"),
        FieldValue::Bytes(dns_wire_name("admin.example.com").leak())
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_serial"),
        FieldValue::U32(2024010101)
    );
    assert_eq!(answer_0_sub(&buf, "rdata_refresh"), FieldValue::U32(3600));
    assert_eq!(answer_0_sub(&buf, "rdata_retry"), FieldValue::U32(900));
    assert_eq!(answer_0_sub(&buf, "rdata_expire"), FieldValue::U32(604800));
    assert_eq!(answer_0_sub(&buf, "rdata_minimum"), FieldValue::U32(86400));
}

#[test]
fn parse_dns_rdata_unknown() {
    let rdata = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let data = build_dns_response_with_rdata(99, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
    );
}

#[test]
fn parse_dns_rdata_srv() {
    // RFC 2782 — SRV: priority(2) + weight(2) + port(2) + target(name)
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&10u16.to_be_bytes()); // priority = 10
    rdata.extend_from_slice(&20u16.to_be_bytes()); // weight = 20
    rdata.extend_from_slice(&443u16.to_be_bytes()); // port = 443
    // target: srv.example.com
    rdata.push(3);
    rdata.extend_from_slice(b"srv");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(33, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_priority"), FieldValue::U16(10));
    assert_eq!(answer_0_sub(&buf, "rdata_weight"), FieldValue::U16(20));
    assert_eq!(answer_0_sub(&buf, "rdata_port"), FieldValue::U16(443));
    assert_eq!(
        answer_0_sub(&buf, "rdata_target"),
        FieldValue::Bytes(dns_wire_name("srv.example.com").leak())
    );
}

#[test]
fn parse_dns_rdata_caa() {
    // RFC 8659 — CAA: flags(1) + tag_length(1) + tag + value
    let mut rdata = Vec::new();
    rdata.push(0); // flags
    rdata.push(5); // tag length
    rdata.extend_from_slice(b"issue"); // tag
    rdata.extend_from_slice(b"letsencrypt.org"); // value

    let data = build_dns_response_with_rdata(257, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_flags"), FieldValue::U8(0));
    assert_eq!(answer_0_sub(&buf, "rdata_tag"), FieldValue::Bytes(b"issue"));
    assert_eq!(
        answer_0_sub(&buf, "rdata_value"),
        FieldValue::Bytes(b"letsencrypt.org")
    );
}

#[test]
fn parse_dns_rdata_naptr() {
    // RFC 3403 — NAPTR: order(2) + preference(2) + flags(charstr) + services(charstr) + regexp(charstr) + replacement(name)
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&100u16.to_be_bytes()); // order = 100
    rdata.extend_from_slice(&10u16.to_be_bytes()); // preference = 10
    // flags: "u"
    rdata.push(1);
    rdata.push(b'u');
    // services: "E2U+sip"
    rdata.push(7);
    rdata.extend_from_slice(b"E2U+sip");
    // regexp: "!^.*$!sip:info@example.com!"
    let regexp = b"!^.*$!sip:info@example.com!";
    rdata.push(regexp.len() as u8);
    rdata.extend_from_slice(regexp);
    // replacement: sip.example.com
    rdata.push(3);
    rdata.extend_from_slice(b"sip");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(35, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_order"), FieldValue::U16(100));
    assert_eq!(answer_0_sub(&buf, "rdata_preference"), FieldValue::U16(10));
    // NAPTR character-string fields include the length prefix byte
    assert_eq!(
        answer_0_sub(&buf, "rdata_flags"),
        FieldValue::Bytes(b"\x01u")
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_services"),
        FieldValue::Bytes(b"\x07E2U+sip")
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_regexp"),
        FieldValue::Bytes(b"\x1b!^.*$!sip:info@example.com!")
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_replacement"),
        FieldValue::Bytes(dns_wire_name("sip.example.com").leak())
    );
}

#[test]
fn parse_dns_rdata_dname() {
    // RFC 6672 — DNAME: target domain name (same encoding as CNAME)
    let mut rdata = Vec::new();
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"net");
    rdata.push(0);

    let data = build_dns_response_with_rdata(39, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(dns_wire_name("example.net").leak())
    );
}

#[test]
fn parse_dns_rdata_sshfp() {
    // RFC 4255 — SSHFP: algorithm(1) + fingerprint_type(1) + fingerprint(rest)
    let mut rdata = Vec::new();
    rdata.push(1); // algorithm = RSA
    rdata.push(1); // fingerprint type = SHA-1
    rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]); // fingerprint

    let data = build_dns_response_with_rdata(44, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_algorithm"), FieldValue::U8(1));
    assert_eq!(
        answer_0_sub(&buf, "rdata_fingerprint_type"),
        FieldValue::U8(1)
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_fingerprint"),
        FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
    );
}

#[test]
fn parse_dns_rdata_tlsa() {
    // RFC 6698 — TLSA: cert_usage(1) + selector(1) + matching_type(1) + cert_assoc_data(rest)
    let mut rdata = Vec::new();
    rdata.push(3); // cert usage = DANE-EE
    rdata.push(1); // selector = SPKI
    rdata.push(1); // matching type = SHA-256
    rdata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // cert data

    let data = build_dns_response_with_rdata(52, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_cert_usage"), FieldValue::U8(3));
    assert_eq!(answer_0_sub(&buf, "rdata_selector"), FieldValue::U8(1));
    assert_eq!(answer_0_sub(&buf, "rdata_matching_type"), FieldValue::U8(1));
    assert_eq!(
        answer_0_sub(&buf, "rdata_cert_assoc_data"),
        FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    );
}

/// Build a DNS response with one A answer and one OPT record in additionals.
/// `udp_payload_size` goes into OPT CLASS, `ttl_bytes` is the 4-byte TTL field
/// (extended_rcode, version, flags), `opt_rdata` is the EDNS option data.
fn build_dns_response_with_opt(
    udp_payload_size: u16,
    ttl_bytes: [u8; 4],
    opt_rdata: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header
    pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // ARCOUNT = 1
    // Question: example.com
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    // Answer: A record
    pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to "example.com"
    pkt.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
    pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    pkt.extend_from_slice(&[93, 184, 216, 34]); // RDATA
    // Additional: OPT record
    pkt.push(0); // NAME = root (empty)
    pkt.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    pkt.extend_from_slice(&udp_payload_size.to_be_bytes()); // CLASS = UDP payload size
    pkt.extend_from_slice(&ttl_bytes); // TTL = extended RCODE + version + flags
    pkt.extend_from_slice(&(opt_rdata.len() as u16).to_be_bytes()); // RDLENGTH
    pkt.extend_from_slice(opt_rdata);
    pkt
}

/// Get the first additional record's sub-field value by name.
fn additional_0_sub<'a>(buf: &'a DissectBuffer<'_>, name: &str) -> FieldValue<'a> {
    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref additionals_range) =
        buf.field_by_name(layer, "additionals").unwrap().value
    else {
        panic!("expected Array")
    };
    let additionals_all = buf.nested_fields(additionals_range);
    let additionals: Vec<_> = additionals_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    let FieldValue::Object(ref obj_range) = additionals[0].value else {
        panic!("expected Object")
    };
    let fields = buf.nested_fields(obj_range);
    fields
        .iter()
        .find(|f| f.name() == name)
        .unwrap()
        .value
        .clone()
}

#[test]
fn parse_dns_edns0_opt_basic() {
    // RFC 6891 — OPT with no options, DO=0
    // TTL: extended_rcode=0, version=0, DO=0, Z=0
    let data = build_dns_response_with_opt(4096, [0, 0, 0, 0], &[]);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(additional_0_sub(&buf, "type"), FieldValue::U16(41));
    assert_eq!(
        additional_0_sub(&buf, "udp_payload_size"),
        FieldValue::U16(4096)
    );
    assert_eq!(additional_0_sub(&buf, "extended_rcode"), FieldValue::U8(0));
    assert_eq!(additional_0_sub(&buf, "edns_version"), FieldValue::U8(0));
    assert_eq!(additional_0_sub(&buf, "do_bit"), FieldValue::U8(0));
}

#[test]
fn parse_dns_edns0_opt_do_bit_set() {
    // TTL: extended_rcode=0, version=0, DO=1 (bit 15 of flags = 0x8000)
    // TTL bytes: [0x00, 0x00, 0x80, 0x00]
    let data = build_dns_response_with_opt(4096, [0, 0, 0x80, 0x00], &[]);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(additional_0_sub(&buf, "do_bit"), FieldValue::U8(1));
    assert_eq!(
        additional_0_sub(&buf, "udp_payload_size"),
        FieldValue::U16(4096)
    );
}

#[test]
fn parse_dns_edns0_opt_with_options() {
    // EDNS option: code=10 (COOKIE), length=8, data=8 bytes
    let mut opt_rdata = Vec::new();
    opt_rdata.extend_from_slice(&10u16.to_be_bytes()); // option code
    opt_rdata.extend_from_slice(&8u16.to_be_bytes()); // option length
    opt_rdata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let data = build_dns_response_with_opt(4096, [0, 0, 0x80, 0x00], &opt_rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref additionals_range) =
        buf.field_by_name(layer, "additionals").unwrap().value
    else {
        panic!("expected Array")
    };
    let additionals_all = buf.nested_fields(additionals_range);
    let additionals: Vec<_> = additionals_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    let opt = &additionals[0];
    let FieldValue::Object(ref opt_range) = opt.value else {
        panic!("expected Object")
    };
    let opt_fields = buf.nested_fields(opt_range);
    let edns_field = opt_fields
        .iter()
        .find(|f| f.name() == "edns_options")
        .unwrap();
    let FieldValue::Array(ref edns_options_range) = edns_field.value else {
        panic!("edns_options should be an Array")
    };
    let edns_options_all = buf.nested_fields(edns_options_range);
    let edns_options: Vec<_> = edns_options_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    assert_eq!(edns_options.len(), 1);
    let FieldValue::Object(ref opt0_range) = edns_options[0].value else {
        panic!("expected Object")
    };
    let opt0_fields = buf.nested_fields(opt0_range);
    assert_eq!(
        opt0_fields
            .iter()
            .find(|f| f.name() == "code")
            .unwrap()
            .value,
        FieldValue::U16(10)
    );
    assert_eq!(
        opt0_fields
            .iter()
            .find(|f| f.name() == "length")
            .unwrap()
            .value,
        FieldValue::U16(8)
    );
    assert_eq!(
        opt0_fields
            .iter()
            .find(|f| f.name() == "data")
            .unwrap()
            .value,
        FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    );
}

#[test]
fn parse_dns_rdata_dnskey() {
    // RFC 4035 — DNSKEY: flags(2) + protocol(1) + algorithm(1) + public_key(rest)
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&256u16.to_be_bytes()); // flags = 256 (Zone Key)
    rdata.push(3); // protocol = 3 (DNSSEC)
    rdata.push(8); // algorithm = 8 (RSASHA256)
    rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // public key

    let data = build_dns_response_with_rdata(48, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_flags"), FieldValue::U16(256));
    assert_eq!(answer_0_sub(&buf, "rdata_protocol"), FieldValue::U8(3));
    assert_eq!(answer_0_sub(&buf, "rdata_algorithm"), FieldValue::U8(8));
    assert_eq!(
        answer_0_sub(&buf, "rdata_public_key"),
        FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD])
    );
}

#[test]
fn parse_dns_rdata_ds() {
    // RFC 4035 — DS: key_tag(2) + algorithm(1) + digest_type(1) + digest(rest)
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&12345u16.to_be_bytes()); // key_tag
    rdata.push(8); // algorithm = RSASHA256
    rdata.push(2); // digest type = SHA-256
    rdata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]); // digest

    let data = build_dns_response_with_rdata(43, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_key_tag"), FieldValue::U16(12345));
    assert_eq!(answer_0_sub(&buf, "rdata_algorithm"), FieldValue::U8(8));
    assert_eq!(answer_0_sub(&buf, "rdata_digest_type"), FieldValue::U8(2));
    assert_eq!(
        answer_0_sub(&buf, "rdata_digest"),
        FieldValue::Bytes(&[0x01, 0x02, 0x03, 0x04, 0x05])
    );
}

#[test]
fn parse_dns_rdata_rrsig() {
    // RFC 4035 — RRSIG: type_covered(2) + algorithm(1) + labels(1) + original_ttl(4)
    //   + sig_expiration(4) + sig_inception(4) + key_tag(2) + signer_name + signature
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&1u16.to_be_bytes()); // type_covered = A
    rdata.push(8); // algorithm = RSASHA256
    rdata.push(2); // labels = 2
    rdata.extend_from_slice(&3600u32.to_be_bytes()); // original TTL
    rdata.extend_from_slice(&1700000000u32.to_be_bytes()); // signature expiration
    rdata.extend_from_slice(&1699000000u32.to_be_bytes()); // signature inception
    rdata.extend_from_slice(&12345u16.to_be_bytes()); // key tag
    // signer_name: example.com
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);
    // signature
    rdata.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let data = build_dns_response_with_rdata(46, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_type_covered"), FieldValue::U16(1));
    assert_eq!(answer_0_sub(&buf, "rdata_algorithm"), FieldValue::U8(8));
    assert_eq!(answer_0_sub(&buf, "rdata_labels"), FieldValue::U8(2));
    assert_eq!(
        answer_0_sub(&buf, "rdata_original_ttl"),
        FieldValue::U32(3600)
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_signature_expiration"),
        FieldValue::U32(1700000000)
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_signature_inception"),
        FieldValue::U32(1699000000)
    );
    assert_eq!(answer_0_sub(&buf, "rdata_key_tag"), FieldValue::U16(12345));
    assert_eq!(
        answer_0_sub(&buf, "rdata_signer_name"),
        FieldValue::Bytes(dns_wire_name("example.com").leak())
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_signature"),
        FieldValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
    );
}

#[test]
fn parse_dns_rdata_nsec() {
    // RFC 4035 — NSEC: next_domain_name + type_bitmaps
    let mut rdata = Vec::new();
    // next_domain_name: host.example.com
    rdata.push(4);
    rdata.extend_from_slice(b"host");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);
    // type bitmaps (window 0, bitmap length 1, bitmap: A=bit1)
    rdata.extend_from_slice(&[0x00, 0x01, 0x40]);

    let data = build_dns_response_with_rdata(47, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata_next_domain_name"),
        FieldValue::Bytes(dns_wire_name("host.example.com").leak())
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_type_bitmaps"),
        FieldValue::Bytes(&[0x00, 0x01, 0x40])
    );
}

#[test]
fn parse_dns_rdata_nsec3() {
    // RFC 5155 — NSEC3: hash_alg(1) + flags(1) + iterations(2) + salt_len(1) + salt
    //   + hash_len(1) + next_hashed_owner + type_bitmaps
    let mut rdata = Vec::new();
    rdata.push(1); // hash algorithm = SHA-1
    rdata.push(0); // flags
    rdata.extend_from_slice(&10u16.to_be_bytes()); // iterations = 10
    rdata.push(4); // salt length = 4
    rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // salt
    rdata.push(20); // hash length = 20
    rdata.extend_from_slice(&[0x01; 20]); // next hashed owner name (20 bytes)
    // type bitmaps
    rdata.extend_from_slice(&[0x00, 0x01, 0x40]);

    let data = build_dns_response_with_rdata(50, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata_hash_algorithm"),
        FieldValue::U8(1)
    );
    assert_eq!(answer_0_sub(&buf, "rdata_flags"), FieldValue::U8(0));
    assert_eq!(answer_0_sub(&buf, "rdata_iterations"), FieldValue::U16(10));
    assert_eq!(answer_0_sub(&buf, "rdata_salt_length"), FieldValue::U8(4));
    assert_eq!(
        answer_0_sub(&buf, "rdata_salt"),
        FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD])
    );
    assert_eq!(answer_0_sub(&buf, "rdata_hash_length"), FieldValue::U8(20));
    assert_eq!(
        answer_0_sub(&buf, "rdata_next_hashed_owner"),
        FieldValue::Bytes(&[0x01; 20])
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_type_bitmaps"),
        FieldValue::Bytes(&[0x00, 0x01, 0x40])
    );
}

// ---- DNS over TCP tests ----

#[test]
fn parse_dns_tcp_basic() {
    // RFC 1035, Section 4.2.2 — TCP: 2-byte length prefix + DNS message
    let dns_msg = build_dns_query();
    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&dns_msg);

    let mut buf = DissectBuffer::new();
    let result = DnsTcpDissector.dissect(&tcp_data, &mut buf, 0).unwrap();

    // bytes_consumed includes 2-byte length prefix + DNS message
    assert_eq!(result.bytes_consumed, 2 + dns_msg.len());
    assert_eq!(result.next, DispatchHint::End);

    let layer = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "id").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert_eq!(
        buf.field_by_name(layer, "rd").unwrap().value,
        FieldValue::U8(1)
    );
}

#[test]
fn parse_dns_tcp_truncated_length() {
    // Only 1 byte — need at least 2 for the length prefix
    let data = [0u8; 1];
    let mut buf = DissectBuffer::new();
    let err = DnsTcpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 2,
            actual: 1
        }
    ));
}

#[test]
fn parse_dns_tcp_length_mismatch() {
    // Length says 100 but only 10 bytes of DNS data follow
    let mut data = Vec::new();
    data.extend_from_slice(&100u16.to_be_bytes());
    data.extend_from_slice(&[0u8; 10]);

    let mut buf = DissectBuffer::new();
    let err = DnsTcpDissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 102,
            actual: 12
        }
    ));
}

#[test]
fn dns_tcp_dissector_metadata() {
    let d = DnsTcpDissector;
    assert_eq!(d.name(), "DNS over TCP");
    assert_eq!(d.short_name(), "DNS");
}

// ---- HTTPS/SVCB tests ----

#[test]
fn parse_dns_rdata_https() {
    // RFC 9460 — HTTPS: SvcPriority(2) + TargetName(name) + SvcParams(rest)
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&1u16.to_be_bytes()); // priority = 1 (service mode)
    // target: cdn.example.com
    rdata.push(3);
    rdata.extend_from_slice(b"cdn");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);
    // SvcParams: alpn=h2 (key=1, length=3, value=\x02h2)
    rdata.extend_from_slice(&1u16.to_be_bytes()); // key = alpn
    rdata.extend_from_slice(&3u16.to_be_bytes()); // length = 3
    rdata.extend_from_slice(&[0x02, b'h', b'2']); // value

    let data = build_dns_response_with_rdata(65, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_priority"), FieldValue::U16(1));
    assert_eq!(
        answer_0_sub(&buf, "rdata_target"),
        FieldValue::Bytes(dns_wire_name("cdn.example.com").leak())
    );
    assert_eq!(
        answer_0_sub(&buf, "rdata_params"),
        FieldValue::Bytes(&[0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2'])
    );
}

#[test]
fn parse_dns_rdata_svcb() {
    // RFC 9460 — SVCB: same wire format as HTTPS
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&2u16.to_be_bytes()); // priority = 2
    // target: svc.example.com
    rdata.push(3);
    rdata.extend_from_slice(b"svc");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(64, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_priority"), FieldValue::U16(2));
    assert_eq!(
        answer_0_sub(&buf, "rdata_target"),
        FieldValue::Bytes(dns_wire_name("svc.example.com").leak())
    );
    // No SvcParams → empty bytes
    assert_eq!(answer_0_sub(&buf, "rdata_params"), FieldValue::Bytes(&[]));
}

#[test]
fn parse_dns_rdata_https_alias_mode() {
    // RFC 9460 — HTTPS alias mode: priority=0, target=alias
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&0u16.to_be_bytes()); // priority = 0 (alias mode)
    // target: alias.example.com
    rdata.push(5);
    rdata.extend_from_slice(b"alias");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(65, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_priority"), FieldValue::U16(0));
    assert_eq!(
        answer_0_sub(&buf, "rdata_target"),
        FieldValue::Bytes(dns_wire_name("alias.example.com").leak())
    );
}

// ---- NSEC3PARAM, CDS, CDNSKEY tests ----

#[test]
fn parse_dns_rdata_nsec3param() {
    // RFC 5155 §4.2 — NSEC3PARAM: hash_alg(1) + flags(1) + iterations(2) + salt_len(1) + salt
    let mut rdata = Vec::new();
    rdata.push(1); // hash algorithm = SHA-1
    rdata.push(0); // flags
    rdata.extend_from_slice(&5u16.to_be_bytes()); // iterations = 5
    rdata.push(4); // salt length = 4
    rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // salt

    let data = build_dns_response_with_rdata(51, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata_hash_algorithm"),
        FieldValue::U8(1)
    );
    assert_eq!(answer_0_sub(&buf, "rdata_flags"), FieldValue::U8(0));
    assert_eq!(answer_0_sub(&buf, "rdata_iterations"), FieldValue::U16(5));
    assert_eq!(answer_0_sub(&buf, "rdata_salt_length"), FieldValue::U8(4));
    assert_eq!(
        answer_0_sub(&buf, "rdata_salt"),
        FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD])
    );
}

#[test]
fn parse_dns_rdata_cds() {
    // RFC 7344 — CDS: same format as DS
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&54321u16.to_be_bytes()); // key_tag
    rdata.push(13); // algorithm = ECDSAP256SHA256
    rdata.push(2); // digest type = SHA-256
    rdata.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // digest

    let data = build_dns_response_with_rdata(59, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_key_tag"), FieldValue::U16(54321));
    assert_eq!(answer_0_sub(&buf, "rdata_algorithm"), FieldValue::U8(13));
    assert_eq!(answer_0_sub(&buf, "rdata_digest_type"), FieldValue::U8(2));
    assert_eq!(
        answer_0_sub(&buf, "rdata_digest"),
        FieldValue::Bytes(&[0xAB, 0xCD, 0xEF])
    );
}

#[test]
fn parse_dns_rdata_cdnskey() {
    // RFC 7344 — CDNSKEY: same format as DNSKEY
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&257u16.to_be_bytes()); // flags = 257 (KSK)
    rdata.push(3); // protocol = 3 (DNSSEC)
    rdata.push(13); // algorithm = ECDSAP256SHA256
    rdata.extend_from_slice(&[0x11, 0x22, 0x33]); // public key

    let data = build_dns_response_with_rdata(60, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata_flags"), FieldValue::U16(257));
    assert_eq!(answer_0_sub(&buf, "rdata_protocol"), FieldValue::U8(3));
    assert_eq!(answer_0_sub(&buf, "rdata_algorithm"), FieldValue::U8(13));
    assert_eq!(
        answer_0_sub(&buf, "rdata_public_key"),
        FieldValue::Bytes(&[0x11, 0x22, 0x33])
    );
}

// ---- RDATA truncation fallback tests ----

#[test]
fn parse_dns_rdata_a_truncated() {
    // A record needs 4 bytes, give only 3 → should fall back to raw bytes
    let rdata = vec![10, 0, 0];
    let data = build_dns_response_with_rdata(1, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(answer_0_sub(&buf, "rdata"), FieldValue::Bytes(&[10, 0, 0]));
}

#[test]
fn parse_dns_rdata_srv_truncated() {
    // SRV needs ≥7 bytes, give only 5 → should fall back to raw bytes
    let rdata = vec![0, 1, 0, 2, 0];
    let data = build_dns_response_with_rdata(33, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(&[0, 1, 0, 2, 0])
    );
}

#[test]
fn parse_dns_rdata_dnskey_truncated() {
    // DNSKEY needs ≥4 bytes, give only 3 → should fall back to raw bytes
    let rdata = vec![0x01, 0x00, 0x03];
    let data = build_dns_response_with_rdata(48, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(
        answer_0_sub(&buf, "rdata"),
        FieldValue::Bytes(&[0x01, 0x00, 0x03])
    );
}

/// Return the full Field struct (including range) for the first answer's sub-field.
fn answer_0_field_full<'a>(
    buf: &'a DissectBuffer<'_>,
    name: &str,
) -> packet_dissector::field::Field<'a> {
    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref answers_range) = buf.field_by_name(layer, "answers").unwrap().value
    else {
        panic!("expected Array")
    };
    let answers_all = buf.nested_fields(answers_range);
    let answers: Vec<_> = answers_all.iter().filter(|f| f.value.is_object()).collect();
    let FieldValue::Object(ref obj_range) = answers[0].value else {
        panic!("expected Object")
    };
    let fields = buf.nested_fields(obj_range);
    fields.iter().find(|f| f.name() == name).unwrap().clone()
}

// ---- RFC conformance: name total length, Z bit, NAPTR ranges ----

#[test]
fn parse_dns_name_too_long() {
    // RFC 1035, Section 3.1 — total name wire length must be ≤ 255 octets.
    // 4 labels of 63 bytes each = 4*(1+63)+1(root) = 257 bytes → must be rejected.
    let mut pkt = vec![0u8; 12];
    pkt[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    for _ in 0..4 {
        pkt.push(63); // label length
        pkt.extend_from_slice(&[b'a'; 63]); // label content
    }
    pkt.push(0); // root terminator
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    let mut buf = DissectBuffer::new();
    let err = DnsDissector.dissect(&pkt, &mut buf, 0).unwrap_err();
    assert!(
        matches!(err, packet_dissector::error::PacketError::InvalidHeader(_)),
        "expected InvalidHeader for name > 255 bytes, got: {err:?}"
    );
}

#[test]
fn parse_dns_header_z_bit() {
    // RFC 1035, Section 4.1.1 — Z is the reserved bit (bit 6 of flags word).
    // Flags byte 3 = 0x40 sets Z=1; all other flags zero.
    let mut pkt = vec![0u8; 12];
    pkt[3] = 0x40; // bit 6 of the flags word

    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&pkt, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "z").unwrap().value,
        FieldValue::U8(1),
        "Z reserved bit should be 1"
    );
    // Neighbouring bits should be unaffected
    assert_eq!(
        buf.field_by_name(layer, "ra").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "ad").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "cd").unwrap().value,
        FieldValue::U8(0)
    );
}

#[test]
fn parse_dns_rdata_naptr_field_ranges() {
    // RFC 3403, Section 2 — each char-string (flags, services, regexp) must
    // carry its own individual byte range, not a shared range covering all three.
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&100u16.to_be_bytes()); // order
    rdata.extend_from_slice(&10u16.to_be_bytes()); // preference
    // flags: "u" — 1 length byte + 1 content byte  (rdata[4..6])
    rdata.push(1);
    rdata.push(b'u');
    // services: "E2U+sip" — 1 length byte + 7 content bytes  (rdata[6..14])
    rdata.push(7);
    rdata.extend_from_slice(b"E2U+sip");
    // regexp: 26-byte string  (rdata[14..41])
    let regexp = b"!^.*$!sip:info@example.com!";
    rdata.push(regexp.len() as u8);
    rdata.extend_from_slice(regexp);
    // replacement: sip.example.com
    rdata.push(3);
    rdata.extend_from_slice(b"sip");
    rdata.push(7);
    rdata.extend_from_slice(b"example");
    rdata.push(3);
    rdata.extend_from_slice(b"com");
    rdata.push(0);

    let data = build_dns_response_with_rdata(35, &rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    // RDATA absolute start offset inside the built packet:
    // Header(12) + "example.com" name(13) + QTYPE(2)+QCLASS(2)
    // + answer NAME ptr(2) + TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) = 41
    let rdata_abs = 41usize;

    let flags_field = answer_0_field_full(&buf, "rdata_flags");
    assert_eq!(
        flags_field.range,
        rdata_abs + 4..rdata_abs + 6,
        "flags range should cover only its own 2 bytes (len+content)"
    );

    let services_field = answer_0_field_full(&buf, "rdata_services");
    assert_eq!(
        services_field.range,
        rdata_abs + 6..rdata_abs + 14,
        "services range should cover only its own 8 bytes (len+content)"
    );

    // regexp = "!^.*$!sip:info@example.com!" = 27 bytes of content → char-str = 1+27 = 28 bytes
    let regexp_field = answer_0_field_full(&buf, "rdata_regexp");
    assert_eq!(
        regexp_field.range,
        rdata_abs + 14..rdata_abs + 42,
        "regexp range should cover only its own 28 bytes (len+content)"
    );
}

// ---- DNS over TCP reassembly tests ----
//
// TCP stream reassembly is now handled by the registry. These tests build
// full Ethernet+IPv4+TCP packets and feed them through the registry to
// verify reassembly behavior.

use packet_dissector::registry::DissectorRegistry;

/// Build a raw Ethernet + IPv4 + TCP packet with the given DNS TCP payload.
///
/// Returns the full wire-format packet suitable for registry.dissect().
fn build_raw_eth_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(&[0x00; 6]); // dst MAC
    pkt.extend_from_slice(&[0x00; 6]); // src MAC
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let tcp_header_len = 20;
    let total_len = 20u16 + tcp_header_len as u16 + payload.len() as u16;
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // identification
    pkt.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
    pkt.push(0x40); // TTL=64
    pkt.push(6); // protocol=TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // TCP header (20 bytes, data offset = 5)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes()); // sequence number
    pkt.extend_from_slice(&0u32.to_be_bytes()); // ack number
    pkt.push(0x50); // data offset = 5 (20 bytes), reserved = 0
    pkt.push(0x18); // flags: ACK + PSH
    pkt.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

    // Payload
    pkt.extend_from_slice(payload);

    pkt
}

#[test]
fn dns_tcp_reassembly_two_segments() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&dns_msg);

    let split_at = tcp_data.len() / 2;
    let part1 = &tcp_data[..split_at];
    let part2 = &tcp_data[split_at..];
    let base_seq: u32 = 1000;

    // Segment 1: first half — should get reassembly-in-progress on TCP layer
    let pkt1 =
        build_raw_eth_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 53, base_seq, part1);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt1, &mut buf).unwrap();

    let tcp1 = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(tcp1, "reassembly_in_progress")
            .unwrap()
            .value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(tcp1, "segment_count").unwrap().value,
        FieldValue::U32(1)
    );
    // DNS layer exists with reassembly metadata (enables -p dns filtering)
    let dns1 = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns1, "reassembly_in_progress")
            .unwrap()
            .value,
        FieldValue::U8(1)
    );
    assert_eq!(
        buf.field_by_name(dns1, "segment_count").unwrap().value,
        FieldValue::U32(1)
    );

    // Segment 2: second half — should get full DNS layer
    let pkt2 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        53,
        base_seq + split_at as u32,
        part2,
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt2, &mut buf).unwrap();

    let dns = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns, "tcp_length").unwrap().value,
        FieldValue::U16(dns_msg.len() as u16)
    );
    assert_eq!(
        buf.field_by_name(dns, "id").unwrap().value,
        FieldValue::U16(0x1234)
    );
}

#[test]
fn dns_tcp_reassembly_three_segments() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&dns_msg);

    let split1 = tcp_data.len() / 3;
    let split2 = 2 * tcp_data.len() / 3;
    let part1 = &tcp_data[..split1];
    let part2 = &tcp_data[split1..split2];
    let part3 = &tcp_data[split2..];
    let base_seq: u32 = 5000;

    // Segment 1
    let pkt1 =
        build_raw_eth_ipv4_tcp_packet([192, 168, 1, 1], [8, 8, 8, 8], 50000, 53, base_seq, part1);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt1, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_some()
    );
    // DNS layer with reassembly metadata
    let dns1 = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns1, "reassembly_in_progress")
            .unwrap()
            .value,
        FieldValue::U8(1)
    );

    // Segment 2
    let pkt2 = build_raw_eth_ipv4_tcp_packet(
        [192, 168, 1, 1],
        [8, 8, 8, 8],
        50000,
        53,
        base_seq + split1 as u32,
        part2,
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt2, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_some()
    );
    assert_eq!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "segment_count"))
            .unwrap()
            .value,
        FieldValue::U32(2)
    );
    // DNS layer with reassembly metadata
    let dns2 = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns2, "segment_count").unwrap().value,
        FieldValue::U32(2)
    );

    // Segment 3 — should complete the DNS message
    let pkt3 = build_raw_eth_ipv4_tcp_packet(
        [192, 168, 1, 1],
        [8, 8, 8, 8],
        50000,
        53,
        base_seq + split2 as u32,
        part3,
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt3, &mut buf).unwrap();
    let dns = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns, "id").unwrap().value,
        FieldValue::U16(0x1234)
    );
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_none()
    );
}

#[test]
fn dns_tcp_single_segment_with_stream_info() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&dns_msg);

    let pkt =
        build_raw_eth_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 53, 1000, &tcp_data);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    let dns = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns, "tcp_length").unwrap().value,
        FieldValue::U16(dns_msg.len() as u16)
    );
    assert_eq!(
        buf.field_by_name(dns, "id").unwrap().value,
        FieldValue::U16(0x1234)
    );
}

#[test]
fn dns_tcp_independent_streams() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut tcp_data = Vec::new();
    tcp_data.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    tcp_data.extend_from_slice(&dns_msg);

    let split_at = tcp_data.len() / 2;
    let part1 = &tcp_data[..split_at];
    let part2 = &tcp_data[split_at..];

    // Stream A: first segment
    let pkt_a1 =
        build_raw_eth_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 53, 1000, part1);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt_a1, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_some()
    );
    assert!(
        buf.layer_by_name("DNS").is_some(),
        "intermediate DNS-over-TCP segment must have DNS layer"
    );

    // Stream B: first segment (different source IP)
    let pkt_b1 =
        build_raw_eth_ipv4_tcp_packet([10, 0, 0, 3], [10, 0, 0, 2], 12345, 53, 2000, part1);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt_b1, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_some()
    );
    assert!(
        buf.layer_by_name("DNS").is_some(),
        "intermediate DNS-over-TCP segment must have DNS layer"
    );

    // Complete stream A
    let pkt_a2 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        53,
        1000 + split_at as u32,
        part2,
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt_a2, &mut buf).unwrap();
    assert_eq!(
        buf.layer_by_name("DNS")
            .and_then(|l| buf.field_by_name(l, "id"))
            .unwrap()
            .value,
        FieldValue::U16(0x1234)
    );

    // Complete stream B
    let pkt_b2 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 2],
        12345,
        53,
        2000 + split_at as u32,
        part2,
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt_b2, &mut buf).unwrap();
    assert_eq!(
        buf.layer_by_name("DNS")
            .and_then(|l| buf.field_by_name(l, "id"))
            .unwrap()
            .value,
        FieldValue::U16(0x1234)
    );
}

#[test]
fn dns_tcp_base_seq_advances_after_consume() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(&dns_msg);
    let msg_len = framed.len();

    let base_seq: u32 = 1000;
    let split = msg_len / 2;

    // First DNS message: segment 1
    let pkt1 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9000,
        53,
        base_seq,
        &framed[..split],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt1, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_some()
    );
    assert!(
        buf.layer_by_name("DNS").is_some(),
        "intermediate segment must have DNS layer"
    );

    // First DNS message: segment 2
    let pkt2 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9000,
        53,
        base_seq + split as u32,
        &framed[split..],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt2, &mut buf).unwrap();
    assert_eq!(
        buf.layer_by_name("DNS")
            .and_then(|l| buf.field_by_name(l, "id"))
            .unwrap()
            .value,
        FieldValue::U16(0x1234),
        "first DNS message must be fully parsed"
    );

    // Second DNS message: segment 1
    let seq2 = base_seq + msg_len as u32;
    let pkt3 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9000,
        53,
        seq2,
        &framed[..split],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt3, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("TCP")
            .and_then(|l| buf.field_by_name(l, "reassembly_in_progress"))
            .is_some(),
        "second message first segment must be reassembly-in-progress"
    );
    assert!(
        buf.layer_by_name("DNS").is_some(),
        "second message intermediate segment must have DNS layer"
    );

    // Second DNS message: segment 2
    let pkt4 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9000,
        53,
        seq2 + split as u32,
        &framed[split..],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt4, &mut buf).unwrap();
    let dns4 = buf.layer_by_name("DNS").unwrap();
    assert!(
        buf.field_by_name(dns4, "reassembly_in_progress").is_none(),
        "second message must be fully assembled"
    );
    assert_eq!(
        buf.field_by_name(dns4, "id").unwrap().value,
        FieldValue::U16(0x1234),
        "second DNS message must be fully parsed"
    );
}

#[test]
fn dns_tcp_large_seq_jump_resets_stream() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(&dns_msg);

    // First segment establishes base_seq = 1000
    let pkt1 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9001,
        53,
        1000,
        &framed[..framed.len() / 2],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt1, &mut buf).unwrap();

    // Second segment with seq far beyond MAX_STREAM_WINDOW (1 MiB + 1)
    let far_seq: u32 = 1000_u32.wrapping_add(1_048_577);
    let pkt2 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9001,
        53,
        far_seq,
        &framed[..framed.len() / 2],
    );
    let mut buf = DissectBuffer::new();
    let result = reg.dissect(&pkt2, &mut buf);
    assert!(
        result.is_ok(),
        "large seq jump must not cause an error/panic"
    );
}

#[test]
fn dns_tcp_backward_seq_resets_stream() {
    let reg = DissectorRegistry::default();

    let dns_msg = build_dns_query();
    let mut framed = Vec::new();
    framed.extend_from_slice(&(dns_msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(&dns_msg);

    // Establish stream at base_seq = 2_000_000
    let base: u32 = 2_000_000;
    let pkt1 =
        build_raw_eth_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 9002, 53, base, &framed[..1]);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt1, &mut buf).unwrap();

    // Send a segment at seq=0 — simulates 4-tuple reuse
    let pkt2 = build_raw_eth_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 9002, 53, 0, &framed);
    let mut buf = DissectBuffer::new();
    let result = reg.dissect(&pkt2, &mut buf);
    assert!(result.is_ok(), "backward seq must not cause an error/panic");
    // After reset, the complete framed message should be parsed
    result.unwrap();
    let dns = buf.layer_by_name("DNS").unwrap();
    assert_eq!(
        buf.field_by_name(dns, "id").unwrap().value,
        FieldValue::U16(0x1234)
    );
}

/// RFC 7766, Section 6.2.1 — pipelining: multiple DNS messages on one TCP
/// connection within a single segment.
#[test]
fn dns_tcp_pipelined_messages() {
    let reg = DissectorRegistry::default();

    // Build two DNS queries with different IDs
    let msg1 = build_dns_query_with_id(0xAAAA);
    let msg2 = build_dns_query_with_id(0xBBBB);

    // Frame both with TCP length prefixes and concatenate
    let mut framed = Vec::new();
    framed.extend_from_slice(&(msg1.len() as u16).to_be_bytes());
    framed.extend_from_slice(&msg1);
    framed.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
    framed.extend_from_slice(&msg2);

    // Send as a single TCP segment containing both pipelined messages
    let pkt = build_raw_eth_ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 9010, 53, 1000, &framed);
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt, &mut buf).unwrap();

    // Both DNS messages should be parsed
    let dns_layers: Vec<_> = buf.layers().iter().filter(|l| l.name == "DNS").collect();
    assert_eq!(
        dns_layers.len(),
        2,
        "expected 2 DNS layers from pipelined messages, got {}",
        dns_layers.len()
    );
    assert_eq!(
        buf.field_by_name(dns_layers[0], "id").unwrap().value,
        FieldValue::U16(0xAAAA)
    );
    assert_eq!(
        buf.field_by_name(dns_layers[1], "id").unwrap().value,
        FieldValue::U16(0xBBBB)
    );
}

#[test]
fn dns_tcp_buffered_pipelined_messages_preserve_names() {
    let reg = DissectorRegistry::default();

    let msg1 = build_dns_query_with_id(0xAAAA);
    let msg2 = build_dns_query_with_id(0xBBBB);

    let mut framed = Vec::new();
    framed.extend_from_slice(&(msg1.len() as u16).to_be_bytes());
    framed.extend_from_slice(&msg1);
    framed.extend_from_slice(&(msg2.len() as u16).to_be_bytes());
    framed.extend_from_slice(&msg2);

    let split = 10;
    let pkt1 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9010,
        53,
        1000,
        &framed[..split],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt1, &mut buf).unwrap();
    assert!(
        buf.layer_by_name("DNS")
            .and_then(|layer| buf.field_by_name(layer, "reassembly_in_progress"))
            .is_some(),
        "first partial segment should expose DNS reassembly metadata"
    );

    let pkt2 = build_raw_eth_ipv4_tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        9010,
        53,
        1000 + split as u32,
        &framed[split..],
    );
    let mut buf = DissectBuffer::new();
    reg.dissect(&pkt2, &mut buf).unwrap();

    let dns_layers: Vec<_> = buf.layers().iter().filter(|l| l.name == "DNS").collect();
    assert_eq!(dns_layers.len(), 2);
    assert_eq!(
        buf.field_by_name(dns_layers[0], "id").unwrap().value,
        FieldValue::U16(0xAAAA)
    );
    assert_eq!(
        buf.field_by_name(dns_layers[1], "id").unwrap().value,
        FieldValue::U16(0xBBBB)
    );

    let FieldValue::Array(ref q0_range) =
        buf.field_by_name(dns_layers[0], "questions").unwrap().value
    else {
        panic!("expected first DNS questions array")
    };
    let questions0 = buf
        .nested_fields(q0_range)
        .iter()
        .filter(|f| f.value.is_object())
        .collect::<Vec<_>>();
    assert_eq!(questions0.len(), 1);
    assert_eq!(
        obj_field(&buf, questions0[0], "name"),
        Some(FieldValue::Bytes(dns_wire_name("example.com").leak()))
    );

    let FieldValue::Array(ref q1_range) =
        buf.field_by_name(dns_layers[1], "questions").unwrap().value
    else {
        panic!("expected second DNS questions array")
    };
    let questions1 = buf
        .nested_fields(q1_range)
        .iter()
        .filter(|f| f.value.is_object())
        .collect::<Vec<_>>();
    assert_eq!(questions1.len(), 1);
    assert_eq!(
        obj_field(&buf, questions1[0], "name"),
        Some(FieldValue::Bytes(dns_wire_name("example.com").leak()))
    );
}

#[test]
fn parse_dns_edns0_tcp_keepalive_with_timeout() {
    // RFC 7828 — TCP Keepalive option (code=11) with 2-byte timeout.
    // Timeout value: 1200 (= 120.0 seconds in 100ms units).
    let mut opt_rdata = Vec::new();
    opt_rdata.extend_from_slice(&11u16.to_be_bytes()); // option code = TCP-KEEPALIVE
    opt_rdata.extend_from_slice(&2u16.to_be_bytes()); // option length = 2
    opt_rdata.extend_from_slice(&1200u16.to_be_bytes()); // timeout = 1200 (120s)

    let data = build_dns_response_with_opt(4096, [0, 0, 0x80, 0x00], &opt_rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref additionals_range) =
        buf.field_by_name(layer, "additionals").unwrap().value
    else {
        panic!("expected Array")
    };
    let additionals_all = buf.nested_fields(additionals_range);
    let additionals: Vec<_> = additionals_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    let opt = &additionals[0];
    let FieldValue::Object(ref opt_obj_range) = opt.value else {
        panic!("expected Object")
    };
    let opt_fields = buf.nested_fields(opt_obj_range);
    let edns_field = opt_fields
        .iter()
        .find(|f| f.name() == "edns_options")
        .unwrap();
    let FieldValue::Array(ref edns_range) = edns_field.value else {
        panic!("edns_options should be an Array")
    };
    let edns_all = buf.nested_fields(edns_range);
    let edns_objs: Vec<_> = edns_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(edns_objs.len(), 1);
    let FieldValue::Object(ref opt0_range) = edns_objs[0].value else {
        panic!("expected Object")
    };
    let opt0 = buf.nested_fields(opt0_range);
    assert_eq!(
        opt0.iter().find(|f| f.name() == "code").unwrap().value,
        FieldValue::U16(11)
    );
    assert_eq!(
        buf.resolve_nested_display_name(opt0_range, "code_name"),
        Some("TCP-KEEPALIVE")
    );
    assert_eq!(
        opt0.iter().find(|f| f.name() == "length").unwrap().value,
        FieldValue::U16(2)
    );
    assert_eq!(
        opt0.iter().find(|f| f.name() == "timeout").unwrap().value,
        FieldValue::U16(1200)
    );
    assert!(opt0.iter().find(|f| f.name() == "data").is_none());
}

#[test]
fn parse_dns_edns0_tcp_keepalive_no_timeout() {
    // RFC 7828 — TCP Keepalive option (code=11) with no timeout (query form).
    let mut opt_rdata = Vec::new();
    opt_rdata.extend_from_slice(&11u16.to_be_bytes()); // option code = TCP-KEEPALIVE
    opt_rdata.extend_from_slice(&0u16.to_be_bytes()); // option length = 0

    let data = build_dns_response_with_opt(4096, [0, 0, 0x80, 0x00], &opt_rdata);
    let mut buf = DissectBuffer::new();
    DnsDissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("DNS").unwrap();
    let FieldValue::Array(ref additionals_range) =
        buf.field_by_name(layer, "additionals").unwrap().value
    else {
        panic!("expected Array")
    };
    let additionals_all = buf.nested_fields(additionals_range);
    let additionals: Vec<_> = additionals_all
        .iter()
        .filter(|f| f.value.is_object())
        .collect();
    let opt = &additionals[0];
    let FieldValue::Object(ref opt_obj_range) = opt.value else {
        panic!("expected Object")
    };
    let opt_fields = buf.nested_fields(opt_obj_range);
    let edns_field = opt_fields
        .iter()
        .find(|f| f.name() == "edns_options")
        .unwrap();
    let FieldValue::Array(ref edns_range) = edns_field.value else {
        panic!("edns_options should be an Array")
    };
    let edns_all = buf.nested_fields(edns_range);
    let edns_objs: Vec<_> = edns_all.iter().filter(|f| f.value.is_object()).collect();
    assert_eq!(edns_objs.len(), 1);
    let FieldValue::Object(ref opt0_range) = edns_objs[0].value else {
        panic!("expected Object")
    };
    let opt0 = buf.nested_fields(opt0_range);
    assert_eq!(
        opt0.iter().find(|f| f.name() == "code").unwrap().value,
        FieldValue::U16(11)
    );
    assert_eq!(
        buf.resolve_nested_display_name(opt0_range, "code_name"),
        Some("TCP-KEEPALIVE")
    );
    assert_eq!(
        opt0.iter().find(|f| f.name() == "length").unwrap().value,
        FieldValue::U16(0)
    );
    assert!(opt0.iter().find(|f| f.name() == "timeout").is_none());
    assert!(opt0.iter().find(|f| f.name() == "data").is_none());
}
