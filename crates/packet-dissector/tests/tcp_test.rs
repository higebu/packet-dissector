//! # RFC 9293 (TCP) Coverage
//!
//! | RFC Section | Description                                    | Test                                    |
//! |-------------|------------------------------------------------|-----------------------------------------|
//! | 3.1         | Source Port, Destination Port                  | parse_tcp_basic                         |
//! | 3.1         | Sequence Number                                | parse_tcp_basic                         |
//! | 3.1         | Acknowledgment Number                          | parse_tcp_basic                         |
//! | 3.1         | Data Offset                                    | parse_tcp_basic                         |
//! | 3.1         | Reserved (3 bits, ignored in received segments)| parse_tcp_basic, parse_tcp_nonzero_reserved_ignored |
//! | 3.1         | Flags (CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)       | parse_tcp_syn, parse_tcp_all_flags      |
//! | 3.1         | Window                                         | parse_tcp_basic                         |
//! | 3.1         | Checksum                                       | parse_tcp_basic                         |
//! | 3.1         | Urgent Pointer                                 | parse_tcp_urgent                        |
//! | 3.1         | Options (Data Offset > 5) as option objects    | parse_tcp_with_options, parse_tcp_options_with_offset |
//! | 3.1         | Options end with header, no EOL                | parse_tcp_options_without_eol           |
//! | 3.1         | Option length 0 or 1 (malformed)               | parse_tcp_option_malformed_length_zero_or_one |
//! | 3.1         | Option runs past header (malformed)            | parse_tcp_option_runs_past_header       |
//! | 3.1         | Kind byte without length byte (malformed)      | parse_tcp_option_missing_length_byte    |
//! | 3.2         | End of Option List stops parsing               | parse_tcp_option_eol_stops_parsing      |
//! | 3.2         | No-Operation                                   | parse_tcp_with_options                  |
//! | 3.2         | Maximum Segment Size                           | parse_tcp_with_options                  |
//! | 3.2         | Known kind with wrong length kept as data      | parse_tcp_option_known_kind_wrong_length_keeps_data |
//! | —           | Option kind names (IANA registry)              | parse_tcp_option_kind_name_resolves, parse_tcp_option_unknown_kind |
//! | —           | Truncated header                               | parse_tcp_truncated                     |
//! | —           | Data Offset < 5 invalid                        | parse_tcp_invalid_data_offset           |
//! | —           | Truncated with options                         | parse_tcp_truncated_with_options        |
//! | —           | Offset handling                                | parse_tcp_with_offset                   |
//! | —           | Dissector metadata                             | tcp_dissector_metadata                  |
//! | —           | Next dissector by port                         | parse_tcp_next_dissector_by_port        |
//! | —           | Stream ID (sequential) with IPv4               | tcp_stream_id_present_ipv4              |
//! | —           | Stream ID consistent for same 4-tuple          | tcp_stream_id_consistent                |
//! | —           | Stream ID differs for different 4-tuples       | tcp_stream_id_different                 |
//! | —           | Stream ID absent without IP layer              | tcp_stream_id_absent_without_ip         |
//! | —           | Stream ID with IPv6                            | tcp_stream_id_present_ipv6              |
//! | —           | Stream ID (bidirectional)                      | tcp_stream_id_bidirectional             |
//! | —           | Stream ID is sequential                        | tcp_stream_id_sequential                |
//! | 3.5         | Stream ID kept after RST (retransmitted RST)   | tcp_stream_id_kept_after_rst            |
//! | 3.5         | Stream ID rotates on SYN with a new ISN        | tcp_stream_id_rotates_on_new_syn        |
//! | 3.5         | Stream ID kept on retransmitted SYN            | tcp_stream_id_kept_on_retransmitted_syn |
//! | 3.5         | Stream ID kept on simultaneous open            | tcp_stream_id_kept_on_simultaneous_open |
//! | 3.5         | Stream ID rotates on SYN after mid-stream data | tcp_stream_id_rotates_on_syn_after_data |
//! | 3.1         | Reassembly context carries flags and ISN+1     | tcp_stream_context_syn_seq_and_flags    |
//! | 3.1         | ISN+1 carried per direction (stream_start)     | tcp_stream_context_stream_start_per_direction |
//! | —           | Oldest connection evicted past the table limit | tcp_stream_id_table_evicts_oldest       |
//! | 3.1         | Payload length from the IP length fields       | tcp_payload_len_from_ip_total_length    |
//! | 3.1         | Payload length of a reassembled IP datagram    | tcp_payload_len_of_reassembled_datagram |
//!
//! # TCP Option RFC Coverage
//!
//! | RFC / Section      | Description                              | Test                                  |
//! |--------------------|------------------------------------------|---------------------------------------|
//! | RFC 7323 §2.2      | Window Scale                             | parse_tcp_with_options                |
//! | RFC 7323 §3.2      | Timestamps                               | parse_tcp_with_options                |
//! | RFC 2018 §2        | SACK-Permitted                           | parse_tcp_with_options                |
//! | RFC 2018 §3        | SACK blocks                              | parse_tcp_option_sack_blocks          |
//! | RFC 2385 §3.0      | MD5 Signature                            | parse_tcp_option_md5_signature        |
//! | RFC 5925 §2.2      | TCP-AO (KeyID, RNextKeyID, MAC)          | parse_tcp_option_tcp_ao               |
//! | RFC 8684 §3, §7.2  | MPTCP subtype                            | parse_tcp_option_mptcp_subtype        |
//! | RFC 7413 §4.1.1    | Fast Open cookie / cookie request        | parse_tcp_option_fast_open            |
//! | RFC 9768 §3.2.3    | AccECN0 / AccECN1, short and odd lengths | parse_tcp_option_accecn               |
//! | RFC 6994 §3        | Experimental option ExID                 | parse_tcp_option_experimental_exid    |
//! | RFC 9768 §3.1.1    | AE flag (former NS bit)                  | parse_tcp_ae_flag, parse_tcp_nonzero_reserved_ignored |

use packet_dissector::dissector::{DispatchHint, Dissector};
use packet_dissector::field::{Field, FieldValue};
use packet_dissector::packet::DissectBuffer;

use packet_dissector::dissectors::tcp::TcpDissector;

/// Create a leaked static FieldDescriptor for tests.
#[cfg(test)]
fn test_desc(
    name: &'static str,
    display_name: &'static str,
) -> &'static packet_dissector::field::FieldDescriptor {
    Box::leak(Box::new(packet_dissector::field::FieldDescriptor {
        name,
        display_name,
        field_type: packet_dissector::field::FieldType::U8, // placeholder
        optional: false,
        children: None,
        display_fn: None,
        format_fn: None,
    }))
}

/// Build a minimal valid TCP header (20 bytes, no options).
fn build_tcp_packet(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    // RFC 9293, Section 3.1
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes()); // Source Port
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes()); // Destination Port
    pkt[4..8].copy_from_slice(&seq.to_be_bytes()); // Sequence Number
    pkt[8..12].copy_from_slice(&ack.to_be_bytes()); // Acknowledgment Number
    pkt[12] = 0x50; // Data Offset = 5, Reserved = 0
    pkt[13] = flags; // Flags
    pkt[14..16].copy_from_slice(&8192u16.to_be_bytes()); // Window = 8192
    pkt[16..18].copy_from_slice(&[0x00, 0x00]); // Checksum (0 for test)
    pkt[18..20].copy_from_slice(&[0x00, 0x00]); // Urgent Pointer
    pkt
}

#[test]
fn parse_tcp_basic() {
    let data = build_tcp_packet(12345, 80, 0x01020304, 0x05060708, 0x10); // ACK
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0).unwrap();

    assert_eq!(result.bytes_consumed, 20);

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(layer.name, "TCP");
    assert_eq!(layer.range, 0..20);

    assert_eq!(
        buf.field_by_name(layer, "src_port").unwrap().value,
        FieldValue::U16(12345)
    );
    assert_eq!(
        buf.field_by_name(layer, "dst_port").unwrap().value,
        FieldValue::U16(80)
    );
    assert_eq!(
        buf.field_by_name(layer, "seq").unwrap().value,
        FieldValue::U32(0x01020304)
    );
    assert_eq!(
        buf.field_by_name(layer, "ack").unwrap().value,
        FieldValue::U32(0x05060708)
    );
    assert_eq!(
        buf.field_by_name(layer, "data_offset").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x10)
    );
    assert_eq!(
        buf.field_by_name(layer, "window").unwrap().value,
        FieldValue::U16(8192)
    );
    assert_eq!(
        buf.field_by_name(layer, "checksum").unwrap().value,
        FieldValue::U16(0)
    );
    assert_eq!(
        buf.field_by_name(layer, "urgent_pointer").unwrap().value,
        FieldValue::U16(0)
    );
}

#[test]
fn parse_tcp_syn() {
    let data = build_tcp_packet(54321, 443, 0xAABBCCDD, 0, 0x02); // SYN
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x02)
    ); // SYN
}

#[test]
fn parse_tcp_all_flags() {
    // CWR=0x80, ECE=0x40, URG=0x20, ACK=0x10, PSH=0x08, RST=0x04, SYN=0x02, FIN=0x01
    let data = build_tcp_packet(1, 2, 0, 0, 0xFF); // All flags set
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0xFF)
    );
}

#[test]
fn parse_tcp_urgent() {
    let mut data = build_tcp_packet(1, 2, 0, 0, 0x20); // URG flag
    data[18..20].copy_from_slice(&100u16.to_be_bytes()); // Urgent Pointer = 100
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "flags").unwrap().value,
        FieldValue::U8(0x20)
    ); // URG
    assert_eq!(
        buf.field_by_name(layer, "urgent_pointer").unwrap().value,
        FieldValue::U16(100)
    );
}

/// Build a TCP header whose Options area is `opts`, zero-padded to a
/// multiple of 4 bytes (RFC 9293, Section 3.1).
fn build_tcp_with_options(opts: &[u8], flags: u8) -> Vec<u8> {
    let padded = opts.len().div_ceil(4) * 4;
    let mut pkt = build_tcp_packet(8080, 80, 0, 0, flags);
    pkt[12] = (((20 + padded) / 4) as u8) << 4;
    pkt.extend_from_slice(opts);
    pkt.resize(20 + padded, 0);
    pkt
}

/// Return the flat-buffer indices of the direct children of a container
/// field, skipping grandchildren.
fn child_indices(buf: &DissectBuffer<'_>, range: &std::ops::Range<u32>) -> Vec<u32> {
    let mut out = Vec::new();
    let mut i = range.start;
    while i < range.end {
        out.push(i);
        i = match &buf.fields()[i as usize].value {
            FieldValue::Array(r) | FieldValue::Object(r) => r.end,
            _ => i + 1,
        };
    }
    out
}

/// Return the direct children of a container field, skipping grandchildren.
fn direct_children<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    range: &std::ops::Range<u32>,
) -> Vec<&'a Field<'pkt>> {
    child_indices(buf, range)
        .into_iter()
        .map(|i| &buf.fields()[i as usize])
        .collect()
}

/// Dissect `data` and return the flat-buffer indices of the TCP option
/// objects in wire order.
fn dissect_options<'pkt>(data: &'pkt [u8], buf: &mut DissectBuffer<'pkt>) -> Vec<u32> {
    TcpDissector::new().dissect(data, buf, 0).unwrap();
    let layer = buf.layer_by_name("TCP").unwrap();
    let opts = buf.field_by_name(layer, "options").unwrap();
    let range = match &opts.value {
        FieldValue::Array(r) => r.clone(),
        other => panic!("options must be an Array, got {other:?}"),
    };
    let idx = child_indices(buf, &range);
    for &i in &idx {
        let f = &buf.fields()[i as usize];
        assert_eq!(f.name(), "option");
        assert!(f.value.is_object());
    }
    idx
}

/// Look up a named child of the option object at `idx`.
fn opt_field<'a, 'pkt>(
    buf: &'a DissectBuffer<'pkt>,
    idx: u32,
    name: &str,
) -> Option<&'a Field<'pkt>> {
    let FieldValue::Object(r) = &buf.fields()[idx as usize].value else {
        panic!("not an object");
    };
    direct_children(buf, r)
        .into_iter()
        .find(|f| f.name() == name)
}

fn opt_value<'pkt>(buf: &DissectBuffer<'pkt>, idx: u32, name: &str) -> FieldValue<'pkt> {
    opt_field(buf, idx, name)
        .unwrap_or_else(|| panic!("option field {name} missing"))
        .value
        .clone()
}

fn opt_kind_name(buf: &DissectBuffer<'_>, idx: u32) -> Option<&'static str> {
    buf.resolve_container_display_name(idx)
}

#[test]
fn parse_tcp_with_options() {
    // Linux SYN option set: MSS, SACK-Permitted, Timestamps, NOP, Window Scale.
    let data = build_tcp_with_options(
        &[
            0x02, 0x04, 0x05, 0xB4, // MSS 1460
            0x04, 0x02, // SACK Permitted
            0x08, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // TS 1, 0
            0x01, // NOP
            0x03, 0x03, 0x07, // Window Scale 7
        ],
        0x02,
    );
    assert_eq!(data.len(), 40);
    let mut buf = DissectBuffer::new();
    let opts = dissect_options(&data, &mut buf);
    assert_eq!(opts.len(), 5);

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(buf.field_by_name(layer, "options").unwrap().range, 20..40);

    // RFC 9293, Section 3.2 — MSS
    assert_eq!(opt_value(&buf, opts[0], "kind"), FieldValue::U8(2));
    assert_eq!(opt_value(&buf, opts[0], "length"), FieldValue::U8(4));
    assert_eq!(opt_value(&buf, opts[0], "mss"), FieldValue::U16(1460));
    assert_eq!(opt_field(&buf, opts[0], "mss").unwrap().range, 22..24);
    assert_eq!(buf.fields()[opts[0] as usize].range, 20..24);
    assert_eq!(opt_kind_name(&buf, opts[0]), Some("Maximum Segment Size"));

    // RFC 2018, Section 2 — SACK Permitted
    assert_eq!(opt_value(&buf, opts[1], "kind"), FieldValue::U8(4));
    assert_eq!(opt_value(&buf, opts[1], "length"), FieldValue::U8(2));
    assert_eq!(opt_kind_name(&buf, opts[1]), Some("SACK Permitted"));

    // RFC 7323, Section 3.2 — Timestamps
    assert_eq!(opt_value(&buf, opts[2], "kind"), FieldValue::U8(8));
    assert_eq!(opt_value(&buf, opts[2], "ts_val"), FieldValue::U32(1));
    assert_eq!(opt_value(&buf, opts[2], "ts_ecr"), FieldValue::U32(0));
    assert_eq!(opt_kind_name(&buf, opts[2]), Some("Timestamps"));

    // RFC 9293, Section 3.2 — NOP has no length
    assert_eq!(opt_value(&buf, opts[3], "kind"), FieldValue::U8(1));
    assert!(opt_field(&buf, opts[3], "length").is_none());
    assert_eq!(opt_kind_name(&buf, opts[3]), Some("No-Operation"));
    assert_eq!(buf.fields()[opts[3] as usize].range, 36..37);

    // RFC 7323, Section 2.2 — Window Scale
    assert_eq!(opt_value(&buf, opts[4], "kind"), FieldValue::U8(3));
    assert_eq!(opt_value(&buf, opts[4], "shift_count"), FieldValue::U8(7));
    assert_eq!(opt_kind_name(&buf, opts[4]), Some("Window Scale"));
}

#[test]
fn parse_tcp_option_kind_name_resolves() {
    let data = build_tcp_with_options(&[0x02, 0x04, 0x05, 0xB4], 0x02);
    let mut buf = DissectBuffer::new();
    let opts = dissect_options(&data, &mut buf);
    let FieldValue::Object(r) = buf.fields()[opts[0] as usize].value.clone() else {
        unreachable!()
    };
    assert_eq!(
        buf.resolve_nested_display_name(&r, "kind_name"),
        Some("Maximum Segment Size")
    );
}

#[test]
fn parse_tcp_option_eol_stops_parsing() {
    // NOP, EOL, then padding that looks like an MSS option must be ignored.
    let data = build_tcp_with_options(&[0x01, 0x00, 0x02, 0x04, 0x05, 0xB4, 0x00, 0x00], 0x10);
    let mut buf = DissectBuffer::new();
    let opts = dissect_options(&data, &mut buf);
    assert_eq!(opts.len(), 2);
    assert_eq!(opt_value(&buf, opts[1], "kind"), FieldValue::U8(0));
    assert!(opt_field(&buf, opts[1], "length").is_none());
    assert_eq!(opt_kind_name(&buf, opts[1]), Some("End of Option List"));
    // The Options field still covers the whole options area.
    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(buf.field_by_name(layer, "options").unwrap().range, 20..28);
}

#[test]
fn parse_tcp_option_sack_blocks() {
    let data = build_tcp_with_options(
        &[
            0x01, 0x01, // NOP NOP
            0x05, 0x12, // SACK, length 18 (2 blocks)
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, // 16..32
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, // 256..512
        ],
        0x10,
    );
    let mut buf = DissectBuffer::new();
    let opts = dissect_options(&data, &mut buf);
    assert_eq!(opts.len(), 3);
    let sack = opts[2];
    assert_eq!(opt_kind_name(&buf, sack), Some("SACK"));
    let blocks = opt_field(&buf, sack, "sack_blocks").unwrap();
    let FieldValue::Array(r) = blocks.value.clone() else {
        panic!("sack_blocks must be an Array")
    };
    assert_eq!(blocks.range, 24..40);
    let items = direct_children(&buf, &r);
    assert_eq!(items.len(), 2);
    let expect = [(16u32, 32u32, 24usize), (256, 512, 32)];
    for (item, (l, rr, start)) in items.iter().zip(expect) {
        assert_eq!(item.name(), "sack_block");
        assert_eq!(item.range, start..start + 8);
        let FieldValue::Object(or) = &item.value else {
            panic!("sack_block must be an Object")
        };
        let kids = direct_children(&buf, or);
        assert_eq!(kids[0].name(), "left_edge");
        assert_eq!(kids[0].value, FieldValue::U32(l));
        assert_eq!(kids[1].name(), "right_edge");
        assert_eq!(kids[1].value, FieldValue::U32(rr));
    }
}

#[test]
fn parse_tcp_option_md5_signature() {
    let mut opts = vec![0x13, 0x12];
    opts.extend(0u8..16);
    opts.extend([0x00, 0x00]);
    let data = build_tcp_with_options(&opts, 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_kind_name(&buf, o[0]), Some("MD5 Signature Option"));
    let expected: Vec<u8> = (0u8..16).collect();
    assert_eq!(
        opt_value(&buf, o[0], "digest"),
        FieldValue::Bytes(&expected[..])
    );
}

#[test]
fn parse_tcp_option_tcp_ao() {
    let data = build_tcp_with_options(
        &[
            0x1D, 0x10, 0x05, 0x07, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
            0xAA, 0xAB,
        ],
        0x10,
    );
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(
        opt_kind_name(&buf, o[0]),
        Some("TCP Authentication Option (TCP-AO)")
    );
    assert_eq!(opt_value(&buf, o[0], "key_id"), FieldValue::U8(5));
    assert_eq!(opt_value(&buf, o[0], "rnext_key_id"), FieldValue::U8(7));
    assert_eq!(
        opt_value(&buf, o[0], "mac"),
        FieldValue::Bytes(&[
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB
        ])
    );
}

#[test]
fn parse_tcp_option_mptcp_subtype() {
    // MP_CAPABLE (subtype 0, version 1) on a SYN, length 4.
    let data = build_tcp_with_options(&[0x1E, 0x04, 0x01, 0x81], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_kind_name(&buf, o[0]), Some("Multipath TCP (MPTCP)"));
    assert_eq!(opt_value(&buf, o[0], "subtype"), FieldValue::U8(0));
    let FieldValue::Object(r) = buf.fields()[o[0] as usize].value.clone() else {
        unreachable!()
    };
    assert_eq!(
        buf.resolve_nested_display_name(&r, "subtype_name"),
        Some("MP_CAPABLE")
    );
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[0x01, 0x81])
    );

    // DSS (subtype 2)
    let data = build_tcp_with_options(&[0x1E, 0x04, 0x20, 0x01], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_value(&buf, o[0], "subtype"), FieldValue::U8(2));
    let FieldValue::Object(r) = buf.fields()[o[0] as usize].value.clone() else {
        unreachable!()
    };
    assert_eq!(
        buf.resolve_nested_display_name(&r, "subtype_name"),
        Some("DSS")
    );
}

#[test]
fn parse_tcp_option_fast_open() {
    // Cookie request (empty cookie).
    let data = build_tcp_with_options(&[0x22, 0x02], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_kind_name(&buf, o[0]), Some("TCP Fast Open Cookie"));
    assert_eq!(opt_value(&buf, o[0], "length"), FieldValue::U8(2));
    assert!(opt_field(&buf, o[0], "cookie").is_none());
    assert!(opt_field(&buf, o[0], "data").is_none());

    // 8-byte cookie.
    let data = build_tcp_with_options(&[0x22, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(
        opt_value(&buf, o[0], "cookie"),
        FieldValue::Bytes(&[1, 2, 3, 4, 5, 6, 7, 8])
    );
}

#[test]
fn parse_tcp_option_accecn() {
    // AccECN0 (order 0): EE0B, ECEB, EE1B
    let data = build_tcp_with_options(
        &[
            0xAC, 0x0B, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03,
        ],
        0x10,
    );
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(
        opt_kind_name(&buf, o[0]),
        Some("Accurate ECN Order 0 (AccECN0)")
    );
    assert_eq!(opt_value(&buf, o[0], "ee0b"), FieldValue::U32(1));
    assert_eq!(opt_value(&buf, o[0], "eceb"), FieldValue::U32(2));
    assert_eq!(opt_value(&buf, o[0], "ee1b"), FieldValue::U32(3));
    assert_eq!(opt_field(&buf, o[0], "ee0b").unwrap().range, 22..25);

    // AccECN1 (order 1), truncated to two fields (length 8): EE1B, ECEB
    let data = build_tcp_with_options(&[0xAE, 0x08, 0x00, 0x00, 0x05, 0x00, 0x00, 0x06], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(
        opt_kind_name(&buf, o[0]),
        Some("Accurate ECN Order 1 (AccECN1)")
    );
    assert_eq!(opt_value(&buf, o[0], "ee1b"), FieldValue::U32(5));
    assert_eq!(opt_value(&buf, o[0], "eceb"), FieldValue::U32(6));
    assert!(opt_field(&buf, o[0], "ee0b").is_none());

    // Empty AccECN option (length 2)
    let data = build_tcp_with_options(&[0xAC, 0x02], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert!(opt_field(&buf, o[0], "ee0b").is_none());

    // Non-standard length 7: only the first whole 3-octet field is used,
    // the remainder is ignored as padding (RFC 9768, Section 3.2.3).
    let data = build_tcp_with_options(&[0xAC, 0x07, 0x00, 0x00, 0x09, 0xFF, 0xFF], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_value(&buf, o[0], "ee0b"), FieldValue::U32(9));
    assert!(opt_field(&buf, o[0], "eceb").is_none());
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[0xFF, 0xFF])
    );
    assert_eq!(opt_field(&buf, o[0], "data").unwrap().range, 25..27);

    // Length 14: three fields, the extra 3 octets are kept as data.
    let data = build_tcp_with_options(
        &[0xAC, 0x0E, 0, 0, 1, 0, 0, 2, 0, 0, 3, 0xEE, 0xEE, 0xEE],
        0x10,
    );
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_value(&buf, o[0], "ee1b"), FieldValue::U32(3));
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[0xEE, 0xEE, 0xEE])
    );
}

#[test]
fn parse_tcp_option_experimental_exid() {
    // RFC 6994: kind 254, 16-bit ExID 0xF989 (TCP Fast Open experimental), data.
    let data = build_tcp_with_options(&[0xFE, 0x08, 0xF9, 0x89, 1, 2, 3, 4], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(
        opt_kind_name(&buf, o[0]),
        Some("RFC3692-style Experiment 2")
    );
    assert_eq!(opt_value(&buf, o[0], "exid"), FieldValue::U16(0xF989));
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[1, 2, 3, 4])
    );

    // Kind 253 with only the ExID.
    let data = build_tcp_with_options(&[0xFD, 0x04, 0xAC, 0xC0], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(
        opt_kind_name(&buf, o[0]),
        Some("RFC3692-style Experiment 1")
    );
    assert_eq!(opt_value(&buf, o[0], "exid"), FieldValue::U16(0xACC0));
    assert!(opt_field(&buf, o[0], "data").is_none());
}

#[test]
fn parse_tcp_option_unknown_kind() {
    let data = build_tcp_with_options(&[0x63, 0x04, 0xDE, 0xAD], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(opt_value(&buf, o[0], "kind"), FieldValue::U8(99));
    assert_eq!(opt_value(&buf, o[0], "length"), FieldValue::U8(4));
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[0xDE, 0xAD])
    );
    assert_eq!(opt_kind_name(&buf, o[0]), None);
}

#[test]
fn parse_tcp_option_known_kind_wrong_length_keeps_data() {
    // MSS with length 3 (should be 4): not decoded, body kept as data.
    let data = build_tcp_with_options(&[0x02, 0x03, 0x05, 0x01], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(o.len(), 2);
    assert!(opt_field(&buf, o[0], "mss").is_none());
    assert_eq!(opt_value(&buf, o[0], "data"), FieldValue::Bytes(&[0x05]));
    // Next option is the NOP at offset 23.
    assert_eq!(opt_value(&buf, o[1], "kind"), FieldValue::U8(1));

    // SACK whose length is not 2 + 8n.
    let data = build_tcp_with_options(&[0x05, 0x06, 0, 0, 0, 1], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert!(opt_field(&buf, o[0], "sack_blocks").is_none());
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[0, 0, 0, 1])
    );

    // TCP-AO with length < 4.
    let data = build_tcp_with_options(&[0x1D, 0x03, 0x01, 0x00], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert!(opt_field(&buf, o[0], "key_id").is_none());
    assert_eq!(opt_value(&buf, o[0], "data"), FieldValue::Bytes(&[0x01]));

    // Fast Open with an odd length.
    let data = build_tcp_with_options(&[0x22, 0x07, 1, 2, 3, 4, 5], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert!(opt_field(&buf, o[0], "cookie").is_none());
    assert_eq!(
        opt_value(&buf, o[0], "data"),
        FieldValue::Bytes(&[1, 2, 3, 4, 5])
    );

    // Experimental option too short for an ExID.
    let data = build_tcp_with_options(&[0xFE, 0x03, 0x01, 0x00], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert!(opt_field(&buf, o[0], "exid").is_none());
    assert_eq!(opt_value(&buf, o[0], "data"), FieldValue::Bytes(&[0x01]));

    // MPTCP without a subtype byte.
    let data = build_tcp_with_options(&[0x1E, 0x02, 0x00, 0x00], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert!(opt_field(&buf, o[0], "subtype").is_none());
}

#[test]
fn parse_tcp_option_malformed_length_zero_or_one() {
    for bad_len in [0u8, 1] {
        let data =
            build_tcp_with_options(&[0x01, 0x02, bad_len, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE], 0x02);
        let mut buf = DissectBuffer::new();
        let result = TcpDissector::new().dissect(&data, &mut buf, 0).unwrap();
        assert_eq!(result.bytes_consumed, 28);
        let mut buf = DissectBuffer::new();
        let o = dissect_options(&data, &mut buf);
        assert_eq!(o.len(), 2);
        assert_eq!(opt_value(&buf, o[1], "kind"), FieldValue::U8(2));
        assert_eq!(opt_value(&buf, o[1], "length"), FieldValue::U8(bad_len));
        assert_eq!(
            opt_value(&buf, o[1], "data"),
            FieldValue::Bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
        );
        assert!(opt_field(&buf, o[1], "mss").is_none());
        assert_eq!(buf.fields()[o[1] as usize].range, 21..28);
    }
}

#[test]
fn parse_tcp_option_runs_past_header() {
    // NOP, NOP, then Timestamps claiming length 10 with only 6 bytes left.
    let data = build_tcp_with_options(&[0x01, 0x01, 0x08, 0x0A, 0, 0, 0, 1], 0x10);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(o.len(), 3);
    assert_eq!(opt_value(&buf, o[2], "kind"), FieldValue::U8(8));
    assert_eq!(opt_value(&buf, o[2], "length"), FieldValue::U8(10));
    assert!(opt_field(&buf, o[2], "ts_val").is_none());
    assert_eq!(
        opt_value(&buf, o[2], "data"),
        FieldValue::Bytes(&[0, 0, 0, 1])
    );
    assert_eq!(buf.fields()[o[2] as usize].range, 22..28);
}

#[test]
fn parse_tcp_option_missing_length_byte() {
    // Three NOPs then a lone MSS kind byte at the end of the header.
    let data = build_tcp_with_options(&[0x01, 0x01, 0x01, 0x02], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(o.len(), 4);
    assert_eq!(opt_value(&buf, o[3], "kind"), FieldValue::U8(2));
    assert!(opt_field(&buf, o[3], "length").is_none());
    assert_eq!(buf.fields()[o[3] as usize].range, 23..24);
}

#[test]
fn parse_tcp_options_without_eol() {
    // Options exactly fill the header with no EOL (RFC 9293, Section 3.2:
    // EOL "need only be used if the end of the options would not otherwise
    // coincide with the end of the TCP header").
    let data = build_tcp_with_options(&[0x01, 0x03, 0x03, 0x0E], 0x02);
    let mut buf = DissectBuffer::new();
    let o = dissect_options(&data, &mut buf);
    assert_eq!(o.len(), 2);
    assert_eq!(opt_value(&buf, o[1], "shift_count"), FieldValue::U8(14));
}

#[test]
fn parse_tcp_options_with_offset() {
    let data = build_tcp_with_options(&[0x02, 0x04, 0x05, 0xB4], 0x02);
    let mut buf = DissectBuffer::new();
    TcpDissector::new().dissect(&data, &mut buf, 34).unwrap();
    let layer = buf.layer_by_name("TCP").unwrap();
    let opts = buf.field_by_name(layer, "options").unwrap();
    assert_eq!(opts.range, 54..58);
    let FieldValue::Array(r) = opts.value.clone() else {
        panic!()
    };
    let o = direct_children(&buf, &r);
    assert_eq!(o[0].range, 54..58);
    let FieldValue::Object(or) = &o[0].value else {
        panic!()
    };
    let kids = direct_children(&buf, or);
    assert_eq!(kids[0].range, 54..55); // kind
    assert_eq!(kids[1].range, 55..56); // length
    assert_eq!(kids[2].range, 56..58); // mss
}

/// RFC 9768, Section 3.1.1 — the former NS bit is the AE flag.
#[test]
fn parse_tcp_ae_flag() {
    let mut data = build_tcp_packet(1234, 80, 0, 0, 0xC2); // CWR|ECE|SYN
    data[12] = 0x51; // Data Offset = 5, AE = 1
    let mut buf = DissectBuffer::new();
    TcpDissector::new().dissect(&data, &mut buf, 0).unwrap();
    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "ae").unwrap().value,
        FieldValue::U8(1)
    );
    assert_eq!(buf.field_by_name(layer, "ae").unwrap().range, 12..13);
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.resolve_display_name(layer, "flags_name"),
        Some("SYN, ECE, CWR, AE")
    );

    // AE alone.
    let mut data = build_tcp_packet(1234, 80, 0, 0, 0x00);
    data[12] = 0x51;
    let mut buf = DissectBuffer::new();
    TcpDissector::new().dissect(&data, &mut buf, 0).unwrap();
    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(buf.resolve_display_name(layer, "flags_name"), Some("AE"));

    // AE clear.
    let data = build_tcp_packet(1234, 80, 0, 0, 0x12);
    let mut buf = DissectBuffer::new();
    TcpDissector::new().dissect(&data, &mut buf, 0).unwrap();
    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "ae").unwrap().value,
        FieldValue::U8(0)
    );
    assert_eq!(
        buf.resolve_display_name(layer, "flags_name"),
        Some("SYN, ACK")
    );
}

#[test]
fn parse_tcp_truncated() {
    let data = [0u8; 10]; // Too short for 20-byte header
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 20,
            actual: 10
        }
    ));
}

#[test]
fn parse_tcp_invalid_data_offset() {
    let mut data = build_tcp_packet(1, 2, 0, 0, 0);
    data[12] = 0x30; // Data Offset = 3 (< 5)
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::InvalidFieldValue {
            field: "data_offset",
            ..
        }
    ));
}

#[test]
fn parse_tcp_truncated_with_options() {
    // Data Offset = 8 means 32 bytes header, but only 24 available
    let mut data = vec![0u8; 24];
    data[12] = 0x80; // Data Offset = 8
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let err = dissector.dissect(&data, &mut buf, 0).unwrap_err();
    assert!(matches!(
        err,
        packet_dissector::error::PacketError::Truncated {
            expected: 32,
            actual: 24
        }
    ));
}

#[test]
fn parse_tcp_with_offset() {
    let data = build_tcp_packet(1234, 5678, 0, 0, 0);
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    dissector.dissect(&data, &mut buf, 34).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(layer.range, 34..54);
    assert_eq!(buf.field_by_name(layer, "src_port").unwrap().range, 34..36);
    assert_eq!(buf.field_by_name(layer, "dst_port").unwrap().range, 36..38);
}

#[test]
fn tcp_dissector_metadata() {
    let d = TcpDissector::new();
    assert_eq!(d.name(), "Transmission Control Protocol");
    assert_eq!(d.short_name(), "TCP");
}

#[test]
fn parse_tcp_next_dissector_by_port() {
    let data = build_tcp_packet(54321, 80, 0, 0, 0x10);
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0).unwrap();
    assert_eq!(result.next, DispatchHint::ByTcpPort(54321, 80));
}

/// RFC 9293, Section 3.1: Reserved bits "MUST be zero when sent and MUST be
/// ignored when received".
/// A dissector must accept segments with non-zero Reserved bits without error.
#[test]
fn parse_tcp_nonzero_reserved_ignored() {
    let mut data = build_tcp_packet(1234, 80, 0, 0, 0x02); // SYN
    // Set the 3 Reserved bits and AE while keeping Data Offset = 5
    data[12] = 0x5F; // Data Offset = 5 (high nibble), Reserved = 0b111, AE = 1
    let mut buf = DissectBuffer::new();
    let dissector = TcpDissector::new();
    let result = dissector.dissect(&data, &mut buf, 0);
    assert!(
        result.is_ok(),
        "Non-zero Reserved bits must be ignored per RFC 9293 Section 3.1"
    );
    let layer = buf.layer_by_name("TCP").unwrap();
    assert_eq!(
        buf.field_by_name(layer, "data_offset").unwrap().value,
        FieldValue::U8(5)
    );
    assert_eq!(
        buf.field_by_name(layer, "reserved").unwrap().value,
        FieldValue::U8(0x07)
    );
    assert_eq!(
        buf.field_by_name(layer, "ae").unwrap().value,
        FieldValue::U8(1)
    );
}

/// Add a pre-populated IPv4 layer to a DissectBuffer for stream_id tests.
fn add_ipv4_layer(buf: &mut DissectBuffer<'_>, src_ip: [u8; 4], dst_ip: [u8; 4]) {
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.push_field(
        test_desc("src", "Source Address"),
        FieldValue::Ipv4Addr(src_ip),
        12..16,
    );
    buf.push_field(
        test_desc("dst", "Destination Address"),
        FieldValue::Ipv4Addr(dst_ip),
        16..20,
    );
    buf.end_layer();
}

/// Add a pre-populated IPv6 layer to a DissectBuffer for stream_id tests.
fn add_ipv6_layer(buf: &mut DissectBuffer<'_>, src_ip: [u8; 16], dst_ip: [u8; 16]) {
    buf.begin_layer("IPv6", None, &[], 0..40);
    buf.push_field(
        test_desc("src", "Source Address"),
        FieldValue::Ipv6Addr(src_ip),
        8..24,
    );
    buf.push_field(
        test_desc("dst", "Destination Address"),
        FieldValue::Ipv6Addr(dst_ip),
        24..40,
    );
    buf.end_layer();
}

#[test]
fn tcp_stream_id_present_ipv4() {
    let tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf = DissectBuffer::new();
    add_ipv4_layer(&mut buf, [10, 0, 0, 1], [10, 0, 0, 2]);
    let dissector = TcpDissector::new();
    dissector.dissect(&tcp_data, &mut buf, 20).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    let stream_id = buf.field_by_name(layer, "stream_id");
    assert!(stream_id.is_some(), "stream_id should be present with IPv4");
    assert!(
        matches!(stream_id.unwrap().value, FieldValue::U32(_)),
        "stream_id should be U32"
    );
}

#[test]
fn tcp_stream_id_consistent() {
    let dissector = TcpDissector::new();

    let tcp_data = build_tcp_packet(12345, 80, 100, 0, 0x10);
    let mut buf1 = DissectBuffer::new();
    add_ipv4_layer(&mut buf1, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data, &mut buf1, 20).unwrap();

    let tcp_data2 = build_tcp_packet(12345, 80, 200, 100, 0x10);
    let mut buf2 = DissectBuffer::new();
    add_ipv4_layer(&mut buf2, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data2, &mut buf2, 20).unwrap();

    let sid1 = buf1
        .layer_by_name("TCP")
        .and_then(|l| buf1.field_by_name(l, "stream_id"))
        .unwrap();
    let sid2 = buf2
        .layer_by_name("TCP")
        .and_then(|l| buf2.field_by_name(l, "stream_id"))
        .unwrap();
    assert_eq!(
        sid1.value, sid2.value,
        "same 4-tuple must produce the same stream_id"
    );
}

#[test]
fn tcp_stream_id_different() {
    let dissector = TcpDissector::new();

    let tcp_data1 = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf1 = DissectBuffer::new();
    add_ipv4_layer(&mut buf1, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data1, &mut buf1, 20).unwrap();

    // Different source IP
    let tcp_data2 = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf2 = DissectBuffer::new();
    add_ipv4_layer(&mut buf2, [10, 0, 0, 3], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data2, &mut buf2, 20).unwrap();

    let sid1 = buf1
        .layer_by_name("TCP")
        .and_then(|l| buf1.field_by_name(l, "stream_id"))
        .unwrap();
    let sid2 = buf2
        .layer_by_name("TCP")
        .and_then(|l| buf2.field_by_name(l, "stream_id"))
        .unwrap();
    assert_ne!(
        sid1.value, sid2.value,
        "different 4-tuples must produce different stream_ids"
    );
}

#[test]
fn tcp_stream_id_absent_without_ip() {
    let tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf = DissectBuffer::new(); // No IP layer
    let dissector = TcpDissector::new();
    dissector.dissect(&tcp_data, &mut buf, 0).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    assert!(
        buf.field_by_name(layer, "stream_id").is_none(),
        "stream_id should be absent without IP layer"
    );
}

#[test]
fn tcp_stream_id_present_ipv6() {
    let tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut src_ip = [0u8; 16];
    src_ip[15] = 1; // ::1
    let mut dst_ip = [0u8; 16];
    dst_ip[15] = 2; // ::2
    let mut buf = DissectBuffer::new();
    add_ipv6_layer(&mut buf, src_ip, dst_ip);
    let dissector = TcpDissector::new();
    dissector.dissect(&tcp_data, &mut buf, 40).unwrap();

    let layer = buf.layer_by_name("TCP").unwrap();
    let stream_id = buf.field_by_name(layer, "stream_id");
    assert!(stream_id.is_some(), "stream_id should be present with IPv6");
    assert!(matches!(stream_id.unwrap().value, FieldValue::U32(_)));
}

/// Both directions of the same TCP connection must map to the same stream_id
/// (canonicalized 4-tuple).
#[test]
fn tcp_stream_id_bidirectional() {
    let dissector = TcpDissector::new();

    // Forward: 10.0.0.1:12345 -> 10.0.0.2:80
    let tcp_fwd = build_tcp_packet(12345, 80, 100, 0, 0x02);
    let mut buf_fwd = DissectBuffer::new();
    add_ipv4_layer(&mut buf_fwd, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_fwd, &mut buf_fwd, 20).unwrap();

    // Reverse: 10.0.0.2:80 -> 10.0.0.1:12345
    let tcp_rev = build_tcp_packet(80, 12345, 200, 101, 0x12);
    let mut buf_rev = DissectBuffer::new();
    add_ipv4_layer(&mut buf_rev, [10, 0, 0, 2], [10, 0, 0, 1]);
    dissector.dissect(&tcp_rev, &mut buf_rev, 20).unwrap();

    let sid_fwd = buf_fwd
        .layer_by_name("TCP")
        .and_then(|l| buf_fwd.field_by_name(l, "stream_id"))
        .unwrap();
    let sid_rev = buf_rev
        .layer_by_name("TCP")
        .and_then(|l| buf_rev.field_by_name(l, "stream_id"))
        .unwrap();
    assert_eq!(
        sid_fwd.value, sid_rev.value,
        "reverse direction must produce the same stream_id"
    );
}

#[test]
fn tcp_stream_id_sequential() {
    let dissector = TcpDissector::new();

    // First stream: 10.0.0.1:12345 -> 10.0.0.2:80
    let tcp_data1 = build_tcp_packet(12345, 80, 0, 0, 0x02);
    let mut buf1 = DissectBuffer::new();
    add_ipv4_layer(&mut buf1, [10, 0, 0, 1], [10, 0, 0, 2]);
    dissector.dissect(&tcp_data1, &mut buf1, 20).unwrap();

    // Second stream: 10.0.0.3:54321 -> 10.0.0.4:443
    let tcp_data2 = build_tcp_packet(54321, 443, 0, 0, 0x02);
    let mut buf2 = DissectBuffer::new();
    add_ipv4_layer(&mut buf2, [10, 0, 0, 3], [10, 0, 0, 4]);
    dissector.dissect(&tcp_data2, &mut buf2, 20).unwrap();

    let sid1 = buf1
        .layer_by_name("TCP")
        .and_then(|l| buf1.field_by_name(l, "stream_id"))
        .unwrap()
        .value
        .as_u32()
        .unwrap();
    let sid2 = buf2
        .layer_by_name("TCP")
        .and_then(|l| buf2.field_by_name(l, "stream_id"))
        .unwrap()
        .value
        .as_u32()
        .unwrap();

    assert_eq!(sid1, 0, "first stream should get id 0");
    assert_eq!(sid2, 1, "second stream should get id 1");
}

/// Dissect one segment between 10.0.0.1:`sport` and 10.0.0.2:`dport`
/// (swapped when `reverse`) and return its stream_id.
fn stream_id_of(dissector: &TcpDissector, reverse: bool, seq: u32, flags: u8) -> u32 {
    let (sport, dport, src, dst) = if reverse {
        (80, 40000, [10, 0, 0, 2], [10, 0, 0, 1])
    } else {
        (40000, 80, [10, 0, 0, 1], [10, 0, 0, 2])
    };
    let tcp_data = build_tcp_packet(sport, dport, seq, 0, flags);
    let mut buf = DissectBuffer::new();
    add_ipv4_layer(&mut buf, src, dst);
    dissector.dissect(&tcp_data, &mut buf, 20).unwrap();
    let layer = buf.layer_by_name("TCP").unwrap();
    buf.field_u32(layer, "stream_id").unwrap()
}

/// RFC 9293, Section 3.5.3 — a RST ends the connection, but later packets
/// of that connection (a retransmitted RST, the peer's RST, a late ACK)
/// still belong to it.
#[test]
fn tcp_stream_id_kept_after_rst() {
    let d = TcpDissector::new();
    let syn = stream_id_of(&d, false, 1000, 0x02);
    assert_eq!(stream_id_of(&d, true, 5000, 0x12), syn);
    assert_eq!(stream_id_of(&d, false, 1001, 0x18), syn);
    assert_eq!(stream_id_of(&d, true, 5001, 0x14), syn);
    assert_eq!(stream_id_of(&d, true, 5001, 0x14), syn);
    assert_eq!(stream_id_of(&d, false, 1001, 0x10), syn);
}

/// RFC 9293, Section 3.5 — a SYN with a new ISN on a known 4-tuple opens a
/// new connection (e.g. reuse after FIN), which gets a new stream_id.
#[test]
fn tcp_stream_id_rotates_on_new_syn() {
    let d = TcpDissector::new();
    let first = stream_id_of(&d, false, 1000, 0x02);
    assert_eq!(stream_id_of(&d, false, 1001, 0x11), first);
    assert_eq!(stream_id_of(&d, true, 5001, 0x11), first);

    let second = stream_id_of(&d, false, 90000, 0x02);
    assert_ne!(second, first);
    assert_eq!(stream_id_of(&d, true, 7000, 0x12), second);
    assert_eq!(stream_id_of(&d, false, 90001, 0x10), second);
}

/// A retransmitted SYN (same ISN) belongs to the same connection.
#[test]
fn tcp_stream_id_kept_on_retransmitted_syn() {
    let d = TcpDissector::new();
    let first = stream_id_of(&d, false, 1000, 0x02);
    assert_eq!(stream_id_of(&d, false, 1000, 0x02), first);
}

/// RFC 9293, Section 3.1 — "If SYN is set, the sequence number is the
/// initial sequence number (ISN) and the first data octet is ISN+1."
#[test]
fn tcp_stream_context_syn_seq_and_flags() {
    let d = TcpDissector::new();
    let tcp_data = build_tcp_packet(40000, 80, 1000, 0, 0x02);
    let mut buf = DissectBuffer::new();
    add_ipv4_layer(&mut buf, [10, 0, 0, 1], [10, 0, 0, 2]);
    let result = d.dissect(&tcp_data, &mut buf, 20).unwrap();
    let ctx = result.tcp_stream_context.unwrap();
    assert_eq!(ctx.seq, 1001);
    assert_eq!(ctx.flags, 0x02);
    assert_eq!(ctx.stream_start, Some(1001));
    assert!(ctx.is_syn());
    assert!(!ctx.is_fin());
    assert!(!ctx.is_rst());
}

/// RFC 9293, Section 3.5 (Figure 8) — in a simultaneous open both ends send
/// a SYN without ACK; they are one connection.
#[test]
fn tcp_stream_id_kept_on_simultaneous_open() {
    let d = TcpDissector::new();
    let first = stream_id_of(&d, false, 1000, 0x02);
    assert_eq!(stream_id_of(&d, true, 5000, 0x02), first);
    assert_eq!(stream_id_of(&d, false, 1000, 0x12), first);
}

/// A SYN on a 4-tuple first seen mid-connection (capture started late)
/// opens a new connection.
#[test]
fn tcp_stream_id_rotates_on_syn_after_data() {
    let d = TcpDissector::new();
    let first = stream_id_of(&d, false, 1000, 0x18);
    assert_ne!(stream_id_of(&d, false, 90000, 0x02), first);
}

/// The ISN of each direction is carried to later segments as stream_start.
#[test]
fn tcp_stream_context_stream_start_per_direction() {
    let d = TcpDissector::new();
    let ctx_of = |reverse: bool, seq: u32, flags: u8| {
        let (sport, dport, src, dst) = if reverse {
            (80, 40000, [10, 0, 0, 2], [10, 0, 0, 1])
        } else {
            (40000, 80, [10, 0, 0, 1], [10, 0, 0, 2])
        };
        let tcp_data = build_tcp_packet(sport, dport, seq, 0, flags);
        let mut buf = DissectBuffer::new();
        add_ipv4_layer(&mut buf, src, dst);
        d.dissect(&tcp_data, &mut buf, 20)
            .unwrap()
            .tcp_stream_context
            .unwrap()
    };
    assert_eq!(ctx_of(false, 1000, 0x18).stream_start, None);
    ctx_of(false, 2000, 0x02);
    ctx_of(true, 7000, 0x12);
    assert_eq!(ctx_of(false, 2001, 0x18).stream_start, Some(2001));
    assert_eq!(ctx_of(true, 7001, 0x18).stream_start, Some(7001));
}

/// The stream-ID table is bounded: past 65,536 connections the oldest one
/// is forgotten and gets a new ID when seen again.
#[test]
fn tcp_stream_id_table_evicts_oldest() {
    let d = TcpDissector::new();
    let first = stream_id_of(&d, false, 1, 0x10);
    let tcp_data = build_tcp_packet(1, 2, 1, 0, 0x10);
    for i in 0..65_536u32 {
        let mut buf = DissectBuffer::new();
        add_ipv4_layer(
            &mut buf,
            [11, (i >> 16) as u8, (i >> 8) as u8, i as u8],
            [10, 0, 0, 2],
        );
        d.dissect(&tcp_data, &mut buf, 20).unwrap();
    }
    assert_ne!(stream_id_of(&d, false, 2, 0x10), first);
}

/// IPv4 layer with src/dst and the given Total Length at bytes 0..20.
fn add_ipv4_layer_with_total_length(buf: &mut DissectBuffer<'_>, total_length: u16) {
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.push_field(
        test_desc("total_length", "Total Length"),
        FieldValue::U16(total_length),
        2..4,
    );
    buf.push_field(
        test_desc("src", "Source Address"),
        FieldValue::Ipv4Addr([10, 0, 0, 1]),
        12..16,
    );
    buf.push_field(
        test_desc("dst", "Destination Address"),
        FieldValue::Ipv4Addr([10, 0, 0, 2]),
        16..20,
    );
    buf.end_layer();
}

#[test]
fn tcp_payload_len_from_ip_total_length() {
    // A snaplen-truncated capture holds fewer payload bytes than the IP
    // Total Length declares; the segment still occupies the declared
    // length in sequence space.
    let mut tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x18);
    tcp_data.extend_from_slice(&[0u8; 40]);
    let mut buf = DissectBuffer::new();
    add_ipv4_layer_with_total_length(&mut buf, 20 + 20 + 100);
    let result = TcpDissector::new()
        .dissect(&tcp_data, &mut buf, 20)
        .unwrap();
    assert_eq!(result.tcp_stream_context.unwrap().payload_len, 100);
}

#[test]
fn tcp_payload_len_of_reassembled_datagram() {
    // A segment dissected from a reassembled IP datagram is longer than the
    // Total Length of the IPv4 header of the fragment that completed it
    // (RFC 791, Section 3.2); the reassembled bytes all belong to it.
    // https://www.rfc-editor.org/rfc/rfc791#section-3.2
    let mut tcp_data = build_tcp_packet(12345, 80, 0, 0, 0x18);
    tcp_data.extend_from_slice(&[0u8; 100]);
    let mut buf = DissectBuffer::new();
    add_ipv4_layer_with_total_length(&mut buf, 20 + 16);
    let result = TcpDissector::new()
        .dissect(&tcp_data, &mut buf, 20)
        .unwrap();
    assert_eq!(result.tcp_stream_context.unwrap().payload_len, 100);
}
