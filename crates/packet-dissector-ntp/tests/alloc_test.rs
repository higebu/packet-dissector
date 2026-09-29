//! Zero-allocation dissection tests for the NTP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_ntp::NtpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

/// Build a minimal NTP packet.
fn build_ntp(li: u8, vn: u8, mode: u8, stratum: u8, ref_id: [u8; 4]) -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    pkt[0] = (li << 6) | (vn << 3) | mode;
    pkt[1] = stratum;
    pkt[2] = 6; // poll
    pkt[3] = 0xEC_u8; // precision: -20 as i8
    pkt[12..16].copy_from_slice(&ref_id);
    pkt
}

#[test]
fn zero_alloc_dissect_ntp_client() {
    let raw = build_ntp(0, 4, 3, 0, [0; 4]);

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        NtpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "NTP client dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "NTP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 13);
    assert_eq!(fields[0].value, FieldValue::U8(0)); // leap_indicator
    assert_eq!(fields[2].value, FieldValue::U8(3)); // mode (client)
}

#[test]
fn zero_alloc_dissect_ntp_server() {
    let raw = build_ntp(0, 4, 4, 2, [192, 168, 1, 1]);

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        NtpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "NTP server dissect allocated {allocs} times, expected 0"
    );

    assert_eq!(buf.layers().len(), 1);
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields[2].value, FieldValue::U8(4)); // mode (server)
    assert_eq!(fields[8].value, FieldValue::Bytes(&[192, 168, 1, 1])); // reference_id
}

#[test]
fn zero_alloc_dissect_ntp_control_message() {
    // RFC 9327, Section 2 — mode 6 response with 4 data octets.
    //   <https://www.rfc-editor.org/rfc/rfc9327#section-2>
    let raw: &[u8] = &[
        0x16, 0x82, 0x00, 0x01, 0x06, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'l', b'e', b'a',
        b'p',
    ];
    let mut buf = DissectBuffer::new();
    NtpDissector.dissect(raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        NtpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NTP mode 6 dissect allocated {allocs} times");
    assert_eq!(buf.layers().len(), 1);
}

/// Build an extension field (RFC 7822, Section 3).
///   <https://www.rfc-editor.org/rfc/rfc7822#section-3>
fn build_ef(field_type: u16, body: &[u8]) -> Vec<u8> {
    let mut ef = field_type.to_be_bytes().to_vec();
    ef.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    ef.extend_from_slice(body);
    ef
}

#[test]
fn zero_alloc_dissect_ntp_nts_client() {
    // RFC 8915, Section 5.7 — Unique Identifier, NTS Cookie, NTS Cookie
    // Placeholder and NTS Authenticator and Encrypted Extension Fields.
    //   <https://www.rfc-editor.org/rfc/rfc8915#section-5.7>
    let mut raw = build_ntp(0, 4, 3, 0, [0; 4]);
    raw.extend_from_slice(&build_ef(0x0104, &[0x11; 32]));
    raw.extend_from_slice(&build_ef(0x0204, &[0x22; 100]));
    raw.extend_from_slice(&build_ef(0x0304, &[0; 100]));
    let mut auth = vec![0x00, 0x10, 0x00, 0x10];
    auth.extend_from_slice(&[0x33; 32]);
    raw.extend_from_slice(&build_ef(0x0404, &auth));

    let mut buf = DissectBuffer::new();
    // Warm up so the buffer's vectors reach their steady-state capacity.
    NtpDissector.dissect(&raw, &mut buf, 0).unwrap();

    let allocs = count_allocs(|| {
        buf.clear();
        NtpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NTS dissect allocated {allocs} times");
    assert_eq!(buf.layers().len(), 1);
    let layer = &buf.layers()[0];
    assert!(buf.field_by_name(layer, "extension_fields").is_some());
    assert!(buf.field_by_name(layer, "trailing_data").is_none());
}

#[test]
fn zero_alloc_dissect_ntp_mac() {
    // RFC 5905, Section 7.3 — 20-octet MAC (Key Identifier + digest).
    //   <https://www.rfc-editor.org/rfc/rfc5905#section-7.3>
    let mut raw = build_ntp(0, 4, 3, 0, [0; 4]);
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&[0x44; 16]);

    let mut buf = DissectBuffer::new();
    NtpDissector.dissect(&raw, &mut buf, 0).unwrap();
    let allocs = count_allocs(|| {
        buf.clear();
        NtpDissector.dissect(&raw, &mut buf, 0).unwrap();
    });
    assert_eq!(allocs, 0, "NTP MAC dissect allocated {allocs} times");
    let layer = &buf.layers()[0];
    assert_eq!(
        buf.field_by_name(layer, "key_id").unwrap().value,
        FieldValue::U32(1)
    );
}
