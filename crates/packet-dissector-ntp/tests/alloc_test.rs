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
