//! Zero-allocation dissection tests for the RTP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_rtp::RtpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

#[test]
fn zero_alloc_dissect_rtp() {
    // Minimal RTP header: V=2, P=0, X=0, CC=0, M=0, PT=111
    let raw: &[u8] = &[
        0x80, // V=2, P=0, X=0, CC=0
        0x6F, // M=0, PT=111
        0x03, 0xE8, // seq=1000
        0x00, 0x02, 0x71, 0x00, // timestamp=160000
        0x12, 0x34, 0x56, 0x78, // SSRC
    ];

    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        RtpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "RTP dissect allocated {allocs} times, expected 0"
    );

    // Verify the dissected data is correct.
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "RTP");
    let fields = buf.layer_fields(&buf.layers()[0]);
    assert_eq!(fields.len(), 9);
    assert_eq!(fields[0].value, FieldValue::U8(2)); // version
    assert_eq!(fields[5].value, FieldValue::U8(111)); // payload_type
}

#[test]
fn zero_alloc_dissect_rtp_with_csrc() {
    // RTP header: V=2, P=0, X=0, CC=2, M=0, PT=0
    let raw: &[u8] = &[
        0x82, // V=2, P=0, X=0, CC=2
        0x00, // M=0, PT=0
        0x00, 0x01, // seq=1
        0x00, 0x00, 0x00, 0x64, // timestamp=100
        0xAA, 0xBB, 0xCC, 0xDD, // SSRC
        0x11, 0x11, 0x11, 0x11, // CSRC[0]
        0x22, 0x22, 0x22, 0x22, // CSRC[1]
    ];

    let mut buf = DissectBuffer::new();

    let allocs = count_allocs(|| {
        buf.clear();
        RtpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "RTP with CSRC dissect allocated {allocs} times, expected 0"
    );

    assert_eq!(buf.layers().len(), 1);
    let fields = buf.layer_fields(&buf.layers()[0]);
    // 9 fixed fields + 1 csrc_list container + 2 csrc elements = 12
    assert_eq!(fields.len(), 12);
    assert_eq!(fields[3].value, FieldValue::U8(2)); // csrc_count
}
