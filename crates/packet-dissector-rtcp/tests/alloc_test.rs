//! Zero-allocation dissection tests for the RTCP dissector.

use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use packet_dissector_rtcp::RtcpDissector;
use packet_dissector_test_alloc::{count_allocs, setup_counting_allocator};

setup_counting_allocator!();

fn assert_zero_alloc(raw: &[u8]) {
    // Pre-allocate the buffer (this allocation is OK — happens once).
    let mut buf = DissectBuffer::new();
    RtcpDissector.dissect(raw, &mut buf, 0).unwrap();

    // The dissect call itself must be zero-allocation.
    let allocs = count_allocs(|| {
        buf.clear();
        RtcpDissector.dissect(raw, &mut buf, 0).unwrap();
    });
    assert_eq!(
        allocs, 0,
        "RTCP dissect allocated {allocs} times, expected 0"
    );
    assert_eq!(buf.layers().len(), 1);
    assert_eq!(buf.layers()[0].name, "RTCP");
}

#[test]
fn zero_alloc_dissect_rtcp_sr_sdes_bye() {
    // SR (RC=1) + SDES (CNAME, PRIV) + BYE with reason
    // (RFC 3550, Sections 6.4.1, 6.5, 6.6 —
    // https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1).
    let mut raw = vec![0x81, 200, 0x00, 0x0C];
    raw.extend_from_slice(&[0x11; 4]); // SSRC of sender
    raw.extend_from_slice(&[0; 20]); // sender info
    raw.extend_from_slice(&[0x22; 4]); // report block SSRC
    raw.extend_from_slice(&[0x01, 0xFF, 0xFF, 0xFE]); // fraction, cumulative
    raw.extend_from_slice(&[0; 16]); // ext seq, jitter, LSR, DLSR
    raw.extend_from_slice(&[0x81, 202, 0x00, 0x04]);
    raw.extend_from_slice(&[0x11; 4]);
    raw.extend_from_slice(&[1, 1, b'a', 8, 3, 1, b'p', b'v', 0, 0, 0, 0]);
    raw.extend_from_slice(&[0x81, 203, 0x00, 0x02]);
    raw.extend_from_slice(&[0x11; 4]);
    raw.extend_from_slice(&[2, b'o', b'k', 0]);
    assert_zero_alloc(&raw);
}

#[test]
fn zero_alloc_dissect_rtcp_feedback_and_xr() {
    // RR + RTPFB Generic NACK + PSFB FIR + XR (RRT, DLRR, Loss RLE)
    // (RFC 4585, Section 6.2.1 — https://www.rfc-editor.org/rfc/rfc4585#section-6.2.1;
    // RFC 5104, Section 4.3.1 — https://www.rfc-editor.org/rfc/rfc5104#section-4.3.1;
    // RFC 3611, Section 4 — https://www.rfc-editor.org/rfc/rfc3611#section-4).
    let mut raw = vec![0x80, 201, 0x00, 0x01, 0, 0, 0, 1];
    raw.extend_from_slice(&[0x81, 205, 0x00, 0x03, 0, 0, 0, 1, 0, 0, 0, 2, 0, 5, 0, 1]);
    raw.extend_from_slice(&[0x84, 206, 0x00, 0x04, 0, 0, 0, 1, 0, 0, 0, 0]);
    raw.extend_from_slice(&[0, 0, 0, 2, 7, 0, 0, 0]);
    raw.extend_from_slice(&[0x80, 207, 0x00, 0x0C, 0, 0, 0, 1]);
    raw.extend_from_slice(&[4, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]);
    raw.extend_from_slice(&[5, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4]);
    raw.extend_from_slice(&[1, 0, 0, 3, 0, 0, 0, 2, 0, 1, 0, 9, 0x40, 5, 0xC0, 0]);
    assert_zero_alloc(&raw);
}
